import type { Express } from 'express';
import { db } from '../db.js';
import type { Severity } from '../../src/shared/types.js';
import type { RouteContext } from './context.js';

interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}

const getAllSpans = db.prepare(`SELECT * FROM spans`);

export function registerCostRoutes(app: Express, ctx: RouteContext): void {
  const { lookupPricing, MODEL_PRICING } = ctx;
  if (!lookupPricing || !MODEL_PRICING) {
    throw new Error('registerCostRoutes requires lookupPricing and MODEL_PRICING in ctx');
  }

  // ── Token cost estimation ─────────────────────────────────────────────────
  app.get('/api/costs', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];
    const sessionRows = db.prepare('SELECT traceId, name FROM sessions').all() as { traceId: string; name: string }[];
    const sessionNames = new Map(sessionRows.map(s => [s.traceId, s.name]));

    // Aggregate by traceId × model
    interface CostRow {
      traceId:    string;
      sessionName: string;
      harness:    string;
      model:      string;
      modelLabel: string;
      tokensIn:   number;
      tokensOut:  number;
      cacheReadTokens:  number;
      cacheWriteTokens: number;
      costUsd:    number;
      knownPrice: boolean;
      inferred:   boolean;
    }

    const key = (t: string, m: string) => `${t}::${m}`;
    const rowMap = new Map<string, CostRow>();
    let totalCostUsd = 0;
    let totalTokensIn = 0;
    let totalTokensOut = 0;
    let totalCacheReadTokens = 0;
    let totalCacheWriteTokens = 0;

    for (const span of allSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        let model = String(
          attrs['gen_ai.request.model'] ??
          attrs['gen_ai.response.model'] ??
          attrs['llm.request.model']    ?? ''
        ).toLowerCase().trim();
        // Infer model from harness if not provided by telemetry
        let modelInferred = false;
        if (!model || model === '') {
          const harness = span.harness?.toLowerCase() ?? '';
          if (harness.includes('claude') || harness === 'claude-code') model = 'claude-sonnet-4-6';
          if (model) modelInferred = true;
        }
        const ti = Number(attrs['gen_ai.usage.input_tokens']  ?? attrs['llm.usage.input_tokens']  ?? 0);
        const to = Number(attrs['gen_ai.usage.output_tokens'] ?? attrs['llm.usage.output_tokens'] ?? 0);
        const cacheRead   = Number(attrs['gen_ai.usage.cache_read_input_tokens']     ?? 0);
        const cacheCreate = Number(attrs['gen_ai.usage.cache_creation_input_tokens'] ?? 0);
        if (!model && ti === 0 && to === 0 && cacheRead === 0 && cacheCreate === 0) continue;

        const k = key(span.traceId, model || 'unknown');
        if (!rowMap.has(k)) {
          const pricing = model ? lookupPricing(model) : null;
          rowMap.set(k, {
            traceId:    span.traceId,
            sessionName: sessionNames.get(span.traceId) ?? span.traceId.slice(0, 8),
            harness:    span.harness,
            model:      model || 'unknown',
            modelLabel: pricing?.label ?? (model || 'Unknown Model'),
            tokensIn:   0, tokensOut: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0,
            knownPrice: !!pricing,
            inferred:   modelInferred,
          });
        }
        const row = rowMap.get(k)!;
        row.tokensIn  += ti;
        row.tokensOut += to;
        row.cacheReadTokens  += cacheRead;
        row.cacheWriteTokens += cacheCreate;
        totalTokensIn  += ti;
        totalTokensOut += to;
        totalCacheReadTokens  += cacheRead;
        totalCacheWriteTokens += cacheCreate;

        if (model) {
          const pricing = lookupPricing(model);
          if (pricing) {
            const billedInput = ti + cacheCreate * 1.25 + cacheRead * 0.1;
            row.costUsd += (billedInput / 1_000_000) * pricing.inputPer1M + (to / 1_000_000) * pricing.outputPer1M;
          }
        }
      } catch {}
    }

    const rows = [...rowMap.values()].sort((a, b) => b.costUsd - a.costUsd);
    rows.forEach(r => { totalCostUsd += r.costUsd; });

    // Per-model summary (across all sessions)
    const modelSummary = new Map<string, { label: string; tokensIn: number; tokensOut: number; cacheReadTokens: number; cacheWriteTokens: number; costUsd: number; knownPrice: boolean; inferred: boolean }>();
    for (const row of rows) {
      if (!modelSummary.has(row.model)) {
        modelSummary.set(row.model, { label: row.modelLabel, tokensIn: 0, tokensOut: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0, knownPrice: row.knownPrice, inferred: row.inferred });
      }
      const ms = modelSummary.get(row.model)!;
      ms.tokensIn  += row.tokensIn;
      ms.tokensOut += row.tokensOut;
      ms.cacheReadTokens  += row.cacheReadTokens;
      ms.cacheWriteTokens += row.cacheWriteTokens;
      ms.costUsd   += row.costUsd;
      if (row.inferred) ms.inferred = true; // if ANY session was inferred, mark model as inferred
    }

    res.json({
      sessions:      rows.map(r => ({ ...r, costUsd: Math.round(r.costUsd * 1_000_000) / 1_000_000 })),
      models:        [...modelSummary.entries()].map(([model, s]) => ({ model, ...s, costUsd: Math.round(s.costUsd * 1_000_000) / 1_000_000 })).sort((a, b) => b.costUsd - a.costUsd),
      totalCostUsd:  Math.round(totalCostUsd  * 1_000_000) / 1_000_000,
      totalTokensIn,
      totalTokensOut,
      totalCacheReadTokens,
      totalCacheWriteTokens,
      pricingTable:  Object.entries(MODEL_PRICING).map(([model, p]) => ({ model, ...p })),
    });
  });

  // ── Cost trend — token usage over time per session ───────────────────────
  app.get('/api/cost-trend', (req, res) => {
    const traceId = req.query.traceId as string | undefined;
    const spans = (traceId
      ? db.prepare('SELECT * FROM spans WHERE traceId = ? ORDER BY startNano').all(traceId)
      : db.prepare('SELECT * FROM spans ORDER BY startNano').all()
    ) as SpanRecord[];

    let cumIn = 0, cumOut = 0;
    const points: { ts: number; tokensIn: number; tokensOut: number; cumIn: number; cumOut: number }[] = [];

    for (const span of spans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const ti = Number(attrs['gen_ai.usage.input_tokens'] ?? 0);
        const to = Number(attrs['gen_ai.usage.output_tokens'] ?? 0);
        if (ti === 0 && to === 0) continue;
        cumIn += ti;
        cumOut += to;
        const ts = Number(BigInt(span.startNano || '0') / 1_000_000n);
        points.push({ ts, tokensIn: ti, tokensOut: to, cumIn, cumOut });
      } catch {}
    }

    res.json({ points, totalIn: cumIn, totalOut: cumOut });
  });
}
