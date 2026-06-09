import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// Token + model aggregation pushed into SQL: json_extract pulls the usage
// fields straight from the attributes column and GROUP BY rolls them up per
// (traceId, model) instead of JSON.parse-ing every row in JS. The model name is
// coalesced/lowercased here so grouping matches; harness-based inference and the
// pricing math stay in JS (per-group, cheap). Spans with no model and no tokens
// are filtered out, mirroring the old `continue`.
const tokenAggByTraceModel = db.prepare(`
  SELECT
    traceId,
    harness,
    LOWER(TRIM(COALESCE(
      json_extract(attributes, '$."gen_ai.request.model"'),
      json_extract(attributes, '$."gen_ai.response.model"'),
      json_extract(attributes, '$."llm.request.model"'),
      ''
    ))) AS model,
    SUM(COALESCE(json_extract(attributes, '$."gen_ai.usage.input_tokens"'),  json_extract(attributes, '$."llm.usage.input_tokens"'),  0)) AS tokensIn,
    SUM(COALESCE(json_extract(attributes, '$."gen_ai.usage.output_tokens"'), json_extract(attributes, '$."llm.usage.output_tokens"'), 0)) AS tokensOut,
    SUM(COALESCE(json_extract(attributes, '$."gen_ai.usage.cache_read_input_tokens"'),     0)) AS cacheReadTokens,
    SUM(COALESCE(json_extract(attributes, '$."gen_ai.usage.cache_creation_input_tokens"'), 0)) AS cacheWriteTokens
  FROM spans
  GROUP BY traceId, model
`);

export function registerCostRoutes(app: Express, ctx: RouteContext): void {
  const { lookupPricing, MODEL_PRICING } = ctx;
  if (!lookupPricing || !MODEL_PRICING) {
    throw new Error('registerCostRoutes requires lookupPricing and MODEL_PRICING in ctx');
  }

  // ── Token cost estimation ─────────────────────────────────────────────────
  app.get('/api/costs', (_req, res) => {
    const sessionRows = db.prepare('SELECT traceId, name FROM sessions').all() as { traceId: string; name: string }[];
    const sessionNames = new Map(sessionRows.map(s => [s.traceId, s.name]));

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

    interface AggRow {
      traceId: string;
      harness: string;
      model: string;
      tokensIn: number;
      tokensOut: number;
      cacheReadTokens: number;
      cacheWriteTokens: number;
    }

    // The SQL groups identical models per trace; harness-based inference can map
    // several SQL groups (e.g. empty model + a real one) onto the same JS row,
    // so a Map keyed on (traceId, effective-model) re-merges them.
    const key = (t: string, m: string) => `${t}::${m}`;
    const rowMap = new Map<string, CostRow>();
    let totalCostUsd = 0;
    let totalTokensIn = 0;
    let totalTokensOut = 0;
    let totalCacheReadTokens = 0;
    let totalCacheWriteTokens = 0;

    for (const agg of tokenAggByTraceModel.all() as AggRow[]) {
      let model = agg.model ?? '';
      // Infer model from harness if not provided by telemetry
      let modelInferred = false;
      if (!model || model === '') {
        const harness = agg.harness?.toLowerCase() ?? '';
        if (harness.includes('claude') || harness === 'claude-code') model = 'claude-sonnet-4-6';
        if (model) modelInferred = true;
      }
      const ti = Number(agg.tokensIn) || 0;
      const to = Number(agg.tokensOut) || 0;
      const cacheRead   = Number(agg.cacheReadTokens) || 0;
      const cacheCreate = Number(agg.cacheWriteTokens) || 0;
      if (!model && ti === 0 && to === 0 && cacheRead === 0 && cacheCreate === 0) continue;

      const k = key(agg.traceId, model || 'unknown');
      if (!rowMap.has(k)) {
        const pricing = model ? lookupPricing(model) : null;
        rowMap.set(k, {
          traceId:    agg.traceId,
          sessionName: sessionNames.get(agg.traceId) ?? agg.traceId.slice(0, 8),
          harness:    agg.harness,
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

    // Pull only token-bearing spans and extract the usage fields in SQL so the
    // JS loop touches just the rows that produce a point — no JSON.parse per row.
    const sql = `
      SELECT
        startNano,
        COALESCE(json_extract(attributes, '$."gen_ai.usage.input_tokens"'),  json_extract(attributes, '$."llm.usage.input_tokens"'),  0) AS tokensIn,
        COALESCE(json_extract(attributes, '$."gen_ai.usage.output_tokens"'), json_extract(attributes, '$."llm.usage.output_tokens"'), 0) AS tokensOut
      FROM spans
      WHERE ${traceId ? 'traceId = ? AND' : ''} (
        COALESCE(json_extract(attributes, '$."gen_ai.usage.input_tokens"'),  json_extract(attributes, '$."llm.usage.input_tokens"'),  0) != 0 OR
        COALESCE(json_extract(attributes, '$."gen_ai.usage.output_tokens"'), json_extract(attributes, '$."llm.usage.output_tokens"'), 0) != 0
      )
      ORDER BY startNano ASC
    `;
    const rows = (traceId
      ? db.prepare(sql).all(traceId)
      : db.prepare(sql).all()
    ) as { startNano: string; tokensIn: number; tokensOut: number }[];

    let cumIn = 0, cumOut = 0;
    const points: { ts: number; tokensIn: number; tokensOut: number; cumIn: number; cumOut: number }[] = [];

    for (const row of rows) {
      const ti = Number(row.tokensIn) || 0;
      const to = Number(row.tokensOut) || 0;
      if (ti === 0 && to === 0) continue;
      cumIn += ti;
      cumOut += to;
      let ts = 0;
      try { ts = Number(BigInt(row.startNano || '0') / 1_000_000n); } catch {}
      points.push({ ts, tokensIn: ti, tokensOut: to, cumIn, cumOut });
    }

    // Hard cap: the payload grows unbounded with the span table (3.7MB at 45k),
    // so return at most the most-recent points. The cumulative on each retained
    // point is still correct (computed over the full prefix) and totalIn/totalOut
    // remain the grand totals, so the chart's end-state is unchanged.
    const MAX_TREND_POINTS = 5000;
    const capped = points.length > MAX_TREND_POINTS ? points.slice(-MAX_TREND_POINTS) : points;

    res.json({ points: capped, totalIn: cumIn, totalOut: cumOut });
  });
}
