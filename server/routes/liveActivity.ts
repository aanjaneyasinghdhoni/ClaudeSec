import type { Express } from 'express';
import { db } from '../db.js';
import type { Severity } from '../../src/shared/types.js';
import { HARNESSES } from '../../src/harnesses.js';
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

export function registerLiveActivityRoutes(app: Express, _ctx: RouteContext): void {
  // ── Live agent activity — what each agent is doing right now ──────────
  app.get('/api/live-activity', (_req, res) => {
    // For each harness, find the most recent span
    const latestPerHarness = db.prepare(`
      SELECT s.harness, s.spanId, s.name, s.attributes, s.startNano, s.endNano, s.severity, s.traceId
      FROM spans s
      INNER JOIN (
        SELECT harness, MAX(endNano) as maxEnd FROM spans GROUP BY harness
      ) latest ON s.harness = latest.harness AND s.endNano = latest.maxEnd
    `).all() as SpanRecord[];

    const resolveModel = (attrs: Record<string, string>): string =>
      attrs['gen_ai.request.model'] ?? attrs['llm.model'] ?? attrs['gen_ai.response.model'] ?? '';

    const lastModelByHarness = new Map<string, string>();
    const modelRows = db.prepare(`
      SELECT harness, attributes FROM spans ORDER BY CAST(endNano AS INTEGER) DESC
    `).all() as { harness: string; attributes: string }[];
    for (const row of modelRows) {
      if (lastModelByHarness.has(row.harness)) continue;
      let rowAttrs: Record<string, string> = {};
      try { rowAttrs = JSON.parse(row.attributes); } catch {}
      const m = resolveModel(rowAttrs);
      if (m) lastModelByHarness.set(row.harness, m);
    }

    const agents = latestPerHarness.map(span => {
      let attrs: Record<string, string> = {};
      try { attrs = JSON.parse(span.attributes); } catch {}
      const toolName = attrs['gen_ai.tool.name'] ?? attrs['tool'] ?? '';
      const toolInput = attrs['tool.input'] ?? attrs['command'] ?? attrs['description'] ?? attrs['file_path'] ?? '';
      const model = resolveModel(attrs) || lastModelByHarness.get(span.harness) || '';
      const endMs = Number(BigInt(span.endNano || '0') / 1_000_000n);
      const secondsAgo = Math.max(0, Math.round((Date.now() - endMs) / 1000));
      const h = HARNESSES.find(h => h.id === span.harness) ?? HARNESSES[HARNESSES.length - 1];

      return {
        harness:    span.harness,
        harnessName: h.name,
        color:      h.color,
        lastSpan:   span.name,
        tool:       toolName,
        input:      toolInput.slice(0, 120),
        model,
        severity:   span.severity,
        traceId:    span.traceId,
        secondsAgo,
        active:     secondsAgo < 60,
      };
    }).sort((a, b) => a.secondsAgo - b.secondsAgo);

    res.json({ agents, ts: new Date().toISOString() });
  });
}
