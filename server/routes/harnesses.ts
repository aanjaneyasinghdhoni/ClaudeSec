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

export function registerHarnessRoutes(app: Express, _ctx: RouteContext): void {
  // ── Harness profiles (full per-agent stats) ──────────────────────────────
  app.get('/api/harnesses', (_req, res) => {
    const rows = db.prepare(`
      SELECT
        s.harness,
        COUNT(s.spanId)                                                          AS spanCount,
        COUNT(DISTINCT s.traceId)                                                AS sessionCount,
        SUM(CASE s.severity WHEN 'high'   THEN 1 ELSE 0 END)                    AS threatHigh,
        SUM(CASE s.severity WHEN 'medium' THEN 1 ELSE 0 END)                    AS threatMedium,
        SUM(CASE s.severity WHEN 'low'    THEN 1 ELSE 0 END)                    AS threatLow,
        MIN(s.startNano)                                                         AS firstSeenNano,
        MAX(s.startNano)                                                         AS lastSeenNano
      FROM spans s
      GROUP BY s.harness
      ORDER BY spanCount DESC
    `).all() as any[];

    // Compute token totals per harness by iterating attributes
    const tokenMap = new Map<string, { tokensIn: number; tokensOut: number }>();
    const allSpans = getAllSpans.all() as SpanRecord[];
    for (const span of allSpans) {
      try {
        const a = JSON.parse(span.attributes);
        const ti = Number(a['gen_ai.usage.input_tokens']  ?? a['llm.usage.input_tokens']  ?? 0);
        const to = Number(a['gen_ai.usage.output_tokens'] ?? a['llm.usage.output_tokens'] ?? 0);
        if (!ti && !to) continue;
        const entry = tokenMap.get(span.harness) ?? { tokensIn: 0, tokensOut: 0 };
        entry.tokensIn  += ti;
        entry.tokensOut += to;
        tokenMap.set(span.harness, entry);
      } catch {}
    }

    const harnesses = rows.map(r => {
      const tokens = tokenMap.get(r.harness) ?? { tokensIn: 0, tokensOut: 0 };
      // Convert nanosecond strings to ISO dates for display
      const nanoToIso = (nano: string | null) => {
        if (!nano || nano === '0') return null;
        try { return new Date(Number(BigInt(nano) / 1_000_000n)).toISOString(); } catch { return null; }
      };
      return {
        harness:       r.harness,
        spanCount:     r.spanCount,
        sessionCount:  r.sessionCount,
        threatHigh:    r.threatHigh,
        threatMedium:  r.threatMedium,
        threatLow:     r.threatLow,
        tokensIn:      tokens.tokensIn,
        tokensOut:     tokens.tokensOut,
        firstSeen:     nanoToIso(r.firstSeenNano),
        lastSeen:      nanoToIso(r.lastSeenNano),
      };
    });

    res.json({ harnesses });
  });
}
