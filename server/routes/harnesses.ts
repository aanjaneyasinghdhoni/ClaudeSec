import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';
import { dedupedTokenTotals } from './costs.js';

export function registerHarnessRoutes(app: Express, _ctx: RouteContext): void {
  // ── Harness profiles (full per-agent stats) ──────────────────────────────
  app.get('/api/harnesses', (_req, res) => {
    const rows = db.prepare(`
      SELECT
        s.harness,
        COUNT(s.spanId)                                                          AS spanCount,
        COUNT(DISTINCT s.traceId)                                                AS sessionCount,
        -- Fold the critical exfiltration tier into the high bucket so a confirmed
        -- exfil counts against the agent's profile instead of vanishing.
        SUM(CASE WHEN s.severity IN ('high', 'critical') THEN 1 ELSE 0 END)     AS threatHigh,
        SUM(CASE WHEN s.severity = 'medium' THEN 1 ELSE 0 END)                  AS threatMedium,
        SUM(CASE WHEN s.severity = 'low'    THEN 1 ELSE 0 END)                  AS threatLow,
        MIN(s.startNano)                                                         AS firstSeenNano,
        MAX(s.startNano)                                                         AS lastSeenNano
      FROM spans s
      GROUP BY s.harness
      ORDER BY spanCount DESC
    `).all() as any[];

    // Token totals per harness, on the SAME basis as /api/costs: de-duplicated
    // LLM usage with demo traces excluded and cache tokens folded into input, so
    // the HarnessTab, CostTab, session report, and /metrics all agree.
    const tokenMap = dedupedTokenTotals('harness');

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
