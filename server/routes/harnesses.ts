import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';
import { dedupedUsageRows } from './costs.js';

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
    // LLM usage (exact response-id dedupe + the legacy time/usage heuristic) with
    // demo traces excluded, and cache tokens folded into the input total so the
    // HarnessTab figures agree with the CostTab. Without this, the old code summed
    // every duplicate transcript line and ignored cache reads/writes, so the two
    // tabs disagreed and the totals were inflated.
    const tokenMap = new Map<string, { tokensIn: number; tokensOut: number }>();
    for (const u of dedupedUsageRows()) {
      const ti = u.tokensIn + u.cacheRead + u.cacheWrite;
      const to = u.tokensOut;
      if (!ti && !to) continue;
      const entry = tokenMap.get(u.harness) ?? { tokensIn: 0, tokensOut: 0 };
      entry.tokensIn  += ti;
      entry.tokensOut += to;
      tokenMap.set(u.harness, entry);
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
