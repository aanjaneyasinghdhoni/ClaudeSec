import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// GET /api/repos — per-repository rollup for the dashboard's "observatory".
//
// Groups every span by its `repo` grouping key (the git-root resolved at ingest,
// see server/repoIdentity.ts) and returns one row per repository with span /
// session counts, the harnesses seen, a threat breakdown, and the SAME health
// score the session list uses (healthFromCounts) so the two views can't diverge.
//
// The `idx_spans_repo_severity` composite index covers the GROUP BY + the
// per-severity SUM(CASE ...) aggregation, so this is a single index-backed scan.
//
// KNOWN, EXPECTED bucket: historical Claude spans stored a SCRUBBED cwd that
// can't be walked to a git root, so they remain repo='unknown'. New spans group
// correctly. The UI labels this bucket honestly rather than hiding it.
export function registerRepoRoutes(app: Express, ctx: RouteContext): void {
  const { healthFromCounts } = ctx;
  if (!healthFromCounts) {
    throw new Error('registerRepoRoutes requires healthFromCounts in ctx');
  }

  app.get('/api/repos', (_req, res) => {
    const rows = db.prepare(`
      SELECT
        s.repo                    AS repo,
        COUNT(DISTINCT s.spanId)  AS spanCount,
        COUNT(DISTINCT s.traceId) AS sessionCount,
        GROUP_CONCAT(DISTINCT s.harness) AS harnesses,
        -- critical folds into the high bucket, mirroring the sessions/harness
        -- rollups, so a confirmed exfil still penalizes a repo's health.
        SUM(CASE WHEN s.severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS threatHigh,
        SUM(CASE WHEN s.severity = 'medium' THEN 1 ELSE 0 END) AS threatMedium,
        SUM(CASE WHEN s.severity = 'low'    THEN 1 ELSE 0 END) AS threatLow,
        MIN(s.startNano) AS firstSeen,
        MAX(s.startNano) AS lastSeen
      FROM spans s
      GROUP BY s.repo
      ORDER BY threatHigh DESC, lastSeen DESC
    `).all() as Array<{
      repo: string;
      spanCount: number;
      sessionCount: number;
      harnesses: string | null;
      threatHigh: number;
      threatMedium: number;
      threatLow: number;
      firstSeen: string | null;
      lastSeen: string | null;
    }>;

    // Per-repo health on the SHARED healthFromCounts() formula — same one behind
    // the session list and CLI report. Alerts aren't keyed by repo, so we pass 0
    // (repo health is a threat-only rollup); the threat penalties dominate the
    // score either way. The list query already SELECTs every input the formula
    // needs, so this adds zero extra DB round-trips (no N+1).
    const repos = rows.map(r => {
      const health = healthFromCounts(r.threatHigh ?? 0, r.threatMedium ?? 0, r.threatLow ?? 0, 0);
      return { ...r, healthScore: health.score, grade: health.grade };
    });

    res.json({ repos });
  });
}
