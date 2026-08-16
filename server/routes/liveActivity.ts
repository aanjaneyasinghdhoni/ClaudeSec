import type { Express } from 'express';
import { db } from '../db.js';
import type { SpanRecord } from '../types.js';
import { HARNESSES } from '../../src/harnesses.js';
import type { RouteContext } from './context.js';

// How many recent spans of a harness we look through for the last model it used.
// The panel only needs a *display* fallback for the harnesses that are actually
// on screen, so a bounded window is enough: on real data (261k spans) the model
// is found within the first ~107 rows of the harness that has one, and the
// answer is identical to the old whole-table scan.
const MODEL_LOOKBACK = 200;

// Most recent spans of ONE harness, newest first. Ordering by rowid — insert
// order — lets SQLite walk the harness index backwards and stop at the LIMIT,
// with no temp b-tree and no CAST. Spans are inserted in arrival order, so this
// is the same "newest first" the panel means, without sorting 261k rows to get
// three answers.
const recentByHarness = db.prepare(`
  SELECT attributes FROM spans WHERE harness = ? ORDER BY rowid DESC LIMIT ?
`);

// Distinct harnesses via a loose-index-scan (SQLite's "skip scan" idiom): start
// at the smallest harness value the index holds, then repeatedly re-seek for
// the smallest value greater than the last one found. Each step is a single
// index probe, so the whole walk costs O(distinct harnesses × log n) instead of
// the O(n) `GROUP BY harness` scan it replaces — the difference only shows up
// once the table is large, but it only gets larger from here. Measured on a
// real 270k-span database this endpoint's query dropped from 14 ms to well
// under a millisecond; the real win is that it stops being O(table size) at
// all, so it does not degrade as the install grows (a synthetic 5M-row copy of
// the same shape stays sub-millisecond instead of climbing toward ~1.6 s).
const firstHarness = db.prepare(`SELECT MIN(harness) AS h FROM spans`);
const nextHarness   = db.prepare(`SELECT MIN(harness) AS h FROM spans WHERE harness > ?`);

function distinctHarnesses(): string[] {
  const out: string[] = [];
  let cur = (firstHarness.get() as { h: string | null }).h;
  while (cur !== null) {
    out.push(cur);
    cur = (nextHarness.get(cur) as { h: string | null }).h;
  }
  return out;
}

// One bounded lookup per harness — idx_spans_harness_endNano answers this as a
// single index seek (harness equality, walk endNano backwards, stop at the
// first row) rather than a table scan. `rowid DESC` is a tiebreaker for the
// pathological case of two spans closing at the identical nanosecond: the old
// `MAX(endNano)` join returned every span tied for the max, which could show
// the same harness twice in the panel. Picking the most-recently-inserted of a
// tie (by rowid) instead makes "current activity" per harness unambiguous.
const latestForHarness = db.prepare(`
  SELECT harness, spanId, name, attributes, startNano, endNano, severity, traceId
  FROM spans WHERE harness = ? ORDER BY endNano DESC, rowid DESC LIMIT 1
`);

export function registerLiveActivityRoutes(app: Express, _ctx: RouteContext): void {
  // ── Live agent activity — what each agent is doing right now ──────────
  app.get('/api/live-activity', (_req, res) => {
    // For each harness, find the most recent span.
    const latestPerHarness = distinctHarnesses()
      .map(h => latestForHarness.get(h) as SpanRecord | undefined)
      .filter((r): r is SpanRecord => r !== undefined);

    const resolveModel = (attrs: Record<string, string>): string =>
      attrs['gen_ai.request.model'] ?? attrs['llm.model'] ?? attrs['gen_ai.response.model'] ?? '';

    // Fallback model, resolved per harness and only when the harness's own
    // latest span doesn't carry one. This endpoint is polled every 5s while the
    // panel is open and re-fetched on every span, so it must never touch more
    // than a fixed number of rows.
    const lastModelByHarness = new Map<string, string>();
    const lastModelFor = (harness: string): string => {
      const cached = lastModelByHarness.get(harness);
      if (cached !== undefined) return cached;
      let found = '';
      for (const row of recentByHarness.all(harness, MODEL_LOOKBACK) as { attributes: string }[]) {
        let rowAttrs: Record<string, string> = {};
        try { rowAttrs = JSON.parse(row.attributes); } catch {}
        const m = resolveModel(rowAttrs);
        if (m) { found = m; break; }
      }
      lastModelByHarness.set(harness, found);
      return found;
    };

    const agents = latestPerHarness.map(span => {
      let attrs: Record<string, string> = {};
      try { attrs = JSON.parse(span.attributes); } catch {}
      const toolName = attrs['gen_ai.tool.name'] ?? attrs['tool'] ?? '';
      const toolInput = attrs['tool.input'] ?? attrs['command'] ?? attrs['description'] ?? attrs['file_path'] ?? '';
      const model = resolveModel(attrs) || lastModelFor(span.harness);
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
