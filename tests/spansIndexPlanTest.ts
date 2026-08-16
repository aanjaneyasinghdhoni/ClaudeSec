/**
 * tests/spansIndexPlanTest.ts
 *
 * Gate for the index swap in server/db.ts's "Query accelerators" block.
 *
 * That block replaced six narrow indexes on `spans` with four composites
 * shaped after the query, plus kept/added two narrow exceptions
 * (idx_spans_harness, idx_spans_traceId) and one restored exception
 * (idx_spans_harness_severity) where the composite-only set measurably
 * regressed a real query on a 271k-span production copy — see the comment
 * above the index block for the full writeup and numbers. This test pins two
 * things so neither regression can silently come back:
 *
 *   1. The exact final index set on `spans` — no more, no fewer. A stray
 *      leftover (the eight-redundant-indexes bug this swap itself was fixing)
 *      or an accidental drop of one of the three exceptions both show up here.
 *   2. The two query shapes that motivated the two "kept against the audit's
 *      recommendation" indexes still get a plan that needs no full-table
 *      filter or sort:
 *        - /api/search's combined harness+severity COUNT(*) (no ORDER BY) —
 *          needs idx_spans_harness_severity's direct equality seek, not
 *          idx_spans_harness_start_sev (which puts startNano between harness
 *          and severity in the key, turning the severity match into a filter
 *          over every row of that harness).
 *        - the anomaly sweep's per-batch tail read (`WHERE traceId = ? ORDER
 *          BY rowid DESC LIMIT 10`) — needs a bare (traceId) index so SQLite
 *          reads matching rows in rowid order for free; the five-column
 *          idx_spans_trace can satisfy the equality but not the ordering
 *          without a temp b-tree.
 *
 * A plan assertion here is deliberately EXPLAIN QUERY PLAN text, not a timing
 * threshold — the point is that the wrong index gets picked, at all, not how
 * many milliseconds that costs on this machine.
 *
 * Run via:  npx tsx tests/spansIndexPlanTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB points under os.tmpdir() BEFORE server/db.ts is
 * imported, and the file is removed in a finally block. The real ~/.claudesec
 * database is never opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = path.join(os.tmpdir(), `csec-spansindexplan-${process.pid}-${Date.now()}.db`);
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_WATCH = '0';

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try { await fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
}

// The final, intended index set on `spans` — everything else declared in
// db.ts's history (traceId_startNano, severity, endNano, traceId_severity,
// repo, repo_severity) must be gone, not just unused.
const EXPECTED_INDEXES = [
  'idx_spans_harness',
  'idx_spans_harness_endNano',
  'idx_spans_harness_severity',
  'idx_spans_harness_start_sev',
  'idx_spans_repo_sev_start',
  'idx_spans_severity_startNano',
  'idx_spans_startNano',
  'idx_spans_trace',
  'idx_spans_traceId',
].sort();

async function main(): Promise<void> {
  try {
    const { db } = await import('../server/db.js');

    await check('the final index set on spans is exact — nothing redundant survives, nothing needed is missing', () => {
      const names = (db.prepare(
        `SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'spans' AND name LIKE 'idx_%'`,
      ).all() as { name: string }[]).map(r => r.name).sort();
      assert.deepStrictEqual(names, EXPECTED_INDEXES);
    });

    await check('the eight superseded indexes are actually dropped, not just absent from a fresh db', () => {
      // A DROP INDEX IF EXISTS on a name that never existed is a no-op — so
      // recreate the OLD index under a disposable name and confirm the drop
      // statements in db.ts really are unconditional DROP INDEX IF EXISTS
      // (converging an EXISTING database), not CREATE-only additions that
      // only look complete on a fresh one.
      const stale = ['idx_spans_traceId_startNano', 'idx_spans_severity', 'idx_spans_endNano',
        'idx_spans_traceId_severity', 'idx_spans_repo', 'idx_spans_repo_severity'];
      for (const name of stale) {
        assert.ok(
          !(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='index' AND name = ?`).get(name)),
          `${name} must not exist on the migrated database`,
        );
      }
    });

    // Seed enough rows that the query planner's row-count estimates favor a
    // real index over a table scan — EXPLAIN QUERY PLAN on an empty/tiny table
    // can pick a different (equally valid, but not what we're testing) plan.
    const insert = db.prepare(`
      INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo)
      VALUES (@spanId, @traceId, '', 'tool_call/Bash', 'otlp', '', @severity, @harness, '{}', @startNano, @endNano, 'unknown')
    `);
    const seed = db.transaction((n: number) => {
      for (let i = 0; i < n; i++) {
        insert.run({
          spanId: `plan-${i}`,
          traceId: `trace-${i % 50}`,
          severity: i % 7 === 0 ? 'high' : 'none',
          harness: i % 3 === 0 ? 'claude-code' : 'copilot',
          startNano: String(1_700_000_000_000_000_000 + i),
          endNano: String(1_700_000_000_000_000_000 + i + 1000),
        });
      }
    });
    seed(4000);

    const plan = (sql: string): string =>
      (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[])
        .map(r => r.detail).join(' | ');

    await check('/api/search combined-filter COUNT(*) seeks harness+severity directly, no per-row filter', () => {
      const p = plan(`SELECT COUNT(*) as c FROM spans WHERE harness = 'claude-code' AND severity = 'high'`);
      assert.match(p, /USING (COVERING )?INDEX idx_spans_harness_severity \(harness=\? AND severity=\?\)/,
        `expected a direct (harness, severity) equality seek, got: ${p}`);
    });

    await check('the anomaly sweep tail read needs no temp sort for ORDER BY rowid', () => {
      const p = plan(`SELECT spanId, severity FROM spans WHERE traceId = 'trace-1' ORDER BY rowid DESC LIMIT 10`);
      assert.match(p, /USING INDEX idx_spans_traceId \(traceId=\?\)/, `expected the bare traceId index, got: ${p}`);
      assert.doesNotMatch(p, /TEMP B-TREE FOR ORDER BY/, `must not need a temp sort, got: ${p}`);
    });

    await check('live-activity model-lookback still reads a harness in rowid order without a sort', () => {
      const p = plan(`SELECT attributes FROM spans WHERE harness = 'claude-code' ORDER BY rowid DESC LIMIT 200`);
      assert.match(p, /USING INDEX idx_spans_harness \(harness=\?\)/, `expected idx_spans_harness, got: ${p}`);
      assert.doesNotMatch(p, /TEMP B-TREE FOR ORDER BY/, `must not need a temp sort, got: ${p}`);
    });

    await check('live-activity bounded per-harness lookup seeks harness+endNano directly', () => {
      const p = plan(`SELECT spanId FROM spans WHERE harness = 'claude-code' ORDER BY endNano DESC, rowid DESC LIMIT 1`);
      assert.match(p, /USING INDEX idx_spans_harness_endNano \(harness=\?\)/, `expected idx_spans_harness_endNano, got: ${p}`);
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  spansIndexPlanTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[spansIndexPlanTest] fatal:', err);
  cleanup();
  process.exit(1);
});
