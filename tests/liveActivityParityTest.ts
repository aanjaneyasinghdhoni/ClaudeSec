/**
 * tests/liveActivityParityTest.ts
 *
 * Gate for the /api/live-activity rewrite in server/routes/liveActivity.ts.
 *
 * The old implementation was `SELECT harness, MAX(endNano) FROM spans GROUP BY
 * harness` joined back to `spans` — a full covering-index scan that measured
 * 14 ms at 271k spans and projected to ~1.6 s at 5M. The new implementation
 * enumerates distinct harnesses with a loose-index-scan recursive walk (`MIN
 * (harness)`, then repeatedly `MIN(harness) WHERE harness > previous`) and
 * does one bounded per-harness lookup — O(harnesses × log n) instead of
 * O(table size).
 *
 * This test pins that the two are equivalent, not just individually
 * plausible:
 *   1. Same set of harnesses.
 *   2. Same "latest span" per harness, on ordinary data.
 *   3. The endNano-TIE case, where they legitimately differ on purpose: the
 *      old `MAX(endNano)` join returns every span tied for the max (which
 *      could show one harness twice, or pick an arbitrary one depending on
 *      SQLite's join order), while the new bounded lookup's `ORDER BY endNano
 *      DESC, rowid DESC LIMIT 1` deterministically picks the most-recently-
 *      inserted of the tie. That tiebreaker is documented, deliberate
 *      behavior — the test locks in that the new result is the higher-rowid
 *      row among the tied set, not that the two queries agree on every field
 *      (they can't, on a tie).
 *
 * Run via:  npx tsx tests/liveActivityParityTest.ts
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

const DB_PATH = path.join(os.tmpdir(), `csec-liveactivityparity-${process.pid}-${Date.now()}.db`);
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

const INSERT_COLS =
  'spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo';

async function main(): Promise<void> {
  try {
    const { db } = await import('../server/db.js');

    const insertSpan = db.prepare(
      `INSERT INTO spans (${INSERT_COLS}) VALUES (?, 'trace-1', '', 'tool_call/Bash', 'otlp', '', 'none', ?, '{}', ?, ?, 'unknown')`,
    );

    // OLD implementation, verbatim.
    const oldQuery = db.prepare(`
      SELECT s.harness, s.spanId, s.startNano, s.endNano
      FROM spans s
      INNER JOIN (SELECT harness, MAX(endNano) as maxEnd FROM spans GROUP BY harness) latest
        ON s.harness = latest.harness AND s.endNano = latest.maxEnd
    `);

    // NEW implementation, matching server/routes/liveActivity.ts exactly.
    const firstHarness = db.prepare(`SELECT MIN(harness) AS h FROM spans`);
    const nextHarness = db.prepare(`SELECT MIN(harness) AS h FROM spans WHERE harness > ?`);
    function distinctHarnesses(): string[] {
      const out: string[] = [];
      let cur = (firstHarness.get() as { h: string | null }).h;
      while (cur !== null) { out.push(cur); cur = (nextHarness.get(cur) as { h: string | null }).h; }
      return out;
    }
    const latestForHarness = db.prepare(`
      SELECT harness, spanId, startNano, endNano
      FROM spans WHERE harness = ? ORDER BY endNano DESC, rowid DESC LIMIT 1
    `);
    function newLatestPerHarness() {
      return distinctHarnesses()
        .map(h => latestForHarness.get(h) as { harness: string; spanId: string; startNano: string; endNano: string } | undefined)
        .filter((r): r is NonNullable<typeof r> => r !== undefined);
    }

    // ── Ordinary data: no ties ──────────────────────────────────────────
    insertSpan.run('a1', 'claude-code', '100', '200');
    insertSpan.run('a2', 'claude-code', '300', '900');   // latest for claude-code
    insertSpan.run('b1', 'copilot',     '150', '400');
    insertSpan.run('b2', 'copilot',     '250', '350');   // NOT latest (400 > 350)
    insertSpan.run('c1', 'codex',       '500', '600');   // only span for codex

    await check('same set of harnesses, no ties', () => {
      const oldHarnesses = (oldQuery.all() as { harness: string }[]).map(r => r.harness).sort();
      const newHarnesses = newLatestPerHarness().map(r => r.harness).sort();
      assert.deepStrictEqual(newHarnesses, oldHarnesses);
      assert.deepStrictEqual(newHarnesses, ['claude-code', 'codex', 'copilot']);
    });

    await check('same latest spanId per harness, no ties', () => {
      const oldByHarness = new Map((oldQuery.all() as { harness: string; spanId: string }[]).map(r => [r.harness, r.spanId]));
      const newByHarness = new Map(newLatestPerHarness().map(r => [r.harness, r.spanId]));
      assert.deepStrictEqual(newByHarness, oldByHarness);
      assert.strictEqual(newByHarness.get('claude-code'), 'a2');
      assert.strictEqual(newByHarness.get('copilot'), 'b1');
      assert.strictEqual(newByHarness.get('codex'), 'c1');
    });

    // ── endNano tie for one harness ─────────────────────────────────────
    // Two spans for 'gemini' close at the identical nanosecond. The old
    // MAX(endNano) join returns BOTH (a real bug the new tiebreaker fixes);
    // the new bounded lookup picks the higher-rowid (most recently inserted)
    // one deterministically.
    insertSpan.run('g1', 'gemini', '700', '800');
    insertSpan.run('g2', 'gemini', '750', '800'); // tie on endNano, inserted after g1

    await check('old MAX(endNano) join returns every span tied for the max — the bug the rewrite fixes', () => {
      const tied = (oldQuery.all() as { harness: string; spanId: string }[]).filter(r => r.harness === 'gemini');
      assert.deepStrictEqual(tied.map(r => r.spanId).sort(), ['g1', 'g2'],
        'both tied spans must come back from the old query — this is the ambiguity being fixed, not asserted as correct');
    });

    await check('new bounded lookup deterministically picks the higher-rowid span on a tie', () => {
      const winner = latestForHarness.get('gemini') as { spanId: string } | undefined;
      assert.strictEqual(winner?.spanId, 'g2', 'the later-inserted (higher rowid) of the tied pair must win');
    });

    // ── Non-tied harnesses stay byte-identical alongside the tie ────────
    await check('non-tied harnesses are unaffected by another harness having a tie', () => {
      const newByHarness = new Map(newLatestPerHarness().map(r => [r.harness, r.spanId]));
      assert.strictEqual(newByHarness.get('claude-code'), 'a2');
      assert.strictEqual(newByHarness.get('copilot'), 'b1');
      assert.strictEqual(newByHarness.get('codex'), 'c1');
      assert.strictEqual(newByHarness.get('gemini'), 'g2');
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  liveActivityParityTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[liveActivityParityTest] fatal:', err);
  cleanup();
  process.exit(1);
});
