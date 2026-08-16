/**
 * tests/ftsMirrorTest.ts
 *
 * Gate for the spans_fts full-text mirror in server/db.ts.
 *
 * ── The defect this pins ──
 * spans_fts had an AFTER INSERT trigger and nothing else. pruneSpans() deletes
 * from `spans` only, so every pruned span left its name and attributes behind in
 * the search index — permanently. That breaks the retention contract the code
 * explicitly claims (deleted content stayed searchable and on disk) and the
 * mirror grows without bound.
 *
 * Two things are asserted here:
 *   1. Deleting a span removes its FTS row (the AFTER DELETE trigger).
 *   2. reindexFtsMirror() repairs a database that predates the trigger: it drops
 *      orphaned rows and re-pins every FTS rowid to the span it mirrors. The
 *      rowid pinning is load-bearing, not cosmetic — spanId is UNINDEXED, so a
 *      spanId-keyed delete costs a full scan of the FTS content table (~24ms per
 *      row at 260k spans), which would make a retention sweep hold the write
 *      lock for seconds. A misaligned rowid would also make the trigger evict
 *      the WRONG row, so the repair has to run before the trigger can be trusted.
 *
 * Run via:  npx tsx tests/ftsMirrorTest.ts
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

const DB_PATH = path.join(os.tmpdir(), `csec-ftsmirror-${process.pid}-${Date.now()}.db`);
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

async function main(): Promise<void> {
  try {
    const { db, reindexFtsMirror } = await import('../server/db.js');

    const insertSpan = db.prepare(`
      INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo)
      VALUES (?, ?, '', ?, 'HTTPS', 'test', 'none', 'claude-code', ?, '0', '0', 'unknown')
    `);
    const ftsRows  = () => (db.prepare('SELECT COUNT(*) AS c FROM spans_fts').get() as { c: number }).c;
    const spanRows = () => (db.prepare('SELECT COUNT(*) AS c FROM spans').get() as { c: number }).c;
    const ftsHas = (spanId: string) =>
      (db.prepare('SELECT COUNT(*) AS c FROM spans_fts WHERE spanId = ?').get(spanId) as { c: number }).c > 0;

    for (let i = 0; i < 6; i++) {
      insertSpan.run(`span-${i}`, `trace-${i % 2}`, `tool_call/Bash`, JSON.stringify({ 'tool.input': `secret-payload-${i}` }));
    }

    await check('the insert trigger mirrors every span into spans_fts', () => {
      assert.strictEqual(spanRows(), 6);
      assert.strictEqual(ftsRows(), 6);
      assert.ok(ftsHas('span-3'));
    });

    await check('FTS rowids are pinned to the span rowids they mirror', () => {
      const mismatched = (db.prepare(`
        SELECT COUNT(*) AS c FROM spans_fts f
          LEFT JOIN spans s ON s.rowid = f.rowid
         WHERE s.spanId IS NULL OR s.spanId != f.spanId
      `).get() as { c: number }).c;
      assert.strictEqual(mismatched, 0, 'every FTS rowid must resolve to the span it mirrors');
    });

    await check('deleting a span removes its FTS row (the retention contract)', () => {
      db.prepare('DELETE FROM spans WHERE spanId = ?').run('span-3');
      assert.strictEqual(spanRows(), 5);
      assert.strictEqual(ftsRows(), 5, 'spans_fts must shrink with spans');
      assert.strictEqual(ftsHas('span-3'), false, 'pruned content must not stay searchable');
    });

    await check('a whole-session delete (age-based prune) cleans the mirror too', () => {
      db.prepare('DELETE FROM spans WHERE traceId = ?').run('trace-1');
      assert.strictEqual(ftsRows(), spanRows());
      assert.strictEqual(ftsHas('span-1'), false);
    });

    await check('the delete trigger leaves OTHER spans indexed', () => {
      assert.ok(ftsHas('span-0'), 'a surviving span must keep its FTS row');
      const hits = db.prepare(`SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?`).all('secret') as { spanId: string }[];
      assert.deepStrictEqual(hits.map(h => h.spanId).sort(), ['span-0', 'span-2', 'span-4']);
    });

    // ── The repair pass for an index that drifted away from `spans`. ────────
    await check('reindexFtsMirror({ force }) rebuilds a damaged index from scratch', async () => {
      // Double-index a span with text it does not contain — the shape any bug in
      // the trigger set would leave behind. A forced pass must erase it.
      const rowid = (db.prepare('SELECT rowid AS r FROM spans WHERE spanId = ?').get('span-0') as { r: number }).r;
      db.prepare(`INSERT INTO spans_fts(rowid, spanId, name, attributes) VALUES (?, ?, ?, ?)`)
        .run(rowid, 'span-0', 'tool_call/Read', '{"path":"/etc/shadow"}');
      assert.strictEqual(
        (db.prepare(`SELECT COUNT(*) AS c FROM spans_fts WHERE spans_fts MATCH ?`).get('shadow') as { c: number }).c,
        1,
        'fixture must actually corrupt the index',
      );

      const { ran, rows } = await reindexFtsMirror({ chunkSize: 2, force: true });
      assert.strictEqual(ran, true);
      assert.strictEqual(rows, spanRows(), 'every surviving span is re-indexed');
      assert.strictEqual(ftsRows(), spanRows(), 'no stale row survives the rebuild');
      assert.strictEqual(
        (db.prepare(`SELECT COUNT(*) AS c FROM spans_fts WHERE spans_fts MATCH ?`).get('shadow') as { c: number }).c,
        0,
        'text no span contains must not remain searchable',
      );

      const mismatched = (db.prepare(`
        SELECT COUNT(*) AS c FROM spans_fts f
          LEFT JOIN spans s ON s.rowid = f.rowid
         WHERE s.spanId IS NULL OR s.spanId != f.spanId
      `).get() as { c: number }).c;
      assert.strictEqual(mismatched, 0);
    });

    await check('reindexFtsMirror() is idempotent and runs at most once by default', async () => {
      const before = ftsRows();
      const again = await reindexFtsMirror({ chunkSize: 2, force: true });
      assert.strictEqual(again.rows, before, 'a second forced pass reproduces the same contents');
      assert.strictEqual(ftsRows(), before);

      const skipped = await reindexFtsMirror();
      assert.strictEqual(skipped.ran, false, 'the completion marker makes it a no-op afterwards');
    });

    await check('search still works after the rebuild', () => {
      const hits = db.prepare(`SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?`).all('secret') as { spanId: string }[];
      assert.deepStrictEqual(hits.map(h => h.spanId).sort(), ['span-0', 'span-2', 'span-4']);
    });

    await check('the delete trigger still holds after a rebuild', () => {
      db.prepare('DELETE FROM spans WHERE spanId = ?').run('span-4');
      assert.strictEqual(ftsRows(), spanRows());
      assert.strictEqual(ftsHas('span-4'), false);
      assert.ok(ftsHas('span-0'), 'the rebuild must not have shifted rowids off their spans');
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  ftsMirrorTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[ftsMirrorTest] fatal:', err);
  cleanup();
  process.exit(1);
});
