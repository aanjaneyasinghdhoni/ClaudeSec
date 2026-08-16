/**
 * tests/ftsExternalContentTest.ts
 *
 * Gate for the external-content conversion of spans_fts in server/db.ts.
 *
 * ── What this pins ──
 * spans_fts used to be declared with no `content=` clause, so FTS5 kept its own
 * verbatim copy of the name and attributes of every span in a shadow table
 * called spans_fts_content — a second complete copy of the database that grew
 * forever alongside the first. Declaring the index against `spans` as external
 * content removes that copy, at the cost of a much stricter contract: the index
 * can no longer look up what it is deleting, so the triggers have to hand it the
 * exact old text, and every index rowid must resolve to the span it describes.
 * Get that wrong and the index silently reports the wrong rows, or queries start
 * failing with "missing row from content table".
 *
 * Asserted here:
 *   1. A database created with the OLD self-contained schema is converted on
 *      import, and the spans_fts_content shadow table is gone afterwards.
 *   2. The converted index answers MATCH with EXACTLY the same rows as the
 *      legacy index did — same set, before and after.
 *   3. The trigger set is complete: INSERT indexes, DELETE purges (the retention
 *      contract), UPDATE replaces rather than accumulating stale terms.
 *   4. The migration is resumable — a run interrupted at a cursor picks up from
 *      there instead of restarting or double-indexing — and idempotent, guarded
 *      by a completion marker in `config`.
 *   5. The backfill yields to the event loop between chunks, so it cannot hold
 *      the write lock long enough to stall ingest.
 *
 * Run via:  npx tsx tests/ftsExternalContentTest.ts
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
import Database from 'better-sqlite3';

const DB_PATH = path.join(os.tmpdir(), `csec-ftsexternal-${process.pid}-${Date.now()}.db`);
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_WATCH = '0';

const SPAN_COUNT = 40;

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

/** Every spanId the index matches, sorted — the comparison unit for "identical results". */
function matchedSpanIds(dbh: Database.Database, query: string): string[] {
  return (dbh.prepare(`SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?`).all(query) as { spanId: string }[])
    .map(r => r.spanId)
    .sort();
}

const QUERIES = ['payload', 'shadow', 'tool_call', 'payload OR shadow', '"needle"*'];

/**
 * Build a database exactly as the pre-conversion code did: a self-contained
 * spans_fts with no content= clause, kept in sync by a rowid-pinned insert
 * trigger. This is the state a real installation is upgrading FROM.
 */
function seedLegacyDatabase(): Record<string, string[]> {
  const dbh = new Database(DB_PATH);
  dbh.pragma('journal_mode = WAL');
  dbh.exec(`
    CREATE TABLE spans (
      spanId     TEXT PRIMARY KEY,
      traceId    TEXT NOT NULL DEFAULT 'unknown',
      parentId   TEXT NOT NULL,
      name       TEXT NOT NULL,
      protocol   TEXT NOT NULL,
      reason     TEXT NOT NULL,
      severity   TEXT NOT NULL DEFAULT 'none',
      harness    TEXT NOT NULL DEFAULT 'unknown',
      attributes TEXT NOT NULL DEFAULT '{}',
      startNano  TEXT NOT NULL DEFAULT '0',
      endNano    TEXT NOT NULL DEFAULT '0',
      repo       TEXT NOT NULL DEFAULT 'unknown'
    );
    CREATE VIRTUAL TABLE spans_fts USING fts5(
      spanId UNINDEXED, name, attributes, tokenize = 'unicode61 remove_diacritics 1'
    );
    CREATE TRIGGER spans_fts_insert AFTER INSERT ON spans BEGIN
      INSERT OR REPLACE INTO spans_fts(rowid, spanId, name, attributes)
      VALUES (new.rowid, new.spanId, new.name, new.attributes);
    END;
  `);

  const ins = dbh.prepare(
    `INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', 'none', 'claude-code', ?, '0', '0', 'unknown')`,
  );
  for (let i = 0; i < SPAN_COUNT; i++) {
    const attrs = JSON.stringify({
      'tool.input': `secret-payload-${i}`,
      'file.path': i % 4 === 0 ? '/etc/shadow' : `/tmp/file-${i}.txt`,
      note: i === 7 ? 'needlepoint' : 'ordinary',
    });
    ins.run(`span-${i}`, `trace-${i % 3}`, `tool_call/Bash-${i}`, attrs);
  }

  // Prune a few spans WITHOUT a delete trigger — the legacy defect. Their rows
  // stay in the old index, so the conversion has to shed them.
  dbh.prepare(`DELETE FROM spans WHERE spanId IN ('span-1', 'span-2')`).run();

  assert.ok(
    dbh.prepare(`SELECT 1 FROM sqlite_master WHERE name = 'spans_fts_content'`).get() !== undefined,
    'the legacy fixture must actually have a self-contained index',
  );

  // The expected result set is what the SPANS TABLE says, not what the stale
  // legacy index says — the orphans of span-1/span-2 are the bug being fixed.
  const expected: Record<string, string[]> = {};
  for (const q of QUERIES) {
    expected[q] = (dbh.prepare(`
      SELECT s.spanId FROM spans_fts f JOIN spans s ON s.rowid = f.rowid WHERE spans_fts MATCH ?
    `).all(q) as { spanId: string }[]).map(r => r.spanId).sort();
  }
  dbh.close();
  return expected;
}

async function main(): Promise<void> {
  try {
    const expected = seedLegacyDatabase();

    // Importing server/db.ts against the legacy file runs the conversion.
    const { db, reindexFtsMirror, capSpanAttributes } = await import('../server/db.js');

    const spanRows = () => (db.prepare('SELECT COUNT(*) AS c FROM spans').get() as { c: number }).c;
    const ftsRows  = () => (db.prepare('SELECT COUNT(*) AS c FROM spans_fts').get() as { c: number }).c;
    const marker   = (key: string) =>
      (db.prepare('SELECT value FROM config WHERE key = ?').get(key) as { value: string } | undefined)?.value;

    await check('importing server/db.ts converts a legacy index to external content', () => {
      const sql = (db.prepare(
        `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'spans_fts'`,
      ).get() as { sql: string }).sql;
      assert.match(sql, /content\s*=\s*'spans'/i, 'spans_fts must be declared against spans');
      assert.match(sql, /content_rowid\s*=\s*'rowid'/i, 'the join key must be the span rowid');
    });

    await check('the duplicate spans_fts_content shadow table is gone', () => {
      const shadow = db.prepare(
        `SELECT 1 FROM sqlite_master WHERE name = 'spans_fts_content'`,
      ).get();
      assert.strictEqual(shadow, undefined, 'external content must store no second copy of span text');
    });

    await check('the FTS triggers exist alongside the chain tombstone trigger', () => {
      const names = (db.prepare(
        `SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'spans' ORDER BY name`,
      ).all() as { name: string }[]).map(r => r.name);
      // spans_chain_tombstone belongs to the hash chain, not to FTS: it preserves
      // a deleted span's chain link so retention cannot silently break the chain.
      assert.deepStrictEqual(names, [
        'spans_chain_tombstone', 'spans_fts_delete', 'spans_fts_insert', 'spans_fts_update',
      ]);
    });

    await check('the delete and update triggers use FTS5 delete-command rows', () => {
      const sql = (db.prepare(
        `SELECT group_concat(sql, ';') AS s FROM sqlite_master
          WHERE type = 'trigger' AND name IN ('spans_fts_delete', 'spans_fts_update')`,
      ).get() as { s: string }).s;
      // An external-content index cannot read the row it is removing, so a plain
      // DELETE would leave its terms behind. The 'delete' command carries them.
      assert.ok(!/DELETE\s+FROM\s+spans_fts/i.test(sql), 'a plain DELETE corrupts an external-content index');
      assert.strictEqual((sql.match(/'delete'/g) ?? []).length, 2, 'delete + update each need one delete command');
    });

    await check('the backfill runs and reports every surviving span', async () => {
      assert.strictEqual(marker('fts.external_content_v1'), undefined, 'conversion must leave the work pending');
      const { ran, rows } = await reindexFtsMirror({ chunkSize: 7 });
      assert.strictEqual(ran, true);
      assert.strictEqual(rows, spanRows(), 'every surviving span is indexed exactly once');
      assert.strictEqual(ftsRows(), spanRows());
      assert.ok(marker('fts.external_content_v1'), 'a completed migration must be marked');
      assert.strictEqual(marker('fts.external_content_v1.cursor'), undefined, 'progress state is cleared on completion');
    });

    await check('MATCH returns identical rows before and after the conversion', () => {
      for (const q of QUERIES) {
        assert.deepStrictEqual(matchedSpanIds(db, q), expected[q], `query ${q} changed its result set`);
      }
    });

    await check('spans pruned before the conversion are no longer searchable', () => {
      const ids = matchedSpanIds(db, 'payload');
      assert.ok(!ids.includes('span-1') && !ids.includes('span-2'), 'orphaned index rows must not survive');
    });

    await check('every index rowid resolves to the span it describes', () => {
      const mismatched = (db.prepare(`
        SELECT COUNT(*) AS c FROM spans_fts f
          LEFT JOIN spans s ON s.rowid = f.rowid
         WHERE s.spanId IS NULL OR s.spanId != f.spanId
      `).get() as { c: number }).c;
      assert.strictEqual(mismatched, 0);
    });

    await check('the migration is a no-op once marked', async () => {
      const before = ftsRows();
      const again = await reindexFtsMirror({ chunkSize: 7 });
      assert.strictEqual(again.ran, false, 'the completion marker must stop a second pass');
      assert.strictEqual(ftsRows(), before);
    });

    // ── Trigger set, exercised through `spans` the way ingest and retention do.
    await check('the INSERT trigger indexes a new span', () => {
      db.prepare(`INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', 'none', 'claude-code', ?, '0', '0', 'unknown')`)
        .run('span-new', 'trace-9', 'tool_call/Write', JSON.stringify({ content: 'freshcanary' }));
      assert.deepStrictEqual(matchedSpanIds(db, 'freshcanary'), ['span-new']);
      assert.strictEqual(ftsRows(), spanRows());
    });

    await check('the DELETE trigger purges the index (the retention contract)', () => {
      db.prepare('DELETE FROM spans WHERE spanId = ?').run('span-new');
      assert.deepStrictEqual(matchedSpanIds(db, 'freshcanary'), [], 'pruned content must not stay searchable');
      assert.strictEqual(ftsRows(), spanRows(), 'the index must shrink with spans');
      // A stale posting pointing at a deleted span is not merely wrong — the
      // content lookup behind it fails outright, so this doubles as a check that
      // reads still work at all after a prune.
      assert.doesNotThrow(() => matchedSpanIds(db, 'payload'));
    });

    await check('a whole-session prune leaves nothing behind', () => {
      db.prepare('DELETE FROM spans WHERE traceId = ?').run('trace-1');
      assert.strictEqual(ftsRows(), spanRows());
      const survivors = new Set(
        (db.prepare(`SELECT spanId FROM spans WHERE traceId != 'trace-1'`).all() as { spanId: string }[]).map(r => r.spanId),
      );
      for (const id of matchedSpanIds(db, 'payload')) {
        assert.ok(survivors.has(id), `${id} was pruned but is still searchable`);
      }
    });

    await check('the UPDATE trigger replaces terms instead of accumulating them', () => {
      db.prepare('UPDATE spans SET attributes = ? WHERE spanId = ?')
        .run(JSON.stringify({ content: 'afterword' }), 'span-0');
      assert.deepStrictEqual(matchedSpanIds(db, 'afterword'), ['span-0'], 'the new text must be searchable');
      assert.deepStrictEqual(
        matchedSpanIds(db, '"secret-payload-0"'), [],
        'the superseded text must not remain searchable',
      );
      assert.strictEqual(ftsRows(), spanRows(), 'an update must not add a second index row');
    });

    await check('the index survives an integrity check', () => {
      assert.doesNotThrow(() => db.exec(`INSERT INTO spans_fts(spans_fts) VALUES('integrity-check')`));
    });

    // ── Resumability: simulate a process killed part-way through the backfill.
    await check('an interrupted backfill resumes from its cursor', async () => {
      const ceiling = (db.prepare('SELECT MAX(rowid) AS m FROM spans').get() as { m: number }).m;
      const midpoint = (db.prepare(
        'SELECT rowid AS r FROM spans ORDER BY rowid LIMIT 1 OFFSET ?',
      ).get(Math.floor(spanRows() / 2)) as { r: number }).r;

      // Roll the index back to what a crash at `midpoint` would have left: rows
      // above the cursor unindexed, the cursor and ceiling persisted, no marker.
      for (const row of db.prepare(
        'SELECT rowid AS rid, spanId, name, attributes FROM spans WHERE rowid > ?',
      ).all(midpoint) as { rid: number; spanId: string; name: string; attributes: string }[]) {
        db.prepare(`INSERT INTO spans_fts(spans_fts, rowid, spanId, name, attributes) VALUES ('delete', ?, ?, ?, ?)`)
          .run(row.rid, row.spanId, row.name, row.attributes);
      }
      const remaining = (db.prepare('SELECT COUNT(*) AS c FROM spans WHERE rowid > ?').get(midpoint) as { c: number }).c;
      db.prepare(`DELETE FROM config WHERE key = 'fts.external_content_v1'`).run();
      db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('fts.external_content_v1.ceiling', ?)`).run(String(ceiling));
      db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('fts.external_content_v1.cursor', ?)`).run(String(midpoint));

      const { ran, rows } = await reindexFtsMirror({ chunkSize: 3 });
      assert.strictEqual(ran, true);
      assert.strictEqual(rows, remaining, 'only the rows above the cursor are re-indexed');
      assert.strictEqual(ftsRows(), spanRows(), 'no span is indexed twice or left out');
      assert.doesNotThrow(() => db.exec(`INSERT INTO spans_fts(spans_fts) VALUES('integrity-check')`));
    });

    await check('the backfill yields to the event loop between chunks', async () => {
      let ticks = 0;
      const timer = setInterval(() => { ticks++; }, 1);
      try {
        await reindexFtsMirror({ chunkSize: 2, force: true });
      } finally {
        clearInterval(timer);
      }
      assert.ok(ticks > 0, 'a backfill that never yields would hold the write lock for its whole run');
      assert.strictEqual(ftsRows(), spanRows());
    });

    // ── The stored-content cap that keeps the index (and the table) bounded.
    await check('capSpanAttributes truncates only oversized string values', () => {
      const long = 'x'.repeat(9000);
      const out = capSpanAttributes({ content: long, file_path: '/tmp/a.txt', tokens: 42 }, 4096);
      assert.strictEqual(out.file_path, '/tmp/a.txt', 'short values pass through untouched');
      assert.strictEqual(out.tokens, 42, 'non-strings pass through untouched');
      const capped = out.content as string;
      assert.ok(capped.length < long.length, 'an oversized value must shrink');
      assert.ok(capped.startsWith('x'.repeat(4096)), 'the head of the value is preserved verbatim');
      assert.match(capped, /ClaudeSec truncated 4904 characters/, 'truncation must be marked with the byte count');
    });

    await check('a capped span still round-trips as valid JSON through the index', () => {
      const attrs = JSON.stringify(capSpanAttributes({ content: `canaryword ${'y'.repeat(9000)}` }, 4096));
      db.prepare(`INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', 'none', 'claude-code', ?, '0', '0', 'unknown')`)
        .run('span-capped', 'trace-9', 'tool_call/Write', attrs);
      assert.doesNotThrow(() => JSON.parse(
        (db.prepare('SELECT attributes AS a FROM spans WHERE spanId = ?').get('span-capped') as { a: string }).a,
      ));
      assert.deepStrictEqual(matchedSpanIds(db, 'canaryword'), ['span-capped'],
        'the retained head must still be searchable');
      assert.ok(attrs.length < 5000, 'the stored attributes must actually be bounded');
    });

    await check('the cap never splits a surrogate pair', () => {
      // A 4-byte emoji straddling the cap boundary would otherwise leave a lone
      // high surrogate in the stored JSON.
      const value = 'a'.repeat(9) + '😀'.repeat(20);
      const out = capSpanAttributes({ content: value }, 10) as { content: string };
      assert.ok(!/[\uD800-\uDBFF]$/.test(out.content.split('\n')[0]), 'no dangling high surrogate');
      assert.doesNotThrow(() => JSON.parse(JSON.stringify(out)));
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  ftsExternalContentTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[ftsExternalContentTest] fatal:', err);
  cleanup();
  process.exit(1);
});
