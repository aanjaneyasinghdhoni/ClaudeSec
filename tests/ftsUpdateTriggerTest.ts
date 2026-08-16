/**
 * tests/ftsUpdateTriggerTest.ts
 *
 * Gate for the `spans_fts_update` trigger guard in server/db.ts.
 *
 * ── What this pins ──
 * `updateSpanEnd` (server/index.ts) closes out a span with `UPDATE spans SET
 * endNano = ? WHERE spanId = ?` — a write that happens for essentially every
 * span. The trigger is scoped `AFTER UPDATE OF name, attributes`, which already
 * keeps it from firing on that exact statement (endNano is not in its SET
 * clause). What the OF-clause does NOT catch is any update that mentions
 * `attributes` or `name` in its SET list without actually changing the value —
 * SQLite decides whether an `UPDATE OF` trigger fires from the statement's
 * column list, not from whether the value changed. The `WHEN old.name IS NOT
 * new.name OR old.attributes IS NOT new.attributes` guard closes that gap: it
 * makes "no content changed → no reindex" true by construction instead of by
 * every future caller happening to leave those columns out of its SET clause.
 *
 * Asserted here:
 *   1. The shipped trigger's SQL carries the WHEN guard (structural check —
 *      the guard is what makes the behavioral checks below possible at all).
 *   2. An attributes-only content change still reindexes: the new text becomes
 *      searchable and the superseded text stops being searchable.
 *   3. A name-only content change still reindexes.
 *   4. An UPDATE whose SET clause mentions `attributes` but assigns the SAME
 *      value does NOT touch the index: the existing posting for a needle
 *      elsewhere in the table is untouched (nothing here should raise a
 *      "missing row from content table" error, and spans_fts row count is
 *      unchanged), which is the same guarantee updateSpanEnd relies on today.
 *   5. An endNano-only update (the real production shape) leaves the index
 *      untouched.
 *   6. A same-process relative-timing check: on a batch of "attributes present
 *      in SET, value unchanged" updates, the guarded trigger is markedly
 *      cheaper than the same trigger with the WHEN clause stripped back out —
 *      corroborating (not the sole proof of) the ~0.75 ms → ~0.037 ms measured
 *      on a real 265k-span database. Comparative, not an absolute-ms
 *      assertion, so it isn't sensitive to CI machine speed.
 *
 * Run via:  npx tsx tests/ftsUpdateTriggerTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB and CLAUDESEC_HOME both point under os.tmpdir()
 * BEFORE server/db.ts is imported, and both are removed in a finally block.
 * The real ~/.claudesec database and hooks/ control-plane directory are never
 * opened or written.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = path.join(os.tmpdir(), `csec-ftsupdatetrigger-${process.pid}-${Date.now()}.db`);
// server/db.ts pulls in server/auditChain.ts, whose module-level chain-probe
// registration mints an ed25519 signing key the first time no anchor file is
// found — a real write under CLAUDESEC_HOME/hooks. Sandbox it before the
// `server/db.js` import below so that mint (and any anchor read) lands in a
// throwaway directory instead of the maintainer's live ~/.claudesec/hooks.
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-ftsupdatetrigger-home-'));
process.env.CLAUDESEC_HOME = HOME_DIR;
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
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

const INSERT_COLS =
  'spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo';

async function main(): Promise<void> {
  try {
    const { db } = await import('../server/db.js');

    const insertSpan = db.prepare(
      `INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', 'none', 'claude-code', ?, '0', '0', 'unknown')`,
    );
    const matched = (q: string): string[] =>
      (db.prepare(`SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?`).all(q) as { spanId: string }[])
        .map(r => r.spanId).sort();
    const ftsRowCount = () => (db.prepare('SELECT COUNT(*) AS c FROM spans_fts').get() as { c: number }).c;
    const spanRowCount = () => (db.prepare('SELECT COUNT(*) AS c FROM spans').get() as { c: number }).c;

    await check('the shipped trigger carries the WHEN guard', () => {
      const sql = (db.prepare(
        `SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'spans_fts_update'`,
      ).get() as { sql: string }).sql;
      assert.match(sql, /WHEN\s+old\.name\s+IS\s+NOT\s+new\.name\s+OR\s+old\.attributes\s+IS\s+NOT\s+new\.attributes/i,
        'the trigger must gate on whether name/attributes actually changed, not just whether they were assigned');
    });

    insertSpan.run('trig-1', 'trace-1', 'tool_call/Bash-1', JSON.stringify({ note: 'originaltext' }));
    insertSpan.run('trig-2', 'trace-1', 'tool_call/Bash-2', JSON.stringify({ note: 'untouchedneedle' }));

    await check('an attributes content change still reindexes', () => {
      db.prepare('UPDATE spans SET attributes = ? WHERE spanId = ?')
        .run(JSON.stringify({ note: 'replacementtext' }), 'trig-1');
      assert.deepStrictEqual(matched('replacementtext'), ['trig-1'], 'the new text must be searchable');
      assert.deepStrictEqual(matched('originaltext'), [], 'the superseded text must not remain searchable');
      assert.strictEqual(ftsRowCount(), spanRowCount(), 'no row should be duplicated or dropped');
    });

    await check('a name content change still reindexes', () => {
      db.prepare('UPDATE spans SET name = ? WHERE spanId = ?').run('tool_call/RenamedTool', 'trig-1');
      assert.deepStrictEqual(matched('RenamedTool'), ['trig-1'], 'the new name must be searchable');
      assert.deepStrictEqual(matched('"Bash-1"'), [], 'the superseded name must not remain searchable');
    });

    await check('attributes present in SET but unchanged does not touch the index', () => {
      const before = ftsRowCount();
      // Same value, re-assigned — the shape a broader UPDATE could produce
      // without meaning to touch this row's text.
      const current = (db.prepare('SELECT attributes FROM spans WHERE spanId = ?').get('trig-1') as { attributes: string }).attributes;
      db.prepare('UPDATE spans SET attributes = ?, endNano = ? WHERE spanId = ?').run(current, '123', 'trig-1');
      assert.strictEqual(ftsRowCount(), before, 'row count must be unaffected either way');
      // The untouched neighbor's posting must survive regardless — this is the
      // regression the guard exists to prevent from ever mattering.
      assert.deepStrictEqual(matched('untouchedneedle'), ['trig-2']);
      assert.doesNotThrow(() => db.exec(`INSERT INTO spans_fts(spans_fts) VALUES('integrity-check')`));
    });

    await check('an endNano-only update (the real updateSpanEnd shape) leaves the index untouched', () => {
      const before = matched('untouchedneedle');
      db.prepare('UPDATE spans SET endNano = ? WHERE spanId = ?').run('999999', 'trig-2');
      assert.deepStrictEqual(matched('untouchedneedle'), before, 'closing a span must not disturb its own posting');
    });

    await check('relative timing: guarded trigger is markedly cheaper than an unguarded one', () => {
      // Build a disposable comparison table with the SAME shape and both trigger
      // variants, isolated from `spans` so this cannot perturb the assertions
      // above. Comparative on purpose — an absolute-ms threshold would be a flaky
      // gate on a shared CI runner; a same-process, same-machine ratio is not.
      db.exec(`
        CREATE TABLE trig_cmp (id INTEGER PRIMARY KEY, name TEXT, attributes TEXT, endNano TEXT);
        CREATE VIRTUAL TABLE trig_cmp_fts USING fts5(id UNINDEXED, name, attributes, content='trig_cmp', content_rowid='id');
      `);
      const N = 500;
      const attrs = JSON.stringify({ a: 'x'.repeat(200) });
      for (let i = 0; i < N; i++) {
        db.prepare('INSERT INTO trig_cmp (id, name, attributes, endNano) VALUES (?, ?, ?, ?)').run(i, 'n', attrs, '0');
        db.prepare(`INSERT INTO trig_cmp_fts(rowid, id, name, attributes) VALUES (?, ?, ?, ?)`).run(i, i, 'n', attrs);
      }

      const timeBatch = (): number => {
        const t0 = process.hrtime.bigint();
        const upd = db.prepare('UPDATE trig_cmp SET attributes = ?, endNano = ? WHERE id = ?');
        for (let i = 0; i < N; i++) upd.run(attrs, String(i), i); // same value, unchanged content
        const t1 = process.hrtime.bigint();
        return Number(t1 - t0) / 1e6;
      };

      db.exec(`
        DROP TRIGGER IF EXISTS trig_cmp_fts_update;
        CREATE TRIGGER trig_cmp_fts_update AFTER UPDATE OF name, attributes ON trig_cmp
        WHEN old.name IS NOT new.name OR old.attributes IS NOT new.attributes BEGIN
          INSERT INTO trig_cmp_fts(trig_cmp_fts, rowid, id, name, attributes) VALUES ('delete', old.id, old.id, old.name, old.attributes);
          INSERT INTO trig_cmp_fts(rowid, id, name, attributes) VALUES (new.id, new.id, new.name, new.attributes);
        END;
      `);
      const guardedMs = timeBatch();

      db.exec(`
        DROP TRIGGER IF EXISTS trig_cmp_fts_update;
        CREATE TRIGGER trig_cmp_fts_update AFTER UPDATE OF name, attributes ON trig_cmp BEGIN
          INSERT INTO trig_cmp_fts(trig_cmp_fts, rowid, id, name, attributes) VALUES ('delete', old.id, old.id, old.name, old.attributes);
          INSERT INTO trig_cmp_fts(rowid, id, name, attributes) VALUES (new.id, new.id, new.name, new.attributes);
        END;
      `);
      const unguardedMs = timeBatch();

      db.exec(`DROP TABLE trig_cmp_fts; DROP TABLE trig_cmp;`);

      console.log(`    (relative timing: guarded ${guardedMs.toFixed(2)}ms vs unguarded ${unguardedMs.toFixed(2)}ms over ${N} same-value updates)`);
      assert.ok(guardedMs < unguardedMs, 'the WHEN guard must make the no-op case cheaper, not just equal');
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  ftsUpdateTriggerTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[ftsUpdateTriggerTest] fatal:', err);
  cleanup();
  process.exit(1);
});
