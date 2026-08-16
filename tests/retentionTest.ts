/**
 * tests/retentionTest.ts
 *
 * Gate for the retention / pruning policy (CLAUDESEC_MAX_SPANS count-based prune
 * + CLAUDESEC_RETENTION_DAYS age-based prune).
 *
 * Run via:  npx tsx tests/retentionTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 *
 * ── Why this test reimplements the SQL instead of importing pruneSpans() ──
 * pruneSpans() lives INSIDE server/index.ts and closes over module-level
 * singletons (`db`, `getConfig`, `getMaxSpans`, `getRetentionDays`). It is not
 * exported, and importing index.ts has heavy side effects: it opens the live DB,
 * binds a port, starts the transcript watcher, and registers timers. There is no
 * seam to inject a test DB handle.
 *
 * So this test pins the *behavioural contract* of the two prune queries against
 * a throwaway temp SQLite DB seeded with synthetic spans/sessions. The SQL below
 * is copied verbatim from server/index.ts pruneSpans() (age-based session sweep
 * + count-based delete of the oldest *out-of-window* spans by startNano). If the
 * production query changes, this copy must change with it — see REFACTOR note in
 * the summary.
 *
 * ── Age floor takes precedence over the count cap (compliance) ──
 * Count-based pruning must NEVER evict a span that is still inside the retention
 * window. Retention is a hard floor (EU AI Act: keep 6 months); the count cap is
 * a soft ceiling that only ever reclaims rows that are ALSO past the age cutoff.
 * Consequence: when in-window data alone exceeds CLAUDESEC_MAX_SPANS the DB is
 * allowed to exceed the count cap — the floor wins. Age-based pruning is what
 * actually bounds growth.
 *
 * DB DISCIPLINE: a fresh DB is created under os.tmpdir() and deleted in a
 * finally block. The maintainer's real ~/.claudesec/spans.db is NEVER opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import Database from 'better-sqlite3';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Schema + prune logic mirror (kept in lock-step with server/index.ts).
// ---------------------------------------------------------------------------

function createSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE spans (
      spanId    TEXT PRIMARY KEY,
      traceId   TEXT NOT NULL DEFAULT 'unknown',
      name      TEXT NOT NULL DEFAULT '',
      severity  TEXT NOT NULL DEFAULT 'none',
      startNano TEXT NOT NULL DEFAULT '0'
    );
    CREATE TABLE sessions (
      traceId   TEXT PRIMARY KEY,
      name      TEXT NOT NULL DEFAULT '',
      createdAt TEXT NOT NULL
    );
    CREATE TABLE alerts (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      traceId TEXT NOT NULL,
      ts      TEXT NOT NULL DEFAULT ''
    );
  `);
}

/**
 * Verbatim mirror of server/index.ts pruneSpans(), parameterised on the DB
 * handle + the two retention knobs (which in production come from env/config).
 */
function pruneSpans(
  db: Database.Database,
  retentionDays: number,
  maxSpans: number,
): { prunedByAge: number; prunedByCount: number } {
  let prunedByAge = 0;
  let prunedByCount = 0;

  // Age-based: drop sessions (and their spans/alerts) older than N days.
  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const oldSessions = db.prepare(
    `SELECT traceId FROM sessions WHERE createdAt < ?`,
  ).all(cutoffDate) as { traceId: string }[];

  for (const { traceId } of oldSessions) {
    const deleted = db.prepare(`DELETE FROM spans WHERE traceId = ?`).run(traceId).changes;
    db.prepare(`DELETE FROM alerts WHERE traceId = ?`).run(traceId);
    db.prepare(`DELETE FROM sessions WHERE traceId = ?`).run(traceId);
    prunedByAge += deleted;
  }

  // Count-based: reclaim the oldest spans down to maxSpans, but NEVER evict a
  // span still inside the retention window. The age floor (above) is a hard
  // compliance floor; the count cap is a soft ceiling that may only reclaim rows
  // whose own startNano is already past the cutoff. When in-window data alone
  // exceeds maxSpans the DB is allowed to stay over the cap — the floor wins.
  // startNano is a Unix-epoch *nanosecond* timestamp; compare numerically.
  const cutoffNano = String((Date.now() - retentionDays * 24 * 60 * 60 * 1000) * 1e6);
  const totalSpans = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as { c: number }).c;
  if (totalSpans > maxSpans) {
    const excess = totalSpans - maxSpans;
    const result = db.prepare(
      `DELETE FROM spans WHERE rowid IN (
         SELECT rowid FROM spans
         WHERE CAST(startNano AS INTEGER) < CAST(? AS INTEGER)
         ORDER BY startNano ASC LIMIT ?
       )`,
    ).run(cutoffNano, excess);
    prunedByCount = result.changes;
  }

  return { prunedByAge, prunedByCount };
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function daysAgoIso(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

// startNano is a Unix-epoch nanosecond timestamp (string). Produce realistic
// values so the count cap's age-floor (startNano vs cutoff) can be exercised.
function daysAgoNano(days: number): string {
  return String((Date.now() - days * 24 * 60 * 60 * 1000) * 1e6);
}

function seedSession(db: Database.Database, traceId: string, createdAt: string): void {
  db.prepare(`INSERT INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)`)
    .run(traceId, traceId, createdAt);
}

function seedSpan(db: Database.Database, spanId: string, traceId: string, startNano: string): void {
  db.prepare(`INSERT INTO spans (spanId, traceId, startNano) VALUES (?, ?, ?)`)
    .run(spanId, traceId, startNano);
}

function countSpans(db: Database.Database): number {
  return (db.prepare('SELECT COUNT(*) as c FROM spans').get() as { c: number }).c;
}

// Truncate all three tables between cases. Uses prepared statements (not a
// multi-statement batch) so each table reset is an isolated, parameter-free run.
function resetTables(db: Database.Database): void {
  for (const t of ['spans', 'sessions', 'alerts']) {
    db.prepare(`DELETE FROM ${t}`).run();
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

const tmpFile = path.join(
  os.tmpdir(),
  `csec-retention-${process.pid}-${Date.now()}.db`,
);

// Sandbox the home dir too: should this test ever import server/index.ts, that
// module mirrors the enforce mode to <CLAUDESEC_HOME>/hooks/enforce-config.json
// at load. Pointing CLAUDESEC_HOME at a throwaway temp dir guarantees the real
// ~/.claudesec/hooks is never touched. Set before any server-side import.
process.env.CLAUDESEC_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-retention-home-'));
const HOME_DIR = process.env.CLAUDESEC_HOME;

function cleanup(): void {
  for (const f of [tmpFile, `${tmpFile}-wal`, `${tmpFile}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

try {
  const db = new Database(tmpFile);
  try {
    db.pragma('journal_mode = WAL');
    createSchema(db);

    // ── Age-based pruning ──────────────────────────────────────────────────
    // Two old sessions (40 + 45 days), one fresh (1 day). Retention window 30d.
    db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
    seedSession(db, 'old-a', daysAgoIso(40));
    seedSession(db, 'old-b', daysAgoIso(45));
    seedSession(db, 'fresh', daysAgoIso(1));
    seedSpan(db, 'sa1', 'old-a', '1000');
    seedSpan(db, 'sa2', 'old-a', '1001');
    seedSpan(db, 'sb1', 'old-b', '1002');
    seedSpan(db, 'sf1', 'fresh', '9000');
    db.prepare(`INSERT INTO alerts (traceId, ts) VALUES (?, ?)`).run('old-a', daysAgoIso(40));

    check('age prune removes only spans from sessions older than the window', () => {
      const { prunedByAge } = pruneSpans(db, 30, 100_000);
      assert.strictEqual(prunedByAge, 3, `expected 3 aged spans removed, got ${prunedByAge}`);
      assert.strictEqual(countSpans(db), 1, 'only the fresh span should remain');
    });
    check('age prune cascades to sessions and alerts', () => {
      const sessions = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as { c: number }).c;
      const alerts = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as { c: number }).c;
      assert.strictEqual(sessions, 1, 'old sessions should be deleted');
      assert.strictEqual(alerts, 0, 'alerts for old sessions should be deleted');
    });

    // ── Age floor wins over the count cap (compliance) ─────────────────────
    // 10 spans, all timestamped 1 day ago — well inside a 30d window. Cap at 4.
    // The count cap must NOT evict in-window data: prunedByCount === 0 and the
    // DB is allowed to stay over the cap. This is the EU AI Act floor in action.
    resetTables(db);
    seedSession(db, 'live', daysAgoIso(1));
    for (let i = 0; i < 10; i++) {
      seedSpan(db, `c${i}`, 'live', daysAgoNano(1));
    }

    check('count prune NEVER evicts spans inside the retention window', () => {
      const { prunedByAge, prunedByCount } = pruneSpans(db, 30, 4);
      assert.strictEqual(prunedByAge, 0, 'nothing is past the age cutoff');
      assert.strictEqual(prunedByCount, 0, `in-window spans must survive the cap, got ${prunedByCount}`);
      assert.strictEqual(countSpans(db), 10, 'the DB stays over the cap — the age floor wins');
    });

    // ── Count-based pruning of OLD spans ───────────────────────────────────
    // 10 spans all timestamped ~40 days ago (past a 30d window). Cap at 4 → the
    // 6 oldest out-of-window spans are reclaimed, newest 4 kept. This is the
    // count cap doing its real job: trimming aged overflow that the session
    // sweep didn't cover, without ever touching in-window data.
    resetTables(db);
    for (let i = 0; i < 10; i++) {
      // Strictly increasing nanos so "oldest" is well-defined. All > 30 days old.
      seedSpan(db, `o${i}`, 'gone', daysAgoNano(40 - i * 0.1));
    }

    check('count prune reclaims the excess OLDEST out-of-window spans', () => {
      const { prunedByCount } = pruneSpans(db, 30, 4);
      assert.strictEqual(prunedByCount, 6, `expected 6 aged-overflow spans removed, got ${prunedByCount}`);
      assert.strictEqual(countSpans(db), 4, 'should keep exactly maxSpans of the out-of-window data');
    });
    check('count prune keeps the NEWEST out-of-window spans', () => {
      const remaining = (db.prepare('SELECT spanId FROM spans ORDER BY startNano ASC').all() as { spanId: string }[])
        .map(r => r.spanId);
      assert.deepStrictEqual(remaining, ['o6', 'o7', 'o8', 'o9'], `kept wrong spans: ${remaining.join(',')}`);
    });

    // ── Mixed in-window + out-of-window, over cap ──────────────────────────
    // 6 stale (out-of-window) + 6 fresh (in-window) = 12 spans, cap at 4. Only
    // the 6 stale are eligible; the 6 fresh are protected by the age floor. The
    // cap wants to drop 8, but only 6 are eligible → 6 removed, DB lands at 6
    // (all fresh), still over the cap. The floor wins.
    resetTables(db);
    for (let i = 0; i < 6; i++) seedSpan(db, `s${i}`, 'mix', daysAgoNano(40 - i * 0.1));
    for (let i = 0; i < 6; i++) seedSpan(db, `f${i}`, 'mix', daysAgoNano(1));

    check('count prune trims only the out-of-window tail, keeps in-window over cap', () => {
      const { prunedByCount } = pruneSpans(db, 30, 4);
      assert.strictEqual(prunedByCount, 6, `only the 6 stale spans are eligible, got ${prunedByCount}`);
      assert.strictEqual(countSpans(db), 6, 'the 6 in-window spans survive even above the cap');
      const remaining = (db.prepare('SELECT spanId FROM spans ORDER BY spanId ASC').all() as { spanId: string }[])
        .map(r => r.spanId);
      assert.deepStrictEqual(remaining, ['f0', 'f1', 'f2', 'f3', 'f4', 'f5'], `wrong survivors: ${remaining.join(',')}`);
    });

    // ── No-op cases ────────────────────────────────────────────────────────
    check('under capacity + all-fresh is a no-op', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions;');
      seedSession(db, 'ok', daysAgoIso(2));
      seedSpan(db, 'k1', 'ok', '000100');
      seedSpan(db, 'k2', 'ok', '000200');
      const { prunedByAge, prunedByCount } = pruneSpans(db, 30, 100_000);
      assert.strictEqual(prunedByAge, 0);
      assert.strictEqual(prunedByCount, 0);
      assert.strictEqual(countSpans(db), 2);
    });

    check('count prune at exact capacity is a no-op (> not >=)', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions;');
      seedSession(db, 'cap', daysAgoIso(0));
      seedSpan(db, 'e1', 'cap', '000001');
      seedSpan(db, 'e2', 'cap', '000002');
      const { prunedByCount } = pruneSpans(db, 30, 2);
      assert.strictEqual(prunedByCount, 0, 'exactly at cap must not prune');
      assert.strictEqual(countSpans(db), 2);
    });
  } finally {
    db.close();
  }
} finally {
  cleanup();
}

// ---------------------------------------------------------------------------
// Report + exit
// ---------------------------------------------------------------------------

const total = passed + failed;
console.log('───────────────────────────────────────────────');
console.log(`  retentionTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failed > 0) {
  console.error(`\n  ${failed} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
