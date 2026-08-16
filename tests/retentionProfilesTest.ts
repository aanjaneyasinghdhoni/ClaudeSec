/**
 * tests/retentionProfilesTest.ts
 *
 * Gate for retention PROFILES — the two retention knobs treated as one policy.
 *
 * Run via:  npx tsx tests/retentionProfilesTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 *
 * ── What this pins, and why it exists ──
 * The shipped defaults were 183 days and 50,000 spans. Pruning itself was never
 * the problem: count-based pruning may only reclaim spans that are ALREADY past
 * the age cutoff, so the day window is a hard floor. The damage landed on the
 * ingest path instead — the capacity circuit breaker stops OTLP ingestion at 90%
 * of the span ceiling, and with a ceiling smaller than the window's own volume
 * NOTHING is ever prunable to relieve it. Measured against real usage
 * (~3,545 spans/day), the "six month" default stopped recording on about day 12
 * and never restarted.
 *
 * So the assertions below cover three things:
 *   1. Each profile prunes exactly as documented (and Forensic prunes nothing).
 *   2. The effective-window calculation is right at a stated ingest rate — the
 *      shipped defaults are proven to deliver ~12 days, and each profile is
 *      proven to deliver its full window at that same rate.
 *   3. An existing configuration survives the upgrade untouched.
 *
 * Unlike tests/retentionTest.ts (which mirrors prune SQL that lives inside
 * server/index.ts and cannot be imported), the profile logic lives in a pure
 * module, so this test imports the REAL implementation. Only the prune SQL is
 * mirrored, and it is kept in lock-step with server/index.ts pruneSpans().
 *
 * DB DISCIPLINE: every database is created under os.tmpdir() and removed in a
 * finally block. The maintainer's real ~/.claudesec/spans.db is NEVER opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import Database from 'better-sqlite3';

// Sandbox the home dir before ANY server-side import: server modules mirror
// config into <CLAUDESEC_HOME>/hooks at load time, and the real ~/.claudesec
// must never be touched by a test run.
process.env.CLAUDESEC_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-retprofiles-home-'));
const HOME_DIR = process.env.CLAUDESEC_HOME;
const DB_FILE = path.join(os.tmpdir(), `csec-retprofiles-${process.pid}-${Date.now()}.db`);
process.env.CLAUDESEC_DB = DB_FILE;

const {
  RETENTION_PROFILES,
  RETENTION_UNBOUNDED,
  INGEST_BREAKER_RATIO,
  DEFAULT_MAX_SPANS,
  DEFAULT_RETENTION_DAYS,
  describeRetention,
  identifyProfile,
  observedSpansPerDay,
  parseRetentionValue,
  resolveKnob,
  resolveRetention,
  retentionProfile,
} = await import('../server/retentionProfiles.js');

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
// Fixtures
// ---------------------------------------------------------------------------

/** The rate measured on a real install: 269,386 spans over 76 days of use. */
const MEASURED_SPANS_PER_DAY = 3_545;

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
    CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);
}

const daysAgoIso = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString();
const daysAgoNano = (d: number) => String((Date.now() - d * 86_400_000) * 1e6);

/** One session `ageDays` old carrying `spans` spans stamped at the same age. */
function seed(db: Database.Database, traceId: string, ageDays: number, spans: number): void {
  db.prepare('INSERT OR REPLACE INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)')
    .run(traceId, traceId, daysAgoIso(ageDays));
  const insert = db.prepare('INSERT OR REPLACE INTO spans (spanId, traceId, startNano) VALUES (?, ?, ?)');
  const nano = daysAgoNano(ageDays);
  const many = db.transaction((n: number) => {
    for (let i = 0; i < n; i++) insert.run(`${traceId}-${i}`, traceId, nano);
  });
  many(spans);
}

/**
 * Verbatim mirror of server/index.ts pruneSpans(), parameterised on the DB
 * handle and the two knobs. Includes the unbounded (Forensic) short-circuits.
 * If the production query changes, this copy must change with it.
 */
function pruneSpans(
  db: Database.Database,
  retentionDays: number,
  maxSpans: number,
): { prunedByAge: number; prunedByCount: number } {
  let prunedByAge = 0;
  let prunedByCount = 0;

  if (retentionDays === RETENTION_UNBOUNDED) return { prunedByAge, prunedByCount };

  const cutoffDate = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
  for (const { traceId } of db.prepare('SELECT traceId FROM sessions WHERE createdAt < ?').all(cutoffDate) as { traceId: string }[]) {
    prunedByAge += db.prepare('DELETE FROM spans WHERE traceId = ?').run(traceId).changes;
    db.prepare('DELETE FROM alerts WHERE traceId = ?').run(traceId);
    db.prepare('DELETE FROM sessions WHERE traceId = ?').run(traceId);
  }

  const cutoffNano = String((Date.now() - retentionDays * 86_400_000) * 1e6);
  const totalSpans = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as { c: number }).c;
  if (maxSpans !== RETENTION_UNBOUNDED && totalSpans > maxSpans) {
    prunedByCount = db.prepare(
      `DELETE FROM spans WHERE rowid IN (
         SELECT rowid FROM spans
         WHERE CAST(startNano AS INTEGER) < CAST(? AS INTEGER)
         ORDER BY startNano ASC LIMIT ?
       )`,
    ).run(cutoffNano, totalSpans - maxSpans).changes;
  }

  return { prunedByAge, prunedByCount };
}

/** Mirror of server/index.ts ingestCapacityExhausted() — the OTLP 503 gate. */
const ingestBlocked = (currentSpans: number, maxSpans: number) =>
  maxSpans !== RETENTION_UNBOUNDED && currentSpans >= maxSpans * INGEST_BREAKER_RATIO;

const countSpans = (db: Database.Database) =>
  (db.prepare('SELECT COUNT(*) as c FROM spans').get() as { c: number }).c;

function cleanup(): void {
  for (const f of [DB_FILE, `${DB_FILE}-wal`, `${DB_FILE}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

try {
  const db = new Database(DB_FILE);
  try {
    db.pragma('journal_mode = WAL');
    createSchema(db);

    // ── 1. The bug this work exists to fix ────────────────────────────────
    check('REGRESSION: the old 183d/50k defaults stop ingestion ~12 days in and pruning cannot help', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      // 13 days of real-rate traffic, all inside a 183-day window.
      for (let d = 0; d < 13; d++) seed(db, `day-${d}`, d, 3_545);
      const total = countSpans(db);
      assert.ok(total > 45_000, `13 days at the measured rate should exceed 45,000 spans (got ${total})`);

      const { prunedByAge, prunedByCount } = pruneSpans(db, 183, 50_000);
      assert.strictEqual(prunedByAge, 0, 'nothing is 183 days old yet');
      assert.strictEqual(prunedByCount, 0, 'count pruning may not touch in-window spans');
      assert.ok(ingestBlocked(countSpans(db), 50_000), 'the ingest breaker latches shut with no prunable data');

      // Same data, the new default ceiling: ingestion keeps flowing.
      assert.ok(!ingestBlocked(countSpans(db), DEFAULT_MAX_SPANS), 'the Minimum profile keeps ingesting');
    });

    // ── 2. Each profile prunes as documented ──────────────────────────────
    check('Minimum keeps the full 183-day window and drops what falls out of it', () => {
      const p = RETENTION_PROFILES.minimum;
      assert.strictEqual(p.days, 183);
      assert.strictEqual(p.maxSpans, 1_000_000);
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      seed(db, 'in-window', 182, 500);     // one day inside the floor
      seed(db, 'just-out',  184, 500);     // one day past it
      const { prunedByAge } = pruneSpans(db, p.days, p.maxSpans);
      assert.strictEqual(prunedByAge, 500, 'only the out-of-window session is dropped');
      assert.strictEqual(countSpans(db), 500);
      assert.ok(!ingestBlocked(countSpans(db), p.maxSpans));
    });

    check('Minimum holds its window at the measured rate without tripping the breaker', () => {
      const p = RETENTION_PROFILES.minimum;
      const projected = p.days * MEASURED_SPANS_PER_DAY;             // ~649,000 spans
      assert.ok(
        projected < p.maxSpans * INGEST_BREAKER_RATIO,
        `183 days of traffic (${projected}) must fit under the ${p.maxSpans * INGEST_BREAKER_RATIO} breaker`,
      );
    });

    check('Audit year keeps 400 days — a year plus a tail — and holds it at the measured rate', () => {
      const p = RETENTION_PROFILES['audit-year'];
      assert.strictEqual(p.days, 400);
      assert.strictEqual(p.maxSpans, 5_000_000);
      assert.ok(p.days > 365, 'must extend past a bare year so day one is still there at audit time');
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      seed(db, 'day-365', 365, 100);   // the day an auditor samples
      seed(db, 'day-420', 420, 100);   // genuinely expired
      const { prunedByAge } = pruneSpans(db, p.days, p.maxSpans);
      assert.strictEqual(prunedByAge, 100, 'only the 420-day-old session expires');
      assert.strictEqual(countSpans(db), 100, 'the 365-day-old session survives');
      assert.ok(400 * MEASURED_SPANS_PER_DAY < p.maxSpans * INGEST_BREAKER_RATIO);
    });

    check('Forensic prunes nothing, ever, and never blocks ingestion', () => {
      const p = RETENTION_PROFILES.forensic;
      assert.strictEqual(p.days, RETENTION_UNBOUNDED);
      assert.strictEqual(p.maxSpans, RETENTION_UNBOUNDED);
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      seed(db, 'ancient', 5_000, 200);
      const { prunedByAge, prunedByCount } = pruneSpans(db, p.days, p.maxSpans);
      assert.strictEqual(prunedByAge, 0);
      assert.strictEqual(prunedByCount, 0);
      assert.strictEqual(countSpans(db), 200, 'a 14-year-old span is still kept');
      assert.ok(!ingestBlocked(50_000_000, p.maxSpans), 'no ceiling means no breaker');
    });

    check('the count cap still reclaims out-of-window spans (the ceiling is not inert)', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      // Spans stamped 200 days ago but attached to a session created recently,
      // so age pruning (which sweeps by session) leaves them for the count cap.
      db.prepare('INSERT INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)')
        .run('recent-session', 'recent', daysAgoIso(1));
      const insert = db.prepare('INSERT INTO spans (spanId, traceId, startNano) VALUES (?, ?, ?)');
      for (let i = 0; i < 300; i++) insert.run(`old-${i}`, 'recent-session', daysAgoNano(200));
      const { prunedByCount } = pruneSpans(db, 183, 100);
      assert.strictEqual(prunedByCount, 200, 'reclaims down to the ceiling from out-of-window rows only');
      assert.strictEqual(countSpans(db), 100);
    });

    // ── 3. The effective-window calculation ───────────────────────────────
    check('effective window at the measured rate: the old defaults deliver ~12 days, not 183', () => {
      const d = describeRetention({ retentionDays: 183, maxSpans: 50_000, spansPerDay: MEASURED_SPANS_PER_DAY });
      assert.strictEqual(d.limitingFactor, 'capacity');
      assert.strictEqual(d.ingestStopsAtSpans, 45_000);
      assert.strictEqual(d.effectiveWindowDays, Math.floor(45_000 / MEASURED_SPANS_PER_DAY)); // 12
      assert.strictEqual(d.effectiveWindowDays, 12);
      assert.strictEqual(d.projectedSpansInWindow, 183 * MEASURED_SPANS_PER_DAY);
      assert.ok(d.warning && d.warning.includes('12 days'), 'the warning must state the real window');
      assert.ok(d.warning!.includes('183'), 'and contrast it with the configured window');
    });

    check('effective window at the measured rate: Minimum delivers its full 183 days', () => {
      const p = RETENTION_PROFILES.minimum;
      const d = describeRetention({ retentionDays: p.days, maxSpans: p.maxSpans, spansPerDay: MEASURED_SPANS_PER_DAY });
      assert.strictEqual(d.profile, 'minimum');
      assert.strictEqual(d.limitingFactor, 'age');
      assert.strictEqual(d.effectiveWindowDays, 183);
      assert.strictEqual(d.warning, null, 'a coherent policy raises no warning');
    });

    check('effective window at the measured rate: Audit year delivers its full 400 days', () => {
      const p = RETENTION_PROFILES['audit-year'];
      const d = describeRetention({ retentionDays: p.days, maxSpans: p.maxSpans, spansPerDay: MEASURED_SPANS_PER_DAY });
      assert.strictEqual(d.profile, 'audit-year');
      assert.strictEqual(d.limitingFactor, 'age');
      assert.strictEqual(d.effectiveWindowDays, 400);
      assert.strictEqual(d.warning, null);
    });

    check('Minimum still holds at 4,900 spans/day and gives way above it', () => {
      const p = RETENTION_PROFILES.minimum;
      const ok = describeRetention({ retentionDays: p.days, maxSpans: p.maxSpans, spansPerDay: 4_900 });
      assert.strictEqual(ok.limitingFactor, 'age', 'the stated headroom must be real');
      const over = describeRetention({ retentionDays: p.days, maxSpans: p.maxSpans, spansPerDay: 6_000 });
      assert.strictEqual(over.limitingFactor, 'capacity', 'and beyond it the user must be warned');
      assert.ok(over.warning);
    });

    check('Forensic reports no limiting factor and no window', () => {
      const p = RETENTION_PROFILES.forensic;
      const d = describeRetention({ retentionDays: p.days, maxSpans: p.maxSpans, spansPerDay: MEASURED_SPANS_PER_DAY });
      assert.strictEqual(d.profile, 'forensic');
      assert.strictEqual(d.limitingFactor, 'none');
      assert.strictEqual(d.effectiveWindowDays, null);
      assert.strictEqual(d.retentionDays, null);
      assert.strictEqual(d.maxSpans, null);
    });

    check('an unbounded window with a finite ceiling is reported as capacity-limited', () => {
      const d = describeRetention({ retentionDays: RETENTION_UNBOUNDED, maxSpans: 100_000, spansPerDay: 1_000 });
      assert.strictEqual(d.limitingFactor, 'capacity');
      assert.strictEqual(d.effectiveWindowDays, 90);
      assert.ok(d.warning && d.warning.includes('Forensic'), 'must point at the profile that removes the ceiling');
    });

    check('no measured rate → no invented window', () => {
      const d = describeRetention({ retentionDays: 183, maxSpans: 50_000, spansPerDay: null });
      assert.strictEqual(d.limitingFactor, 'unknown');
      assert.strictEqual(d.spansPerDay, null);
      assert.strictEqual(d.warning, null, 'never warn on a guess');
    });

    check('a custom pair is reported as custom, never rounded to a nearby profile', () => {
      assert.strictEqual(identifyProfile(365, 5_000_000), 'custom');
      assert.strictEqual(identifyProfile(183, 1_000_000), 'minimum');
      assert.strictEqual(identifyProfile(400, 5_000_000), 'audit-year');
      assert.strictEqual(identifyProfile(0, 0), 'forensic');
      assert.strictEqual(retentionProfile('nonsense'), null);
    });

    // ── 4. Measuring the ingest rate ──────────────────────────────────────
    check('observedSpansPerDay measures a seeded rate within tolerance', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      for (let d = 0; d < 10; d++) seed(db, `rate-${d}`, d, 200);   // 200/day over 10 days
      const { spansPerDay, sampleSpans } = observedSpansPerDay(db);
      assert.strictEqual(sampleSpans, 2_000);
      assert.ok(spansPerDay !== null && Math.abs(spansPerDay - 200) <= 30, `expected ~200/day, got ${spansPerDay}`);
    });

    check('observedSpansPerDay returns null on a database too small to extrapolate from', () => {
      db.exec('DELETE FROM spans; DELETE FROM sessions; DELETE FROM alerts;');
      seed(db, 'tiny', 1, 5);
      assert.strictEqual(observedSpansPerDay(db).spansPerDay, null);
    });

    // ── 5. Migration: existing configuration is preserved ─────────────────
    check('a fresh install gets the Minimum profile', () => {
      const status = resolveRetention({ env: {}, readConfig: () => undefined, db });
      assert.strictEqual(status.configured.retentionDays, DEFAULT_RETENTION_DAYS);
      assert.strictEqual(status.configured.maxSpans, DEFAULT_MAX_SPANS);
      assert.strictEqual(status.profile, 'minimum');
      assert.strictEqual(status.sources.retentionDays, 'default');
      assert.strictEqual(status.sources.maxSpans, 'default');
    });

    check('MIGRATION: an existing configuration survives untouched and is simply re-described', () => {
      // The values a real install already had in its config table.
      const stored: Record<string, string> = { 'retention.days': '365', 'retention.max_spans': '5000000' };
      const status = resolveRetention({ env: {}, readConfig: (k) => stored[k], db });
      assert.strictEqual(status.configured.retentionDays, 365, 'the saved window must not move');
      assert.strictEqual(status.configured.maxSpans, 5_000_000, 'the saved ceiling must not move');
      assert.strictEqual(status.sources.retentionDays, 'config');
      assert.strictEqual(status.sources.maxSpans, 'config');
      assert.strictEqual(status.profile, 'custom', 'reported through the new lens, not rewritten');
      // Still coherent, so the user is not nagged about a configuration that works.
      assert.strictEqual(
        describeRetention({ retentionDays: 365, maxSpans: 5_000_000, spansPerDay: MEASURED_SPANS_PER_DAY }).limitingFactor,
        'age',
      );
    });

    check('MIGRATION: a partially-configured install keeps its own value and defaults only the other', () => {
      const stored: Record<string, string> = { 'retention.days': '30' };
      const status = resolveRetention({ env: {}, readConfig: (k) => stored[k], db });
      assert.strictEqual(status.configured.retentionDays, 30, 'an explicit 30-day window is honoured');
      assert.strictEqual(status.sources.retentionDays, 'config');
      assert.strictEqual(status.configured.maxSpans, DEFAULT_MAX_SPANS);
      assert.strictEqual(status.sources.maxSpans, 'default');
    });

    check('precedence is env → config → default, and 0 means unbounded rather than unset', () => {
      assert.deepStrictEqual(resolveKnob('7', '30', 183), { value: 7, source: 'env' });
      assert.deepStrictEqual(resolveKnob(undefined, '30', 183), { value: 30, source: 'config' });
      assert.deepStrictEqual(resolveKnob(undefined, undefined, 183), { value: 183, source: 'default' });
      assert.deepStrictEqual(resolveKnob('0', '30', 183), { value: 0, source: 'env' });
      assert.strictEqual(parseRetentionValue('0'), 0);
      assert.strictEqual(parseRetentionValue(''), null);
      assert.strictEqual(parseRetentionValue('not-a-number'), null);
      assert.strictEqual(parseRetentionValue('-5'), null);
      // A malformed env var must fall through to config, not crash or win.
      assert.deepStrictEqual(resolveKnob('abc', '30', 183), { value: 30, source: 'config' });
    });

    check('an env var shadowing a saved dashboard value is reported, not swallowed', () => {
      const stored: Record<string, string> = { 'retention.days': '365', 'retention.max_spans': '5000000' };
      const shadowed = resolveRetention({
        env: { CLAUDESEC_RETENTION_DAYS: '7' },
        readConfig: (k) => stored[k],
        db,
      });
      assert.strictEqual(shadowed.configured.retentionDays, 7, 'env still wins at runtime');
      assert.ok(shadowed.envOverride, 'but the user is told the saved value is being ignored');
      assert.ok(shadowed.envOverride!.includes('CLAUDESEC_RETENTION_DAYS'));

      // No stored value → nothing is being shadowed → no noise.
      const clean = resolveRetention({ env: { CLAUDESEC_RETENTION_DAYS: '7' }, readConfig: () => undefined, db });
      assert.strictEqual(clean.envOverride, null);
    });
  } finally {
    db.close();
  }
} finally {
  cleanup();
}

if (failures.length) {
  console.error('\n  retentionProfilesTest FAILURES:');
  for (const f of failures) console.error(`   ✗ ${f}`);
}
console.log(`  retentionProfilesTest: ${passed}/${passed + failed} passed`);
process.exit(failed === 0 ? 0 : 1);
