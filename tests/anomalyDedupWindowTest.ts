/**
 * tests/anomalyDedupWindowTest.ts
 *
 * Gate for the behavioural-anomaly dedup window in server/index.ts.
 *
 * ── The defect this pins ──
 * Alerts store `ts` as a full ISO-8601 string ("2026-05-31T23:16:10.922Z"), but
 * the dedup checks compared it against SQLite's datetime('now','-5 minutes'),
 * which renders "2026-05-31 23:11:10" — a SPACE where the ISO string has a 'T'.
 * TEXT comparison reaches offset 10 before any clock digit, and 'T' (0x54) sorts
 * above ' ' (0x20), so EVERY same-UTC-day ISO timestamp compared as "newer than
 * now". The 5/10/30/60-minute windows all behaved like a 24-hour one, and the
 * token-spike / threat-burst / excessive-tool-call / off-hours alerts could fire
 * at most once per day per trace.
 *
 * The fix binds a JS-computed ISO cutoff (alertFiredWithin), so both sides of the
 * comparison are the same format. `nowMs` is injectable, which is what lets this
 * test pin the boundary against a FIXED reference instant instead of racing the
 * wall clock — the old bug only reproduced on same-UTC-day timestamps, so a test
 * anchored to real "now" would silently stop testing anything just after
 * midnight UTC.
 *
 * Run via:  npx tsx tests/anomalyDedupWindowTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB and CLAUDESEC_HOME are redirected under
 * os.tmpdir() BEFORE server/index.ts is imported, and removed in a finally
 * block. The real ~/.claudesec database is never opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = path.join(os.tmpdir(), `csec-anomdedup-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-anomdedup-home-'));

// Must be set before the module graph opens the database or mirrors any config.
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_HOME = HOME_DIR;
process.env.CLAUDESEC_WATCH = '0';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try { fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

// A FIXED reference instant. Everything below is expressed relative to it, so
// the assertions do not depend on what time the suite happens to run.
const NOW = Date.parse('2026-05-31T23:20:00.000Z');
const TRACE = 'trace-anomaly-dedup';
const LABEL = 'Token spike detected';

async function main(): Promise<void> {
  try {
    const { db } = await import('../server/db.js');
    const { alertFiredWithin } = await import('../server/index.js');

    const insertAlert = db.prepare(`
      INSERT INTO alerts (ts, ruleLabel, severity, spanId, traceId, harness, spanName, matchedText, fingerprint, count)
      VALUES (?, ?, 'medium', 'span-1', ?, 'claude-code', 'behavioral-anomaly', 'x', ?, 1)
    `);
    const clearAlerts = db.prepare(`DELETE FROM alerts WHERE traceId = ?`);

    // ── The exact shape the bug needed: an ISO alert from EARLIER THE SAME UTC
    //    DAY. 22h20m before the reference instant, so far outside every window.
    check('same-day ISO alert 22h old is NOT inside the 5-minute window', () => {
      clearAlerts.run(TRACE);
      insertAlert.run('2026-05-31T01:00:00.000Z', LABEL, TRACE, `${LABEL}::${TRACE}::claude-code`);
      assert.strictEqual(
        alertFiredWithin(TRACE, LABEL, 5 * 60_000, NOW),
        false,
        'a 22-hour-old alert must not suppress a new one — this is the regression',
      );
    });

    // Sanity: the same row is (correctly) inside a window wide enough to hold it.
    check('the same alert IS inside a 24-hour window', () => {
      assert.strictEqual(alertFiredWithin(TRACE, LABEL, 24 * 60 * 60_000, NOW), true);
    });

    // ── Boundary: just inside / just outside the window. ────────────────────
    check('an alert 4 minutes old suppresses a repeat (inside 5 minutes)', () => {
      clearAlerts.run(TRACE);
      insertAlert.run(new Date(NOW - 4 * 60_000).toISOString(), LABEL, TRACE, `${LABEL}::${TRACE}::claude-code`);
      assert.strictEqual(alertFiredWithin(TRACE, LABEL, 5 * 60_000, NOW), true);
    });

    check('an alert 6 minutes old does NOT suppress a repeat (outside 5 minutes)', () => {
      clearAlerts.run(TRACE);
      insertAlert.run(new Date(NOW - 6 * 60_000).toISOString(), LABEL, TRACE, `${LABEL}::${TRACE}::claude-code`);
      assert.strictEqual(alertFiredWithin(TRACE, LABEL, 5 * 60_000, NOW), false);
    });

    // ── The window is scoped per trace and per rule. ────────────────────────
    check('a recent alert on ANOTHER trace does not suppress this one', () => {
      clearAlerts.run(TRACE);
      insertAlert.run(new Date(NOW - 60_000).toISOString(), LABEL, 'some-other-trace', 'fp');
      assert.strictEqual(alertFiredWithin(TRACE, LABEL, 5 * 60_000, NOW), false);
    });

    check('a recent alert for ANOTHER rule does not suppress this one', () => {
      clearAlerts.run(TRACE);
      insertAlert.run(new Date(NOW - 60_000).toISOString(), 'Threat burst detected', TRACE, 'fp');
      assert.strictEqual(alertFiredWithin(TRACE, LABEL, 5 * 60_000, NOW), false);
    });

    // ── The old comparison, reproduced verbatim, to document WHY. ───────────
    // Anchored to the same fixed reference instant so it can never go stale.
    check('the old datetime() comparison misjudges a same-day ISO timestamp', () => {
      const cutoffSqlite = db
        .prepare(`SELECT datetime(?, '-5 minutes') AS c`)
        .get('2026-05-31T23:20:00Z') as { c: string };
      assert.strictEqual(cutoffSqlite.c, '2026-05-31 23:15:00', 'datetime() renders a space, not a T');
      assert.ok(
        '2026-05-31T01:00:00.000Z' > cutoffSqlite.c,
        "a 22-hour-old ISO timestamp sorts ABOVE datetime()'s output — the whole defect",
      );
      const cutoffIso = new Date(NOW - 5 * 60_000).toISOString();
      assert.ok(
        !('2026-05-31T01:00:00.000Z' > cutoffIso),
        'the same comparison against an ISO cutoff is correct',
      );
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  anomalyDedupWindowTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[anomalyDedupWindowTest] fatal:', err);
  cleanup();
  process.exit(1);
});
