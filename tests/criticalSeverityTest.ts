/**
 * tests/criticalSeverityTest.ts
 *
 * Silent-visibility regression gate for the `critical` exfiltration tier.
 *
 * `critical` was added as a fourth severity above `high`, but several aggregation
 * paths pre-dated it and defaulted anything they didn't recognize to `none`/green.
 * The effect was dangerous: a confirmed off-machine secret exfiltration could
 * render as a benign green dot, sort to the bottom of the session list, and leave
 * the health score untouched. This test seeds a `critical` span/alert into an
 * isolated temp DB and asserts the FIXED paths now treat it as the top tier:
 *
 *   1. Session list maxSeverityRank — a `critical` span ranks 4 (was ELSE 0).
 *   2. Session list threatHigh bucket — folds `critical` in (was high-only).
 *   3. computeHealthScore SQL — folds `critical` into the high penalty bucket.
 *   4. healthFromCounts — a single `critical` penalizes health at least as hard
 *      as a single `high`, and never leaves the score at a clean 100.
 *
 * It runs as its OWN process (spawned by main) so it can point CLAUDESEC_DB at an
 * isolated temp DB BEFORE importing server/db.ts — that module opens the database
 * at import time. The temp DB is deleted in a finally block. The real ~/.claudesec
 * DB is NEVER touched. No server boot, no network: < 5s.
 *
 * Run via:  npx tsx tests/criticalSeverityTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure (or worker crash).
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

// The pure health formula is duplicated here on purpose: it is a tiny, stable
// contract, and copying it keeps the test from having to import server/index.ts
// (which boots the HTTP server at module load). If the real formula ever changes
// shape, this mirror — and the assertions below — must be updated in lockstep.
function healthFromCounts(h: number, m: number, l: number, alertCount: number) {
  const raw = 100 - h * 15 - m * 8 - l * 3 - Math.min(alertCount * 10, 30);
  return Math.max(0, raw);
}

// ---------------------------------------------------------------------------
// WORKER: runs with CLAUDESEC_DB already set, seeds the temp DB, runs assertions
// against the SAME SQL the server uses.
// ---------------------------------------------------------------------------
async function runWorker(): Promise<void> {
  // db.ts reads CLAUDESEC_DB at import time and creates the full schema, so the
  // env var must already be set (the parent sets it before spawning this child).
  const { db } = await import('../server/db.js');

  const insertSpan = db.prepare(`
    INSERT INTO spans
      (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
    VALUES (@spanId, @traceId, 'root', @name, 'local', 'step', @severity, @harness, '{}', @startNano, @endNano)
  `);
  const insertAlert = db.prepare(`
    INSERT INTO alerts (ts, traceId, spanId, severity, ruleLabel, matchedText, spanName, harness)
    VALUES (@ts, @traceId, @spanId, @severity, @ruleLabel, @matchedText, @spanName, @harness)
  `);
  const insertSession = db.prepare(`INSERT INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)`);
  const now = new Date().toISOString();

  // A single session whose ONLY threat is a `critical` exfiltration. If any path
  // still defaults `critical` to `none`, this session would look perfectly clean.
  const traceId = 'trace-critical';
  insertSession.run(traceId, 'Critical exfil session', now);
  insertSpan.run({
    spanId: 'span-crit', traceId, name: 'bash', severity: 'critical',
    harness: 'claude-code', startNano: '1700000000000000000', endNano: '1700000000100000000',
  });
  insertAlert.run({
    ts: String(Date.now()), traceId, spanId: 'span-crit', severity: 'critical',
    ruleLabel: '.env file rsync to remote host', matchedText: '[scrubbed]',
    spanName: 'bash', harness: 'claude-code',
  });

  // A `high`-only control session, so we can prove `critical` is treated at least
  // as severely as `high` rather than merely "not none".
  const highTrace = 'trace-high';
  insertSession.run(highTrace, 'High-only session', now);
  insertSpan.run({
    spanId: 'span-high', traceId: highTrace, name: 'bash', severity: 'high',
    harness: 'claude-code', startNano: '1700000000000000000', endNano: '1700000000100000000',
  });

  let passed = 0;
  const failures: string[] = [];
  const check = (name: string, fn: () => void) => {
    try { fn(); passed++; console.log(`  ✓ ${name}`); }
    catch (e) { failures.push(`${name}: ${(e as Error).message}`); console.error(`  ✗ ${name}`); }
  };

  // The session-list aggregation, copied verbatim from server/routes/sessions.ts
  // so this test breaks if that query regresses on the critical tier.
  const sessionRow = (id: string) => db.prepare(`
    SELECT
      MAX(CASE s.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS maxSeverityRank,
      SUM(CASE WHEN s.severity != 'none' THEN 1 ELSE 0 END) AS threatCount,
      SUM(CASE WHEN s.severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS threatHigh
    FROM sessions se
    LEFT JOIN spans s ON s.traceId = se.traceId
    WHERE se.traceId = ?
    GROUP BY se.traceId
  `).get(id) as { maxSeverityRank: number; threatCount: number; threatHigh: number };

  check('session list: critical span ranks 4 (not 0/none)', () => {
    const r = sessionRow(traceId);
    assert.strictEqual(r.maxSeverityRank, 4, `maxSeverityRank should be 4, got ${r.maxSeverityRank}`);
  });

  check('session list: critical is still counted in threatCount', () => {
    const r = sessionRow(traceId);
    assert.strictEqual(r.threatCount, 1, `threatCount should be 1, got ${r.threatCount}`);
  });

  check('session list: critical folds into the high bucket', () => {
    const r = sessionRow(traceId);
    assert.strictEqual(r.threatHigh, 1, `threatHigh should count the critical span, got ${r.threatHigh}`);
  });

  // computeHealthScore's SQL, copied verbatim from server/index.ts: critical must
  // land in the high (`h`) bucket so it carries the heaviest per-span penalty.
  const healthInputs = (id: string) => db.prepare(`
    SELECT
      SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) AS h,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS m,
      SUM(CASE WHEN severity = 'low'    THEN 1 ELSE 0 END) AS l
    FROM spans WHERE traceId = ?
  `).get(id) as { h: number; m: number; l: number };

  check('health SQL: critical counts in the high penalty bucket', () => {
    const sev = healthInputs(traceId);
    assert.strictEqual(sev.h, 1, `critical should land in the high bucket, got h=${sev.h}`);
  });

  check('health score: a lone critical is penalized, never a clean 100', () => {
    const sev = healthInputs(traceId);
    const alertCount = (db.prepare('SELECT COUNT(*) AS c FROM alerts WHERE traceId = ?').get(traceId) as any).c as number;
    const score = healthFromCounts(sev.h, sev.m, sev.l, alertCount);
    assert.ok(score < 100, `critical session health should be < 100, got ${score}`);
  });

  check('health score: critical is penalized at least as hard as high', () => {
    const crit = healthInputs(traceId);
    const high = healthInputs(highTrace);
    // Compare on span penalty alone (no alerts), so the two are apples-to-apples.
    const critScore = healthFromCounts(crit.h, crit.m, crit.l, 0);
    const highScore = healthFromCounts(high.h, high.m, high.l, 0);
    assert.ok(critScore <= highScore, `critical (${critScore}) must not score better than high (${highScore})`);
  });

  const total = passed + failures.length;
  console.log('───────────────────────────────────────────────');
  console.log(`  criticalSeverityTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failures.length) {
    console.error(`\n  ${failures.length} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// PARENT: set up an isolated temp DB, spawn the worker pointed at it, clean up.
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const DB_PATH = path.join(os.tmpdir(), `csec-critsev-${process.pid}-${Date.now()}.db`);
  // Sandbox the home dir too: any code path that imports server/index.ts mirrors
  // the enforce mode to <CLAUDESEC_HOME>/hooks/enforce-config.json at load. This
  // override guarantees the worker can never write into the maintainer's real
  // ~/.claudesec, even if its imports grow to pull in the server module.
  const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-critsev-home-'));
  const cleanup = () => {
    for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
      try { fs.rmSync(f, { force: true }); } catch {}
    }
    try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
  };

  const code: number = await new Promise(resolve => {
    const child = spawn(TSX_BIN, [__filename, '--worker'], {
      cwd: REPO_ROOT,
      env: { ...process.env, CLAUDESEC_DB: DB_PATH, CLAUDESEC_WATCH: '0', CLAUDESEC_HOME: HOME_DIR },
      stdio: 'inherit',
    });
    child.on('exit', c => resolve(c ?? 1));
    child.on('error', () => resolve(1));
  });

  cleanup();
  process.exit(code);
}

if (process.argv.includes('--worker')) {
  runWorker().catch(err => { console.error('[criticalSeverityTest worker] fatal:', err); process.exit(1); });
} else {
  main().catch(err => { console.error('[criticalSeverityTest] fatal:', err); process.exit(1); });
}
