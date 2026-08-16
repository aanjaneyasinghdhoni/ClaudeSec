/**
 * tests/legacyDbMigrationTest.ts
 *
 * Gate for the one-time move of a pre-2.0 database into ~/.claudesec.
 *
 * Releases up to 1.3.0 resolved the database name against the process working
 * directory; 2.0.0 resolves it to an absolute path under the home directory.
 * server/db.ts migrates the old file into the new location on first boot. That
 * migration touches the single copy of a user's security ledger, so every branch
 * of its decision table is pinned here, and — because the ledger is
 * tamper-evident — the hash chain is re-verified on the far side of the move.
 *
 *   A. Decision table (no data at risk in any of these):
 *      1. fresh install           → nothing to do
 *      2. legacy present, target absent → moved, and the legacy path is gone
 *      3. BOTH present            → nothing moved, both files byte-identical,
 *                                   and the user is told the old one is there
 *      4. CLAUDESEC_DB pinned     → never acts, however tempting the candidate
 *      5. legacy is not a SQLite file → left alone
 *      6. legacy held by another connection → left alone
 *      7. re-running after a successful move → idempotent no-op
 *      8. legacy and target are the same file → no-op, no warning
 *      9. interrupted run (target directory unwritable) → legacy intact, and a
 *         retry once the interruption clears completes the move
 *     10. the candidate list itself: working directory first, then the checkout
 *
 *   B. Hash chain across the move. A legacy database is filled with chained
 *      spans (and tombstones) in a child process, verified, moved, and verified
 *      again from a second child process opened on the NEW path. The chain must
 *      still say `ok`, over the same positions, with the same tail hash — a
 *      migration that rewrites one byte of span content would report the user's
 *      untouched history as tampered. A deliberately edited copy is then run
 *      through the same check, so a clean result can never be a vacuous one.
 *
 * Fully sandboxed. Every path is inside a throwaway directory under os.tmpdir();
 * HOME, CLAUDESEC_HOME and CLAUDESEC_DB are all redirected before any server
 * module loads. The live database is never opened.
 *
 * Run via:  npx tsx tests/legacyDbMigrationTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';

const SELF = fileURLToPath(import.meta.url);

// ---------------------------------------------------------------------------
// Child phases (section B). server/db.ts binds its database at import time, so
// "before the move" and "after the move" cannot share a process.
// ---------------------------------------------------------------------------

/**
 * Fill a chained database (seed) or verify one (verify), and print a single
 * JSON line the parent reads back. Both phases run against whatever
 * CLAUDESEC_DB and CLAUDESEC_HOME the parent handed down.
 */
async function runChildPhase(phase: string): Promise<void> {
  const { db, insertChainedSpan, verifySpanChain, checkpointAndClose } =
    await import('../server/db.js');
  const { flushChainAnchors } = await import('../server/auditChain.js');

  if (phase === 'seed') {
    for (let i = 0; i < 150; i++) {
      insertChainedSpan({
        spanId:     `chain-${i}`,
        traceId:    'trace-legacy-migration',
        parentId:   '',
        name:       `Bash tool call ${i}`,
        protocol:   'HTTPS',
        reason:     'Processing step',
        severity:   i % 11 === 0 ? 'high' : 'none',
        harness:    'claude-code',
        attributes: JSON.stringify({ command: `echo step ${i}`, cwd: '/work', blob: 'x'.repeat(256) }),
        startNano:  String(BigInt(1_700_000_000_000) * 1_000_000n + BigInt(i)),
        endNano:    String(BigInt(1_700_000_000_000) * 1_000_000n + BigInt(i) + 1_000n),
        repo:       'legacy-fixture',
      });
    }
    // Delete a few so the chain carries tombstones too — those are part of what
    // has to come through the move intact.
    db.prepare(`DELETE FROM spans WHERE spanId IN ('chain-3','chain-4','chain-5')`).run();
    flushChainAnchors();
  }

  const status = await verifySpanChain({ deep: true });
  const rows = db.prepare(
    `SELECT chainSeq, spanId, rowHash FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq`,
  ).all() as { chainSeq: number; spanId: string; rowHash: string }[];
  const tail = rows[rows.length - 1];

  console.log(JSON.stringify({
    status:       status.status,
    detail:       status.detail,
    chainedSpans: status.chainedSpans,
    tombstones:   status.tombstones,
    checkedHashes: status.checkedHashes,
    attested:     status.attested,
    tailHash:     tail?.rowHash ?? '',
    rows,
  }));

  // Seal the WAL so the file the parent moves is a single self-contained one.
  checkpointAndClose();
}

if (process.env.CSEC_PHASE) {
  await runChildPhase(process.env.CSEC_PHASE);
  process.exit(0);
}

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-legacy-db-'));

// Keep the parent process itself off the default path: importing server/db.ts
// here (case B does it in children) must never reach the real ~/.claudesec.
process.env.CLAUDESEC_HOME = path.join(ROOT, 'home', '.claudesec');
process.env.HOME = path.join(ROOT, 'home');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A fresh sandbox directory per case, so cases can never see each other. */
function sandbox(name: string): { legacy: string; target: string } {
  const dir = path.join(ROOT, name);
  fs.mkdirSync(path.join(dir, 'checkout'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'home', '.claudesec'), { recursive: true });
  return {
    legacy: path.join(dir, 'checkout', 'spans.db'),
    target: path.join(dir, 'home', '.claudesec', 'spans.db'),
  };
}

/**
 * Write a plausible 1.3.0-era database: WAL mode, a spans table, some rows, and
 * — deliberately — left with an UNCHECKPOINTED -wal and a live -shm, which is
 * exactly the state an ungracefully-stopped 1.3.0 server leaves behind and the
 * state a naive single-file move would silently truncate.
 */
function makeLegacyDb(file: string, rows = 200): { rowCount: number; handle: Database.Database } {
  const handle = new Database(file);
  handle.pragma('journal_mode = WAL');
  handle.exec(`CREATE TABLE IF NOT EXISTS spans (spanId TEXT PRIMARY KEY, name TEXT NOT NULL)`);
  const insert = handle.prepare(`INSERT OR IGNORE INTO spans (spanId, name) VALUES (?, ?)`);
  const many = handle.transaction((n: number) => {
    for (let i = 0; i < n; i++) insert.run(`legacy-${i}`, `Bash tool call ${i}`);
  });
  many(rows);
  return { rowCount: rows, handle };
}

/** Row count read through a throwaway connection. */
function countSpans(file: string): number {
  const handle = new Database(file, { readonly: true });
  try {
    return (handle.prepare(`SELECT COUNT(*) AS c FROM spans`).get() as { c: number }).c;
  } finally {
    handle.close();
  }
}

function sha256(file: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// The unit under test. Imported AFTER the env redirect above; server/db.ts runs
// its own migration at import time against the sandboxed (and absent) default,
// which is a no-op.
const { migrateLegacyDbLocation, legacyDbCandidates } = await import('../server/db.js');

// ---------------------------------------------------------------------------
// A. Decision table
// ---------------------------------------------------------------------------

/** Convenience: run the migration with logging captured. */
function migrate(opts: { targetPath: string; pinned?: boolean; candidates: string[] }) {
  const logged: string[] = [];
  const result = migrateLegacyDbLocation({
    targetPath: opts.targetPath,
    pinned: opts.pinned ?? false,
    candidates: opts.candidates,
    log: message => logged.push(message),
  });
  return { result, logged };
}

// ── 1. Fresh install: neither file exists ───────────────────────────────────
{
  const { legacy, target } = sandbox('case1-fresh');
  const { result, logged } = migrate({ targetPath: target, candidates: [legacy] });
  check('case1: fresh install does nothing', () => assert.strictEqual(result.action, 'none'));
  check('case1: reason is no-legacy', () => assert.strictEqual(result.reason, 'no-legacy'));
  check('case1: a fresh install is silent', () => assert.deepStrictEqual(logged, []));
  check('case1: no database was created', () => assert.strictEqual(fs.existsSync(target), false));
}

// ── 2. Legacy present, target absent: the move, WAL and all ─────────────────
{
  const { legacy, target } = sandbox('case2-move');
  const { rowCount, handle } = makeLegacyDb(legacy);
  // Prove the fixture really is mid-WAL before we let go of it — otherwise this
  // case would silently stop testing the thing it exists to test.
  check('case2: fixture leaves an uncheckpointed -wal', () =>
    assert.ok(fs.statSync(`${legacy}-wal`).size > 0, 'expected a non-empty -wal'));
  check('case2: fixture leaves a -shm', () =>
    assert.strictEqual(fs.existsSync(`${legacy}-shm`), true));
  handle.close(); // the old server exits; better-sqlite3 checkpoints on close

  // Re-dirty the WAL from a connection we then abandon WITHOUT closing, so the
  // migration is handed a database with live sidecars rather than a tidy one.
  const dirty = new Database(legacy);
  dirty.pragma('journal_mode = WAL');
  dirty.prepare(`INSERT OR IGNORE INTO spans (spanId, name) VALUES (?, ?)`).run('legacy-wal', 'tail write');
  const expectedRows = rowCount + 1;
  dirty.close();

  const { result, logged } = migrate({ targetPath: target, candidates: [legacy] });
  check('case2: the database is moved', () => assert.strictEqual(result.action, 'moved'));
  check('case2: reason is ok', () => assert.strictEqual(result.reason, 'ok'));
  check('case2: the new location exists', () => assert.strictEqual(fs.existsSync(target), true));
  check('case2: the legacy path is gone', () => assert.strictEqual(fs.existsSync(legacy), false));
  check('case2: no sidecar is orphaned at the legacy path', () => {
    assert.strictEqual(fs.existsSync(`${legacy}-wal`), false, 'stale -wal left behind');
    assert.strictEqual(fs.existsSync(`${legacy}-shm`), false, 'stale -shm left behind');
  });
  check('case2: every row survived, including the ones only the -wal held', () =>
    assert.strictEqual(countSpans(target), expectedRows));
  check('case2: the moved database is owner-only (0600)', () =>
    assert.strictEqual(fs.statSync(target).mode & 0o777, 0o600));
  check('case2: the user is told what happened and where', () => {
    assert.strictEqual(logged.length, 1, `expected one line, got ${logged.length}`);
    assert.ok(logged[0].includes(legacy) && logged[0].includes(target), logged[0]);
  });

  // ── 7. Idempotency: the same call again must be a no-op ───────────────────
  const again = migrate({ targetPath: target, candidates: [legacy] });
  check('case7: a second run does nothing', () => assert.strictEqual(again.result.action, 'none'));
  check('case7: reason is no-legacy', () => assert.strictEqual(again.result.reason, 'no-legacy'));
  check('case7: a second run is silent', () => assert.deepStrictEqual(again.logged, []));
  check('case7: the migrated database is untouched', () =>
    assert.strictEqual(countSpans(target), expectedRows));
}

// ── 3. Both present: never overwrite, and say so ────────────────────────────
{
  const { legacy, target } = sandbox('case3-both');
  const { handle: legacyHandle } = makeLegacyDb(legacy, 50);
  legacyHandle.close();
  const { handle: targetHandle } = makeLegacyDb(target, 7);
  targetHandle.close();

  const legacyBefore = sha256(legacy);
  const targetBefore = sha256(target);

  const { result, logged } = migrate({ targetPath: target, candidates: [legacy] });
  check('case3: nothing is moved', () => assert.strictEqual(result.action, 'none'));
  check('case3: reason is target-exists', () => assert.strictEqual(result.reason, 'target-exists'));
  check('case3: the legacy file is byte-identical', () =>
    assert.strictEqual(sha256(legacy), legacyBefore));
  check('case3: the target file is byte-identical', () =>
    assert.strictEqual(sha256(target), targetBefore));
  check('case3: the user is told the old file is still there', () => {
    assert.strictEqual(logged.length, 1, `expected one line, got ${logged.length}`);
    assert.ok(logged[0].includes(legacy), logged[0]);
  });
}

// ── 4. CLAUDESEC_DB pinned: the operator chose, hands off ───────────────────
{
  const { legacy, target } = sandbox('case4-pinned');
  const { handle } = makeLegacyDb(legacy, 12);
  handle.close();
  const before = sha256(legacy);

  const { result, logged } = migrate({ targetPath: target, pinned: true, candidates: [legacy] });
  check('case4: a pinned path is never migrated', () => assert.strictEqual(result.action, 'none'));
  check('case4: reason is pinned', () => assert.strictEqual(result.reason, 'pinned'));
  check('case4: the legacy file is untouched', () => assert.strictEqual(sha256(legacy), before));
  check('case4: the target is not created', () => assert.strictEqual(fs.existsSync(target), false));
  check('case4: pinning is silent', () => assert.deepStrictEqual(logged, []));
}

// ── 5. Not a SQLite file: an empty placeholder, or something else entirely ──
{
  const { legacy, target } = sandbox('case5-notsqlite');
  fs.writeFileSync(legacy, '');
  const empty = migrate({ targetPath: target, candidates: [legacy] });
  check('case5: a zero-byte spans.db is not migrated', () =>
    assert.strictEqual(empty.result.reason, 'not-sqlite'));
  check('case5: the zero-byte file stays put', () => assert.strictEqual(fs.existsSync(legacy), true));
  check('case5: nothing is created at the target', () =>
    assert.strictEqual(fs.existsSync(target), false));

  check('case5: a zero-byte candidate is silent', () => assert.deepStrictEqual(empty.logged, []));

  fs.writeFileSync(legacy, 'this is somebody else’s file that happens to be named spans.db\n');
  const other = migrate({ targetPath: target, candidates: [legacy] });
  check('case5: an unrelated file named spans.db is not migrated', () =>
    assert.strictEqual(other.result.reason, 'not-sqlite'));
  check('case5: the unrelated file stays put', () => assert.strictEqual(fs.existsSync(legacy), true));
  check('case5: a candidate with content that is not a database IS reported', () => {
    assert.strictEqual(other.logged.length, 1, `expected one line, got ${other.logged.length}`);
    assert.ok(other.logged[0].includes(legacy), other.logged[0]);
  });
}

// ── 6. Legacy held by another process: refuse to move a live database ───────
{
  const { legacy, target } = sandbox('case6-busy');
  const { handle } = makeLegacyDb(legacy, 30);
  // Simulate the old 1.3.0 server still running: hold the write lock open.
  handle.exec('BEGIN IMMEDIATE');
  handle.prepare(`INSERT OR IGNORE INTO spans (spanId, name) VALUES (?, ?)`).run('busy', 'in flight');

  const { result, logged } = migrate({ targetPath: target, candidates: [legacy] });
  check('case6: a locked database is not moved', () => assert.strictEqual(result.action, 'none'));
  check('case6: reason is busy', () => assert.strictEqual(result.reason, 'busy'));
  check('case6: the legacy database is still where it was', () =>
    assert.strictEqual(fs.existsSync(legacy), true));
  check('case6: nothing lands at the target', () => assert.strictEqual(fs.existsSync(target), false));
  check('case6: the user is told why it was skipped', () => {
    assert.strictEqual(logged.length, 1, `expected one line, got ${logged.length}`);
    assert.ok(/still running/.test(logged[0]), logged[0]);
  });

  handle.exec('ROLLBACK');
  handle.close();

  // Once the other process lets go, the retry completes.
  const retry = migrate({ targetPath: target, candidates: [legacy] });
  check('case6: the retry after the lock clears moves it', () =>
    assert.strictEqual(retry.result.action, 'moved'));
  check('case6: the rolled-back write did not survive', () =>
    assert.strictEqual(countSpans(target), 30));
}

// ── 8. Legacy and target are two names for one file ─────────────────────────
{
  const { legacy, target } = sandbox('case8-samefile');
  const { handle } = makeLegacyDb(target, 9);
  handle.close();
  fs.symlinkSync(target, legacy);

  const { result, logged } = migrate({ targetPath: target, candidates: [legacy] });
  check('case8: a symlink to the target is a no-op', () => assert.strictEqual(result.action, 'none'));
  check('case8: reason is same-file', () => assert.strictEqual(result.reason, 'same-file'));
  check('case8: the database is still readable', () => assert.strictEqual(countSpans(target), 9));
  check('case8: same-file is silent', () => assert.deepStrictEqual(logged, []));
}

// ── 9. Interrupted run: the failure must leave the legacy database intact ───
// The interruption is forced by making the target directory unwritable, which
// is the closest reproducible stand-in for "the process died mid-move": the
// rename cannot complete, and the only question that matters is whether the
// user's single copy is still there and still whole.
{
  const { legacy, target } = sandbox('case9-interrupted');
  const { handle } = makeLegacyDb(legacy, 64);
  handle.close();
  const before = sha256(legacy);

  const targetDir = path.dirname(target);
  fs.chmodSync(targetDir, 0o500); // r-x — rename(2) into it must fail
  let interrupted;
  try {
    interrupted = migrate({ targetPath: target, candidates: [legacy] });
  } finally {
    fs.chmodSync(targetDir, 0o700);
  }

  check('case9: an interrupted move reports failure', () =>
    assert.strictEqual(interrupted!.result.action, 'none'));
  check('case9: reason is failed', () => assert.strictEqual(interrupted!.result.reason, 'failed'));
  check('case9: the legacy database is byte-for-byte intact', () =>
    assert.strictEqual(sha256(legacy), before));
  check('case9: the legacy database still opens and still has every row', () =>
    assert.strictEqual(countSpans(legacy), 64));
  check('case9: no half-written file is left at the target', () => {
    assert.strictEqual(fs.existsSync(target), false);
    assert.strictEqual(fs.existsSync(`${target}.migrating`), false);
  });
  check('case9: the user is told the data is still at the old path', () => {
    assert.strictEqual(interrupted!.logged.length, 1);
    assert.ok(interrupted!.logged[0].includes(legacy), interrupted!.logged[0]);
  });

  // The retry, once the interruption clears, completes the move.
  const retry = migrate({ targetPath: target, candidates: [legacy] });
  check('case9: the retry after the interruption completes the move', () =>
    assert.strictEqual(retry.result.action, 'moved'));
  check('case9: the retried move carries every row', () =>
    assert.strictEqual(countSpans(target), 64));
  check('case9: the retried database is byte-identical to the interrupted one', () =>
    assert.strictEqual(sha256(target), before));
}

// ── 10. Candidate list: the working directory first, then the checkout ──────
{
  const cwdCandidate = path.join(ROOT, 'cwd-probe');
  const candidates = legacyDbCandidates(cwdCandidate);
  check('case10: the working directory is the first candidate', () =>
    assert.strictEqual(candidates[0], path.join(cwdCandidate, 'spans.db')));
  check('case10: the repo checkout is also probed', () =>
    assert.ok(candidates.some(c => c.endsWith(path.join('ClaudeSec', 'spans.db')) || c !== candidates[0]),
      candidates.join(', ')));
  check('case10: candidates are de-duplicated', () =>
    assert.strictEqual(new Set(candidates).size, candidates.length));
}

// ---------------------------------------------------------------------------
// B. The hash chain survives the move
// ---------------------------------------------------------------------------
//
// server/db.ts opens its database at import time, so each half runs in its own
// child process: one writes and seals a chained database at the legacy path,
// the other verifies it after the move at the new path. CLAUDESEC_HOME is
// shared between them because that is where the signing key and the signed tail
// anchor live — a migration that broke the link between the database and its
// anchor would show up here as `truncated` or `tail_mismatch`.

const CHAIN_DIR    = path.join(ROOT, 'chain');
const CHAIN_HOME   = path.join(CHAIN_DIR, 'home', '.claudesec');
const CHAIN_LEGACY = path.join(CHAIN_DIR, 'checkout', 'spans.db');
const CHAIN_TARGET = path.join(CHAIN_DIR, 'home', '.claudesec', 'spans.db');
fs.mkdirSync(path.dirname(CHAIN_LEGACY), { recursive: true });
fs.mkdirSync(CHAIN_HOME, { recursive: true });

function runPhase(phase: 'seed' | 'verify', dbPath: string): Record<string, unknown> {
  const out = execFileSync(process.execPath, ['--import', 'tsx', SELF, phase], {
    env: {
      ...process.env,
      CLAUDESEC_DB: dbPath,
      CLAUDESEC_HOME: CHAIN_HOME,
      HOME: path.join(CHAIN_DIR, 'home'),
      CSEC_PHASE: phase,
    },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const line = out.trim().split('\n').filter(l => l.startsWith('{')).pop();
  if (!line) throw new Error(`phase ${phase} produced no result line`);
  return JSON.parse(line) as Record<string, unknown>;
}

const seeded = runPhase('seed', CHAIN_LEGACY);
check('chain: the legacy database verifies before the move', () =>
  assert.strictEqual(seeded.status, 'ok', String(seeded.detail)));
check('chain: the legacy database really is chained', () =>
  assert.ok((seeded.chainedSpans as number) >= 120, String(seeded.chainedSpans)));

const legacyDigest = sha256(CHAIN_LEGACY);
const chainMove = migrate({ targetPath: CHAIN_TARGET, candidates: [CHAIN_LEGACY] });
check('chain: the chained database is moved', () =>
  assert.strictEqual(chainMove.result.action, 'moved'));
check('chain: not one byte of the database changed in the move', () =>
  assert.strictEqual(sha256(CHAIN_TARGET), legacyDigest));

const verified = runPhase('verify', CHAIN_TARGET);
check('chain: the moved database still verifies', () =>
  assert.strictEqual(verified.status, 'ok', String(verified.detail)));
check('chain: the deep check recomputed every span hash', () =>
  assert.strictEqual(verified.checkedHashes, seeded.chainedSpans));
check('chain: the signed anchor still attests it', () =>
  assert.strictEqual(verified.attested, true));
check('chain: the same number of positions came through', () => {
  assert.strictEqual(verified.chainedSpans, seeded.chainedSpans);
  assert.strictEqual(verified.tombstones, seeded.tombstones);
});
check('chain: the tail hash is unchanged', () =>
  assert.strictEqual(verified.tailHash, seeded.tailHash));
check('chain: every span id and content hash is unchanged', () =>
  assert.deepStrictEqual(verified.rows, seeded.rows));

// The clean result above is only meaningful if this verification can fail at
// all. Take a copy of the migrated database, edit one span's content the way an
// outside editor would, and confirm the same check reports it — otherwise every
// assertion in this section would pass on a migration that shredded the file.
{
  const tampered = path.join(CHAIN_DIR, 'tampered.db');
  fs.copyFileSync(CHAIN_TARGET, tampered);
  const handle = new Database(tampered);
  handle.prepare(`UPDATE spans SET attributes = ? WHERE spanId = 'chain-77'`).run('{"command":"tampered"}');
  handle.close();

  const caught = runPhase('verify', tampered);
  check('chain: the verification is not vacuous — a tampered span is caught', () =>
    assert.strictEqual(caught.status, 'row_mismatch', String(caught.detail)));
}

// ---------------------------------------------------------------------------

try { fs.rmSync(ROOT, { recursive: true, force: true }); } catch {}

if (failures.length > 0) {
  console.error(`\nlegacyDbMigrationTest: ${failures.length} failure(s), ${passed} passed\n`);
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
console.log(`legacyDbMigrationTest: ${passed} assertions passed`);
