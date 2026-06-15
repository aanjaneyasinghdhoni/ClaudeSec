/**
 * tests/repoIdentityTest.ts
 *
 * Gate for server/repoIdentity.ts — the per-span repository-identity helper and
 * its one-time, data-safe startup backfill (Per-Repository Dashboard, Task 1).
 *
 * Proves:
 *   1. resolveRepo() walks UP to the nearest .git ancestor and returns that root.
 *   2. resolveRepo() returns the cwd unchanged when no .git ancestor exists.
 *   3. resolveRepo() returns 'unknown' for undefined / empty cwd.
 *   4. resolveRepo() is bounded and never throws on a bogus path.
 *   5. resolveRepo() memoizes (same cwd → same cached result).
 *   6. The `repo` column migration adds the column to a fresh temp DB and is
 *      idempotent (running the additive ALTER twice never errors).
 *   7. backfillRepos() sets `repo` from attributes.cwd for a NULL/unknown row,
 *      writes ONLY that column (every other column byte-identical), and is
 *      idempotent (a second run updates nothing).
 *
 * Pure unit test: every filesystem and SQLite artifact lives under os.tmpdir(),
 * created and torn down by the test. The real ~/.claudesec is NEVER touched.
 *
 * Run via:  npx tsx tests/repoIdentityTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import Database from 'better-sqlite3';

import {
  resolveRepo,
  backfillRepos,
  _resetRepoCache,
  UNKNOWN_REPO,
} from '../server/repoIdentity.js';

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// Skip scrubbing for the resolveRepo assertions so we compare raw paths
// deterministically; the backfill test exercises the no-opts path too.
const NO_SCRUB = undefined;

// ── temp dirs ───────────────────────────────────────────────────────────────
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'claudesec-repo-'));
function cleanup(): void {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
}

// ── 1. nested cwd inside a git repo resolves to the git root ─────────────────
check('resolveRepo finds the git root from a nested cwd', () => {
  _resetRepoCache();
  const repoDir = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, 'gitrepo-')));
  fs.mkdirSync(path.join(repoDir, '.git'));
  const nested = path.join(repoDir, 'src', 'deep', 'nested');
  fs.mkdirSync(nested, { recursive: true });

  const got = resolveRepo(nested, NO_SCRUB);
  assert.strictEqual(got, repoDir, `expected git root ${repoDir}, got ${got}`);

  // A `.git` FILE (worktree/submodule style) must also count as a root.
  _resetRepoCache();
  const wtRepo = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, 'worktree-')));
  fs.writeFileSync(path.join(wtRepo, '.git'), 'gitdir: /elsewhere\n');
  const wtNested = path.join(wtRepo, 'a', 'b');
  fs.mkdirSync(wtNested, { recursive: true });
  assert.strictEqual(resolveRepo(wtNested, NO_SCRUB), wtRepo);
});

// ── 2. no .git ancestor → cwd returned unchanged ─────────────────────────────
check('resolveRepo returns cwd unchanged when no .git ancestor exists', () => {
  _resetRepoCache();
  // A directory under tmp with NO .git anywhere up to the filesystem root.
  const plain = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, 'nogit-')));
  const sub = path.join(plain, 'x');
  fs.mkdirSync(sub);
  assert.strictEqual(resolveRepo(sub, NO_SCRUB), sub);
});

// ── 3. undefined / empty cwd → 'unknown' ─────────────────────────────────────
check('resolveRepo returns unknown for undefined/empty cwd', () => {
  _resetRepoCache();
  assert.strictEqual(resolveRepo(undefined, NO_SCRUB), UNKNOWN_REPO);
  assert.strictEqual(resolveRepo('', NO_SCRUB), UNKNOWN_REPO);
  assert.strictEqual(resolveRepo('   ', NO_SCRUB), UNKNOWN_REPO);
});

// ── 4. bounded / never throws on a bogus path ────────────────────────────────
check('resolveRepo is bounded and never throws on a bogus path', () => {
  _resetRepoCache();
  // A path that does not exist on disk — falls back to returning it unchanged.
  const bogus = path.join(tmpRoot, 'does', 'not', 'exist', 'at', 'all');
  let got = '';
  assert.doesNotThrow(() => { got = resolveRepo(bogus, NO_SCRUB); });
  assert.strictEqual(got, bogus);

  // A pathological deeply-nested string must not hang or throw.
  const deep = '/' + Array.from({ length: 500 }, (_, i) => `d${i}`).join('/');
  assert.doesNotThrow(() => { resolveRepo(deep, NO_SCRUB); });
});

// ── 5. memoization ───────────────────────────────────────────────────────────
check('resolveRepo memoizes repeated cwds', () => {
  _resetRepoCache();
  const repoDir = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, 'memo-')));
  fs.mkdirSync(path.join(repoDir, '.git'));
  const nested = path.join(repoDir, 'pkg');
  fs.mkdirSync(nested);

  const first = resolveRepo(nested, NO_SCRUB);
  assert.strictEqual(first, repoDir);

  // Delete the .git AFTER the first resolve. A non-memoized impl would now fall
  // back to returning `nested`; the cache must still return the original root.
  fs.rmSync(path.join(repoDir, '.git'), { recursive: true, force: true });
  const second = resolveRepo(nested, NO_SCRUB);
  assert.strictEqual(second, first, 'memoized result should be returned unchanged');
});

// ── DB helpers — schema mirrors server/db.ts spans table + repo migration ────
// Uses prepare().run() (not exec) so each DDL statement is a single explicit op.
function makeSpansDb(): { db: Database.Database; file: string } {
  const file = path.join(tmpRoot, `spans-${Math.random().toString(36).slice(2)}.db`);
  const db = new Database(file);
  db.prepare(`
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
      endNano    TEXT NOT NULL DEFAULT '0'
    )
  `).run();
  return { db, file };
}

function applyRepoMigration(db: Database.Database): void {
  // Mirrors server/db.ts: additive + idempotent.
  try { db.prepare(`ALTER TABLE spans ADD COLUMN repo TEXT NOT NULL DEFAULT 'unknown'`).run(); } catch {}
}

// ── 6. repo-column migration is additive + idempotent ────────────────────────
check('repo column migration adds the column and is idempotent', () => {
  const { db } = makeSpansDb();
  try {
    const before = (db.prepare(`PRAGMA table_info(spans)`).all() as { name: string }[]).map(c => c.name);
    assert.ok(!before.includes('repo'), 'fresh table should not yet have repo');

    applyRepoMigration(db);
    const after = (db.prepare(`PRAGMA table_info(spans)`).all() as { name: string }[]).map(c => c.name);
    assert.ok(after.includes('repo'), 'repo column should exist after migration');

    // Running it again must not throw and must not duplicate the column.
    assert.doesNotThrow(() => applyRepoMigration(db));
    const after2 = (db.prepare(`PRAGMA table_info(spans)`).all() as { name: string }[]).map(c => c.name);
    assert.strictEqual(after2.filter(n => n === 'repo').length, 1, 'repo column must not be duplicated');
  } finally {
    db.close();
  }
});

// ── 7. backfill sets repo from attributes.cwd, ONLY that column, idempotent ──
check('backfillRepos sets repo from cwd, touches only repo, is idempotent', () => {
  _resetRepoCache();
  const { db } = makeSpansDb();
  try {
    applyRepoMigration(db);

    // A real git repo on disk that the stored cwd lives inside.
    const repoDir = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, 'bf-')));
    fs.mkdirSync(path.join(repoDir, '.git'));
    const cwd = path.join(repoDir, 'src');
    fs.mkdirSync(cwd);

    const insert = db.prepare(`
      INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
      VALUES (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness, @attributes, @startNano, @endNano)
    `);
    // Row A: has cwd → should be backfilled to repoDir.
    insert.run({
      spanId: 'a', traceId: 't1', parentId: 'p', name: 'Bash', protocol: 'local',
      reason: 'run', severity: 'none', harness: 'claude',
      attributes: JSON.stringify({ cwd, tool: 'Bash' }), startNano: '10', endNano: '20',
    });
    // Row B: no cwd → must stay 'unknown'.
    insert.run({
      spanId: 'b', traceId: 't1', parentId: 'p', name: 'llm_request', protocol: 'local',
      reason: 'x', severity: 'none', harness: 'claude',
      attributes: JSON.stringify({ 'llm.model': 'sonnet' }), startNano: '30', endNano: '40',
    });
    // Row C: a SCRUBBED / non-existent cwd (no .git reachable on disk). The
    // backfill must leave it 'unknown' rather than write a subdir key that would
    // not match how live spans for the same repo are grouped.
    insert.run({
      spanId: 'c', traceId: 't1', parentId: 'p', name: 'Bash', protocol: 'local',
      reason: 'run', severity: 'none', harness: 'claude',
      attributes: JSON.stringify({ cwd: '/Users/***/code/myrepo/src', tool: 'Bash' }),
      startNano: '50', endNano: '60',
    });

    // Snapshot every NON-repo column of row A so we can prove they are untouched.
    const cols = ['spanId', 'traceId', 'parentId', 'name', 'protocol', 'reason', 'severity', 'harness', 'attributes', 'startNano', 'endNano'];
    const beforeA = db.prepare(`SELECT * FROM spans WHERE spanId = 'a'`).get() as Record<string, unknown>;

    const r1 = backfillRepos(db, undefined, () => {});
    assert.strictEqual(r1.updated, 1, `expected 1 update, got ${r1.updated}`);

    const afterA = db.prepare(`SELECT * FROM spans WHERE spanId = 'a'`).get() as Record<string, unknown>;
    assert.strictEqual(afterA.repo, repoDir, `row A repo should be ${repoDir}, got ${afterA.repo}`);
    // Every other column must be byte-identical.
    for (const c of cols) {
      assert.strictEqual(afterA[c], beforeA[c], `column ${c} must be unchanged by backfill`);
    }

    const afterB = db.prepare(`SELECT repo FROM spans WHERE spanId = 'b'`).get() as { repo: string };
    assert.strictEqual(afterB.repo, 'unknown', 'row B (no cwd) must stay unknown');

    const afterC = db.prepare(`SELECT repo FROM spans WHERE spanId = 'c'`).get() as { repo: string };
    assert.strictEqual(afterC.repo, 'unknown', 'row C (scrubbed/non-resolvable cwd) must stay unknown');

    // Idempotent: a second run finds nothing left to update.
    const r2 = backfillRepos(db, undefined, () => {});
    assert.strictEqual(r2.updated, 0, `second run should update nothing, got ${r2.updated}`);
    const afterA2 = db.prepare(`SELECT * FROM spans WHERE spanId = 'a'`).get() as Record<string, unknown>;
    assert.strictEqual(afterA2.repo, repoDir);
    for (const c of cols) {
      assert.strictEqual(afterA2[c], beforeA[c], `column ${c} must be unchanged by the 2nd backfill`);
    }
  } finally {
    db.close();
  }
});

// ── report ───────────────────────────────────────────────────────────────────
cleanup();
if (failures.length > 0) {
  console.error(`repoIdentityTest: ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
console.log(`repoIdentityTest: all ${passed} checks passed`);
process.exit(0);
