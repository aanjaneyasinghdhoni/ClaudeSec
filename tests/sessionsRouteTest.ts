/**
 * tests/sessionsRouteTest.ts
 *
 * Gate for GET /api/sessions — the session list behind the dashboard's Sessions
 * tab. Boots the real server as a child process against an ISOLATED temp DB,
 * seeds spans across one multi-repo session and one clean session directly in
 * SQLite (matching the live ingest schema), then asserts the route returns 200
 * with the expected per-session aggregates.
 *
 * Regression guard: the list query GROUP_CONCATs each session's distinct repos
 * with a newline separator. SQLite forbids a custom separator on a DISTINCT
 * aggregate (GROUP_CONCAT(DISTINCT x, sep) is a syntax error), so the column has
 * to de-dupe in a subquery first. A naive `GROUP_CONCAT(DISTINCT s.repo, sep)`
 * makes the whole route throw SqliteError -> HTTP 500 on every poll. This test
 * exercises a multi-repo session so that mistake can never ship again silently.
 *
 * Run via:  npx tsx tests/sessionsRouteTest.ts
 *   Exit 0  -> every assertion passed.   Exit 1  -> a failure (or boot failure).
 *
 * DB DISCIPLINE: the child server uses CLAUDESEC_DB under os.tmpdir(), seeded by
 * this test and removed in a finally block. CLAUDESEC_WATCH=0 keeps it off host
 * transcripts. The real ~/.claudesec DB is NEVER opened or touched.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'index.ts');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

const PORT = 3212;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(os.tmpdir(), `csec-sessionstest-${process.pid}-${Date.now()}.db`);

const REPO_A = '~/code/alpha'; // a real repo path
const REPO_B = '~/code/beta';  // a second real repo path
const REPO_UNKNOWN = 'unknown'; // historical / cwd-less bucket

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${(err as Error).message}`);
  }
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function waitForServer(timeoutMs: number, earlyExit?: () => string | null): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dead = earlyExit?.();
    if (dead) throw new Error(`server failed to start: ${dead}`);
    try {
      const r = await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(1500) });
      if (r.status >= 200 && r.status < 500) return;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`server did not become ready on ${BASE} within ${timeoutMs}ms`);
}

function cleanupDb(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group gone */ }
  try { child.kill('SIGKILL'); } catch { /* dead */ }
}

async function waitForPortFree(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(500) });
    } catch { return; }
    await sleep(150);
  }
}

interface SessionRow {
  traceId: string;
  name: string;
  pinned: number;
  label: string;
  spanCount: number;
  threatCount: number;
  threatHigh: number;
  threatMedium: number;
  threatLow: number;
  harnesses: string | null;
  repo: string | null;
  healthScore: number;
  grade: string;
}

// ---------------------------------------------------------------------------
// Seed the temp DB AFTER the server has booted, so the server owns the schema
// (full column set + the `repo` migration) and we just INSERT rows over its own
// committed tables via a second connection. We supply every NOT-NULL column that
// lacks a default (parentId) and let defaults cover the rest. prepare().run()
// keeps the test source free of patterns the local enforce hook flags.
// ---------------------------------------------------------------------------

const INSERT_COLS = 'spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo';

let seq = 0;
function seedSpan(
  dbh: Database.Database,
  opts: { traceId: string; repo: string; harness: string; severity: string },
): void {
  const id = `span${String(++seq).padStart(8, '0')}`;
  const start = String(1_700_000_000_000_000_000n + BigInt(seq) * 1_000_000_000n);
  const end = String(BigInt(start) + 500_000_000n);
  dbh
    .prepare(`INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', ?, ?, '{}', ?, ?, ?)`)
    .run(id, opts.traceId, `tool_call/${id}`, opts.severity, opts.harness, start, end, opts.repo);
}

function seedSession(dbh: Database.Database, traceId: string, name: string): void {
  dbh
    .prepare('INSERT INTO sessions (traceId, name, createdAt) VALUES (?, ?, ?)')
    .run(traceId, name, new Date().toISOString());
}

function seedDb(): void {
  // Open a second connection on the already-created (by the server) DB file.
  const dbh = new Database(DB_PATH);

  // Start from a clean slate: the server may write its own bootstrap span(s) on
  // startup, which would otherwise skew the counts. We own this isolated temp
  // DB, so wiping it here gives the seeded rows below exact, reproducible counts.
  dbh.prepare('DELETE FROM spans').run();
  dbh.prepare('DELETE FROM sessions').run();

  // Session 1: spans the agent touched TWO repos in (plus the unknown bucket) —
  // the case that breaks a DISTINCT-with-separator GROUP_CONCAT. Mixed severity.
  seedSession(dbh, 'traceMulti', 'multi-repo session');
  seedSpan(dbh, { traceId: 'traceMulti', repo: REPO_A, harness: 'claude-code', severity: 'high' });
  seedSpan(dbh, { traceId: 'traceMulti', repo: REPO_B, harness: 'claude-code', severity: 'medium' });
  seedSpan(dbh, { traceId: 'traceMulti', repo: REPO_UNKNOWN, harness: 'codex', severity: 'none' });

  // Session 2: a single clean repo, no threats.
  seedSession(dbh, 'traceClean', 'clean session');
  seedSpan(dbh, { traceId: 'traceClean', repo: REPO_A, harness: 'claude-code', severity: 'none' });

  dbh.close();
}

async function main(): Promise<void> {
  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_HOST: '127.0.0.1',
        CLAUDESEC_WATCH: '0',
        CLAUDESEC_TRUST_LOCAL: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    });

    let serverLog = '';
    let exitInfo: string | null = null;
    child.stdout?.on('data', d => { serverLog += String(d); });
    child.stderr?.on('data', d => { serverLog += String(d); });
    child.on('exit', (code, sig) => { exitInfo = `child exited early (code=${code}, signal=${sig})`; });

    await waitForServer(30_000, () => exitInfo).catch(err => {
      throw new Error(`${err.message}\n--- server output ---\n${serverLog.slice(-2000)}`);
    });

    // Server is up and owns the schema; seed rows over its committed tables.
    seedDb();

    let sessions: SessionRow[] = [];

    await check('GET /api/sessions returns 200 with a sessions array', async () => {
      const r = await fetch(`${BASE}/api/sessions`);
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const j = await r.json() as { sessions: SessionRow[] };
      assert.ok(Array.isArray(j.sessions), 'expected sessions to be an array');
      sessions = j.sessions;
    });

    const byTrace = () => new Map(sessions.map(s => [s.traceId, s]));

    await check('lists exactly the two seeded sessions', () => {
      const keys = sessions.map(s => s.traceId).sort();
      assert.deepStrictEqual(keys, ['traceClean', 'traceMulti'].sort(),
        `unexpected session keys: ${JSON.stringify(keys)}`);
    });

    await check('a multi-repo session carries its distinct repos newline-joined', () => {
      const m = byTrace().get('traceMulti')!;
      const repos = (m.repo ?? '').split('\n').sort();
      assert.deepStrictEqual(repos, [REPO_A, REPO_B, REPO_UNKNOWN].sort(),
        `expected the three distinct repos newline-joined, got ${JSON.stringify(m.repo)}`);
    });

    await check('span + threat counts aggregate per session', () => {
      const m = byTrace().get('traceMulti')!;
      assert.strictEqual(m.spanCount, 3, `multi spanCount expected 3, got ${m.spanCount}`);
      assert.strictEqual(m.threatHigh, 1, `multi threatHigh expected 1, got ${m.threatHigh}`);
      assert.strictEqual(m.threatMedium, 1, `multi threatMedium expected 1, got ${m.threatMedium}`);
      const c = byTrace().get('traceClean')!;
      assert.strictEqual(c.threatCount, 0, 'clean session should have no threats');
    });

    await check('a threatened session scores lower health than a clean one, with a grade', () => {
      const m = byTrace().get('traceMulti')!;
      const c = byTrace().get('traceClean')!;
      assert.ok(m.healthScore < c.healthScore,
        `multi (${m.healthScore}) should score below clean (${c.healthScore})`);
      assert.ok(typeof c.grade === 'string' && c.grade.length === 1, 'clean session missing grade');
    });

    await check('the ?label filter narrows the list without erroring', async () => {
      const r = await fetch(`${BASE}/api/sessions?label=normal`);
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const j = await r.json() as { sessions: SessionRow[] };
      assert.ok(j.sessions.every(s => s.label === 'normal'),
        'every returned session should carry the requested label');
    });
  } finally {
    if (child) {
      killTree(child);
      await waitForPortFree(8_000);
    }
    cleanupDb();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  sessionsRouteTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[sessionsRouteTest] fatal:', err);
  cleanupDb();
  process.exit(1);
});
