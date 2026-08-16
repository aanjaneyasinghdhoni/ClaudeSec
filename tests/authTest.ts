/**
 * tests/authTest.ts
 *
 * Gate for the bearer-token auth behaviour on the gated routes (/api, /mcp,
 * /v1/traces). The check is INLINE express middleware in server/index.ts
 * (app.use((req,res,next) => …)), not an exported function, so it can only be
 * exercised by driving the real server.
 *
 * Run via:  npx tsx tests/authTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed (or the server failed to boot).
 *
 * ── What this test CAN cover (hermetically, from 127.0.0.1) ──
 *   • Loopback requests are EXEMPT from the token gate (the dashboard's local
 *     same-origin path) — even with CLAUDESEC_TOKEN set, a loopback caller is
 *     allowed and reaches the route. This is the core "don't break local use"
 *     contract.
 *   • Loopback callers reach gated routes with NO Authorization header.
 *   • A wrong/garbage bearer token from loopback is STILL allowed (loopback
 *     exemption takes precedence over token validation — verifies the gate
 *     short-circuits on address, not on token).
 *
 * ── What this test CANNOT cover without a second network interface ──
 *   The 401 paths (non-loopback + no token, non-loopback + wrong token,
 *   non-loopback + correct token → 200) require a request whose
 *   req.socket.remoteAddress is NOT loopback. From a single-host test runner
 *   every connection to 127.0.0.1 arrives AS 127.0.0.1, so the gate's
 *   isLoopbackAddr() branch always wins and we can't reach the token-compare
 *   branch over the wire. The constant-time tokenMatches() helper (length guard
 *   + crypto.timingSafeEqual, empty-token → false) is likewise a private
 *   function and is documented in the summary as needing an export seam to
 *   unit-test directly. See REFACTOR note in the returned summary.
 *
 * DB DISCIPLINE: child server uses CLAUDESEC_DB under os.tmpdir(), deleted in a
 * finally block. CLAUDESEC_WATCH=0 keeps it off host transcripts. The real
 * ~/.claudesec DB is NEVER touched.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'index.ts');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

const PORT = 3202;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = 'testtoken';
const DB_PATH = path.join(os.tmpdir(), `csec-authtest-${process.pid}-${Date.now()}.db`);
// Sandbox the home dir too: server startup mirrors the enforce mode to
// <CLAUDESEC_HOME>/hooks/enforce-config.json. Without this override the child
// would write the test's (monitor) mode into the maintainer's real
// ~/.claudesec/hooks, silently disabling their live enforcement.
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-authtest-home-'));

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

/** Poll the server until it answers (or time out). Uses fetch, not shell sleep. */
async function waitForServer(timeoutMs: number, earlyExit?: () => string | null): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dead = earlyExit?.();
    if (dead) throw new Error(`server failed to start: ${dead}`);
    try {
      const r = await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(1500) });
      if (r.status >= 200 && r.status < 500) return; // any HTTP answer = up
    } catch {
      // not up yet
    }
    await sleep(200);
  }
  throw new Error(`server did not become ready on ${BASE} within ${timeoutMs}ms`);
}

function cleanupDb(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

/**
 * Kill the WHOLE process group, not just the tsx wrapper. `tsx` spawns the
 * actual node server as a grandchild; killing only child.pid orphans the
 * server and leaks the port across runs. Spawning detached makes the child a
 * group leader, so kill(-pid) reaps the grandchild too.
 */
function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group already gone */ }
  try { child.kill('SIGKILL'); } catch { /* already dead */ }
}

/** Wait until the port stops accepting connections (no leak into the next run). */
async function waitForPortFree(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(500) });
      // still answering → not free yet
    } catch {
      return; // connection refused/aborted → port is free
    }
    await sleep(150);
  }
  // Best-effort: don't fail the suite on a slow teardown, just note it.
  console.warn(`  warn: port ${PORT} still responding after ${timeoutMs}ms teardown wait`);
}

async function main(): Promise<void> {
  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        // Redirect the hooks-dir enforce-config mirror into the temp home so the
        // server's startup write can never touch the real ~/.claudesec.
        CLAUDESEC_HOME: HOME_DIR,
        // Pin both port vars — CLAUDESEC_PORT outranks PORT, so an inherited
        // value from the host shell must not steer the test server elsewhere.
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_TOKEN: TOKEN,
        CLAUDESEC_HOST: '127.0.0.1',
        CLAUDESEC_WATCH: '0',     // no transcript watching — stay off host data
        CLAUDESEC_TRUST_LOCAL: '', // ensure loopback-exemption path (not trust-all)
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // own process group → killTree() reaps the tsx grandchild
    });

    let serverLog = '';
    let exitInfo: string | null = null;
    child.stdout?.on('data', d => { serverLog += String(d); });
    child.stderr?.on('data', d => { serverLog += String(d); });
    child.on('exit', (code, sig) => { exitInfo = `child exited early (code=${code}, signal=${sig})`; });

    await waitForServer(30_000, () => exitInfo).catch(err => {
      throw new Error(`${err.message}\n--- server output ---\n${serverLog.slice(-2000)}`);
    });

    // ── Loopback exemption: no Authorization header → allowed (not 401). ────
    await check('loopback GET /api/spans without token is allowed (not 401)', async () => {
      const r = await fetch(`${BASE}/api/spans`);
      assert.notStrictEqual(r.status, 401, 'loopback caller must be exempt from the token gate');
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
    });

    // ── Loopback exemption short-circuits BEFORE token validation. ──────────
    await check('loopback with a WRONG bearer token is still allowed', async () => {
      const r = await fetch(`${BASE}/api/spans`, {
        headers: { authorization: 'Bearer totally-wrong-token' },
      });
      assert.notStrictEqual(r.status, 401, 'loopback must win over token mismatch');
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
    });

    // ── Loopback with the CORRECT token also works (sanity). ────────────────
    await check('loopback with the correct bearer token is allowed', async () => {
      const r = await fetch(`${BASE}/api/spans`, {
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
    });

    // ── A gated MCP route is also reachable over loopback. ──────────────────
    await check('loopback reaches the gated /v1/traces route (not 401)', async () => {
      // Empty/odd body may yield 200/400/503 depending on capacity, but never
      // 401 from loopback — that is the only thing this assertion cares about.
      const r = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ resourceSpans: [] }),
      });
      assert.notStrictEqual(r.status, 401, 'loopback must be exempt on /v1/traces too');
    });

    // ── A non-gated path stays open regardless. ─────────────────────────────
    await check('non-gated /metrics is reachable (not gated)', async () => {
      const r = await fetch(`${BASE}/metrics`);
      assert.notStrictEqual(r.status, 401, '/metrics is operational, not gated');
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
  console.log(`  authTest: ${passed}/${total} passed`);
  console.log('  (note: non-loopback 401 paths need a 2nd interface — see summary)');
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[authTest] fatal:', err);
  cleanupDb();
  process.exit(1);
});
