/**
 * tests/sessionsPaginationTest.ts
 *
 * Gate for the paging contract on GET /api/sessions.
 *
 * ── Why this exists ──
 * The route returned every session on every dashboard load — 6.5k rows and
 * 2.4 MB on a real install — and offered no way to ask for less. Paging was
 * added WITHOUT changing the default response, because the dashboard reads the
 * full array; that compatibility promise is only worth anything if something
 * checks it, so this test pins both halves:
 *
 *   1. No paging params → every session, same shape as before, plus the metadata
 *      a client needs to start paging.
 *   2. `limit`/`offset` → a stable, non-overlapping window whose pages reassemble
 *      into exactly the unpaged list, with a hard server-side cap that a caller
 *      cannot exceed and a `total` that respects the `label` filter.
 *
 * The label filter matters here specifically: it used to be applied in
 * JavaScript AFTER the query, which silently drops rows out of an already-sliced
 * page and makes `total` unreachable.
 *
 * Run via:  npx tsx tests/sessionsPaginationTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure (or boot failure).
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

const PORT = 3214;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(os.tmpdir(), `csec-sessionspaging-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-sessionspaginationtest-home-'));

const SESSION_COUNT = 25;
const INCIDENT_EVERY = 5;   // every 5th session is labelled `incident`

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try { await fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
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
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group gone */ }
  try { child.kill('SIGKILL'); } catch { /* dead */ }
}

interface SessionRow {
  traceId: string; name: string; label: string;
  spanCount: number; threatCount: number; threatHigh: number;
  alertCount: number; repo: string | null; harnesses: string | null;
  healthScore: number; grade: string;
}
interface ListResponse {
  sessions: SessionRow[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

const INSERT_COLS =
  'spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo';

let seq = 0;
function seedSpan(dbh: Database.Database, traceId: string, severity: string): void {
  const id = `span${String(++seq).padStart(8, '0')}`;
  const start = String(1_700_000_000_000_000_000n + BigInt(seq) * 1_000_000_000n);
  dbh.prepare(`INSERT INTO spans (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', ?, 'claude-code', '{}', ?, ?, ?)`)
    .run(id, traceId, `tool_call/${id}`, severity, start, start, '~/code/alpha');
}

function seedDb(): void {
  const dbh = new Database(DB_PATH);
  dbh.prepare('DELETE FROM spans').run();
  dbh.prepare('DELETE FROM sessions').run();
  dbh.prepare('DELETE FROM alerts').run();

  for (let i = 0; i < SESSION_COUNT; i++) {
    const traceId = `trace-${String(i).padStart(3, '0')}`;
    // Distinct createdAt values, so the sort is total and the pages are stable.
    dbh.prepare('INSERT INTO sessions (traceId, name, createdAt, label) VALUES (?, ?, ?, ?)')
      .run(traceId, `session ${i}`, new Date(1_700_000_000_000 + i * 60_000).toISOString(),
           i % INCIDENT_EVERY === 0 ? 'incident' : 'normal');
    // A varying threat mix, so ordering is not accidentally insertion order.
    seedSpan(dbh, traceId, i % 3 === 0 ? 'high' : 'none');
    seedSpan(dbh, traceId, i % 4 === 0 ? 'medium' : 'none');
  }
  // One session with no spans at all — the LEFT JOIN case that must still report
  // zeros rather than nulls once the aggregates moved into CTEs.
  dbh.prepare('INSERT INTO sessions (traceId, name, createdAt, label) VALUES (?, ?, ?, ?)')
    .run('trace-empty', 'empty session', new Date(1_700_000_000_000).toISOString(), 'normal');
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
        // Keep the child off the operator's real ~/.claudesec: booting the
        // server mirrors its hook artifacts (enforce-config, protected-paths,
        // the rule snapshot, the control-plane pairing key) into CLAUDESEC_HOME.
        CLAUDESEC_HOME: HOME_DIR,
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

    seedDb();

    const get = async (qs = ''): Promise<ListResponse> => {
      const r = await fetch(`${BASE}/api/sessions${qs}`);
      assert.strictEqual(r.status, 200, `expected 200 for /api/sessions${qs}, got ${r.status}`);
      return await r.json() as ListResponse;
    };

    const TOTAL = SESSION_COUNT + 1;
    let unpaged: ListResponse = { sessions: [], total: 0, limit: 0, offset: 0, hasMore: false };

    await check('the default response is still the complete list', async () => {
      unpaged = await get();
      assert.ok(Array.isArray(unpaged.sessions));
      assert.strictEqual(unpaged.sessions.length, TOTAL, 'omitting paging params must return every session');
      assert.strictEqual(unpaged.total, TOTAL);
      assert.strictEqual(unpaged.hasMore, false, 'an unpaged response can never have more');
    });

    await check('a session with no spans reports zeros, not nulls', () => {
      const empty = unpaged.sessions.find(s => s.traceId === 'trace-empty');
      assert.ok(empty, 'the span-less session must still be listed');
      assert.strictEqual(empty.spanCount, 0);
      assert.strictEqual(empty.threatCount, 0);
      assert.strictEqual(empty.alertCount, 0);
      assert.strictEqual(typeof empty.healthScore, 'number');
    });

    await check('a page returns exactly `limit` rows and reports how many remain', async () => {
      const page = await get('?limit=10');
      assert.strictEqual(page.sessions.length, 10);
      assert.strictEqual(page.limit, 10);
      assert.strictEqual(page.offset, 0);
      assert.strictEqual(page.total, TOTAL, 'total counts the whole set, not the page');
      assert.strictEqual(page.hasMore, true);
    });

    await check('walking the pages reproduces the unpaged list exactly', async () => {
      const walked: string[] = [];
      for (let offset = 0; offset < TOTAL; offset += 10) {
        const page = await get(`?limit=10&offset=${offset}`);
        assert.strictEqual(page.offset, offset);
        walked.push(...page.sessions.map(s => s.traceId));
      }
      assert.deepStrictEqual(walked, unpaged.sessions.map(s => s.traceId),
        'paging must not drop, duplicate, or reorder rows');
    });

    await check('the last page reports hasMore = false', async () => {
      const last = await get(`?limit=10&offset=20`);
      assert.strictEqual(last.sessions.length, TOTAL - 20);
      assert.strictEqual(last.hasMore, false);
    });

    await check('an offset past the end returns an empty page, not an error', async () => {
      const beyond = await get('?limit=10&offset=1000');
      assert.deepStrictEqual(beyond.sessions, []);
      assert.strictEqual(beyond.total, TOTAL);
      assert.strictEqual(beyond.hasMore, false);
    });

    await check('the hard cap bounds an oversized limit', async () => {
      const huge = await get('?limit=99999');
      assert.strictEqual(huge.limit, 500, 'a caller must not be able to raise the cap');
    });

    await check('junk paging params degrade to a bounded page, never a 500', async () => {
      const junk = await get('?limit=abc&offset=-7');
      assert.strictEqual(junk.offset, 0, 'a negative offset clamps to the start');
      assert.ok(junk.limit >= 1 && junk.limit <= 500);
      assert.strictEqual(junk.total, TOTAL);
    });

    await check('the label filter is applied before paging, so total is reachable', async () => {
      const incidents = Math.ceil(SESSION_COUNT / INCIDENT_EVERY);
      const all = await get('?label=incident');
      assert.strictEqual(all.total, incidents, 'total must count only the filtered set');
      assert.strictEqual(all.sessions.length, incidents);
      assert.ok(all.sessions.every(s => s.label === 'incident'));

      const page = await get('?label=incident&limit=2&offset=2');
      assert.strictEqual(page.total, incidents);
      assert.strictEqual(page.sessions.length, Math.min(2, incidents - 2));
      assert.ok(page.sessions.every(s => s.label === 'incident'),
        'a filtered page must never be diluted by rows of another label');
      assert.deepStrictEqual(
        page.sessions.map(s => s.traceId),
        all.sessions.slice(2, 4).map(s => s.traceId),
        'a filtered page must be the matching window of the filtered list',
      );
    });

    await check('the response is not larger than the page it promised', async () => {
      const r = await fetch(`${BASE}/api/sessions?limit=5`);
      const body = await r.text();
      const j = JSON.parse(body) as ListResponse;
      assert.strictEqual(j.sessions.length, 5);
      assert.ok(body.length < 8000, `a 5-row page should be small, got ${body.length} bytes`);
    });
  } finally {
    if (child) killTree(child);
    cleanupDb();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  sessionsPaginationTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[sessionsPaginationTest] fatal:', err);
  cleanupDb();
  process.exit(1);
});
