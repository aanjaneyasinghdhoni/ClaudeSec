/**
 * tests/controlPlaneGateTest.ts
 *
 * Gate for three server behaviours that can only be exercised by driving the
 * real server (they are inline express middleware / route handlers, not exported
 * functions):
 *
 *   1. THE CONTROL-PLANE GATE. Every /api route used to be wide open to any
 *      local caller, and the subject ClaudeSec monitors IS a local process — one
 *      curl from a compromised agent could disable detection rules, flip enforce
 *      back to monitor, or read the audit log. Reads stay open so the dashboard
 *      is unchanged; MUTATIONS need the control token.
 *
 *      The token used to be granted to any loopback GET whose HEADERS looked
 *      like a browser's, which a client picks for itself — so the gate certified
 *      whatever the caller claimed. It is now granted only to a caller that
 *      already holds the out-of-band pairing key. The spoof table below is the
 *      regression guard: every header shape that used to work must now fail.
 *
 *   2. /api/config/status REPORTS THE EFFECTIVE MODE. The dashboard toggle writes
 *      enforce-config.json, which outranks CLAUDESEC_MODE in the hook's own
 *      precedence. The route used to read the env var, so Settings could show
 *      "monitor" while tool calls were actually being blocked.
 *
 *   3. OTLP INGEST VALIDATION + TRANSACTION. A malformed payload used to throw a
 *      TypeError (opaque 500), and spans with no spanId were stored as
 *      unaddressable rows — `spanId TEXT PRIMARY KEY` has no NOT NULL, and SQLite
 *      treats every NULL primary key as distinct, so INSERT OR IGNORE never
 *      deduped them.
 *
 * Run via:  npx tsx tests/controlPlaneGateTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure (or boot failure).
 *
 * ── What this test CANNOT cover from a single host ──
 * The non-loopback 401 paths need a request whose req.socket.remoteAddress is
 * not loopback; every connection to 127.0.0.1 arrives AS 127.0.0.1. Same
 * limitation authTest documents. What IS covered here is that the CLAUDESEC_TOKEN
 * comparison still works (a bearer token satisfies the mutation gate), so the
 * remote branch's token check has not been disturbed.
 *
 * DB DISCIPLINE: the child server uses CLAUDESEC_DB + CLAUDESEC_HOME under
 * os.tmpdir(), removed in a finally block. CLAUDESEC_WATCH=0 keeps it off host
 * transcripts. The real ~/.claudesec database is NEVER opened or touched.
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

const PORT = 3214;
const BASE = `http://127.0.0.1:${PORT}`;
const TOKEN = 'control-plane-test-token';
const DB_PATH = path.join(os.tmpdir(), `csec-ctlplane-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-ctlplane-home-'));
// The dashboard toggle's on-disk form. The test switches it to 'enforce' through
// the API with CLAUDESEC_MODE left unset, so the file and the env var disagree
// and /api/config/status has to pick the layer the hook actually obeys.
const ENFORCE_CONFIG = path.join(HOME_DIR, 'enforce-config.json');

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

function cleanup(): void {
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

async function waitForPortFree(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(500) }); }
    catch { return; }
    await sleep(150);
  }
}

/** A mutation with no side effects: the session does not exist, so a request
 *  that clears the gate lands on the handler's 404 instead of the gate's 403. */
const MUTATION = `${BASE}/api/sessions/no-such-session`;
const mutationBody = {
  method: 'PATCH',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ notes: 'gate probe' }),
};

/** Minimal well-formed OTLP batch. */
function otlpBatch(spans: unknown[]) {
  return {
    resourceSpans: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'claude-code' } }] },
      scopeSpans: [{ spans }],
    }],
  };
}
const goodSpan = (id: string) => ({
  spanId: id, traceId: 'trace-ctlplane', name: 'tool_call/Bash',
  startTimeUnixNano: '1700000000000000000', endTimeUnixNano: '1700000000500000000',
  attributes: [{ key: 'gen_ai.tool.name', value: { stringValue: 'Bash' } }],
});

async function main(): Promise<void> {
  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        CLAUDESEC_HOME: HOME_DIR,
        CLAUDESEC_ENFORCE_CONFIG: ENFORCE_CONFIG,
        CLAUDESEC_MODE: '',        // deliberately unset: the config file must win
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_TOKEN: TOKEN,
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

    // ── 1. Control-plane gate ──────────────────────────────────────────────
    await check('an unauthenticated local READ is still allowed', async () => {
      for (const route of ['/api/spans', '/api/rules', '/api/enforce/status', '/api/audit-log', '/api/protected-paths']) {
        const r = await fetch(`${BASE}${route}`);
        assert.strictEqual(r.status, 200, `${route} expected 200, got ${r.status}`);
      }
    });

    await check('an unauthenticated local MUTATION is refused', async () => {
      const r = await fetch(MUTATION, mutationBody);
      assert.strictEqual(r.status, 403, `expected 403, got ${r.status}`);
      const j = await r.json() as { error: string };
      assert.strictEqual(j.error, 'forbidden');
    });

    // ── 1a. Header spoofing must NOT earn a token ──────────────────────────
    // The regression this locks down: the cookie used to be granted to any
    // loopback GET whose headers looked like a browser's. Headers are chosen by
    // the client, so `curl -H 'Sec-Fetch-Dest: document'` — three seconds of
    // work for a compromised agent — got the same mutation rights as the
    // dashboard. Every shape of that request is enumerated here.
    const SPOOFS: Array<[string, Record<string, string>]> = [
      ['Sec-Fetch-Dest: document (the old document-navigation test)',
        { 'sec-fetch-dest': 'document' }],
      ["same-origin empty (the old page's-own-fetch test)",
        { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' }],
      ['an HTML Accept header (the old no-Sec-Fetch fallback)',
        { accept: 'text/html,application/xhtml+xml' }],
      ['a full browser header set including a real User-Agent',
        {
          'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate',
          'sec-fetch-site': 'none', 'sec-fetch-user': '?1',
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126 Safari/537.36',
          'accept-language': 'en-US,en;q=0.9',
          referer: BASE,
          origin: BASE,
        }],
    ];

    for (const [label, headers] of SPOOFS) {
      await check(`a request that only LOOKS like the SPA gets no token — ${label}`, async () => {
        for (const route of ['/', '/api/spans']) {
          const r = await fetch(`${BASE}${route}`, { headers, redirect: 'manual' });
          const raw = r.headers.getSetCookie?.() ?? [];
          assert.ok(!raw.some(c => c.startsWith('claudesec_ct=')),
            `${route} handed out a control cookie to spoofed headers (${label})`);
        }
      });
    }

    await check('spoofed browser headers still cannot mutate', async () => {
      for (const [label, headers] of SPOOFS) {
        const r = await fetch(MUTATION, {
          ...mutationBody,
          headers: { ...mutationBody.headers, ...headers },
        });
        assert.strictEqual(r.status, 403, `${label} reached the handler (got ${r.status})`);
      }
    });

    await check('a plain non-browser GET does NOT receive the control token', async () => {
      // What `curl http://localhost:3000/...` sends: no Sec-Fetch-*, Accept: */*.
      for (const route of ['/', '/api/spans']) {
        const r = await fetch(`${BASE}${route}`, { headers: { accept: '*/*' }, redirect: 'manual' });
        const raw = r.headers.getSetCookie?.() ?? [];
        assert.ok(!raw.some(c => c.startsWith('claudesec_ct=')),
          `${route} must not hand the token to a caller that is not the dashboard`);
      }
    });

    await check('a WRONG pairing key earns nothing', async () => {
      const r = await fetch(`${BASE}/?ct=${'f'.repeat(64)}`, { redirect: 'manual' });
      const raw = r.headers.getSetCookie?.() ?? [];
      assert.ok(!raw.some(c => c.startsWith('claudesec_ct=')), 'a bogus key must not pair');
      assert.notStrictEqual(r.status, 302, 'a bogus key must not trigger the pairing redirect');
    });

    // ── 1b. The real pairing path ──────────────────────────────────────────
    let pairingKey = '';
    let cookieValue = '';
    await check('the pairing key is written 0600 under the self-protected hooks dir', () => {
      const keyPath = path.join(HOME_DIR, 'hooks', 'control-token');
      pairingKey = fs.readFileSync(keyPath, 'utf8').trim();
      assert.match(pairingKey, /^[0-9a-f]{64}$/, 'the pairing key should be 32 random bytes as hex');
      const mode = fs.statSync(keyPath).mode & 0o777;
      assert.strictEqual(mode, 0o600, `pairing key mode should be 0600, got ${mode.toString(8)}`);
    });

    await check('presenting the pairing key pairs the browser and redirects the key away', async () => {
      const r = await fetch(`${BASE}/?ct=${pairingKey}`, { redirect: 'manual' });
      assert.strictEqual(r.status, 302, `expected a redirect, got ${r.status}`);
      assert.strictEqual(r.headers.get('location'), '/', 'the key must be stripped from the URL');
      const raw = r.headers.getSetCookie?.() ?? [];
      const cookie = raw.find(c => c.startsWith('claudesec_ct='));
      assert.ok(cookie, `expected a claudesec_ct cookie, got ${JSON.stringify(raw)}`);
      assert.match(cookie!, /SameSite=Strict/i, 'the control cookie must be SameSite=Strict');
      assert.match(cookie!, /HttpOnly/i, 'the control cookie must be HttpOnly — page script has no use for it');
      cookieValue = decodeURIComponent(cookie!.split(';')[0].split('=')[1]);
      assert.ok(cookieValue.length >= 32, 'control cookie looks too short');
      assert.notStrictEqual(cookieValue, pairingKey,
        'the cookie must be derived from the key, not be the key');
    });

    await check('a MUTATION carrying the paired cookie is allowed through', async () => {
      const r = await fetch(MUTATION, {
        ...mutationBody,
        headers: { ...mutationBody.headers, cookie: `claudesec_ct=${cookieValue}` },
      });
      assert.strictEqual(r.status, 404, `expected the handler's 404, got ${r.status}`);
    });

    await check('a MUTATION carrying the pairing key as a header is allowed through', async () => {
      const r = await fetch(MUTATION, {
        ...mutationBody,
        headers: { ...mutationBody.headers, 'x-claudesec-token': pairingKey },
      });
      assert.strictEqual(r.status, 404, `expected the handler's 404, got ${r.status}`);
    });

    // The token the rest of this file uses for legitimate mutations.
    const controlToken = pairingKey;

    await check('a MUTATION carrying a WRONG control token is refused', async () => {
      const r = await fetch(MUTATION, {
        ...mutationBody,
        headers: { ...mutationBody.headers, 'x-claudesec-token': 'not-the-token-at-all-not-even-close' },
      });
      assert.strictEqual(r.status, 403, `expected 403, got ${r.status}`);
    });

    await check('CLAUDESEC_TOKEN still satisfies the gate (remote token path intact)', async () => {
      const r = await fetch(MUTATION, {
        ...mutationBody,
        headers: { ...mutationBody.headers, authorization: `Bearer ${TOKEN}` },
      });
      assert.strictEqual(r.status, 404, `expected the handler's 404, got ${r.status}`);
    });

    await check('machine-client mutations stay open (OTLP ingest, hook event log)', async () => {
      const ingest = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(otlpBatch([])),
      });
      assert.notStrictEqual(ingest.status, 403, '/v1/traces must not need a control token');

      const hookLog = await fetch(`${BASE}/api/enforce-log`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ mode: 'monitor', label: 'probe', severity: 'high', command: 'x', wouldBlock: true, blocked: false }),
      });
      assert.notStrictEqual(hookLog.status, 403, '/api/enforce-log must not need a control token');
    });

    await check('/metrics stays ungated', async () => {
      const r = await fetch(`${BASE}/metrics`);
      assert.notStrictEqual(r.status, 401);
      assert.notStrictEqual(r.status, 403);
    });

    // ── 2. Effective enforcement mode ──────────────────────────────────────
    // Switch to enforce the way an operator does — through the dashboard, which
    // persists to the config table and mirrors it to enforce-config.json. That
    // file outranks CLAUDESEC_MODE (left unset here) in the hook's precedence.
    await check('the dashboard can switch enforcement on with its control token', async () => {
      const r = await fetch(`${BASE}/api/enforce/config`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-claudesec-token': controlToken },
        body: JSON.stringify({ mode: 'enforce' }),
      });
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const written = JSON.parse(fs.readFileSync(ENFORCE_CONFIG, 'utf8')) as { mode: string };
      assert.strictEqual(written.mode, 'enforce', 'the hook config file must carry the new mode');
    });

    await check('/api/config/status reports the EFFECTIVE mode, not the env var', async () => {
      assert.strictEqual(process.env.CLAUDESEC_MODE ?? '', '', 'fixture requires CLAUDESEC_MODE unset');
      const r = await fetch(`${BASE}/api/config/status`);
      assert.strictEqual(r.status, 200);
      const j = await r.json() as { envVars?: unknown; settings?: { key: string; effectiveValue: string; enabled: boolean; detail?: string }[] };
      const mode = (j.settings ?? []).find(s => s.key === 'CLAUDESEC_MODE');
      assert.ok(mode, 'no CLAUDESEC_MODE entry in /api/config/status');
      assert.strictEqual(mode!.effectiveValue, 'enforce',
        'enforce-config.json outranks CLAUDESEC_MODE — Settings must not claim "monitor" while the hook blocks');
      assert.strictEqual(mode!.enabled, true);
      assert.match(String(mode!.detail), /dashboard/i, 'the detail should say where the mode came from');
    });

    // ── 3. OTLP ingest validation + batch accounting ───────────────────────
    await check('a non-array resourceSpans gets a structured 400, not a 500', async () => {
      const r = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ resourceSpans: 5 }),
      });
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
      const j = await r.json() as { error: string; detail: string };
      assert.strictEqual(j.error, 'Bad Request');
      assert.match(j.detail, /resourceSpans/);
    });

    await check('a non-object body gets a structured 400', async () => {
      const r = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify([1, 2, 3]),
      });
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
    });

    await check('spans without a usable spanId/traceId are skipped and counted', async () => {
      const r = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(otlpBatch([
          goodSpan('aaaaaaaaaaaaaaa1'),
          { ...goodSpan('aaaaaaaaaaaaaaa2'), spanId: null },
          { ...goodSpan('aaaaaaaaaaaaaaa3'), spanId: '' },
          { ...goodSpan('aaaaaaaaaaaaaaa4'), traceId: undefined },
          goodSpan('aaaaaaaaaaaaaaa5'),
        ])),
      });
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const j = await r.json() as { received: number; ingested: number; skipped: number };
      assert.strictEqual(j.received, 5, `received expected 5, got ${j.received}`);
      assert.strictEqual(j.ingested, 2, `ingested expected 2, got ${j.ingested}`);
      assert.strictEqual(j.skipped, 3, `skipped expected 3, got ${j.skipped}`);
    });

    await check('only the valid spans reached the database', async () => {
      const r = await fetch(`${BASE}/api/spans?session=trace-ctlplane`);
      assert.strictEqual(r.status, 200);
      const j = await r.json() as { spans: { spanId: string }[] };
      const ids = j.spans.map(s => s.spanId).sort();
      assert.deepStrictEqual(ids, ['aaaaaaaaaaaaaaa1', 'aaaaaaaaaaaaaaa5']);
    });

    await check('replaying the same batch stores nothing new (dedup by spanId)', async () => {
      await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(otlpBatch([
          { ...goodSpan('aaaaaaaaaaaaaaa2'), spanId: null },
          { ...goodSpan('aaaaaaaaaaaaaaa3'), spanId: null },
        ])),
      });
      const r = await fetch(`${BASE}/api/spans?session=trace-ctlplane`);
      const j = await r.json() as { spans: { spanId: string }[] };
      assert.strictEqual(j.spans.length, 2,
        'a replayed batch of spanId-less spans must not accumulate unaddressable rows');
    });
  } finally {
    if (child) {
      killTree(child);
      await waitForPortFree(8_000);
    }
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  controlPlaneGateTest: ${passed}/${total} passed`);
  console.log('  (note: non-loopback 401 paths need a 2nd interface — see header)');
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[controlPlaneGateTest] fatal:', err);
  cleanup();
  process.exit(1);
});
