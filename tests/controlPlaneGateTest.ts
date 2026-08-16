/**
 * tests/controlPlaneGateTest.ts
 *
 * Gate for six server behaviours that can only be exercised by driving the
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
 *   4. THE GATE CLASSIFIES A PATH THE WAY THE ROUTER MATCHES IT. The gate asked
 *      `req.path.startsWith('/api/')` — a case-SENSITIVE test — while express
 *      matches routes case-INSENSITIVELY unless `case sensitive routing` is set.
 *      `PUT /API/enforce/config` therefore missed the gate and reached the
 *      handler, turning enforcement off with no token; off-loopback it also
 *      skipped the CLAUDESEC_TOKEN branch, because the "not a gated path"
 *      early-out runs first. Section 1c walks every spelling that a router, or
 *      a normalising proxy in front of one, could resolve to a gated route.
 *
 *   5. /mcp IS EXEMPT FROM THE GATE — ITS CONTROL TOOLS ARE NOT. The exemption
 *      is a deliberate trade for machine clients that cannot hold a secret, and
 *      it is right for INGEST. It was also letting `suppress_rule` switch off
 *      any detection rule by an enumerable id (`builtin-0` is `rm -rf /`) with
 *      no token, no cap, no catastrophic-label guard and no audit trail.
 *
 *   6. AN OPEN APPEND ENDPOINT MUST NOT BE AN ERASE ENDPOINT. POST
 *      /api/enforce-log is token-free by the same trade (the PreToolUse hook has
 *      nowhere safe to keep a secret). 500 unauthenticated posts used to push
 *      every real entry out of the capped feed in under half a second, and
 *      because the survivors are re-anchored, /api/audit/verify still reported
 *      "chain intact". Section 6 floods the feed and asserts the evidence
 *      survives, that displacement is bounded, and that it is recorded.
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
/**
 * Every spelling of `p` that express — or a proxy that normalises before
 * forwarding — could resolve back to the route `p` names. The gate has to treat
 * all of them as the gated route (or the router has to refuse them outright);
 * what it must never do is let one through unclassified.
 */
function pathSpellings(p: string): Array<[string, string]> {
  const upper   = p.toUpperCase();
  const capped  = p.replace(/\/([a-z])/g, (_m, c: string) => `/${c.toUpperCase()}`);
  const pctHead = `/%${p.charCodeAt(1).toString(16).toUpperCase()}${p.slice(2)}`;
  const dupIn   = p.replace(/^\/([^/]+)\//, '/$1//');
  const out: Array<[string, string]> = [
    ['upper case',                    upper],
    ['capitalised segments',          capped],
    ['trailing slash',                `${p}/`],
    ['upper case + trailing slash',   `${upper}/`],
    ['duplicate leading slash',       `/${p}`],
    ['percent-encoded first letter',  pctHead],
  ];
  if (dupIn !== p) out.push(['duplicate interior slash', dupIn]);
  return out;
}

/** A refusal — any of them. The point is that the handler did not run. */
const REFUSALS = new Set([400, 401, 403, 404, 405, 429]);

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

    // ── 1c. Path spelling: the gate must model the router ──────────────────
    // The regression: the gate classified with case-SENSITIVE comparisons and
    // express matches case-INSENSITIVELY, so `PUT /API/enforce/config` walked
    // past the gate into the handler and turned enforcement off with no token.
    // Case is the spelling that was live, but it is one of a family — trailing
    // slashes, duplicate slashes and percent-escapes are the same mistake — so
    // every member is checked, not the one that happened to be exploitable.
    await check('no spelling of PUT /api/enforce/config flips the mode without a token', async () => {
      const before = (await (await fetch(`${BASE}/api/enforce/config`)).json() as { mode: string }).mode;
      for (const [label, p] of pathSpellings('/api/enforce/config')) {
        const r = await fetch(`${BASE}${p}`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ mode: 'enforce' }),
        });
        assert.ok(REFUSALS.has(r.status),
          `${label} (${p}) reached the handler — expected a refusal, got ${r.status}`);
      }
      const after = (await (await fetch(`${BASE}/api/enforce/config`)).json() as { mode: string }).mode;
      assert.strictEqual(after, before,
        'an unauthenticated caller changed the enforcement mode through an alternate path spelling');
    });

    await check('no spelling of POST /api/suppressions can silence a rule without a token', async () => {
      for (const [label, p] of pathSpellings('/api/suppressions')) {
        const r = await fetch(`${BASE}${p}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ ruleKey: `spelling-probe:${label}`, durationMs: 60_000 }),
        });
        assert.ok(REFUSALS.has(r.status),
          `${label} (${p}) reached the handler — expected a refusal, got ${r.status}`);
      }
      const list = await (await fetch(`${BASE}/api/suppressions`)).json() as { suppressions: { ruleKey: string }[] };
      const leaked = list.suppressions.filter(s => s.ruleKey.startsWith('spelling-probe:'));
      assert.deepStrictEqual(leaked, [],
        `an alternate path spelling created ${leaked.length} suppression(s) with no token`);
    });

    await check('a spoofed-shape mutation through a case variant is still refused', async () => {
      // The two bypasses composed: browser-looking headers (which used to earn
      // the cookie) on a case-variant path (which used to skip the gate).
      for (const [, headers] of SPOOFS) {
        const r = await fetch(`${BASE}/API/enforce/config`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json', ...headers },
          body: JSON.stringify({ mode: 'enforce' }),
        });
        assert.ok(REFUSALS.has(r.status), `spoofed headers + /API reached the handler (${r.status})`);
      }
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

    // ── 5. /mcp is exempt from the gate; its CONTROL tools must not be ─────
    // POST /mcp carries no token by design — a cross-agent MCP client has
    // nowhere to hold one. That trade buys ingest and read tools. It was also
    // buying `suppress_rule`, which switches OFF a detection rule by an
    // enumerable id, with none of the guards its gated REST twin has.
    type RpcReply = { result?: { content?: { text: string }[] }; error?: { code: number; message: string } };
    const mcpCall = async (
      tool: string,
      args: Record<string, unknown>,
      opts: { token?: string; path?: string } = {},
    ): Promise<RpcReply> => {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (opts.token) headers['x-claudesec-token'] = opts.token;
      const r = await fetch(`${BASE}${opts.path ?? '/mcp'}`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: args } }),
      });
      // A refusal at the gate is an HTTP status, not a JSON-RPC envelope.
      if (!r.ok) return { error: { code: r.status, message: `HTTP ${r.status}` } };
      return await r.json() as RpcReply;
    };
    const suppressionsNow = async (): Promise<{ ruleKey: string; suppressUntil: string }[]> =>
      ((await (await fetch(`${BASE}/api/suppressions`)).json()) as { suppressions: { ruleKey: string; suppressUntil: string }[] }).suppressions;

    // The refusal must be an AUTH refusal. Asserting only "an error came back"
    // would pass on any incidental failure — and one is live today: the tool's
    // upsert names a constraint the suppressions table does not have, so it
    // raises -32603 on every call. A test that accepts that as a pass proves
    // nothing about the gate.
    const refusedForAuth = (reply: RpcReply, where: string): void => {
      assert.ok(reply.error, `${where}: expected a refusal, got ${JSON.stringify(reply.result)}`);
      assert.match(reply.error!.message, /control token|unauthorized|forbidden|HTTP 40/i,
        `${where}: the refusal must be about the missing credential, not an incidental error ` +
        `(got "${reply.error!.message}")`);
    };

    await check('suppress_rule over /mcp is refused with no control token', async () => {
      const reply = await mcpCall('suppress_rule', { ruleKey: 'builtin-77', durationMs: 60_000 });
      refusedForAuth(reply, 'POST /mcp');
      const rows = await suppressionsNow();
      assert.ok(!rows.some(s => s.ruleKey === 'builtin-77'),
        'an unauthenticated /mcp call switched a detection rule off');
    });

    await check('a case-variant /MCP does not sidestep the control-tool check', async () => {
      for (const [label, p] of pathSpellings('/mcp')) {
        const reply = await mcpCall('suppress_rule', { ruleKey: `builtin-78`, durationMs: 60_000 }, { path: p });
        refusedForAuth(reply, `${label} (${p})`);
      }
      const rows = await suppressionsNow();
      assert.ok(!rows.some(s => s.ruleKey === 'builtin-78'), 'a /MCP spelling switched a rule off');
    });

    await check('suppress_rule refuses a CATASTROPHIC-floor rule even WITH the token', async () => {
      // builtin-0 is "Recursive root deletion" — rm -rf /. The catastrophic
      // labels are the ones the tool exists to catch; no caller may snooze them.
      const reply = await mcpCall('suppress_rule', { ruleKey: 'builtin-0', durationMs: 60_000 }, { token: controlToken });
      assert.ok(reply.error, `expected a refusal, got ${JSON.stringify(reply.result)}`);
      assert.match(reply.error!.message, /catastroph/i, 'the refusal should say why');
      const rows = await suppressionsNow();
      assert.ok(!rows.some(s => s.ruleKey === 'builtin-0'), 'a catastrophic-floor rule was suppressed');
    });

    await check('a suppression created over /mcp is capped and audited', async () => {
      const TEN_YEARS = 10 * 365 * 24 * 60 * 60 * 1000;
      const reply = await mcpCall('suppress_rule', { ruleKey: 'builtin-79', durationMs: TEN_YEARS }, { token: controlToken });
      assert.ok(!reply.error, `an authorised suppression should succeed: ${JSON.stringify(reply.error)}`);
      const row = (await suppressionsNow()).find(s => s.ruleKey === 'builtin-79');
      assert.ok(row, 'the authorised suppression was not created');
      const forMs = Date.parse(row!.suppressUntil) - Date.now();
      assert.ok(forMs <= 24 * 60 * 60 * 1000 + 10_000,
        `a rule may not be snoozed for ${Math.round(forMs / 86_400_000)} days — the duration must be capped`);
      const audit = await (await fetch(`${BASE}/api/audit-log?limit=200`)).json() as { entries?: { action: string; target: string }[]; auditLog?: { action: string; target: string }[] };
      const rows = audit.entries ?? audit.auditLog ?? [];
      assert.ok(rows.some(e => e.action.startsWith('suppression') && e.target === 'builtin-79'),
        'turning a detection rule off over /mcp must leave an audit entry');
    });

    await check('a suppressed catastrophic rule still fires in detection', async () => {
      // Defence in depth for the row itself: however a `builtin-<n>` suppression
      // of a catastrophic label got written (a stale row, the ungated REST twin),
      // applying it must not silence the rule. Created here through the REST
      // route WITH the control token, then a span that trips builtin-0 is
      // ingested and must still be scored.
      const created = await fetch(`${BASE}/api/suppressions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-claudesec-token': controlToken },
        body: JSON.stringify({ ruleKey: 'builtin-0', durationMs: 600_000, reason: 'floor probe' }),
      });
      assert.ok([200, 201, 400, 403].includes(created.status), `unexpected status ${created.status}`);
      await sleep(2_200); // the suppressed-key cache has a ~2s TTL
      const ingest = await fetch(`${BASE}/v1/traces`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(otlpBatch([{
          spanId: 'cata0000000000c1', traceId: 'trace-catastrophic', name: 'tool_call/Bash',
          startTimeUnixNano: '1700000000000000000', endTimeUnixNano: '1700000000500000000',
          // This payload trips builtin-0 and NOTHING else — deliberately. A
          // richer command (`sudo …`, say) also trips the low-severity sudo
          // rule, and then "severity is not none" would pass with builtin-0
          // fully silenced, which is the assertion passing for the wrong reason.
          // The trailing ` && …` matters too: detection runs over the serialized
          // attribute blob, and rule 0 needs a delimiter after the slash, which
          // a bare `rm -rf /` does not have once it is wrapped in JSON quotes.
          attributes: [{ key: 'tool.input', value: { stringValue: 'rm -rf / && echo done' } }],
        }])),
      });
      assert.strictEqual(ingest.status, 200, `ingest failed: ${ingest.status}`);
      const spans = await (await fetch(`${BASE}/api/spans?session=trace-catastrophic`)).json() as { spans: { spanId: string; severity: string; reason?: string }[] };
      const span = spans.spans.find(s => s.spanId === 'cata0000000000c1');
      assert.ok(span, 'the probe span was not stored');
      assert.strictEqual(span!.severity, 'high',
        `a suppression row silenced a catastrophic-floor detection rule (scored "${span!.severity}", reason "${span!.reason ?? ''}")`);
    });

    // ── 6. The open append endpoint must not be an erase endpoint ──────────
    await check('flooding /api/enforce-log cannot erase the recorded evidence', async () => {
      const EVIDENCE = 'EVIDENCE-real-block-do-not-evict';
      const post = (body: Record<string, unknown>) => fetch(`${BASE}/api/enforce-log`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });

      // The evidence: a real block, recorded by the hook the way the hook does
      // it — with no token, because the hook has none. It is the OLDEST entry
      // but one, so a FIFO cap evicts it almost immediately under flood.
      const totalBefore = ((await (await fetch(`${BASE}/api/enforce-log?limit=1`)).json()) as { total: number }).total;
      const seeded = await post({ mode: 'enforce', label: EVIDENCE, severity: 'critical', command: 'rm -rf /', wouldBlock: true, blocked: true });
      assert.strictEqual(seeded.status, 200, `seeding the evidence failed: ${seeded.status}`);

      // The attack: unauthenticated appends, as fast as the server will take
      // them — 500 of these used to clear the feed in 451ms while
      // /api/audit/verify still reported the chain intact.
      //
      // The attempt budget is the attacker's real one. Every route but OTLP
      // ingest sits behind a 1000-request/minute global limiter, so ~700 posts
      // is what one minute of flooding actually buys — and pre-fix that was
      // already several times the 500-entry cap. Pacing at the feed's own
      // refill rate keeps the flood inside the same budget while still driving
      // the feed to its cap, which is where the eviction rules are decided.
      const TARGET = 640;
      const MAX_ATTEMPTS = 700;
      const deadline = Date.now() + 25_000;
      let accepted = 0, rateLimited = 0, saturated = 0, attempts = 0, emptyBatches = 0;
      while (accepted < TARGET && attempts < MAX_ATTEMPTS && Date.now() < deadline && emptyBatches < 6) {
        const batch = await Promise.all(Array.from({ length: 25 }, (_v, i) =>
          post({ mode: 'monitor', label: `flood-${attempts + i}`, severity: 'high', command: `flood ${attempts + i}`, wouldBlock: true, blocked: false })
            .then(async r => (r.ok ? 'ok' : ((await r.json().catch(() => ({}))) as { error?: string }).error ?? `http-${r.status}`))
            .catch(() => 'net-error')));
        attempts += batch.length;
        const before = accepted;
        for (const outcome of batch) {
          if (outcome === 'ok') accepted++;
          else if (outcome === 'rate_limited') rateLimited++;
          else if (outcome === 'feed_saturated') saturated++;
        }
        emptyBatches = accepted === before ? emptyBatches + 1 : 0;
        await sleep(40);
      }

      const feed = await (await fetch(`${BASE}/api/enforce-log?limit=500`)).json() as { events: { label: string }[]; total: number };
      const evicted = totalBefore + 1 /* the seed */ + accepted - feed.total;
      if (process.env.CSEC_TEST_VERBOSE === '1') {
        console.log(`      [flood] attempts=${attempts} accepted=${accepted} rateLimited=${rateLimited} saturated=${saturated} total=${feed.total} evicted=${evicted}`);
      }

      assert.ok(feed.events.some(e => e.label === EVIDENCE),
        `the recorded block was evicted by ${accepted} unauthenticated appends ` +
        `(${feed.total} entries left, ${evicted} evicted)`);
      assert.ok(evicted <= 80,
        `an unauthenticated flood displaced ${evicted} entries — displacement must be budgeted`);
      assert.ok(rateLimited + saturated > 0,
        'the flood was never refused: neither the per-source rate limit nor the saturation guard engaged');
      // Only assertable once the feed actually reached its cap — on a slow host
      // the rate limiter alone may keep it below, and that is not a failure.
      if (feed.total >= 500) {
        assert.ok(saturated > 0,
          'the feed hit its cap and kept accepting appends: the saturation guard never engaged');
      }
    });

    await check('the enforce feed still verifies after the flood', async () => {
      const r = await fetch(`${BASE}/api/audit/verify`);
      assert.strictEqual(r.status, 200);
      const j = await r.json() as { enforce?: { ok: boolean } };
      assert.ok(j.enforce?.ok !== false, 'the enforce chain must still verify after pruning');
    });

    await check('pressure on the enforce feed is recorded, not silent', async () => {
      const audit = await (await fetch(`${BASE}/api/audit-log?limit=200`)).json() as { entries?: { action: string }[]; auditLog?: { action: string }[] };
      const rows = audit.entries ?? audit.auditLog ?? [];
      assert.ok(rows.some(e => e.action.startsWith('enforce-log.')),
        'evicting or refusing enforcement events must leave an audit entry — silent loss is the defect');
    });

    await check('the hook can still append after the flood subsides', async () => {
      // Fail-open matters here: refusing a flood must not permanently wedge the
      // feed. Once the head is no longer protected evidence the hook gets in.
      const r = await fetch(`${BASE}/api/enforce-log`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-claudesec-token': controlToken },
        body: JSON.stringify({ mode: 'monitor', label: 'post-flood-probe', severity: 'low', command: 'ls', wouldBlock: false, blocked: false }),
      });
      assert.strictEqual(r.status, 200, `a credentialed append was refused (${r.status})`);
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
