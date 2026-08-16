/**
 * tests/pairingRedirectTest.ts
 *
 * Gate for the pairing redirect in `tryPairing()` (server/index.ts).
 *
 * WHY THIS EXISTS. Presenting the out-of-band pairing key on a normal
 * navigation (`/?ct=<key>`) sets the mutation cookie and then redirects to the
 * same URL with the key removed, so the key never lands in browser history, a
 * Referer header, or the SPA's address bar. That redirect takes its target from
 * `req.path` — a value the caller writes — which is exactly the shape of an open
 * redirect, and CodeQL flags it as one (js/server-side-unvalidated-url-
 * redirection, alert 51).
 *
 * The guard in front of it admits only a string whose first character is `/` and
 * whose second, if present, is neither `/` nor `\`; everything else falls back
 * to `/`. This file is the evidence that the guard actually holds, because
 * "I read the regex and it looked right" is not evidence — the previous
 * pairing mechanism was deleted for exactly that reason.
 *
 * The requests are written onto a raw socket rather than through fetch(), on
 * purpose. A client library normalises the request target before it goes out, so
 * driving this with fetch() would only ever test targets that a well-behaved
 * client can express — and every interesting evasion here (absolute-form,
 * asterisk-form, raw control characters, unencoded backslashes, duplicated
 * leading slashes) is one that a client library would rewrite or refuse.
 *
 * WHAT COUNTS AS A FAILURE. Not "the Location header looks odd" — the only
 * question that matters is where a BROWSER ends up. So each response's Location
 * is resolved against the dashboard's own origin exactly as a user agent would
 * (`new URL(location, origin)`), and the assertion is that the result is still
 * on that origin. A Location of `/%2f%2fevil.example/` is fine: percent-encoded
 * separators stay encoded through `res.location`'s encodeurl, so a browser reads
 * them as path characters, not as the start of an authority.
 *
 * The suite also asserts that nothing reaches the response headers that should
 * not: `qs` is rebuilt from the request and concatenated after the guard runs,
 * so CRLF smuggled through the query string is checked for directly.
 *
 * Run via:  npx tsx tests/pairingRedirectTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure (or boot failure).
 *
 * DB DISCIPLINE: the child server runs with CLAUDESEC_DB + CLAUDESEC_HOME under
 * os.tmpdir(), removed in a finally block, and CLAUDESEC_WATCH=0 so it never
 * reads host transcripts. The real ~/.claudesec database is never opened.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'index.ts');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

const PORT = 3217;
const HOST = '127.0.0.1';
const ORIGIN = `http://${HOST}:${PORT}`;

const DB_PATH = path.join(os.tmpdir(), `csec-pairredir-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-pairredir-home-'));

// Seed the pairing key rather than reading the one the server mints, so the test
// never depends on a file-write race at boot. Same shape the server accepts.
const PAIR_KEY = crypto.randomBytes(32).toString('hex');
fs.mkdirSync(path.join(HOME_DIR, 'hooks'), { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(HOME_DIR, 'hooks', 'control-token'), `${PAIR_KEY}\n`, { mode: 0o600 });

/** The host an evasion is trying to reach. Never resolved — it is only a string. */
const EVIL = 'evil.example';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, ok: boolean, detail = ''): void {
  if (ok) { passed++; return; }
  failed++;
  failures.push(`${name}${detail ? `: ${detail}` : ''}`);
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function waitForServer(timeoutMs: number, earlyExit: () => string | null): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dead = earlyExit();
    if (dead) throw new Error(`server failed to start: ${dead}`);
    try {
      const r = await fetch(`${ORIGIN}/api/spans`, { signal: AbortSignal.timeout(1500) });
      if (r.status >= 200 && r.status < 500) return;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`server did not become ready on ${ORIGIN} within ${timeoutMs}ms`);
}

interface RawResponse {
  /** Status line, or '' when the connection produced nothing. */
  status: string;
  /** Location header verbatim, or '' when absent. */
  location: string;
  /** Whole response text, for header-injection assertions. */
  text: string;
}

/**
 * Write one request line onto a socket verbatim. Nothing normalises the target,
 * which is the entire point — see the file header.
 */
function raw(requestLine: string): Promise<RawResponse> {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, HOST);
    let buf = '';
    const done = () => {
      const status = (buf.split('\r\n')[0] ?? '').trim();
      const m = /\r\nLocation: (.*)\r\n/i.exec(buf);
      resolve({ status, location: m ? m[1] : '', text: buf });
    };
    sock.on('connect', () => {
      sock.write(`${requestLine}\r\nHost: ${HOST}:${PORT}\r\nConnection: close\r\n\r\n`);
    });
    sock.on('data', (d) => { buf += d.toString('latin1'); });
    sock.on('error', () => done());
    sock.on('close', () => done());
    setTimeout(() => { sock.destroy(); }, 4000);
  });
}

/**
 * Where a browser actually lands, given a Location and this origin. Returns null
 * when there was no redirect at all (which is a pass — nothing to point off-box).
 */
function resolveLocation(location: string): string | null {
  if (!location) return null;
  try { return new URL(location, `${ORIGIN}/`).href; }
  catch { return '(unparseable)'; }
}

/** Header lines the evasions try to smuggle in through the query string. */
const INJECTED_HEADER = /\r\n(?:Set-Cookie: injected|X-Injected|Evil):/i;

async function main(): Promise<void> {
  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        CLAUDESEC_HOME: HOME_DIR,
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_WATCH: '0',
        CLAUDESEC_TOKEN: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    });
    let stderr = '';
    let exited: string | null = null;
    child.stderr?.on('data', (d) => { stderr += d.toString(); });
    child.on('exit', (code) => { exited = `exit ${code}\n${stderr.slice(-2000)}`; });

    await waitForServer(45_000, () => exited);

    // ── 0. The redirect happens at all ───────────────────────────────────────
    // A suite of "no off-origin redirect" assertions is worthless if the handler
    // stopped redirecting. This is the liveness anchor for everything below.
    {
      const r = await raw(`GET /settings?ct=${PAIR_KEY}&tab=rules HTTP/1.1`);
      check('pairing redirects and strips the key',
        r.status.includes('302') && r.location === '/settings?tab=rules',
        `status=${r.status} location=${JSON.stringify(r.location)}`);
      check('pairing sets the control cookie',
        /\r\nSet-Cookie: claudesec_ct=/i.test(r.text),
        'no claudesec_ct cookie in the response');
    }

    // ── 1. Off-origin evasions ───────────────────────────────────────────────
    // Every request target below is an attempt to make the Location resolve to
    // somewhere other than this origin. Each must either not redirect, or
    // redirect somewhere still on this origin.
    const evasions: Array<[name: string, requestLine: string]> = [
      // Protocol-relative and its lookalikes — the shape the guard names.
      ['protocol-relative //host',        `GET //${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['triple slash ///host',            `GET ///${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['quad slash ////host',             `GET ////${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['backslash /\\host',               `GET /\\${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['backslash-slash /\\/host',        `GET /\\/${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['double backslash /\\\\host',      `GET /\\\\${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['slash-backslash /\\ mixed',       `GET /\\/\\${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],

      // Encoded separators — the classic way past a guard that only reads bytes.
      ['percent-encoded //',              `GET /%2f%2f${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['percent-encoded // upper',        `GET /%2F%2F${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['double-encoded //',               `GET /%252f%252f${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['percent-encoded backslash',       `GET /%5c%5c${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['overlong UTF-8 solidus',          `GET /%c0%af%c0%af${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['fullwidth solidus U+FF0F',        `GET /%ef%bc%8f%ef%bc%8f${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['line separator U+2028',           `GET /%e2%80%a8//${EVIL}?ct=${PAIR_KEY} HTTP/1.1`],
      ['null byte then //',               `GET /%00//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['encoded tab then //',             `GET /%09//${EVIL}?ct=${PAIR_KEY} HTTP/1.1`],
      ['encoded CR/LF then //',           `GET /%0d%0a//${EVIL}?ct=${PAIR_KEY} HTTP/1.1`],

      // Shapes a normalising proxy in front of the dashboard might rewrite.
      ['dot-segment /..//host',           `GET /..//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['dot-segment /.//host',            `GET /.//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['parent escape /../../host',       `GET /../..//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],

      // Authority-confusion characters that are legal in a path.
      ['userinfo /@host',                 `GET /@${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['semicolon /;//host',              `GET /;//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['colon /:/ /host',                 `GET /:${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],

      // Request-target forms other than origin-form.
      ['absolute-form http://host',       `GET http://${EVIL}/p?ct=${PAIR_KEY} HTTP/1.1`],
      ['absolute-form https://host',      `GET https://${EVIL}/p?ct=${PAIR_KEY} HTTP/1.1`],
      ['absolute-form with userinfo',     `GET http://user@${EVIL}/p?ct=${PAIR_KEY} HTTP/1.1`],
      ['network-path //host',             `GET //${EVIL}/p?ct=${PAIR_KEY} HTTP/1.1`],
      ['asterisk-form',                   `OPTIONS *?ct=${PAIR_KEY} HTTP/1.1`],

      // Raw control characters. Node's HTTP parser should refuse these outright;
      // the assertion is only that they never produce an off-origin Location.
      ['raw TAB in target',               `GET /\t//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['raw CR in target',                `GET /\r//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['raw LF in target',                `GET /\n//${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],

      // The query string is concatenated AFTER the guard runs.
      ['off-origin in the query',         `GET /?ct=${PAIR_KEY}&next=//${EVIL} HTTP/1.1`],
      ['absolute URL in the query',       `GET /?ct=${PAIR_KEY}&next=https://${EVIL} HTTP/1.1`],
      ['fragment before the key',         `GET /a#//${EVIL}?ct=${PAIR_KEY} HTTP/1.1`],
      ['fragment after the key',          `GET /a?ct=${PAIR_KEY}#//${EVIL} HTTP/1.1`],

      // Other safe methods reach the same code path.
      ['HEAD protocol-relative',          `HEAD //${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
      ['OPTIONS protocol-relative',       `OPTIONS //${EVIL}/?ct=${PAIR_KEY} HTTP/1.1`],
    ];

    for (const [name, line] of evasions) {
      const r = await raw(line);
      const landed = resolveLocation(r.location);
      const offOrigin = landed !== null && !landed.startsWith(`${ORIGIN}/`);
      check(`no off-origin redirect — ${name}`, !offOrigin,
        `Location=${JSON.stringify(r.location)} resolves to ${landed}`);
    }

    // ── 2. Header injection through the rebuilt query string ─────────────────
    // `qs` comes back out of URLSearchParams.toString(), which percent-encodes
    // everything it emits — but it is concatenated onto the Location after the
    // guard, so it gets its own assertions rather than an argument.
    const injections: Array<[name: string, requestLine: string]> = [
      ['encoded CRLF in a query value',   `GET /p?ct=${PAIR_KEY}&x=%0d%0aSet-Cookie:%20injected=1 HTTP/1.1`],
      ['encoded LF in a query value',     `GET /p?ct=${PAIR_KEY}&x=%0aEvil:%20yes HTTP/1.1`],
      ['encoded CRLF in a query name',    `GET /p?ct=${PAIR_KEY}&%0d%0aX-Injected:%20yes=1 HTTP/1.1`],
      ['encoded CRLF in the path',        `GET /%0d%0aX-Injected:%20yes?ct=${PAIR_KEY} HTTP/1.1`],
      ['plus-encoded CRLF',               `GET /p?ct=${PAIR_KEY}&x=%0D%0AX-Injected:+yes HTTP/1.1`],
    ];
    for (const [name, line] of injections) {
      const r = await raw(line);
      check(`no header injection — ${name}`, !INJECTED_HEADER.test(r.text),
        `response carried an injected header: ${JSON.stringify(r.text.slice(0, 400))}`);
      // A Location containing a bare CR or LF would be a split even if the
      // header name did not survive our pattern above.
      check(`Location has no bare CR/LF — ${name}`, !/[\r\n]/.test(r.location),
        JSON.stringify(r.location));
    }

    // ── 3. The redirect is not a general-purpose redirector ──────────────────
    // Without the key nothing redirects at all, so none of the above is reachable
    // by an unpaired caller in the first place.
    {
      const r = await raw(`GET //${EVIL}/?ct=not-the-key HTTP/1.1`);
      check('a wrong key produces no redirect', !r.status.includes('302'),
        `status=${r.status} location=${JSON.stringify(r.location)}`);
      const r2 = await raw(`GET //${EVIL}/ HTTP/1.1`);
      check('no key produces no redirect', !r2.status.includes('302'),
        `status=${r2.status} location=${JSON.stringify(r2.location)}`);
    }

    // ── 4. Legitimate targets still survive the guard ────────────────────────
    // The guard must not be so blunt that it sends every navigation to `/`; the
    // whole point is to return the operator to the page they asked for.
    const preserved: Array<[requestLine: string, expected: string]> = [
      [`GET /?ct=${PAIR_KEY} HTTP/1.1`, '/'],
      [`GET /alerts?ct=${PAIR_KEY} HTTP/1.1`, '/alerts'],
      [`GET /settings?ct=${PAIR_KEY}&tab=enforcement HTTP/1.1`, '/settings?tab=enforcement'],
      [`GET /a/b/c?ct=${PAIR_KEY}&x=1&y=2 HTTP/1.1`, '/a/b/c?x=1&y=2'],
    ];
    for (const [line, expected] of preserved) {
      const r = await raw(line);
      check(`target preserved — ${expected}`, r.location === expected,
        `got ${JSON.stringify(r.location)}`);
    }
  } finally {
    if (child?.pid) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group gone */ }
      try { child.kill('SIGKILL'); } catch { /* dead */ }
    }
    for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
      try { fs.rmSync(f, { force: true }); } catch { /* best effort */ }
    }
    try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
  }

  console.log(`\npairingRedirectTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    for (const f of failures) console.error(`  ✗ ${f}`);
    process.exit(1);
  }
  console.log('pairingRedirectTest: the pairing redirect stays same-origin');
}

main().catch((err) => {
  console.error(`pairingRedirectTest: ${(err as Error).message}`);
  process.exit(1);
});
