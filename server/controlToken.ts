// server/controlToken.ts
//
// The control-plane pairing key: the secret that separates "the operator's
// dashboard" from "some other process on this machine" for MUTATING /api calls.
//
// ── WHY THIS EXISTS IN THIS SHAPE ───────────────────────────────────────────
//
// ClaudeSec watches a local agent, so "the request came from loopback" says
// nothing about who sent it. It is worth being precise about why: a TCP
// connection to 127.0.0.1 carries no user or process identity. The kernel will
// not tell the listener which UID opened the socket, and no amount of header
// inspection recovers it. That is a property of sockets, not a bug we can fix.
//
// The previous design issued the mutation cookie to any loopback GET whose
// headers LOOKED like a browser's (`Sec-Fetch-Dest: document`, or an HTML
// `Accept`). Request headers are chosen by the client, so that test was
// self-certifying: three lines of `curl -H` earned the same cookie the dashboard
// got, and with it the ability to flip `enforce` back to `monitor` or disable
// rules. Anything derived only from the content of an HTTP request has that
// flaw, so the token cannot be granted by an HTTP request at all.
//
// So the key is delivered OUT OF BAND — the same answer Jupyter reached for the
// same reason. It is generated once, stored at 0600 under the enforcement
// control-plane directory, and handed to the browser exactly once as
// `http://localhost:PORT/?ct=<key>`, which `claudesec open` (or the startup
// banner on a real terminal) constructs. The server exchanges that for a
// derived, httpOnly cookie and redirects the key out of the URL.
//
// ── WHAT THIS DOES AND DOES NOT DEFEND AGAINST ──────────────────────────────
//
//   CLOSED: obtaining mutation rights over HTTP alone. There is no request —
//   with any headers, from any client — that causes the server to hand out a
//   usable token. A prompt-injected agent that can only make HTTP calls, a
//   malicious page in another tab, and a remote caller are all shut out.
//
//   CLOSED: escalating a stolen cookie into the master key. The cookie is
//   HMAC(key, …), not the key, and it is httpOnly so page script cannot read it.
//
//   NOT CLOSED: a process running as the same OS user that reads the key file.
//   It is 0600, and the agent IS the owner. What changed is the cost and the
//   visibility — the attack is now a filesystem read of a path inside the
//   self-protected control-plane directory rather than one unremarkable HTTP
//   request, and the enforcement floor already refuses to let that directory be
//   written, so the key cannot be REPLACED with an attacker-chosen value.
//   Making the key unreadable needs a second OS user; nothing at this layer can
//   substitute for that, and this file does not pretend otherwise.
//
//   NOT CLOSED: anything that can read the browser's cookie jar, drive the
//   browser, or read the operator's terminal scrollback.

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import { hooksDir } from './auditChain.js';

/** Cookie the paired browser presents on every same-origin mutation. */
export const CONTROL_COOKIE = 'claudesec_ct';
/** Header a script may present instead of the cookie. */
export const CONTROL_HEADER = 'x-claudesec-token';
/** Query parameter that exchanges the pairing key for the cookie. */
export const CONTROL_QUERY  = 'ct';

/**
 * The key lives under hooks/ deliberately. That whole directory is a
 * self-protection prefix in `server/enforceEval.ts` and the PreToolUse hook, so
 * the floor blocks WRITES to it in every mode. An attacker who could overwrite
 * this file with a value of their choosing would not need to read it at all.
 */
const KEY_FILE = 'control-token';

/** Only ever 64 lowercase hex chars; anything else is treated as corrupt. */
const KEY_PATTERN = /^[0-9a-f]{48,128}$/;

type KeySource = 'file' | 'ephemeral';

let cached: { key: string; source: KeySource } | null = null;

/** Absolute path of the pairing-key file. Honors CLAUDESEC_HOME via hooksDir(). */
export function controlKeyPath(): string {
  return path.join(hooksDir(), KEY_FILE);
}

function readKeyFile(file: string): string | null {
  try {
    const raw = fs.readFileSync(file, 'utf8').trim();
    return KEY_PATTERN.test(raw) ? raw : null;
  } catch {
    return null;
  }
}

/**
 * Resolve the pairing key, creating it on first run.
 *
 * If the file cannot be created (a read-only container, a CI sandbox) we fall
 * back to a process-lifetime random value and report `ephemeral`. That is not a
 * silent degradation: nothing can ever present that key, so mutations then
 * require CLAUDESEC_TOKEN, which is the correct answer for a deployment whose
 * state directory is not writable. The caller surfaces it at boot.
 */
function resolveKey(): { key: string; source: KeySource } {
  if (cached) return cached;

  const file = controlKeyPath();
  const existing = readKeyFile(file);
  if (existing) {
    cached = { key: existing, source: 'file' };
    return cached;
  }

  const minted = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${minted}\n`, { mode: 0o600 });
    // writeFileSync honors the umask on an existing file, so tighten explicitly.
    try { fs.chmodSync(file, 0o600); } catch { /* best-effort */ }
    // Re-read rather than trusting what we just wrote: if a second process
    // minted concurrently, the file is the tiebreaker and both agree.
    cached = { key: readKeyFile(file) ?? minted, source: 'file' };
  } catch {
    cached = { key: minted, source: 'ephemeral' };
  }
  return cached;
}

/** Where the key came from — 'ephemeral' means no client can ever present it. */
export function controlKeySource(): KeySource {
  return resolveKey().source;
}

/**
 * The value stored in the browser cookie: a domain-separated HMAC of the
 * pairing key rather than the key itself.
 *
 * Two reasons. It is stable across restarts, so a paired tab keeps working when
 * launchd bounces the service (the old boot-random token broke every tab). And
 * a cookie that leaks — an extension, a cookie-jar read, a future XSS — grants
 * API access but does not yield the key, so it cannot be turned into a fresh
 * pairing link or CLI credential. Possession of either still means mutation
 * rights; the derivation limits blast radius, it does not create a boundary.
 */
export function controlCookieValue(): string {
  return crypto
    .createHmac('sha256', resolveKey().key)
    .update('claudesec/control-cookie/v1')
    .digest('hex');
}

/** Constant-time comparison with a length guard (timingSafeEqual throws on
 *  unequal lengths, and the mismatched-length case is the attacker path). */
export function tokenMatches(presented: string | undefined | null, expected: string): boolean {
  if (!expected) return false;            // fail closed: no server token configured
  if (!presented) return false;
  const a = Buffer.from(String(presented));
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Does any of these candidate credentials satisfy the control plane?
 *
 * Both the pairing key and its derived cookie are accepted: the browser has the
 * cookie, and a script that legitimately holds the key (the CLI, a Makefile)
 * should not have to derive anything to use it.
 */
export function controlTokenAccepted(presented: string[]): boolean {
  if (presented.length === 0) return false;
  if (resolveKey().source === 'ephemeral') return false;  // nothing can hold it
  const key    = resolveKey().key;
  const cookie = controlCookieValue();
  return presented.some(t => tokenMatches(t, key) || tokenMatches(t, cookie));
}

/**
 * The one-time pairing link. Printing this anywhere durable — a log file, a
 * shell history, a screenshot — is equivalent to publishing the key, so callers
 * must only emit it to an interactive terminal or straight into a browser.
 */
export function pairingUrl(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/?${CONTROL_QUERY}=${resolveKey().key}`;
}

/** Test seam: drop the memoized key so a fixture can point CLAUDESEC_HOME
 *  somewhere else mid-process. Not used by the server. */
export function resetControlKeyCacheForTests(): void {
  cached = null;
}
