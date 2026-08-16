// server/keychain.ts
//
// A minimal, additive adapter over the macOS Keychain, used to hold the Ed25519
// audit signing key somewhere other than a file in ~/.claudesec/hooks.
//
// WHY: the signing key on disk is 0600 and owned by the same account the agent
// runs as, so the agent can read it, and — worse — delete it. Deleting the key
// and letting the server mint a fresh one on restart rebuilds a history that
// verifies perfectly under the new key. Moving the key into the Keychain does
// not make this machine's owner powerless (nothing local can), but it takes the
// key out of `cat`/`rm` range and turns its removal into an explicit,
// distinctive Keychain operation instead of an ordinary file delete.
//
// WHAT THIS IS NOT: a boundary against a same-user attacker who is willing to
// invoke `/usr/bin/security` themselves. Item ACLs discriminate by application,
// and `security` is the application in both cases. The real strengthening lever
// is pointing CLAUDESEC_KEYCHAIN_PATH at a DEDICATED keychain with its own
// password and an autolock, so the secret is unreadable while it is locked;
// with the default login keychain you get relocation, not confidentiality.
//
// PORTABILITY: every entry point returns false/null on a non-darwin host or when
// /usr/bin/security is missing. Linux, Docker, and CI keep the file path
// untouched — this module is never on their critical path.

import { execFileSync } from 'child_process';
import fs from 'fs';

const SECURITY_BIN = '/usr/bin/security';

/**
 * Hard cap on how long we will wait for `security`. A locked keychain makes it
 * pop a GUI unlock prompt, which never returns under launchd; without this the
 * audit path would hang the request that triggered it.
 */
const TIMEOUT_MS = 5_000;

export interface KeychainRef {
  service: string;
  account: string;
  /** Explicit keychain file. Omit for the user's default (login) keychain. */
  keychain?: string;
}

/** Is the Keychain usable on this host at all? */
export function keychainAvailable(): boolean {
  if (process.platform !== 'darwin') return false;
  try { return fs.existsSync(SECURITY_BIN); } catch { return false; }
}

function keychainArgs(ref: KeychainRef): string[] {
  return ref.keychain ? [ref.keychain] : [];
}

/**
 * Read a secret. Returns null for "not there" and for every failure mode —
 * callers must decide what a missing key means, and for the audit key the answer
 * is deliberately "report unsigned", never "mint a replacement".
 *
 * The secret is stored base64-encoded so a PEM's newlines survive the round trip
 * through `security`'s line-oriented interface.
 */
export function keychainRead(ref: KeychainRef): string | null {
  if (!keychainAvailable()) return null;
  try {
    const out = execFileSync(
      SECURITY_BIN,
      ['find-generic-password', '-a', ref.account, '-s', ref.service, '-w', ...keychainArgs(ref)],
      { encoding: 'utf8', timeout: TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    if (!out) return null;
    const decoded = Buffer.from(out, 'base64').toString('utf8');
    return decoded || null;
  } catch {
    return null;
  }
}

/**
 * Write (or replace) a secret.
 *
 * Driven through `security -i` — its batch mode — rather than as command-line
 * arguments. `security add-generic-password -w <secret>` puts the secret in
 * argv, where `ps` shows it to every process on the machine, which for this
 * particular secret would be a spectacular own goal. In batch mode the command
 * line arrives on stdin instead.
 */
export function keychainWrite(ref: KeychainRef, secret: string): boolean {
  if (!keychainAvailable()) return false;
  // Batch mode tokenises on whitespace and honours double quotes, and the
  // default service name has spaces in it, so every operand is quoted. A value
  // carrying a quote or a newline would break out of that, so it is rejected
  // rather than escaped — these are our own constants and env vars, and there is
  // no legitimate reason for one to contain either.
  if ([ref.account, ref.service, ref.keychain ?? ''].some(v => /["\r\n]/.test(v))) return false;
  const encoded = Buffer.from(secret, 'utf8').toString('base64');
  const q = (v: string) => `"${v}"`;
  const args = [
    'add-generic-password',
    '-a', q(ref.account),
    '-s', q(ref.service),
    '-D', q('ClaudeSec audit key'),
    '-U',
    // base64 is [A-Za-z0-9+/=] only, so it never needs quoting.
    '-w', encoded,
    ...keychainArgs(ref).map(q),
  ].join(' ');
  try {
    execFileSync(SECURITY_BIN, ['-i'], {
      input: `${args}\n`,
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    return keychainRead(ref) === secret;
  } catch {
    return false;
  }
}

/** Remove a secret. True when the item is gone afterwards (including "was never there"). */
export function keychainDelete(ref: KeychainRef): boolean {
  if (!keychainAvailable()) return false;
  try {
    execFileSync(
      SECURITY_BIN,
      ['delete-generic-password', '-a', ref.account, '-s', ref.service, ...keychainArgs(ref)],
      { timeout: TIMEOUT_MS, stdio: 'ignore' },
    );
  } catch {
    /* already absent, or refused — the read below is the real answer */
  }
  return keychainRead(ref) === null;
}
