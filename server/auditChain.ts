// server/auditChain.ts
//
// Hash chaining + an externally-signed tail anchor for the append-only records
// (operator audit log, enforcement feed, and the spans ledger).
//
// WHAT THIS CAN AND CANNOT DO — read this before trusting anything below.
//
//   • It DETECTS modification. It does not PREVENT it. Schneier & Kelsey (1998):
//     "no cryptographic method can be used to actually prevent the deletion of
//     log entries … the only thing cryptographic protocols can do is guarantee
//     detection." Everything here is a detection mechanism.
//   • COMPLETENESS CAN NEVER BE PROVEN. A record that was never written leaves
//     no cryptographic residue, so no verifier — ours or a third party's — can
//     tell "nothing happened" apart from "the writer was silenced". What we can
//     prove is that what WAS written has not been altered, reordered, or removed
//     without leaving a hole we can point at.
//   • A KEY ON THE MACHINE DOES NOT BIND THE MACHINE'S OWNER. Whoever controls
//     this host controls the signing key and can therefore mint a history that
//     verifies. Signing raises the bar for everyone else; it does not turn a
//     local log into a statement against the operator's own interest.
//
// DESIGN
//
//   1. ROW CHAIN. rowHash = sha256( canonical(fields…) + prevHash ), where
//      prevHash is the immediately-preceding row's rowHash. Editing any earlier
//      row breaks every hash from that point on and the verifier reports the
//      first id that no longer matches. The canonical form is a deterministic
//      JSON array with a FIXED field order — the array framing is what stops two
//      different field splits from colliding.
//
//   2. TAIL ANCHOR. The row chain alone cannot see its own boundaries: an empty
//      table is a valid empty chain, and lopping the newest N rows off the end
//      leaves a perfectly valid prefix. So the boundaries live OUTSIDE the table
//      they guard — a small JSON file under CLAUDESEC_HOME recording, per chain,
//      how many rows were ever appended, how many were ever deleted, and the id
//      and hash of the newest row. Verification compares the table against that
//      anchor, which is why "the table is empty" and "the table was emptied" are
//      now different answers.
//
//   2b. THE PIN ONLY MOVES OVER STATE THAT STILL VERIFIES. The anchor's whole
//      job is to let a verifier compare the record against a point in the past,
//      so advancing the pin is an assertion that everything the OLD pin covered
//      is still intact. It is therefore conditional: before the pin moves from
//      row P to a newer row, the probe is asked what hash row P carries RIGHT
//      NOW, and the move happens only if that is still, byte for byte, the hash
//      the anchor signed for P.
//
//      Why one row is enough. rowHash(P) is a function of row P's content and
//      rowHash(P-1), transitively of every row before it. Rewriting any row
//      k <= P forces a rewrite of every hash from k to P to keep the links
//      consistent — which changes rowHash(P). An attacker who declines to
//      re-thread instead leaves row k+1's stored prevHash pointing at a hash
//      that no longer exists, which the link walk reports. So "row P still
//      hashes to what we signed" plus "the links walk cleanly" covers the whole
//      prefix, at the cost of ONE indexed lookup per sweep rather than a
//      289,000-row rehash per append.
//
//      Without this, the pin was a moving target an attacker could wait out:
//      rewrite a row, re-thread the positions after it with the same PUBLIC
//      SHA-256 this file documents, then let the next append carry the anchor
//      forward onto the forged tail — a full forge of the record with no access
//      to the private key at all. The pin now freezes instead (`pinFrozenAt`),
//      the freeze is counted for good (`pinBreaks`), and nothing after a frozen
//      pin is reported as attested.
//
//   3. Ed25519 SIGNATURE over the anchor, NOT per row. Signing every row with an
//      asymmetric key would cost ~50µs each and buy nothing extra — the row
//      chain already binds the rows to each other. Signing only the anchor is
//      the Certificate-Transparency shape: cheap to produce, and a third party
//      holding ONLY the public key can re-derive every rowHash with plain
//      SHA-256 and check the signed tail. That is the concrete gain over the
//      HMAC this replaces:
//        (i)  an HMAC verifier necessarily holds the secret, so anyone who can
//             verify can also forge; a public-key verifier cannot.
//        (ii) a remote or different-UID attacker cannot produce a valid anchor.
//      It does NOT defeat this machine's owner, who holds the private key. Its
//      real value is that it is the prerequisite for anchoring the tail
//      somewhere we do not control (a notary, a peer, a transparency log) —
//      which is the only thing that can bind the owner.
//
//   4. KEY IDENTITY IS PART OF THE EVIDENCE. Deleting the database AND the key
//      and letting us mint a fresh one rebuilds a history that verifies — that
//      is unavoidable locally. What we can do is make the swap visible: the
//      public key's fingerprint (`keyId`) is reported by the verify endpoint and
//      the anchor records when the key was founded. Record the keyId off-box
//      once; a keyId that changes means the record was re-founded, whatever the
//      chain says about itself.
//      On macOS the key can optionally be moved into the Keychain, which puts it
//      out of `cat`/`rm` reach — see the "Keychain-backed storage" section below
//      for what that does and does not buy. Opt-in; nothing migrates on its own.
//
// LEGACY ROWS
//   • Rows written before hashing existed carry '' hashes. They are not part of
//     the chain; the verifier skips that prefix cleanly.
//   • Rows written by the previous HMAC-SHA256 scheme still verify: each row is
//     checked against SHA-256 first and, on mismatch, retried against the legacy
//     HMAC key if one is still present. Nothing is re-signed — history keeps the
//     hashes it was written with, and the cutover is simply the first row whose
//     hash is a plain SHA-256. `legacyHmacRows` in the status reports how many
//     rows are still on the old scheme, because those are exactly the rows a
//     third party CANNOT verify without our secret.

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  keychainAvailable, keychainDelete, keychainRead, keychainWrite, type KeychainRef,
} from './keychain.js';

// ── Paths ───────────────────────────────────────────────────────────────────
// Everything lives under the hooks/ prefix so the enforcement self-protection
// floor guards it from agent reads and replacement.

// Exported so server/auditAnchor.ts (the external-anchoring module) agrees with
// this file on where things live, rather than keeping a second copy that could
// drift — the anchor file and the checkpoint queue are siblings under hooks/.
export function claudesecHome(): string {
  return process.env.CLAUDESEC_HOME ?? path.join(os.homedir(), '.claudesec');
}

export function hooksDir(): string {
  return path.join(claudesecHome(), 'hooks');
}

const PRIVATE_KEY_FILE = 'audit-key.ed25519.pem';
const PUBLIC_KEY_FILE  = 'audit-key.pub.pem';
const LEGACY_HMAC_FILE = 'audit-key';
const ANCHOR_FILE      = 'audit-anchor.json';
// Written ONLY by the explicit migration below. Its presence is what makes the
// Keychain authoritative; without it nothing about key handling changes, which
// is why an existing install is untouched until someone opts in by hand.
const KEY_STORE_FILE   = 'audit-key.store.json';

// ── Legacy HMAC key (verification only — never minted any more) ──────────────
// Kept solely so rows written by the previous scheme keep verifying. We do NOT
// create this file; an install that never had one simply has no legacy rows.
let legacyHmacKey: Buffer | null | undefined;

function resolveLegacyHmacKey(): Buffer | null {
  if (legacyHmacKey !== undefined) return legacyHmacKey;
  legacyHmacKey = null;
  for (const p of [
    path.join(hooksDir(), LEGACY_HMAC_FILE),
    path.join(claudesecHome(), LEGACY_HMAC_FILE),
  ]) {
    try {
      if (fs.existsSync(p)) {
        const buf = fs.readFileSync(p);
        if (buf.length > 0) { legacyHmacKey = buf; break; }
      }
    } catch { /* unreadable key → simply no legacy verification */ }
  }
  return legacyHmacKey;
}

// ── Ed25519 signing key ─────────────────────────────────────────────────────

interface SigningKey {
  privatePem: string;
  publicPem:  string;
  keyId:      string;
  /** True when this process minted the key rather than finding one. */
  minted:     boolean;
}

let signingKey: SigningKey | null | undefined;

// ── Keychain-backed storage (macOS, opt-in, additive) ───────────────────────
//
// A file at 0600 is owned by the same account the monitored agent runs as, so
// the agent can read the private key and — the worse half — delete it, restart
// the service, and let it mint a clean replacement under which a fabricated
// history verifies. The macOS Keychain takes the key out of `cat`/`rm` range
// without a second OS account or a single `sudo`.
//
// It is OPT-IN AND NEVER AUTOMATIC. `claudesec audit-key to-keychain` is the
// only thing that writes the pointer file, and it verifies a real sign/verify
// round trip through the Keychain before it writes anything and before it will
// so much as rename the file on disk. An install that never runs it behaves
// exactly as it did before this existed, on every platform.
//
// See server/keychain.ts for what the Keychain does and does not buy you.

const KEYCHAIN_SERVICE_DEFAULT = 'ClaudeSec audit signing key';
const KEYCHAIN_ACCOUNT_DEFAULT = 'audit-key-ed25519';

/** Which Keychain item holds the key. CLAUDESEC_KEYCHAIN_PATH selects a
 *  dedicated keychain (recommended — see server/keychain.ts) or, unset, the
 *  user's default login keychain. Resolved per call, like every other path in
 *  this file, so a fixture can repoint it without reloading the module. */
function keychainRef(): KeychainRef {
  const keychain = process.env.CLAUDESEC_KEYCHAIN_PATH;
  return {
    service: process.env.CLAUDESEC_KEYCHAIN_SERVICE || KEYCHAIN_SERVICE_DEFAULT,
    account: process.env.CLAUDESEC_KEYCHAIN_ACCOUNT || KEYCHAIN_ACCOUNT_DEFAULT,
    ...(keychain ? { keychain } : {}),
  };
}

interface KeyStorePointer {
  store: 'keychain';
  keyId?: string;
  migratedAt?: string;
}

function keyStorePath(): string {
  return path.join(hooksDir(), KEY_STORE_FILE);
}

function readKeyStorePointer(): KeyStorePointer | null {
  try {
    const raw = JSON.parse(fs.readFileSync(keyStorePath(), 'utf8')) as KeyStorePointer;
    return raw && raw.store === 'keychain' ? raw : null;
  } catch {
    return null;   // absent or unparseable → the file store, i.e. no change
  }
}

/** Build a SigningKey from a PEM, or null if the PEM is not a usable Ed25519 key. */
function signingKeyFromPem(privatePem: string, minted: boolean): SigningKey | null {
  try {
    const publicPem = crypto
      .createPublicKey(privatePem)
      .export({ type: 'spki', format: 'pem' })
      .toString();
    return { privatePem, publicPem, keyId: fingerprint(publicPem), minted };
  } catch {
    return null;
  }
}

function readKeychainKey(): SigningKey | null {
  const pem = keychainRead(keychainRef());
  return pem ? signingKeyFromPem(pem, false) : null;
}

// Shell out to `security` at most once a minute while it is failing: a locked
// keychain would otherwise spawn a process per signature attempt.
let keychainWarnAt = 0;
function warnKeychainUnavailableOnce(): void {
  const now = Date.now();
  if (now - keychainWarnAt < 60_000) return;
  keychainWarnAt = now;
  console.warn(
    '[ClaudeSec] audit key is stored in the Keychain but could not be read — ' +
    'the anchor will be UNSIGNED until it is reachable again. ' +
    'Unlock the keychain, or run `claudesec audit-key to-file` to move back to disk.',
  );
}

/**
 * Verify that a PEM really signs and verifies before anyone relies on it.
 *
 * This is the gate the migration will not proceed without: a key that made the
 * round trip through base64, `security`'s stdin, and back is not proven usable
 * by the fact that the bytes compare equal — it is proven by producing a
 * signature over fresh random bytes and checking it against the public half.
 */
function keyRoundTrips(privatePem: string, expectPublicPem?: string): boolean {
  try {
    const nonce = crypto.randomBytes(32);
    const sig = crypto.sign(null, nonce, privatePem);
    const publicPem = crypto
      .createPublicKey(privatePem)
      .export({ type: 'spki', format: 'pem' })
      .toString();
    if (expectPublicPem && expectPublicPem.trim() !== publicPem.trim()) return false;
    return crypto.verify(null, nonce, publicPem, sig);
  } catch {
    return false;
  }
}

export interface AuditKeyStoreStatus {
  /** Where the key is read from RIGHT NOW. */
  store: 'file' | 'keychain' | 'none';
  keyId: string;
  /** The private-key file, whether or not it is currently authoritative. */
  filePath: string;
  fileExists: boolean;
  keychainAvailable: boolean;
  keychainHasItem: boolean;
  /** Set when the pointer says Keychain but the item cannot be read. */
  degraded: boolean;
}

/** Report where the audit key lives, without minting or moving anything. */
export function auditKeyStoreStatus(): AuditKeyStoreStatus {
  const filePath = path.join(hooksDir(), PRIVATE_KEY_FILE);
  const fileExists = (() => { try { return fs.existsSync(filePath); } catch { return false; } })();
  const available = keychainAvailable();
  const pointer = readKeyStorePointer();
  const item = available ? keychainRead(keychainRef()) : null;
  const keychainHasItem = item !== null;

  if (pointer?.store === 'keychain') {
    const key = item ? signingKeyFromPem(item, false) : null;
    return {
      store: 'keychain',
      keyId: key?.keyId ?? pointer.keyId ?? '',
      filePath, fileExists,
      keychainAvailable: available,
      keychainHasItem,
      degraded: key === null,
    };
  }

  let keyId = '';
  if (fileExists) {
    try { keyId = signingKeyFromPem(fs.readFileSync(filePath, 'utf8'), false)?.keyId ?? ''; } catch { /* unreadable */ }
  }
  return {
    store: fileExists ? 'file' : 'none',
    keyId, filePath, fileExists,
    keychainAvailable: available,
    keychainHasItem,
    degraded: false,
  };
}

export interface KeyMoveResult {
  ok: boolean;
  message: string;
  keyId?: string;
}

/**
 * Move the audit key from the file store into the macOS Keychain.
 *
 * Deliberately never called by the server: this only ever runs because a human
 * typed `claudesec audit-key to-keychain`. Auto-migrating a live chain would be
 * an unattended, hard-to-reverse operation on the one artifact that makes every
 * historical record verifiable, and getting it wrong is unrecoverable.
 *
 * Order of operations, and why:
 *   1. Read the file key. If there isn't one, stop — this command MOVES a key,
 *      it never founds one; a new identity must be a conscious separate act.
 *   2. Write it into the Keychain.
 *   3. Read it BACK OUT of the Keychain and prove it signs and verifies, with a
 *      public half identical to the on-disk key's. Any failure here removes the
 *      item we just wrote and aborts with the file untouched.
 *   4. Only then write the pointer file that makes the Keychain authoritative.
 *   5. The private key file is LEFT IN PLACE unless `removeFile` is passed, and
 *      even then it is renamed to `<name>.migrated`, never deleted. Reversing
 *      the migration is `claudesec audit-key to-file`.
 */
export function migrateAuditKeyToKeychain(opts: { removeFile?: boolean } = {}): KeyMoveResult {
  if (!keychainAvailable()) {
    return { ok: false, message: 'The macOS Keychain is not available on this host; the key stays in its file.' };
  }
  if (readKeyStorePointer()?.store === 'keychain') {
    return { ok: false, message: 'The audit key is already stored in the Keychain. Nothing to do.' };
  }

  const filePath = path.join(hooksDir(), PRIVATE_KEY_FILE);
  let privatePem: string;
  try {
    privatePem = fs.readFileSync(filePath, 'utf8');
  } catch {
    return { ok: false, message: `No audit key at ${filePath}. This command moves an existing key; it will not create one.` };
  }

  const parsed = signingKeyFromPem(privatePem, false);
  if (!parsed || !keyRoundTrips(privatePem)) {
    return { ok: false, message: `The key at ${filePath} does not sign and verify; refusing to migrate it.` };
  }

  if (!keychainWrite(keychainRef(), privatePem)) {
    return { ok: false, message: 'Writing the key into the Keychain failed. Nothing was changed.' };
  }

  const readBack = keychainRead(keychainRef());
  if (!readBack || !keyRoundTrips(readBack, parsed.publicPem)) {
    keychainDelete(keychainRef());
    return { ok: false, message: 'The Keychain copy did not round-trip a signature. The item was removed and the file is untouched.' };
  }

  try {
    fs.writeFileSync(
      keyStorePath(),
      `${JSON.stringify({ store: 'keychain', keyId: parsed.keyId, migratedAt: new Date().toISOString() }, null, 2)}\n`,
      { mode: 0o600 },
    );
  } catch (err) {
    keychainDelete(keychainRef());
    return { ok: false, message: `Could not write ${keyStorePath()} (${(err as Error).message}). The item was removed and the file is untouched.` };
  }

  let note = `The key file was left at ${filePath}; remove it yourself once you are satisfied.`;
  if (opts.removeFile) {
    const parked = `${filePath}.migrated`;
    try {
      fs.renameSync(filePath, parked);
      try { fs.chmodSync(parked, 0o600); } catch { /* best-effort */ }
      note = `The key file was renamed to ${parked} (never deleted).`;
    } catch (err) {
      note = `The key is in the Keychain, but the file could not be renamed (${(err as Error).message}); it is still at ${filePath}.`;
    }
  }

  signingKey = undefined;   // next resolve reads from the Keychain
  return { ok: true, keyId: parsed.keyId, message: `Audit key ${parsed.keyId} is now served from the Keychain. ${note}` };
}

/**
 * Reverse the migration: make the file store authoritative again.
 *
 * Restores the PEM from the Keychain (or from a `.migrated` rename) if the file
 * is gone, proves it round-trips BEFORE removing the pointer, and leaves the
 * Keychain item alone — deleting a copy of a signing key on the operator's
 * behalf is not this function's call to make.
 */
export function revertAuditKeyToFile(): KeyMoveResult {
  if (readKeyStorePointer()?.store !== 'keychain') {
    return { ok: false, message: 'The audit key is already served from its file. Nothing to do.' };
  }

  const filePath = path.join(hooksDir(), PRIVATE_KEY_FILE);
  const parked   = `${filePath}.migrated`;
  let privatePem: string | null = keychainRead(keychainRef());

  if (!privatePem) {
    for (const candidate of [filePath, parked]) {
      try { privatePem = fs.readFileSync(candidate, 'utf8'); break; } catch { /* try the next */ }
    }
  }
  if (!privatePem || !keyRoundTrips(privatePem)) {
    return { ok: false, message: 'Could not recover a working key from the Keychain or from disk. The pointer was left in place — do not delete it, or this install will found a NEW identity on next boot.' };
  }

  try {
    fs.mkdirSync(hooksDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, privatePem, { mode: 0o600 });
    try { fs.chmodSync(filePath, 0o600); } catch { /* best-effort */ }
    try { fs.rmSync(parked, { force: true }); } catch { /* best-effort */ }
  } catch (err) {
    return { ok: false, message: `Could not write ${filePath} (${(err as Error).message}). Nothing was changed.` };
  }

  // Only now is the file a complete, verified copy — so only now is it safe to
  // stop pointing at the Keychain.
  try {
    fs.rmSync(keyStorePath(), { force: true });
  } catch (err) {
    return { ok: false, message: `The key was restored to ${filePath} but ${keyStorePath()} could not be removed (${(err as Error).message}); the Keychain is still authoritative.` };
  }

  signingKey = undefined;
  const keyId = signingKeyFromPem(privatePem, false)?.keyId ?? '';
  return {
    ok: true,
    keyId,
    message: `Audit key ${keyId} is served from ${filePath} again. The Keychain still holds a copy — remove it with: security delete-generic-password -a ${keychainRef().account} -s '${keychainRef().service}'`,
  };
}

/** Test seam: drop the memoized key so a fixture can repoint CLAUDESEC_HOME or
 *  the Keychain mid-process. Not used by the server. */
export function resetSigningKeyCacheForTests(): void {
  signingKey = undefined;
  keychainWarnAt = 0;
}

/** Test seam: forget the in-memory anchor so the next read comes off disk.
 *  Needed by tests that write an anchor file behind this module's back — chiefly
 *  the one proving that an attacker WITH the private key can still mint an anchor
 *  that verifies. Not used by the server. */
export function resetAnchorCacheForTests(): void {
  anchorState = undefined;
  anchorDirty = false;
  anchorFileExisted = false;
  anchorSignatureValid = true;
}

/** Short, stable fingerprint of a public key — sha256 of its DER, first 32 hex. */
function fingerprint(publicPem: string): string {
  try {
    const der = crypto.createPublicKey(publicPem).export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
  } catch {
    return '';
  }
}

/**
 * Load the Ed25519 key pair, minting one on first run.
 *
 * `mint: false` asks only whether a key ALREADY exists and never creates one —
 * the mode a caller wants when signing is a side effect of serving a request
 * rather than of the chain's own bookkeeping. That negative answer is
 * deliberately not cached: the key file is shared, and a passing probe must not
 * decide on the anchor sweep's behalf that this install will never have one.
 *
 * Fail-open by contract: if the key cannot be read or written we return null and
 * the chain degrades to unsigned SHA-256 — still detection, just without the
 * anchor signature. An audit facility that crashes the server it audits is worse
 * than one that reports "unsigned".
 */
function resolveSigningKey(opts: { mint?: boolean } = {}): SigningKey | null {
  if (signingKey !== undefined) return signingKey;

  // The Keychain, when — and only when — this install explicitly moved there.
  if (readKeyStorePointer()?.store === 'keychain') {
    const fromKeychain = readKeychainKey();
    if (fromKeychain) {
      signingKey = fromKeychain;
      return signingKey;
    }
    // The operator deliberately moved the key off disk. If it is unreadable now
    // — keychain locked, ACL denied, `security` gone — the only safe answer is
    // "this install cannot sign". Falling through to the file path could mint a
    // REPLACEMENT identity, and a forged history would then verify cleanly under
    // a key nobody has ever seen. Degrade to unsigned instead, loudly, and do
    // not cache the failure so a later unlock recovers without a restart.
    warnKeychainUnavailableOnce();
    return null;
  }

  const mint    = opts.mint !== false;
  const dir     = hooksDir();
  const privPath = path.join(dir, PRIVATE_KEY_FILE);
  const pubPath  = path.join(dir, PUBLIC_KEY_FILE);
  try {
    if (fs.existsSync(privPath)) {
      const privatePem = fs.readFileSync(privPath, 'utf8');
      const publicPem  = crypto
        .createPublicKey(privatePem)
        .export({ type: 'spki', format: 'pem' })
        .toString();
      // Keep the exported public key on disk so a third party can be handed a
      // file rather than an API call.
      try { if (!fs.existsSync(pubPath)) fs.writeFileSync(pubPath, publicPem, { mode: 0o644 }); } catch { /* best effort */ }
      signingKey = { privatePem, publicPem, keyId: fingerprint(publicPem), minted: false };
      return signingKey;
    }
    if (!mint) return null;
    fs.mkdirSync(dir, { recursive: true });
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const publicPem  = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    // Private key owner-only; public key deliberately world-readable — its whole
    // purpose is to leave this machine.
    fs.writeFileSync(privPath, privatePem, { mode: 0o600 });
    try { fs.chmodSync(privPath, 0o600); } catch { /* best-effort tighten */ }
    fs.writeFileSync(pubPath, publicPem, { mode: 0o644 });
    signingKey = { privatePem, publicPem, keyId: fingerprint(publicPem), minted: true };
    return signingKey;
  } catch {
    if (!mint) return null;
    signingKey = null;
    return signingKey;
  }
}

/** True when this install can sign its anchor with the Ed25519 key. */
export function isAuditSigned(): boolean {
  return resolveSigningKey() !== null;
}

/**
 * Sign arbitrary bytes with the SAME Ed25519 key that signs the tail anchor.
 *
 * Used by server/auditAnchor.ts to produce COSE_Sign1 checkpoints under the same
 * key identity as the row-chain anchor, so an external verifier only ever needs
 * to trust one public key per install, not a second one minted for anchoring.
 *
 * Fail-open: returns null when no key is available (e.g. the key file could not
 * be read or written) rather than throwing — the caller falls back to skipping
 * the checkpoint entirely. A signature proves who signed, not that the signed
 * content is true; that ceiling applies here exactly as it does to the anchor.
 */
export function signWithAuditKey(data: Buffer): Buffer | null {
  const key = resolveSigningKey();
  if (!key) return null;
  try {
    return crypto.sign(null, data, key.privatePem);
  } catch {
    return null;
  }
}

/**
 * Sign bytes with the audit key ONLY when one already exists, reporting the key
 * identity alongside the signature.
 *
 * The difference from signWithAuditKey is the point of the function. Anchor
 * signing runs on this server's own clock and may legitimately found the key on
 * first use; producing an artifact for SOMEONE ELSE must never be the act that
 * mints an identity. A key an operator deliberately removed would otherwise come
 * back under a fresh keyId, and the artifact would carry a signature that
 * verifies perfectly against a key no recipient has ever seen — an attestation
 * that reads far stronger than it is.
 *
 * Returns null when no key is present so the caller can ship the artifact marked
 * unsigned. Same ceiling as everywhere else in this file: a signature proves who
 * signed, not that the signed content is true.
 */
export function signWithExistingAuditKey(data: Buffer): { signature: Buffer; keyId: string } | null {
  const key = resolveSigningKey({ mint: false });
  if (!key) return null;
  try {
    return { signature: crypto.sign(null, data, key.privatePem), keyId: key.keyId };
  } catch {
    return null;
  }
}

/** The public key, PEM-encoded — hand this to anyone who needs to verify. */
export function auditPublicKeyPem(): string {
  return resolveSigningKey()?.publicPem ?? '';
}

/** Fingerprint of the public key. Record this off-box: if it ever changes, the
 *  record was re-founded, no matter how cleanly the chain verifies. */
export function auditKeyId(): string {
  return resolveSigningKey()?.keyId ?? '';
}

// ── Row hashing ─────────────────────────────────────────────────────────────

/**
 * Deterministic canonical serialization of a row's fields. A JSON array preserves
 * order and JSON.stringify escapes every value unambiguously, so distinct field
 * sets can never serialize to the same string. The caller passes fields in a
 * FIXED order — that order is the contract, and changing it invalidates history.
 */
export function canonicalString(fields: Array<string | number | boolean | null | undefined>): string {
  // Map undefined → null so the framing is stable whether or not an optional
  // field (e.g. the auto-increment id, unknown before insert) is supplied.
  return JSON.stringify(fields.map(f => (f === undefined ? null : f)));
}

/**
 * A row's hash: plain SHA-256 over canonical content + the previous row's hash.
 *
 * Deliberately keyless. A keyed row hash would mean a third party needs our
 * secret to check the chain — the exact property we are trying to get rid of.
 * Unforgeability comes from the Ed25519 signature over the anchor instead.
 *
 * Fail-open: any hashing error returns '' (an empty hash links nothing and reads
 * as a legacy/unhashed row) rather than throwing into an insert path.
 */
export function computeRowHash(canonical: string, prevHash: string): string {
  try {
    return crypto.createHash('sha256').update(canonical + prevHash).digest('hex');
  } catch {
    return '';
  }
}

/** The pre-cutover HMAC-SHA256 hash, for verifying rows written by the old
 *  scheme. Returns '' when no legacy key exists (nothing to verify against). */
function computeLegacyHmacRowHash(canonical: string, prevHash: string): string {
  const key = resolveLegacyHmacKey();
  if (!key) return '';
  try {
    return crypto.createHmac('sha256', key).update(canonical + prevHash).digest('hex');
  } catch {
    return '';
  }
}

/**
 * Re-thread a contiguous slice of rows into a self-consistent chain that starts
 * fresh from prevHash=''. Used after pruning the oldest rows of a CAPPED log: the
 * new head's stored prevHash pointed at a now-deleted row, so we re-anchor the
 * head to '' and recompute every surviving row's hash. Returns the new tail
 * rowHash so callers can refresh their O(1) tail cache.
 *
 * Note what this costs: re-threading rewrites hashes, so the rewritten rows are
 * afterwards attested only by the anchor, not by their original hashes. That is
 * an acceptable trade for the two small capped logs. It is NOT how the spans
 * ledger handles retention — see the tombstone design in server/db.ts, which
 * keeps the original links intact across deletions.
 *
 * `rows` MUST be in ascending id order and carry the SAME canonical content used
 * at insert. Rows with an empty stored rowHash are legacy and are left alone.
 */
export function reanchorChain(
  rows: Array<{ id: number; rowHash: string; canonical: string }>,
  applyUpdate: (id: number, prevHash: string, rowHash: string) => void,
): string {
  let prev = '';
  let tail = '';
  for (const row of rows) {
    if (!row.rowHash) continue;
    const rowHash = computeRowHash(row.canonical, prev);
    // A re-thread is the one hash rewrite this server performs on purpose, so it
    // is also the one the conditional pin must be told about — otherwise the
    // next sweep would read the pinned row, find a hash it never signed, and
    // freeze the anchor over our own maintenance. See repinAfterRethread.
    repinAfterRethread(row.id, row.rowHash, rowHash);
    applyUpdate(row.id, prev, rowHash);
    prev = rowHash;
    tail = rowHash;
  }
  return tail;
}

/**
 * Carry the anchor's pin across a hash rewrite that THIS PROCESS performed.
 *
 * Reachable only from reanchorChain, i.e. only from the capped logs' prune path.
 * It is deliberately keyed on an exact (position, previous hash) pair rather than
 * on a chain name: the caller supplying the name would be one more thing a future
 * caller could forget, whereas a match here requires already knowing the hash the
 * anchor holds for that exact position — which is to say, requires being the code
 * that just rewrote it. The move is stamped (`rethreads` / `rethreadedAt`) so an
 * auditor sees that the pinned hash changed for a reason other than an append.
 *
 * Not persisted synchronously: the caller runs inside a SQLite transaction, and
 * flushing the anchor from inside one would sign a state that could still roll
 * back. The next sweep (<= ANCHOR_SWEEP_MS) seals it. A crash inside that window
 * leaves the anchor pinned to the pre-prune hash, which reports as tail_mismatch
 * — a false alarm rather than a missed detection, which is the direction this
 * whole file errs in.
 */
function repinAfterRethread(id: number, from: string, to: string): void {
  if (!from || !to || from === to) return;
  try {
    const state = loadAnchor();
    for (const entry of Object.values(state.chains)) {
      if (entry.lastId !== id || entry.lastRowHash !== from) continue;
      entry.lastRowHash = to;
      entry.rethreads   = (entry.rethreads ?? 0) + 1;
      entry.rethreadedAt = new Date().toISOString();
      entry.updatedAt   = entry.rethreadedAt;
      anchorDirty = true;
    }
  } catch { /* never break a prune */ }
}

// ── Tail anchor ─────────────────────────────────────────────────────────────
//
// The anchor is the answer to the two things a hash chain cannot see about
// itself: how many rows there are supposed to be, and where the chain is
// supposed to end. Both live OUTSIDE the table, in a small signed file under
// CLAUDESEC_HOME, which is why "the table is empty" and "the table was emptied"
// are now different answers.
//
// HOW THE COUNTS ARE KEPT HONEST. Every guarded table uses INTEGER PRIMARY KEY
// AUTOINCREMENT, so SQLite's own `sqlite_sequence` holds the highest id ever
// allocated — a number that does not go down when rows are deleted. The spans
// chain has the same property in `chainSeq`. A probe reads that high-water mark
// and the current tail, and the anchor takes the MAXIMUM of what it already
// recorded and what it just saw. Monotonic on purpose: an attacker who deletes
// rows can lower what the database reports, but not what we already signed, so
// the discrepancy is exactly what verification reports.
//
// This deliberately needs no cooperation from the code that writes the rows. An
// earlier version maintained the anchor from SQLite triggers calling back into
// JavaScript, which worked but made the database unopenable by anything except
// this process — `sqlite3 spans.db` failed on "no such function". A security
// tool that makes its own evidence file unreadable by standard tools has traded
// the wrong thing.

/** Per-chain boundary record. Kept OUTSIDE the table it guards, on purpose. */
export interface ChainAnchorEntry {
  /** High-water mark of rows ever written to this chain. Monotonic — the anchor
   *  never lowers it, whatever the database claims later. */
  appended: number;
  /** The table's id high-water mark at the moment this chain was founded or
   *  re-founded. Row counts are measured relative to it, so a deliberate reset
   *  starts the count from zero without the (never-reset) sqlite_sequence
   *  dragging the old total along with it. */
  origin: number;
  /** id (audit/enforce) or chainSeq (spans) of the newest row seen. */
  lastId: number;
  /** rowHash of that row. */
  lastRowHash: string;
  /** Positions at which a new chain segment legitimately begins, i.e. rows whose
   *  prevHash is '' by design (chain genesis, or the boundary armed when a
   *  backfill reserved a range for pre-existing rows). Recorded when it happens
   *  so a verifier can tell a designed restart from a severed link. */
  segments: number[];
  foundedAt: string;
  updatedAt: string;
  /** When a backfill adopted pre-existing rows as this chain's baseline, and how
   *  many. Recorded because it is a real limit on what the chain proves: rows
   *  adopted at that moment are attested from then on, NOT from when they were
   *  written. Anything done to them before adoption left no residue. */
  adoptedAt?: string;
  adoptedRows?: number;
  /** When the chain was deliberately re-founded (an operator reset). Recorded
   *  rather than silently forgotten — a re-founded chain makes no claim about
   *  anything that happened before this timestamp. */
  refoundedAt?: string;
  /** Set while the pin is FROZEN: the row this anchor had pinned no longer
   *  carries the hash it was pinned with, so the pin refuses to move forward and
   *  nothing newer than it is attested. Cleared if the pinned state comes back
   *  (an operator restoring a good copy), which is why the count below is the
   *  durable half of the evidence. */
  pinFrozenAt?: string;
  /** The position that stopped matching. */
  pinFrozenId?: number;
  /** How many times this anchor has ever refused to advance. Never decreases:
   *  a chain that verifies today but reports pinBreaks > 0 was, at some moment,
   *  inconsistent with what had already been signed. */
  pinBreaks?: number;
  /** Pin moves caused by this server re-threading a capped log after a prune,
   *  rather than by an append. Stamped because the pinned hash changing without
   *  the position changing is otherwise exactly what tampering looks like. */
  rethreads?: number;
  rethreadedAt?: string;
  /** How many times the pinned position had already been pruned away by a capped
   *  log's own retention when the anchor next looked. Counted rather than
   *  silently allowed, because it marks a stretch of a capped log the pin never
   *  got to cover. */
  pinsPruned?: number;
}

interface AnchorFile {
  v: 1;
  keyId: string;
  publicKey: string;
  chains: Record<string, ChainAnchorEntry>;
  updatedAt: string;
  /** Ed25519 signature (base64) over the canonical payload below. */
  sig: string;
}

/** What a probe reports about a table's current state. */
export interface ChainProbeReading {
  /** Highest row id / chain position ever allocated (sqlite_sequence or MAX). */
  appended: number;
  lastId: number;
  lastRowHash: string;
  /**
   * Lowest id still present, for a chain that drops its oldest rows on purpose
   * (the two capped logs). A pinned position BELOW this fell out of the retention
   * window rather than being tampered with, which is the one case where the pin
   * may be re-founded without the old one verifying.
   *
   * That is safe precisely because pruning is oldest-first: for the pinned row to
   * be gone, every row before it is gone too, so there is nothing left below the
   * pin for a rewrite to hide in. Deletions that are NOT the cap doing its job
   * still show up, as a row count short of min(everWritten, cap).
   *
   * Omit (or 0) for a chain that never loses a position — the spans ledger keeps
   * a tombstone for every deletion, so nothing there is ever legitimately absent.
   */
  firstId?: number;
}

/** How the anchor reads a guarded table. Two questions, both cheap. */
export interface ChainProbe {
  /** The table's high-water mark and current tail. */
  read(): ChainProbeReading;
  /**
   * The hash the table stores at position `id` right now, or null when that
   * position is no longer present at all (for chains with tombstones, a
   * tombstoned position IS present — it keeps its hash).
   *
   * This is what makes re-anchoring conditional, so it must be an indexed point
   * lookup: it runs once per chain per sweep, and a sequential scan here would
   * put a full table read on a 5-second timer.
   */
  pin(id: number): string | null;
}

/** The exact bytes that get signed. Chain names are sorted so the payload is
 *  byte-stable regardless of insertion order. */
function anchorPayload(file: Omit<AnchorFile, 'sig'>): string {
  const chains: Record<string, ChainAnchorEntry> = {};
  for (const name of Object.keys(file.chains).sort()) chains[name] = file.chains[name];
  return JSON.stringify({ v: file.v, keyId: file.keyId, publicKey: file.publicKey, chains, updatedAt: file.updatedAt });
}

let anchorState: AnchorFile | undefined;
let anchorSignatureValid = true;
let anchorFileExisted = false;
let anchorDirty = false;
let sweepTimer: NodeJS.Timeout | null = null;

const probes = new Map<string, ChainProbe>();

function anchorPath(): string {
  return path.join(hooksDir(), ANCHOR_FILE);
}

function emptyAnchor(): AnchorFile {
  const key = resolveSigningKey();
  return { v: 1, keyId: key?.keyId ?? '', publicKey: key?.publicPem ?? '', chains: {}, updatedAt: new Date().toISOString(), sig: '' };
}

function verifyAnchorSignature(file: AnchorFile): boolean {
  try {
    if (!file.sig || !file.publicKey) return false;
    const payload = anchorPayload({ v: file.v, keyId: file.keyId, publicKey: file.publicKey, chains: file.chains, updatedAt: file.updatedAt });
    return crypto.verify(null, Buffer.from(payload, 'utf8'), file.publicKey, Buffer.from(file.sig, 'base64'));
  } catch {
    return false;
  }
}

function loadAnchor(): AnchorFile {
  if (anchorState !== undefined) return anchorState;
  try {
    const parsed = JSON.parse(fs.readFileSync(anchorPath(), 'utf8')) as AnchorFile;
    anchorFileExisted = true;
    // Verify the signature against the key recorded IN the file. A file signed
    // by some other key is not so much "invalid" as "not ours" — either way we
    // refuse to treat it as attested, and the keyId is what an auditor compares.
    anchorSignatureValid = verifyAnchorSignature(parsed);
    anchorState = parsed;
  } catch {
    anchorFileExisted = false;
    anchorSignatureValid = true;   // nothing on disk yet, so nothing to disbelieve
    anchorState = emptyAnchor();
  }
  return anchorState;
}

function entryFor(chain: string): ChainAnchorEntry {
  const state = loadAnchor();
  let entry = state.chains[chain];
  if (!entry) {
    const now = new Date().toISOString();
    entry = { appended: 0, origin: 0, lastId: 0, lastRowHash: '', segments: [], foundedAt: now, updatedAt: now };
    state.chains[chain] = entry;
    anchorDirty = true;
  }
  if (!Array.isArray(entry.segments)) entry.segments = [];
  return entry;
}

/**
 * Register the reader that keeps a chain's anchor current.
 *
 * Called once per guarded table from server/db.ts, which is the only module that
 * holds the database handle. The probe is read on a timer and before any
 * verification, so no write path has to remember to update anything.
 */
export function registerChainProbe(chain: string, probe: ChainProbe): void {
  probes.set(chain, probe);
  refreshChainAnchors();
}

/**
 * Fold every probe reading into the anchor.
 *
 * Two different rules, because the two numbers mean different things.
 *
 *   • `appended` is a high-water mark, so it only ever goes UP. Raising it is
 *     always safe: it can only ever increase what verification demands of the
 *     table, never excuse a shortfall.
 *   • the PIN (`lastId` + `lastRowHash`) is a claim about the past, so moving it
 *     forward is only sound while the state it already covered is still intact.
 *     Before the pin advances we ask the probe what hash the currently pinned
 *     position holds and require it to equal what we signed. See the "2b" note
 *     at the top of this file for why checking that ONE row is sufficient — and
 *     for what an unconditional advance let an attacker do without a key.
 *
 * When the check fails the pin does not move. It stays where it is, the freeze
 * is stamped and counted, and every verifier downstream reports the chain as
 * unattested past that point rather than quietly re-baselining onto whatever the
 * table happens to say now.
 */
export function refreshChainAnchors(): void {
  const now = () => new Date().toISOString();
  for (const [chain, probe] of probes) {
    try {
      const r = probe.read();
      const e = entryFor(chain);
      // Measured from the chain's origin, so a re-founded chain counts its own
      // rows rather than every row the table ever held.
      const effective = Math.max(0, r.appended - (e.origin ?? 0));
      if (effective > e.appended) { e.appended = effective; anchorDirty = true; }

      // Never lower the pin, and never re-pin in place: at the same position we
      // keep what we signed, so rewriting a row cannot launder itself in.
      if (r.lastId <= e.lastId) continue;

      // Nothing pinned yet — the first reading founds the pin, and there is no
      // earlier claim for it to contradict.
      if (!e.lastRowHash) {
        e.lastId = r.lastId; e.lastRowHash = r.lastRowHash; e.updatedAt = now();
        anchorDirty = true;
        continue;
      }

      // The pinned row fell off the front of a capped log. Not tampering — see
      // ChainProbeReading.firstId for why re-founding the pin here hides nothing.
      if (r.firstId !== undefined && r.firstId > 0 && e.lastId < r.firstId) {
        e.pinsPruned = (e.pinsPruned ?? 0) + 1;
        e.lastId = r.lastId; e.lastRowHash = r.lastRowHash; e.updatedAt = now();
        anchorDirty = true;
        continue;
      }

      if (probe.pin(e.lastId) !== e.lastRowHash) {
        // The row we pinned is gone, or carries a hash we never signed. Freeze:
        // whatever happens after this is not covered by anything we can stand
        // behind, and saying so is the entire point of the anchor.
        if (!e.pinFrozenAt) {
          e.pinFrozenAt = now();
          e.pinFrozenId = e.lastId;
          e.pinBreaks   = (e.pinBreaks ?? 0) + 1;
          anchorDirty   = true;
        }
        continue;
      }

      // The pinned state held. Thaw (the break stays counted in pinBreaks — that
      // is the durable record that something was once inconsistent) and advance.
      if (e.pinFrozenAt) {
        delete e.pinFrozenAt;
        delete e.pinFrozenId;
      }
      e.lastId = r.lastId;
      e.lastRowHash = r.lastRowHash;
      e.updatedAt = now();
      anchorDirty = true;
    } catch { /* a probe that throws must not break the sweep */ }
  }
}

/**
 * Persist the anchor atomically at 0600.
 *
 * Atomic because a half-written anchor reads as a wiped record and would cry
 * wolf on every restart: write a sibling temp file, fsync it, rename over the
 * target. rename(2) within a directory is atomic, so a reader sees either the
 * whole old file or the whole new one.
 */
export function flushChainAnchors(): void {
  refreshChainAnchors();
  if (!anchorDirty || anchorState === undefined) return;
  const key = resolveSigningKey();
  const state = anchorState;
  state.updatedAt = new Date().toISOString();
  state.keyId     = key?.keyId ?? '';
  state.publicKey = key?.publicPem ?? '';
  const payload = anchorPayload({ v: state.v, keyId: state.keyId, publicKey: state.publicKey, chains: state.chains, updatedAt: state.updatedAt });
  try {
    state.sig = key ? crypto.sign(null, Buffer.from(payload, 'utf8'), key.privatePem).toString('base64') : '';
  } catch {
    state.sig = '';
  }
  try {
    fs.mkdirSync(hooksDir(), { recursive: true });
    const target = anchorPath();
    const tmp    = `${target}.${process.pid}.tmp`;
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      fs.writeFileSync(fd, JSON.stringify(state));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, target);
    anchorDirty = false;
    anchorFileExisted = true;
    anchorSignatureValid = state.sig !== '';
  } catch {
    // Fail-open: an unwritable anchor must not break the write path it guards.
    // The next sweep retries, and verification meanwhile reports the chain as
    // less attested rather than pretending everything is fine.
  }
}

/**
 * Seal the anchor on a slow timer rather than on every write.
 *
 * Signing costs an fsync, and the spans chain appends thousands of rows a
 * minute; one fsync per span would be a real ingest cost for no extra safety.
 * The consequence is honest and bounded: rows written since the last sweep are
 * "unsealed" — still chained to each other, just not yet covered by a signed
 * count. Verification says so rather than glossing over it, and a clean shutdown
 * seals whatever is outstanding (see checkpointAndClose in server/db.ts).
 */
export const ANCHOR_SWEEP_MS = 5_000;

function startAnchorSweep(): void {
  if (sweepTimer) return;
  sweepTimer = setInterval(() => flushChainAnchors(), ANCHOR_SWEEP_MS);
  // unref so the sweep never keeps the process alive on its own.
  if (typeof sweepTimer.unref === 'function') sweepTimer.unref();
}
startAnchorSweep();

/**
 * Read-only view of a chain's anchor.
 *
 * Refreshes from the probe and seals before answering, so a verification always
 * compares against a freshly signed anchor rather than whatever the sweep last
 * happened to write. That is safe in the direction that matters: the fold is
 * monotonic, so a table that just lost rows cannot lower what was already
 * recorded — the refresh sees the damage, keeps the old numbers, and the
 * discrepancy is exactly what gets reported.
 */
export function getChainAnchor(chain: string): ChainAnchorEntry | null {
  loadAnchor();
  flushChainAnchors();
  return anchorState?.chains[chain] ?? null;
}

/** True when the anchor file on disk carried a signature we could verify. */
export function anchorIsSigned(): boolean {
  loadAnchor();
  return anchorFileExisted && anchorSignatureValid;
}

/** True when an anchor file exists on disk at all. */
export function anchorExists(): boolean {
  loadAnchor();
  return anchorFileExisted;
}

/** Declare a designed segment start at `id` — a row whose prevHash is '' because
 *  the chain genuinely restarts there, not because a link was severed. */
export function recordChainSegment(chain: string, id: number): void {
  try {
    const e = entryFor(chain);
    if (!e.segments.includes(id)) { e.segments.push(id); anchorDirty = true; }
  } catch { /* never break a write */ }
}

/**
 * Adopt the rows currently in a table as the chain's baseline.
 *
 * Used once, when a backfill finishes hashing rows that predate the chain. It is
 * an ADOPTION, not a retroactive guarantee: from this moment those rows cannot
 * be altered undetected, but nothing here says anything about what happened to
 * them before. The event is stamped into the anchor (`adoptedAt` / `adoptedRows`)
 * precisely so an auditor can see where the guarantee starts.
 */
export function adoptChainBaseline(
  chain: string,
  baseline: { rows: number; lastId: number; lastRowHash: string },
): void {
  try {
    const e = entryFor(chain);
    e.appended    = Math.max(e.appended, baseline.rows, baseline.lastId);
    if (baseline.lastId >= e.lastId) { e.lastId = baseline.lastId; e.lastRowHash = baseline.lastRowHash; }
    e.adoptedAt   = new Date().toISOString();
    e.adoptedRows = baseline.rows;
    e.updatedAt   = e.adoptedAt;
    anchorDirty   = true;
    flushChainAnchors();
  } catch { /* never break the backfill */ }
}

/**
 * Deliberately re-found a chain, discarding what the anchor knew.
 *
 * The only legitimate use is an operator reset — a chain whose table was
 * intentionally emptied would otherwise report `wiped` forever. It is a real
 * erasure of evidence, so it is stamped (`refoundedAt`) and the re-founded chain
 * makes no claim at all about anything before that moment.
 */
export function refoundChain(chain: string): void {
  try {
    const state = loadAnchor();
    const now = new Date().toISOString();
    const previous = state.chains[chain];
    state.chains[chain] = {
      appended: 0, origin: probes.get(chain)?.read().appended ?? 0,
      lastId: 0, lastRowHash: '', segments: [],
      foundedAt: previous?.foundedAt ?? now,
      updatedAt: now,
      refoundedAt: now,
    };
    anchorDirty = true;
    flushChainAnchors();
  } catch { /* never break a reset */ }
}

// ── Verification ────────────────────────────────────────────────────────────

/**
 * What the verifier concluded. "ok / not ok" is not enough for an auditor — the
 * distinction between "this row was edited", "the end was cut off" and "the
 * whole table was emptied" is the difference between three very different
 * incidents, so each gets its own verdict.
 */
export type ChainVerdict =
  | 'ok'               // every hashed row recomputes, and matches the anchor
  | 'row_mismatch'     // a row's content no longer hashes to its stored rowHash
  | 'wiped'            // rows the anchor accounts for are gone, or every hash was blanked
  | 'truncated'        // fewer rows present than the anchor accounts for
  | 'tail_mismatch'    // the row the anchor pinned is present but carries a different hash
  | 'tail_unpinned'    // the anchor accounts for rows but pins no tail hash to check them against
  | 'anchor_missing'   // the table holds chained rows but no anchor exists
  | 'anchor_unsigned'  // an anchor exists but its Ed25519 signature does not verify
  | 'unanchored';      // nothing chained and nothing anchored — no claim either way

export interface ChainStatus {
  /** No evidence of tampering. NOT a claim that the record is complete. */
  ok: boolean;
  status: ChainVerdict;
  /** One line an operator can read without knowing the internals. */
  detail: string;
  rows: number;         // total rows scanned
  hashedRows: number;   // rows that participate in the chain
  /** Rows still verified with the pre-cutover HMAC — a third party holding only
   *  the public key CANNOT check these. */
  legacyHmacRows: number;
  brokenAtId?: number;
  /** The chain's boundaries are covered by a signed anchor AND that anchor is
   *  still advancing — a frozen pin means everything newer than it is covered by
   *  nothing, so this is false however good the signature is. */
  attested: boolean;
  /** How many times the anchor has ever refused to advance because the state it
   *  had pinned stopped verifying. Non-zero is durable evidence even on a chain
   *  that verifies today. */
  anchorPinBreaks?: number;
  /** Set while the pin is frozen: when it froze, and at which row. */
  pinFrozenAt?: string;
  pinFrozenId?: number;
  /** An Ed25519 signing key is available on this install. */
  signed: boolean;
  expectedRows?: number;
  anchoredId?: number;
  keyId?: string;
}

export interface ChainRow {
  id: number;
  prevHash: string;
  rowHash: string;
  /** Canonical string of this row's content fields, in the fixed order. */
  canonical: string;
}

export interface VerifyOptions {
  /** Anchor name for this table. Omit to verify the row links only. */
  chain?: string;
  /** Retained-row cap, for the two logs that prune their oldest rows on insert.
   *  With it, the expected row count is exactly min(everWritten, cap) — which is
   *  why those two chains need no deletion bookkeeping at all: legitimate
   *  pruning is fully described by the cap, so any shortfall against it is a
   *  deletion that did not come from the cap. Omit for an uncapped chain. */
  cap?: number;
}

/**
 * Recompute the chain top-to-bottom (ascending id) and compare it to the anchor.
 *
 * Legacy handling: rows with an empty stored rowHash predate hashing and are
 * skipped — they are not part of the chain. The chain "starts" at the first row
 * with a non-empty rowHash.
 */
export function verifyChain(rows: ChainRow[], opts: VerifyOptions = {}): ChainStatus {
  const signed = isAuditSigned();
  const keyId  = auditKeyId();
  const anchor = opts.chain ? getChainAnchor(opts.chain) : null;
  const anchored = anchor !== null && anchor.appended > 0;
  const expected = anchor
    ? (opts.cap !== undefined ? Math.min(anchor.appended, opts.cap) : anchor.appended)
    : 0;
  // A frozen pin is not a signature problem — the anchor may be perfectly signed
  // — but it means the anchor stopped covering the table at some earlier row, so
  // there is nothing to attest the current state with. Reporting attested:true
  // here would be the exact claim we cannot make.
  const pinFrozen = Boolean(anchor?.pinFrozenAt);
  const attested = anchored && anchorIsSigned() && !pinFrozen;

  let hashedRows = 0;
  let legacyHmacRows = 0;
  let prev = '';
  let tail = '';
  let tailId = 0;

  const base = (status: ChainVerdict, detail: string, extra: Partial<ChainStatus> = {}): ChainStatus => ({
    ok: status === 'ok' || status === 'unanchored',
    status,
    detail,
    rows: rows.length,
    hashedRows,
    legacyHmacRows,
    attested,
    signed,
    keyId,
    expectedRows: anchor ? expected : undefined,
    anchoredId: anchor?.lastId,
    ...(anchor?.pinBreaks ? { anchorPinBreaks: anchor.pinBreaks } : {}),
    ...(anchor?.pinFrozenAt ? { pinFrozenAt: anchor.pinFrozenAt, pinFrozenId: anchor.pinFrozenId } : {}),
    ...extra,
  });

  for (const row of rows) {
    if (!row.rowHash) continue;   // legacy, unhashed prefix
    hashedRows++;

    if (computeRowHash(row.canonical, prev) === row.rowHash) {
      // Current scheme.
    } else if (computeLegacyHmacRowHash(row.canonical, prev) === row.rowHash && row.rowHash !== '') {
      // Pre-cutover HMAC row. Accepted, but counted — it is exactly the set of
      // rows an external verifier cannot check without our secret.
      legacyHmacRows++;
    } else {
      return base('row_mismatch', `Row ${row.id} no longer hashes to its stored value — its content was changed, or a row before it was removed.`, { brokenAtId: row.id });
    }
    prev = row.rowHash;
    tail = row.rowHash;
    tailId = row.id;
  }

  // Wipe detection that does not need the anchor: a chained table whose rows all
  // carry an empty rowHash means every hash was blanked (or an all-legacy
  // database was swapped in to defeat verification).
  if (rows.length > 0 && hashedRows === 0) {
    return base('wiped', 'Rows are present but not one carries a hash — every hash was blanked, or an unchained database was substituted.');
  }

  // ── Boundary checks against the anchor ────────────────────────────────────
  // A caller that names no chain is asking for link verification only — a useful
  // primitive, but it makes no claim about how many rows there should be, and it
  // says so rather than passing itself off as a full check.
  if (!opts.chain) {
    return hashedRows > 0
      ? base('ok', `${hashedRows} hashed row(s) link correctly. No anchor was consulted, so nothing is being claimed about missing or truncated rows.`)
      : base('unanchored', 'Nothing chained and no anchor consulted — no claim is being made about this table.');
  }
  if (!anchored) {
    if (hashedRows > 0) {
      return base('anchor_missing', 'This table holds hash-chained rows but no signed anchor accounts for them, so the number of rows and the end of the chain cannot be checked. The anchor file was removed or never written.');
    }
    return base('unanchored', 'Nothing chained and nothing anchored — no claim is being made about this table.');
  }

  // Counted against rows PRESENT, not rows hashed: a database that predates
  // hashing still holds real rows, and they are still rows the anchor counted.
  if (rows.length === 0 && expected > 0) {
    return base('wiped', `The anchor accounts for ${expected} row(s); the table is empty. The record was deleted.`);
  }
  if (rows.length < expected) {
    return base('truncated', `The anchor accounts for ${expected} row(s); ${rows.length} remain. ${expected - rows.length} row(s) were removed without going through this server.`);
  }

  // Tail check. Rows appended since the last anchor flush are expected and fine
  // (they are simply not yet sealed), so we check that the row the anchor PINNED
  // is still present and still carries the hash it was pinned with. Note this is
  // checked at the PINNED POSITION, not at the end of the table: a chain that has
  // grown past the pin must still answer for the row the pin covers.
  if (anchor!.lastRowHash) {
    if (tailId < anchor!.lastId) {
      return base('truncated', `The anchor pins row ${anchor!.lastId} as the newest; the table ends at ${tailId}. The end of the record was cut off.`);
    }
    const pinned = rows.find(r => r.id === anchor!.lastId);
    if (!pinned) {
      return base('truncated', `The anchor pins row ${anchor!.lastId}, which is no longer in the table.`);
    }
    if (pinned.rowHash !== anchor!.lastRowHash) {
      return base('tail_mismatch', `Row ${anchor!.lastId} is present but carries a different hash than the anchor recorded.`);
    }
  } else if (hashedRows > 0) {
    // The anchor counts rows for this chain but holds no hash to check any of
    // them against. That is not a clean bill of health — it is a verifier with
    // nothing to compare to — so it gets its own verdict rather than falling
    // through to 'ok'.
    return base('tail_unpinned', `The anchor accounts for ${expected} row(s) but pins no tail hash, so the end of the chain cannot be checked at all.`);
  }

  if (pinFrozen) {
    return base('tail_mismatch', `The anchor stopped advancing at row ${anchor!.pinFrozenId ?? anchor!.lastId} (${anchor!.pinFrozenAt}) because the state it had pinned no longer verified. Nothing written since is covered by a signed boundary.`);
  }

  if (!attested) {
    return base('anchor_unsigned', 'The chain is internally consistent, but the anchor is unsigned or its signature does not verify — its boundaries cannot be trusted.');
  }

  const unsealed = rows.length - expected;
  return base('ok', unsealed > 0
    ? `Chain intact; ${hashedRows} hashed row(s), of which ${unsealed} are newer than the last signed checkpoint. Detection only — this is not proof that every event was recorded.`
    : `Chain intact; ${hashedRows} hashed row(s) match the signed anchor. Detection only — this is not proof that every event was recorded.`,
  { ...(tail ? {} : {}) });
}

/** The status a table-level verifier returns when it could not even read the
 *  table. Reported as an error rather than silently as "ok" — a verifier that
 *  cannot read is not a verifier that found nothing wrong. */
export function chainReadError(detail: string): ChainStatus {
  return {
    ok: false,
    status: 'row_mismatch',
    detail,
    rows: 0,
    hashedRows: 0,
    legacyHmacRows: 0,
    attested: false,
    signed: isAuditSigned(),
  };
}

/** Standing limits on what any verification result can mean. Surfaced by the API
 *  so nobody has to read this file to learn what they are not being told. */
export const AUDIT_LIMITS: readonly string[] = [
  'Detection, never prevention: a verified chain proves records were not altered after they were written; it cannot stop anyone from altering them.',
  'Completeness cannot be proven. An event that was never recorded leaves no cryptographic residue, so no verifier can distinguish a quiet period from a silenced writer.',
  'A key held on this machine does not bind this machine\'s owner. Whoever controls the host controls the signing key and can produce a history that verifies.',
  'Third-party verification covers only rows hashed with SHA-256. Rows still carrying the pre-cutover HMAC (reported as legacyHmacRows) need the local secret to check.',
  'Changes made through this server\'s own database handle are recorded as legitimate. The boundary check catches modifications made outside it — offline edits, another sqlite3 session, a restored copy.',
  'Rows newer than the last sealed anchor are UNSEALED for up to five seconds. The pin cannot move over a rewritten history, but rows written since the last sweep are not yet covered by any signature, so a rewrite confined to that window leaves no residue. Sealing every append instead would cost an fsync per span.',
  'The two capped logs (operator audit, enforcement feed) forgive deletion up to their retention cap by design — the expected count is min(everWritten, cap), so a wholesale replacement of a capped log with a fabricated one of the same length is not distinguishable from ordinary pruning. The spans ledger does not have this property: it tombstones every deletion.',
];
