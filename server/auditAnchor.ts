// server/auditAnchor.ts
//
// External anchoring for the chain head — the piece that server/auditChain.ts
// cannot provide by itself.
//
// WHY THIS FILE EXISTS
//
//   auditChain.ts signs the tail anchor with an Ed25519 key that lives on THIS
//   machine, under CLAUDESEC_HOME. That defeats a remote or different-UID
//   attacker, and lets a third party verify with the public key alone — real
//   gains. But the private key is on the same host as the record it protects.
//   Whoever controls this machine controls the key, and can therefore wipe the
//   database, mint a fresh key, and re-sign a fabricated history that verifies
//   perfectly against itself. A signature proves who signed, not that the
//   signed content is true, and it cannot bind the machine's own owner.
//
//   The only fix is a witness that does not live here: something outside this
//   machine sees the chain head at a point in time and will say so later, even
//   if the machine is wiped afterward. That is what a periodic CHECKPOINT does:
//   it takes a snapshot of where the chain currently stands and gets it
//   countersigned by an external authority, so a later verifier has something
//   to compare against that the operator could not have retroactively produced.
//
// PRIVACY IS NOT TRADED AWAY FOR THIS. Both external witnesses this file
// supports — an RFC 3161 Time-Stamp Authority and OpenTimestamps — are
// specified to see ONLY A HASH. We send 32 bytes of SHA-256 digest; nothing
// about spans, commands, file contents, or repo names ever leaves the machine
// through this path. That property is load-bearing for a local-first tool: it
// is what makes "opt in to an external witness" compatible with "nothing
// leaves your machine" everywhere else. State this to anyone who asks, and
// keep it true — if a future change ever sends more than a hash to either kind
// of endpoint, that is a regression in the product's core promise, not a
// feature.
//
// WHAT A CHECKPOINT DOES NOT DO — read this before trusting anything below.
//
//   • It does not make completeness provable. A row never written still leaves
//     no residue anywhere, on this machine or off it. Anchoring the tail proves
//     the tail was not moved after a certain instant; it says nothing about
//     what should have been appended and was not.
//   • It is detection, never prevention (RFC 6962's framing, and Schneier &
//     Kelsey 1998: "no cryptographic method can be used to actually prevent
//     the deletion of log entries … the only thing cryptographic protocols can
//     do is guarantee detection"). A checkpoint makes a REWRITE detectable
//     after the fact; it does not stop the operator from rewriting.
//   • A signature proves who signed, not that the content is true. The TSA
//     proves "this exact hash existed at this exact time, per the TSA's
//     clock." It does not audit what the hash represents.
//   • THE TRUNCATION WINDOW IS THE EXPOSURE. An anchor freezes history only up
//     to the last checkpoint that was actually countersigned. Everything
//     appended between that checkpoint and now sits in a window where a local
//     rewrite would go undetected by any external party until the NEXT
//     checkpoint lands. Shrinking the checkpoint interval shrinks the window;
//     it cannot close it to zero without checkpointing every single write,
//     which no free public TSA would tolerate. server/routes/auditVerify.ts
//     reports this number explicitly — see computeTruncationWindow below —
//     rather than letting "anchored" imply "current."
//
// DESIGN
//
//   1. CHECKPOINT. A small JSON object over exactly {version, timestamp, mode,
//      tree_size, root_hash, policy_hash} (buildCheckpoint). tree_size/root_hash
//      describe the spans chain specifically — the actual record of agent
//      activity, not the smaller operator/enforcement logs — using the same
//      vocabulary Certificate Transparency (RFC 6962) uses for a tree head,
//      even though our "tree" is a hash chain rather than a Merkle tree.
//      policy_hash binds the checkpoint to the full local evidence snapshot at
//      that instant (every guarded chain's position, plus the signing key's
//      identity) without bloating the checkpoint schema — see computePolicyHash.
//
//   2. LOCAL SIGNATURE, ALWAYS. Every checkpoint is immediately wrapped in a
//      COSE_Sign1 envelope (RFC 9052) and signed with the SAME Ed25519 key that
//      signs the tail anchor (auditChain.signWithAuditKey) — one key identity
//      for the whole install. This step needs no network and cannot fail
//      offline; it is what makes "queue and retry" meaningful at all, because
//      the checkpoint and its local proof of origin exist before any TSA or
//      calendar has been asked to look at it.
//
//   3. EXTERNAL COUNTERSIGN, BEST-EFFORT. The checkpoint's hash — and ONLY the
//      hash — is sent to a configured RFC 3161 TSA or OpenTimestamps calendar.
//      Success attaches a durable, independently-checkable receipt. Failure
//      (offline, TSA down, timeout) leaves the checkpoint queued as `pending`
//      forever — never dropped — and retried on the next sweep. Nothing about
//      this step can block ingest: it runs off a timer, and every network call
//      is wrapped so an exception here cannot propagate into the request path
//      that triggered it (there isn't one — checkpoints are taken on a clock,
//      not per-request).
//
//   4. DURABLE QUEUE. Every checkpoint — receipted or not — is persisted to
//      CLAUDESEC_HOME/hooks/audit-anchor-checkpoints.json (0600, atomic write,
//      same tmp+fsync+rename pattern as the tail anchor) the moment it is
//      created, before any network call is attempted. A checkpoint that is
//      created and then loses power, network, or the whole process is still on
//      disk and still gets retried on the next start. Only RECEIPTED
//      checkpoints are ever pruned once the queue grows past a cap — an
//      unresolved (`pending`/`error`) checkpoint is never discarded, because
//      discarding it would be losing the thing this file exists to keep.
//
// SCOPE OF WHAT VERIFICATION ACTUALLY CHECKS
//
//   RFC 3161 (method: 'tsa'): the response is a CMS SignedData wrapping a
//   TSTInfo. We parse enough DER to pull out the TSTInfo's messageImprint
//   (hash algorithm + hashed value) and genTime, and confirm the imprint
//   equals the checkpoint hash we submitted (verifyTsaToken) — that binding is
//   the whole point, and it is real: a token whose imprint does not match
//   provably does not cover this checkpoint. What we do NOT do is validate the
//   TSA's own X.509 certificate chain against a trust root — that needs a CA
//   bundle and revocation checking, a materially larger scope than a hash
//   comparison. An operator who wants that layer too can run
//   `openssl ts -verify` against the stored token; we keep the raw DER
//   specifically so that tool can consume it unmodified.
//
//   OpenTimestamps (method: 'ots'): a calendar's `/digest` response is an
//   opaque, unstamped proof fragment — by protocol it carries no plaintext
//   copy of the digest it was computed from, so there is no cryptographic
//   binding we can check independently of our own bookkeeping. What we DO is
//   keep our own record of which checkpoint hash produced which receipt
//   (referential integrity, not cryptographic proof), and we say so — see the
//   status naming below. A calendar receipt is also not yet a Bitcoin-confirmed
//   proof; upgrading it to one requires the official OTS client walking the
//   Merkle path against a Bitcoin block header, which this file does not
//   implement. We export the raw receipt bytes so the official `ots` CLI
//   (`pip install opentimestamps-client`) can do that upgrade and full
//   verification independently.
//
// Both paths therefore land at the SAME honest floor: "receipted" means an
// external party's server responded to a request naming this hash at
// (approximately) this time. For TSA that response is itself a signed,
// independently re-checkable cryptographic statement. For OTS it is a
// calendar's acknowledgement, upgradeable later into one. Neither is
// "impossible to have faked before submission" — the operator could always
// have queued a checkpoint describing a fabricated history and gotten it
// honestly countersigned. What the countersignature defeats is RETROACTIVE
// rewriting: once countersigned, the operator cannot go back and make the TSA
// (or the Bitcoin blockchain, once an OTS receipt is upgraded) believe it saw
// a different hash at that time.

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  hooksDir, getChainAnchor, auditKeyId, signWithAuditKey,
} from './auditChain.js';
import { assertSafeFetchUrl, isLoopbackUrlHost } from './ssrf.js';

// ── Config — OFF by default, opt-in via env ─────────────────────────────────
//
// No env var set → getAnchorConfig() returns null → every exported function
// that touches the network or the queue file no-ops immediately. This mirrors
// server/llmJudge.ts's contract: the absence of configuration IS the
// no-egress guarantee, checked before any fetch is constructed.

export type AnchorMethod = 'tsa' | 'ots';

export interface AnchorConfig {
  method: AnchorMethod;
  tsaUrl: string;
  otsCalendars: string[];
  intervalMs: number;
  timeoutMs: number;
}

// timestamp.digicert.com is a long-running, widely-used, free, no-auth RFC
// 3161 TSA (also the default many `openssl ts` tutorials point at). Other
// reliable free public TSAs worth knowing about, in case this one is ever
// unreachable from a given network: http://timestamp.sectigo.com,
// http://tsa.baltimore.com/tsa, https://freetsa.org/tsr (freetsa.org requires
// no auth but is a smaller volunteer-run service — treat it as a fallback,
// not a primary). All are configurable via CLAUDESEC_ANCHOR_TSA_URL; nothing
// here is hardcoded as the ONLY option.
const DEFAULT_TSA_URL = 'http://timestamp.digicert.com';

// The three calendar servers the reference OpenTimestamps client itself uses
// by default, chosen because they are independently operated (not the same
// party), which is the point of asking more than one.
const DEFAULT_OTS_CALENDARS = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
];

const DEFAULT_INTERVAL_MS = 15 * 60_000; // 15 min — gentle on free public infra
const DEFAULT_TIMEOUT_MS = 10_000;
const MIN_INTERVAL_MS = 60_000;          // refuse to hammer a free TSA/calendar

/**
 * Read anchor config from env at call time (so tests can flip it per-call, the
 * same convention llmJudge.ts uses). Returns null — OFF — unless
 * CLAUDESEC_ANCHOR_METHOD is explicitly 'tsa' or 'ots'.
 */
export function getAnchorConfig(): AnchorConfig | null {
  const method = (process.env.CLAUDESEC_ANCHOR_METHOD ?? '').trim().toLowerCase();
  if (method !== 'tsa' && method !== 'ots') return null; // ← OFF BY DEFAULT
  const tsaUrl = (process.env.CLAUDESEC_ANCHOR_TSA_URL ?? '').trim() || DEFAULT_TSA_URL;
  const otsRaw = (process.env.CLAUDESEC_ANCHOR_OTS_URL ?? '').trim();
  const otsCalendars = otsRaw
    ? otsRaw.split(',').map(s => s.trim()).filter(Boolean)
    : DEFAULT_OTS_CALENDARS;
  const rawInterval = Number(process.env.CLAUDESEC_ANCHOR_INTERVAL_MS);
  const intervalMs = Number.isFinite(rawInterval) && rawInterval >= MIN_INTERVAL_MS
    ? rawInterval : DEFAULT_INTERVAL_MS;
  const rawTimeout = Number(process.env.CLAUDESEC_ANCHOR_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(rawTimeout) && rawTimeout > 0
    ? Math.min(rawTimeout, 60_000) : DEFAULT_TIMEOUT_MS;
  return { method: method as AnchorMethod, tsaUrl, otsCalendars, intervalMs, timeoutMs };
}

/** True iff external anchoring is configured (does NOT make a network call). */
export function isAnchorEnabled(): boolean {
  return getAnchorConfig() !== null;
}

// ── Checkpoint construction ──────────────────────────────────────────────────

export interface Checkpoint {
  version: 1;
  timestamp: string;
  mode: string;
  tree_size: number;
  root_hash: string;
  policy_hash: string;
}

// The chains registered with auditChain.ts (server/db.ts registers all three).
// Hardcoded here rather than discovered at runtime: this module must be able
// to describe "what would be checkpointed" even before db.ts has registered
// anything (e.g. under test), and the set of guarded chains is a design
// constant, not something that varies per install.
const KNOWN_CHAINS = ['operator_audit_log', 'enforce_log', 'spans'] as const;

/**
 * Hash of every guarded chain's current position plus the signing key's
 * identity. Not a hash of "policy" in the rules-file sense — the name matches
 * the field the checkpoint schema calls for, and what it actually captures is
 * broader and more useful: the complete signed-anchor state (audit log,
 * enforce log, spans) at the instant of checkpointing, so a verifier who only
 * has the checkpoint can still tell, later, whether ANY guarded chain's
 * position at that time matches what the anchor file claims now.
 */
function computePolicyHash(): string {
  const snapshot: Record<string, { appended: number; lastRowHash: string }> = {};
  for (const name of KNOWN_CHAINS) {
    const e = getChainAnchor(name);
    snapshot[name] = { appended: e?.appended ?? 0, lastRowHash: e?.lastRowHash ?? '' };
  }
  const payload = JSON.stringify({ keyId: auditKeyId(), chains: snapshot });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Build a checkpoint from the current state of the spans chain — the record of
 * what the agent actually did, not the smaller operator/enforcement logs.
 * `mode` is read directly from CLAUDESEC_MODE (the operator's own override);
 * it does not attempt to reconstruct the fully-resolved effective mode that
 * server/enforceStatus.ts computes (per-rule overrides, etc.) — that would
 * need wiring this module does not have. Documented as a known simplification
 * rather than silently guessed at.
 */
export function buildCheckpoint(): Checkpoint {
  const spans = getChainAnchor('spans');
  return {
    version: 1,
    timestamp: new Date().toISOString(),
    mode: (process.env.CLAUDESEC_MODE ?? 'monitor').trim() || 'monitor',
    tree_size: spans?.appended ?? 0,
    root_hash: spans?.lastRowHash ?? '',
    policy_hash: computePolicyHash(),
  };
}

/** Deterministic, fixed-key-order serialization — the bytes that get hashed
 *  and the bytes that go inside the COSE_Sign1 payload. */
function canonicalCheckpoint(cp: Checkpoint): string {
  return JSON.stringify({
    version: cp.version, timestamp: cp.timestamp, mode: cp.mode,
    tree_size: cp.tree_size, root_hash: cp.root_hash, policy_hash: cp.policy_hash,
  });
}

export function checkpointHash(cp: Checkpoint): string {
  return crypto.createHash('sha256').update(canonicalCheckpoint(cp)).digest('hex');
}

// ── COSE_Sign1 (RFC 9052 §4.2) ───────────────────────────────────────────────
//
// We hand-roll the minimal CBOR needed for exactly this structure rather than
// add a dependency. Justification: no CBOR/COSE library is already a
// dependency of this project; the structure we need is small and completely
// fixed (a 4-element array, a 1-entry protected map, a 1-entry unprotected
// map, byte strings, two integers) — general-purpose CBOR codecs spend most of
// their code on shapes we will never produce (indefinite-length items, floats,
// tags we don't use, streaming). Pulling in a full dependency for six fixed
// TLV shapes trades a few hundred lines of auditable, dependency-free code for
// an unaudited addition to the supply chain of a SECURITY tool — the wrong
// trade for this codebase (see CISO review criteria). If COSE needs ever grow
// beyond Sign1 (e.g. COSE_Sign with multiple signers, encryption), revisit.
//
// PROFILE IMPLEMENTED: COSE_Sign1, tagged (CBOR tag 18), algorithm EdDSA
// (COSE alg -8, Ed25519 per RFC 8152 §8.2 / the IANA COSE Algorithms
// registry), protected header {1: -8}, unprotected header {4: <keyId bytes>},
// payload = the checkpoint's canonical UTF-8 JSON (attached, not detached —
// the whole point is a self-contained artifact a third party can check without
// a side channel back to this server). No countersignature or X.509 chain is
// embedded in the COSE structure itself; the RFC 3161 token or OTS receipt (if
// any) is stored alongside it in the same queue entry, not inside the CBOR.

const COSE_ALG_EDDSA = -8;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_KID = 4;
const COSE_TAG_SIGN1 = 18;

function cborHeader(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n >>> 0, 1);
  return b;
}
function cborBytes(buf: Buffer): Buffer { return Buffer.concat([cborHeader(2, buf.length), buf]); }
function cborText(s: string): Buffer { const b = Buffer.from(s, 'utf8'); return Buffer.concat([cborHeader(3, b.length), b]); }
function cborInt(n: number): Buffer { return n >= 0 ? cborHeader(0, n) : cborHeader(1, -1 - n); }
function cborArrayHeader(count: number): Buffer { return cborHeader(4, count); }
function cborMapHeader(count: number): Buffer { return cborHeader(5, count); }
function cborTag(n: number): Buffer { return cborHeader(6, n); }

/** { 1: -8 } — protected header, wrapped as a bstr per COSE_Sign1's shape. */
function buildProtectedHeaderBytes(): Buffer {
  return Buffer.concat([cborMapHeader(1), cborInt(COSE_HEADER_ALG), cborInt(COSE_ALG_EDDSA)]);
}
/** { 4: kid } — unprotected header, embedded directly (NOT bstr-wrapped). */
function buildUnprotectedHeaderBytes(keyId: string): Buffer {
  return Buffer.concat([cborMapHeader(1), cborInt(COSE_HEADER_KID), cborBytes(Buffer.from(keyId, 'utf8'))]);
}
/** Sig_structure per RFC 9052 §4.4 — what actually gets signed. */
function buildSigStructure(protectedBytes: Buffer, payload: Buffer): Buffer {
  return Buffer.concat([
    cborArrayHeader(4),
    cborText('Signature1'),
    cborBytes(protectedBytes),
    cborBytes(Buffer.alloc(0)), // external_aad — none
    cborBytes(payload),
  ]);
}

/** Assemble the final tagged COSE_Sign1 byte string from its four fields. */
export function encodeCoseSign1(protectedBytes: Buffer, unprotectedBytes: Buffer, payload: Buffer, signature: Buffer): Buffer {
  return Buffer.concat([
    cborTag(COSE_TAG_SIGN1),
    cborArrayHeader(4),
    cborBytes(protectedBytes),
    unprotectedBytes,
    cborBytes(payload),
    cborBytes(signature),
  ]);
}

/**
 * Sign a checkpoint into a COSE_Sign1 envelope with the install's Ed25519 audit
 * key. Returns null when no signing key is available (fail-open — the caller
 * skips the checkpoint entirely rather than shipping something unsigned).
 */
export function buildCoseCheckpoint(cp: Checkpoint, keyId: string): Buffer | null {
  const payload = Buffer.from(canonicalCheckpoint(cp), 'utf8');
  const protectedBytes = buildProtectedHeaderBytes();
  const unprotectedBytes = buildUnprotectedHeaderBytes(keyId);
  const signature = signWithAuditKey(buildSigStructure(protectedBytes, payload));
  if (!signature) return null;
  return encodeCoseSign1(protectedBytes, unprotectedBytes, payload, signature);
}

// ── Minimal DER (ASN.1) — just enough for RFC 3161 ──────────────────────────
//
// Hand-rolled for the same reason as the CBOR above: the shapes needed are
// small and fixed (TimeStampReq on the way out, TimeStampResp → ContentInfo →
// SignedData → encapContentInfo → TSTInfo on the way in), and a general X.509
// toolkit is a much larger surface than six SEQUENCE/OCTET STRING/OID/INTEGER
// shapes. This is NOT a general ASN.1 library — it does not handle indefinite
// lengths, BER quirks, or tag numbers above 30, all of which are absent from
// well-formed RFC 3161 messages from real TSAs.

const SHA256_OID = '2.16.840.1.101.3.4.2.1';

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function derTLV(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}
function derInteger(n: number): Buffer {
  if (n === 0) return derTLV(0x02, Buffer.from([0x00]));
  const bytes: number[] = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes[0] & 0x80) bytes.unshift(0x00); // keep it non-negative
  return derTLV(0x02, Buffer.from(bytes));
}
/** INTEGER from an arbitrary byte string (used for the nonce). */
function derIntegerFromBytes(buf: Buffer): Buffer {
  const b = (buf[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
  return derTLV(0x02, b);
}
function derBoolean(b: boolean): Buffer { return derTLV(0x01, Buffer.from([b ? 0xff : 0x00])); }
function derNull(): Buffer { return derTLV(0x05, Buffer.alloc(0)); }
function derSequence(children: Buffer[]): Buffer { return derTLV(0x30, Buffer.concat(children)); }
function derOctetString(buf: Buffer): Buffer { return derTLV(0x04, buf); }

function encodeOidSubIdentifier(v: number): number[] {
  const out: number[] = [v & 0x7f];
  v = Math.floor(v / 128);
  while (v > 0) { out.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
  return out;
}
function derOid(oid: string): Buffer {
  const parts = oid.split('.').map(Number);
  const bytes: number[] = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) bytes.push(...encodeOidSubIdentifier(p));
  return derTLV(0x06, Buffer.from(bytes));
}
function decodeOid(bytes: Buffer): string {
  if (bytes.length === 0) return '';
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  for (let i = 1; i < bytes.length; i++) {
    val = (val * 128) + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join('.');
}

/** RFC 3161 TimeStampReq, requesting the TSA's certificate be embedded (so the
 *  token is self-contained enough for `openssl ts -verify` without a fetch). */
function buildTimeStampReq(hash: Buffer, nonce: Buffer): Buffer {
  const algId = derSequence([derOid(SHA256_OID), derNull()]);
  const messageImprint = derSequence([algId, derOctetString(hash)]);
  return derSequence([
    derInteger(1),                    // version
    messageImprint,
    derIntegerFromBytes(nonce),       // nonce
    derBoolean(true),                 // certReq
  ]);
}

interface DerNode {
  tag: number;
  constructed: boolean;
  content: Buffer;
  raw: Buffer;         // the full TLV, tag+length+content — what we persist as "the token"
  children: DerNode[];
}

/** Parse a run of TLVs. `buf` is always the SAME top-level buffer across the
 *  whole recursive walk (never re-sliced into a fresh Buffer) so that `raw`
 *  always points at real bytes of the original message. Throws on any
 *  malformed input — every caller wraps this in try/catch and fails open. */
function parseDerNodes(buf: Buffer, start: number, end: number): DerNode[] {
  const nodes: DerNode[] = [];
  let i = start;
  while (i < end) {
    const tlvStart = i;
    const tagByte = buf[i];
    const constructed = (tagByte & 0x20) !== 0;
    i += 1;
    if (i >= end) throw new Error('DER: truncated tag');
    const lenByte = buf[i];
    i += 1;
    let length: number;
    if (lenByte & 0x80) {
      const numBytes = lenByte & 0x7f;
      // Reject indefinite length (0 here) and anything that could overflow
      // JS's 32-bit bitwise ops (>4 length-of-length bytes is already far
      // larger than any real TSA response) rather than mis-parse it.
      if (numBytes === 0 || numBytes > 4) throw new Error('DER: unsupported length form');
      if (i + numBytes > end) throw new Error('DER: truncated length');
      length = 0;
      for (let k = 0; k < numBytes; k++) length = (length << 8) | buf[i + k];
      i += numBytes;
    } else {
      length = lenByte;
    }
    if (length < 0 || i + length > end) throw new Error('DER: truncated content');
    const contentStart = i;
    const contentEnd = i + length;
    const node: DerNode = {
      tag: tagByte,
      constructed,
      content: buf.subarray(contentStart, contentEnd),
      raw: buf.subarray(tlvStart, contentEnd),
      children: [],
    };
    if (constructed) {
      try { node.children = parseDerNodes(buf, contentStart, contentEnd); } catch { node.children = []; }
    }
    nodes.push(node);
    i = contentEnd;
  }
  return nodes;
}

/** Pull {status, tokenRaw} out of a TimeStampResp. tokenRaw is the raw DER of
 *  the ContentInfo (TimeStampToken) — exactly what a standalone `.tsr` token
 *  file / `openssl ts -reply -token_out` would contain. */
function extractPkiStatus(resp: Buffer): { status: number; tokenRaw: Buffer | null } | null {
  try {
    const [top] = parseDerNodes(resp, 0, resp.length);
    if (!top || top.tag !== 0x30) return null;
    const pkiStatusInfo = top.children[0];
    const statusInt = pkiStatusInfo?.children?.[0];
    if (!statusInt || statusInt.tag !== 0x02) return null;
    let status = 0;
    for (const b of statusInt.content) status = (status << 8) | b;
    const contentInfoNode = top.children[1] ?? null;
    return { status, tokenRaw: contentInfoNode ? Buffer.from(contentInfoNode.raw) : null };
  } catch {
    return null;
  }
}

/**
 * Walk ContentInfo → SignedData → encapContentInfo → TSTInfo using the FIXED
 * field order RFC 3161 / CMS specify (each field's SEQUENCE position is part
 * of the wire format, not something we're guessing at). Any surprise at any
 * step returns null — fail open, the token is stored but reported as
 * structurally unverifiable rather than crashing the caller.
 */
function extractTstInfoFields(contentInfoRaw: Buffer): { hashOid: string; hashedMessage: Buffer; genTime: string } | null {
  try {
    const [contentInfo] = parseDerNodes(contentInfoRaw, 0, contentInfoRaw.length);
    if (!contentInfo || contentInfo.tag !== 0x30) return null;
    const explicitContent = contentInfo.children[1];              // [0] EXPLICIT content
    const signedData = explicitContent?.children?.[0];
    if (!signedData || signedData.tag !== 0x30) return null;
    const encapContentInfo = signedData.children[2];               // fixed position: after version, digestAlgorithms
    if (!encapContentInfo || encapContentInfo.tag !== 0x30) return null;
    const eContentTag = encapContentInfo.children[1];              // [0] EXPLICIT eContent
    const eContentOctet = eContentTag?.children?.[0];
    if (!eContentOctet || eContentOctet.tag !== 0x04) return null;
    const [tstInfo] = parseDerNodes(eContentOctet.content, 0, eContentOctet.content.length);
    if (!tstInfo || tstInfo.tag !== 0x30) return null;
    // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
    const messageImprint = tstInfo.children[2];
    const genTimeNode = tstInfo.children[4];
    if (!messageImprint || messageImprint.tag !== 0x30) return null;
    const algIdNode = messageImprint.children[0];
    const hashedMessageNode = messageImprint.children[1];
    if (!hashedMessageNode || hashedMessageNode.tag !== 0x04) return null;
    const oidNode = algIdNode?.children?.[0];
    const hashOid = oidNode ? decodeOid(oidNode.content) : '';
    const genTime = (genTimeNode && (genTimeNode.tag === 0x18 || genTimeNode.tag === 0x17))
      ? genTimeNode.content.toString('ascii') : '';
    return { hashOid, hashedMessage: Buffer.from(hashedMessageNode.content), genTime };
  } catch {
    return null;
  }
}

export interface TsaTokenVerification {
  ok: boolean;
  detail: string;
  hashAlgorithm?: string;
  genTime?: string;
}

/**
 * Validate an RFC 3161 token against the checkpoint hash it is supposed to
 * cover. This is the concrete claim a third party can check independently:
 * the token's embedded messageImprint hash equals the checkpoint's hash. It
 * does NOT validate the TSA's certificate chain — see the file header.
 */
export function verifyTsaToken(tokenRaw: Buffer, expectedHashHex: string): TsaTokenVerification {
  const fields = extractTstInfoFields(tokenRaw);
  if (!fields) return { ok: false, detail: 'could not parse the timestamp token structure' };
  if (fields.hashOid !== SHA256_OID) {
    return { ok: false, detail: `token uses an unexpected hash algorithm (OID ${fields.hashOid || 'unknown'}), not SHA-256` };
  }
  const gotHex = fields.hashedMessage.toString('hex').toLowerCase();
  if (gotHex !== expectedHashHex.toLowerCase()) {
    return {
      ok: false,
      detail: 'the token\'s message imprint does not match this checkpoint\'s hash — this token does not cover this checkpoint',
      hashAlgorithm: 'sha256', genTime: fields.genTime,
    };
  }
  return { ok: true, detail: 'the token\'s message imprint matches this checkpoint\'s hash', hashAlgorithm: 'sha256', genTime: fields.genTime };
}

// ── Network clients ──────────────────────────────────────────────────────────
//
// Both follow the SAME SSRF discipline as server/llmJudge.ts: a loopback
// endpoint (only realistically used in tests) skips the guard, anything else
// is resolved and classified at call time via assertSafeFetchUrl so a
// configured public TSA/calendar that later starts resolving inward gets
// rejected on the next attempt, not just at config time.

const MAX_RESPONSE_BYTES = 65_536; // generous for a TSA/calendar reply; a cap against a misbehaving endpoint

// Both arms carry the other's key as an explicit `undefined`. The discriminant
// still narrows normally, but reading `.error` off an unnarrowed value is legal
// too — `Buffer` became generic in recent @types/node, and the resulting
// `NetResult<Buffer<ArrayBufferLike>>` did not always narrow through `!r.ok`.
type NetResult<T> =
  | { ok: true;  value: T;          error?: undefined }
  | { ok: false; value?: undefined; error: string };

async function fetchGuarded(url: string, init: RequestInit, timeoutMs: number): Promise<NetResult<Buffer>> {
  try {
    if (!isLoopbackUrlHost(url)) await assertSafeFetchUrl(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length === 0) return { ok: false, error: 'empty response' };
    if (buf.length > MAX_RESPONSE_BYTES) return { ok: false, error: 'response exceeded the size limit' };
    return { ok: true, value: buf };
  } catch (err) {
    const msg = (err as Error)?.name === 'AbortError'
      ? `timed out after ${timeoutMs}ms`
      : ((err as Error)?.message ?? 'request failed');
    return { ok: false, error: msg };
  }
}

async function requestTsaToken(tsaUrl: string, hashHex: string, timeoutMs: number): Promise<NetResult<Buffer>> {
  const hash = Buffer.from(hashHex, 'hex');
  const nonce = crypto.randomBytes(8);
  const reqDer = buildTimeStampReq(hash, nonce);
  const r = await fetchGuarded(tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: new Uint8Array(reqDer),
  }, timeoutMs);
  if (!r.ok) return r;
  const parsed = extractPkiStatus(r.value);
  if (!parsed) return { ok: false, error: 'could not parse the TSA response' };
  // PKIStatus 0 = granted, 1 = grantedWithMods — both carry a usable token.
  if (parsed.status !== 0 && parsed.status !== 1) return { ok: false, error: `TSA declined the request (status ${parsed.status})` };
  if (!parsed.tokenRaw) return { ok: false, error: 'TSA granted the request but returned no token' };
  return { ok: true, value: parsed.tokenRaw };
}

async function requestOtsReceipt(calendarUrl: string, hashHex: string, timeoutMs: number): Promise<NetResult<Buffer>> {
  const digestUrl = `${calendarUrl.replace(/\/+$/, '')}/digest`;
  return fetchGuarded(digestUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/vnd.opentimestamps.v1' },
    body: new Uint8Array(Buffer.from(hashHex, 'hex')),
  }, timeoutMs);
}

// ── Durable checkpoint queue ─────────────────────────────────────────────────

export type CheckpointStatus = 'pending' | 'receipted' | 'error';

export interface CheckpointEntry {
  id: number;
  checkpoint: Checkpoint;
  checkpointHash: string;
  cose: string;                 // base64 COSE_Sign1 envelope — produced locally, always present
  method: AnchorMethod;
  endpoint: string;              // TSA URL, or the calendar that actually answered (ots)
  status: CheckpointStatus;
  attempts: number;
  createdAt: string;
  lastAttemptAt?: string;
  lastError?: string;
  receiptedAt?: string;
  // Present once status === 'receipted'.
  token?: string;                 // base64: TSA ContentInfo DER, or the raw OTS calendar receipt
  tokenHashAlgorithm?: string;    // 'sha256' — tsa only, read back out of the parsed token
  tsGenTime?: string;             // TSA-asserted time — tsa only
}

interface QueueFile {
  v: 1;
  nextId: number;
  entries: CheckpointEntry[];
}

const QUEUE_FILE = 'audit-anchor-checkpoints.json';
// Beyond this many entries we prune the oldest RECEIPTED ones (never
// pending/error — see the file header). At the default 15-minute interval
// this is roughly two months of history before anything is trimmed.
const MAX_QUEUE_ENTRIES = 5_000;

function queuePath(): string {
  return path.join(hooksDir(), QUEUE_FILE);
}

let queueState: QueueFile | undefined;
let queueDirty = false;

function loadQueue(): QueueFile {
  if (queueState !== undefined) return queueState;
  try {
    const parsed = JSON.parse(fs.readFileSync(queuePath(), 'utf8')) as QueueFile;
    queueState = { v: 1, nextId: parsed.nextId ?? 1, entries: Array.isArray(parsed.entries) ? parsed.entries : [] };
  } catch {
    queueState = { v: 1, nextId: 1, entries: [] };
  }
  return queueState;
}

function pruneQueue(state: QueueFile): void {
  if (state.entries.length <= MAX_QUEUE_ENTRIES) return;
  const overflow = state.entries.length - MAX_QUEUE_ENTRIES;
  let removed = 0;
  state.entries = state.entries.filter((e) => {
    if (removed >= overflow) return true;
    if (e.status === 'receipted') { removed++; return false; }
    return true; // never drop pending/error entries — see file header
  });
}

/** Atomic 0600 write — same tmp+fsync+rename pattern as auditChain's anchor
 *  file, for the same reason: a half-written queue must never read as a
 *  wiped one. */
function persistQueue(): void {
  if (!queueDirty || queueState === undefined) return;
  try {
    fs.mkdirSync(hooksDir(), { recursive: true });
    const target = queuePath();
    const tmp = `${target}.${process.pid}.tmp`;
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      fs.writeFileSync(fd, JSON.stringify(queueState));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, target);
    queueDirty = false;
  } catch {
    // Fail-open: an unwritable queue must not break the sweep that produced
    // it. The checkpoint stays in memory for this process's lifetime and the
    // next successful persist catches it up; worst case across a restart is
    // one lost in-memory (never-yet-persisted) checkpoint, not a corrupted file.
  }
}

/**
 * Build, locally sign, and durably queue a new checkpoint. No-ops (returns
 * null, touches nothing) when anchoring is disabled or no audit signing key is
 * available on this install — both fail-open conditions.
 */
export function createAndQueueCheckpoint(): CheckpointEntry | null {
  const cfg = getAnchorConfig();
  if (!cfg) return null;
  const cp = buildCheckpoint();
  const hash = checkpointHash(cp);
  const cose = buildCoseCheckpoint(cp, auditKeyId());
  if (!cose) return null; // no signing key — never queue an unsigned checkpoint
  const state = loadQueue();
  const entry: CheckpointEntry = {
    id: state.nextId++,
    checkpoint: cp,
    checkpointHash: hash,
    cose: cose.toString('base64'),
    method: cfg.method,
    endpoint: cfg.method === 'tsa' ? cfg.tsaUrl : cfg.otsCalendars[0],
    status: 'pending',
    attempts: 0,
    createdAt: cp.timestamp,
  };
  state.entries.push(entry);
  pruneQueue(state);
  queueDirty = true;
  persistQueue();
  return entry;
}

/** One external countersign attempt for a single entry. Mutates `entry` in
 *  place; never throws (the caller doesn't need to catch). */
async function attemptExternalCountersign(entry: CheckpointEntry, cfg: AnchorConfig): Promise<void> {
  entry.attempts += 1;
  entry.lastAttemptAt = new Date().toISOString();
  try {
    if (entry.method === 'tsa') {
      const r = await requestTsaToken(cfg.tsaUrl, entry.checkpointHash, cfg.timeoutMs);
      if (!r.ok) { entry.lastError = r.error; return; }
      const verification = verifyTsaToken(r.value, entry.checkpointHash);
      if (!verification.ok) { entry.lastError = `TSA response ${verification.detail}`; return; }
      entry.token = r.value.toString('base64');
      entry.tokenHashAlgorithm = verification.hashAlgorithm;
      entry.tsGenTime = verification.genTime;
      entry.status = 'receipted';
      entry.receiptedAt = new Date().toISOString();
      entry.lastError = undefined;
      return;
    }
    // OTS: try each configured calendar until one answers.
    let lastErr = 'no calendar configured';
    for (const cal of cfg.otsCalendars) {
      const r = await requestOtsReceipt(cal, entry.checkpointHash, cfg.timeoutMs);
      if (r.ok) {
        entry.token = r.value.toString('base64');
        entry.endpoint = cal;
        // "receipted" here means the calendar acknowledged the digest — NOT
        // that it is Bitcoin-confirmed yet. See the file header.
        entry.status = 'receipted';
        entry.receiptedAt = new Date().toISOString();
        entry.lastError = undefined;
        return;
      }
      lastErr = `${cal}: ${r.error}`;
    }
    entry.lastError = lastErr;
  } catch (err) {
    entry.lastError = (err as Error)?.message ?? 'countersign attempt failed';
  }
}

/**
 * Retry every not-yet-receipted checkpoint. Safe to call repeatedly (e.g. from
 * the sweep timer, or directly from a test): a checkpoint that is already
 * `receipted` is skipped, one that keeps failing simply accumulates attempts
 * and stays `pending`/`error` — it is NEVER removed from the queue by this
 * function. No-ops entirely when anchoring is disabled.
 */
export async function submitPendingCheckpoints(): Promise<void> {
  const cfg = getAnchorConfig();
  if (!cfg) return;
  const state = loadQueue();
  const due = state.entries.filter(e => e.status !== 'receipted');
  for (const entry of due) {
    await attemptExternalCountersign(entry, cfg);
    entry.status = entry.status === 'receipted' ? 'receipted' : 'error'; // 'error' just means "not yet — see lastError", not "gave up"
    queueDirty = true;
  }
  persistQueue();
}

export function listCheckpoints(limit = 20): CheckpointEntry[] {
  const state = loadQueue();
  return state.entries.slice(-limit);
}

// ── Truncation window (Task 3: say exactly what this proves) ────────────────

export interface TruncationWindow {
  windowMs: number | null;
  detail: string;
}

/**
 * The number an auditor actually needs: how far back does the LAST
 * externally-countersigned checkpoint reach, and how much has been appended
 * since without an outside witness. Pure function — no I/O — so it is directly
 * unit-testable with synthetic inputs rather than needing real elapsed time or
 * a live network call.
 */
export function computeTruncationWindow(
  opts: { enabled: boolean; lastReceiptedAt: string | null },
  now: number = Date.now(),
): TruncationWindow {
  if (!opts.enabled) {
    return {
      windowMs: null,
      detail: 'External anchoring is disabled on this install. The chain head is attested only by the local Ed25519 anchor — nothing outside this machine has seen it. There is no bound on the exposure window: an operator holding the signing key could rewrite all local history undetected by any outside party.',
    };
  }
  if (!opts.lastReceiptedAt) {
    return {
      windowMs: null,
      detail: 'External anchoring is enabled but no checkpoint has been externally countersigned yet. Every row written so far sits in the exposure window — there is no off-machine record of the chain head at any point in time.',
    };
  }
  const windowMs = Math.max(0, now - Date.parse(opts.lastReceiptedAt));
  return {
    windowMs,
    detail: `The chain head was last externally countersigned ${Math.round(windowMs / 1000)}s ago. An anchor freezes history only up to the checkpoint it covers — everything appended after that instant, up to now, is the exposure window: it could be silently rewritten by someone holding the local signing key without the external witness ever seeing the difference, until the next checkpoint lands.`,
  };
}

// ── Status summary, for the verify API ───────────────────────────────────────

export const ANCHOR_LIMITS: readonly string[] = [
  'Both RFC 3161 and OpenTimestamps see only a 32-byte SHA-256 hash — never span content, commands, file paths, or repo names.',
  'Detection, never prevention: an external checkpoint proves the chain head existed at a point in time; it cannot stop anyone from rewriting history before or after that instant.',
  'A signature proves who signed, not that the signed content is true — an RFC 3161 TSA attests "this hash existed at this time," not that the record behind the hash is accurate.',
  'Completeness can never be proven: a row that was never written leaves no residue for a checkpoint to freeze, on this machine or off it.',
  'The truncation window (see truncationWindowMs) is the real exposure: anything appended since the last externally-countersigned checkpoint is only as trustworthy as the local signature.',
  'RFC 3161 receipts are structurally checked against the checkpoint hash (verifyTsaToken) but the TSA\'s own certificate chain is NOT validated here — use `openssl ts -verify` for that layer.',
  'OpenTimestamps "receipted" means a calendar server acknowledged the digest, not that it is Bitcoin-confirmed yet — upgrade and fully verify with the official `ots` CLI against the stored receipt.',
];

export interface AnchorStatusSummary {
  enabled: boolean;
  method: AnchorMethod | null;
  endpoint: string | null;
  intervalMs: number | null;
  queueDepth: number;
  pendingCount: number;
  errorCount: number;
  lastCheckpoint: { at: string; hash: string; status: CheckpointStatus } | null;
  lastReceipted: { at: string; method: AnchorMethod; endpoint: string; hash: string; tsGenTime?: string } | null;
  truncationWindowMs: number | null;
  truncationWindowDetail: string;
  limits: readonly string[];
}

export function getAnchorStatus(now: number = Date.now()): AnchorStatusSummary {
  const cfg = getAnchorConfig();
  const state = loadQueue();
  const entries = state.entries;
  const last = entries.length ? entries[entries.length - 1] : null;
  let receipted: CheckpointEntry | null = null;
  for (let i = entries.length - 1; i >= 0; i--) {
    if (entries[i].status === 'receipted') { receipted = entries[i]; break; }
  }
  const window = computeTruncationWindow({ enabled: cfg !== null, lastReceiptedAt: receipted?.receiptedAt ?? null }, now);
  return {
    enabled: cfg !== null,
    method: cfg?.method ?? null,
    endpoint: cfg ? (cfg.method === 'tsa' ? cfg.tsaUrl : cfg.otsCalendars[0]) : null,
    intervalMs: cfg?.intervalMs ?? null,
    queueDepth: entries.length,
    pendingCount: entries.filter(e => e.status !== 'receipted').length,
    errorCount: entries.filter(e => e.status === 'error').length,
    lastCheckpoint: last ? { at: last.checkpoint.timestamp, hash: last.checkpointHash, status: last.status } : null,
    lastReceipted: receipted
      ? { at: receipted.receiptedAt!, method: receipted.method, endpoint: receipted.endpoint, hash: receipted.checkpointHash, tsGenTime: receipted.tsGenTime }
      : null,
    truncationWindowMs: window.windowMs,
    truncationWindowDetail: window.detail,
    limits: ANCHOR_LIMITS,
  };
}

// ── Self-starting sweep ───────────────────────────────────────────────────────
//
// Same shape as auditChain.ts's own anchor sweep: a module-level, unref'd
// timer that starts unconditionally at import time but does REAL work only
// when anchoring is configured. Importing this module — which server/index.ts
// must do simply to register the verify-route additions — therefore never
// costs a network call, a file write, or a blocked startup on an install that
// has not opted in. Every step inside the tick is independently fail-open, and
// the tick itself is wrapped so nothing here can crash the process it audits.

async function anchorSweepTick(): Promise<void> {
  if (!isAnchorEnabled()) return;
  try {
    createAndQueueCheckpoint();
    await submitPendingCheckpoints();
  } catch {
    // A checkpoint sweep must never take the server down with it.
  }
}

let sweepTimer: NodeJS.Timeout | null = null;

/** Exported so a clean shutdown (or a test) can stop the timer explicitly;
 *  harmless to skip since it is unref'd and never keeps the process alive. */
export function stopAnchorSweep(): void {
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
}

function startAnchorSweep(): void {
  if (sweepTimer) return;
  const everyMs = getAnchorConfig()?.intervalMs ?? DEFAULT_INTERVAL_MS;
  sweepTimer = setInterval(() => { void anchorSweepTick(); }, everyMs);
  if (typeof sweepTimer.unref === 'function') sweepTimer.unref();
}
startAnchorSweep();
