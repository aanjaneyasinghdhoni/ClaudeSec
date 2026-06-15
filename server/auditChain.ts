// server/auditChain.ts
//
// Tamper-evident hash chaining for the append-only logs (operator audit log and
// the persisted enforce/block feed). Each row carries the hash of the previous
// row, so any later edit to an earlier row's content breaks every hash from that
// point on — a verifier can recompute the chain top-to-bottom and pinpoint the
// first id that no longer matches.
//
// DESIGN:
//   • rowHash = sha256( canonical(fields...) + prevHash ), where prevHash is the
//     immediately-preceding row's rowHash ('' for the very first hashed row).
//   • The canonical form is a deterministic JSON array with a FIXED field order.
//     The JSON-array framing (brackets, commas, quoting) is what keeps two
//     different field splits from colliding. Numbers and strings are serialized
//     as-is; only the order and framing matter.
//   • Optional HMAC: if a key exists (or can be created) at ~/.claudesec/audit-key
//     (0600), rowHash is an HMAC-SHA256 keyed by that secret instead of a plain
//     SHA-256. This makes the chain unforgeable without the local key, not merely
//     tamper-evident. It is OPTIONAL and FAIL-OPEN — if the key can't be read or
//     written, we fall back to a plain SHA-256 chain, which still detects tamper.
//
// LEGACY ROWS: databases that predate this feature have empty ('') prevHash and
// rowHash on their existing rows. Those rows are NOT part of the chain — the
// chain effectively starts at the first row that has a non-empty rowHash. The
// verifier skips the empty-hash prefix cleanly and only validates hashed rows.

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

// ── Optional HMAC key ───────────────────────────────────────────────────────
// Lazily resolved once. `null` means "no key" → plain SHA-256 chain. The key is
// a 32-byte random secret stored 0600 next to the DB's home dir. Generating or
// reading it must never throw into the audit path, so every access is guarded.
let hmacKey: Buffer | null | undefined; // undefined = not yet resolved

function resolveHmacKey(): Buffer | null {
  if (hmacKey !== undefined) return hmacKey;
  const keyPath = path.join(os.homedir(), '.claudesec', 'audit-key');
  try {
    if (fs.existsSync(keyPath)) {
      const buf = fs.readFileSync(keyPath);
      hmacKey = buf.length > 0 ? buf : null;
      return hmacKey;
    }
    // First run: mint a key and persist it owner-only. If the dir or write
    // fails, fall back to a plain hash chain (still tamper-evident).
    const key = crypto.randomBytes(32);
    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
    try { fs.chmodSync(keyPath, 0o600); } catch { /* best-effort tighten */ }
    hmacKey = key;
    return hmacKey;
  } catch {
    // Fail-open: no key available → plain SHA-256 chain.
    hmacKey = null;
    return hmacKey;
  }
}

/** True when this install signs the chain with a local HMAC key. */
export function isAuditSigned(): boolean {
  return resolveHmacKey() !== null;
}

/**
 * Deterministic canonical serialization of a row's fields. A JSON array preserves
 * order and JSON.stringify escapes every value unambiguously, so distinct field
 * sets can never serialize to the same string. The caller passes fields in a
 * FIXED order (see the audit/enforce insert sites) — that order is the contract.
 */
export function canonicalString(fields: Array<string | number | boolean | null | undefined>): string {
  // Map undefined → null so the framing is stable whether or not an optional
  // field (e.g. the auto-increment id, unknown before insert) is supplied.
  return JSON.stringify(fields.map(f => (f === undefined ? null : f)));
}

/**
 * Compute a row's hash from its canonical field string and the previous row's
 * hash. HMAC-SHA256 when a local key exists, else plain SHA-256. Hex digest.
 * Fail-open: any hashing error returns '' (an empty hash links nothing and is
 * treated as a legacy/unhashed row by the verifier) rather than throwing into
 * the insert path.
 */
export function computeRowHash(canonical: string, prevHash: string): string {
  try {
    const input = canonical + prevHash;
    const key = resolveHmacKey();
    if (key) return crypto.createHmac('sha256', key).update(input).digest('hex');
    return crypto.createHash('sha256').update(input).digest('hex');
  } catch {
    return '';
  }
}

/** Result of verifying a chain. `brokenAtId` is the first row whose stored hash
 *  no longer matches a recomputation; absent when the chain is intact. */
export interface ChainStatus {
  ok: boolean;
  rows: number;        // total rows scanned
  hashedRows: number;  // rows that participate in the chain (non-empty rowHash)
  brokenAtId?: number;
  signed: boolean;     // whether an HMAC key is in use
}

/** A row as stored, with the chain columns. Only the fields we hash are needed. */
export interface ChainRow {
  id: number;
  prevHash: string;
  rowHash: string;
  /** Canonical string of this row's content fields, in the fixed order. */
  canonical: string;
}

/**
 * Recompute the chain top-to-bottom (ascending id) and return its status.
 *
 * Legacy handling: rows with an empty stored rowHash predate hashing and are
 * skipped — they are not part of the chain. The chain "starts" at the first row
 * with a non-empty rowHash; its prevHash is whatever was recorded at insert
 * ('' for the first-ever hashed row), and we carry forward each verified rowHash
 * as the expected prevHash of the next hashed row.
 */
export function verifyChain(rows: ChainRow[]): ChainStatus {
  const signed = isAuditSigned();
  let hashedRows = 0;
  let prev = ''; // expected prevHash of the next hashed row; '' before the chain starts

  for (const row of rows) {
    // Skip the legacy (unhashed) prefix without disturbing the chain.
    if (!row.rowHash) continue;
    hashedRows++;

    // The recorded prevHash must match what we carried forward. For the first
    // hashed row, `prev` is '' which matches its recorded '' prevHash.
    const expected = computeRowHash(row.canonical, prev);
    if (expected !== row.rowHash) {
      return { ok: false, rows: rows.length, hashedRows, brokenAtId: row.id, signed };
    }
    prev = row.rowHash;
  }

  return { ok: true, rows: rows.length, hashedRows, signed };
}
