// server/auditLog.ts
//
// Operator audit log — records every config-mutating action so an operator can
// answer "who changed what, when". The store is append-only over the API
// (server/routes/auditLog.ts exposes a read endpoint only; there is no delete),
// and growth is bounded by pruning the oldest rows once the table passes a cap.
//
// SECURITY:
//   • `detail` is scrubbed (server/scrub.ts) before insert, so a secret that
//     rode in on a config payload never lands in the log.
//   • `sourceIp` comes from req.socket.remoteAddress only — NEVER the spoofable
//     X-Forwarded-For header, matching the auth gate's choice elsewhere.
//   • Writing the log must never break the action it records, so insert errors
//     are swallowed (best-effort, like the webhook/enforce mirrors).

import type { Request } from 'express';
import { db } from './db.js';
import { scrubText, type ScrubOptions } from './scrub.js';
import {
  canonicalString, chainReadError, computeRowHash, reanchorChain, verifyChain,
  type ChainStatus,
} from './auditChain.js';

// Hard cap on retained rows. The oldest rows are pruned on insert once the
// table grows past this, so a long-lived install can't accumulate an unbounded
// log. 10k rows is plenty to answer recent "who changed what" questions while
// staying small on disk.
const MAX_AUDIT_ROWS = 10_000;

const insertAudit = db.prepare(`
  INSERT INTO operator_audit_log (ts, actor, action, target, detail, sourceIp, prevHash, rowHash)
  VALUES (@ts, @actor, @action, @target, @detail, @sourceIp, @prevHash, @rowHash)
`);

const countAudit = db.prepare(`SELECT COUNT(*) AS c FROM operator_audit_log`);
const pruneAudit = db.prepare(
  `DELETE FROM operator_audit_log WHERE id IN (
     SELECT id FROM operator_audit_log ORDER BY id ASC LIMIT ?
   )`,
);
// After a prune, the new-oldest surviving row's prevHash points at a now-deleted
// row, so the retained chain no longer verifies from a fresh '' seed. We re-anchor
// it: re-thread every surviving row from prevHash='' (see reanchorChain). Reading
// every survivor's content fields lets us recompute their hashes.
const selectSurvivors = db.prepare(
  `SELECT id, ts, actor, action, target, detail, sourceIp, rowHash
     FROM operator_audit_log ORDER BY id ASC`,
);
const updateAuditHashes = db.prepare(
  `UPDATE operator_audit_log SET prevHash = @prevHash, rowHash = @rowHash WHERE id = @id`,
);

/**
 * Prune the oldest `excess` rows, then re-anchor the retained chain so it verifies
 * standalone, all in one transaction so a verify never sees a half-pruned state.
 * Returns the new tail rowHash so the O(1) insert cache can be refreshed.
 */
const pruneAndReanchor = db.transaction((excess: number): string => {
  pruneAudit.run(excess);
  const survivors = selectSurvivors.all() as Array<{
    id: number; ts: number; actor: string; action: string; target: string;
    detail: string; sourceIp: string; rowHash: string;
  }>;
  return reanchorChain(
    survivors.map(r => ({ id: r.id, rowHash: r.rowHash, canonical: auditCanonical(r) })),
    (id, prevHash, rowHash) => updateAuditHashes.run({ id, prevHash, rowHash }),
  );
});

// O(1) inserts: we cache the rowHash of the most recently inserted row so each
// insert links to it WITHOUT rescanning the table. Seeded lazily from the last
// row in the DB on first use (covers a restart that re-opens an existing log).
// Pruning the oldest rows never touches the newest, so the tail hash is stable.
let lastAuditRowHash: string | undefined;

function tailRowHash(): string {
  if (lastAuditRowHash !== undefined) return lastAuditRowHash;
  try {
    const row = db
      .prepare(`SELECT rowHash FROM operator_audit_log ORDER BY id DESC LIMIT 1`)
      .get() as { rowHash?: string } | undefined;
    lastAuditRowHash = row?.rowHash ?? '';
  } catch {
    lastAuditRowHash = '';
  }
  return lastAuditRowHash;
}

// Fixed canonical field order for an audit row — the hash-chain contract. The id
// is auto-increment (unknown before insert) so it is NOT hashed; the chain is
// anchored by ts/actor/action/target/detail/sourceIp + the previous rowHash.
function auditCanonical(r: {
  ts: number; actor: string; action: string; target: string; detail: string; sourceIp: string;
}): string {
  return canonicalString([r.ts, r.actor, r.action, r.target, r.detail, r.sourceIp]);
}

/**
 * Verify the operator audit log's hash chain end-to-end. O(n) — recomputes every
 * hashed row from the start. Legacy (pre-upgrade) rows with empty hashes are
 * skipped cleanly. Fail-open: a read/hash error reports ok:false rather than
 * throwing, so a verify call can never crash the server.
 */
export function verifyAuditChain(): ChainStatus {
  try {
    const rows = db
      .prepare(
        `SELECT id, ts, actor, action, target, detail, sourceIp, prevHash, rowHash
           FROM operator_audit_log ORDER BY id ASC`,
      )
      .all() as Array<{
        id: number; ts: number; actor: string; action: string; target: string;
        detail: string; sourceIp: string; prevHash: string; rowHash: string;
      }>;
    return verifyChain(
      rows.map(r => ({
        id: r.id,
        prevHash: r.prevHash,
        rowHash: r.rowHash,
        canonical: auditCanonical(r),
      })),
      // Capped log: the expected retained count is exactly min(everWritten, cap),
      // so pruning needs no bookkeeping and any shortfall is a real deletion.
      { chain: 'operator_audit_log', cap: MAX_AUDIT_ROWS },
    );
  } catch (e) {
    return chainReadError(`The operator audit log could not be read for verification: ${(e as Error).message}`);
  }
}

/**
 * Decide who performed the action.
 *
 * The HTTP auth gate (server/index.ts) lets a loopback / trust-local request
 * through with no token, and requires a valid CLAUDESEC_TOKEN for anything
 * non-loopback. So by the time a handler runs, a non-loopback request must have
 * authenticated with the token, and a loopback one is the local operator.
 */
function deriveActor(req: Request, isLocalRequest: (req: Request) => boolean): string {
  return isLocalRequest(req) ? 'local' : 'token';
}

/**
 * Build the audit-log writer. `getScrubOptions` and `isLocalRequest` are
 * injected from index.ts so this module stays decoupled from the live
 * scrub-options / loopback-trust state that index.ts owns.
 */
export function makeAuditLogger(
  getScrubOptions: () => ScrubOptions,
  isLocalRequest: (req: Request) => boolean,
): (req: Request, action: string, target: string, detail?: unknown) => void {
  return function auditLog(req: Request, action: string, target: string, detail?: unknown): void {
    try {
      // Scrub the serialized detail so secrets in a config payload never persist.
      const raw = detail === undefined ? '{}' : JSON.stringify(detail);
      const scrubbed = scrubText(raw, getScrubOptions());

      const row = {
        ts:       Date.now(),
        actor:    deriveActor(req, isLocalRequest),
        action:   String(action).slice(0, 128),
        target:   String(target ?? '').slice(0, 256),
        detail:   scrubbed.slice(0, 4000),
        // req.socket.remoteAddress only — never X-Forwarded-For (spoofable).
        sourceIp: String(req.socket?.remoteAddress ?? 'unknown'),
      };

      // Hash-chain this row to the previous one. prevHash is the cached tail
      // rowHash (O(1) — no rescan); rowHash links content + prevHash. A hashing
      // error returns '' (fail-open), which the verifier treats as unchained.
      const prevHash = tailRowHash();
      const rowHash  = computeRowHash(auditCanonical(row), prevHash);
      insertAudit.run({ ...row, prevHash, rowHash });
      // Advance the cached tail only when the hash actually computed. If a one-off
      // crypto failure fails-open to '' (see computeRowHash), caching that empty
      // string would chain the NEXT row onto '' and make the verifier report the
      // whole chain broken from here on. Leaving the cache untouched lets the next
      // insert re-link to the last good hash instead.
      if (rowHash !== '') lastAuditRowHash = rowHash;

      // Bound the table: prune the oldest rows once we pass the cap, then
      // re-anchor the survivors so the retained chain still verifies (the new head
      // would otherwise chain onto a deleted row). Refresh the tail cache from the
      // re-threaded tail so the next insert links to the correct hash.
      const count = (countAudit.get() as { c: number }).c;
      if (count > MAX_AUDIT_ROWS) {
        const newTail = pruneAndReanchor(count - MAX_AUDIT_ROWS);
        lastAuditRowHash = newTail;
      }
    } catch {
      /* never let audit logging break the action it records */
    }
  };
}
