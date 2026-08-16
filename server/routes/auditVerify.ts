import type { Express } from 'express';
import type { RouteContext } from './context.js';
import { verifyAuditChain } from '../auditLog.js';
import { verifyEnforceChain } from '../enforceLogStore.js';
import {
  verifySpanChain, spanChainBackfillComplete, spanChainMutableFieldFixComplete,
  spanChainFieldCoverage, SPAN_CHAIN_MUTABLE_FIELD_LIMITS,
} from '../db.js';
import {
  AUDIT_LIMITS, anchorExists, anchorIsSigned, auditKeyId, auditPublicKeyPem,
} from '../auditChain.js';
import { getAnchorStatus } from '../auditAnchor.js';

// Read-only chain-verification endpoints.
//
// Three append-only records are checked: the operator audit log, the persisted
// enforcement feed, and the spans ledger — the last of which is the one that
// matters, since it is the actual record of what the agent did rather than a
// capped summary of the last few days.
//
// WHAT A PASSING RESULT MEANS, EXACTLY
//   • Rows were not edited, reordered, or removed since they were written,
//     unless whoever did it also held this machine's signing key.
//   • It does NOT mean the record is complete. An event that was never written
//     leaves no residue; no verifier can tell a quiet hour from a silenced one.
//   • It does NOT bind the operator. The private key lives on this host, so its
//     owner can always produce a history that verifies. Signing defeats a remote
//     or different-UID attacker, and — unlike the HMAC it replaced — it lets a
//     third party verify with the public key alone, without gaining the ability
//     to forge. That property is what makes anchoring the tail off-box possible;
//     until that exists, the ceiling above is real.
//   • `status` is deliberately more than ok/not-ok. "someone edited row 12",
//     "the last 40 rows were cut off" and "the table was emptied" are different
//     incidents and an auditor needs to be told which one happened.
//
// `anchor` (from server/auditAnchor.ts) answers the question the chain check
// above cannot: everything up to this point verifies against ITSELF, but the
// operator holds the signing key and could have wiped and re-signed all of it.
// `anchor.truncationWindowMs` is the number that actually matters — how far
// back the last EXTERNALLY countersigned checkpoint reaches, i.e. how much of
// "now" is still only as trustworthy as the local key. off by default; when no
// TSA/OTS method is configured this is a cheap, synchronous, no-op read of an
// unset config (see getAnchorConfig in auditAnchor.ts) with a null window and
// an explicit "no bound on the exposure window" explanation.
//
// Neither endpoint mutates anything, and both sit behind the same loopback/auth
// gate as every other route (applied centrally in server/index.ts).
export function registerAuditVerifyRoutes(app: Express, _ctx: RouteContext): void {
  app.get('/api/audit/verify', (req, res) => {
    // The spans check is windowed by default because a full recomputation reads
    // every stored attribute back off disk. `?deep=1` asks for all of it.
    const deep = String(req.query.deep ?? '') === '1';
    void verifySpanChain({ deep })
      .then((spans) => {
        const audit = verifyAuditChain();
        const enforce = verifyEnforceChain();
        res.json({
          ok: audit.ok && enforce.ok && spans.ok,
          audit,
          enforce,
          spans,
          key: {
            keyId: auditKeyId(),
            algorithm: 'ed25519',
            // Record this fingerprint somewhere off this machine. A keyId that
            // changes means the record was re-founded under a new key, however
            // cleanly the chain verifies against itself.
            anchorPresent: anchorExists(),
            anchorSigned: anchorIsSigned(),
          },
          // The external-witness layer. `ok` above never depends on this — a
          // clean local chain is still reported clean whether or not anyone
          // opted in to an outside witness; the exposure this describes is
          // orthogonal, not a verification failure.
          anchor: getAnchorStatus(),
          backfillComplete: spanChainBackfillComplete(),
          // Separate from backfillComplete (which only means "every span has a
          // chain position"): this is "the endNano/repo mutation defect has
          // been repaired everywhere it could reach". A row_mismatch on a span
          // means something different depending on which of these is true —
          // see spans.mutableFieldFixComplete in the per-chain result and
          // SPAN_CHAIN_MUTABLE_FIELD_LIMITS below for what it changes.
          mutableFieldFixComplete: spanChainMutableFieldFixComplete(),
          // At-a-glance record coverage, computed once and cached (see
          // spanChainFieldCoverage's doc comment in server/db.ts) so this costs
          // nothing beyond a COUNT(*) even on a 274k-row table — no deep
          // recompute needed just to answer "how much of my record is on the
          // scheme that doesn't have this landmine." `exact:false` means the
          // one-time classification pass hasn't finished yet (it starts itself
          // on the first call); poll again shortly.
          //
          // WHY THIS IS REPORTED INSTEAD OF FIXED: legacyFieldRows are not
          // bulk-rewritten onto the current scheme. Doing so on an install with
          // no external anchor (server/auditAnchor.ts, opt-in, off by default)
          // would be a fully deterministic recompute over public code and each
          // row's own stored fields — exactly what an attacker with the same
          // database-write access could also produce, with nothing external to
          // tell the two apart. It would also spend real protection those rows
          // already have: endNano/repo ARE part of their hash, so an edit to
          // either breaks verification today (proven against a copy of the
          // production database), which rewriting onto spanCanonical would
          // silently give up. See SPAN_CHAIN_MUTABLE_FIELD_LIMITS for the full
          // shape of the tradeoff.
          spansFieldCoverage: spanChainFieldCoverage(),
          limits: AUDIT_LIMITS,
          spanLimits: SPAN_CHAIN_MUTABLE_FIELD_LIMITS,
        });
      })
      .catch((e: Error) => {
        res.status(500).json({ ok: false, error: `verification failed: ${e.message}` });
      });
  });

  // Cheap, synchronous status-only read (no chain recomputation) for a
  // dashboard widget or a poller that just wants "is anchoring on, and how
  // stale is the last external witness" without paying for a full verify.
  app.get('/api/audit/anchor', (_req, res) => {
    res.json(getAnchorStatus());
  });

  // The public half of the signing key, so a third party can verify the anchor
  // without being handed anything secret — the whole point of moving off HMAC.
  app.get('/api/audit/public-key', (_req, res) => {
    const pem = auditPublicKeyPem();
    if (!pem) {
      res.status(503).json({ error: 'no signing key available on this install' });
      return;
    }
    res.json({ keyId: auditKeyId(), algorithm: 'ed25519', publicKeyPem: pem, limits: AUDIT_LIMITS });
  });
}
