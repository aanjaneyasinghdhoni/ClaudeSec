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

// Hard cap on retained rows. The oldest rows are pruned on insert once the
// table grows past this, so a long-lived install can't accumulate an unbounded
// log. 10k rows is plenty to answer recent "who changed what" questions while
// staying small on disk.
const MAX_AUDIT_ROWS = 10_000;

const insertAudit = db.prepare(`
  INSERT INTO operator_audit_log (ts, actor, action, target, detail, sourceIp)
  VALUES (@ts, @actor, @action, @target, @detail, @sourceIp)
`);

const countAudit = db.prepare(`SELECT COUNT(*) AS c FROM operator_audit_log`);
const pruneAudit = db.prepare(
  `DELETE FROM operator_audit_log WHERE id IN (
     SELECT id FROM operator_audit_log ORDER BY id ASC LIMIT ?
   )`,
);

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

      insertAudit.run({
        ts:       Date.now(),
        actor:    deriveActor(req, isLocalRequest),
        action:   String(action).slice(0, 128),
        target:   String(target ?? '').slice(0, 256),
        detail:   scrubbed.slice(0, 4000),
        // req.socket.remoteAddress only — never X-Forwarded-For (spoofable).
        sourceIp: String(req.socket?.remoteAddress ?? 'unknown'),
      });

      // Bound the table: prune the oldest rows once we pass the cap.
      const count = (countAudit.get() as { c: number }).c;
      if (count > MAX_AUDIT_ROWS) pruneAudit.run(count - MAX_AUDIT_ROWS);
    } catch {
      /* never let audit logging break the action it records */
    }
  };
}
