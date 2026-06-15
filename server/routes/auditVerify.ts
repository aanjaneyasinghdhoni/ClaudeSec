import type { Express } from 'express';
import type { RouteContext } from './context.js';
import { verifyAuditChain } from '../auditLog.js';
import { verifyEnforceChain } from '../enforceLogStore.js';

// Read-only chain-verification endpoint. Recomputes the tamper-evident hash
// chain for BOTH append-only logs (operator audit log + persisted enforce feed)
// and reports whether each is intact. There is no mutation here — verification
// only reads — and it follows the same loopback/auth gate as every other route
// (applied centrally in server/index.ts), so no extra auth wiring is needed.
//
// Response shape:
//   {
//     ok: boolean,                  // true only if BOTH chains verify
//     audit:   { ok, rows, hashedRows, signed, brokenAtId? },
//     enforce: { ok, rows, hashedRows, signed, brokenAtId? }
//   }
// A non-ok result with `brokenAtId` points at the first row whose stored hash no
// longer matches a recomputation — i.e. where the log was tampered with.
export function registerAuditVerifyRoutes(app: Express, _ctx: RouteContext): void {
  app.get('/api/audit/verify', (_req, res) => {
    const audit = verifyAuditChain();
    const enforce = verifyEnforceChain();
    res.json({ ok: audit.ok && enforce.ok, audit, enforce });
  });
}
