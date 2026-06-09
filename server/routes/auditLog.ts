import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// Read-only view over the operator audit log. There is intentionally NO delete
// endpoint: an audit log that can be cleared from the UI is not an audit log.
// Retention is handled at write time (server/auditLog.ts caps the table and
// prunes the oldest rows), not by an operator-triggered purge.
export function registerAuditLogRoutes(app: Express, _ctx: RouteContext): void {
  app.get('/api/audit-log', (req, res) => {
    // Pagination: newest first, capped page size, optional before-id cursor.
    const rawLimit = Number(req.query.limit);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0
      ? Math.min(Math.floor(rawLimit), 500)
      : 100;

    const rawBefore = Number(req.query.before);
    const before = Number.isFinite(rawBefore) && rawBefore > 0 ? Math.floor(rawBefore) : null;

    const rows = before === null
      ? db.prepare(
          `SELECT id, ts, actor, action, target, detail, sourceIp
             FROM operator_audit_log ORDER BY id DESC LIMIT ?`,
        ).all(limit)
      : db.prepare(
          `SELECT id, ts, actor, action, target, detail, sourceIp
             FROM operator_audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`,
        ).all(before, limit);

    const total = (db.prepare('SELECT COUNT(*) AS c FROM operator_audit_log').get() as { c: number }).c;
    // Next cursor: the id of the last (oldest) row in this page, or null at the end.
    const nextBefore = rows.length === limit ? (rows[rows.length - 1] as { id: number }).id : null;

    res.json({ entries: rows, total, nextBefore });
  });
}
