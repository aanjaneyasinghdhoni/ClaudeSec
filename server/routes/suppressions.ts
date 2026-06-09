import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

export function registerSuppressionRoutes(app: Express, ctx: RouteContext): void {
  const { io, invalidateSuppressedCache, auditLog } = ctx;

  // ── Suppressions CRUD (s61) ───────────────────────────────────────────────
  app.get('/api/suppressions', (_req, res) => {
    const now  = new Date().toISOString();
    const rows = db.prepare(`
      SELECT * FROM suppressions WHERE suppressUntil > ? ORDER BY id DESC
    `).all(now) as any[];
    res.json({ suppressions: rows });
  });

  app.post('/api/suppressions', (req, res) => {
    const { ruleKey, durationMs, reason } = req.body as {
      ruleKey?: string; durationMs?: number; reason?: string;
    };
    if (!ruleKey?.trim())                 return res.status(400).json({ error: 'ruleKey required' }) as any;
    if (!durationMs || durationMs <= 0)   return res.status(400).json({ error: 'durationMs > 0 required' }) as any;
    const suppressUntil = new Date(Date.now() + durationMs).toISOString();
    const result = db.prepare(`
      INSERT INTO suppressions (ruleKey, suppressUntil, reason, createdAt)
      VALUES (?, ?, ?, ?)
    `).run(ruleKey.trim(), suppressUntil, (reason ?? '').trim(), new Date().toISOString());
    const row = db.prepare('SELECT * FROM suppressions WHERE id = ?').get(result.lastInsertRowid);
    invalidateSuppressedCache?.();
    auditLog?.(req, 'suppression.create', ruleKey.trim(), { ruleKey: ruleKey.trim(), durationMs, reason: (reason ?? '').trim() });
    io.emit('rules-update');
    res.status(201).json(row);
  });

  app.delete('/api/suppressions/:id', (req, res) => {
    const changes = db.prepare('DELETE FROM suppressions WHERE id = ?').run(Number(req.params.id)).changes;
    if (!changes) return res.status(404).json({ error: 'suppression not found' }) as any;
    invalidateSuppressedCache?.();
    auditLog?.(req, 'suppression.delete', req.params.id, {});
    io.emit('rules-update');
    res.json({ status: 'ok' });
  });
}
