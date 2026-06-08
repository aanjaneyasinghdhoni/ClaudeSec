import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

export function registerBookmarkRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Span bookmarks (s67) ──────────────────────────────────────────────────
  app.get('/api/bookmarks', (req, res) => {
    const session = req.query.session ? String(req.query.session) : null;
    const rows = session
      ? db.prepare(`
          SELECT b.*, s.name AS spanName, s.severity, s.harness
          FROM span_bookmarks b
          LEFT JOIN spans s ON s.spanId = b.spanId
          WHERE b.traceId = ?
          ORDER BY b.id DESC
        `).all(session)
      : db.prepare(`
          SELECT b.*, s.name AS spanName, s.severity, s.harness
          FROM span_bookmarks b
          LEFT JOIN spans s ON s.spanId = b.spanId
          ORDER BY b.id DESC LIMIT 200
        `).all();
    res.json({ bookmarks: rows });
  });

  app.post('/api/bookmarks', (req, res) => {
    const { spanId, traceId, note } = req.body as { spanId?: string; traceId?: string; note?: string };
    if (!spanId?.trim()) return res.status(400).json({ error: 'spanId required' }) as any;
    const result = db.prepare(`
      INSERT INTO span_bookmarks (spanId, traceId, note, createdAt)
      VALUES (?, ?, ?, ?)
    `).run(spanId.trim(), traceId?.trim() ?? '', (note ?? '').trim(), new Date().toISOString());
    const row = db.prepare('SELECT * FROM span_bookmarks WHERE id = ?').get(result.lastInsertRowid);
    io.emit('bookmarks-update');
    res.status(201).json(row);
  });

  app.patch('/api/bookmarks/:id', (req, res) => {
    const { note } = req.body as { note?: string };
    if (note === undefined) return res.status(400).json({ error: 'note required' }) as any;
    const changes = db.prepare('UPDATE span_bookmarks SET note = ? WHERE id = ?')
      .run(note.trim(), Number(req.params.id)).changes;
    if (!changes) return res.status(404).json({ error: 'bookmark not found' }) as any;
    res.json({ status: 'ok' });
  });

  app.delete('/api/bookmarks/:id', (req, res) => {
    const changes = db.prepare('DELETE FROM span_bookmarks WHERE id = ?')
      .run(Number(req.params.id)).changes;
    if (!changes) return res.status(404).json({ error: 'bookmark not found' }) as any;
    io.emit('bookmarks-update');
    res.json({ status: 'ok' });
  });

  // Delete bookmark by spanId (convenient for toggle-off)
  app.delete('/api/bookmarks/span/:spanId', (req, res) => {
    db.prepare('DELETE FROM span_bookmarks WHERE spanId = ?').run(req.params.spanId);
    io.emit('bookmarks-update');
    res.json({ status: 'ok' });
  });
}
