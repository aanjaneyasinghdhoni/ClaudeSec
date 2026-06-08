import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// Prepared statements for span annotations (relocated from index.ts alongside
// the annotation handlers). `db` is imported directly; index.ts retains only
// `deleteAllAnnotations`, which the /api/reset path still uses.
const insertAnnotation = db.prepare(`
  INSERT INTO annotations (spanId, text, author, createdAt)
  VALUES (@spanId, @text, @author, @createdAt)
`);
const deleteAnnotation = db.prepare(`DELETE FROM annotations WHERE id = ? AND spanId = ?`);
const getAnnotationsBySpan = db.prepare(`SELECT * FROM annotations WHERE spanId = ? ORDER BY id ASC`);

export function registerSpanMetaRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Annotations ──────────────────────────────────────────────────────────
  app.get('/api/spans/:spanId/annotations', (req, res) => {
    const rows = getAnnotationsBySpan.all(req.params.spanId);
    res.json({ annotations: rows });
  });

  app.post('/api/spans/:spanId/annotations', (req, res) => {
    const { text, author } = req.body as { text?: string; author?: string };
    if (!text?.trim()) return res.status(400).json({ error: 'text is required' }) as any;
    const result = insertAnnotation.run({
      spanId:    req.params.spanId,
      text:      text.trim(),
      author:    (author?.trim() || 'analyst'),
      createdAt: new Date().toISOString(),
    });
    const row = db.prepare('SELECT * FROM annotations WHERE id = ?').get(result.lastInsertRowid);
    io.emit('annotation-update', { spanId: req.params.spanId });
    res.status(201).json(row);
  });

  app.delete('/api/spans/:spanId/annotations/:id', (req, res) => {
    const changes = deleteAnnotation.run(Number(req.params.id), req.params.spanId).changes;
    if (!changes) return res.status(404).json({ error: 'Not found' }) as any;
    io.emit('annotation-update', { spanId: req.params.spanId });
    res.json({ status: 'ok' });
  });

  // ── Span custom tags (s62) ───────────────────────────────────────────────
  app.get('/api/spans/:spanId/tags', (req, res) => {
    const rows = db.prepare('SELECT tag, createdAt FROM span_tags WHERE spanId = ? ORDER BY id ASC')
      .all(req.params.spanId) as { tag: string; createdAt: string }[];
    res.json({ tags: rows.map(r => r.tag) });
  });

  app.post('/api/spans/:spanId/tags', (req, res) => {
    const { tag } = req.body as { tag?: string };
    if (!tag?.trim()) return res.status(400).json({ error: 'tag is required' }) as any;
    const clean = tag.trim().toLowerCase().replace(/[^a-z0-9_:.-]/g, '').slice(0, 64);
    if (!clean) return res.status(400).json({ error: 'tag contains no valid characters' }) as any;
    try {
      db.prepare('INSERT OR IGNORE INTO span_tags (spanId, tag, createdAt) VALUES (?, ?, ?)')
        .run(req.params.spanId, clean, new Date().toISOString());
    } catch {
      return res.status(409).json({ error: 'tag already exists' }) as any;
    }
    res.status(201).json({ tag: clean });
  });

  app.delete('/api/spans/:spanId/tags/:tag', (req, res) => {
    const changes = db.prepare('DELETE FROM span_tags WHERE spanId = ? AND tag = ?')
      .run(req.params.spanId, req.params.tag.toLowerCase()).changes;
    if (!changes) return res.status(404).json({ error: 'tag not found' }) as any;
    res.json({ status: 'ok' });
  });
}
