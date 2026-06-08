import type { Express } from 'express';
import { db } from '../db.js';
import type { Severity } from '../../src/shared/types.js';
import type { RouteContext } from './context.js';

interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}

// ── Full-text search (s54) ───────────────────────────────────────────────

function buildSearchQuery(opts: {
  q: string; severity?: string; harness?: string;
  from?: string; to?: string; tag?: string; limit: number; offset: number;
}): { spans: SpanRecord[]; total: number } {
  const conditions: string[] = [];
  const params: unknown[]    = [];

  // Tag filter — join against span_tags
  let fromClause = 'spans';
  if (opts.tag) {
    const tagClean = opts.tag.trim().toLowerCase();
    conditions.push('spanId IN (SELECT spanId FROM span_tags WHERE tag = ?)');
    params.push(tagClean);
  }

  // FTS5 match — fall back to LIKE if query is empty
  if (opts.q) {
    try {
      const escaped = '"' + opts.q.replace(/"/g, '""') + '"';
      const ftsIds  = (db.prepare('SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?').all(escaped) as { spanId: string }[]).map(r => r.spanId);
      if (ftsIds.length === 0) return { spans: [], total: 0 };
      const ph = ftsIds.map(() => '?').join(',');
      conditions.push(`spanId IN (${ph})`);
      params.push(...ftsIds);
    } catch {
      // FTS5 syntax error → fall back to LIKE
      const like = `%${opts.q}%`;
      conditions.push('(name LIKE ? OR attributes LIKE ?)');
      params.push(like, like);
    }
  }

  if (opts.severity && opts.severity !== 'all') {
    conditions.push('severity = ?');
    params.push(opts.severity);
  }
  if (opts.harness) {
    conditions.push('harness = ?');
    params.push(opts.harness);
  }
  if (opts.from) {
    try {
      const nanoFrom = String(BigInt(new Date(opts.from).getTime()) * 1_000_000n);
      conditions.push('startNano >= ?');
      params.push(nanoFrom);
    } catch {}
  }
  if (opts.to) {
    try {
      const nanoTo = String(BigInt(new Date(opts.to).getTime()) * 1_000_000n);
      conditions.push('startNano <= ?');
      params.push(nanoTo);
    } catch {}
  }

  const where  = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const total  = (db.prepare(`SELECT COUNT(*) as c FROM ${fromClause} ${where}`).get(...params) as any).c as number;
  const spans  = db.prepare(`SELECT * FROM ${fromClause} ${where} ORDER BY startNano DESC LIMIT ? OFFSET ?`)
    .all(...params, opts.limit, opts.offset) as SpanRecord[];
  return { spans, total };
}

export function registerSearchRoutes(app: Express, _ctx: RouteContext): void {
  app.get('/api/search', (req, res) => {
    const q        = String(req.query.q        ?? '').trim();
    const severity = String(req.query.severity ?? '').trim();
    const harness  = String(req.query.harness  ?? '').trim();
    const from     = String(req.query.from     ?? '').trim();
    const to       = String(req.query.to       ?? '').trim();
    const tag      = String(req.query.tag      ?? '').trim() || undefined;
    const limit    = Math.min(Math.max(1, Number(req.query.limit ?? 20)), 100);
    const page     = Math.max(1, Number(req.query.page ?? 1));
    const offset   = (page - 1) * limit;

    const { spans, total } = buildSearchQuery({ q, severity, harness, from, to, tag, limit, offset });
    res.json({ spans, total, page, pages: Math.ceil(total / limit), query: q });
  });

  app.get('/api/search/export', (req, res) => {
    const q        = String(req.query.q        ?? '').trim();
    const severity = String(req.query.severity ?? '').trim();
    const harness  = String(req.query.harness  ?? '').trim();
    const tag      = String(req.query.tag      ?? '').trim() || undefined;
    const { spans } = buildSearchQuery({ q, severity, harness, tag, limit: 5000, offset: 0 });
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-search-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), query: q, count: spans.length, spans });
  });

  // ── FTS5 full-text search over span name + attributes ──────────────────
  // Backed by the existing spans_fts virtual table (kept in sync by trigger).
  app.get('/api/search/fts', (req, res) => {
    const raw   = String(req.query.q ?? '').trim();
    const limit = Math.min(Math.max(1, Number(req.query.limit ?? 50)), 200);
    if (raw.length < 2) {
      res.json({ spans: [], total: 0, query: raw });
      return;
    }
    // Escape FTS5 special characters; wrap each term as a prefix match.
    const terms = raw.replace(/["']/g, ' ').split(/\s+/).filter(Boolean);
    if (terms.length === 0) {
      res.json({ spans: [], total: 0, query: raw });
      return;
    }
    const ftsQuery = terms.map(t => `"${t}"*`).join(' ');
    try {
      const rows = db.prepare(`
        SELECT s.*
        FROM   spans_fts f
        JOIN   spans s ON s.spanId = f.spanId
        WHERE  spans_fts MATCH ?
        ORDER BY rank
        LIMIT ?
      `).all(ftsQuery, limit) as SpanRecord[];
      const total = (db.prepare(`
        SELECT COUNT(*) as c FROM spans_fts WHERE spans_fts MATCH ?
      `).get(ftsQuery) as { c: number }).c;
      res.json({ spans: rows, total, query: raw });
    } catch (err) {
      res.status(400).json({ error: 'Invalid FTS query', detail: (err as Error).message });
    }
  });
}
