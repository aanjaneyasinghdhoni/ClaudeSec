import fs from 'fs';
import type { Express } from 'express';
import { db, DB_PATH } from '../db.js';
import type { RouteContext } from './context.js';

const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);

export function registerDbStatsRoutes(app: Express, ctx: RouteContext): void {
  const { io, getMaxSpans, getRetentionDays, pruneSpans, buildGraph, auditLog } = ctx;
  if (!getMaxSpans || !getRetentionDays || !pruneSpans || !buildGraph) {
    throw new Error('registerDbStatsRoutes requires getMaxSpans/getRetentionDays/pruneSpans/buildGraph in ctx');
  }

  // ── DB stats + retention config ──────────────────────────────────────────
  app.get('/api/db-stats', (_req, res) => {
    const spansTotal    = (db.prepare('SELECT COUNT(*) as c FROM spans').get() as any).c as number;
    const sessionsTotal = (db.prepare('SELECT COUNT(*) as c FROM sessions').get() as any).c as number;
    const alertsTotal   = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as any).c as number;
    const oldestSession = (db.prepare('SELECT MIN(createdAt) as d FROM sessions').get() as any).d as string | null;
    const newestSession = (db.prepare('SELECT MAX(createdAt) as d FROM sessions').get() as any).d as string | null;
    let dbSizeBytes = 0;
    try { dbSizeBytes = fs.statSync(DB_PATH).size; } catch {}

    res.json({
      spansTotal,
      sessionsTotal,
      alertsTotal,
      dbSizeBytes,
      dbSizeHuman: dbSizeBytes > 1_048_576
        ? `${(dbSizeBytes / 1_048_576).toFixed(1)} MB`
        : `${(dbSizeBytes / 1024).toFixed(1)} KB`,
      oldestSession,
      newestSession,
      retentionConfig: {
        maxSpans:      getMaxSpans(),
        retentionDays: getRetentionDays(),
      },
    });
  });

  app.post('/api/db-stats/prune', (_req, res) => {
    const result = pruneSpans();
    io.emit('sessions-update');
    io.emit('graph-update', buildGraph());
    res.json({ status: 'ok', ...result });
  });

  app.post('/api/db-stats/retention', (req, res) => {
    const { maxSpans, retentionDays } = req.body as { maxSpans?: number; retentionDays?: number };
    // Reject non-finite (NaN from a cleared field serializes to JSON null, which
    // arrives as `null` not `undefined`) and out-of-range values with a 400, so a
    // bad input can never be silently skipped while the UI flashes "Saved".
    if (maxSpans !== undefined && maxSpans !== null) {
      if (!Number.isFinite(maxSpans) || maxSpans < 100) {
        return res.status(400).json({ error: 'maxSpans must be a finite number >= 100' }) as any;
      }
      setConfig.run('retention.max_spans', String(maxSpans));
    }
    if (retentionDays !== undefined && retentionDays !== null) {
      if (!Number.isFinite(retentionDays) || retentionDays < 1) {
        return res.status(400).json({ error: 'retentionDays must be a finite number >= 1' }) as any;
      }
      setConfig.run('retention.days', String(retentionDays));
    }
    auditLog?.(req, 'retention.set', 'retention', { maxSpans: getMaxSpans(), retentionDays: getRetentionDays() });
    res.json({ status: 'ok', maxSpans: getMaxSpans(), retentionDays: getRetentionDays() });
  });
}
