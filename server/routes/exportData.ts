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

const getAllSpans = db.prepare(`SELECT * FROM spans`);

/** Export routes also need the running app version to stamp into the dump. */
interface ExportRouteContext extends RouteContext {
  appVersion?: string;
}

export function registerExportRoutes(app: Express, ctx: ExportRouteContext): void {
  // Fall back to '0.0.0' so a missing version never produces an unstamped dump.
  const version = ctx.appVersion ?? '0.0.0';

  // ── Export ───────────────────────────────────────────────────────────────
  app.get('/api/export', (_req, res) => {
    const records     = getAllSpans.all() as SpanRecord[];
    const annotations = db.prepare('SELECT * FROM annotations ORDER BY id ASC').all();
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), version, spans: records, annotations });
  });

  app.get('/api/export/csv', (_req, res) => {
    const records = getAllSpans.all() as SpanRecord[];
    const header  = 'spanId,traceId,name,harness,severity,protocol,reason,startNano,endNano\n';
    const rows    = records.map(r =>
      [
        r.spanId, r.traceId,
        `"${r.name.replace(/"/g, '""')}"`,
        r.harness, r.severity, r.protocol,
        `"${r.reason.replace(/"/g, '""')}"`,
        r.startNano, r.endNano,
      ].join(',')
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-${Date.now()}.csv"`);
    res.send(header + rows);
  });
}
