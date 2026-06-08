import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

const deleteAllAlerts = db.prepare(`DELETE FROM alerts`);

export function registerAlertRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Alerts ───────────────────────────────────────────────────────────────
  app.get('/api/alerts', (req, res) => {
    const limit          = Math.min(Number(req.query.limit ?? 200), 1000);
    const severity       = req.query.severity      ? String(req.query.severity)      : null;
    const showDismissed  = req.query.showDismissed === 'true';
    // groupBy=rule collapses duplicate alerts into a single row per fingerprint
    const groupBy        = req.query.groupBy === 'rule';

    const conditions: string[] = [];
    const params: unknown[]    = [];

    if (severity && severity !== 'all') { conditions.push('severity = ?');    params.push(severity); }
    if (!showDismissed)                 { conditions.push('dismissed = 0'); }

    const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';

    let alerts: unknown[];
    if (groupBy) {
      // Grouped view: one row per unique (ruleLabel, traceId, harness), SUM(count)
      alerts = db.prepare(`
        SELECT
          MIN(id) as id, MAX(ts) as ts, ruleLabel, severity,
          MAX(spanId) as spanId, traceId, harness, spanName,
          MAX(matchedText) as matchedText, MAX(dismissed) as dismissed,
          MAX(fp) as fp, fingerprint, SUM(count) as count
        FROM alerts${where}
        GROUP BY ruleLabel, traceId, harness
        ORDER BY MAX(id) DESC
        LIMIT ?
      `).all(...params, limit);
    } else {
      alerts = db.prepare(`SELECT * FROM alerts${where} ORDER BY id DESC LIMIT ?`).all(...params, limit);
    }
    const total  = groupBy ? alerts.length : (db.prepare(`SELECT COUNT(*) as c FROM alerts${where}`).get(...params) as any).c;

    // SECURITY: Redact sensitive matched text (API keys, tokens, passwords)
    // Show first 6 + last 4 chars, mask the rest
    const SENSITIVE_LABELS = /key|token|password|secret|credential|private/i;
    const redactedAlerts = (alerts as any[]).map(a => {
      if (a.matchedText && SENSITIVE_LABELS.test(a.ruleLabel) && a.matchedText.length > 12) {
        const mt = a.matchedText;
        a.matchedText = mt.slice(0, 6) + '*'.repeat(Math.min(mt.length - 10, 20)) + mt.slice(-4);
      }
      return a;
    });

    res.json({ alerts: redactedAlerts, total });
  });

  app.get('/api/alerts/export', (_req, res) => {
    const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC').all();
    // SECURITY: Apply same redaction as /api/alerts
    const SENSITIVE_LABELS = /key|token|password|secret|credential|private/i;
    const redactedAlerts = (alerts as any[]).map(a => {
      if (a.matchedText && SENSITIVE_LABELS.test(a.ruleLabel) && a.matchedText.length > 12) {
        const mt = a.matchedText;
        a.matchedText = mt.slice(0, 6) + '*'.repeat(Math.min(mt.length - 10, 20)) + mt.slice(-4);
      }
      return a;
    });
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-alerts-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), alerts: redactedAlerts });
  });

  app.delete('/api/alerts', (_req, res) => {
    deleteAllAlerts.run();
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });

  // ── Alert triage — dismiss & false-positive (s60) ─────────────────────────
  app.patch('/api/alerts/:id', (req, res) => {
    const id  = Number(req.params.id);
    const { dismissed, fp } = req.body as { dismissed?: boolean; fp?: boolean };
    if (dismissed === undefined && fp === undefined) {
      return res.status(400).json({ error: 'dismissed or fp is required' }) as any;
    }
    const existing = db.prepare('SELECT id FROM alerts WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'alert not found' }) as any;

    if (dismissed !== undefined) {
      db.prepare('UPDATE alerts SET dismissed = ? WHERE id = ?').run(dismissed ? 1 : 0, id);
    }
    if (fp !== undefined) {
      db.prepare('UPDATE alerts SET fp = ? WHERE id = ?').run(fp ? 1 : 0, id);
    }
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });
}
