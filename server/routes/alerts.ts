import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

const deleteAllAlerts = db.prepare(`DELETE FROM alerts`);

// SECURITY: redact sensitive matched text (API keys, tokens, passwords) before
// it leaves the server. Show the first 6 + last 4 chars and mask the middle.
// Shared by GET /api/alerts and GET /api/alerts/export so both stay in lockstep.
const SENSITIVE_LABELS = /key|token|password|secret|credential|private/i;
function redactAlert(a: any): any {
  if (a.matchedText && SENSITIVE_LABELS.test(a.ruleLabel) && a.matchedText.length > 12) {
    const mt = a.matchedText;
    a.matchedText = mt.slice(0, 6) + '*'.repeat(Math.min(mt.length - 10, 20)) + mt.slice(-4);
  }
  return a;
}

export function registerAlertRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Alerts ───────────────────────────────────────────────────────────────
  app.get('/api/alerts', (req, res) => {
    const limit          = Math.min(Number(req.query.limit ?? 200), 1000);
    const severity       = req.query.severity      ? String(req.query.severity)      : null;
    const showDismissed  = req.query.showDismissed === 'true';
    const showFp         = req.query.showFp        === 'true';
    // groupBy=rule collapses duplicate alerts into a single row per fingerprint
    const groupBy        = req.query.groupBy === 'rule';

    const conditions: string[] = [];
    const params: unknown[]    = [];

    if (severity && severity !== 'all') { conditions.push('severity = ?');    params.push(severity); }
    // The triage view hides dismissed and false-positive alerts by default. The
    // nav badge reads `total` from this same WHERE, so excluding fp here is what
    // makes marking an alert FP actually drop it from the count.
    if (!showDismissed)                 { conditions.push('dismissed = 0'); }
    if (!showFp)                        { conditions.push('fp = 0'); }

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

    const redactedAlerts = (alerts as any[]).map(redactAlert);

    res.json({ alerts: redactedAlerts, total });
  });

  app.get('/api/alerts/export', (_req, res) => {
    const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC').all();
    // Apply the same redaction as GET /api/alerts.
    const redactedAlerts = (alerts as any[]).map(redactAlert);
    res.setHeader('Content-Disposition', `attachment; filename="claudesec-alerts-${Date.now()}.json"`);
    res.json({ exportedAt: new Date().toISOString(), alerts: redactedAlerts });
  });

  app.delete('/api/alerts', (_req, res) => {
    deleteAllAlerts.run();
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });

  // ── Alert triage — dismiss & false-positive (s60) ─────────────────────────
  // The body may carry an optional `fingerprint`. When present, the change is
  // applied to every alert sharing that fingerprint instead of the single row
  // in the path. The grouped (groupBy=rule) view collapses duplicates into one
  // row, so dismissing/FP'ing from there must hit all the underlying duplicates
  // — otherwise N-1 rows survive and reappear on ungrouping. The :id stays the
  // anchor (it must exist and match the fingerprint) so the route still 404s on
  // a stale row and never blind-writes by fingerprint alone.
  app.patch('/api/alerts/:id', (req, res) => {
    const id  = Number(req.params.id);
    const { dismissed, fp, fingerprint } = req.body as {
      dismissed?: boolean; fp?: boolean; fingerprint?: string;
    };
    if (dismissed === undefined && fp === undefined) {
      return res.status(400).json({ error: 'dismissed or fp is required' }) as any;
    }
    const existing = db.prepare('SELECT id, fingerprint FROM alerts WHERE id = ?')
      .get(id) as { id: number; fingerprint: string } | undefined;
    if (!existing) return res.status(404).json({ error: 'alert not found' }) as any;

    // Decide the target set. A fingerprint must match the anchor row's own
    // fingerprint to be honored — otherwise fall back to the single row.
    const useFingerprint = fingerprint !== undefined && fingerprint === existing.fingerprint;
    const filterSql = useFingerprint ? 'fingerprint = ?' : 'id = ?';
    const filterArg = useFingerprint ? fingerprint : id;

    if (dismissed !== undefined) {
      db.prepare(`UPDATE alerts SET dismissed = ? WHERE ${filterSql}`).run(dismissed ? 1 : 0, filterArg);
    }
    if (fp !== undefined) {
      db.prepare(`UPDATE alerts SET fp = ? WHERE ${filterSql}`).run(fp ? 1 : 0, filterArg);
    }
    io.emit('alerts-update');
    res.json({ status: 'ok' });
  });
}
