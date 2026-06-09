import type { Express } from 'express';
import { db } from '../db.js';
import { assertSafeFetchUrl } from '../ssrf.js';
import type { RouteContext } from './context.js';

const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);
const delConfig = db.prepare(`DELETE FROM config WHERE key = ?`);
const updateDelivery = db.prepare(`
  UPDATE webhook_deliveries
  SET status = ?, httpCode = ?, latencyMs = ?, error = ?, attempts = attempts + 1, lastAttemptAt = ?
  WHERE id = ?
`);

export function registerWebhookRoutes(app: Express, ctx: RouteContext): void {
  const { getWebhookUrl, getWebhookThreshold, maskWebhookUrl, fireWebhook, auditLog } = ctx;
  if (!getWebhookUrl || !getWebhookThreshold || !maskWebhookUrl || !fireWebhook) {
    throw new Error('registerWebhookRoutes requires getWebhookUrl/getWebhookThreshold/maskWebhookUrl/fireWebhook in ctx');
  }

  // ── Webhook config ───────────────────────────────────────────────────────
  app.get('/api/webhook', (_req, res) => {
    const url       = getWebhookUrl();
    const threshold = getWebhookThreshold();
    res.json({
      configured:  !!url,
      // Never expose full URL — only show redacted form for UI display
      urlPreview:  url ? maskWebhookUrl(url) : null,
      threshold,
      envOverride: !!process.env.CLAUDESEC_WEBHOOK_URL,
    });
  });

  app.post('/api/webhook', async (req, res) => {
    if (process.env.CLAUDESEC_WEBHOOK_URL) {
      return res.status(409).json({ error: 'CLAUDESEC_WEBHOOK_URL env var is set — remove it to manage via API' }) as any;
    }
    const { url, threshold } = req.body as { url?: string; threshold?: string };
    if (!url?.trim()) return res.status(400).json({ error: 'url is required' }) as any;
    // SECURITY: Block SSRF to private/internal networks. Uses the same
    // DNS-resolving guard as the delivery path (defeats integer/hex/IPv6
    // literals and public-name→private-IP tricks) so config-time validation
    // matches delivery-time enforcement. The guard re-runs at every send, so
    // this is an early-rejection convenience, not the only line of defence.
    try {
      await assertSafeFetchUrl(url.trim());
    } catch (err) {
      return res.status(400).json({ error: `Webhook URL rejected: ${(err as Error).message}` }) as any;
    }
    setConfig.run('webhook.url', url.trim());
    if (threshold && ['low', 'medium', 'high'].includes(threshold)) {
      setConfig.run('webhook.threshold', threshold);
    }
    // Audit the change — record the redacted URL only, never the raw secret URL.
    auditLog?.(req, 'webhook.set', 'webhook.url', { urlPreview: maskWebhookUrl(url.trim()), threshold: getWebhookThreshold() });
    res.json({ status: 'ok', urlPreview: maskWebhookUrl(url), threshold: getWebhookThreshold() });
  });

  app.delete('/api/webhook', (req, res) => {
    if (process.env.CLAUDESEC_WEBHOOK_URL) {
      return res.status(409).json({ error: 'CLAUDESEC_WEBHOOK_URL env var is set — unset it instead' }) as any;
    }
    delConfig.run('webhook.url');
    auditLog?.(req, 'webhook.delete', 'webhook.url', {});
    res.json({ status: 'ok' });
  });

  app.post('/api/webhook/test', async (_req, res) => {
    const url = getWebhookUrl();
    if (!url) return res.status(404).json({ error: 'No webhook URL configured' }) as any;
    await fireWebhook({
      ruleLabel:   'Webhook test',
      severity:    'high',
      harness:     'claudesec',
      spanName:    'test',
      matchedText: 'This is a test alert from ClaudeSec',
      traceId:     'test-' + Date.now().toString(16),
    });
    res.json({ status: 'ok', url: maskWebhookUrl(url) });
  });

  // ── Webhook delivery log (s56) ────────────────────────────────────────────

  app.get('/api/webhook-deliveries', (req, res) => {
    const limit = Math.min(Number(req.query.limit ?? 50), 200);
    const rows  = db.prepare('SELECT * FROM webhook_deliveries ORDER BY id DESC LIMIT ?').all(limit) as any[];
    const total = (db.prepare('SELECT COUNT(*) as c FROM webhook_deliveries').get() as any).c as number;
    res.json({ deliveries: rows, total });
  });

  app.post('/api/webhook-deliveries/:id/retry', async (req, res) => {
    const delivery = db.prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(Number(req.params.id)) as any;
    if (!delivery) return res.status(404).json({ error: 'delivery not found' }) as any;
    if (delivery.status === 'success') return res.status(409).json({ error: 'delivery already succeeded' }) as any;

    const url = getWebhookUrl();
    if (!url) return res.status(503).json({ error: 'No webhook URL configured' }) as any;

    // Re-resolve + SSRF-check the configured URL on retry too (it may have been
    // changed to an internal target, or its DNS rebound, since first delivery).
    try {
      await assertSafeFetchUrl(url);
    } catch (err: any) {
      updateDelivery.run('failed', null, 0, `blocked (SSRF guard): ${err.message}`, new Date().toISOString(), delivery.id);
      return res.status(400).json({ status: 'failed', error: `blocked: ${err.message}` }) as any;
    }

    const t0 = Date.now();
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'claudesec', rule: delivery.ruleLabel, severity: delivery.severity, retry: true }) });
      updateDelivery.run(r.ok ? 'success' : 'failed', r.status, Date.now() - t0, r.ok ? null : `HTTP ${r.status}`, new Date().toISOString(), delivery.id);
      res.json({ status: r.ok ? 'success' : 'failed', httpCode: r.status });
    } catch (err: any) {
      updateDelivery.run('failed', null, Date.now() - t0, err.message, new Date().toISOString(), delivery.id);
      res.status(502).json({ status: 'failed', error: err.message });
    }
  });

  app.delete('/api/webhook-deliveries', (_req, res) => {
    db.prepare('DELETE FROM webhook_deliveries').run();
    res.json({ status: 'ok' });
  });
}
