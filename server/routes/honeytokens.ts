import type { Express } from 'express';
import type { RouteContext } from './context.js';

export function registerHoneytokenRoutes(app: Express, ctx: RouteContext): void {
  // ── Honeytokens ────────────────────────────────────────────────────────
  // Operator-planted canary strings that should never appear in legitimate
  // telemetry.  Any match fires a HIGH-severity "Honeytoken exfiltration"
  // alert regardless of other rules.
  app.get('/api/honeytokens', (_req, res) => {
    const tokens = ctx.getHoneytokens?.() ?? [];
    res.json({
      tokens: tokens.map(t => ({
        preview:  t.slice(0, 4) + '***' + t.slice(-2),
        length:   t.length,
      })),
      count: tokens.length,
      envOverride: !!process.env.CLAUDESEC_HONEYTOKENS,
    });
  });

  app.post('/api/honeytokens', (req, res) => {
    if (process.env.CLAUDESEC_HONEYTOKENS) {
      res.status(409).json({ error: 'CLAUDESEC_HONEYTOKENS env var is set — remove it to manage via API' });
      return;
    }
    const { tokens } = req.body as { tokens?: string[] };
    if (!Array.isArray(tokens)) {
      res.status(400).json({ error: 'tokens must be an array of strings' });
      return;
    }
    const clean = tokens.filter((t): t is string => typeof t === 'string' && t.trim().length >= 6);
    ctx.saveHoneytokens?.(clean);
    res.json({ status: 'ok', count: clean.length });
  });

  app.delete('/api/honeytokens', (_req, res) => {
    if (process.env.CLAUDESEC_HONEYTOKENS) {
      res.status(409).json({ error: 'CLAUDESEC_HONEYTOKENS env var is set — unset it instead' });
      return;
    }
    ctx.clearHoneytokens?.();
    res.json({ status: 'ok' });
  });
}
