import type { Express } from 'express';
import type { RouteContext } from './context.js';

export function registerScrubRoutes(app: Express, ctx: RouteContext): void {
  const { getScrubEnabled, getHoneytokens } = ctx;
  if (!getScrubEnabled || !getHoneytokens) {
    throw new Error('registerScrubRoutes requires getScrubEnabled and getHoneytokens in ctx');
  }

  // ── Scrub status (read-only) ───────────────────────────────────────────
  app.get('/api/scrub', (_req, res) => {
    res.json({
      enabled:     getScrubEnabled(),
      envOverride: process.env.CLAUDESEC_DISABLE_SCRUB === '1',
      honeytokens: getHoneytokens().length,
      description: 'Inline redaction of /Users/<n>, /home/<n>, C:\\Users\\<n>, $HOME, OS username, email local-parts, and sensitive attribute keys (authorization, token, secret, password, …). Preserves the OTLP attribute shape so downstream dashboards and FTS search keep working.',
    });
  });
}
