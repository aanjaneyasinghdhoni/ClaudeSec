// auth.ts
//
// Optional bearer-token authentication for mutating API routes.
//
//   - Disabled when CLAUDESEC_API_TOKEN is unset (default).  All routes behave
//     exactly as before — the dashboard works without friction for single-user
//     local installs.
//   - Enabled when CLAUDESEC_API_TOKEN is set.  Mounted routes require the
//     header `Authorization: Bearer <token>` using constant-time comparison.
//   - Read-only routes (/api/health, /metrics, /api/activity, UI assets) stay
//     public so Prometheus scrapes and uptime checks keep working.

import type { Request, Response, NextFunction } from 'express';
import { timingSafeEqual } from 'crypto';

function constantTimeEq(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function getConfiguredToken(): string | null {
  const t = process.env.CLAUDESEC_API_TOKEN;
  return t && t.trim().length >= 8 ? t.trim() : null;
}

/**
 * Middleware — 401s when a token is configured and missing/mismatched.
 * No-op when no token is configured.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = getConfiguredToken();
  if (!token) return next();

  const header = req.headers['authorization'];
  if (typeof header !== 'string' || !header.toLowerCase().startsWith('bearer ')) {
    res.status(401).json({ error: 'Unauthorized', detail: 'Bearer token required' });
    return;
  }
  const supplied = header.slice(7).trim();
  if (!constantTimeEq(supplied, token)) {
    res.status(401).json({ error: 'Unauthorized', detail: 'Invalid bearer token' });
    return;
  }
  next();
}
