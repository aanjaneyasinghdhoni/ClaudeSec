import type { Express } from 'express';
import type { ProtectedPath, RouteContext } from './context.js';

// Bound the stored path length. Real paths are short; a giant string is almost
// certainly a paste mistake or an attempt to bloat the mirrored artifact.
const MAX_PATH_LEN = 4096;

/**
 * Routes for the user-defined "protected paths" floor — paths that the
 * PreToolUse hook ALWAYS blocks, in every mode. No UI yet; these back a future
 * dashboard affordance.
 */
export function registerProtectedPathRoutes(app: Express, ctx: RouteContext): void {
  const { io, auditLog } = ctx;

  app.get('/api/protected-paths', (_req, res) => {
    res.json({ protectedPaths: ctx.getProtectedPaths?.() ?? [] });
  });

  app.post('/api/protected-paths', (req, res) => {
    const { path: rawPath, label } = req.body as { path?: unknown; label?: unknown };
    if (typeof rawPath !== 'string' || rawPath.trim().length === 0) {
      return res.status(400).json({ error: 'path is required and must be a non-empty string' }) as any;
    }
    const p = rawPath.trim();
    if (p.length > MAX_PATH_LEN) {
      return res.status(400).json({ error: `path must be at most ${MAX_PATH_LEN} characters` }) as any;
    }
    // Reject an exact duplicate path so the list can't silently accumulate the
    // same entry (which would bloat the mirrored artifact and confuse the user).
    const existing = ctx.getProtectedPaths?.() ?? [];
    if (existing.some((e) => e.path === p)) {
      return res.status(409).json({ error: 'path is already protected' }) as any;
    }

    const cleanLabel =
      typeof label === 'string' && label.trim().length > 0 ? label.trim() : p;

    const entry: ProtectedPath = {
      id: `protected-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      path: p,
      label: cleanLabel,
      createdAt: new Date().toISOString(),
    };
    ctx.addProtectedPath?.(entry);
    auditLog?.(req, 'protected-path.create', entry.id, { path: entry.path, label: entry.label });
    io.emit('protected-paths-update');
    res.status(201).json(entry);
  });

  app.delete('/api/protected-paths/:id', (req, res) => {
    const removed = ctx.removeProtectedPath?.(req.params.id) ?? false;
    if (!removed) return res.status(404).json({ error: 'protected path not found' }) as any;
    auditLog?.(req, 'protected-path.delete', req.params.id, {});
    io.emit('protected-paths-update');
    res.json({ status: 'ok' });
  });
}
