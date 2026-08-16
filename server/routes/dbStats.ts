import fs from 'fs';
import type { Express } from 'express';
import { db, DB_PATH } from '../db.js';
import {
  RETENTION_PROFILES,
  RETENTION_UNBOUNDED,
  resolveRetention,
  retentionProfile,
  type RetentionProfileId,
} from '../retentionProfiles.js';
import type { RouteContext } from './context.js';

const setConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);
const getConfigValue = db.prepare<[string], { value: string }>(`SELECT value FROM config WHERE key = ?`);

/** Same precedence the server runs on: env → stored config → profile default. */
const retentionStatus = () =>
  resolveRetention({
    env: process.env,
    readConfig: (key) => getConfigValue.get(key)?.value,
    db,
  });

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

    // Retention is reported as a policy, not as two numbers. `effective` says
    // which limit actually governs, how many days that really is at this
    // install's own ingest rate, and where each value came from — so nobody can
    // read "183 days" off this screen while the span ceiling is quietly ending
    // ingestion three weeks in.
    const retention = retentionStatus();

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
        // Unchanged shape for existing clients — 0 still means unbounded.
        maxSpans:      getMaxSpans(),
        retentionDays: getRetentionDays(),
        profile:       retention.profile,
        profileLabel:  retention.profileLabel,
        sources:       retention.sources,
        envOverride:   retention.envOverride,
        effective: {
          limitingFactor:         retention.limitingFactor,
          effectiveWindowDays:    retention.effectiveWindowDays,
          spansPerDay:            retention.spansPerDay,
          projectedSpansInWindow: retention.projectedSpansInWindow,
          ingestStopsAtSpans:     retention.ingestStopsAtSpans,
          ingestStopsAfterDays:   retention.ingestStopsAfterDays,
          estimatedBytes:         retention.estimatedBytes,
          warning:                retention.warning,
        },
      },
      // The catalogue the UI renders as a profile picker.
      retentionProfiles: Object.values(RETENTION_PROFILES).map(p => ({
        id: p.id,
        label: p.label,
        days: p.days,
        maxSpans: p.maxSpans,
        summary: p.summary,
      })),
    });
  });

  app.post('/api/db-stats/prune', (_req, res) => {
    const result = pruneSpans();
    io.emit('sessions-update');
    io.emit('graph-update', buildGraph());
    res.json({ status: 'ok', ...result });
  });

  app.post('/api/db-stats/retention', (req, res) => {
    const { profile, maxSpans, retentionDays } = req.body as {
      profile?: string; maxSpans?: number; retentionDays?: number;
    };

    // A named profile sets BOTH knobs in one write. That is the whole point:
    // setting the day window alone is what let a 50,000-span ceiling end
    // ingestion long before a 183-day window closed.
    if (profile !== undefined && profile !== null && profile !== 'custom') {
      const preset = retentionProfile(String(profile));
      if (!preset) {
        return res.status(400).json({
          error: `unknown profile "${profile}". Expected one of: ${Object.keys(RETENTION_PROFILES).join(', ')}, custom`,
        }) as any;
      }
      setConfig.run('retention.days', String(preset.days));
      setConfig.run('retention.max_spans', String(preset.maxSpans));
      auditLog?.(req, 'retention.set', 'retention', {
        profile: preset.id, maxSpans: getMaxSpans(), retentionDays: getRetentionDays(),
      });
      const status = retentionStatus();
      return res.json({
        status: 'ok',
        profile: preset.id,
        maxSpans: getMaxSpans(),
        retentionDays: getRetentionDays(),
        effective: status,
      }) as any;
    }

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

    // Hand back the consequence of what was just saved, not only an echo of it.
    // A custom pair whose ceiling is too small for its window is legal — but the
    // caller is told, in the same response, how many days it will really keep.
    const status = retentionStatus();
    res.json({
      status: 'ok',
      maxSpans: getMaxSpans(),
      retentionDays: getRetentionDays(),
      profile: status.profile,
      effective: status,
      warning: status.warning,
    });
  });

  // ── Retention profiles ───────────────────────────────────────────────────
  // The catalogue plus what each profile would deliver at THIS install's
  // measured ingest rate, so the choice can be made on evidence rather than on
  // which number looks biggest.
  app.get('/api/db-stats/retention/profiles', (_req, res) => {
    const current = retentionStatus();
    const spansPerDay = current.spansPerDay;
    const profiles = (Object.values(RETENTION_PROFILES) as { id: RetentionProfileId; label: string; days: number; maxSpans: number; summary: string }[])
      .map(p => ({
        id: p.id,
        label: p.label,
        days: p.days === RETENTION_UNBOUNDED ? null : p.days,
        maxSpans: p.maxSpans === RETENTION_UNBOUNDED ? null : p.maxSpans,
        summary: p.summary,
        active: current.profile === p.id,
        // What this profile would really deliver here, at the measured rate.
        deliversDays: p.days === RETENTION_UNBOUNDED
          ? null
          : spansPerDay
            ? Math.min(p.days, Math.floor((p.maxSpans * 0.9) / spansPerDay))
            : p.days,
      }));
    res.json({ current: current.profile, spansPerDay, profiles });
  });
}
