import type { Express } from 'express';
import { db } from '../db.js';
import { SEVERITY_RULES, CATASTROPHIC_DETECTION_LABELS } from '../detection.js';
import type { RouteContext } from './context.js';

// Per-rule enable/disable persistence.
//
// Distinct from a suppression (which is time-boxed): an override permanently
// silences a noisy rule until the operator re-enables it. Only the enabled flag
// is persisted — severity is not overridable here, by design (keeps the surface
// small and the audit trail unambiguous).
//
// SAFETY: the catastrophic-floor detection labels (detection.ts
// CATASTROPHIC_DETECTION_LABELS) can never be disabled. Any attempt is a 400.
// This mirrors the enforcement floor, which blocks those intents even in
// monitor mode — they are the catastrophic events the tool exists to catch.

const getOverrides = db.prepare(`SELECT ruleLabel, enabled, updatedTs FROM rule_overrides ORDER BY ruleLabel ASC`);
const upsertOverride = db.prepare(`
  INSERT INTO rule_overrides (ruleLabel, enabled, updatedTs) VALUES (@ruleLabel, @enabled, @updatedTs)
  ON CONFLICT(ruleLabel) DO UPDATE SET enabled = excluded.enabled, updatedTs = excluded.updatedTs
`);

export function registerRuleOverrideRoutes(app: Express, ctx: RouteContext): void {
  const { io, invalidateDisabledRulesCache, getCustomRules, auditLog } = ctx;

  // ── List current overrides ─────────────────────────────────────────────
  app.get('/api/rule-overrides', (_req, res) => {
    res.json({ overrides: getOverrides.all() });
  });

  // ── Enable / disable a single rule by its label ──────────────────────────
  app.put('/api/rule-overrides/:label', (req, res) => {
    const label = String(req.params.label ?? '').trim();
    const { enabled } = req.body as { enabled?: unknown };

    if (!label)                 return res.status(400).json({ error: 'rule label required' }) as any;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled (boolean) required' }) as any;
    }

    // SAFETY: never let an operator disable a catastrophic-floor rule. Record
    // the rejected attempt — "who tried to silence a catastrophic rule" is
    // exactly the kind of event an audit log exists to surface.
    if (!enabled && CATASTROPHIC_DETECTION_LABELS.has(label)) {
      auditLog?.(req, 'rule.disable.rejected', label, { label, reason: 'catastrophic-floor rule' });
      return res.status(400).json({
        error: `"${label}" is a catastrophic-floor rule and cannot be disabled`,
      }) as any;
    }

    // Validate the label exists among built-in or custom rules — we don't want
    // to accumulate overrides for labels that no rule actually carries.
    const builtinLabels = new Set(SEVERITY_RULES.map(r => r.label));
    const customLabels  = new Set((getCustomRules?.() ?? []).map(r => r.label));
    if (!builtinLabels.has(label) && !customLabels.has(label)) {
      return res.status(404).json({ error: `no rule found with label "${label}"` }) as any;
    }

    upsertOverride.run({ ruleLabel: label, enabled: enabled ? 1 : 0, updatedTs: Date.now() });
    invalidateDisabledRulesCache?.();

    auditLog?.(req, enabled ? 'rule.enable' : 'rule.disable', label, { label, enabled });

    io.emit('rules-update');
    res.json({ status: 'ok', ruleLabel: label, enabled });
  });
}
