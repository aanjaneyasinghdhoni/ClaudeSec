import type { Express } from 'express';
import RE2 from 're2';
import { SEVERITY_RULES } from '../detection.js';
import type { Severity } from '../../src/shared/types.js';
import type { CustomRule, RouteContext } from './context.js';

// Cap user-supplied regex length to mitigate catastrophic backtracking (ReDoS)
// before a pattern is ever compiled and run against ingested spans.
const MAX_RULE_PATTERN_LEN = 1000;

export function registerRuleRoutes(app: Express, ctx: RouteContext): void {
  const { io } = ctx;

  // ── Rules CRUD ───────────────────────────────────────────────────────────
  app.get('/api/rules', (_req, res) => {
    const builtIn = SEVERITY_RULES.map((r, i) => ({
      id:       `builtin-${i}`,
      pattern:  r.pattern.source,
      flags:    r.pattern.flags,
      severity: r.severity,
      label:    r.label,
      builtin:  true,
    }));
    res.json({ builtIn, custom: ctx.getCustomRules?.() ?? [] });
  });

  app.post('/api/rules', (req, res) => {
    const { pattern, severity, label } = req.body as { pattern?: string; severity?: string; label?: string };
    if (!pattern || !severity || !label) {
      return res.status(400).json({ error: 'pattern, severity, and label are required' }) as any;
    }
    const validSeverities: Severity[] = ['low', 'medium', 'high'];
    if (!validSeverities.includes(severity as Severity)) {
      return res.status(400).json({ error: 'severity must be low, medium, or high' }) as any;
    }
    // Bound user-supplied regex length to mitigate catastrophic-backtracking
    // (ReDoS) before it is ever compiled and run against ingested spans.
    if (pattern.length > MAX_RULE_PATTERN_LEN) {
      return res.status(400).json({ error: `pattern must be at most ${MAX_RULE_PATTERN_LEN} characters` }) as any;
    }
    try { new RE2(pattern); } catch {
      return res.status(400).json({ error: 'invalid regex pattern' }) as any;
    }
    const rule: CustomRule = {
      id:        `custom-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      pattern,
      flags:     'i',
      severity:  severity as Severity,
      label,
      createdAt: new Date().toISOString(),
    };
    ctx.addCustomRule?.(rule);
    io.emit('rules-update');
    res.status(201).json(rule);
  });

  app.delete('/api/rules/:id', (req, res) => {
    const removed = ctx.removeCustomRule?.(req.params.id) ?? false;
    if (!removed) return res.status(404).json({ error: 'rule not found' }) as any;
    io.emit('rules-update');
    res.json({ status: 'ok' });
  });
}
