import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// Threshold-rule statements are stateless db handles; index.ts keeps its own
// copies for the evaluator (evaluateThresholdRules).
const insertThresholdRule = db.prepare(`
  INSERT INTO threshold_rules (name, metric, operator, value, window_min, enabled, createdAt)
  VALUES (@name, @metric, @operator, @value, @window_min, @enabled, @createdAt)
`);
const deleteThresholdRule  = db.prepare(`DELETE FROM threshold_rules WHERE id = ?`);
const updateThresholdRule  = db.prepare(`UPDATE threshold_rules SET enabled = ? WHERE id = ?`);
const getAllThresholdRules  = db.prepare(`SELECT * FROM threshold_rules ORDER BY id ASC`);

export function registerThresholdRuleRoutes(app: Express, _ctx: RouteContext): void {
  // ── Threshold alert rules ────────────────────────────────────────────────
  app.get('/api/threshold-rules', (_req, res) => {
    res.json({ rules: getAllThresholdRules.all() });
  });

  app.post('/api/threshold-rules', (req, res) => {
    const { name, metric, operator, value, window_min, enabled } = req.body as {
      name?: string; metric?: string; operator?: string;
      value?: number; window_min?: number; enabled?: boolean;
    };
    const validMetrics   = ['tokens_in', 'tokens_out', 'threat_count', 'span_count', 'high_threat_count'];
    const validOperators = ['>', '>=', '<', '<=', '='];
    if (!name?.trim())                  return res.status(400).json({ error: 'name required' }) as any;
    if (!metric || !validMetrics.includes(metric))   return res.status(400).json({ error: `metric must be one of: ${validMetrics.join(', ')}` }) as any;
    if (!operator || !validOperators.includes(operator)) return res.status(400).json({ error: `operator must be one of: ${validOperators.join(', ')}` }) as any;
    if (value === undefined || isNaN(Number(value))) return res.status(400).json({ error: 'value (number) required' }) as any;
    const result = insertThresholdRule.run({
      name: name.trim(), metric, operator, value: Number(value),
      window_min: Number(window_min ?? 60), enabled: enabled !== false ? 1 : 0,
      createdAt: new Date().toISOString(),
    });
    const row = db.prepare('SELECT * FROM threshold_rules WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(row);
  });

  app.patch('/api/threshold-rules/:id', (req, res) => {
    const { enabled } = req.body as { enabled?: boolean };
    if (enabled === undefined) return res.status(400).json({ error: 'enabled required' }) as any;
    const changes = updateThresholdRule.run(enabled ? 1 : 0, Number(req.params.id)).changes;
    if (!changes) return res.status(404).json({ error: 'Rule not found' }) as any;
    res.json({ status: 'ok' });
  });

  app.delete('/api/threshold-rules/:id', (req, res) => {
    const changes = deleteThresholdRule.run(Number(req.params.id)).changes;
    if (!changes) return res.status(404).json({ error: 'Rule not found' }) as any;
    res.json({ status: 'ok' });
  });
}
