import type { Express } from 'express';
import { db } from '../db.js';
import { judgeContent } from '../llmJudge.js';
import type { SpanRecord } from '../types.js';
import type { RouteContext } from './context.js';

export function registerJudgeRoutes(app: Express, _ctx: RouteContext): void {
  // ── LLM-as-judge (optional, opt-in, local-first) ─────────────────────────
  // Semantic detection layer that augments the regex rules. OFF by default:
  // unless CLAUDESEC_JUDGE_URL is configured this endpoint reports
  // {enabled:false} and makes ZERO outbound calls (no-egress preserved). When
  // enabled, it classifies the given text (or a span's content) as
  // prompt-injection / jailbreak / data-exfiltration / benign via a configured
  // OpenAI-compatible chat endpoint — recommended: a LOCAL Ollama. Fail-open:
  // any error returns {enabled:true, error} and never blocks anything.
  app.post('/api/judge', async (req, res) => {
    const body = (req.body ?? {}) as { text?: string; spanId?: string };
    let text = typeof body.text === 'string' ? body.text : '';
    let spanId: string | undefined;

    // If a spanId is given, build the judged text from that span's content
    // (mirrors /api/spans/:spanId/match: attributes + name).
    if (!text && body.spanId) {
      const row = db.prepare('SELECT * FROM spans WHERE spanId = ?').get(body.spanId) as SpanRecord | undefined;
      if (!row) {
        res.status(404).json({ error: 'span not found' });
        return;
      }
      spanId = row.spanId;
      text = row.attributes + ' ' + row.name;
    }

    if (!text.trim()) {
      res.status(400).json({ error: 'text or spanId is required' });
      return;
    }

    // judgeContent never throws and never blocks — it returns {enabled:false}
    // when no judge is configured (no network call) or {enabled:true,...}.
    const result = await judgeContent(text);
    res.json({ ...result, spanId });
  });
}
