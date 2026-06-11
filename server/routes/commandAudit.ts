import type { Express } from 'express';
import { db } from '../db.js';
import type { Severity } from '../../src/shared/types.js';
import type { RouteContext } from './context.js';

interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}

const getAllSpans = db.prepare(`SELECT * FROM spans`);

// ── Command audit trail — all tool executions with risk scores ────────
const SHELL_TOOLS = new Set(['bash', 'Bash', 'exec', 'sh', 'terminal', 'shell', 'subprocess']);

function computeRiskScore(cmd: string): number {
  let score = 0;
  if (/\bsudo\b/i.test(cmd)) score += 20;
  if (/\bcurl\b.*\|\s*(ba)?sh/i.test(cmd)) score += 30;
  if (/\bcurl\b|\bwget\b/i.test(cmd)) score += 15;
  if (/\brm\s+-rf\b/i.test(cmd)) score += 30;
  if (/\|.*\bsh\b/i.test(cmd)) score += 25;
  if (/\/etc\/(passwd|shadow|sudoers)/i.test(cmd)) score += 25;
  if (/~\/\.ssh\//i.test(cmd)) score += 20;
  if (/\.env\b/i.test(cmd)) score += 15;
  if (/\bnc\b|\bncat\b/i.test(cmd)) score += 30;
  if (/\bchmod\s+[247]?[0-7][0-7]\b/i.test(cmd)) score += 15;
  if (/\bchown\s+root\b/i.test(cmd)) score += 25;
  if (/\bkill\b|\bpkill\b/i.test(cmd)) score += 10;
  if (/\beval\b|\bexec\b/i.test(cmd)) score += 20;
  if (/process\.env|printenv|env\b/i.test(cmd)) score += 10;
  return Math.min(100, score);
}

export function registerCommandAuditRoutes(app: Express, _ctx: RouteContext): void {
  // Query params mirror /api/file-access paging:
  //   ?limit=  (default 200, max 5000) — page size
  //   ?offset= (default 0)             — page offset into the risk-sorted list
  //
  // The response always reports the true `total` so the client can page through
  // every recorded command — no hard cap on how far you can walk.
  app.get('/api/command-audit', (req, res) => {
    const limit = Math.min(Math.max(1, Number(req.query.limit) || 200), 5000);
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    const allSpans = getAllSpans.all() as SpanRecord[];
    const commands: {
      spanId: string; traceId: string; harness: string;
      command: string; severity: string; riskScore: number;
      tool: string; timestamp: string;
    }[] = [];

    for (const span of allSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['tool'] ?? attrs['gen_ai.tool.name'] ?? span.name ?? '';
        if (!SHELL_TOOLS.has(toolName) && !span.name.toLowerCase().includes('bash')) continue;
        const cmd = attrs['command'] ?? attrs['tool.input'] ?? '';
        if (!cmd) continue;
        commands.push({
          spanId:    span.spanId,
          traceId:   span.traceId,
          harness:   span.harness,
          command:   cmd,
          severity:  span.severity,
          riskScore: computeRiskScore(cmd),
          tool:      toolName || 'bash',
          timestamp: span.startNano,
        });
      } catch {}
    }

    commands.sort((a, b) => b.riskScore - a.riskScore);
    res.json({ commands: commands.slice(offset, offset + limit), total: commands.length, limit, offset });
  });
}
