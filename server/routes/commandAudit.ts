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

// ── Command audit trail — all tool executions with risk scores ────────
const SHELL_TOOLS = new Set(['bash', 'Bash', 'exec', 'sh', 'terminal', 'shell', 'subprocess']);

// Push the row filter into SQLite so we never load and JSON.parse the whole
// spans table in Node. A row can only become a command-audit entry if it both
// resolves to a shell tool AND carries a non-empty command string — so we let
// SQLite (via JSON1's json_extract) discard everything else up front.
//
// The WHERE is a deliberate *superset* of the in-Node predicate: it keeps any
// row the Node logic could possibly accept and lets the original checks below
// make the final call, so the response stays byte-for-byte identical. The
// tool-name arm mirrors the `attrs.tool ?? attrs['gen_ai.tool.name'] ?? name`
// resolution; the name arm mirrors `name.includes('bash')`. The command arm
// keeps only rows whose command/tool.input is present and non-empty (the
// `if (!cmd) continue` gate). Final tool resolution and risk scoring still run
// in Node against the parsed page so subtle `??`/truthiness semantics are
// preserved exactly.
const SHELL_TOOL_PLACEHOLDERS = [...SHELL_TOOLS].map(() => '?').join(', ');
const getCommandSpans = db.prepare(`
  SELECT spanId, traceId, name, severity, harness, attributes, startNano
  FROM spans
  WHERE json_valid(attributes)
    AND (
      json_extract(attributes, '$.tool')               IN (${SHELL_TOOL_PLACEHOLDERS})
      OR json_extract(attributes, '$."gen_ai.tool.name"') IN (${SHELL_TOOL_PLACEHOLDERS})
      OR (
        json_extract(attributes, '$.tool')               IS NULL
        AND json_extract(attributes, '$."gen_ai.tool.name"') IS NULL
        AND name IN (${SHELL_TOOL_PLACEHOLDERS})
      )
      OR LOWER(name) LIKE '%bash%'
    )
    AND (
      (json_extract(attributes, '$.command')      IS NOT NULL AND json_extract(attributes, '$.command')      != '')
      OR (json_extract(attributes, '$."tool.input"') IS NOT NULL AND json_extract(attributes, '$."tool.input"') != '')
    )
`);
const SHELL_TOOLS_ARR = [...SHELL_TOOLS];

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
    // Only shell-command rows are loaded and JSON.parsed (SQL-side prefilter),
    // not the full spans table. The args feed the three IN(...) placeholder
    // groups in getCommandSpans (tool, gen_ai.tool.name, name), in order.
    const candidateSpans = getCommandSpans.all(
      ...SHELL_TOOLS_ARR, ...SHELL_TOOLS_ARR, ...SHELL_TOOLS_ARR,
    ) as Pick<SpanRecord, 'spanId' | 'traceId' | 'name' | 'severity' | 'harness' | 'attributes' | 'startNano'>[];
    const commands: {
      spanId: string; traceId: string; harness: string;
      command: string; severity: string; riskScore: number;
      tool: string; timestamp: string;
    }[] = [];

    for (const span of candidateSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['tool'] ?? attrs['gen_ai.tool.name'] ?? span.name ?? '';
        if (!SHELL_TOOLS.has(toolName) && !span.name.toLowerCase().includes('bash')) continue;
        const cmd = attrs['command'] ?? attrs['tool.input'] ?? '';
        // `tool.input` is whatever the agent sent — often a JSON object. Scoring
        // an object coerces it to "[object Object]", which scores 0 and ships a
        // non-string `command` to a client that types it as a string. Only a
        // real command string is auditable.
        if (!cmd || typeof cmd !== 'string') continue;
        commands.push({
          spanId:    span.spanId,
          traceId:   span.traceId,
          harness:   span.harness,
          command:   cmd,
          severity:  span.severity,
          riskScore: computeRiskScore(cmd),
          tool:      toolName || 'bash',
          // Epoch *nanoseconds* in a string, like every other span time in the
          // API — 19 digits overflow a JS number, and a client that hands this
          // straight to `new Date()` gets Invalid Date. Divide by 1e6 first.
          timestamp: span.startNano,
        });
      } catch {}
    }

    commands.sort((a, b) => b.riskScore - a.riskScore);
    res.json({ commands: commands.slice(offset, offset + limit), total: commands.length, limit, offset });
  });
}
