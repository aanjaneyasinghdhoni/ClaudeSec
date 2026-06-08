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

export function registerFileAccessRoutes(app: Express, _ctx: RouteContext): void {
  // ── File access analysis — which files agents read/write ────────────
  app.get('/api/file-access', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];
    const READ_TOOLS = new Set(['Read', 'file_read', 'Glob', 'cat', 'head', 'tail', 'Grep']);
    const WRITE_TOOLS = new Set(['Write', 'Edit', 'file_edit', 'touch', 'mv', 'cp']);
    const SENSITIVE_PATTERNS = [/\.env\b/, /\.ssh\//, /\/etc\/(passwd|shadow|sudoers|hosts)/, /credentials/, /\.pem$/, /id_rsa/];

    const fileMap = new Map<string, {
      path: string; reads: number; writes: number;
      agents: Set<string>; threats: number; sensitive: boolean;
    }>();

    for (const span of allSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['tool'] ?? attrs['gen_ai.tool.name'] ?? span.name ?? '';
        const input = attrs['file_path'] ?? attrs['path'] ?? attrs['pattern'] ?? attrs['tool.input'] ?? '';
        if (!input || typeof input !== 'string') continue;

        const isRead = READ_TOOLS.has(toolName);
        const isWrite = WRITE_TOOLS.has(toolName);
        if (!isRead && !isWrite) continue;

        // Normalize path
        const filePath = input.trim().split('\n')[0].slice(0, 200);
        if (!filePath || filePath.length < 2) continue;

        if (!fileMap.has(filePath)) {
          const sensitive = SENSITIVE_PATTERNS.some(p => p.test(filePath));
          fileMap.set(filePath, { path: filePath, reads: 0, writes: 0, agents: new Set(), threats: 0, sensitive });
        }
        const entry = fileMap.get(filePath)!;
        if (isRead) entry.reads++;
        if (isWrite) entry.writes++;
        entry.agents.add(span.harness);
        if (span.severity !== 'none') entry.threats++;
      } catch {}
    }

    const files = [...fileMap.values()]
      .map(f => ({ ...f, agents: [...f.agents], total: f.reads + f.writes }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 100);

    res.json({ files, total: fileMap.size });
  });
}
