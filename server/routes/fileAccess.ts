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

interface FileAgg {
  path: string;
  reads: number;
  writes: number;
  agents: Set<string>;
  threats: number;
  sensitive: boolean;
  folder: string;
  branch: string;
}

const getAllSpans = db.prepare(`SELECT * FROM spans`);

const READ_TOOLS = new Set(['Read', 'file_read', 'Glob', 'cat', 'head', 'tail', 'Grep']);
const WRITE_TOOLS = new Set(['Write', 'Edit', 'file_edit', 'touch', 'mv', 'cp']);
const SENSITIVE_PATTERNS = [/\.env\b/, /\.ssh\//, /\/etc\/(passwd|shadow|sudoers|hosts)/, /credentials/, /\.pem$/, /id_rsa/];

// Build the per-file aggregation from every span that touched a file. The cwd /
// git.branch attributes are stamped by the transcript watcher, so we can group a
// file under the repo/folder it was accessed from.
function aggregateFiles(spans: SpanRecord[]): Map<string, FileAgg> {
  const fileMap = new Map<string, FileAgg>();

  for (const span of spans) {
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

      const cwd = typeof attrs['cwd'] === 'string' && attrs['cwd'] ? attrs['cwd'] : '';
      const branch = typeof attrs['git.branch'] === 'string' && attrs['git.branch'] ? attrs['git.branch'] : '';
      // Group key: the cwd the agent ran in. Falls back to the file's own parent
      // directory when no cwd was recorded (e.g. OTLP-only spans).
      const folder = cwd || parentDir(filePath) || '(unknown)';

      if (!fileMap.has(filePath)) {
        const sensitive = SENSITIVE_PATTERNS.some(p => p.test(filePath));
        fileMap.set(filePath, {
          path: filePath, reads: 0, writes: 0, agents: new Set(), threats: 0,
          sensitive, folder, branch,
        });
      }
      const entry = fileMap.get(filePath)!;
      if (isRead) entry.reads++;
      if (isWrite) entry.writes++;
      entry.agents.add(span.harness);
      if (span.severity !== 'none') entry.threats++;
      // Keep the first non-empty branch we see for this file.
      if (!entry.branch && branch) entry.branch = branch;
    } catch {}
  }

  return fileMap;
}

function parentDir(filePath: string): string {
  const idx = filePath.replace(/\/+$/, '').lastIndexOf('/');
  return idx > 0 ? filePath.slice(0, idx) : '';
}

export function registerFileAccessRoutes(app: Express, _ctx: RouteContext): void {
  // ── File access analysis — which files agents read/write ────────────
  //
  // Query params:
  //   ?limit=  (default 500)  — flat-mode page size
  //   ?offset= (default 0)    — flat-mode page offset
  //   ?groupBy=folder         — return files grouped per cwd/repo instead of flat
  //
  // The flat response always reports `total` so the client can page through every
  // file (no hard cap — the maintainer wants to see all of them).
  app.get('/api/file-access', (req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];
    const fileMap = aggregateFiles(allSpans);

    const allFiles = [...fileMap.values()]
      .map(f => ({
        path: f.path,
        reads: f.reads,
        writes: f.writes,
        agents: [...f.agents],
        threats: f.threats,
        sensitive: f.sensitive,
        folder: f.folder,
        branch: f.branch,
        total: f.reads + f.writes,
      }))
      .sort((a, b) => b.total - a.total);

    // ── Grouped mode: aggregate per folder (cwd / repo) ──────────────────
    if (String(req.query.groupBy ?? '') === 'folder') {
      const groupMap = new Map<string, {
        folder: string;
        branch: string;
        files: typeof allFiles;
        reads: number;
        writes: number;
        threats: number;
        sensitive: number;
        agents: Set<string>;
      }>();

      for (const f of allFiles) {
        if (!groupMap.has(f.folder)) {
          groupMap.set(f.folder, {
            folder: f.folder, branch: f.branch, files: [],
            reads: 0, writes: 0, threats: 0, sensitive: 0, agents: new Set(),
          });
        }
        const g = groupMap.get(f.folder)!;
        g.files.push(f);
        g.reads += f.reads;
        g.writes += f.writes;
        g.threats += f.threats;
        if (f.sensitive) g.sensitive++;
        for (const a of f.agents) g.agents.add(a);
        if (!g.branch && f.branch) g.branch = f.branch;
      }

      const groups = [...groupMap.values()]
        .map(g => ({
          folder: g.folder,
          branch: g.branch,
          files: g.files,
          fileCount: g.files.length,
          reads: g.reads,
          writes: g.writes,
          total: g.reads + g.writes,
          threats: g.threats,
          sensitive: g.sensitive,
          agents: [...g.agents],
        }))
        .sort((a, b) => b.total - a.total);

      res.json({ groups, totalFiles: fileMap.size, totalFolders: groups.length });
      return;
    }

    // ── Flat mode: limit / offset paging over the sorted file list ───────
    const limit = Math.min(Math.max(1, Number(req.query.limit ?? 500)), 5000);
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    const files = allFiles.slice(offset, offset + limit);

    res.json({ files, total: fileMap.size, limit, offset });
  });
}
