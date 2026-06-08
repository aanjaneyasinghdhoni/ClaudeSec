import type { Express } from 'express';
import { scanMcpAndSkills, type ScanResult } from '../mcpScan.js';
import type { RouteContext } from './context.js';

export function registerMcpScanRoutes(app: Express, ctx: RouteContext): void {
  const { detectSeverity } = ctx;
  if (!detectSeverity) {
    throw new Error('registerMcpScanRoutes requires detectSeverity in ctx');
  }

  // ── MCP / skill static scanner ───────────────────────────────────────────
  // Scans installed MCP server configs and Claude skills for prompt-injection,
  // tool poisoning, hardcoded secrets, and suspicious launch commands. The scan
  // is READ-ONLY (never launches a server, never writes a scanned file) and
  // bounded (file/size/finding caps in mcpScan.ts). Results are cached briefly
  // so repeated dashboard polls don't re-walk the filesystem; ?force=1 bypasses.
  let mcpScanCache: { at: number; result: ScanResult } | null = null;
  const MCP_SCAN_TTL_MS = 30_000;
  app.get('/api/mcp-scan', (req, res) => {
    const force = req.query.force === '1' || req.query.force === 'true';
    const now = Date.now();
    if (!force && mcpScanCache && now - mcpScanCache.at < MCP_SCAN_TTL_MS) {
      return res.json({ ...mcpScanCache.result, cached: true }) as any;
    }
    try {
      const result = scanMcpAndSkills(detectSeverity);
      mcpScanCache = { at: now, result };
      res.json({ ...result, cached: false });
    } catch (err) {
      res.status(500).json({ error: 'scan failed', detail: String((err as Error)?.message ?? err) });
    }
  });
}
