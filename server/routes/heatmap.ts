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

export function registerHeatmapRoutes(app: Express, _ctx: RouteContext): void {
  // ── Threat heatmap — 7×24 day-of-week × hour matrix ─────────────────────
  app.get('/api/heatmap', (req, res) => {
    if (req.query.mode === 'calendar') {
      const calGrid: { spans: number; threats: number }[][] = Array.from({ length: 14 }, () =>
        Array.from({ length: 24 }, () => ({ spans: 0, threats: 0 })),
      );
      const now = new Date();
      const todayMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
      const days: string[] = [];
      for (let i = 0; i < 14; i++) {
        const d = new Date(todayMidnight - (13 - i) * 86400000);
        const yyyy = d.getFullYear();
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        days.push(`${yyyy}-${mm}-${dd}`);
      }
      const calSpans = getAllSpans.all() as SpanRecord[];
      for (const span of calSpans) {
        try {
          const nanoMs = Number(BigInt(span.startNano) / 1_000_000n);
          if (!nanoMs) continue;
          const d = new Date(nanoMs);
          const spanMidnight = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
          const daysAgo = Math.floor((todayMidnight - spanMidnight) / 86400000);
          const dayIndex = 13 - daysAgo;
          if (dayIndex < 0 || dayIndex > 13) continue;
          const hour = d.getHours();
          calGrid[dayIndex][hour].spans++;
          if (span.severity !== 'none') calGrid[dayIndex][hour].threats++;
        } catch {}
      }
      return res.json({ mode: 'calendar', days, grid: calGrid }) as any;
    }

    // Matrix: grid[dayOfWeek 0-6][hour 0-23] = { spans, threats }
    const grid: { spans: number; threats: number }[][] = Array.from({ length: 7 }, () =>
      Array.from({ length: 24 }, () => ({ spans: 0, threats: 0 })),
    );

    const allSpans = getAllSpans.all() as SpanRecord[];
    for (const span of allSpans) {
      try {
        const nanoMs = Number(BigInt(span.startNano) / 1_000_000n);
        if (!nanoMs) continue;
        const d = new Date(nanoMs);
        const dow  = d.getDay();   // 0 = Sunday
        const hour = d.getHours(); // 0–23
        grid[dow][hour].spans++;
        if (span.severity !== 'none') grid[dow][hour].threats++;
      } catch {}
    }

    const maxThreats = Math.max(1, ...grid.flatMap(row => row.map(c => c.threats)));
    const maxSpans   = Math.max(1, ...grid.flatMap(row => row.map(c => c.spans)));

    res.json({ grid, maxThreats, maxSpans, totalSpans: allSpans.length });
  });
}
