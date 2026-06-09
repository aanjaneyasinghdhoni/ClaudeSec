import type { Express } from 'express';
import { db } from '../db.js';
import type { RouteContext } from './context.js';

// startNano is nanoseconds-since-epoch stored as TEXT/INTEGER. SQLite datetime
// helpers want seconds, so divide by 1e9. 'localtime' matches the previous
// JS Date getDay()/getHours() behaviour (local timezone). Rows with a zero/
// unparseable startNano are excluded, preserving the old `if (!nanoMs) continue`.
const calendarBuckets = db.prepare(`
  SELECT
    strftime('%Y-%m-%d', startNano / 1000000000.0, 'unixepoch', 'localtime') AS day,
    CAST(strftime('%H', startNano / 1000000000.0, 'unixepoch', 'localtime') AS INTEGER) AS hour,
    COUNT(*) AS spans,
    SUM(CASE WHEN severity != 'none' THEN 1 ELSE 0 END) AS threats
  FROM spans
  WHERE startNano IS NOT NULL AND CAST(startNano AS INTEGER) >= 1000000
  GROUP BY day, hour
`);

const weekdayBuckets = db.prepare(`
  SELECT
    CAST(strftime('%w', startNano / 1000000000.0, 'unixepoch', 'localtime') AS INTEGER) AS dow,
    CAST(strftime('%H', startNano / 1000000000.0, 'unixepoch', 'localtime') AS INTEGER) AS hour,
    COUNT(*) AS spans,
    SUM(CASE WHEN severity != 'none' THEN 1 ELSE 0 END) AS threats
  FROM spans
  WHERE startNano IS NOT NULL AND CAST(startNano AS INTEGER) >= 1000000
  GROUP BY dow, hour
`);

const countSpans = db.prepare(`SELECT COUNT(*) AS c FROM spans`);

interface Bucket { hour: number; spans: number; threats: number }

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
      const dayToIndex = new Map<string, number>();
      for (let i = 0; i < 14; i++) {
        const d = new Date(todayMidnight - (13 - i) * 86400000);
        const yyyy = d.getFullYear();
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        const key = `${yyyy}-${mm}-${dd}`;
        days.push(key);
        dayToIndex.set(key, i);
      }
      for (const row of calendarBuckets.all() as (Bucket & { day: string })[]) {
        const dayIndex = dayToIndex.get(row.day);
        if (dayIndex === undefined || row.hour < 0 || row.hour > 23) continue;
        calGrid[dayIndex][row.hour].spans   += row.spans;
        calGrid[dayIndex][row.hour].threats += row.threats;
      }
      return res.json({ mode: 'calendar', days, grid: calGrid }) as any;
    }

    // Matrix: grid[dayOfWeek 0-6][hour 0-23] = { spans, threats }
    const grid: { spans: number; threats: number }[][] = Array.from({ length: 7 }, () =>
      Array.from({ length: 24 }, () => ({ spans: 0, threats: 0 })),
    );

    for (const row of weekdayBuckets.all() as (Bucket & { dow: number })[]) {
      if (row.dow < 0 || row.dow > 6 || row.hour < 0 || row.hour > 23) continue;
      grid[row.dow][row.hour].spans   += row.spans;
      grid[row.dow][row.hour].threats += row.threats;
    }

    const maxThreats = Math.max(1, ...grid.flatMap(row => row.map(c => c.threats)));
    const maxSpans   = Math.max(1, ...grid.flatMap(row => row.map(c => c.spans)));
    const totalSpans = (countSpans.get() as { c: number }).c;

    res.json({ grid, maxThreats, maxSpans, totalSpans });
  });
}
