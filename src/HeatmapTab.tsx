/**
 * HeatmapTab — threat density calendar heatmap (7 days × 24 hours)
 * GET /api/heatmap → { grid[7][24]: {spans, threats}, maxThreats, maxSpans }
 */
import React, { useEffect, useState, useCallback } from 'react';
import { Flame } from 'lucide-react';
import { socket } from './socket';

interface Cell { spans: number; threats: number }
interface HeatmapData {
  grid: Cell[][];       // [dayOfWeek 0-6][hour 0-23]
  maxThreats: number;
  maxSpans: number;
  totalSpans: number;
}

const DAYS  = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HOURS = Array.from({ length: 24 }, (_, i) =>
  i === 0 ? '12a' : i < 12 ? `${i}a` : i === 12 ? '12p' : `${i - 12}p`,
);

// Interpolate green→yellow→red based on ratio 0..1
function threatColor(ratio: number): string {
  if (ratio === 0)      return 'rgba(30,41,59,0.8)';      // bg-slate-800 — no data
  if (ratio < 0.0001)  return 'rgba(34,197,94,0.25)';    // green — safe activity
  if (ratio < 0.25)    return 'rgba(34,197,94,0.6)';
  if (ratio < 0.5)     return 'rgba(234,179,8,0.7)';     // yellow
  if (ratio < 0.75)    return 'rgba(249,115,22,0.8)';    // orange
  return                      'rgba(239,68,68,0.9)';     // red — high threat density
}

function threatLabel(ratio: number): string {
  if (ratio === 0)     return 'No data';
  if (ratio < 0.0001) return 'Clean';
  if (ratio < 0.25)   return 'Low risk';
  if (ratio < 0.5)    return 'Medium risk';
  if (ratio < 0.75)   return 'High risk';
  return 'Critical';
}

interface TooltipState {
  day: number; hour: number; cell: Cell;
  x: number; y: number;
}

export function HeatmapTab() {
  const [data, setData]       = useState<HeatmapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [mode, setMode]       = useState<'threat-ratio' | 'threat-abs' | 'spans'>('threat-ratio');

  const fetchHeatmap = useCallback(() => {
    fetch('/api/heatmap')
      .then(r => r.json())
      .then((d: HeatmapData) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchHeatmap();
    socket.on('graph-update', fetchHeatmap);
    return () => { socket.off('graph-update', fetchHeatmap); };
  }, [fetchHeatmap]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        Loading heatmap…
      </div>
    );
  }

  if (!data || data.totalSpans === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-500">
        <Flame className="w-8 h-8 text-slate-700" />
        <p className="text-sm font-medium">No span data yet</p>
        <p className="text-xs text-slate-600 max-w-xs text-center">
          The heatmap shows threat density by day and hour once spans start arriving.
        </p>
      </div>
    );
  }

  const cellColor = (dow: number, hour: number): string => {
    const cell = data.grid[dow][hour];
    if (mode === 'spans') {
      const ratio = cell.spans / data.maxSpans;
      return ratio === 0
        ? 'rgba(30,41,59,0.8)'
        : `rgba(59,130,246,${0.15 + ratio * 0.85})`;
    }
    if (mode === 'threat-abs') {
      const ratio = cell.threats / data.maxThreats;
      return threatColor(ratio);
    }
    // threat-ratio: threats / spans per cell
    const ratio = cell.spans > 0 ? cell.threats / cell.spans : 0;
    return threatColor(ratio);
  };

  return (
    <div className="flex-1 overflow-auto p-6 bg-slate-950">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="font-bold text-slate-200 flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" /> Threat Heatmap
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Activity density by day of week × hour — {data.totalSpans.toLocaleString()} spans total
          </p>
        </div>
        <div className="flex gap-1.5">
          {(['threat-ratio', 'threat-abs', 'spans'] as const).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                mode === m
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
              }`}
            >
              {m === 'threat-ratio' ? 'Threat %' : m === 'threat-abs' ? 'Threat Count' : 'Span Count'}
            </button>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mb-4">
        <span className="text-[10px] text-slate-600 uppercase font-bold">Less</span>
        {[0, 0.1, 0.35, 0.6, 0.85, 1].map(r => (
          <div
            key={r}
            className="w-5 h-5 rounded"
            style={{ background: mode === 'spans' ? `rgba(59,130,246,${0.15 + r * 0.85})` : threatColor(r) }}
          />
        ))}
        <span className="text-[10px] text-slate-600 uppercase font-bold">More</span>
      </div>

      {/* Grid */}
      <div className="overflow-x-auto">
        <div className="inline-block min-w-0">
          {/* Hour axis */}
          <div className="flex" style={{ marginLeft: 40 }}>
            {HOURS.map((h, i) => (
              <div
                key={i}
                className="text-[9px] text-slate-600 text-center flex-shrink-0"
                style={{ width: 28 }}
              >
                {i % 3 === 0 ? h : ''}
              </div>
            ))}
          </div>

          {/* Rows */}
          {DAYS.map((day, dow) => (
            <div key={dow} className="flex items-center mb-0.5">
              {/* Day label */}
              <div className="text-[10px] text-slate-500 font-medium w-10 shrink-0 text-right pr-2">
                {day}
              </div>
              {/* Cells */}
              {data.grid[dow].map((cell, hour) => {
                const ratio = mode === 'spans'
                  ? cell.spans / data.maxSpans
                  : mode === 'threat-abs'
                  ? cell.threats / data.maxThreats
                  : cell.spans > 0 ? cell.threats / cell.spans : 0;
                return (
                  <div
                    key={hour}
                    className="rounded-sm cursor-pointer transition-all hover:scale-110 hover:z-10 relative flex-shrink-0"
                    style={{ width: 26, height: 26, margin: 1, background: cellColor(dow, hour) }}
                    onMouseEnter={e => {
                      const rect = (e.target as HTMLElement).getBoundingClientRect();
                      setTooltip({ day: dow, hour, cell, x: rect.left, y: rect.top });
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
        {(() => {
          // Find busiest hour
          let busiestSpans = 0, busiestDow = 0, busiestHour = 0;
          let mostThreats = 0, threatDow = 0, threatHour = 0;
          for (let d = 0; d < 7; d++) {
            for (let h = 0; h < 24; h++) {
              const c = data.grid[d][h];
              if (c.spans > busiestSpans) { busiestSpans = c.spans; busiestDow = d; busiestHour = h; }
              if (c.threats > mostThreats) { mostThreats = c.threats; threatDow = d; threatHour = h; }
            }
          }
          const totalThreats = data.grid.flat().reduce((s, c) => s + c.threats, 0);
          const threatRatio  = data.totalSpans > 0 ? (totalThreats / data.totalSpans * 100).toFixed(1) : '0.0';
          return (
            <>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Busiest Hour</p>
                <p className="text-sm font-bold text-blue-400">{DAYS[busiestDow]} {HOURS[busiestHour]}</p>
                <p className="text-[10px] text-slate-600">{busiestSpans} spans</p>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Peak Threats</p>
                <p className="text-sm font-bold text-red-400">{DAYS[threatDow]} {HOURS[threatHour]}</p>
                <p className="text-[10px] text-slate-600">{mostThreats} threats</p>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Total Threats</p>
                <p className="text-sm font-bold text-orange-400">{totalThreats.toLocaleString()}</p>
                <p className="text-[10px] text-slate-600">across all time</p>
              </div>
              <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Threat Rate</p>
                <p className="text-sm font-bold text-yellow-400">{threatRatio}%</p>
                <p className="text-[10px] text-slate-600">of all spans</p>
              </div>
            </>
          );
        })()}
      </div>

      {/* Floating tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 bg-slate-800 border border-slate-600 rounded-lg p-2.5 shadow-xl pointer-events-none text-xs"
          style={{ left: tooltip.x + 30, top: tooltip.y - 10 }}
        >
          <p className="font-bold text-slate-200 mb-1">{DAYS[tooltip.day]} · {HOURS[tooltip.hour]}</p>
          <p className="text-slate-400">{tooltip.cell.spans} span{tooltip.cell.spans !== 1 ? 's' : ''}</p>
          <p className="text-red-400">{tooltip.cell.threats} threat{tooltip.cell.threats !== 1 ? 's' : ''}</p>
          {tooltip.cell.spans > 0 && (
            <p className="text-slate-500 mt-1">
              {(tooltip.cell.threats / tooltip.cell.spans * 100).toFixed(1)}% threat rate ·{' '}
              {threatLabel(tooltip.cell.threats / tooltip.cell.spans)}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
