/**
 * HeatmapTab — activity density by day and hour.
 *
 * GET /api/heatmap → { grid[7][24]: {spans, threats}, maxThreats, maxSpans }
 *
 * Two of the three metrics genuinely encode severity (a cell's threat ratio
 * and its raw threat count are both "how much risk happened here"), so those
 * two reuse the actual severity ramp rather than an invented traffic-light
 * gradient — the same five tokens, words and meanings as everywhere else in
 * the app. The third metric, span volume, is activity rather than risk, so it
 * stays on the accent (chrome) scale instead of borrowing severity's colour.
 */
import React, { useEffect, useState, useCallback } from 'react';
import { Flame } from 'lucide-react';
import { socket } from './socket';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import {
  Toolbar, ToolButton, ToolbarTitle,
  SEVERITY_META, SEVERITY_ORDER,
  EmptyState, ErrorState,
} from './components/data';
import type { Severity } from './shared/types';

interface Cell { spans: number; threats: number }
interface HeatmapData {
  grid: Cell[][];       // [dayOfWeek 0-6][hour 0-23]
  maxThreats: number;
  maxSpans: number;
  totalSpans: number;
  days?: string[];
}

const DAYS  = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HOURS = Array.from({ length: 24 }, (_, i) =>
  i === 0 ? '12a' : i < 12 ? `${i}a` : i === 12 ? '12p' : `${i - 12}p`,
);

type Mode = 'threat-ratio' | 'threat-abs' | 'spans';

// The severity bucket a threat ratio falls into. Reuses the same five-level
// ramp the rest of the app triages with, rather than a bespoke gradient — a
// cell at "high" density means the same thing here as a High alert anywhere
// else.
const SEV_BUCKETS: { max: number; level: Severity }[] = [
  { max: 0.0001, level: 'none'     },
  { max: 0.25,   level: 'low'      },
  { max: 0.5,    level: 'medium'   },
  { max: 0.75,   level: 'high'     },
  { max: Infinity, level: 'critical' },
];

function severityBucket(ratio: number): Severity {
  return (SEV_BUCKETS.find(b => ratio < b.max) ?? SEV_BUCKETS[SEV_BUCKETS.length - 1]).level;
}

// A cell's fill for a severity-encoded mode: the bucket's mark colour, with
// alpha rising inside the bucket so two "high" cells can still be told apart.
function threatCellStyle(ratio: number): string {
  if (ratio <= 0) return 'var(--cs-bg-raised)';
  const level = severityBucket(ratio);
  const alpha = 0.32 + Math.min(1, ratio) * 0.55;
  return `rgba(var(--cs-sev-${level}-rgb), ${alpha.toFixed(2)})`;
}

// A cell's fill for the span-volume mode: not a risk signal, so it stays on
// the accent scale rather than borrowing severity's colour language.
function spanCellStyle(ratio: number): string {
  if (ratio <= 0) return 'var(--cs-bg-raised)';
  return `rgba(var(--cs-accent-rgb),${(0.18 + ratio * 0.75).toFixed(2)})`;
}

interface TooltipState {
  day: number; hour: number; cell: Cell;
  x: number; y: number;
}

export function HeatmapTab() {
  const [data, setData]         = useState<HeatmapData | null>(null);
  const [loading, setLoading]   = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [tooltip, setTooltip]   = useState<TooltipState | null>(null);
  const [mode, setMode]         = useState<Mode>('threat-ratio');
  const [view, setView]         = useState<'weekday' | 'calendar'>('weekday');

  const fetchHeatmap = useCallback(() => {
    const url = view === 'calendar' ? '/api/heatmap?mode=calendar' : '/api/heatmap';
    fetch(url)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: HeatmapData) => {
        const flat = (d.grid ?? []).flat();
        const normalized: HeatmapData = {
          ...d,
          grid: d.grid ?? [],
          maxSpans: d.maxSpans ?? Math.max(1, ...flat.map(c => c.spans)),
          maxThreats: d.maxThreats ?? Math.max(1, ...flat.map(c => c.threats)),
          totalSpans: d.totalSpans ?? flat.reduce((s, c) => s + c.spans, 0),
        };
        setData(normalized);
        setLoadError(null);
      })
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, [view]);

  // Recomputing the heatmap scans every span. Debounce the socket-driven
  // refresh so a burst of `graph-update` events collapses into one refetch;
  // the initial load below stays immediate so first paint isn't delayed.
  const debouncedFetch = useDebouncedCallback(fetchHeatmap);

  useEffect(() => {
    fetchHeatmap();
    socket.on('graph-update', debouncedFetch);
    return () => { socket.off('graph-update', debouncedFetch); };
  }, [fetchHeatmap, debouncedFetch]);

  const rowLabels  = data?.days ?? DAYS;
  const labelWidth = view === 'calendar' ? 76 : 40;
  const hasData     = !!data && data.totalSpans > 0;

  const ratioFor = (dow: number, hour: number): number => {
    const cell = data!.grid[dow][hour];
    if (mode === 'spans')       return cell.spans / Math.max(1, data!.maxSpans);
    if (mode === 'threat-abs')  return cell.threats / Math.max(1, data!.maxThreats);
    return cell.spans > 0 ? cell.threats / cell.spans : 0;
  };

  const cellStyle = (ratio: number) => mode === 'spans' ? spanCellStyle(ratio) : threatCellStyle(ratio);

  // Busiest hour / peak threats / totals for the summary row below the grid.
  const stats = data ? (() => {
    let busiestSpans = 0, busiestDow = 0, busiestHour = 0;
    let mostThreats = 0, threatDow = 0, threatHour = 0;
    for (let d = 0; d < data.grid.length; d++) {
      for (let h = 0; h < 24; h++) {
        const c = data.grid[d][h];
        if (c.spans > busiestSpans) { busiestSpans = c.spans; busiestDow = d; busiestHour = h; }
        if (c.threats > mostThreats) { mostThreats = c.threats; threatDow = d; threatHour = h; }
      }
    }
    const totalThreats = data.grid.flat().reduce((s, c) => s + c.threats, 0);
    const threatRatio  = data.totalSpans > 0 ? (totalThreats / data.totalSpans * 100).toFixed(1) : '0.0';
    return { busiestSpans, busiestDow, busiestHour, mostThreats, threatDow, threatHour, totalThreats, threatRatio };
  })() : null;

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-auto" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <Toolbar>
        <ToolbarTitle
          icon={<Flame className="w-3.5 h-3.5" />}
          count={hasData ? `${data!.totalSpans.toLocaleString()} spans` : undefined}
        >
          Activity heatmap
        </ToolbarTitle>

        <div className="flex items-center gap-0.5" role="group" aria-label="Time range">
          {(['weekday', 'calendar'] as const).map(v => (
            <ToolButton
              key={v}
              active={view === v}
              aria-pressed={view === v}
              onClick={() => setView(v)}
              title={v === 'weekday' ? 'Group by day of week' : 'The last 14 individual days'}
            >
              {v === 'weekday' ? 'Weekday' : 'Last 14 days'}
            </ToolButton>
          ))}
        </div>

        <div className="flex items-center gap-0.5 ml-auto" role="group" aria-label="Metric">
          {([
            { value: 'threat-ratio', label: 'Threat %' },
            { value: 'threat-abs',   label: 'Threat count' },
            { value: 'spans',        label: 'Span count' },
          ] as { value: Mode; label: string }[]).map(m => (
            <ToolButton
              key={m.value}
              active={mode === m.value}
              aria-pressed={mode === m.value}
              onClick={() => setMode(m.value)}
            >
              {m.label}
            </ToolButton>
          ))}
        </div>
      </Toolbar>

      {loadError && !data ? (
        <ErrorState
          description={`The heatmap did not respond (${loadError}).`}
          onRetry={() => { setLoading(true); fetchHeatmap(); }}
        />
      ) : !loading && !hasData ? (
        <EmptyState
          icon={<Flame className="w-6 h-6" aria-hidden="true" />}
          title="No activity yet"
          description="This grid fills in by day and hour once spans start arriving — nothing has been recorded yet."
        />
      ) : (
        <div className="flex-1 flex flex-col gap-4 p-4 min-h-0">

          {/* Legend. Severity-encoded modes pair every swatch with the same
              glyph and word used everywhere else, so the scale never depends
              on colour alone. */}
          <div className="flex items-center gap-3 flex-wrap">
            {mode === 'spans' ? (
              <>
                <span className="cs-eyebrow">Less</span>
                {[0, 0.2, 0.4, 0.6, 0.8, 1].map(r => (
                  <div key={r} className="w-5 h-5 rounded" style={{ background: spanCellStyle(r) }} aria-hidden="true" />
                ))}
                <span className="cs-eyebrow">More</span>
              </>
            ) : (
              SEVERITY_ORDER.map(level => {
                const meta = SEVERITY_META[level];
                return (
                  <span
                    key={level}
                    className="inline-flex items-center gap-1.5"
                    title={`${meta.label} — ${meta.meaning}`}
                  >
                    <span
                      className="w-3.5 h-3.5 rounded shrink-0"
                      style={{ background: `rgba(var(--cs-sev-${level}-rgb),0.75)` }}
                      aria-hidden="true"
                    />
                    <meta.Icon className="w-3 h-3" style={{ color: `var(--cs-sev-${level})` }} aria-hidden="true" />
                    <span style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{meta.label}</span>
                  </span>
                );
              })
            )}
          </div>

          {/* ── Grid ───────────────────────────────────────────────────────── */}
          <div className="rounded-lg p-4 overflow-x-auto" style={{ background: 'var(--cs-bg-surface)' }}>
            <div className="inline-block min-w-0">
              <div className="flex" style={{ marginLeft: labelWidth }}>
                {HOURS.map((h, i) => (
                  <div
                    key={i}
                    className="text-center flex-shrink-0"
                    style={{ width: 28, fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}
                  >
                    {i % 3 === 0 ? h : ''}
                  </div>
                ))}
              </div>

              {data && rowLabels.map((label, dow) => (
                <div key={dow} className="flex items-center mb-0.5">
                  <div
                    className="cs-mono shrink-0 text-right pr-2"
                    style={{ width: labelWidth, fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)', fontWeight: 'var(--cs-weight-medium)' }}
                  >
                    {label}
                  </div>
                  {data.grid[dow].map((cell, hour) => {
                    const ratio = ratioFor(dow, hour);
                    const level = mode === 'spans' ? undefined : severityBucket(ratio);
                    return (
                      <button
                        type="button"
                        key={hour}
                        className="rounded-sm transition-transform hover:scale-110 hover:z-10 relative flex-shrink-0"
                        style={{
                          width: 26, height: 26, margin: 1,
                          background: cellStyle(ratio),
                          border: cell.spans === 0 ? '1px solid var(--cs-rule)' : 'none',
                        }}
                        aria-label={`${label} ${HOURS[hour]}: ${cell.spans} spans, ${cell.threats} threats${level ? `, ${SEVERITY_META[level].label.toLowerCase()} density` : ''}`}
                        onMouseEnter={e => {
                          const rect = e.currentTarget.getBoundingClientRect();
                          setTooltip({ day: dow, hour, cell, x: rect.left, y: rect.top });
                        }}
                        onFocus={e => {
                          const rect = e.currentTarget.getBoundingClientRect();
                          setTooltip({ day: dow, hour, cell, x: rect.left, y: rect.top });
                        }}
                        onMouseLeave={() => setTooltip(null)}
                        onBlur={() => setTooltip(null)}
                      />
                    );
                  })}
                </div>
              ))}
            </div>
          </div>

          {/* ── Summary tiles ──────────────────────────────────────────────── */}
          {stats && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg" style={{ background: 'var(--cs-bg-surface)' }}>
                <p className="cs-eyebrow mb-1">Busiest hour</p>
                <p style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
                  {rowLabels[stats.busiestDow]} {HOURS[stats.busiestHour]}
                </p>
                <p className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{stats.busiestSpans} spans</p>
              </div>
              <div className="p-3 rounded-lg" style={{ background: 'var(--cs-bg-surface)' }}>
                <p className="cs-eyebrow mb-1">Peak threats</p>
                <p style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-sev-critical-fg)' }}>
                  {rowLabels[stats.threatDow]} {HOURS[stats.threatHour]}
                </p>
                <p className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{stats.mostThreats} threats</p>
              </div>
              <div className="p-3 rounded-lg" style={{ background: 'var(--cs-bg-surface)' }}>
                <p className="cs-eyebrow mb-1">Total threats</p>
                <p className="cs-mono" style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
                  {stats.totalThreats.toLocaleString()}
                </p>
                <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>across all time</p>
              </div>
              <div className="p-3 rounded-lg" style={{ background: 'var(--cs-bg-surface)' }}>
                <p className="cs-eyebrow mb-1">Threat rate</p>
                <p className="cs-mono" style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
                  {stats.threatRatio}%
                </p>
                <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>of all spans</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Floating tooltip — a real overlay, so it is the one place in this tab
          allowed a hard edge. */}
      {tooltip && (
        <div
          className="fixed z-50 rounded-lg p-2.5 pointer-events-none"
          style={{
            left: tooltip.x + 30,
            top: tooltip.y - 10,
            background: 'var(--cs-bg-overlay)',
            border: '1px solid var(--cs-rule-strong)',
            boxShadow: 'var(--cs-shadow-overlay)',
            fontSize: 'var(--cs-text-xs)',
          }}
        >
          <p style={{ fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)', marginBottom: 4 }}>
            {rowLabels[tooltip.day]} · {HOURS[tooltip.hour]}
          </p>
          <p style={{ color: 'var(--cs-text-muted)' }}>{tooltip.cell.spans} span{tooltip.cell.spans !== 1 ? 's' : ''}</p>
          <p style={{ color: 'var(--cs-sev-critical-fg)' }}>{tooltip.cell.threats} threat{tooltip.cell.threats !== 1 ? 's' : ''}</p>
          {tooltip.cell.spans > 0 && (() => {
            const ratio = tooltip.cell.threats / tooltip.cell.spans;
            const level = severityBucket(ratio);
            return (
              <p style={{ color: 'var(--cs-text-faint)', marginTop: 4 }}>
                {(ratio * 100).toFixed(1)}% threat rate · {SEVERITY_META[level].label}
              </p>
            );
          })()}
        </div>
      )}
    </div>
  );
}
