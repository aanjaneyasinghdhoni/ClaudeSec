import { useState, useEffect, useMemo } from 'react';
import { Clock } from 'lucide-react';
import type { Severity } from './shared/types';
import type { Workflow } from './dashboardTypes';
import { HARNESS_COLORS } from './dashboardTypes';
import { toMs, formatSpanName } from './lib/format';

// ---------------------------------------------------------------------------
// Timeline component
// ---------------------------------------------------------------------------

export function Timeline({
  workflows, onSelect, selectedId,
}: {
  workflows: Workflow[];
  onSelect: (id: string) => void;
  selectedId?: string;
}) {
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  const timed = useMemo(() =>
    workflows
      .filter(wf => wf.startNano !== '0' && wf.endNano !== '0')
      .sort((a, b) => {
        try {
          const diff = BigInt(a.startNano) - BigInt(b.startNano);
          return diff > 0n ? 1 : diff < 0n ? -1 : 0;
        } catch { return 0; }
      }),
    [workflows],
  );

  // Reset page when workflow count changes significantly
  useEffect(() => { setPage(1); }, [timed.length > 0]);

  if (timed.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-500">
        <Clock className="w-8 h-8 text-slate-700" />
        <p className="text-sm font-medium">No timing data yet</p>
        <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
          Spans need <code className="font-mono bg-slate-800 px-1 rounded">startTimeUnixNano</code> /{' '}
          <code className="font-mono bg-slate-800 px-1 rounded">endTimeUnixNano</code> to appear here.
        </p>
      </div>
    );
  }

  const totalPages = Math.ceil(timed.length / PAGE_SIZE);
  const pagedTimed = timed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const starts = pagedTimed.map(wf => toMs(wf.startNano));
  const ends   = pagedTimed.map(wf => toMs(wf.endNano));
  const minT   = Math.min(...starts);
  const maxT   = Math.max(...ends);
  const range  = maxT - minT || 1;

  const ROW_H   = 38;
  const LABEL_W = 152;
  const AXIS_H  = 28;
  const CHART_W = 920;
  const AVAIL_W = CHART_W - LABEL_W - 20;
  const SVG_H   = pagedTimed.length * ROW_H + AXIS_H + 8;

  const sevColor = (sev: Severity) =>
    sev === 'high' ? '#ef4444' : sev === 'medium' ? '#f97316' : sev === 'low' ? '#eab308' : '#22c55e';

  return (
    <div className="flex-1 overflow-auto p-5" style={{ background: 'var(--cs-bg-primary)' }}>
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-bold uppercase tracking-wider font-mono flex items-center gap-1.5" style={{ color: 'var(--cs-text-faint)' }}>
          <Clock className="w-3 h-3" />
          Timeline — {timed.length} spans · {range}ms window
        </p>
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-2 py-1 text-[11px] font-medium rounded transition-all disabled:opacity-30"
              style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
            >Prev</button>
            <span className="text-[11px] font-mono" style={{ color: 'var(--cs-text-faint)' }}>
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2 py-1 text-[11px] font-medium rounded transition-all disabled:opacity-30"
              style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
            >Next</button>
          </div>
        )}
      </div>
      <div className="rounded-xl overflow-hidden p-4" style={{ border: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}>
      <svg viewBox={`0 0 ${CHART_W} ${SVG_H}`} className="w-full" style={{ minWidth: 420 }}>
        {/* Grid lines + axis labels */}
        {[0, 0.25, 0.5, 0.75, 1].map(frac => (
          <g key={frac}>
            <line
              x1={LABEL_W + frac * AVAIL_W} y1={0}
              x2={LABEL_W + frac * AVAIL_W} y2={SVG_H - AXIS_H}
              stroke="var(--cs-svg-grid)" strokeWidth="1"
            />
            <text
              x={LABEL_W + frac * AVAIL_W} y={SVG_H - 8}
              fill="var(--cs-svg-text)" fontSize="9" fontFamily="monospace" textAnchor="middle"
            >
              {Math.round(frac * range)}ms
            </text>
          </g>
        ))}
        <line
          x1={LABEL_W} y1={SVG_H - AXIS_H}
          x2={CHART_W - 8} y2={SVG_H - AXIS_H}
          stroke="var(--cs-svg-axis)" strokeWidth="1"
        />

        {pagedTimed.map((wf, i) => {
          const startMs = toMs(wf.startNano) - minT;
          const endMs   = toMs(wf.endNano)   - minT;
          const durMs   = endMs - startMs;
          const x = LABEL_W + (startMs / range) * AVAIL_W;
          const w = Math.max(3, (durMs / range) * AVAIL_W);
          const y = i * ROW_H + 4;
          const isSelected = wf.id === selectedId;
          const col = sevColor(wf.severity);

          return (
            <g key={wf.id} onClick={() => onSelect(wf.id)} style={{ cursor: 'pointer' }}>
              {isSelected && (
                <rect x={0} y={y} width={CHART_W} height={ROW_H - 2} fill="var(--cs-svg-selected)" rx={2} />
              )}
              {/* Harness dot */}
              <circle cx={10} cy={y + ROW_H / 2 - 2} r={3.5}
                fill={HARNESS_COLORS[wf.harness] ?? '#64748b'} />
              {/* Label */}
              <text
                x={LABEL_W - 6} y={y + ROW_H / 2 + 3}
                fill={isSelected ? 'var(--cs-svg-label)' : 'var(--cs-svg-text)'}
                fontSize="10" fontFamily="monospace" textAnchor="end"
              >
                {(() => { const n = formatSpanName(wf.label); return n.length > 17 ? n.slice(0, 17) + '…' : n; })()}
              </text>
              {/* Track background */}
              <rect x={LABEL_W} y={y + 6} width={AVAIL_W} height={ROW_H - 12}
                fill="var(--cs-svg-track)" rx={2} />
              {/* Bar */}
              <rect x={x} y={y + 6} width={w} height={ROW_H - 12}
                fill={col} fillOpacity={isSelected ? 1 : 0.75} rx={2} />
              {/* Duration inside bar */}
              {w > 44 && (
                <text x={x + w / 2} y={y + ROW_H / 2 + 3}
                  fill="var(--cs-svg-track)" fontSize="9" fontFamily="monospace"
                  textAnchor="middle" fontWeight="bold"
                >
                  {durMs}ms
                </text>
              )}
            </g>
          );
        })}
      </svg>
      </div>
    </div>
  );
}
