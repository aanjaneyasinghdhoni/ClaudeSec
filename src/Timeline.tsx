import { useState, useEffect, useMemo } from 'react';
import { Clock } from 'lucide-react';
import type { Workflow } from './dashboardTypes';
import { HARNESS_COLORS } from './dashboardTypes';
import { toMs, formatSpanName } from './lib/format';
import {
  Toolbar, ToolbarTitle, ToolButton,
  SEVERITY_META, normalizeSeverity, severityMark,
  EmptyState,
} from './components/data';

// ---------------------------------------------------------------------------
// Timeline component
//
// This is the one surface in the app that draws itself rather than sitting on
// <DataTable>, because a Gantt-style chart needs pixel coordinates a CSS grid
// can't give it. That used to mean it also invented its own density and its
// own colour language — foreign next to the alert log and the session list.
// It now borrows both: row height comes from the same `--cs-row-h` token the
// shell uses, and a span's severity is drawn with the same mark + glyph pair
// as everywhere else, never colour alone.
// ---------------------------------------------------------------------------

/**
 * A span whose source never observed a real end time is stamped with a fixed
 * 1ms placeholder duration on ingest (see the transcript watcher's 'end'
 * event, which only arrives for tool calls the watcher actually saw finish).
 * Drawing that placeholder as a proportional bar would show a duration that
 * was never measured. A genuine span landing on exactly 1.000000ms to the
 * nanosecond is not something wall-clock timing produces in practice, so
 * treating that exact value as "unmeasured" is a safe, cheap tell — no flag
 * needs to travel from the server for this to work.
 */
const FABRICATED_DURATION_NS = 1_000_000n;

function isFabricatedDuration(startNano: string, endNano: string): boolean {
  try { return BigInt(endNano) - BigInt(startNano) === FABRICATED_DURATION_NS; }
  catch { return false; }
}

/**
 * Row height, read from the shell's density token instead of a number picked
 * for this component alone. `--cs-row-h` is root-level and breakpoint-driven
 * (see index.css), not per-surface like <DataTable>'s density prop, so it is
 * read from computed style rather than passed down — the same value the
 * session list uses, kept in sync with a resize listener since the token
 * changes at CSS breakpoints rather than through React state.
 */
function useRowHeightPx(fallback = 32): number {
  const [px, setPx] = useState(fallback);
  useEffect(() => {
    const read = () => {
      const raw = getComputedStyle(document.documentElement).getPropertyValue('--cs-row-h');
      const n = parseFloat(raw);
      if (Number.isFinite(n) && n > 0) setPx(n);
    };
    read();
    window.addEventListener('resize', read);
    return () => window.removeEventListener('resize', read);
  }, []);
  return px;
}

export function Timeline({
  workflows, onSelect, selectedId,
}: {
  workflows: Workflow[];
  onSelect: (id: string) => void;
  selectedId?: string;
}) {
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;
  const ROW_H = useRowHeightPx();

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

  const totalPages = Math.max(1, Math.ceil(timed.length / PAGE_SIZE));

  // Narrowing a filter can leave us on a page that no longer exists. Clamp during
  // render as well as in state: an out-of-range page slices to an empty array, and
  // `Math.min(...[])` is `Infinity`, which poisons every coordinate in the chart
  // and paints a blank SVG with a "-Infinityms" axis.
  const safePage = Math.min(page, totalPages);
  useEffect(() => { setPage(p => Math.min(p, totalPages)); }, [totalPages]);

  // The axis window is derived once from the FULL filtered set, not from
  // whatever happens to be on the current page. Recomputing min/max per page
  // used to mean the "0 / 50 / 100ms" axis meant a different slice of
  // wall-clock time on every page — a scale that changes what it measures
  // isn't a scale. Bar positions on every page now read against the same
  // window, so the axis is one stable ruler for the whole span set.
  const { minT, range } = useMemo(() => {
    if (timed.length === 0) return { minT: 0, range: 1 };
    const starts = timed.map(wf => toMs(wf.startNano));
    const ends   = timed.map(wf => toMs(wf.endNano));
    const lo = Math.min(...starts);
    const hi = Math.max(...ends);
    return { minT: lo, range: (hi - lo) || 1 };
  }, [timed]);

  if (timed.length === 0) {
    return (
      <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>
        <EmptyState
          icon={<Clock className="w-6 h-6" aria-hidden="true" />}
          title="No timing data yet"
          description="Spans need startTimeUnixNano / endTimeUnixNano to appear here."
        />
      </div>
    );
  }

  const pagedTimed = timed.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const LABEL_W = 168;
  const AXIS_H  = 28;
  const CHART_W = 920;
  const AVAIL_W = CHART_W - LABEL_W - 20;
  const SVG_H   = pagedTimed.length * ROW_H + AXIS_H + 8;
  const BAR_H   = Math.max(6, ROW_H - 12);

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>
      <Toolbar>
        <ToolbarTitle
          icon={<Clock className="w-3.5 h-3.5" aria-hidden="true" />}
          count={`${timed.length} spans · ${range.toLocaleString()}ms window`}
          countTitle="Span count and the wall-clock window they span — held stable across pages"
        >
          Timeline
        </ToolbarTitle>
        {totalPages > 1 && (
          <div className="flex items-center gap-1.5 ml-auto">
            <ToolButton onClick={() => setPage(Math.max(1, safePage - 1))} disabled={safePage <= 1}>
              Prev
            </ToolButton>
            <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
              {safePage} / {totalPages}
            </span>
            <ToolButton onClick={() => setPage(Math.min(totalPages, safePage + 1))} disabled={safePage >= totalPages}>
              Next
            </ToolButton>
          </div>
        )}
      </Toolbar>

      {/* This is the one panel below that scrolls horizontally on a narrow
          viewport — it stays inside this container, never the page body. */}
      <div className="flex-1 overflow-auto p-4 min-h-0">
        <div className="rounded-lg overflow-hidden p-3" style={{ background: 'var(--cs-bg-surface)' }}>
          <svg
            viewBox={`0 0 ${CHART_W} ${SVG_H}`}
            className="w-full"
            style={{ minWidth: 420 }}
            role="img"
            aria-label={`Timeline of ${timed.length} spans over a ${range}ms window`}
          >
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
                  fill="var(--cs-svg-text)" fontSize="9" fontFamily="var(--cs-font-mono)" textAnchor="middle"
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
              const durMs   = Math.max(0, endMs - startMs);
              const fabricated = isFabricatedDuration(wf.startNano, wf.endNano);
              const x = LABEL_W + (startMs / range) * AVAIL_W;
              const w = Math.max(3, (durMs / range) * AVAIL_W);
              const y = i * ROW_H + 4;
              const isSelected = wf.id === selectedId;
              const sev = normalizeSeverity(wf.severity);
              const col = severityMark(sev);
              // Colour never travels alone — the bar's severity hue is paired
              // with its own glyph, same vocabulary as every list in the app.
              const SevIcon = SEVERITY_META[sev].Icon;

              return (
                <g key={wf.id} onClick={() => onSelect(wf.id)} style={{ cursor: 'pointer' }}>
                  {isSelected && (
                    <rect x={0} y={y} width={CHART_W} height={ROW_H - 2} fill="var(--cs-svg-selected)" rx={2} />
                  )}
                  {/* Severity glyph */}
                  <SevIcon
                    x={4} y={y + ROW_H / 2 - 5} width={10} height={10}
                    style={{ color: col }} aria-hidden="true"
                  />
                  {/* Harness dot — identity, not risk, so it stays a fixed hue */}
                  <circle cx={22} cy={y + ROW_H / 2 - 2} r={3.5}
                    fill={HARNESS_COLORS[wf.harness] ?? '#64748b'} />
                  {/* Label */}
                  <text
                    x={LABEL_W - 6} y={y + ROW_H / 2 + 3}
                    fill={isSelected ? 'var(--cs-svg-label)' : 'var(--cs-svg-text)'}
                    fontSize="10" fontFamily="var(--cs-font-mono)" textAnchor="end"
                  >
                    {(() => { const n = formatSpanName(wf.label); return n.length > 17 ? n.slice(0, 17) + '…' : n; })()}
                  </text>
                  {/* Track background */}
                  <rect x={LABEL_W} y={y + 6} width={AVAIL_W} height={BAR_H}
                    fill="var(--cs-svg-track)" rx={2} />
                  {fabricated ? (
                    // No real end time was ever observed for this span. A
                    // proportional bar here would draw a duration that was
                    // never measured, so this renders as an unmeasured tick —
                    // a dashed outline, no fill, no "Xms" — rather than a
                    // fictional 1ms bar.
                    <rect x={x} y={y + 6} width={10} height={BAR_H}
                      fill="none" stroke={col} strokeWidth={1.25} strokeDasharray="2,2" rx={2}
                    >
                      <title>Duration unknown — this span&apos;s source never reported a real end time</title>
                    </rect>
                  ) : (
                    <>
                      <rect x={x} y={y + 6} width={w} height={BAR_H}
                        fill={col} fillOpacity={isSelected ? 1 : 0.75} rx={2} />
                      {/* Duration inside bar */}
                      {w > 44 && (
                        <text x={x + w / 2} y={y + ROW_H / 2 + 3}
                          fill="var(--cs-svg-track)" fontSize="9" fontFamily="var(--cs-font-mono)"
                          textAnchor="middle" fontWeight="bold"
                        >
                          {durMs}ms
                        </text>
                      )}
                    </>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      </div>
    </div>
  );
}
