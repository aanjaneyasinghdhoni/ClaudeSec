/**
 * ComparePanel — side-by-side diff of two sessions, in a slide-in drawer.
 *
 * Keyboard behaviour (focus trap, Escape-to-close, focus restore) is the
 * shared `useDrawerA11y` hook from `AlertDetailDrawer.tsx` — that file's own
 * doc comment names this panel as one of its intended callers, so this reuses
 * it rather than re-implementing a second focus trap.
 *
 * The panel is inherently two numbers per row (session A, session B), and the
 * thing an operator actually came here to see is the *difference* between
 * them — so the raw values are kept small and muted, and the delta is the
 * loud element: a coloured, directional pill with its own icon, never colour
 * alone. `format` flows from each row into its delta so a compact metric
 * (token counts, which cross a billion on long-lived installs) doesn't fall
 * back to an unformatted diff — see `formatTokens` in `src/lib/format`.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { X, Download, ArrowUp, ArrowDown, Minus, GitCompare } from 'lucide-react';
import { motion } from 'motion/react';
import { formatTokens } from './lib/format';
import { useDrawerA11y } from './AlertDetailDrawer';
import type { Severity } from './shared/types';
import {
  SEVERITY_META, severityMark,
  EmptyState, ErrorState, TableSkeleton,
  Toolbar, ToolbarTitle, ToolButton,
} from './components/data';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CompareStat {
  traceId: string;
  name: string;
  createdAt: string;
  spanCount: number;
  alertCount: number;
  threatHigh: number;
  threatMedium: number;
  threatLow: number;
  tokensIn: number;
  tokensOut: number;
  avgDurationMs: number;
  topTools: { name: string; count: number }[];
  topRules: { name: string; count: number }[];
  harnesses?: string | null;
}

interface CompareResponse {
  a: CompareStat;
  b: CompareStat;
}

interface Props {
  aId: string;
  bId: string;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Agent-harness identity dot, same fixed hues as AlertsTab / AlertDetailDrawer
// — identity, not risk, so it deliberately sits outside the severity ramp.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

// Session A / B are also an identity, not a risk — which column a number
// belongs to — so the same "small dot in a fixed hue" exception applies. Kept
// to exactly two constants so the key at the bottom of Top Tools is the only
// place that needs to explain them.
const SESSION_A_COLOR = '#3b82f6';
const SESSION_B_COLOR = '#8b5cf6';

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Delta badge — the thing the eye is meant to land on
// ---------------------------------------------------------------------------

interface DeltaBadgeProps {
  aVal: number;
  bVal: number;
  lowerIsBetter?: boolean;
  /** Must match the row's own `format`, or a compact value (e.g. token
   *  counts, "17.94B") would diff against an unformatted raw number. */
  format?: (n: number) => string;
}

export interface DeltaResult {
  diff: number;
  /** `null` when the two values are equal — there is no direction to a zero diff. */
  direction: 'up' | 'down' | null;
  /** Whether this direction is the desirable one, given `lowerIsBetter`. */
  isGood: boolean;
  /** Signed, formatted label — `format` applied if given, else `toLocaleString()`. */
  label: string;
  /** Signed, always-exact label — what a tooltip shows when `label` is compact/lossy. */
  exact: string;
}

/**
 * Pure delta computation shared by `<DeltaBadge>` and its unit test, so the
 * "which direction is good" and "what does the number read as" rules live in
 * exactly one place. See tests/comparePanelDeltaTest.ts.
 */
export function computeDelta(
  aVal: number,
  bVal: number,
  { lowerIsBetter = false, format }: { lowerIsBetter?: boolean; format?: (n: number) => string } = {},
): DeltaResult {
  const diff = bVal - aVal;
  const fmt = format ?? ((n: number) => n.toLocaleString());
  if (diff === 0) {
    return { diff, direction: null, isGood: true, label: 'same', exact: 'same' };
  }
  const positive = diff > 0;
  // Lower is better (alerts, threats): B > A is the bad direction. Higher is
  // better (everything else): B > A is the good direction.
  const isGood = lowerIsBetter ? !positive : positive;
  const sign = positive ? '+' : '−';
  return {
    diff,
    direction: positive ? 'up' : 'down',
    isGood,
    label: `${sign}${fmt(Math.abs(diff))}`,
    exact: `${sign}${Math.abs(diff).toLocaleString()}`,
  };
}

function DeltaBadge({ aVal, bVal, lowerIsBetter = false, format }: DeltaBadgeProps): React.ReactElement {
  const delta = computeDelta(aVal, bVal, { lowerIsBetter, format });
  if (delta.direction === null) {
    return (
      <span
        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded"
        style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
      >
        <Minus className="w-2.5 h-2.5 shrink-0" aria-hidden="true" /> same
      </span>
    );
  }
  const Icon = delta.direction === 'up' ? ArrowUp : ArrowDown;
  return (
    <span
      className="cs-mono inline-flex items-center gap-1 px-1.5 py-0.5 rounded"
      style={{
        background: delta.isGood ? 'var(--cs-accent-soft)'     : 'var(--cs-sev-critical-bg)',
        color:      delta.isGood ? 'var(--cs-accent)'           : 'var(--cs-sev-critical-fg)',
        fontSize: 'var(--cs-text-xs)',
        fontWeight: 'var(--cs-weight-semibold)',
      }}
      title={format ? delta.exact : undefined}
    >
      <Icon className="w-2.5 h-2.5 shrink-0" aria-hidden="true" />
      {delta.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Metric row
// ---------------------------------------------------------------------------

interface MetricRowProps {
  label: string;
  aVal: number;
  bVal: number;
  lowerIsBetter?: boolean;
  format?: (n: number) => string;
  /** Exact value shown in a tooltip when `format` is lossy (e.g. compact tokens). */
  titleFormat?: (n: number) => string;
  /** Ties the row to the app's severity vocabulary — same icon+colour a
   *  threat count wears everywhere else, so this reads as the same signal. */
  severityLevel?: Severity;
}

function MetricRow({ label, aVal, bVal, lowerIsBetter = false, format, titleFormat, severityLevel }: MetricRowProps): React.ReactElement {
  const fmt = format ?? ((n: number) => n.toLocaleString());
  // The raw values step back to a muted tone once they differ — the delta
  // pill is what should register first. Equal values stay full-strength: the
  // absence of a story there is itself worth reading directly off the row.
  const changed = aVal !== bVal;
  const SevIcon = severityLevel ? SEVERITY_META[severityLevel].Icon : null;
  return (
    <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
      <td className="px-3 py-2 whitespace-nowrap" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
        <span className="inline-flex items-center gap-1">
          {SevIcon && <SevIcon className="w-2.5 h-2.5 shrink-0" style={{ color: severityMark(severityLevel!) }} aria-hidden="true" />}
          {label}
        </span>
      </td>
      <td
        className="cs-mono px-3 py-2 text-right"
        title={titleFormat?.(aVal)}
        style={{ fontSize: 'var(--cs-text-xs)', color: changed ? 'var(--cs-text-muted)' : 'var(--cs-text-body)' }}
      >
        {fmt(aVal)}
      </td>
      <td
        className="cs-mono px-3 py-2 text-right"
        title={titleFormat?.(bVal)}
        style={{ fontSize: 'var(--cs-text-xs)', color: changed ? 'var(--cs-text-muted)' : 'var(--cs-text-body)' }}
      >
        {fmt(bVal)}
      </td>
      <td className="px-3 py-2 text-right">
        <DeltaBadge aVal={aVal} bVal={bVal} lowerIsBetter={lowerIsBetter} format={format} />
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Harness dots
// ---------------------------------------------------------------------------

interface HarnessDotsProps {
  harnesses: string;
}

function HarnessDots({ harnesses }: HarnessDotsProps): React.ReactElement {
  const list = harnesses.split(',').map(h => h.trim()).filter(Boolean);
  return (
    <span className="flex items-center gap-1 flex-wrap">
      {list.map((h, i) => (
        <span
          key={i}
          title={h}
          className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
          style={{ background: HARNESS_COLORS[h] ?? HARNESS_COLORS['unknown'] }}
        />
      ))}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ComparePanel({ aId, bId, onClose }: Props): React.ReactElement {
  const [data, setData]       = useState<CompareResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const panelRef = useRef<HTMLDivElement>(null);
  useDrawerA11y(true, onClose, panelRef);

  const fetchCompare = useCallback(() => {
    setLoading(true);
    setError('');
    fetch(`/api/sessions/compare?a=${encodeURIComponent(aId)}&b=${encodeURIComponent(bId)}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<CompareResponse>;
      })
      .then(d => { setData(d); setLoading(false); })
      .catch((e: Error) => { setError(e.message || 'Request failed'); setLoading(false); });
  }, [aId, bId]);

  useEffect(() => { fetchCompare(); }, [fetchCompare]);

  const handleDownload = async () => {
    try {
      const res = await fetch(
        `/api/sessions/compare?a=${encodeURIComponent(aId)}&b=${encodeURIComponent(bId)}&download=1`
      );
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compare-${aId.slice(0, 8)}-vs-${bId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // silently fail — user can retry
    }
  };

  // Merged tool list across both sessions
  const mergedTools: string[] = data
    ? Array.from(new Set([
        ...data.a.topTools.map(t => t.name),
        ...data.b.topTools.map(t => t.name),
      ]))
    : [];

  // Merged rules list
  const mergedRules: string[] = data
    ? Array.from(new Set([
        ...data.a.topRules.map(r => r.name),
        ...data.b.topRules.map(r => r.name),
      ]))
    : [];

  const maxToolCount = data
    ? Math.max(
        1,
        ...data.a.topTools.map(t => t.count),
        ...data.b.topTools.map(t => t.count),
      )
    : 1;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <motion.div
        ref={panelRef}
        className="relative h-full flex flex-col overflow-hidden"
        style={{ width: 560, background: 'var(--cs-bg-overlay)', boxShadow: 'var(--cs-shadow-drawer)' }}
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 260 }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Session comparison"
        tabIndex={-1}
      >
        {/* Top bar */}
        <Toolbar>
          <ToolbarTitle icon={<GitCompare className="w-3.5 h-3.5" />}>Session comparison</ToolbarTitle>
          <div className="flex items-center gap-1 ml-auto">
            <ToolButton onClick={handleDownload} title="Download diff as JSON">
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              Download
            </ToolButton>
            <ToolButton onClick={onClose} title="Close" aria-label="Close">
              <X className="w-3.5 h-3.5" aria-hidden="true" />
            </ToolButton>
          </div>
        </Toolbar>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && <TableSkeleton rows={9} columns={4} rowHeight="28px" />}

          {!loading && error && (
            <ErrorState
              description={`The comparison could not be loaded (${error}).`}
              onRetry={fetchCompare}
            />
          )}

          {!loading && !error && data && (
            <div className="p-4 space-y-5">

              {/* Session header */}
              <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}>
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                      <th className="cs-eyebrow px-3 py-2 text-left w-24 font-normal">Field</th>
                      <th className="cs-eyebrow px-3 py-2 text-left font-normal">Session A</th>
                      <th className="cs-eyebrow px-3 py-2 text-left font-normal">Session B</th>
                      <th className="cs-eyebrow px-3 py-2 text-left w-16 font-normal">Delta</th>
                    </tr>
                  </thead>
                  <tbody>
                    {/* Name row */}
                    <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                      <td className="px-3 py-2" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>Name</td>
                      <td className="px-3 py-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>
                        <div className="flex items-center gap-1.5">
                          {data.a.harnesses && <HarnessDots harnesses={data.a.harnesses} />}
                          <span className="truncate max-w-[160px]" title={data.a.name}>{data.a.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>
                        <div className="flex items-center gap-1.5">
                          {data.b.harnesses && <HarnessDots harnesses={data.b.harnesses} />}
                          <span className="truncate max-w-[160px]" title={data.b.name}>{data.b.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2" />
                    </tr>
                    {/* Date row */}
                    <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                      <td className="px-3 py-2" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>Created</td>
                      <td className="cs-mono px-3 py-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>{formatDate(data.a.createdAt)}</td>
                      <td className="cs-mono px-3 py-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>{formatDate(data.b.createdAt)}</td>
                      <td className="px-3 py-2" />
                    </tr>

                    {/* Metric rows */}
                    <MetricRow label="Spans"        aVal={data.a.spanCount}      bVal={data.b.spanCount} />
                    <MetricRow label="Alerts"       aVal={data.a.alertCount}     bVal={data.b.alertCount}     lowerIsBetter />
                    <MetricRow label="High threats"   severityLevel="high"   aVal={data.a.threatHigh}   bVal={data.b.threatHigh}   lowerIsBetter />
                    <MetricRow label="Medium threats" severityLevel="medium" aVal={data.a.threatMedium} bVal={data.b.threatMedium} lowerIsBetter />
                    <MetricRow label="Low threats"    severityLevel="low"    aVal={data.a.threatLow}    bVal={data.b.threatLow}    lowerIsBetter />
                    <MetricRow
                      label="Tokens in" aVal={data.a.tokensIn} bVal={data.b.tokensIn}
                      format={formatTokens} titleFormat={n => `${n.toLocaleString()} tokens`}
                    />
                    <MetricRow
                      label="Tokens out" aVal={data.a.tokensOut} bVal={data.b.tokensOut}
                      format={formatTokens} titleFormat={n => `${n.toLocaleString()} tokens`}
                    />
                    <MetricRow
                      label="Avg duration"
                      aVal={data.a.avgDurationMs}
                      bVal={data.b.avgDurationMs}
                      format={n => `${n.toFixed(1)}ms`}
                    />
                  </tbody>
                </table>
              </div>

              {/* Top Tools */}
              {mergedTools.length > 0 && (
                <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}>
                  <p className="cs-eyebrow px-3 py-2" style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                    Top tools
                  </p>
                  <div className="p-3 space-y-2">
                    {mergedTools.map(toolName => {
                      const aCount = data.a.topTools.find(t => t.name === toolName)?.count ?? 0;
                      const bCount = data.b.topTools.find(t => t.name === toolName)?.count ?? 0;
                      return (
                        <div key={toolName}>
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="cs-mono truncate max-w-[200px]" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-body)' }}>{toolName}</span>
                            <div className="cs-mono flex items-center gap-2" style={{ fontSize: 'var(--cs-text-xs)' }}>
                              <span style={{ color: SESSION_A_COLOR }}>{aCount}</span>
                              <span style={{ color: 'var(--cs-text-faint)' }}>/</span>
                              <span style={{ color: SESSION_B_COLOR }}>{bCount}</span>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-1">
                            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--cs-svg-track)' }}>
                              <div className="h-full rounded-full" style={{ width: `${(aCount / maxToolCount) * 100}%`, background: SESSION_A_COLOR }} />
                            </div>
                            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--cs-svg-track)' }}>
                              <div className="h-full rounded-full" style={{ width: `${(bCount / maxToolCount) * 100}%`, background: SESSION_B_COLOR }} />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <div className="flex items-center gap-3 mt-2 pt-2" style={{ borderTop: '1px solid var(--cs-rule)' }}>
                      <span className="inline-flex items-center gap-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background: SESSION_A_COLOR }} /> Session A
                      </span>
                      <span className="inline-flex items-center gap-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background: SESSION_B_COLOR }} /> Session B
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Top Rules */}
              {mergedRules.length > 0 && (
                <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}>
                  <p className="cs-eyebrow px-3 py-2" style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                    Top rules triggered
                  </p>
                  <table className="w-full text-xs">
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                        <th className="cs-eyebrow px-3 py-2 text-left font-normal">Rule</th>
                        <th className="cs-eyebrow px-3 py-2 text-right font-normal" style={{ color: SESSION_A_COLOR }}>A</th>
                        <th className="cs-eyebrow px-3 py-2 text-right font-normal" style={{ color: SESSION_B_COLOR }}>B</th>
                        <th className="cs-eyebrow px-3 py-2 text-right font-normal">Delta</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mergedRules.map(ruleName => {
                        const aCount = data.a.topRules.find(r => r.name === ruleName)?.count ?? 0;
                        const bCount = data.b.topRules.find(r => r.name === ruleName)?.count ?? 0;
                        return (
                          <tr key={ruleName} style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                            <td className="cs-mono px-3 py-2 truncate max-w-[200px]" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-body)' }}>
                              {ruleName}
                            </td>
                            <td className="cs-mono px-3 py-2 text-right" style={{ color: SESSION_A_COLOR }}>{aCount}</td>
                            <td className="cs-mono px-3 py-2 text-right" style={{ color: SESSION_B_COLOR }}>{bCount}</td>
                            <td className="px-3 py-2 text-right">
                              <DeltaBadge aVal={aCount} bVal={bCount} lowerIsBetter />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {mergedTools.length === 0 && mergedRules.length === 0 && (
                <EmptyState
                  title="Nothing else to compare"
                  description="Neither session recorded a tool call or a rule match, so there is nothing beyond the counts above to line up side by side."
                />
              )}

            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
