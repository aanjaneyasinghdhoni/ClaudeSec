import React, { useEffect, useState } from 'react';
import { X, Download, Loader2 } from 'lucide-react';
import { motion } from 'motion/react';

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

const HARNESS_COLORS: Record<string, string> = {
  'claude-code':    '#f97316',
  'github-copilot': '#6366f1',
  'openhands':      '#22c55e',
  'cursor':         '#a855f7',
  'aider':          '#ec4899',
  'cline':          '#14b8a6',
  'goose':          '#f59e0b',
  'continue':       '#0ea5e9',
  'windsurf':       '#38bdf8',
  'codex':          '#10b981',
  'amazon-q':       '#f59e0b',
  'gemini-cli':     '#4f46e5',
  'roo-code':       '#8b5cf6',
  'bolt':           '#06b6d4',
  'unknown':        '#64748b',
};

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
// Delta badge
// ---------------------------------------------------------------------------

interface DeltaBadgeProps {
  aVal: number;
  bVal: number;
  lowerIsBetter?: boolean;
}

function DeltaBadge({ aVal, bVal, lowerIsBetter = false }: DeltaBadgeProps): React.ReactElement {
  const diff = bVal - aVal;
  if (diff === 0) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-700 text-slate-400">=</span>
    );
  }
  const positive = diff > 0;
  // If lower is better: positive diff (B > A) is bad (red), negative diff (B < A) is good (green)
  // If higher is better: positive diff is good (green), negative is bad (red)
  const isGood = lowerIsBetter ? !positive : positive;
  const label = positive ? `+${diff.toLocaleString()}` : diff.toLocaleString();

  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
      isGood
        ? 'bg-green-900/40 text-green-300 border border-green-700/40'
        : 'bg-red-900/40 text-red-300 border border-red-700/40'
    }`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

function Skeleton(): React.ReactElement {
  return (
    <div className="space-y-3 animate-pulse p-4">
      {[...Array(8)].map((_, i) => (
        <div key={i} className="flex gap-3">
          <div className="h-5 bg-slate-800 rounded flex-1" />
          <div className="h-5 bg-slate-800 rounded w-24" />
          <div className="h-5 bg-slate-800 rounded w-24" />
          <div className="h-5 bg-slate-800 rounded w-12" />
        </div>
      ))}
    </div>
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
}

function MetricRow({ label, aVal, bVal, lowerIsBetter = false, format }: MetricRowProps): React.ReactElement {
  const fmt = format ?? ((n: number) => n.toLocaleString());
  return (
    <tr className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
      <td className="px-3 py-2 text-[11px] text-slate-500 whitespace-nowrap">{label}</td>
      <td className="px-3 py-2 text-xs font-mono text-slate-200 text-right">{fmt(aVal)}</td>
      <td className="px-3 py-2 text-xs font-mono text-slate-200 text-right">{fmt(bVal)}</td>
      <td className="px-3 py-2 text-right">
        <DeltaBadge aVal={aVal} bVal={bVal} lowerIsBetter={lowerIsBetter} />
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
          className="inline-block w-2.5 h-2.5 rounded-full"
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
  const [data, setData]     = useState<CompareResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState('');

  useEffect(() => {
    setLoading(true);
    setError('');
    fetch(`/api/sessions/compare?a=${encodeURIComponent(aId)}&b=${encodeURIComponent(bId)}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<CompareResponse>;
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [aId, bId]);

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
    <>
      {/* Backdrop */}
      <motion.div
        className="fixed inset-0 bg-black/50 z-40"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      />

      {/* Panel */}
      <motion.div
        className="fixed right-0 top-0 h-full z-50 flex flex-col bg-slate-950 border-l border-slate-800 shadow-2xl overflow-hidden"
        style={{ width: 560 }}
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 260 }}
      >
        {/* Top bar */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
          <span className="text-sm font-semibold text-slate-200 flex-1">Session Comparison</span>
          <button
            type="button"
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs text-slate-300 transition-colors"
            title="Download diff as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Download Diff
          </button>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 hover:bg-slate-800 rounded-lg text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading && <Skeleton />}

          {!loading && error && (
            <div className="p-6 text-center text-red-400 text-sm font-mono">
              Failed to load comparison: {error}
            </div>
          )}

          {!loading && !error && data && (
            <div className="p-4 space-y-5">

              {/* Session header */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                      <th className="px-3 py-2 text-left w-24">Field</th>
                      <th className="px-3 py-2 text-left">Session A</th>
                      <th className="px-3 py-2 text-left">Session B</th>
                      <th className="px-3 py-2 text-left w-16">Delta</th>
                    </tr>
                  </thead>
                  <tbody>
                    {/* Name row */}
                    <tr className="border-b border-slate-800/50">
                      <td className="px-3 py-2 text-[11px] text-slate-500">Name</td>
                      <td className="px-3 py-2 text-xs text-slate-200 font-medium">
                        <div className="flex items-center gap-1.5">
                          {data.a.harnesses && <HarnessDots harnesses={data.a.harnesses} />}
                          <span className="truncate max-w-[160px]" title={data.a.name}>{data.a.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-200 font-medium">
                        <div className="flex items-center gap-1.5">
                          {data.b.harnesses && <HarnessDots harnesses={data.b.harnesses} />}
                          <span className="truncate max-w-[160px]" title={data.b.name}>{data.b.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2" />
                    </tr>
                    {/* Date row */}
                    <tr className="border-b border-slate-800/50">
                      <td className="px-3 py-2 text-[11px] text-slate-500">Created</td>
                      <td className="px-3 py-2 text-xs font-mono text-slate-400">{formatDate(data.a.createdAt)}</td>
                      <td className="px-3 py-2 text-xs font-mono text-slate-400">{formatDate(data.b.createdAt)}</td>
                      <td className="px-3 py-2" />
                    </tr>

                    {/* Metric rows */}
                    <MetricRow label="Spans"        aVal={data.a.spanCount}      bVal={data.b.spanCount} />
                    <MetricRow label="Alerts"       aVal={data.a.alertCount}     bVal={data.b.alertCount}     lowerIsBetter />
                    <MetricRow label="HIGH threats" aVal={data.a.threatHigh}     bVal={data.b.threatHigh}     lowerIsBetter />
                    <MetricRow label="MED threats"  aVal={data.a.threatMedium}   bVal={data.b.threatMedium}   lowerIsBetter />
                    <MetricRow label="LOW threats"  aVal={data.a.threatLow}      bVal={data.b.threatLow}      lowerIsBetter />
                    <MetricRow label="Tokens In"    aVal={data.a.tokensIn}       bVal={data.b.tokensIn} />
                    <MetricRow label="Tokens Out"   aVal={data.a.tokensOut}      bVal={data.b.tokensOut} />
                    <MetricRow
                      label="Avg Duration"
                      aVal={data.a.avgDurationMs}
                      bVal={data.b.avgDurationMs}
                      format={n => `${n.toFixed(1)}ms`}
                    />
                  </tbody>
                </table>
              </div>

              {/* Top Tools */}
              {mergedTools.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <p className="px-3 py-2 text-[10px] text-slate-500 uppercase tracking-wider border-b border-slate-800 font-semibold">
                    Top Tools
                  </p>
                  <div className="p-3 space-y-2">
                    {mergedTools.map(toolName => {
                      const aCount = data.a.topTools.find(t => t.name === toolName)?.count ?? 0;
                      const bCount = data.b.topTools.find(t => t.name === toolName)?.count ?? 0;
                      return (
                        <div key={toolName}>
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="text-[11px] text-slate-300 font-mono truncate max-w-[200px]">{toolName}</span>
                            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
                              <span className="text-blue-400">{aCount}</span>
                              <span>/</span>
                              <span className="text-violet-400">{bCount}</span>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-1">
                            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-blue-500 rounded-full"
                                style={{ width: `${(aCount / maxToolCount) * 100}%` }}
                              />
                            </div>
                            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-violet-500 rounded-full"
                                style={{ width: `${(bCount / maxToolCount) * 100}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <div className="flex items-center gap-3 mt-2 pt-2 border-t border-slate-800">
                      <span className="flex items-center gap-1 text-[10px] text-slate-500">
                        <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Session A
                      </span>
                      <span className="flex items-center gap-1 text-[10px] text-slate-500">
                        <span className="w-2 h-2 rounded-full bg-violet-500 inline-block" /> Session B
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Top Rules */}
              {mergedRules.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  <p className="px-3 py-2 text-[10px] text-slate-500 uppercase tracking-wider border-b border-slate-800 font-semibold">
                    Top Rules Triggered
                  </p>
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-800/60 text-[10px] text-slate-500">
                        <th className="px-3 py-2 text-left">Rule</th>
                        <th className="px-3 py-2 text-right text-blue-400">A</th>
                        <th className="px-3 py-2 text-right text-violet-400">B</th>
                        <th className="px-3 py-2 text-right">Delta</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mergedRules.map(ruleName => {
                        const aCount = data.a.topRules.find(r => r.name === ruleName)?.count ?? 0;
                        const bCount = data.b.topRules.find(r => r.name === ruleName)?.count ?? 0;
                        return (
                          <tr key={ruleName} className="border-b border-slate-800/30 hover:bg-slate-800/20">
                            <td className="px-3 py-2 text-[11px] text-slate-300 font-mono truncate max-w-[200px]">
                              {ruleName}
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-blue-400">{aCount}</td>
                            <td className="px-3 py-2 text-right font-mono text-violet-400">{bCount}</td>
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

            </div>
          )}
        </div>
      </motion.div>
    </>
  );
}
