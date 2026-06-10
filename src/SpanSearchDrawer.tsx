/**
 * SpanSearchDrawer — a slide-in panel that fetches and lists the spans matching
 * a free-text query (a tool name or a file path) via the existing /api/search
 * endpoint, then renders each span's parsed attributes with <SpanAttributes>.
 *
 * It exists so list rows in the Orchestration / File-Access tabs become
 * clickable drill-downs without routing selection state through App.tsx — the
 * drawer owns its own fetch + open/close lifecycle.
 */
import React, { useEffect, useState } from 'react';
import { X, Search as SearchIcon } from 'lucide-react';
import { SpanAttributes } from './SpanAttributes';

interface SpanRow {
  spanId: string;
  traceId: string;
  name: string;
  harness: string;
  severity: 'none' | 'low' | 'medium' | 'high';
  attributes: string;
  startNano: string;
  endNano: string;
  protocol: string;
  reason: string;
}

interface SearchResponse {
  spans: SpanRow[];
  total: number;
}

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

function harnessColor(harness: string): string {
  return HARNESS_COLORS[(harness ?? '').toLowerCase()] ?? HARNESS_COLORS['unknown'];
}

function severityClasses(severity: string): string {
  return severity === 'high'   ? 'bg-red-900/60 text-red-300 border-red-700' :
         severity === 'medium' ? 'bg-orange-900/60 text-orange-300 border-orange-700' :
         severity === 'low'    ? 'bg-yellow-900/60 text-yellow-300 border-yellow-700' :
         'bg-green-900/60 text-green-300 border-green-700';
}

function formatTime(nanoStr: string): string {
  try {
    const ms = Number(BigInt(nanoStr) / 1_000_000n);
    return new Date(ms).toLocaleString();
  } catch { return '—'; }
}

export interface SpanSearchTarget {
  /** Free-text query passed to /api/search (a tool name or a file path). */
  query: string;
  /** Human-readable heading for the drawer (e.g. the tool name or file path). */
  title: string;
  /** Optional sub-label under the title (e.g. "Tool" or "File"). */
  kind?: string;
}

export function SpanSearchDrawer({
  target,
  onClose,
}: {
  target: SpanSearchTarget | null;
  onClose: () => void;
}) {
  const [spans, setSpans]     = useState<SpanRow[]>([]);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!target) return;
    let cancelled = false;
    setLoading(true);
    setSpans([]);
    setExpanded(null);
    const params = new URLSearchParams({ q: target.query, limit: '50' });
    fetch(`/api/search?${params.toString()}`)
      .then(r => r.json())
      .then((d: SearchResponse) => {
        if (cancelled) return;
        setSpans(d.spans ?? []);
        setTotal(d.total ?? 0);
      })
      .catch(() => { if (!cancelled) { setSpans([]); setTotal(0); } })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [target]);

  if (!target) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="relative w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-5 py-4 border-b border-slate-800 sticky top-0 bg-slate-900 z-10">
          <div className="min-w-0 pr-4">
            {target.kind && (
              <p className="text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">{target.kind}</p>
            )}
            <h2 className="text-sm font-semibold text-slate-100 truncate font-mono">{target.title}</h2>
            <p className="text-[11px] text-slate-500 mt-1">
              {loading ? 'Searching…' : `${total} matching span${total !== 1 ? 's' : ''}`}
              {total > spans.length && !loading ? ` · showing first ${spans.length}` : ''}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-2">
          {loading ? (
            <div className="space-y-2">
              {[0, 1, 2].map(i => (
                <div key={i} className="h-12 bg-slate-800 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : spans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-500">
              <SearchIcon className="w-8 h-8 opacity-40" />
              <p className="text-sm">No matching spans</p>
              <p className="text-xs text-slate-600">Nothing in the trace store matches this entry.</p>
            </div>
          ) : (
            spans.map(span => {
              const isOpen = expanded === span.spanId;
              let parsed: Record<string, unknown> = {};
              try {
                const p = JSON.parse(span.attributes);
                if (p && typeof p === 'object') parsed = p as Record<string, unknown>;
              } catch {}
              return (
                <div key={span.spanId} className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/60">
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : span.spanId)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800/40 transition-colors"
                  >
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: harnessColor(span.harness) }}
                      title={span.harness}
                    />
                    <code className="text-[11px] font-mono text-slate-200 truncate flex-1">{span.name}</code>
                    <span className={`inline-flex items-center px-1.5 py-0.5 text-[10px] font-semibold rounded border flex-shrink-0 ${severityClasses(span.severity)}`}>
                      {span.severity === 'none' ? 'OK' : span.severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] text-slate-600 flex-shrink-0">{formatTime(span.startNano)}</span>
                  </button>
                  {isOpen && (
                    <div className="px-3 py-2 border-t border-slate-800 bg-slate-950/40">
                      <div className="space-y-1 mb-2 text-[11px] text-slate-500 font-mono break-all">
                        <div>span: {span.spanId}</div>
                        <div>trace: {span.traceId}</div>
                        {span.reason && <div className="text-slate-400">reason: {span.reason}</div>}
                      </div>
                      <SpanAttributes attrs={parsed} />
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
