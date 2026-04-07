import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Search, Download, X, ChevronLeft, ChevronRight } from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

interface SearchResult {
  spans: SpanRow[];
  total: number;
  page: number;
  pages: number;
  query: string;
}

// ---------------------------------------------------------------------------
// Constants
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

const SEVERITY_OPTIONS = ['', 'high', 'medium', 'low', 'none'] as const;
const SEVERITY_LABELS: Record<string, string> = {
  '':       'All',
  'high':   'HIGH',
  'medium': 'MED',
  'low':    'LOW',
  'none':   'OK',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDuration(startNano: string, endNano: string): string {
  try {
    const ms = Number((BigInt(endNano) - BigInt(startNano)) / 1_000_000n);
    if (ms < 0)      return '—';
    if (ms < 1000)   return `${ms}ms`;
    if (ms < 60_000) return `${(ms / 1000).toFixed(2)}s`;
    return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  } catch { return '—'; }
}

function formatTime(nanoStr: string): string {
  try {
    const ms = Number(BigInt(nanoStr) / 1_000_000n);
    return new Date(ms).toLocaleString();
  } catch { return '—'; }
}

function harnessColor(harness: string): string {
  return HARNESS_COLORS[harness.toLowerCase()] ?? HARNESS_COLORS['unknown'];
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'high'   ? 'bg-red-900/60 text-red-300 border-red-700' :
    severity === 'medium' ? 'bg-orange-900/60 text-orange-300 border-orange-700' :
    severity === 'low'    ? 'bg-yellow-900/60 text-yellow-300 border-yellow-700' :
    'bg-green-900/60 text-green-300 border-green-700';
  const label =
    severity === 'high'   ? 'HIGH' :
    severity === 'medium' ? 'MED' :
    severity === 'low'    ? 'LOW' :
    'OK';
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-xs font-semibold rounded border ${cls}`}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Loading skeleton
// ---------------------------------------------------------------------------

function SkeletonRows() {
  return (
    <>
      {[0, 1, 2].map(i => (
        <tr key={i} className="border-b border-slate-800">
          {[1, 2, 3, 4, 5, 6].map(j => (
            <td key={j} className="px-4 py-3">
              <div className="h-4 bg-slate-800 rounded animate-pulse" style={{ width: `${55 + (i + j) * 7}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------
// Drawer — span detail panel
// ---------------------------------------------------------------------------

interface DrawerProps {
  span: SpanRow | null;
  onClose: () => void;
}

function SpanDrawer({ span, onClose }: DrawerProps) {
  if (!span) return null;

  let parsed: unknown = null;
  try { parsed = JSON.parse(span.attributes); } catch { parsed = span.attributes; }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="relative w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 sticky top-0 bg-slate-900 z-10">
          <h2 className="text-sm font-semibold text-slate-100 truncate pr-4">{span.name}</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Meta */}
        <div className="px-5 py-4 space-y-3 border-b border-slate-800">
          <Row label="Span ID"   value={span.spanId} mono />
          <Row label="Trace ID"  value={span.traceId} mono />
          <Row label="Harness">
            <span className="flex items-center gap-1.5 text-xs text-slate-200">
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: harnessColor(span.harness) }} />
              {span.harness}
            </span>
          </Row>
          <Row label="Severity">
            <SeverityBadge severity={span.severity} />
          </Row>
          <Row label="Protocol"  value={span.protocol || '—'} />
          <Row label="Duration"  value={formatDuration(span.startNano, span.endNano)} />
          <Row label="Start"     value={formatTime(span.startNano)} />
          <Row label="End"       value={formatTime(span.endNano)} />
          {span.reason && <Row label="Reason" value={span.reason} />}
        </div>

        {/* Attributes */}
        <div className="px-5 py-4">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Attributes</p>
          <pre className="text-xs text-slate-300 bg-slate-950 rounded-lg p-4 overflow-auto max-h-[50vh] leading-relaxed whitespace-pre-wrap break-all">
            {JSON.stringify(parsed, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  children,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex gap-3 items-start">
      <span className="text-xs text-slate-500 w-20 flex-shrink-0 pt-0.5">{label}</span>
      {children ?? (
        <span className={`text-xs text-slate-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SearchTab
// ---------------------------------------------------------------------------

export function SearchTab() {
  const [query,    setQuery]    = useState('');
  const [severity, setSeverity] = useState('');
  const [harness,  setHarness]  = useState('');
  const [from,     setFrom]     = useState('');
  const [to,       setTo]       = useState('');
  const [page,     setPage]     = useState(1);
  const LIMIT = 20;

  const [result,   setResult]   = useState<SearchResult | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState<SpanRow | null>(null);

  // Debounced query
  const debouncedQuery = useRef('');
  const debounceTimer  = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchResults = useCallback(async (q: string, sev: string, h: string, f: string, t: string, p: number) => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (q)   params.set('q',        q);
      if (sev) params.set('severity', sev);
      if (h)   params.set('harness',  h);
      if (f)   params.set('from',     f);
      if (t)   params.set('to',       t);
      params.set('page',  String(p));
      params.set('limit', String(LIMIT));
      const res = await fetch(`/api/search?${params.toString()}`);
      if (res.ok) {
        const data: SearchResult = await res.json();
        setResult(data);
      }
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, []);

  // Trigger search whenever filters/page change (with debounce on query)
  useEffect(() => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => {
      fetchResults(query, severity, harness, from, to, page);
    }, 300);
    return () => {
      if (debounceTimer.current) clearTimeout(debounceTimer.current);
    };
  }, [query, severity, harness, from, to, page, fetchResults]);

  // Reset to page 1 when filters change
  function handleQueryChange(v: string)   { setQuery(v);    setPage(1); }
  function handleSeverityChange(v: string){ setSeverity(v); setPage(1); }
  function handleHarnessChange(v: string) { setHarness(v);  setPage(1); }
  function handleFromChange(v: string)    { setFrom(v);     setPage(1); }
  function handleToChange(v: string)      { setTo(v);       setPage(1); }

  function buildExportUrl(): string {
    const params = new URLSearchParams();
    if (debouncedQuery.current) params.set('q', debouncedQuery.current);
    if (severity) params.set('severity', severity);
    if (harness)  params.set('harness',  harness);
    if (from)     params.set('from',     from);
    if (to)       params.set('to',       to);
    return `/api/search/export?${params.toString()}`;
  }

  const start = result ? (result.page - 1) * LIMIT + 1 : 0;
  const end   = result ? Math.min(result.page * LIMIT, result.total) : 0;

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-200">
      {/* Toolbar */}
      <div className="flex flex-wrap items-end gap-3 px-5 py-4 bg-slate-900 border-b border-slate-800">
        {/* Query */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <input
            type="text"
            placeholder="Search spans…"
            value={query}
            onChange={e => handleQueryChange(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-600 transition-colors"
          />
          {query && (
            <button
              type="button"
              onClick={() => handleQueryChange('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Severity */}
        <select
          value={severity}
          onChange={e => handleSeverityChange(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-600 transition-colors"
        >
          {SEVERITY_OPTIONS.map(s => (
            <option key={s} value={s}>{SEVERITY_LABELS[s]}</option>
          ))}
        </select>

        {/* Harness */}
        <input
          type="text"
          placeholder="Harness"
          value={harness}
          onChange={e => handleHarnessChange(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-600 transition-colors w-32"
        />

        {/* From */}
        <div className="flex items-center gap-1">
          <span className="text-xs text-slate-500">From</span>
          <input
            type="datetime-local"
            value={from}
            onChange={e => handleFromChange(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </div>

        {/* To */}
        <div className="flex items-center gap-1">
          <span className="text-xs text-slate-500">To</span>
          <input
            type="datetime-local"
            value={to}
            onChange={e => handleToChange(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </div>

        {/* Export */}
        <button
          type="button"
          onClick={() => window.open(buildExportUrl())}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors flex-shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          Export
        </button>
      </div>

      {/* Table area */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm border-collapse">
          <thead className="sticky top-0 z-10 bg-slate-900 border-b border-slate-800">
            <tr>
              {['Span Name', 'Harness', 'Severity', 'Protocol', 'Duration', 'Time'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonRows />
            ) : !result || result.spans.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-16 text-center">
                  <div className="flex flex-col items-center gap-3 text-slate-500">
                    <Search className="w-8 h-8 opacity-40" />
                    <p className="text-sm">No results found</p>
                    {query && (
                      <p className="text-xs text-slate-600">Try a different query or clear the filters</p>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              result.spans.map(span => (
                <tr
                  key={span.spanId}
                  onClick={() => setSelected(span)}
                  className="border-b border-slate-800/60 hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 max-w-[220px]">
                    <span className="block truncate font-mono text-xs text-slate-200">{span.name}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="flex items-center gap-1.5">
                      <span
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: harnessColor(span.harness) }}
                      />
                      <span className="text-xs text-slate-300">{span.harness}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <SeverityBadge severity={span.severity} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-400">{span.protocol || '—'}</td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-400 font-mono">
                    {formatDuration(span.startNano, span.endNano)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                    {formatTime(span.startNano)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination footer */}
      {result && result.total > 0 && (
        <div className="flex items-center justify-between px-5 py-3 bg-slate-900 border-t border-slate-800">
          <span className="text-xs text-slate-400">
            Showing {start}–{end} of {result.total} result{result.total !== 1 ? 's' : ''}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1 || loading}
              onClick={() => setPage(p => p - 1)}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 text-xs rounded-lg transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Previous
            </button>
            <span className="text-xs text-slate-500">
              {page} / {result.pages}
            </span>
            <button
              type="button"
              disabled={page >= result.pages || loading}
              onClick={() => setPage(p => p + 1)}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 text-xs rounded-lg transition-colors"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Detail drawer */}
      <SpanDrawer span={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
