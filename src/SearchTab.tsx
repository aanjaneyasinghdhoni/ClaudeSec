/**
 * SearchTab — full-text search across every recorded span.
 *
 * This is the surface people reach for when they already suspect something:
 * a quarter of a million spans, and one string that has to be found in them.
 * So the three things the rebuild optimises for are, in order:
 *
 *   1. **Where the match is.** A result row that only says "span 4f2a…" makes
 *      you open a drawer to learn whether it was worth opening. Each row now
 *      carries the attribute that actually matched, with the query highlighted
 *      inside it, so the answer is on the row.
 *   2. **Density.** At 28px rows a 1366×768 laptop shows twenty-one results at
 *      once, which is the difference between reading a page of results and
 *      paging through fives.
 *   3. **Scope you can see.** Severity, agent and the time window are permanent
 *      controls in one strip, not a dropdown you have to open to find out what
 *      is currently filtering your results.
 *
 * Everything structural comes from `src/components/data` — the same shell,
 * spine, density control and empty/loading/error states as the alert log.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Search, Download, X, ChevronLeft, ChevronRight, SearchX, Database, Clock,
} from 'lucide-react';
import { formatDuration } from './lib/format';
import type { Severity } from './shared/types';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, SEVERITY_META, SEVERITY_ORDER, normalizeSeverity,
  EmptyState, ErrorState,
} from './components/data';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SpanRow {
  spanId: string;
  traceId: string;
  name: string;
  harness: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
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

// The agent that produced the span. Identity, not risk, so these stay out of the
// severity ramp — a small dot in a fixed hue with the name in text beside it.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

/** `''` is "all severities" — the same value the API treats as unfiltered. */
const SEVERITY_FILTERS: readonly string[] = ['', ...SEVERITY_ORDER] as const;

// The server caps `limit` at 100. Asking for the cap rather than twenty means a
// compact list is a full screen of results instead of a third of one, and the
// pager stops being the main thing you interact with. Rows past the fold cost
// nothing to keep: <DataTable> skips layout and paint for them.
const PAGE_SIZE = 100;

// How much context to keep either side of a match in the snippet column. Wide
// enough to see the surrounding argument, short enough to stay on one line.
const SNIPPET_LEAD = 40;
const SNIPPET_LEN  = 160;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toMillis(nanoStr: string): number | null {
  try { return Number(BigInt(nanoStr) / 1_000_000n); }
  catch { return null; }
}

/** Time of day for the column; the full stamp lives in the cell's tooltip. */
function formatClock(nanoStr: string): string {
  const ms = toMillis(nanoStr);
  return ms === null ? '—' : new Date(ms).toLocaleTimeString();
}

function formatFullTime(nanoStr: string): string {
  const ms = toMillis(nanoStr);
  return ms === null ? '—' : new Date(ms).toLocaleString();
}

function harnessColor(harness: string): string {
  return HARNESS_COLORS[harness.toLowerCase()] ?? HARNESS_COLORS.unknown;
}

/**
 * The attribute a result matched on, reduced to one line.
 *
 * Spans store their attributes as a JSON blob, and dumping that into a cell is
 * unreadable. Instead we find the first attribute whose value contains the
 * query and return `key` plus a window of its value around the hit. With no
 * query there is nothing to centre on, so we fall back to the longest string
 * value — which in practice is the command, the path or the URL, i.e. the thing
 * you wanted to see anyway.
 */
function matchSnippet(attributes: string, needle: string): { key: string; text: string } | null {
  let parsed: unknown;
  try { parsed = JSON.parse(attributes); } catch { parsed = null; }

  const entries: [string, string][] = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? Object.entries(parsed as Record<string, unknown>)
        .map(([k, v]): [string, string] => [k, typeof v === 'string' ? v : JSON.stringify(v) ?? ''])
        .filter(([, v]) => v.length > 0)
    : (attributes ? [['attributes', attributes]] : []);

  if (entries.length === 0) return null;

  const lower = needle.trim().toLowerCase();
  if (lower) {
    for (const [key, value] of entries) {
      const at = value.toLowerCase().indexOf(lower);
      if (at === -1) continue;
      const from = Math.max(0, at - SNIPPET_LEAD);
      const text = (from > 0 ? '…' : '') + value.slice(from, from + SNIPPET_LEN)
                 + (from + SNIPPET_LEN < value.length ? '…' : '');
      return { key, text };
    }
  }

  const longest = entries.reduce((a, b) => (b[1].length > a[1].length ? b : a));
  return {
    key: longest[0],
    text: longest[1].length > SNIPPET_LEN ? `${longest[1].slice(0, SNIPPET_LEN)}…` : longest[1],
  };
}

/**
 * The query, marked inside the string it was found in.
 *
 * Highlighting is chrome, not risk, so it uses the accent rather than a
 * severity colour — a red mark on a matched substring would compete with the
 * spine for the one thing on screen allowed to mean "dangerous".
 */
function Highlight({ text, query }: { text: string; query: string }) {
  const needle = query.trim();
  if (!needle) return <>{text}</>;

  const lowerText   = text.toLowerCase();
  const lowerNeedle = needle.toLowerCase();
  const parts: React.ReactNode[] = [];
  let cursor = 0;

  for (;;) {
    const at = lowerText.indexOf(lowerNeedle, cursor);
    if (at === -1) break;
    if (at > cursor) parts.push(text.slice(cursor, at));
    parts.push(
      <mark
        key={at}
        style={{
          background: 'var(--cs-accent-soft)',
          color: 'var(--cs-text-strong)',
          borderRadius: 'var(--cs-radius-xs)',
          padding: '0 1px',
        }}
      >
        {text.slice(at, at + needle.length)}
      </mark>,
    );
    cursor = at + needle.length;
  }

  if (parts.length === 0) return <>{text}</>;
  if (cursor < text.length) parts.push(text.slice(cursor));
  return <>{parts}</>;
}

/** Toolbar buttons share one shape, so the strip reads as a single control. */
function ToolButton({
  active = false,
  children,
  style,
  ...props
}: React.ComponentProps<'button'> & { active?: boolean }) {
  return (
    <button
      type="button"
      {...props}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors whitespace-nowrap"
      style={{
        background: active ? 'var(--cs-accent-soft)' : 'transparent',
        color: active ? 'var(--cs-accent)' : 'var(--cs-text-muted)',
        fontSize: 'var(--cs-text-xs)',
        ...style,
      }}
    >
      {children}
    </button>
  );
}

/** A text input in the toolbar. Ground, not outline — see the design notes. */
function FieldInput({ className = '', ...props }: React.ComponentProps<'input'>) {
  return (
    <input
      {...props}
      className={`rounded-md px-2 py-1 outline-none focus-visible:outline-2 ${className}`}
      style={{
        background: 'var(--cs-bg-raised)',
        color: 'var(--cs-text-body)',
        fontSize: 'var(--cs-text-xs)',
        outlineColor: 'var(--cs-accent)',
        ...props.style,
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Drawer — the whole span, for when the row is not enough
// ---------------------------------------------------------------------------

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3 items-start">
      <span
        className="w-20 shrink-0 uppercase pt-0.5"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {label}
      </span>
      <div className="min-w-0 flex-1 break-all" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-sm)' }}>
        {children}
      </div>
    </div>
  );
}

function SpanDrawer({ span, query, onClose }: { span: SpanRow | null; query: string; onClose: () => void }) {
  if (!span) return null;

  let attributes = span.attributes;
  try { attributes = JSON.stringify(JSON.parse(span.attributes), null, 2); } catch { /* show it raw */ }

  const sev = normalizeSeverity(span.severity);

  return (
    // A drawer floats over content it cannot predict, so it is the one thing
    // here that gets a hard edge and a shadow.
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        role="dialog"
        aria-label="Span detail"
        className="relative w-full max-w-xl h-full overflow-y-auto"
        style={{
          background: 'var(--cs-bg-surface)',
          borderLeft: '1px solid var(--cs-rule-strong)',
          boxShadow: 'var(--cs-shadow-drawer)',
        }}
        onClick={e => e.stopPropagation()}
      >
        <div
          className="flex items-start justify-between gap-4 px-5 py-3 sticky top-0 z-10"
          style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
        >
          <div className="min-w-0">
            <SeverityBadge severity={sev} />
            <h2
              className="cs-mono truncate mt-1"
              style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}
            >
              {span.name}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close (Esc)"
            title="Close (Esc)"
            className="shrink-0 p-1 rounded transition-colors"
            style={{ color: 'var(--cs-text-muted)' }}
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-2.5" style={{ borderBottom: '1px solid var(--cs-rule)' }}>
          <DetailRow label="Span ID"><span className="cs-mono">{span.spanId}</span></DetailRow>
          <DetailRow label="Trace ID"><span className="cs-mono">{span.traceId}</span></DetailRow>
          <DetailRow label="Agent">
            <span className="inline-flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ background: harnessColor(span.harness) }}
                aria-hidden="true"
              />
              {span.harness}
            </span>
          </DetailRow>
          <DetailRow label="Protocol">{span.protocol || '—'}</DetailRow>
          <DetailRow label="Duration">
            <span className="cs-mono">{formatDuration(span.startNano, span.endNano)}</span>
          </DetailRow>
          <DetailRow label="Start"><span className="cs-mono">{formatFullTime(span.startNano)}</span></DetailRow>
          <DetailRow label="End"><span className="cs-mono">{formatFullTime(span.endNano)}</span></DetailRow>
          {span.reason && <DetailRow label="Reason">{span.reason}</DetailRow>}
        </div>

        <div className="px-5 py-4">
          <p
            className="uppercase mb-2"
            style={{
              color: 'var(--cs-text-faint)',
              fontSize: 'var(--cs-text-2xs)',
              letterSpacing: 'var(--cs-tracking-wide)',
            }}
          >
            Attributes (scrubbed)
          </p>
          {/* A well, not a bordered box: code sits on the sunken plane. */}
          <pre
            className="cs-mono rounded-lg p-3 overflow-auto max-h-[50vh] whitespace-pre-wrap break-all"
            style={{
              background: 'var(--cs-bg-sunken)',
              color: 'var(--cs-text-muted)',
              fontSize: 'var(--cs-text-sm)',
              lineHeight: 'var(--cs-leading-normal)',
            }}
          >
            <Highlight text={attributes} query={query} />
          </pre>
        </div>
      </div>
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

  const [result,    setResult]    = useState<SearchResult | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected,  setSelected]  = useState<SpanRow | null>(null);
  // Scanning a quarter of a million spans is the job, so results default to
  // compact — twenty-one rows on a 1366×768 laptop instead of thirteen.
  const [density,   setDensity]   = useRowDensity('search');

  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

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
      params.set('limit', String(PAGE_SIZE));
      const res = await fetch(`/api/search?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: SearchResult = await res.json();
      setResult(data);
      setLoadError(null);
    } catch (e) {
      // Search silently returning nothing during an outage reads as "there is
      // nothing to find", which is the one answer this screen must never give
      // by accident. Surface the failure instead.
      setLoadError((e as Error).message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  // Trigger a search whenever filters or the page change, debounced so typing a
  // query does not fire a request per keystroke.
  useEffect(() => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => {
      fetchResults(query, severity, harness, from, to, page);
    }, 300);
    return () => {
      if (debounceTimer.current) clearTimeout(debounceTimer.current);
    };
  }, [query, severity, harness, from, to, page, fetchResults]);

  // Escape closes the drawer. Reading a result and getting back to the list is
  // the loop this screen exists for; it must not need the mouse.
  useEffect(() => {
    if (!selected) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selected]);

  // Any change of scope invalidates the current page number.
  function handleQueryChange(v: string)    { setQuery(v);    setPage(1); }
  function handleSeverityChange(v: string) { setSeverity(v); setPage(1); }
  function handleHarnessChange(v: string)  { setHarness(v);  setPage(1); }
  function handleFromChange(v: string)     { setFrom(v);     setPage(1); }
  function handleToChange(v: string)       { setTo(v);       setPage(1); }

  function buildExportUrl(): string {
    const params = new URLSearchParams();
    if (query)    params.set('q',        query);
    if (severity) params.set('severity', severity);
    if (harness)  params.set('harness',  harness);
    if (from)     params.set('from',     from);
    if (to)       params.set('to',       to);
    return `/api/search/export?${params.toString()}`;
  }

  const spans = result?.spans ?? [];

  // Derived once per result set rather than per render of a cell, because
  // parsing an attribute blob is the most expensive thing a row does.
  const snippets = useMemo(() => {
    const map = new Map<string, { key: string; text: string } | null>();
    for (const s of spans) map.set(s.spanId, matchSnippet(s.attributes, query));
    return map;
  }, [spans, query]);

  const scoped = !!(query || severity || harness || from || to);
  const clearAll = () => {
    setQuery(''); setSeverity(''); setHarness(''); setFrom(''); setTo(''); setPage(1);
  };

  // ── Columns ──────────────────────────────────────────────────────────────
  // Ordered by how a result is read: when, how bad, what ran, and what in it
  // matched. The last two survive to the narrowest tier, because a result you
  // cannot identify is not a result.
  const columns: DataColumn<SpanRow>[] = [
    {
      id: 'time', header: 'Time', width: '76px', hideBelow: 'xl', mono: true,
      cell: s => <span title={formatFullTime(s.startNano)}>{formatClock(s.startNano)}</span>,
    },
    {
      id: 'severity', header: 'Severity', width: '104px',
      cell: s => <SeverityBadge severity={normalizeSeverity(s.severity)} />,
    },
    {
      id: 'span', header: 'Span', width: 'minmax(0,1fr)', mono: true,
      // The span name is machine-authored and gets compared between rows, so it
      // is mono — and it is the one thing in the row at full text strength.
      cell: s => (
        <span title={s.name} style={{ color: 'var(--cs-text-strong)' }}>
          <Highlight text={s.name} query={query} />
        </span>
      ),
    },
    {
      id: 'match', header: 'Matched in', width: 'minmax(0,1.7fr)', mono: true,
      // Where the hit is. Without this the only way to tell two results apart
      // is to open both of them.
      cell: s => {
        const snip = snippets.get(s.spanId);
        if (!snip) return <span style={{ color: 'var(--cs-text-faint)' }}>—</span>;
        return (
          <span title={`${snip.key}: ${snip.text}`}>
            <span style={{ color: 'var(--cs-text-faint)' }}>{snip.key} </span>
            <span style={{ color: 'var(--cs-text-body)' }}><Highlight text={snip.text} query={query} /></span>
          </span>
        );
      },
    },
    {
      id: 'agent', header: 'Agent', width: '112px', hideBelow: 'xl',
      cell: s => (
        <span className="flex items-center gap-1.5 min-w-0" title={s.harness}>
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0"
            style={{ background: harnessColor(s.harness) }}
            aria-hidden="true"
          />
          <span className="truncate">{s.harness || 'unknown'}</span>
        </span>
      ),
    },
    {
      id: 'protocol', header: 'Protocol', width: '84px', hideBelow: '2xl',
      cell: s => <span title={s.protocol}>{s.protocol || '—'}</span>,
    },
    {
      id: 'duration', header: 'Duration', width: '78px', align: 'end', mono: true,
      cell: s => <span>{formatDuration(s.startNano, s.endNano)}</span>,
    },
    {
      id: 'trace', header: 'Session', width: '92px', hideBelow: '3xl', mono: true,
      cell: s => <span title={s.traceId}>{s.traceId ? s.traceId.slice(0, 8) : '—'}</span>,
    },
  ];

  const start = result ? (result.page - 1) * PAGE_SIZE + 1 : 0;
  const end   = result ? Math.min(result.page * PAGE_SIZE, result.total) : 0;
  const pages = result?.pages ?? 1;
  const showPager = !!result && result.total > 0 && spans.length > 0;
  const staleWarning = !!loadError && spans.length > 0;

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ────────────────────────────────────────────────────────
          One strip: the query, then the scope it runs inside. Everything that
          narrows the result set is visible at rest, so you can never be
          surprised by a filter you forgot was on. */}
      <div
        className="flex items-center gap-2 xl:gap-3 px-3 py-1.5 shrink-0 flex-wrap"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        {/* The one text input on the screen. */}
        <div className="relative flex-1 min-w-[180px] max-w-[420px]">
          <Search
            className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
            style={{ color: 'var(--cs-text-faint)' }}
            aria-hidden="true"
          />
          <FieldInput
            type="search"
            aria-label="Search spans"
            placeholder="Search every span…"
            value={query}
            onChange={e => handleQueryChange(e.target.value)}
            className="w-full pl-7 pr-7"
            style={{ fontSize: 'var(--cs-text-sm)' }}
          />
          {query && (
            <button
              type="button"
              onClick={() => handleQueryChange('')}
              aria-label="Clear the query"
              className="absolute right-2 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--cs-text-faint)' }}
            >
              <X className="w-3 h-3" aria-hidden="true" />
            </button>
          )}
        </div>

        {/* Severity scale. The primary axis of the product, so it is a
            permanent control rather than a dropdown — and every option carries
            its own glyph, so the level reads without the colour. */}
        <div className="flex items-center gap-0.5" role="group" aria-label="Filter by severity">
          {SEVERITY_FILTERS.map(value => {
            const meta   = value ? SEVERITY_META[value as Severity] : null;
            const active = severity === value;
            return (
              <ToolButton
                key={value || 'all'}
                active={active}
                aria-pressed={active}
                onClick={() => handleSeverityChange(value)}
                title={meta ? `${meta.label} — ${meta.meaning}` : 'All severities'}
              >
                {meta && (
                  <meta.Icon className="w-3 h-3" style={{ color: `var(--cs-sev-${value})` }} aria-hidden="true" />
                )}
                {meta ? meta.label : 'All'}
              </ToolButton>
            );
          })}
        </div>

        <FieldInput
          type="text"
          aria-label="Filter by agent"
          placeholder="Agent"
          value={harness}
          onChange={e => handleHarnessChange(e.target.value)}
          className="w-24 hidden xl:block"
        />

        {/* Time window. Two fields, one label — the icon carries the meaning so
            the strip does not grow two more words at every width. */}
        <div className="hidden 2xl:flex items-center gap-1">
          <Clock className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          <FieldInput
            type="datetime-local"
            aria-label="From"
            title="Only spans that started after this moment"
            value={from}
            onChange={e => handleFromChange(e.target.value)}
          />
          <span style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>→</span>
          <FieldInput
            type="datetime-local"
            aria-label="To"
            title="Only spans that started before this moment"
            value={to}
            onChange={e => handleToChange(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-1 ml-auto">
          {/* A failed refresh with results still on screen is the dangerous
              case: the list looks live but is stale. Say so rather than
              replacing rows the operator may still be reading. */}
          {staleWarning && (
            <span
              role="status"
              title={`The last refresh failed (${loadError}). These results are from the previous query.`}
              style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-xs)' }}
            >
              Stale
            </span>
          )}
          <span
            className="cs-mono"
            title={result ? `Showing ${start.toLocaleString()}–${end.toLocaleString()} of ${result.total.toLocaleString()} matching spans` : undefined}
            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
          >
            {result ? `${start.toLocaleString()}–${end.toLocaleString()} of ${result.total.toLocaleString()}` : '—'}
          </span>

          {/* The pager lives in the toolbar rather than in a footer. The table
              measures its own height down to the bottom of the scrollport, so
              anything rendered underneath it starts life below the fold. */}
          {showPager && (
            <span className="flex items-center gap-0.5">
              <ToolButton
                disabled={page <= 1 || loading}
                onClick={() => setPage(p => p - 1)}
                aria-label="Previous page"
                title="Previous page"
                style={{ opacity: page <= 1 || loading ? 0.4 : 1 }}
              >
                <ChevronLeft className="w-3.5 h-3.5" aria-hidden="true" />
              </ToolButton>
              <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
                {page}/{pages}
              </span>
              <ToolButton
                disabled={page >= pages || loading}
                onClick={() => setPage(p => p + 1)}
                aria-label="Next page"
                title="Next page"
                style={{ opacity: page >= pages || loading ? 0.4 : 1 }}
              >
                <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
              </ToolButton>
            </span>
          )}

          <RowDensityToggle density={density} onChange={setDensity} className="mx-1" />
          {scoped && (
            <ToolButton onClick={clearAll} title="Clear the query and every filter">
              <X className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden 2xl:inline">Clear</span>
            </ToolButton>
          )}
          <ToolButton
            onClick={() => window.open(buildExportUrl())}
            title="Download these results as JSON (up to 5,000 spans)"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden xl:inline">Export</span>
          </ToolButton>
        </div>
      </div>

      {/* ── Results ────────────────────────────────────────────────────────── */}
      <DataTable
        rows={spans}
        columns={columns}
        rowKey={s => s.spanId}
        label="Search results"
        density={density}
        minWidth={640}
        severity={s => normalizeSeverity(s.severity)}
        onActivate={s => setSelected(s)}
        loading={loading && spans.length === 0}
        error={loadError && spans.length === 0 ? (
          <ErrorState
            title="Search is not answering"
            description={`The search index did not respond (${loadError}). Recording and detection are unaffected — this is only the view.`}
            onRetry={() => fetchResults(query, severity, harness, from, to, page)}
          />
        ) : undefined}
        empty={scoped ? (
          <EmptyState
            icon={<SearchX className="w-6 h-6" aria-hidden="true" />}
            title="Nothing matches this search"
            description="No span matched the query inside the current scope. Search matches whole phrases, so try a shorter one — or widen the severity scale, the agent or the time window."
          />
        ) : (
          <EmptyState
            icon={<Database className="w-6 h-6" aria-hidden="true" />}
            title="No spans recorded yet"
            description="Every span an agent produces is indexed for full-text search the moment it lands. Start an agent session, or point one at this instance over OTLP, and its activity becomes searchable here."
          />
        )}
      />

      <SpanDrawer span={selected} query={query} onClose={() => setSelected(null)} />
    </div>
  );
}
