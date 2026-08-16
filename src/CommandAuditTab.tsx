/**
 * CommandAuditTab — every shell command the agents have run.
 *
 * This is the densest, most machine-authored surface in the product: one line
 * of captured shell per row, thousands of rows, and the interesting ones are
 * long. Two rules from the design notes decide how it looks.
 *
 * The monospace rule: a command is a string I compare character by character
 * and copy, so it is mono. The risk number and the timestamp line up in
 * columns, so they are mono too. Everything else — the agent's name, the
 * headings — is a word written for a human, and stays sans.
 *
 * "One idea per row": a 400-character command cannot be a row, so it truncates
 * to a single line and the full text is one click (or Enter) away in a detail
 * strip under the row. Nothing here is ever allowed to widen the page — the
 * table scrolls inside itself, the page body never does.
 *
 * This tab is embedded in the Orchestration view rather than being a top-level
 * tab, which is why it has a panel heading instead of a page toolbar.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal, Search, X, ChevronDown, ShieldCheck, SearchX, Loader2 } from 'lucide-react';
import { useListControls, type FacetConfig } from './FilterControls';
import { toMs } from './lib/format';
import type { Severity } from './shared/types';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, normalizeSeverity,
  EmptyState,
} from './components/data';

interface CommandEntry {
  spanId:    string;
  traceId:   string;
  harness:   string;
  command:   string;
  severity:  string;
  riskScore: number;
  tool:      string;
  /** The span's start as epoch *nanoseconds* in a string — never a date string. */
  timestamp: string;
}

// Identity, not risk — so agents stay out of the severity ramp.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

/**
 * The risk score onto the severity ramp.
 *
 * The score is a risk statement, so it reuses the one colour language the
 * product teaches rather than inventing a second green-to-red. The number sits
 * next to the meter at all times, so the level never depends on colour alone.
 */
function riskSeverity(score: number): Severity {
  if (score >= 60) return 'critical';
  if (score >= 30) return 'high';
  if (score >= 10) return 'medium';
  return 'none';
}

function riskBucket(score: number): string {
  return score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';
}

/** A 100-wide meter plus its value. Chart track on the sunken plane. */
function RiskMeter({ score }: { score: number }) {
  const sev = riskSeverity(score);
  return (
    <span className="flex items-center gap-1.5" title={`Risk score ${score}/100`}>
      <span
        className="h-1 rounded-full overflow-hidden shrink-0"
        style={{ width: '34px', background: 'var(--cs-bg-sunken)' }}
        aria-hidden="true"
      >
        <span
          className="block h-full rounded-full"
          style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: `var(--cs-sev-${sev})` }}
        />
      </span>
      <span
        className="cs-mono tabular-nums text-right"
        style={{ width: '20px', color: `var(--cs-sev-${sev}-fg)`, fontSize: 'var(--cs-text-xs)' }}
      >
        {score}
      </span>
    </span>
  );
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
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors whitespace-nowrap hover:bg-[var(--cs-bg-raised)]"
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

/**
 * Span times arrive as epoch nanoseconds, which `Date` cannot parse — it reads a
 * 19-digit string as a date string and yields `Invalid Date`. Scale down to
 * milliseconds first, the same way the search and timeline views do.
 *
 * `toMs` gives back 0 for a span with no recorded start (and for anything it
 * cannot parse); that is a missing time, not midnight in 1970, so it reads as a
 * dash rather than a wrong-but-plausible clock.
 */
function formatClock(nano: string): string {
  const ms = toMs(nano);
  return ms ? new Date(ms).toLocaleTimeString() : '—';
}

/** The full stamp, for the column's tooltip. */
function formatFullTime(nano: string): string {
  const ms = toMs(nano);
  return ms ? new Date(ms).toLocaleString() : '—';
}

export function CommandAuditTab() {
  const [commands, setCommands] = useState<CommandEntry[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  // Which rows have their full command expanded underneath them.
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [density, setDensity] = useRowDensity('command-audit');
  // Re-entry guard for loadMore. State alone lags a render, so a double-click
  // could start two overlapping page walks; the ref closes that window.
  const loadingRef = useRef(false);

  useEffect(() => {
    fetch('/api/command-audit?limit=200')
      .then(r => r.json())
      .then(d => { setCommands(d.commands ?? []); setTotalCount(d.total ?? 0); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  // The first fetch only brings the top rows by risk; this walks the server's
  // `offset` forward (2k per request) so search and filters can reach every
  // recorded command. Dedupe by spanId — new spans can shift the risk-sorted
  // pages between requests.
  const loadMore = async (all: boolean) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoadingMore(true);
    try {
      let next = commands;
      for (;;) {
        const r = await fetch(`/api/command-audit?limit=2000&offset=${next.length}`);
        const d = await r.json();
        const seen = new Set(next.map(c => c.spanId));
        const fresh = (d.commands ?? []).filter((c: CommandEntry) => !seen.has(c.spanId));
        next = next.concat(fresh);
        setTotalCount(d.total ?? next.length);
        if (!all || fresh.length === 0 || next.length >= (d.total ?? 0)) break;
      }
      setCommands(next);
    } catch {
      // Same policy as the initial fetch: a failed page leaves the list as-is.
    } finally {
      loadingRef.current = false;
      setLoadingMore(false);
    }
  };

  const facets = useMemo<FacetConfig<CommandEntry>[]>(() => {
    const harnesses = [...new Set(commands.map(c => c.harness))].sort();
    return [
      {
        key: 'harness',
        label: 'Agents',
        accessor: c => c.harness,
        options: harnesses.map(h => ({ value: h, label: h })),
      },
      {
        key: 'risk',
        label: 'Risk',
        accessor: c => riskBucket(c.riskScore),
        options: [
          { value: 'high',   label: 'High (≥50)' },
          { value: 'medium', label: 'Medium (20–49)' },
          { value: 'low',    label: 'Low (<20)' },
        ],
      },
    ];
  }, [commands]);

  const { query, setQuery, facetValues, setFacet, visible, total, shown, showMore, showAll } =
    useListControls(commands, { searchText: c => c.command, facets });

  const highRisk = commands.filter(c => c.riskScore >= 50).length;
  const filtered = !!query || Object.values(facetValues).some(Boolean);

  const toggleExpanded = (spanId: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(spanId)) next.delete(spanId); else next.add(spanId);
      return next;
    });
  };

  // Escape collapses every expanded command, so a keyboard user can always get
  // the list back to one-row-per-command without hunting for the row they opened.
  useEffect(() => {
    if (expanded.size === 0) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setExpanded(new Set()); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expanded.size]);

  // ── Columns ──────────────────────────────────────────────────────────────
  // The command is the row. Everything else is the context you need to decide
  // whether to read it, so it drops away first as the viewport narrows.
  const columns: DataColumn<CommandEntry>[] = [
    {
      id: 'risk', header: 'Risk', width: '68px',
      cell: c => <RiskMeter score={c.riskScore} />,
    },
    {
      id: 'severity', header: 'Severity', width: '104px', hideBelow: 'xl',
      cell: c => <SeverityBadge severity={normalizeSeverity(c.severity)} />,
    },
    {
      id: 'agent', header: 'Agent', width: '108px', hideBelow: '2xl',
      cell: c => (
        <span className="flex items-center gap-1.5 min-w-0" title={c.harness}>
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0"
            style={{ background: HARNESS_COLORS[c.harness] ?? HARNESS_COLORS.unknown }}
            aria-hidden="true"
          />
          <span className="truncate">{c.harness || 'unknown'}</span>
        </span>
      ),
    },
    {
      id: 'command', header: 'Command', width: 'minmax(0,1fr)', mono: true,
      // Truncated to one line on purpose. The full string is in the tooltip and,
      // selectable, in the detail strip — never widening the page.
      cell: c => (
        <span title={c.command} style={{ color: 'var(--cs-text-body)' }}>
          {c.command || '—'}
        </span>
      ),
    },
    {
      id: 'tool', header: 'Tool', width: '96px', hideBelow: '3xl', mono: true,
      cell: c => <span title={c.tool}>{c.tool || '—'}</span>,
    },
    {
      id: 'time', header: 'Time', width: '72px', hideBelow: '2xl', mono: true, align: 'end',
      cell: c => <span title={formatFullTime(c.timestamp)}>{formatClock(c.timestamp)}</span>,
    },
    {
      id: 'expand', header: '', width: '24px', align: 'end',
      cell: c => (
        <ChevronDown
          className="w-3.5 h-3.5 transition-transform"
          style={{
            color: 'var(--cs-text-faint)',
            transform: expanded.has(c.spanId) ? 'rotate(180deg)' : undefined,
          }}
          aria-hidden="true"
        />
      ),
    },
  ];

  // The full command, wrapped, on the sunken plane — the one place a machine
  // string is allowed to take as many lines as it needs.
  const renderFullCommand = (c: CommandEntry) => {
    if (!expanded.has(c.spanId)) return null;
    return (
      <pre
        className="cs-mono whitespace-pre-wrap break-all rounded-md px-2 py-1.5 my-1"
        style={{
          background: 'var(--cs-bg-sunken)',
          color: 'var(--cs-text-body)',
          fontSize: 'var(--cs-text-sm)',
          lineHeight: 'var(--cs-leading-normal)',
        }}
      >
        {c.command}
      </pre>
    );
  };

  return (
    <div className="flex flex-col min-w-0">

      {/* ── Panel head ───────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 xl:gap-3 pb-2 flex-wrap">
        <div className="flex items-center gap-2 shrink-0">
          <Terminal className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          <h3 style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
            Command audit
          </h3>
          <span
            className="cs-mono"
            title={`${shown.toLocaleString()} shown of ${totalCount.toLocaleString()} recorded commands`}
            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
          >
            {shown.toLocaleString()}/{totalCount.toLocaleString()}
          </span>
          {highRisk > 0 && (
            <span
              className="inline-flex items-center gap-1"
              title={`${highRisk} commands scored 50 or higher`}
              style={{ color: 'var(--cs-sev-high-fg)', fontSize: 'var(--cs-text-xs)' }}
            >
              {highRisk} high-risk
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 ml-auto flex-wrap">
          <div className="relative">
            <Search
              className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
              style={{ color: 'var(--cs-text-faint)' }}
              aria-hidden="true"
            />
            <input
              type="search"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Filter commands…"
              aria-label="Filter commands"
              className="cs-mono w-40 xl:w-52 rounded-md pl-7 pr-6 py-1 outline-none focus-visible:outline-2"
              style={{
                background: 'var(--cs-bg-raised)',
                color: 'var(--cs-text-body)',
                fontSize: 'var(--cs-text-xs)',
                outlineColor: 'var(--cs-accent)',
              }}
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                aria-label="Clear the filter"
                className="absolute right-1.5 top-1/2 -translate-y-1/2"
                style={{ color: 'var(--cs-text-faint)' }}
              >
                <X className="w-3 h-3" aria-hidden="true" />
              </button>
            )}
          </div>

          {facets.map(facet => (
            <select
              key={facet.key}
              value={facetValues[facet.key] ?? ''}
              onChange={e => setFacet(facet.key, e.target.value)}
              aria-label={facet.label}
              className="rounded-md px-1.5 py-1 outline-none focus-visible:outline-2"
              style={{
                background: 'var(--cs-bg-raised)',
                color: 'var(--cs-text-muted)',
                fontSize: 'var(--cs-text-xs)',
                outlineColor: 'var(--cs-accent)',
              }}
            >
              <option value="">{`All ${facet.label.toLowerCase()}`}</option>
              {facet.options.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          ))}

          <RowDensityToggle density={density} onChange={setDensity} className="ml-1" />
        </div>
      </div>

      {/* ── The list ─────────────────────────────────────────────────────── */}
      <DataTable
        rows={visible}
        columns={columns}
        rowKey={c => c.spanId}
        label="Command audit"
        density={density}
        minWidth={560}
        severity={c => normalizeSeverity(c.severity)}
        onActivate={c => toggleExpanded(c.spanId)}
        renderDetail={renderFullCommand}
        loading={loading}
        empty={filtered ? (
          <EmptyState
            icon={<SearchX className="w-6 h-6" aria-hidden="true" />}
            title="No command matches this filter"
            description="Nothing in the commands loaded so far matches. Clear the filter, or load the rest of the audit trail with the control below."
          />
        ) : (
          <EmptyState
            icon={<ShieldCheck className="w-6 h-6" aria-hidden="true" />}
            title="No shell commands recorded"
            description="Every Bash or shell tool call an agent makes is recorded here with the risk score it was given. None has been seen yet."
          />
        )}
      />

      {/* ── Footers ──────────────────────────────────────────────────────────
          Two different limits, said separately: how much of what is already in
          the browser is being drawn, and how much the server still holds. */}
      {shown < total && (
        <div
          className="flex items-center gap-2 px-3 py-1.5"
          style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)', borderTop: '1px solid var(--cs-rule)' }}
        >
          <span className="cs-mono">Drawing {shown.toLocaleString()} of {total.toLocaleString()} matches</span>
          <span className="ml-auto flex items-center gap-1">
            <ToolButton onClick={showMore} title="Draw another 50 rows">Show more</ToolButton>
            <ToolButton onClick={showAll} title="Draw every matching row">Show all</ToolButton>
          </span>
        </div>
      )}

      {commands.length < totalCount && (
        <div
          className="flex items-center gap-2 px-3 py-1.5"
          style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)', borderTop: '1px solid var(--cs-rule)' }}
        >
          <span className="cs-mono">
            {commands.length.toLocaleString()} of {totalCount.toLocaleString()} commands fetched
          </span>
          <span className="ml-auto flex items-center gap-1">
            <ToolButton
              onClick={() => loadMore(false)}
              disabled={loadingMore}
              title="Fetch the next 2,000 commands from the server"
              style={{ opacity: loadingMore ? 0.5 : 1 }}
            >
              {loadingMore && <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />}
              {loadingMore ? 'Loading…' : 'Load more'}
            </ToolButton>
            <ToolButton
              onClick={() => loadMore(true)}
              disabled={loadingMore}
              title="Fetch every recorded command — this can take a moment"
              style={{ opacity: loadingMore ? 0.5 : 1 }}
            >
              Load all
            </ToolButton>
          </span>
        </div>
      )}
    </div>
  );
}
