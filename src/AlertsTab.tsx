/**
 * AlertsTab — the alert log.
 *
 * This is the reference implementation of the dense-list pattern: severity
 * spine, compact rows, sticky header, responsive columns, and the empty /
 * loading / error states. Anything here that another tab would need lives in
 * `src/components/data/` rather than in this file — see that folder's README
 * comment for the API. The only things below are alert-specific: triage, the
 * optional LLM judge, and the detail drawer.
 *
 * The screen it is designed for is a 1366×768 laptop. Once browser chrome, the
 * app header, the toolbar and the status bar are paid for there is roughly
 * 500px of table body left, so density is the whole game: 32px rows fit fifteen
 * alerts where 40px rows fit twelve.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle, Download, Trash2, ShieldCheck, SearchX, EyeOff, AlertCircle,
  Eye, Layers, Sparkles, Loader2, Undo2, Scale, X,
} from 'lucide-react';
import { socket } from './socket';
import { apiErrorMessage, apiSend, reportApiFailure } from './lib/api';
import type { Severity } from './shared/types';
import { AlertDetailDrawer, type AlertDetail } from './AlertDetailDrawer';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, SEVERITY_META, normalizeSeverity,
  EmptyState, ErrorState,
} from './components/data';

// How long a just-triaged row lingers (greyed, with an Undo affordance) before
// it drops out of the list. Long enough to read "Dismissed — Undo" and react.
const UNDO_WINDOW_MS = 5000;

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

type JudgeVerdict = 'malicious' | 'suspicious' | 'benign';
interface JudgeResult {
  enabled: boolean;
  verdict?: JudgeVerdict;
  category?: string;
  confidence?: number;
  reason?: string;
  error?: string;
  model?: string;
}
type JudgeState =
  | { status: 'loading' }
  | { status: 'done'; result: JudgeResult }
  | { status: 'error'; message: string };

// A row that was just dismissed / marked FP. It stays rendered (greyed, with an
// Undo button) for UNDO_WINDOW_MS so the action reads as deliberate feedback
// rather than an instant vanish. `row` is the snapshot to keep showing while
// the real list no longer returns it; `patch` is what was applied (so Undo can
// send the inverse). `fingerprint` is set when the action targeted a group.
interface PendingTriage {
  kind: 'dismissed' | 'fp';
  row: AlertRow;
  patch: { dismissed?: boolean; fp?: boolean };
  fingerprint?: string;
}

interface AlertRow {
  id: number;
  ts: string;
  ruleLabel: string;
  severity: Severity;
  spanId: string;
  traceId: string;
  harness: string;
  spanName: string;
  matchedText: string;
  dismissed: number;
  fp: number;
  count: number;
  fingerprint: string;
}

// The agent that produced the span. These are identity, not risk, so they stay
// out of the severity ramp — a small dot in a fixed hue, and the name in text.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

const HARNESS_NAMES: Record<string, string> = {
  'claude-code': 'Claude Code',
  'copilot':     'GitHub Copilot CLI',
  'codex':       'Codex',
  'unknown':     'Unknown',
};

// The judge's three verdicts reuse the severity ramp rather than inventing a
// fourth colour language: malicious reads as critical, suspicious as medium,
// benign as the accent (chrome — "nothing to do here").
const JUDGE_VERDICT_COLOR: Record<JudgeVerdict, string> = {
  malicious:  'var(--cs-sev-critical-fg)',
  suspicious: 'var(--cs-sev-medium-fg)',
  benign:     'var(--cs-text-muted)',
};

const FILTER_BTNS: { label: string; value: SeverityFilter }[] = [
  { label: 'All',      value: 'all'      },
  { label: 'Critical', value: 'critical' },
  { label: 'High',     value: 'high'     },
  { label: 'Medium',   value: 'medium'   },
  { label: 'Low',      value: 'low'      },
];

/** Toolbar buttons all share one shape, so the row reads as a single control strip. */
function ToolButton({
  active = false,
  danger = false,
  children,
  ...props
}: React.ComponentProps<'button'> & { active?: boolean; danger?: boolean }) {
  return (
    <button
      type="button"
      {...props}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors whitespace-nowrap"
      style={{
        background: active ? 'var(--cs-accent-soft)' : 'transparent',
        color: active ? 'var(--cs-accent)'
             : danger ? 'var(--cs-sev-critical-fg)'
             : 'var(--cs-text-muted)',
        fontSize: 'var(--cs-text-xs)',
      }}
    >
      {children}
    </button>
  );
}

interface AlertsTabProps {
  // Navigate to the session that produced an alert and pre-select its span.
  // Optional with a safe no-op default so the tab still renders standalone.
  onInvestigate?: (traceId: string, spanId: string) => void;
}

export function AlertsTab({ onInvestigate }: AlertsTabProps = {}) {
  // The rule-label filter lives in the URL, not component state — that is
  // what makes "View in Alert log" from a Govern policy a deep link rather
  // than a one-shot navigation: the filtered view is shareable, survives a
  // refresh, and there is exactly one place (?rule=) it can come from. Repeated
  // `rule` params (not a comma-joined one) because a rule label is a sentence
  // a human wrote for the rule metadata and may itself contain a comma.
  const [searchParams, setSearchParams] = useSearchParams();
  const ruleLabels = searchParams.getAll('rule');
  const ruleFilterActive = ruleLabels.length > 0;
  const clearRuleFilter = () => setSearchParams(prev => {
    const next = new URLSearchParams(prev);
    next.delete('rule');
    return next;
  }, { replace: true });

  const [alerts,          setAlerts]          = useState<AlertRow[]>([]);
  const [total,           setTotal]           = useState(0);
  const [loading,         setLoading]         = useState(true);
  const [loadError,       setLoadError]       = useState<string | null>(null);
  const [severityFilter,  setSeverityFilter]  = useState<SeverityFilter>('all');
  const [showDismissed,   setShowDismissed]   = useState(false);
  const [groupByRule,     setGroupByRule]     = useState(false);
  const [triaging,        setTriaging]        = useState<Set<number>>(new Set());
  // Rows lingering in the undo window, keyed by alert id. Survive a refetch so
  // the user sees the greyed "Undo" affordance instead of an instant vanish.
  const [pending,         setPending]         = useState<Record<number, PendingTriage>>({});
  const undoTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({});
  // LLM-as-judge: off unless a judge URL is configured. judgeStates is keyed by
  // alert id so each row tracks its own on-demand verdict.
  const [judgeEnabled,    setJudgeEnabled]    = useState(false);
  const [judgeStates,     setJudgeStates]     = useState<Record<number, JudgeState>>({});
  // The alert whose detail drawer is open. Clicking a row populates this in
  // place (honouring the "Select an alert to see details" hint) rather than
  // navigating straight to the timeline.
  const [selected,        setSelected]        = useState<AlertDetail | null>(null);
  // Scanning hundreds of alerts is the job, so this list defaults to compact.
  const [density, setDensity] = useRowDensity('alerts');

  const fetchAlerts = useCallback((
    sev: SeverityFilter = severityFilter,
    sd  = showDismissed,
    grp = groupByRule,
  ) => {
    // The server has no rule-label filter to hand this to, so it is applied
    // client-side below — widen the page here so a policy's evidence isn't
    // quietly clipped to the default 200-row page before that filter runs.
    const params = new URLSearchParams({ limit: ruleFilterActive ? '1000' : '200' });
    if (sev !== 'all') params.set('severity', sev);
    if (sd)  params.set('showDismissed', 'true');
    if (grp) params.set('groupBy', 'rule');
    fetch(`/api/alerts?${params}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(({ alerts: a, total: t }: { alerts: AlertRow[]; total: number }) => {
        setAlerts(a ?? []);
        setTotal(t ?? 0);
        setLoadError(null);
      })
      // A monitoring tool that silently shows zero rows during an outage is
      // worse than one that shows nothing, so the failure is surfaced.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, [severityFilter, showDismissed, groupByRule, ruleFilterActive]);

  useEffect(() => {
    fetchAlerts(severityFilter, showDismissed, groupByRule);
  }, [fetchAlerts, severityFilter, showDismissed, groupByRule]);

  useEffect(() => {
    const handler = () => fetchAlerts(severityFilter, showDismissed, groupByRule);
    socket.on('alerts-update', handler);
    return () => { socket.off('alerts-update', handler); };
  }, [fetchAlerts, severityFilter, showDismissed, groupByRule]);

  // Clear any in-flight undo timers when the component unmounts.
  useEffect(() => {
    const timers = undoTimers.current;
    return () => { for (const t of Object.values(timers)) clearTimeout(t); };
  }, []);

  // Escape closes the detail drawer. The drawer itself only offers a click
  // target, and a triage loop that needs the mouse to get out of a detail view
  // is a triage loop nobody uses.
  useEffect(() => {
    if (!selected) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selected]);

  const patchAlert = (id: number, body: { dismissed?: boolean; fp?: boolean; fingerprint?: string }) =>
    apiSend(`/api/alerts/${id}`, 'PATCH', body);

  // Drop a lingering row from the undo window and resync with the server.
  const finalizePending = (id: number) => {
    const t = undoTimers.current[id];
    if (t) { clearTimeout(t); delete undoTimers.current[id]; }
    setPending(prev => { const next = { ...prev }; delete next[id]; return next; });
    fetchAlerts(severityFilter, showDismissed, groupByRule);
  };

  const triage = async (alert: AlertRow, patch: { dismissed?: boolean; fp?: boolean }) => {
    const id = alert.id;
    // In the grouped view a row stands in for every duplicate sharing its
    // fingerprint — send it so the server hits them all, not just MIN(id).
    const fingerprint = groupByRule ? alert.fingerprint : undefined;
    // Turning dismiss/FP *on* removes the row from the default list; keep it
    // visible with an Undo affordance. Toggling *off* (restore / unmark) leaves
    // the row in place, so just refetch as before.
    const isRemoval = patch.dismissed === true || patch.fp === true;

    setTriaging(prev => new Set(prev).add(id));
    try {
      // Only enter the undo window once the server has actually applied the
      // triage — otherwise a refused dismiss would hide the alert behind an
      // "Undo" for something that never happened.
      await patchAlert(id, { ...patch, ...(fingerprint ? { fingerprint } : {}) });
      if (isRemoval) {
        const kind: PendingTriage['kind'] = patch.fp === true ? 'fp' : 'dismissed';
        setPending(prev => ({ ...prev, [id]: { kind, row: alert, patch, fingerprint } }));
        const existing = undoTimers.current[id];
        if (existing) clearTimeout(existing);
        undoTimers.current[id] = setTimeout(() => finalizePending(id), UNDO_WINDOW_MS);
      } else {
        fetchAlerts(severityFilter, showDismissed, groupByRule);
      }
    } catch (err: unknown) {
      reportApiFailure(err, 'Failed to update alert');
    }
    setTriaging(prev => { const s = new Set(prev); s.delete(id); return s; });
  };

  // Reverse a just-applied dismiss/FP and pull the row back into the list.
  const undoTriage = async (id: number) => {
    const p = pending[id];
    if (!p) return;
    const inverse: { dismissed?: boolean; fp?: boolean } = {};
    if (p.patch.dismissed !== undefined) inverse.dismissed = false;
    if (p.patch.fp !== undefined)        inverse.fp = false;
    try {
      await patchAlert(id, { ...inverse, ...(p.fingerprint ? { fingerprint: p.fingerprint } : {}) });
    } catch (err: unknown) {
      reportApiFailure(err, 'Failed to undo');
    }
    // Either way, resync: finalizePending refetches, so the row returns to
    // whatever state the server holds rather than whatever the undo intended.
    finalizePending(id);
  };

  const handleClear = async () => {
    if (!window.confirm('Clear all alerts? This cannot be undone.')) return;
    try {
      await apiSend('/api/alerts', 'DELETE');
    } catch (err: unknown) {
      reportApiFailure(err, 'Failed to clear alerts');
    }
  };

  // Detect whether the optional LLM-as-judge is configured (so the "Analyze"
  // action only shows when it can actually do something). Off by default.
  useEffect(() => {
    fetch('/api/config/status')
      .then(r => r.json())
      .then((data: { settings?: { key: string; enabled: boolean }[] }) => {
        const j = (data.settings ?? []).find(s => s.key === 'CLAUDESEC_JUDGE_URL');
        setJudgeEnabled(!!j?.enabled);
      })
      .catch(() => setJudgeEnabled(false));
  }, []);

  // On-demand semantic analysis of a single alert via POST /api/judge {spanId}.
  // Fail-open on the server; the UI shows whatever verdict / error comes back.
  const analyze = async (alert: AlertRow) => {
    setJudgeStates(prev => ({ ...prev, [alert.id]: { status: 'loading' } }));
    try {
      const result = await apiSend<JudgeResult>(
        '/api/judge', 'POST',
        alert.spanId ? { spanId: alert.spanId } : { text: alert.matchedText },
      );
      setJudgeStates(prev => ({ ...prev, [alert.id]: { status: 'done', result } }));
    } catch (err: unknown) {
      setJudgeStates(prev => ({
        ...prev,
        [alert.id]: { status: 'error', message: apiErrorMessage(err, 'Request failed') },
      }));
    }
  };

  const formatTime = (ts: string) => {
    try { return new Date(ts).toLocaleTimeString(); }
    catch { return ts; }
  };

  // The list the server returns no longer includes rows we just dismissed/FP'd,
  // but we keep them on screen during the undo window. Merge any pending rows
  // back in (deduped by id) at their original position so they linger greyed.
  const fetchedIds  = new Set(alerts.map(a => a.id));
  const lingering   = Object.values(pending).filter(p => !fetchedIds.has(p.row.id)).map(p => p.row);
  const unfilteredAlerts = [...alerts, ...lingering];

  // Arriving from a Govern policy's "View in Alert log" narrows straight to
  // that policy's evidence — the exact rule labels it is backed by, no more.
  const displayAlerts = ruleFilterActive
    ? unfilteredAlerts.filter(a => ruleLabels.includes(a.ruleLabel))
    : unfilteredAlerts;

  // ── Columns ──────────────────────────────────────────────────────────────
  // Ordered by how a row is read: when, how bad, what rule, from which agent,
  // and finally the string that tripped it. Everything that is context rather
  // than signal drops away as the viewport narrows; severity, rule, the matched
  // text and the triage controls survive to the narrowest tier, because those
  // four are what an operator actually acts on.
  const columns: DataColumn<AlertRow>[] = [
    {
      id: 'time', header: 'Time', width: '72px', hideBelow: 'xl', mono: true,
      cell: a => <span title={new Date(a.ts).toLocaleString()}>{formatTime(a.ts)}</span>,
    },
    {
      id: 'severity', header: 'Severity', width: '118px',
      cell: a => {
        const sev = normalizeSeverity(a.severity);
        const hits = a.count ?? 1;
        return (
          <span className="flex items-center gap-1.5 min-w-0">
            <SeverityBadge severity={sev} />
            {hits > 1 && (
              <span
                className="cs-mono shrink-0"
                title={`Fired ${hits} times`}
                style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
              >
                {hits}×
              </span>
            )}
            {!!a.fp && (
              <span
                className="shrink-0 uppercase"
                title="Marked as a false positive"
                style={{
                  color: 'var(--cs-text-faint)',
                  fontSize: 'var(--cs-text-2xs)',
                  letterSpacing: 'var(--cs-tracking-wide)',
                }}
              >
                FP
              </span>
            )}
          </span>
        );
      },
    },
    {
      id: 'rule', header: 'Rule', width: 'minmax(0,1.5fr)',
      // The rule label is a sentence written for a human, so it is sans, and it
      // is the one thing in the row set at full text strength.
      cell: a => (
        <span
          title={a.ruleLabel}
          style={{
            color: a.dismissed ? 'var(--cs-text-faint)' : 'var(--cs-text-strong)',
            fontWeight: 'var(--cs-weight-medium)',
            textDecoration: a.dismissed ? 'line-through' : undefined,
          }}
        >
          {a.ruleLabel}
        </span>
      ),
    },
    {
      id: 'agent', header: 'Agent', width: '112px', hideBelow: 'xl',
      cell: a => (
        <span className="flex items-center gap-1.5 min-w-0" title={HARNESS_NAMES[a.harness] ?? a.harness}>
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0"
            style={{ background: HARNESS_COLORS[a.harness] ?? HARNESS_COLORS.unknown }}
            aria-hidden="true"
          />
          <span className="truncate">{HARNESS_NAMES[a.harness] ?? a.harness}</span>
        </span>
      ),
    },
    {
      id: 'span', header: 'Span', width: 'minmax(0,0.8fr)', hideBelow: '2xl', mono: true,
      cell: a => <span title={a.spanName}>{a.spanName || '—'}</span>,
    },
    {
      id: 'match', header: 'Matched', width: 'minmax(0,1.6fr)', mono: true,
      // The captured string, scrubbed server-side. Machine-authored, so mono —
      // and left uncoloured, because a red block on every row would compete
      // with the spine for the one thing allowed to mean "risk".
      cell: a =>
        a.matchedText
          ? <span title={a.matchedText} style={{ color: 'var(--cs-text-body)' }}>{a.matchedText}</span>
          : <span style={{ color: 'var(--cs-text-faint)' }}>—</span>,
    },
    {
      id: 'session', header: 'Session', width: '92px', hideBelow: '3xl', mono: true,
      cell: a => <span title={a.traceId}>{a.traceId ? a.traceId.slice(0, 8) : '—'}</span>,
    },
    {
      id: 'triage', header: 'Triage', width: '84px', align: 'end',
      // Stops propagation so the buttons never open the detail drawer as well.
      cell: a => {
        const pend       = pending[a.id];
        const isDismissed = !!a.dismissed;
        const isFP        = !!a.fp;
        const isTriaging  = triaging.has(a.id);
        const judgeState  = judgeStates[a.id];
        return (
          <span
            className="flex items-center justify-end gap-0.5"
            onClick={e => e.stopPropagation()}
            onKeyDown={e => e.stopPropagation()}
          >
            {pend ? (
              // Undo window: confirm the action took, and give a way back.
              <button
                type="button"
                onClick={() => undoTriage(a.id)}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors"
                style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
                title={pend.kind === 'fp' ? 'Undo — marked as false positive' : 'Undo — dismissed'}
              >
                <Undo2 className="w-3 h-3" aria-hidden="true" /> Undo
              </button>
            ) : (
              <>
                {judgeEnabled && (
                  <button
                    type="button"
                    disabled={judgeState?.status === 'loading'}
                    onClick={() => analyze(a)}
                    className="p-1 rounded transition-colors disabled:opacity-50"
                    style={{ color: 'var(--cs-text-faint)' }}
                    title="Analyze with the LLM judge (semantic verdict)"
                  >
                    {judgeState?.status === 'loading'
                      ? <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                      : <Sparkles className="w-3 h-3" aria-hidden="true" />}
                  </button>
                )}
                <button
                  type="button"
                  disabled={isTriaging}
                  onClick={() => triage(a, { dismissed: !isDismissed })}
                  className="p-1 rounded transition-colors disabled:opacity-50"
                  style={{ color: isDismissed ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
                  title={isDismissed ? 'Restore alert' : 'Dismiss alert'}
                >
                  <EyeOff className="w-3 h-3" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  disabled={isTriaging}
                  onClick={() => triage(a, { fp: !isFP })}
                  className="p-1 rounded transition-colors disabled:opacity-50"
                  style={{ color: isFP ? 'var(--cs-sev-medium-fg)' : 'var(--cs-text-faint)' }}
                  title={isFP ? 'Unmark false positive' : 'Mark as a false positive'}
                >
                  <AlertCircle className="w-3 h-3" aria-hidden="true" />
                </button>
              </>
            )}
          </span>
        );
      },
    },
  ];

  // The judge verdict for a row, rendered as a strip under it rather than as a
  // popover, so several rows can be compared at once.
  const renderJudge = (a: AlertRow) => {
    const state = judgeStates[a.id];
    if (!state) return null;
    return (
      <div
        className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5"
        style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}
      >
        <span className="inline-flex items-center gap-1 shrink-0" style={{ color: 'var(--cs-text-faint)' }}>
          <Sparkles className="w-3 h-3" aria-hidden="true" /> LLM judge
        </span>
        {state.status === 'loading' && (
          <span className="inline-flex items-center gap-1.5">
            <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" /> Analyzing…
          </span>
        )}
        {state.status === 'error' && (
          <span style={{ color: 'var(--cs-sev-critical-fg)' }}>Request failed — {state.message}</span>
        )}
        {state.status === 'done' && (() => {
          const r = state.result;
          if (!r.enabled) {
            return <span>Judge not configured (set <code className="cs-mono">CLAUDESEC_JUDGE_URL</code>).</span>;
          }
          if (!r.verdict) {
            return (
              <span style={{ color: 'var(--cs-sev-medium-fg)' }}>
                Judge unavailable — {r.error ?? 'no verdict'}{' '}
                <span style={{ color: 'var(--cs-text-faint)' }}>(fail-open: detection unaffected)</span>
              </span>
            );
          }
          return (
            <>
              <span
                className="uppercase"
                style={{
                  color: JUDGE_VERDICT_COLOR[r.verdict],
                  fontWeight: 'var(--cs-weight-bold)',
                  letterSpacing: 'var(--cs-tracking-wide)',
                  fontSize: 'var(--cs-text-2xs)',
                }}
              >
                {r.verdict}
              </span>
              {r.category && <span className="cs-mono">{r.category}</span>}
              {typeof r.confidence === 'number' && (
                <span className="cs-mono" style={{ color: 'var(--cs-text-faint)' }}>
                  conf {(r.confidence * 100).toFixed(0)}%
                </span>
              )}
              {r.reason && <span className="italic basis-full sm:basis-auto">“{r.reason}”</span>}
              {r.model && <span className="cs-mono ml-auto shrink-0" style={{ color: 'var(--cs-text-faint)' }}>{r.model}</span>}
            </>
          );
        })()}
      </div>
    );
  };

  const filtered = severityFilter !== 'all' || ruleFilterActive;
  // A failed refresh with rows still on screen is the dangerous case: the list
  // looks live but is stale. Say so in the toolbar rather than replacing data
  // the operator may still be working through.
  const staleWarning = loadError && displayAlerts.length > 0;

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ────────────────────────────────────────────────────────
          One strip, one control shape. It is chrome, so it is quiet: no
          outlines, no fills except on what is currently on. */}
      <div
        className="flex items-center gap-2 xl:gap-3 px-3 py-1.5 shrink-0 flex-wrap"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        <div className="flex items-center gap-2 shrink-0">
          <AlertTriangle className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          <h2 style={{ fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
            Alert log
          </h2>
          <span
            className="cs-mono"
            title={`Showing ${displayAlerts.length} of ${total} alerts`}
            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
          >
            {displayAlerts.length}/{total}
          </span>
          {staleWarning && (
            <span
              role="status"
              title={`Last refresh failed (${loadError}). Detection is unaffected — this is only the view.`}
              style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-xs)' }}
            >
              Stale
            </span>
          )}
          {ruleFilterActive && (
            // Arrived here from a Govern policy's "View in Alert log" — the
            // one place this narrowing can come from, so it is named and
            // removable rather than a silent, unexplained shrink of the list.
            <span
              className="inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5"
              style={{ background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
              title={ruleLabels.join(', ')}
            >
              <Scale className="w-3 h-3 shrink-0" aria-hidden="true" />
              Policy filter · {ruleLabels.length} rule{ruleLabels.length === 1 ? '' : 's'}
              <button
                type="button"
                onClick={clearRuleFilter}
                aria-label="Clear policy filter"
                className="rounded-full p-0.5 hover:opacity-70"
              >
                <X className="w-2.5 h-2.5" aria-hidden="true" />
              </button>
            </span>
          )}
        </div>

        {/* Severity scale. The primary axis of this product, so it stays
            permanently visible rather than hiding behind a menu. Each option
            carries its own glyph, so the level is legible without the colour. */}
        <div className="flex items-center gap-0.5" role="group" aria-label="Filter by severity">
          {FILTER_BTNS.map(btn => {
            const meta = btn.value === 'all' ? null : SEVERITY_META[btn.value as Severity];
            const active = severityFilter === btn.value;
            return (
              <ToolButton
                key={btn.value}
                active={active}
                aria-pressed={active}
                onClick={() => setSeverityFilter(btn.value)}
                title={meta ? `${meta.label} — ${meta.meaning}` : 'All severities'}
              >
                {meta && (
                  <meta.Icon
                    className="w-3 h-3"
                    style={{ color: `var(--cs-sev-${btn.value})` }}
                    aria-hidden="true"
                  />
                )}
                {btn.label}
              </ToolButton>
            );
          })}
        </div>

        <div className="flex items-center gap-1 ml-auto">
          <RowDensityToggle density={density} onChange={setDensity} className="mr-1" />
          <ToolButton
            active={groupByRule}
            aria-pressed={groupByRule}
            onClick={() => setGroupByRule(v => !v)}
            title={groupByRule ? 'Showing one row per rule' : 'Collapse duplicate alerts into one row per rule'}
          >
            <Layers className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden xl:inline">{groupByRule ? 'Grouped' : 'Group'}</span>
          </ToolButton>
          <ToolButton
            active={showDismissed}
            aria-pressed={showDismissed}
            onClick={() => setShowDismissed(v => !v)}
            title={showDismissed ? 'Hide dismissed alerts' : 'Show dismissed alerts'}
          >
            {showDismissed ? <Eye className="w-3.5 h-3.5" aria-hidden="true" /> : <EyeOff className="w-3.5 h-3.5" aria-hidden="true" />}
            <span className="hidden xl:inline">Dismissed</span>
          </ToolButton>
          <ToolButton onClick={() => window.open('/api/alerts/export', '_blank')} title="Download every alert as JSON">
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden 2xl:inline">Export</span>
          </ToolButton>
          <ToolButton danger onClick={handleClear} title="Delete every alert — cannot be undone">
            <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden 2xl:inline">Clear</span>
          </ToolButton>
        </div>
      </div>

      {/* ── The list ───────────────────────────────────────────────────────── */}
      <DataTable
        rows={displayAlerts}
        columns={columns}
        rowKey={a => a.id}
        label="Alerts"
        density={density}
        minWidth={620}
        severity={a => normalizeSeverity(a.severity)}
        muted={a => !!pending[a.id] || !!a.dismissed}
        onActivate={a => setSelected(a)}
        renderDetail={renderJudge}
        loading={loading}
        error={loadError && displayAlerts.length === 0 ? (
          <ErrorState
            description={`The alert feed did not respond (${loadError}). Detection is unaffected — this is only the view.`}
            onRetry={() => { setLoading(true); fetchAlerts(); }}
          />
        ) : undefined}
        empty={ruleFilterActive ? (
          <EmptyState
            icon={<SearchX className="w-6 h-6" aria-hidden="true" />}
            title="No alerts for this policy"
            description="Nothing in the current window matches the rules this policy is backed by. Clear the policy filter above to see everything, or turn on Dismissed to include alerts already triaged."
          />
        ) : filtered ? (
          <EmptyState
            icon={<SearchX className="w-6 h-6" aria-hidden="true" />}
            title="Nothing matches this filter"
            description="No alerts at this severity. Widen the severity scale above, or turn on Dismissed to include alerts you have already triaged."
          />
        ) : (
          <EmptyState
            icon={<ShieldCheck className="w-6 h-6" aria-hidden="true" />}
            title="No threats detected"
            description="An alert lands here the moment an agent's command, file access or network call trips a detection rule. Nothing has tripped one yet."
          />
        )}
      />

      {/* In-place alert detail — opened by clicking or pressing Enter on a row.
          "Open in Timeline →" inside the drawer is the explicit, secondary path
          to the timeline. */}
      <AlertDetailDrawer
        alert={selected}
        onClose={() => setSelected(null)}
        onInvestigate={onInvestigate ? (traceId, spanId) => {
          setSelected(null);
          onInvestigate(traceId, spanId);
        } : undefined}
      />
    </div>
  );
}
