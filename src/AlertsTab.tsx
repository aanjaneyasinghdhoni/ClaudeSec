import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, Download, Trash2, ShieldOff, EyeOff, AlertCircle, Eye, Layers, Sparkles, Loader2, Undo2 } from 'lucide-react';
import { socket } from './socket';
import type { Severity } from './shared/types';
import { AlertDetailDrawer, type AlertDetail } from './AlertDetailDrawer';

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

const JUDGE_VERDICT_STYLE: Record<JudgeVerdict, string> = {
  malicious:  'bg-red-900/40 text-red-300 border border-red-700/50',
  suspicious: 'bg-orange-900/40 text-orange-300 border border-orange-700/50',
  benign:     'bg-emerald-900/30 text-emerald-300 border border-emerald-700/40',
};

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

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-rose-900/60 text-rose-200 border border-rose-500/60 animate-pulse',
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  none:   'bg-slate-800 text-slate-400',
};

const SEV_COUNT_COLOR: Record<string, string> = {
  critical: 'bg-rose-600 text-white',
  high:   'bg-red-600 text-white',
  medium: 'bg-orange-500 text-white',
  low:    'bg-yellow-500 text-black',
  none:   'bg-slate-600 text-white',
};

const FILTER_BTNS: { label: string; value: SeverityFilter }[] = [
  { label: 'All',      value: 'all'      },
  { label: 'Critical', value: 'critical' },
  { label: 'High',     value: 'high'     },
  { label: 'Medium',   value: 'medium'   },
  { label: 'Low',      value: 'low'      },
];

interface AlertsTabProps {
  // Navigate to the session that produced an alert and pre-select its span.
  // Optional with a safe no-op default so the tab still renders standalone.
  onInvestigate?: (traceId: string, spanId: string) => void;
}

export function AlertsTab({ onInvestigate }: AlertsTabProps = {}) {
  const [alerts,          setAlerts]          = useState<AlertRow[]>([]);
  const [total,           setTotal]           = useState(0);
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

  const fetchAlerts = (
    sev: SeverityFilter = severityFilter,
    sd  = showDismissed,
    grp = groupByRule,
  ) => {
    const params = new URLSearchParams({ limit: '200' });
    if (sev !== 'all') params.set('severity', sev);
    if (sd)  params.set('showDismissed', 'true');
    if (grp) params.set('groupBy', 'rule');
    fetch(`/api/alerts?${params}`)
      .then(r => r.json())
      .then(({ alerts: a, total: t }: { alerts: AlertRow[]; total: number }) => {
        setAlerts(a ?? []);
        setTotal(t ?? 0);
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchAlerts(severityFilter, showDismissed, groupByRule);
  }, [severityFilter, showDismissed, groupByRule]);

  useEffect(() => {
    const handler = () => fetchAlerts(severityFilter, showDismissed, groupByRule);
    socket.on('alerts-update', handler);
    return () => { socket.off('alerts-update', handler); };
  }, [severityFilter, showDismissed, groupByRule]);

  // Clear any in-flight undo timers when the component unmounts.
  useEffect(() => {
    const timers = undoTimers.current;
    return () => { for (const t of Object.values(timers)) clearTimeout(t); };
  }, []);

  const patchAlert = (id: number, body: { dismissed?: boolean; fp?: boolean; fingerprint?: string }) =>
    fetch(`/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

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
    } catch {}
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
    } catch {}
    finalizePending(id);
  };

  const handleClear = async () => {
    if (!window.confirm('Clear all alerts? This cannot be undone.')) return;
    await fetch('/api/alerts', { method: 'DELETE' });
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
      const r = await fetch('/api/judge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert.spanId ? { spanId: alert.spanId } : { text: alert.matchedText }),
      });
      const result = (await r.json()) as JudgeResult;
      setJudgeStates(prev => ({ ...prev, [alert.id]: { status: 'done', result } }));
    } catch {
      setJudgeStates(prev => ({ ...prev, [alert.id]: { status: 'error', message: 'Request failed' } }));
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
  const displayAlerts = [...alerts, ...lingering];

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ background: 'var(--cs-bg-primary)' }}>

      {/* Toolbar */}
      <div className="flex items-center gap-3 px-5 py-3 shrink-0 flex-wrap" style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-border)' }}>
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          <span className="text-sm font-bold" style={{ color: 'var(--cs-text-base)' }}>Alert Log</span>
          <span className="text-[11px] font-mono" style={{ color: 'var(--cs-text-faint)' }}>{total} total</span>
        </div>

        <div className="flex gap-1 ml-2">
          {FILTER_BTNS.map(btn => (
            <button
              key={btn.value}
              onClick={() => setSeverityFilter(btn.value)}
              className={`px-2.5 py-1 text-xs font-medium rounded-full transition-colors ${
                severityFilter === btn.value
                  ? ''
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
              style={severityFilter === btn.value ? { background: 'var(--cs-accent)', color: '#fff' } : undefined}
            >
              {btn.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          {/* Group by rule toggle */}
          <button
            onClick={() => setGroupByRule(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${
              groupByRule
                ? ''
                : 'bg-slate-800 border border-slate-700 text-slate-500 hover:text-slate-300 hover:bg-slate-700'
            }`}
            style={groupByRule ? { background: 'rgba(var(--cs-accent-rgb),0.1)', border: '1px solid rgba(var(--cs-accent-rgb),0.2)', color: 'var(--cs-accent)' } : undefined}
            title={groupByRule ? 'Showing grouped view' : 'Group duplicate alerts by rule'}
          >
            <Layers className="w-3.5 h-3.5" />
            {groupByRule ? 'Grouped' : 'Group'}
          </button>
          {/* Show/hide dismissed toggle */}
          <button
            onClick={() => setShowDismissed(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors ${
              showDismissed
                ? 'bg-slate-700 border-slate-600 text-slate-300'
                : 'bg-slate-800 border-slate-700 text-slate-500 hover:text-slate-300 hover:bg-slate-700'
            }`}
            title={showDismissed ? 'Hide dismissed alerts' : 'Show dismissed alerts'}
          >
            {showDismissed ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            Dismissed
          </button>
          <button
            onClick={() => window.open('/api/alerts/export', '_blank')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-xs text-slate-300 transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> Export JSON
          </button>
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-red-900/40 rounded-lg border border-slate-700 hover:border-red-700/40 text-xs text-slate-400 hover:text-red-400 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto p-4">
        {displayAlerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
            <ShieldOff className="w-8 h-8 text-slate-700" />
            <p className="text-sm font-medium text-slate-500">No alerts yet</p>
            <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
              Alerts appear here when a span matches a threat detection rule.
            </p>
          </div>
        ) : (
          <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}>
          <div className="overflow-x-auto">
          <table className="w-full text-xs min-w-[640px]">
            <thead className="sticky top-0 z-10" style={{ background: 'var(--cs-bg-elevated)' }}>
              <tr className="text-xs uppercase tracking-wider" style={{ color: 'var(--cs-text-muted)', borderBottom: '1px solid var(--cs-border)' }}>
                <th className="px-4 py-2.5 text-left">Time</th>
                <th className="px-4 py-2.5 text-left">Severity</th>
                <th className="px-4 py-2.5 text-left">Rule</th>
                <th className="px-4 py-2.5 text-left">Agent</th>
                <th className="px-4 py-2.5 text-left">Span Name</th>
                <th className="px-4 py-2.5 text-left">Snippet</th>
                <th className="px-4 py-2.5 text-left w-20">Triage</th>
              </tr>
            </thead>
            <tbody>
              {displayAlerts.map(alert => {
                const pend        = pending[alert.id];
                const isDismissed = !!alert.dismissed;
                const isFP        = !!alert.fp;
                const isTriaging  = triaging.has(alert.id);
                const hitCount    = alert.count ?? 1;
                const judgeState  = judgeStates[alert.id];
                // Clicking a row opens the detail drawer in place — matching the
                // panel's promise — instead of jumping away to the timeline. The
                // drawer offers an explicit "Open in Timeline →" action. The triage
                // cell stops propagation so its buttons don't open the drawer.
                const openDetail = () => setSelected(alert);
                return (
                  <React.Fragment key={alert.id}>
                  <tr
                    onClick={openDetail}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(); }
                    }}
                    title="View alert details"
                    className={`transition-colors cursor-pointer ${
                      pend || isDismissed
                        ? 'opacity-40 bg-slate-900/30'
                        : 'hover:bg-slate-800/30'
                    }`}
                    style={{ borderBottom: judgeState ? 'none' : '1px solid var(--cs-border)' }}
                  >
                    <td className="px-4 py-2.5 text-slate-500 font-mono whitespace-nowrap">
                      {formatTime(alert.ts)}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-xs font-mono uppercase ${SEV_BADGE[alert.severity] ?? SEV_BADGE.none}`}>
                          {alert.severity}
                        </span>
                        {hitCount > 1 && (
                          <span
                            className={`px-1.5 py-0.5 rounded-full text-[11px] font-bold tabular-nums ${SEV_COUNT_COLOR[alert.severity] ?? SEV_COUNT_COLOR.none}`}
                            title={`Fired ${hitCount} times`}
                          >
                            {hitCount}×
                          </span>
                        )}
                        {isFP && (
                          <span className="px-1.5 py-0.5 rounded text-[11px] font-bold bg-orange-900/30 text-orange-400 border border-orange-700/30">
                            FP
                          </span>
                        )}
                      </div>
                    </td>
                    <td className={`px-4 py-2.5 font-medium max-w-[180px] truncate ${isDismissed ? 'line-through text-slate-600' : 'text-slate-200'}`} title={alert.ruleLabel}>
                      {alert.ruleLabel}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ background: HARNESS_COLORS[alert.harness] ?? '#64748b' }}
                        />
                        <span className="text-slate-400 truncate max-w-[100px]" title={HARNESS_NAMES[alert.harness]}>
                          {HARNESS_NAMES[alert.harness] ?? alert.harness}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 max-w-[160px] truncate" title={alert.spanName}>
                      {alert.spanName}
                    </td>
                    <td className="px-4 py-2.5">
                      {alert.matchedText ? (
                        <code className="text-xs font-mono text-red-300 bg-red-900/20 px-1.5 py-0.5 rounded max-w-[200px] truncate block" title={alert.matchedText}>
                          {alert.matchedText}
                        </code>
                      ) : (
                        <span className="text-slate-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                      {pend ? (
                        // Undo window: confirm the action took, give a way back.
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] text-slate-500 whitespace-nowrap">
                            {pend.kind === 'fp' ? 'Marked FP' : 'Dismissed'}
                          </span>
                          <button
                            onClick={() => undoTriage(alert.id)}
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium text-sky-400 hover:bg-sky-900/30 hover:text-sky-300 transition-colors"
                            title="Undo"
                          >
                            <Undo2 className="w-3 h-3" /> Undo
                          </button>
                        </div>
                      ) : (
                      <div className="flex items-center gap-1">
                        {/* Analyze with LLM (only when the optional judge is configured) */}
                        {judgeEnabled && (
                          <button
                            disabled={judgeState?.status === 'loading'}
                            onClick={() => analyze(alert)}
                            className="p-1 rounded transition-colors text-violet-400 hover:bg-violet-900/30 hover:text-violet-300 disabled:opacity-50"
                            title="Analyze with LLM judge (semantic verdict)"
                          >
                            {judgeState?.status === 'loading'
                              ? <Loader2 className="w-3 h-3 animate-spin" />
                              : <Sparkles className="w-3 h-3" />}
                          </button>
                        )}
                        {/* Dismiss toggle */}
                        <button
                          disabled={isTriaging}
                          onClick={() => triage(alert, { dismissed: !isDismissed })}
                          className={`p-1 rounded transition-colors ${
                            isDismissed
                              ? 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                              : 'text-slate-500 hover:bg-slate-700 hover:text-slate-300'
                          }`}
                          title={isDismissed ? 'Restore alert' : 'Dismiss alert'}
                        >
                          <EyeOff className="w-3 h-3" />
                        </button>
                        {/* False-positive toggle */}
                        <button
                          disabled={isTriaging}
                          onClick={() => triage(alert, { fp: !isFP })}
                          className={`p-1 rounded transition-colors ${
                            isFP
                              ? 'bg-orange-900/40 text-orange-400 hover:bg-orange-900/60'
                              : 'text-slate-500 hover:bg-slate-700 hover:text-orange-400'
                          }`}
                          title={isFP ? 'Unmark false positive' : 'Mark as false positive'}
                        >
                          <AlertCircle className="w-3 h-3" />
                        </button>
                      </div>
                      )}
                    </td>
                  </tr>
                  {judgeState && (
                    <tr style={{ borderBottom: '1px solid var(--cs-border)' }}>
                      <td colSpan={7} className="px-4 pb-3 pt-0">
                        <div
                          className="rounded-lg px-3 py-2 text-xs flex flex-wrap items-center gap-x-3 gap-y-1.5"
                          style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)' }}
                        >
                          <span className="inline-flex items-center gap-1 text-violet-300 font-semibold shrink-0">
                            <Sparkles className="w-3 h-3" /> LLM judge
                          </span>
                          {judgeState.status === 'loading' && (
                            <span className="inline-flex items-center gap-1.5 text-slate-400">
                              <Loader2 className="w-3 h-3 animate-spin" /> Analyzing…
                            </span>
                          )}
                          {judgeState.status === 'error' && (
                            <span className="text-red-400">Request failed — {judgeState.message}</span>
                          )}
                          {judgeState.status === 'done' && (() => {
                            const r = judgeState.result;
                            if (!r.enabled) return <span className="text-slate-500">Judge not configured (set <code className="font-mono">CLAUDESEC_JUDGE_URL</code>).</span>;
                            if (!r.verdict) return <span className="text-amber-400">Judge unavailable — {r.error ?? 'no verdict'} <span className="text-slate-600">(fail-open: detection unaffected)</span></span>;
                            return (
                              <>
                                <span className={`px-1.5 py-0.5 rounded text-[11px] font-bold uppercase ${JUDGE_VERDICT_STYLE[r.verdict]}`}>
                                  {r.verdict}
                                </span>
                                {r.category && (
                                  <span className="font-mono text-slate-300">{r.category}</span>
                                )}
                                {typeof r.confidence === 'number' && (
                                  <span className="text-slate-500">conf {(r.confidence * 100).toFixed(0)}%</span>
                                )}
                                {r.reason && (
                                  <span className="text-slate-400 italic basis-full sm:basis-auto">“{r.reason}”</span>
                                )}
                                {r.model && (
                                  <span className="text-slate-600 ml-auto shrink-0">{r.model}</span>
                                )}
                              </>
                            );
                          })()}
                        </div>
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          </div>{/* overflow-x-auto */}
          </div>
        )}
      </div>

      {/* In-place alert detail — opened by clicking a row. "Open in Timeline →"
          inside the drawer is the explicit, secondary path to the timeline. */}
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
