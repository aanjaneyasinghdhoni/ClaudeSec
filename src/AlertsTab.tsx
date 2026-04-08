import React, { useEffect, useState } from 'react';
import { AlertTriangle, Download, Trash2, ShieldOff, EyeOff, AlertCircle, Eye, Layers } from 'lucide-react';
import { socket } from './socket';

type Severity = 'none' | 'low' | 'medium' | 'high';
type SeverityFilter = 'all' | 'high' | 'medium' | 'low';

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

const HARNESS_NAMES: Record<string, string> = {
  'claude-code':    'Claude Code',
  'github-copilot': 'GitHub Copilot',
  'openhands':      'OpenHands',
  'cursor':         'Cursor',
  'aider':          'Aider',
  'cline':          'Cline',
  'goose':          'Goose',
  'continue':       'Continue.dev',
  'windsurf':       'Windsurf',
  'codex':          'Codex CLI',
  'amazon-q':       'Amazon Q',
  'gemini-cli':     'Gemini CLI',
  'roo-code':       'Roo-Code',
  'bolt':           'Bolt.new',
  'unknown':        'Unknown',
};

const SEV_BADGE: Record<string, string> = {
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  none:   'bg-slate-800 text-slate-400',
};

const SEV_COUNT_COLOR: Record<string, string> = {
  high:   'bg-red-600 text-white',
  medium: 'bg-orange-500 text-white',
  low:    'bg-yellow-500 text-black',
  none:   'bg-slate-600 text-white',
};

const FILTER_BTNS: { label: string; value: SeverityFilter }[] = [
  { label: 'All',    value: 'all'    },
  { label: 'High',   value: 'high'   },
  { label: 'Medium', value: 'medium' },
  { label: 'Low',    value: 'low'    },
];

export function AlertsTab() {
  const [alerts,          setAlerts]          = useState<AlertRow[]>([]);
  const [total,           setTotal]           = useState(0);
  const [severityFilter,  setSeverityFilter]  = useState<SeverityFilter>('all');
  const [showDismissed,   setShowDismissed]   = useState(false);
  const [groupByRule,     setGroupByRule]     = useState(false);
  const [triaging,        setTriaging]        = useState<Set<number>>(new Set());

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

  const triage = async (id: number, patch: { dismissed?: boolean; fp?: boolean }) => {
    setTriaging(prev => new Set(prev).add(id));
    try {
      await fetch(`/api/alerts/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      fetchAlerts(severityFilter, showDismissed, groupByRule);
    } catch {}
    setTriaging(prev => { const s = new Set(prev); s.delete(id); return s; });
  };

  const handleClear = async () => {
    if (!window.confirm('Clear all alerts? This cannot be undone.')) return;
    await fetch('/api/alerts', { method: 'DELETE' });
  };

  const formatTime = (ts: string) => {
    try { return new Date(ts).toLocaleTimeString(); }
    catch { return ts; }
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-slate-950">

      {/* Toolbar */}
      <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-800 bg-slate-900/40 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          <span className="text-sm font-bold text-slate-200">Alert Log</span>
          <span className="text-[11px] font-mono text-slate-500">{total} total</span>
        </div>

        <div className="flex gap-1 ml-2">
          {FILTER_BTNS.map(btn => (
            <button
              key={btn.value}
              onClick={() => setSeverityFilter(btn.value)}
              className={`px-2.5 py-1 text-[10px] font-medium rounded-full transition-colors ${
                severityFilter === btn.value
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              {btn.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          {/* Group by rule toggle */}
          <button
            onClick={() => setGroupByRule(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors ${
              groupByRule
                ? 'bg-blue-900/30 border-blue-700/40 text-blue-400'
                : 'bg-slate-800 border-slate-700 text-slate-500 hover:text-slate-300 hover:bg-slate-700'
            }`}
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
      <div className="flex-1 overflow-auto">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
            <ShieldOff className="w-8 h-8 text-slate-700" />
            <p className="text-sm font-medium text-slate-500">No alerts yet</p>
            <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
              Alerts appear here when a span matches a threat detection rule.
            </p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-900/90 backdrop-blur-sm z-10">
              <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
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
              {alerts.map(alert => {
                const isDismissed = !!alert.dismissed;
                const isFP        = !!alert.fp;
                const isTriaging  = triaging.has(alert.id);
                const hitCount    = alert.count ?? 1;
                return (
                  <tr
                    key={alert.id}
                    className={`border-b border-slate-800/50 transition-colors ${
                      isDismissed
                        ? 'opacity-40 bg-slate-900/30'
                        : 'hover:bg-slate-800/30'
                    }`}
                  >
                    <td className="px-4 py-2.5 text-slate-500 font-mono whitespace-nowrap">
                      {formatTime(alert.ts)}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${SEV_BADGE[alert.severity] ?? SEV_BADGE.none}`}>
                          {alert.severity}
                        </span>
                        {hitCount > 1 && (
                          <span
                            className={`px-1.5 py-0.5 rounded-full text-[9px] font-bold tabular-nums ${SEV_COUNT_COLOR[alert.severity] ?? SEV_COUNT_COLOR.none}`}
                            title={`Fired ${hitCount} times`}
                          >
                            {hitCount}×
                          </span>
                        )}
                        {isFP && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-orange-900/30 text-orange-400 border border-orange-700/30">
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
                        <code className="text-[10px] font-mono text-red-300 bg-red-900/20 px-1.5 py-0.5 rounded max-w-[200px] truncate block" title={alert.matchedText}>
                          {alert.matchedText}
                        </code>
                      ) : (
                        <span className="text-slate-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1">
                        {/* Dismiss toggle */}
                        <button
                          disabled={isTriaging}
                          onClick={() => triage(alert.id, { dismissed: !isDismissed })}
                          className={`p-1 rounded transition-colors ${
                            isDismissed
                              ? 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                              : 'text-slate-600 hover:bg-slate-700 hover:text-slate-300'
                          }`}
                          title={isDismissed ? 'Restore alert' : 'Dismiss alert'}
                        >
                          <EyeOff className="w-3 h-3" />
                        </button>
                        {/* False-positive toggle */}
                        <button
                          disabled={isTriaging}
                          onClick={() => triage(alert.id, { fp: !isFP })}
                          className={`p-1 rounded transition-colors ${
                            isFP
                              ? 'bg-orange-900/40 text-orange-400 hover:bg-orange-900/60'
                              : 'text-slate-600 hover:bg-slate-700 hover:text-orange-400'
                          }`}
                          title={isFP ? 'Unmark false positive' : 'Mark as false positive'}
                        >
                          <AlertCircle className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
