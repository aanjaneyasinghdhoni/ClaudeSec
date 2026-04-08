import React, { useEffect, useState } from 'react';
import { DollarSign, TrendingUp, Cpu, HelpCircle, Webhook, CheckCircle, XCircle, AlertTriangle, Database, Trash2, RefreshCw } from 'lucide-react';
import { socket } from './socket';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SessionCost {
  traceId:     string;
  sessionName: string;
  harness:     string;
  model:       string;
  modelLabel:  string;
  tokensIn:    number;
  tokensOut:   number;
  costUsd:     number;
  knownPrice:  boolean;
}

interface ModelSummary {
  model:      string;
  label:      string;
  tokensIn:   number;
  tokensOut:  number;
  costUsd:    number;
  knownPrice: boolean;
}

interface CostData {
  sessions:       SessionCost[];
  models:         ModelSummary[];
  totalCostUsd:   number;
  totalTokensIn:  number;
  totalTokensOut: number;
}

interface WebhookStatus {
  configured:  boolean;
  urlPreview:  string | null;
  threshold:   string;
  envOverride: boolean;
}

// ── Constants ─────────────────────────────────────────────────────────────────

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
  'unknown':        '#64748b',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function formatCost(usd: number): string {
  if (usd === 0)   return '$0.00';
  if (usd < 0.001) return `$${(usd * 1000).toFixed(4)}m`; // milli-dollars
  if (usd < 0.01)  return `$${usd.toFixed(4)}`;
  if (usd < 1)     return `$${usd.toFixed(3)}`;
  return `$${usd.toFixed(2)}`;
}

// ── Cost bar ──────────────────────────────────────────────────────────────────

function CostBar({ value, max, color = '#3b82f6' }: { value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--cs-border)' }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  );
}

// ── Webhook panel ─────────────────────────────────────────────────────────────

function WebhookPanel() {
  const [status, setStatus] = useState<WebhookStatus | null>(null);
  const [newUrl, setNewUrl]         = useState('');
  const [threshold, setThreshold]   = useState('high');
  const [saving, setSaving]         = useState(false);
  const [testing, setTesting]       = useState(false);
  const [testResult, setTestResult] = useState<'ok' | 'error' | null>(null);
  const [error, setError]           = useState('');

  const load = () =>
    fetch('/api/webhook').then(r => r.json()).then(setStatus).catch(() => {});

  useEffect(() => { load(); }, []);

  const save = async () => {
    if (!newUrl.trim()) return;
    setSaving(true);
    setError('');
    try {
      const r = await fetch('/api/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: newUrl.trim(), threshold }),
      });
      if (r.ok) { setNewUrl(''); load(); }
      else { const d = await r.json(); setError(d.error ?? 'Unknown error'); }
    } catch { setError('Network error'); }
    setSaving(false);
  };

  const remove = async () => {
    const r = await fetch('/api/webhook', { method: 'DELETE' });
    if (r.ok) load(); else { const d = await r.json(); setError(d.error ?? 'Unknown error'); }
  };

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await fetch('/api/webhook/test', { method: 'POST' });
      setTestResult(r.ok ? 'ok' : 'error');
    } catch { setTestResult('error'); }
    setTesting(false);
    setTimeout(() => setTestResult(null), 4000);
  };

  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
      <div className="flex items-center gap-2 mb-3">
        <Webhook className="w-4 h-4 text-slate-400" />
        <span className="text-xs font-bold text-slate-300">Webhook Alerts</span>
        {status?.configured ? (
          <span className="ml-auto flex items-center gap-1 text-xs text-green-400">
            <CheckCircle className="w-3 h-3" /> Configured
          </span>
        ) : (
          <span className="ml-auto flex items-center gap-1 text-xs text-slate-600">
            <XCircle className="w-3 h-3" /> Not set
          </span>
        )}
      </div>

      {status?.configured && (
        <div className="mb-3 p-2 bg-slate-800 rounded-lg text-xs">
          <div className="flex items-center justify-between">
            <code className="text-slate-400 font-mono truncate max-w-[200px]">{status.urlPreview}</code>
            <span className="ml-2 px-1.5 py-0.5 rounded font-mono uppercase text-[11px]
              bg-slate-700 text-slate-400">
              threshold: {status.threshold}
            </span>
          </div>
          {status.envOverride && (
            <p className="mt-1 text-slate-600 text-[11px]">Set via CLAUDESEC_WEBHOOK_URL env var</p>
          )}
          {!status.envOverride && (
            <div className="mt-2 flex items-center gap-2">
              <button
                onClick={test}
                disabled={testing}
                className="px-2 py-1 text-xs rounded border border-blue-800 transition-colors disabled:opacity-50"
                style={{ background: 'rgba(0,212,170,0.12)', color: '#00d4aa' }}
              >
                {testing ? 'Sending…' : 'Test'}
              </button>
              {testResult === 'ok'    && <span className="text-green-400 text-xs">Delivered!</span>}
              {testResult === 'error' && <span className="text-red-400 text-xs">Failed</span>}
              <button
                onClick={remove}
                className="ml-auto px-2 py-1 text-xs bg-red-600/10 hover:bg-red-600/20 text-red-400 rounded border border-red-900 transition-colors"
              >
                Remove
              </button>
            </div>
          )}
        </div>
      )}

      {!status?.configured && !status?.envOverride && (
        <div className="space-y-2">
          <input
            type="url"
            value={newUrl}
            onChange={e => setNewUrl(e.target.value)}
            placeholder="https://hooks.slack.com/… or Discord webhook URL"
            className="w-full px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded text-[11px] text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
            style={{ '--tw-ring-color': '#00d4aa' } as React.CSSProperties}
            onFocus={e => e.currentTarget.style.borderColor = '#00d4aa'}
            onBlur={e => e.currentTarget.style.borderColor = ''}
          />
          <div className="flex items-center gap-2">
            <select
              value={threshold}
              onChange={e => setThreshold(e.target.value)}
              className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 focus:outline-none"
            >
              <option value="high">HIGH only</option>
              <option value="medium">MEDIUM+</option>
              <option value="low">All alerts</option>
            </select>
            <button
              onClick={save}
              disabled={saving || !newUrl.trim()}
              className="px-6 py-1.5 text-white text-xs font-medium rounded transition-colors disabled:opacity-50"
              style={{ background: '#00d4aa' }}
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
          {error && <p className="text-red-400 text-xs">{error}</p>}
          <p className="text-[11px] text-slate-600">
            Supports Slack, Discord, and any generic JSON endpoint.
            Also set via <code className="font-mono bg-slate-800 px-1 rounded">CLAUDESEC_WEBHOOK_URL</code>.
          </p>
        </div>
      )}
    </div>
  );
}

// ── DB Health Panel ───────────────────────────────────────────────────────────

interface DBStats {
  spansTotal:    number;
  sessionsTotal: number;
  alertsTotal:   number;
  dbSizeHuman:   string;
  dbSizeBytes:   number;
  oldestSession: string | null;
  retentionConfig: { maxSpans: number; retentionDays: number };
}

function DBHealthPanel() {
  const [stats, setStats]         = useState<DBStats | null>(null);
  const [pruning, setPruning]     = useState(false);
  const [pruneResult, setPruneResult] = useState<{ prunedByAge: number; prunedByCount: number } | null>(null);
  const [editing, setEditing]     = useState(false);
  const [maxSpans, setMaxSpans]   = useState('');
  const [retDays, setRetDays]     = useState('');

  const load = () =>
    fetch('/api/db-stats').then(r => r.json()).then((d: DBStats) => {
      setStats(d);
      setMaxSpans(String(d.retentionConfig.maxSpans));
      setRetDays(String(d.retentionConfig.retentionDays));
    }).catch(() => {});

  useEffect(() => { load(); }, []);

  const prune = async () => {
    setPruning(true);
    const r = await fetch('/api/db-stats/prune', { method: 'POST' });
    const result = await r.json();
    setPruneResult(result);
    setTimeout(() => setPruneResult(null), 5000);
    load();
    setPruning(false);
  };

  const saveRetention = async () => {
    await fetch('/api/db-stats/retention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxSpans: Number(maxSpans), retentionDays: Number(retDays) }),
    });
    setEditing(false);
    load();
  };

  if (!stats) return null;

  const usagePct = Math.min(100, Math.round((stats.spansTotal / stats.retentionConfig.maxSpans) * 100));
  const barColor = usagePct > 85 ? '#ef4444' : usagePct > 60 ? '#f97316' : '#22c55e';

  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
      <div className="flex items-center gap-2 mb-3">
        <Database className="w-4 h-4 text-slate-400" />
        <span className="text-xs font-bold text-slate-300">Database Health</span>
        <button onClick={load} className="ml-auto text-slate-600 hover:text-slate-400 transition-colors">
          <RefreshCw className="w-3 h-3" />
        </button>
      </div>

      <div className="grid grid-cols-3 gap-2 mb-3 text-center">
        {([
          { val: stats.spansTotal.toLocaleString(),    label: 'Spans',    color: '', inlineColor: '#00d4aa' },
          { val: stats.sessionsTotal.toLocaleString(),  label: 'Sessions', color: 'text-purple-400' },
          { val: stats.dbSizeHuman,                    label: 'DB Size',  color: 'text-orange-400' },
        ] as Array<{ val: string; label: string; color: string; inlineColor?: string }>).map(c => (
          <div key={c.label} className="bg-slate-800 rounded-lg p-2">
            <div className={`text-sm font-bold font-mono ${c.color}`} style={c.inlineColor ? { color: c.inlineColor } : undefined}>{c.val}</div>
            <div className="text-[11px] text-slate-600 uppercase tracking-wider mt-0.5">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Span usage bar */}
      <div className="mb-3">
        <div className="flex items-center justify-between mb-1">
          <span className="text-[11px] text-slate-600">
            {stats.spansTotal.toLocaleString()} / {stats.retentionConfig.maxSpans.toLocaleString()} max spans
          </span>
          <span className="text-[11px] font-mono" style={{ color: barColor }}>{usagePct}%</span>
        </div>
        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${usagePct}%`, background: barColor }} />
        </div>
      </div>

      {/* Retention config */}
      {!editing ? (
        <div className="flex items-center justify-between text-xs text-slate-500 mb-3">
          <span>Retention: {stats.retentionConfig.retentionDays}d · max {stats.retentionConfig.maxSpans.toLocaleString()} spans</span>
          <button onClick={() => setEditing(true)} className="transition-colors hover:opacity-80" style={{ color: '#00d4aa' }}>Edit</button>
        </div>
      ) : (
        <div className="mb-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500 w-20">Max spans</label>
            <input type="number" value={maxSpans} onChange={e => setMaxSpans(e.target.value)}
              className="flex-1 px-2 py-1 bg-slate-800 border border-slate-700 rounded text-[11px] text-slate-200 focus:outline-none" />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500 w-20">Days to keep</label>
            <input type="number" value={retDays} onChange={e => setRetDays(e.target.value)}
              className="flex-1 px-2 py-1 bg-slate-800 border border-slate-700 rounded text-[11px] text-slate-200 focus:outline-none" />
          </div>
          <div className="flex gap-2">
            <button onClick={saveRetention}
              className="flex-1 py-1 text-white text-xs rounded transition-colors"
              style={{ background: '#00d4aa' }}>
              Save
            </button>
            <button onClick={() => setEditing(false)}
              className="flex-1 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded transition-colors">
              Cancel
            </button>
          </div>
        </div>
      )}

      <button
        onClick={prune}
        disabled={pruning}
        className="w-full flex items-center justify-center gap-1.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs rounded border border-slate-700 transition-colors disabled:opacity-50"
      >
        <Trash2 className="w-3 h-3" /> {pruning ? 'Pruning…' : 'Run manual prune'}
      </button>

      {pruneResult && (
        <p className="mt-1.5 text-xs text-green-400 text-center">
          Pruned {pruneResult.prunedByAge} by age + {pruneResult.prunedByCount} by count
        </p>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function CostTab() {
  const [data, setData]   = useState<CostData | null>(null);
  const [view, setView]   = useState<'sessions' | 'models'>('models');

  const load = () =>
    fetch('/api/costs').then(r => r.json()).then(setData).catch(() => {});

  useEffect(() => {
    load();
    socket.on('graph-update', load);
    socket.on('span-added', load);
    return () => { socket.off('graph-update', load); socket.off('span-added', load); };
  }, []);

  const hasData = data && (data.totalTokensIn + data.totalTokensOut) > 0;
  const maxSessionCost = data ? Math.max(0.000001, ...data.sessions.map(s => s.costUsd)) : 0;
  const maxModelCost   = data ? Math.max(0.000001, ...data.models.map(m => m.costUsd))   : 0;

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-auto" style={{ background: 'var(--cs-bg-primary)' }}>

      {/* ── Summary cards ── */}
      <div className="shrink-0 p-4" style={{ borderBottom: '1px solid var(--cs-border)' }}>
        <div className="flex items-center gap-1.5 mb-3">
          <DollarSign className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Token Cost Estimator</span>
          <span className="ml-auto text-[11px] text-slate-700">approximate — based on public pricing</span>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {([
            {
              label: 'Total Cost',
              value: formatCost(data?.totalCostUsd ?? 0),
              icon: <DollarSign className="w-3.5 h-3.5" />,
              color: 'text-green-400',
              bg:    'bg-green-500/10',
            },
            {
              label: 'Input Tokens',
              value: formatTokens(data?.totalTokensIn ?? 0),
              icon: <TrendingUp className="w-3.5 h-3.5" />,
              color: '',
              bg:    '',
              inlineColor: '#00d4aa',
              inlineBg: 'rgba(0,212,170,0.1)',
            },
            {
              label: 'Output Tokens',
              value: formatTokens(data?.totalTokensOut ?? 0),
              icon: <TrendingUp className="w-3.5 h-3.5 rotate-180" />,
              color: 'text-purple-400',
              bg:    'bg-purple-500/10',
            },
            {
              label: 'Sessions',
              value: String(new Set(data?.sessions.map(s => s.traceId) ?? []).size),
              icon: <Cpu className="w-3.5 h-3.5" />,
              color: 'text-orange-400',
              bg:    'bg-orange-500/10',
            },
          ] as Array<{ label: string; value: string; icon: React.ReactNode; color: string; bg: string; inlineColor?: string; inlineBg?: string }>).map(card => (
            <div key={card.label} className={`${card.bg} rounded-xl p-3`} style={card.inlineBg ? { background: card.inlineBg, border: '1px solid var(--cs-border)' } : { border: '1px solid var(--cs-border)' }}>
              <div className={`${card.color} mb-1`} style={card.inlineColor ? { color: card.inlineColor } : undefined}>{card.icon}</div>
              <div className={`text-lg font-bold font-mono ${card.color}`} style={card.inlineColor ? { color: card.inlineColor } : undefined}>{card.value}</div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider mt-0.5">{card.label}</div>
            </div>
          ))}
        </div>
      </div>

      {!hasData ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-slate-700 p-8">
          <DollarSign className="w-10 h-10" />
          <p className="text-sm text-slate-500 font-medium">No token data yet</p>
          <p className="text-xs text-slate-600 text-center max-w-xs leading-relaxed">
            Costs appear when spans include{' '}
            <code className="font-mono bg-slate-800 px-1 rounded text-slate-400">gen_ai.usage.input_tokens</code>{' '}
            and{' '}
            <code className="font-mono bg-slate-800 px-1 rounded text-slate-400">gen_ai.request.model</code>.
          </p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col p-5 gap-4 min-h-0 overflow-auto">

          {/* View toggle */}
          <div className="flex items-center gap-2">
            <div className="flex bg-slate-800 rounded-lg p-0.5">
              <button
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${view === 'models' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                onClick={() => setView('models')}
              >
                By Model
              </button>
              <button
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${view === 'sessions' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                onClick={() => setView('sessions')}
              >
                By Session
              </button>
            </div>
            <div className="ml-auto flex items-center gap-1 text-[11px] text-slate-600">
              <HelpCircle className="w-3 h-3" />
              Pricing may not reflect current rates
            </div>
          </div>

          {/* Models view */}
          {view === 'models' && (
            <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-xs text-slate-500 uppercase tracking-wider" style={{ borderBottom: '1px solid var(--cs-border)' }}>
                    <th className="px-4 py-2.5 text-left">Model</th>
                    <th className="px-4 py-2.5 text-right">Input</th>
                    <th className="px-4 py-2.5 text-right">Output</th>
                    <th className="px-4 py-2.5 text-right">Cost</th>
                    <th className="px-4 py-2.5 w-24"></th>
                  </tr>
                </thead>
                <tbody>
                  {data.models.map(m => (
                    <tr key={m.model} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <code className="text-slate-200 text-[11px] font-mono">{m.label}</code>
                          {!m.knownPrice && (
                            <span title="No pricing data for this model" className="text-slate-600 cursor-help">
                              <HelpCircle className="w-3 h-3" />
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-400 text-[11px]">
                        {formatTokens(m.tokensIn)}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-400 text-[11px]">
                        {formatTokens(m.tokensOut)}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono font-medium text-green-300 text-[11px]">
                        {formatCost(m.costUsd)}
                      </td>
                      <td className="px-4 py-2.5">
                        <CostBar value={m.costUsd} max={maxModelCost} color="#22c55e" />
                      </td>
                    </tr>
                  ))}
                  <tr className="border-t-2 border-slate-700 bg-slate-800/30">
                    <td className="px-4 py-2.5 font-bold text-slate-300 text-[11px]">Total</td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-300 text-[11px]">
                      {formatTokens(data.totalTokensIn)}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-300 text-[11px]">
                      {formatTokens(data.totalTokensOut)}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono font-bold text-green-300 text-[11px]">
                      {formatCost(data.totalCostUsd)}
                    </td>
                    <td />
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* Sessions view */}
          {view === 'sessions' && (
            <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-xs text-slate-500 uppercase tracking-wider" style={{ borderBottom: '1px solid var(--cs-border)' }}>
                    <th className="px-4 py-2.5 text-left">Session</th>
                    <th className="px-4 py-2.5 text-left">Model</th>
                    <th className="px-4 py-2.5 text-right">Input</th>
                    <th className="px-4 py-2.5 text-right">Output</th>
                    <th className="px-4 py-2.5 text-right">Cost</th>
                    <th className="px-4 py-2.5 w-20"></th>
                  </tr>
                </thead>
                <tbody>
                  {data.sessions.map((s, i) => {
                    const color = HARNESS_COLORS[s.harness] ?? '#64748b';
                    return (
                      <tr key={`${s.traceId}-${s.model}-${i}`} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
                            <span className="text-slate-300 text-[11px] truncate max-w-[120px]" title={s.sessionName}>
                              {s.sessionName}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-2.5">
                          <code className="text-slate-400 text-xs font-mono">{s.modelLabel}</code>
                          {!s.knownPrice && <span className="ml-1 text-slate-700 text-[11px]">(?)</span>}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono text-slate-400 text-[11px]">
                          {formatTokens(s.tokensIn)}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono text-slate-400 text-[11px]">
                          {formatTokens(s.tokensOut)}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono font-medium text-green-300 text-[11px]">
                          {formatCost(s.costUsd)}
                        </td>
                        <td className="px-4 py-2.5">
                          <CostBar value={s.costUsd} max={maxSessionCost} color={color} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Webhook panel */}
          <WebhookPanel />

          {/* DB Health panel */}
          <DBHealthPanel />

          {/* Pricing disclaimer */}
          <div className="flex items-start gap-2 p-3 rounded-xl text-xs text-slate-600" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
            <AlertTriangle className="w-3.5 h-3.5 text-yellow-700 shrink-0 mt-0.5" />
            <p>
              Cost estimates are approximate and based on publicly available pricing.
              Prices vary by region, tier, and caching. Tokens are aggregated from{' '}
              <code className="font-mono">gen_ai.usage.input_tokens</code> /{' '}
              <code className="font-mono">gen_ai.usage.output_tokens</code> span attributes.
              Models without pricing data show 0 cost.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
