/**
 * CostTab — token spend and model breakdown.
 *
 * A prior audit called this tab "pure Inform": no budget, no forecast, no
 * anomaly surface. That is deliberate, not a gap to fill — a parallel fix is
 * landing for a confirmed input-token inflation bug, so the numbers on screen
 * right now are provisional. Nothing here should be built to depend on today's
 * totals being correct; the job is to show what the server reports, clearly
 * and honestly, not to editorialize on top of it.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { DollarSign, TrendingUp, Cpu, HelpCircle, Webhook, CheckCircle, XCircle, AlertTriangle, Database, Trash2, RefreshCw, Info } from 'lucide-react';
import { socket } from './socket';
import { ExperimentalBadge } from './ExperimentalBadge';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import { formatTokens } from './lib/format';
import {
  DataTable, type DataColumn,
  Toolbar, ToolButton, ToolbarTitle,
  EmptyState, ErrorState,
  useRowDensity,
} from './components/data';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SessionCost {
  traceId:     string;
  sessionName: string;
  harness:     string;
  model:       string;
  modelLabel:  string;
  tokensIn:    number;
  tokensOut:   number;
  cacheReadTokens:  number;
  cacheWriteTokens: number;
  costUsd:     number;
  knownPrice:  boolean;
  inferred?:   boolean;
}

interface ModelSummary {
  model:      string;
  label:      string;
  tokensIn:   number;
  tokensOut:  number;
  cacheReadTokens:  number;
  cacheWriteTokens: number;
  costUsd:    number;
  knownPrice: boolean;
  inferred?:  boolean;
}

interface CostData {
  sessions:       SessionCost[];
  models:         ModelSummary[];
  totalCostUsd:   number;
  totalTokensIn:  number;
  totalTokensOut: number;
  totalCacheReadTokens:  number;
  totalCacheWriteTokens: number;
}

interface WebhookStatus {
  configured:  boolean;
  urlPreview:  string | null;
  threshold:   string;
  envOverride: boolean;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// The agent's identity colour — fixed hue per harness, same set as every
// other tab. Identity, not risk, so it stays outside the severity ramp.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

type PlanId = 'api' | 'pro' | 'max5x' | 'max20x';

interface PlanOption {
  id:    PlanId;
  label: string;
  price: number | null;
}

const PLAN_OPTIONS: PlanOption[] = [
  { id: 'api',    label: 'API (pay-per-token)', price: null },
  { id: 'pro',    label: 'Pro — $20/mo',        price: 20   },
  { id: 'max5x',  label: 'Max 5× — $100/mo',    price: 100  },
  { id: 'max20x', label: 'Max 20× — $200/mo',   price: 200  },
];

const PLAN_STORAGE_KEY = 'claudesec.plan';

function loadPlan(): PlanId {
  try {
    const v = localStorage.getItem(PLAN_STORAGE_KEY);
    if (v && PLAN_OPTIONS.some(p => p.id === v)) return v as PlanId;
  } catch {}
  return 'api';
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatCost(usd: number): string {
  if (usd === 0)   return '$0.00';
  if (usd < 0.001) return `$${(usd * 1000).toFixed(4)}m`; // milli-dollars
  if (usd < 0.01)  return `$${usd.toFixed(4)}`;
  if (usd < 1)     return `$${usd.toFixed(3)}`;
  return `$${usd.toFixed(2)}`;
}

// A tiny inline "inferred" flag — the model name came from the agent type,
// not from telemetry, so the actual model may differ. Neutral, not a warning.
function InferredFlag() {
  return (
    <span
      title="Model inferred from agent type. Actual model may differ."
      className="ml-1 px-1 py-0.5 rounded uppercase cursor-help shrink-0"
      style={{ fontSize: '9px', color: 'var(--cs-sev-medium-fg)', background: 'var(--cs-sev-medium-bg)' }}
    >
      inferred
    </span>
  );
}

// ── Cost bar ──────────────────────────────────────────────────────────────────

function CostBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <span className="flex-1 h-1 rounded-full overflow-hidden block" style={{ background: 'var(--cs-bg-raised)' }}>
      <span className="h-full rounded-full block transition-all duration-500" style={{ width: `${pct}%`, background: 'var(--cs-accent)' }} />
    </span>
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
    <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
      <div className="flex items-center gap-2 mb-3">
        <Webhook className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
        <span className="cs-eyebrow">Webhook alerts</span>
        {status?.configured ? (
          <span className="ml-auto inline-flex items-center gap-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-accent)' }}>
            <CheckCircle className="w-3 h-3" aria-hidden="true" /> Configured
          </span>
        ) : (
          <span className="ml-auto inline-flex items-center gap-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            <XCircle className="w-3 h-3" aria-hidden="true" /> Not set
          </span>
        )}
      </div>

      {status?.configured && (
        <div className="mb-3 p-2 rounded-md" style={{ background: 'var(--cs-bg-sunken)', fontSize: 'var(--cs-text-xs)' }}>
          <div className="flex items-center justify-between gap-2">
            <code className="cs-mono truncate max-w-[220px]" style={{ color: 'var(--cs-text-muted)' }}>{status.urlPreview}</code>
            <span
              className="cs-mono uppercase px-1.5 py-0.5 rounded shrink-0"
              style={{ fontSize: 'var(--cs-text-2xs)', background: 'var(--cs-bg-raised)', color: 'var(--cs-text-faint)' }}
            >
              threshold: {status.threshold}
            </span>
          </div>
          {status.envOverride && (
            <p className="mt-1" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
              Set via CLAUDESEC_WEBHOOK_URL env var
            </p>
          )}
          {!status.envOverride && (
            <div className="mt-2 flex items-center gap-2">
              <button
                type="button"
                onClick={test}
                disabled={testing}
                className="px-2 py-1 rounded-md transition-colors disabled:opacity-50"
                style={{ fontSize: 'var(--cs-text-xs)', background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)' }}
              >
                {testing ? 'Sending…' : 'Test'}
              </button>
              {testResult === 'ok'    && <span style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}>Delivered</span>}
              {testResult === 'error' && <span style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-xs)' }}>Failed</span>}
              <button
                type="button"
                onClick={remove}
                className="ml-auto px-2 py-1 rounded-md transition-colors"
                style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-sev-critical-fg)' }}
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
            className="w-full px-2.5 py-1.5 rounded-md outline-none cs-mono"
            style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }}
          />
          <div className="flex items-center gap-2">
            <select
              value={threshold}
              onChange={e => setThreshold(e.target.value)}
              className="px-2 py-1 rounded-md outline-none"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}
            >
              <option value="critical">Critical only</option>
              <option value="high">High+</option>
              <option value="medium">Medium+</option>
              <option value="low">All alerts</option>
            </select>
            <button
              type="button"
              onClick={save}
              disabled={saving || !newUrl.trim()}
              className="px-6 py-1.5 rounded-md transition-colors disabled:opacity-50"
              style={{ background: 'var(--cs-accent)', color: 'var(--cs-text-invert)', fontSize: 'var(--cs-text-xs)', fontWeight: 'var(--cs-weight-medium)' }}
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
          {error && <p style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-xs)' }}>{error}</p>}
          <p style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
            Supports Slack, Discord, and any generic JSON endpoint. Also set via{' '}
            <code className="cs-mono">CLAUDESEC_WEBHOOK_URL</code>.
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
  const barColor = usagePct > 85 ? 'var(--cs-sev-critical)' : usagePct > 60 ? 'var(--cs-sev-medium)' : 'var(--cs-accent)';

  return (
    <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
      <div className="flex items-center gap-2 mb-3">
        <Database className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
        <span className="cs-eyebrow">Database health</span>
        <button type="button" onClick={load} className="ml-auto transition-colors" style={{ color: 'var(--cs-text-faint)' }} title="Refresh">
          <RefreshCw className="w-3 h-3" aria-hidden="true" />
        </button>
      </div>

      <div className="grid grid-cols-3 gap-2 mb-3 text-center">
        {([
          { val: stats.spansTotal.toLocaleString(),    label: 'Spans'    },
          { val: stats.sessionsTotal.toLocaleString(),  label: 'Sessions' },
          { val: stats.dbSizeHuman,                    label: 'DB size'  },
        ]).map(c => (
          <div key={c.label} className="rounded-md p-2" style={{ background: 'var(--cs-bg-raised)' }}>
            <div className="cs-mono" style={{ fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>{c.val}</div>
            <div className="cs-eyebrow mt-0.5">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="mb-3">
        <div className="flex items-center justify-between mb-1">
          <span style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
            {stats.spansTotal.toLocaleString()} / {stats.retentionConfig.maxSpans.toLocaleString()} max spans
          </span>
          <span className="cs-mono" style={{ fontSize: 'var(--cs-text-2xs)', color: barColor }}>{usagePct}%</span>
        </div>
        <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--cs-bg-raised)' }}>
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${usagePct}%`, background: barColor }} />
        </div>
      </div>

      {!editing ? (
        <div className="flex items-center justify-between mb-3" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>
          <span>Retention: {stats.retentionConfig.retentionDays}d · max {stats.retentionConfig.maxSpans.toLocaleString()} spans</span>
          <button type="button" onClick={() => setEditing(true)} className="transition-colors hover:opacity-80" style={{ color: 'var(--cs-accent)' }}>Edit</button>
        </div>
      ) : (
        <div className="mb-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <label className="w-20" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>Max spans</label>
            <input type="number" value={maxSpans} onChange={e => setMaxSpans(e.target.value)}
              className="flex-1 px-2 py-1 rounded-md outline-none cs-mono"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }} />
          </div>
          <div className="flex items-center gap-2">
            <label className="w-20" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>Days to keep</label>
            <input type="number" value={retDays} onChange={e => setRetDays(e.target.value)}
              className="flex-1 px-2 py-1 rounded-md outline-none cs-mono"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }} />
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={saveRetention}
              className="flex-1 py-1 rounded-md transition-colors"
              style={{ background: 'var(--cs-accent)', color: 'var(--cs-text-invert)', fontSize: 'var(--cs-text-xs)', fontWeight: 'var(--cs-weight-medium)' }}>
              Save
            </button>
            <button type="button" onClick={() => setEditing(false)}
              className="flex-1 py-1 rounded-md transition-colors"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={prune}
        disabled={pruning}
        className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-md transition-colors disabled:opacity-50"
        style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}
      >
        <Trash2 className="w-3 h-3" aria-hidden="true" /> {pruning ? 'Pruning…' : 'Run manual prune'}
      </button>

      {pruneResult && (
        <p className="mt-1.5 text-center" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-accent)' }}>
          Pruned {pruneResult.prunedByAge} by age + {pruneResult.prunedByCount} by count
        </p>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function CostTab() {
  const [data, setData]       = useState<CostData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [view, setView]       = useState<'sessions' | 'models'>('models');
  const [plan, setPlan]       = useState<PlanId>(loadPlan);
  const [density, setDensity] = useRowDensity('cost');

  const load = useCallback(() => {
    fetch('/api/costs')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: CostData) => { setData(d); setLoadError(null); })
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, []);

  // `/api/costs` runs a full table scan. Refresh on the coalesced `graph-update`
  // signal (not per `span-added`, which would re-scan once for EVERY span in a
  // batch), and debounce so a burst of updates triggers a single refetch.
  const debouncedLoad = useDebouncedCallback(load);

  useEffect(() => {
    load();
    socket.on('graph-update', debouncedLoad);
    return () => { socket.off('graph-update', debouncedLoad); };
  }, [load, debouncedLoad]);

  useEffect(() => {
    try { localStorage.setItem(PLAN_STORAGE_KEY, plan); } catch {}
  }, [plan]);

  const selectedPlan = PLAN_OPTIONS.find(p => p.id === plan) ?? PLAN_OPTIONS[0];

  const hasData = !!data && (data.totalTokensIn + data.totalTokensOut) > 0;
  const maxSessionCost = data ? Math.max(0.000001, ...data.sessions.map(s => s.costUsd)) : 0;
  const maxModelCost   = data ? Math.max(0.000001, ...data.models.map(m => m.costUsd))   : 0;

  const modelColumns: DataColumn<ModelSummary>[] = [
    {
      id: 'model', header: 'Model', width: 'minmax(0,1.3fr)', mono: true,
      cell: m => (
        <span className="flex items-center gap-1 min-w-0">
          <span className="truncate" style={{ color: 'var(--cs-text-body)' }}>{m.label}</span>
          {m.inferred && <InferredFlag />}
          {!m.knownPrice && (
            <span title="No pricing data for this model" style={{ color: 'var(--cs-text-faint)' }}>
              <HelpCircle className="w-3 h-3" aria-hidden="true" />
            </span>
          )}
        </span>
      ),
    },
    { id: 'in',  header: 'Input',   width: '84px', align: 'end', hideBelow: 'xl',  mono: true, cell: m => <span>{formatTokens(m.tokensIn)}</span> },
    { id: 'out', header: 'Output',  width: '84px', align: 'end', hideBelow: 'xl',  mono: true, cell: m => <span>{formatTokens(m.tokensOut)}</span> },
    { id: 'cr',  header: 'Cache R', width: '84px', align: 'end', hideBelow: '2xl', mono: true, cell: m => <span title="Cache reads — re-sent context, billed at ~10% of fresh input">{formatTokens(m.cacheReadTokens)}</span> },
    { id: 'cw',  header: 'Cache W', width: '84px', align: 'end', hideBelow: '2xl', mono: true, cell: m => <span title="Cache writes — context written to cache, billed at ~125% of fresh input" style={{ color: 'var(--cs-text-faint)' }}>{formatTokens(m.cacheWriteTokens)}</span> },
    { id: 'cost', header: 'Cost',   width: '86px', align: 'end', mono: true, cell: m => <span style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>{formatCost(m.costUsd)}</span> },
    { id: 'bar', header: '', width: 'minmax(0,0.6fr)', hideBelow: '3xl', cell: m => <CostBar value={m.costUsd} max={maxModelCost} /> },
  ];

  const sessionColumns: DataColumn<SessionCost>[] = [
    {
      id: 'session', header: 'Session', width: 'minmax(0,1.2fr)',
      cell: s => (
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: HARNESS_COLORS[s.harness] ?? HARNESS_COLORS.unknown }} aria-hidden="true" />
          <span className="truncate" style={{ color: 'var(--cs-text-body)' }} title={s.sessionName}>{s.sessionName}</span>
        </span>
      ),
    },
    {
      id: 'model', header: 'Model', width: 'minmax(0,0.9fr)', hideBelow: 'xl', mono: true,
      cell: s => (
        <span className="flex items-center gap-1 min-w-0">
          <span className="truncate">{s.modelLabel}</span>
          {s.inferred && <InferredFlag />}
          {!s.knownPrice && <span style={{ color: 'var(--cs-text-faint)' }}>(?)</span>}
        </span>
      ),
    },
    { id: 'in',  header: 'Input',   width: '84px', align: 'end', hideBelow: 'xl',  mono: true, cell: s => <span>{formatTokens(s.tokensIn)}</span> },
    { id: 'out', header: 'Output',  width: '84px', align: 'end', hideBelow: '2xl', mono: true, cell: s => <span>{formatTokens(s.tokensOut)}</span> },
    { id: 'cr',  header: 'Cache R', width: '84px', align: 'end', hideBelow: '2xl', mono: true, cell: s => <span title="Cache reads — re-sent context, billed at ~10% of fresh input">{formatTokens(s.cacheReadTokens)}</span> },
    { id: 'cw',  header: 'Cache W', width: '84px', align: 'end', hideBelow: '3xl', mono: true, cell: s => <span title="Cache writes — context written to cache, billed at ~125% of fresh input" style={{ color: 'var(--cs-text-faint)' }}>{formatTokens(s.cacheWriteTokens)}</span> },
    { id: 'cost', header: 'Cost',   width: '86px', align: 'end', mono: true, cell: s => <span style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>{formatCost(s.costUsd)}</span> },
    { id: 'bar', header: '', width: 'minmax(0,0.6fr)', hideBelow: '3xl', cell: s => <CostBar value={s.costUsd} max={maxSessionCost} /> },
  ];

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-auto" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <Toolbar>
        <ToolbarTitle icon={<DollarSign className="w-3.5 h-3.5" />}>Token spend</ToolbarTitle>
        <span style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
          What this usage would cost on the pay-per-token API — an estimate, not a bill
        </span>
        <select
          value={plan}
          onChange={e => setPlan(e.target.value as PlanId)}
          className="ml-auto px-2 py-1 rounded-md outline-none"
          style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}
          title="Your Claude Code plan"
        >
          {PLAN_OPTIONS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
      </Toolbar>

      {loadError && !data ? (
        <ErrorState
          description={`Cost data did not respond (${loadError}).`}
          onRetry={() => { setLoading(true); load(); }}
        />
      ) : !loading && !hasData ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-4 p-8">
          <EmptyState
            icon={<DollarSign className="w-6 h-6" aria-hidden="true" />}
            title="No token usage data available"
            description="Cost tracking requires agents to include gen_ai.usage.input_tokens and gen_ai.usage.output_tokens in their OpenTelemetry spans."
          />
          <div className="max-w-md space-y-3">
            <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}>
              <p className="mb-2" style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-semibold)' }}>Agent telemetry support</p>
              <div className="space-y-1.5" style={{ color: 'var(--cs-text-muted)' }}>
                <div className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: 'var(--cs-accent)' }} aria-hidden="true" />
                  <div>
                    <strong style={{ color: 'var(--cs-text-body)' }}>Claude Code</strong> — requires{' '}
                    <code className="cs-mono px-1 rounded" style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-sev-medium-fg)' }}>CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1</code>{' '}
                    to emit model name and token counts.
                    <span style={{ color: 'var(--cs-text-faint)' }}> Run </span>
                    <code className="cs-mono px-1 rounded" style={{ background: 'var(--cs-bg-raised)' }}>node cli/init.mjs</code>
                    <span style={{ color: 'var(--cs-text-faint)' }}> to set this up automatically.</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--cs-accent)' }} aria-hidden="true" />
                  <span><strong style={{ color: 'var(--cs-text-body)' }}>Aider, OpenHands, LangChain-based</strong> — typically include full token usage via OpenAI/Anthropic SDK instrumentation</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--cs-text-faint)' }} aria-hidden="true" />
                  <span><strong style={{ color: 'var(--cs-text-body)' }}>Cursor, Copilot, Windsurf</strong> — varies by version; may not expose OTLP telemetry</span>
                </div>
              </div>
            </div>
            <p className="text-center" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
              ClaudeSec monitors all agent activity regardless of cost data availability.
              Security detection, timeline, and alerts work independently of token tracking.
            </p>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col p-4 gap-4 min-h-0">

          {/* Summary tiles */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {([
              { label: 'API-equivalent cost', value: formatCost(data?.totalCostUsd ?? 0),          icon: <DollarSign className="w-3.5 h-3.5" />, emphasize: true },
              { label: 'Input (fresh)',       value: formatTokens(data?.totalTokensIn ?? 0),        icon: <TrendingUp className="w-3.5 h-3.5" /> },
              { label: 'Cache reads',         value: formatTokens(data?.totalCacheReadTokens ?? 0), icon: <Database className="w-3.5 h-3.5" /> },
              { label: 'Output tokens',       value: formatTokens(data?.totalTokensOut ?? 0),       icon: <TrendingUp className="w-3.5 h-3.5 rotate-180" /> },
              { label: 'Sessions',            value: String(new Set(data?.sessions.map(s => s.traceId) ?? []).size), icon: <Cpu className="w-3.5 h-3.5" /> },
            ] as { label: string; value: string; icon: React.ReactNode; emphasize?: boolean }[]).map(card => (
              <div key={card.label} className="rounded-lg p-3" style={{ background: 'var(--cs-bg-surface)' }}>
                <div className="mb-1" style={{ color: card.emphasize ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }} aria-hidden="true">{card.icon}</div>
                <div className="cs-mono" style={{ fontSize: 'var(--cs-text-lg)', fontWeight: 'var(--cs-weight-bold)', color: card.emphasize ? 'var(--cs-accent)' : 'var(--cs-text-strong)' }}>
                  {card.value}
                </div>
                <div className="cs-eyebrow mt-0.5">{card.label}</div>
              </div>
            ))}
          </div>
          <p className="flex items-start gap-1.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', lineHeight: 'var(--cs-leading-normal)' }}>
            <Info className="w-3 h-3 mt-0.5 shrink-0" aria-hidden="true" />
            <span>
              Input dwarfs output by design — every turn re-sends the whole context (system prompt, tool
              schemas, prior messages, file reads) as input, while the model emits only a small response.
              Most of that volume is <strong style={{ color: 'var(--cs-text-muted)' }}>cache reads</strong>:
              re-sent context billed at ~10% of fresh input, not new spend. A high input number is normal
              and mostly cheap.
            </span>
          </p>

          {/* Plan context */}
          {data && selectedPlan.price != null && (() => {
            const apiTotal = data.totalCostUsd;
            const monthly  = selectedPlan.price;
            const ratio    = monthly > 0 ? apiTotal / monthly : 0;
            const ratioGood = ratio >= 1;
            return (
              <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
                <div className="flex items-center gap-2 mb-3">
                  <span className="cs-eyebrow">Your plan</span>
                  <span style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{selectedPlan.label}</span>
                </div>
                <div className="grid grid-cols-3 gap-3 mb-3">
                  <div className="rounded-md p-3" style={{ background: 'var(--cs-bg-raised)' }}>
                    <div className="cs-mono" style={{ fontSize: 'var(--cs-text-lg)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>${monthly}</div>
                    <div className="cs-eyebrow mt-0.5">Flat / month</div>
                  </div>
                  <div className="rounded-md p-3" style={{ background: 'var(--cs-bg-raised)' }}>
                    <div className="cs-mono" style={{ fontSize: 'var(--cs-text-lg)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>{formatCost(apiTotal)}</div>
                    <div className="cs-eyebrow mt-0.5">API-equivalent</div>
                  </div>
                  <div className="rounded-md p-3" style={{ background: 'var(--cs-bg-raised)' }}>
                    <div className="cs-mono" style={{ fontSize: 'var(--cs-text-lg)', fontWeight: 'var(--cs-weight-bold)', color: ratioGood ? 'var(--cs-accent)' : 'var(--cs-text-strong)' }}>
                      {ratio.toFixed(1)}×
                    </div>
                    <div className="cs-eyebrow mt-0.5">Value vs plan</div>
                  </div>
                </div>
                <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)', lineHeight: 'var(--cs-leading-normal)' }}>
                  You'd pay {formatCost(apiTotal)} on the pay-per-token API; on {selectedPlan.label.split(' — ')[0]} you pay ${monthly} flat per month.{' '}
                  <span style={{ color: 'var(--cs-text-faint)' }}>
                    {ratioGood
                      ? `That's ${ratio.toFixed(1)}× your plan price in API-equivalent value.`
                      : `Your usage so far is ${ratio.toFixed(1)}× the flat price — the subscription covers it.`}
                  </span>
                </p>
              </div>
            );
          })()}

          {/* View toggle */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-0.5 rounded-md p-0.5" style={{ background: 'var(--cs-bg-raised)' }} role="group" aria-label="Cost breakdown">
              <ToolButton active={view === 'models'} aria-pressed={view === 'models'} onClick={() => setView('models')}>By model</ToolButton>
              <ToolButton active={view === 'sessions'} aria-pressed={view === 'sessions'} onClick={() => setView('sessions')}>By session</ToolButton>
            </div>
            <div className="ml-auto flex items-center gap-1" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
              <HelpCircle className="w-3 h-3" aria-hidden="true" />
              Pricing may not reflect current rates
            </div>
          </div>

          {view === 'models' ? (
            <DataTable
              rows={data?.models ?? []}
              columns={modelColumns}
              rowKey={m => m.model}
              label="Cost by model"
              density={density}
              minWidth={560}
              loading={loading}
              empty={
                <EmptyState
                  icon={<Cpu className="w-6 h-6" aria-hidden="true" />}
                  title="No models recorded yet"
                  description="A model appears here the first time a session reports its usage."
                />
              }
            />
          ) : (
            <DataTable
              rows={data?.sessions ?? []}
              columns={sessionColumns}
              rowKey={s => `${s.traceId}::${s.model}::${s.tokensIn}::${s.tokensOut}`}
              label="Cost by session"
              density={density}
              minWidth={620}
              loading={loading}
              empty={
                <EmptyState
                  icon={<Cpu className="w-6 h-6" aria-hidden="true" />}
                  title="No sessions recorded yet"
                  description="A session appears here the first time it reports token usage."
                />
              }
            />
          )}

          {/* Webhook panel */}
          <WebhookPanel />

          {/* DB Health panel */}
          <DBHealthPanel />

          {/* Pricing disclaimer */}
          <div className="flex items-start gap-2 p-3 rounded-lg" style={{ background: 'var(--cs-bg-surface)', fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--cs-sev-medium)' }} aria-hidden="true" />
            <div className="space-y-2">
              <p>
                Cost estimates are approximate and based on publicly available pricing. Prices vary by
                region, tier, and caching. Tokens are aggregated from{' '}
                <code className="cs-mono">gen_ai.usage.input_tokens</code> /{' '}
                <code className="cs-mono">gen_ai.usage.output_tokens</code> span attributes. Models
                without pricing data show 0 cost.
              </p>
              <ExperimentalBadge title="GPT-5.x / non-Claude rates are estimates; some models are inferred" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
