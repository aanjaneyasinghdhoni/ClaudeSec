import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { ShieldCheck, ShieldAlert, Ban, Eye, Activity, AlertTriangle, RefreshCw } from 'lucide-react';
import { socket } from './socket';

// ── Types ────────────────────────────────────────────────────────────────────
type EnforceMode = 'monitor' | 'enforce';
type EnforceAction = 'alert' | 'block';

interface EnforceLogEvent {
  ts: number;
  mode: string;
  label: string;
  severity: string;
  command: string;
  wouldBlock: boolean;
}

interface EnforceConfig {
  mode: EnforceMode;
  overrides: Record<string, EnforceAction>;
  configFile?: string;
  envMode?: string | null;
  bypassEnabled?: boolean;
}

const SEV_BADGE: Record<string, string> = {
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
};

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function relTime(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const LOG_LIMIT = 500;

export function EnforceTab() {
  const [config, setConfig]   = useState<EnforceConfig | null>(null);
  const [events, setEvents]   = useState<EnforceLogEvent[]>([]);
  const [saving, setSaving]   = useState(false);
  const [error,  setError]    = useState('');
  const [, setTick]           = useState(0); // re-render for relative times

  // Fetch config + log on mount.
  const fetchConfig = useCallback(() => {
    fetch('/api/enforce/config')
      .then(r => r.json())
      .then((c: EnforceConfig) => setConfig(c))
      .catch(() => setError('Could not load enforcement config'));
  }, []);

  const fetchLog = useCallback(() => {
    fetch(`/api/enforce-log?limit=${LOG_LIMIT}`)
      .then(r => r.json())
      .then((d: { events: EnforceLogEvent[] }) => setEvents(Array.isArray(d.events) ? d.events : []))
      .catch(() => { /* feed is best-effort */ });
  }, []);

  useEffect(() => {
    fetchConfig();
    fetchLog();
  }, [fetchConfig, fetchLog]);

  // Live updates: new would-block events + config changes from elsewhere.
  useEffect(() => {
    const onLog = (evt: EnforceLogEvent) => {
      setEvents(prev => [evt, ...prev].slice(0, LOG_LIMIT));
    };
    const onConfig = (c: { mode: EnforceMode; overrides: Record<string, EnforceAction> }) => {
      setConfig(prev => (prev ? { ...prev, mode: c.mode, overrides: c.overrides } : prev));
    };
    socket.on('enforce-log', onLog);
    socket.on('enforce-config', onConfig);
    return () => {
      socket.off('enforce-log', onLog);
      socket.off('enforce-config', onConfig);
    };
  }, []);

  // Tick every 5s so relative timestamps stay fresh.
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 5000);
    return () => clearInterval(id);
  }, []);

  const mode = config?.mode ?? 'monitor';
  const isEnforce = mode === 'enforce';

  const setMode = async (next: EnforceMode) => {
    if (saving || next === mode) return;
    setSaving(true);
    setError('');
    try {
      const res = await fetch('/api/enforce/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: next }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const updated = await res.json();
      setConfig(prev => (prev ? { ...prev, mode: updated.mode, overrides: updated.overrides } : prev));
    } catch (e) {
      setError((e as Error).message || 'Failed to update mode');
    } finally {
      setSaving(false);
    }
  };

  // Aggregate counts by rule label + severity over the visible feed.
  const stats = useMemo(() => {
    const byRule = new Map<string, { count: number; severity: string }>();
    const bySeverity: Record<string, number> = { high: 0, medium: 0, low: 0 };
    for (const e of events) {
      const r = byRule.get(e.label) ?? { count: 0, severity: e.severity };
      r.count += 1;
      byRule.set(e.label, r);
      if (bySeverity[e.severity] !== undefined) bySeverity[e.severity] += 1;
    }
    const topRules = [...byRule.entries()]
      .map(([label, v]) => ({ label, ...v }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12);
    return { total: events.length, bySeverity, topRules };
  }, [events]);

  return (
    <div className="flex-1 overflow-auto p-4 sm:p-5" style={{ color: 'var(--cs-text-base)' }}>
      <div className="max-w-5xl mx-auto flex flex-col gap-5">

        {/* Header */}
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-5 h-5" style={{ color: 'var(--cs-accent)' }} />
          <h2 className="text-base font-semibold" style={{ color: 'var(--cs-text-base)' }}>Enforcement</h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded" style={{ color: 'var(--cs-text-faint)', background: 'var(--cs-bg-elevated)' }}>
            PreToolUse hook
          </span>
        </div>

        {/* Mode banner + toggle */}
        <div
          className="rounded-2xl p-4 sm:p-5 flex flex-col gap-4"
          style={{
            background: isEnforce ? 'rgba(244,63,94,0.06)' : 'var(--cs-bg-surface)',
            border: `1px solid ${isEnforce ? 'rgba(244,63,94,0.30)' : 'var(--cs-border)'}`,
          }}
        >
          <div className="flex items-start gap-3">
            {isEnforce
              ? <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5" style={{ color: '#ff3b5c' }} />
              : <Eye className="w-5 h-5 shrink-0 mt-0.5" style={{ color: 'var(--cs-accent)' }} />}
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold mb-1" style={{ color: 'var(--cs-text-base)' }}>
                {isEnforce ? 'Enforce mode — high-severity tool calls are BLOCKED' : 'Monitor mode — logging only, nothing is blocked'}
              </div>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--cs-text-muted)' }}>
                {isEnforce
                  ? 'The PreToolUse hook denies Bash / Edit / Write / MultiEdit calls that match a high-severity rule. The always-on catastrophic floor (rm -rf /, fork bombs, reverse shells, etc.) blocks in either mode.'
                  : 'The hook records "would-block" events for high-severity matches but allows every call. Flip to Enforce to actually deny them. The catastrophic floor still blocks the 6 most dangerous commands regardless of mode.'}
              </p>
              <p className="text-[11px] mt-2 font-mono" style={{ color: 'var(--cs-text-faint)' }}>
                Bypass any single run with <span style={{ color: 'var(--cs-accent)' }}>CLAUDESEC_HOOKS_BYPASS=1</span>.
                {config?.bypassEnabled && <span style={{ color: '#ffb224' }}> Bypass is currently ACTIVE in this server's env — the hook allows everything.</span>}
              </p>
            </div>
          </div>

          {/* Segmented toggle */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="inline-flex rounded-xl p-1 gap-1" style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)' }}>
              <button
                onClick={() => setMode('monitor')}
                disabled={saving}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                style={{
                  background: !isEnforce ? 'rgba(var(--cs-accent-rgb),0.15)' : 'transparent',
                  color: !isEnforce ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
                }}
                aria-pressed={!isEnforce}
              >
                <Eye className="w-3.5 h-3.5" /> Monitor
              </button>
              <button
                onClick={() => setMode('enforce')}
                disabled={saving}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                style={{
                  background: isEnforce ? 'rgba(244,63,94,0.18)' : 'transparent',
                  color: isEnforce ? '#ff6b81' : 'var(--cs-text-faint)',
                }}
                aria-pressed={isEnforce}
              >
                <Ban className="w-3.5 h-3.5" /> Enforce
              </button>
            </div>
            {saving && <span className="text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>Saving…</span>}
            {config?.envMode && (
              <span className="text-[11px] font-mono" style={{ color: 'var(--cs-text-faint)' }}>
                env CLAUDESEC_MODE={config.envMode} (file overrides env)
              </span>
            )}
          </div>

          {error && (
            <div className="text-xs flex items-center gap-1.5" style={{ color: '#ff6b81' }}>
              <AlertTriangle className="w-3.5 h-3.5" /> {error}
            </div>
          )}
        </div>

        {/* Counts */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Would-block events" value={stats.total} accent="var(--cs-accent)" icon={<Activity className="w-4 h-4" />} />
          <StatCard label="High severity" value={stats.bySeverity.high} accent="#ff3b5c" icon={<ShieldAlert className="w-4 h-4" />} />
          <StatCard label="Medium severity" value={stats.bySeverity.medium} accent="#f97316" icon={<AlertTriangle className="w-4 h-4" />} />
          <StatCard label="Low severity" value={stats.bySeverity.low} accent="#ffb224" icon={<AlertTriangle className="w-4 h-4" />} />
        </div>

        {/* Counts by rule */}
        {stats.topRules.length > 0 && (
          <div className="rounded-2xl p-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
            <div className="text-xs font-semibold mb-3" style={{ color: 'var(--cs-text-muted)' }}>Top rules (by would-block count)</div>
            <div className="flex flex-col gap-1.5">
              {stats.topRules.map(r => {
                const max = stats.topRules[0]?.count || 1;
                return (
                  <div key={r.label} className="flex items-center gap-3">
                    <div className="flex-1 min-w-0 relative h-7 rounded-lg overflow-hidden" style={{ background: 'var(--cs-bg-elevated)' }}>
                      <div className="absolute inset-y-0 left-0 rounded-lg" style={{ width: `${(r.count / max) * 100}%`, background: 'rgba(var(--cs-accent-rgb),0.18)' }} />
                      <div className="absolute inset-0 flex items-center px-2.5 gap-2">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono shrink-0 ${SEV_BADGE[r.severity] ?? 'bg-slate-800 text-slate-400'}`}>{r.severity}</span>
                        <span className="text-xs truncate" style={{ color: 'var(--cs-text-base)' }}>{r.label}</span>
                      </div>
                    </div>
                    <span className="text-xs font-mono tabular-nums shrink-0 w-10 text-right" style={{ color: 'var(--cs-text-muted)' }}>{r.count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Live feed */}
        <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
          <div className="flex items-center gap-2 px-4 py-3" style={{ borderBottom: '1px solid var(--cs-border)' }}>
            <span className="w-1.5 h-1.5 rounded-full status-live" style={{ background: 'var(--cs-accent)' }} />
            <span className="text-xs font-semibold" style={{ color: 'var(--cs-text-base)' }}>Live would-block feed</span>
            <span className="text-[11px] font-mono ml-1" style={{ color: 'var(--cs-text-faint)' }}>{events.length} events</span>
            <button
              onClick={() => { fetchLog(); fetchConfig(); }}
              className="ml-auto flex items-center gap-1 text-[11px] px-2 py-1 rounded-lg transition-colors hover:opacity-80"
              style={{ color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
              title="Refresh"
            >
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          {events.length === 0 ? (
            <div className="px-4 py-10 text-center text-xs" style={{ color: 'var(--cs-text-faint)' }}>
              No enforcement events yet. When a tool call matches a high-severity rule, it appears here
              {isEnforce ? ' (and is blocked).' : ' as a would-block.'}
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: 'var(--cs-border)' }}>
              {events.slice(0, 200).map((e, i) => (
                <div key={`${e.ts}-${i}`} className="px-4 py-2.5 flex items-start gap-3" style={{ borderColor: 'var(--cs-border)' }}>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono shrink-0 mt-0.5 ${SEV_BADGE[e.severity] ?? 'bg-slate-800 text-slate-400'}`}>{e.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-medium" style={{ color: 'var(--cs-text-base)' }}>{e.label}</span>
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                        style={
                          e.mode === 'enforce'
                            ? { background: 'rgba(244,63,94,0.15)', color: '#ff6b81' }
                            : { background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-faint)' }
                        }
                      >
                        {e.mode === 'enforce' ? 'blocked' : 'would-block'}
                      </span>
                    </div>
                    <code className="text-[11px] font-mono block truncate mt-0.5" style={{ color: 'var(--cs-text-muted)' }}>{e.command}</code>
                  </div>
                  <span className="text-[10px] font-mono shrink-0 mt-0.5" style={{ color: 'var(--cs-text-faint)' }} title={fmtTime(e.ts)}>{relTime(e.ts)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}

function StatCard({ label, value, accent, icon }: { label: string; value: number; accent: string; icon: React.ReactNode }) {
  return (
    <div className="rounded-2xl p-3.5 flex flex-col gap-1.5" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
      <div className="flex items-center gap-1.5" style={{ color: accent }}>
        {icon}
        <span className="text-[10px] font-medium uppercase tracking-wider" style={{ color: 'var(--cs-text-faint)' }}>{label}</span>
      </div>
      <span className="text-2xl font-semibold tabular-nums" style={{ color: 'var(--cs-text-base)' }}>{value}</span>
    </div>
  );
}
