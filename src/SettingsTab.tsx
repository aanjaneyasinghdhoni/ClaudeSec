import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Settings, Database, Globe, Monitor, ChevronDown, ChevronUp, Check, BellRing,
  History, Copy, Terminal, ShieldCheck, AlertTriangle, CircleSlash, CheckCircle2, Activity, Trash2,
} from 'lucide-react';
import { ThresholdRulesSection } from './ThresholdRulesSection';
import { WebhookDeliverySection } from './WebhookDeliverySection';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DbStats {
  spanCount: number;
  maxSpans: number;
  retentionDays: number;
  dbSizeBytes: number;
}

/** Map the server's /api/db-stats response to the DbStats interface */
function parseDbStats(raw: any): DbStats {
  return {
    spanCount:     raw.spansTotal ?? raw.spanCount ?? 0,
    maxSpans:      raw.retentionConfig?.maxSpans ?? raw.maxSpans ?? 50_000,
    retentionDays: raw.retentionConfig?.retentionDays ?? raw.retentionDays ?? 30,
    dbSizeBytes:   raw.dbSizeBytes ?? 0,
  };
}

interface RateLimitInfo {
  rps: number;
  burst: number;
  maxSpansBatch: number;
}

interface WebhookConfig {
  configured: boolean;
  urlPreview: string | null;
  threshold: 'low' | 'medium' | 'high';
  envOverride: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// ---------------------------------------------------------------------------
// Section wrapper — collapsible accordion
// ---------------------------------------------------------------------------

interface SectionProps {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

export function Section({ icon, title, children, defaultOpen = true }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-slate-800/40 transition-colors"
      >
        <span style={{ color: 'var(--cs-accent)' }}>{icon}</span>
        <span className="text-sm font-semibold text-slate-200 flex-1">{title}</span>
        {open
          ? <ChevronUp className="w-4 h-4 text-slate-500" />
          : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>

      {/* Grid-rows 0fr→1fr animates height without a fixed cap, so tall sections
          are never clipped and the collapsing panel never grows past its real
          height to overlap the next section's header. The inner wrapper must own
          `overflow-hidden`. While closed, `pointer-events-none` + aria-hidden keep
          the collapsed content from intercepting clicks meant for siblings. */}
      <div
        className="grid transition-[grid-template-rows] duration-200 ease-out"
        style={{ gridTemplateRows: open ? '1fr' : '0fr' }}
      >
        <div className={`overflow-hidden ${open ? '' : 'pointer-events-none'}`} aria-hidden={!open}>
          <div className="px-4 pb-4 pt-1 border-t border-slate-800">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SaveButton — shows "✓ Saved" for 2 s
// ---------------------------------------------------------------------------

interface SaveButtonProps {
  onClick: () => Promise<void>;
  disabled?: boolean;
  label?: string;
}

function SaveButton({ onClick, disabled, label = 'Save' }: SaveButtonProps) {
  const [saved, setSaved] = useState(false);
  const [busy,  setBusy]  = useState(false);

  const handle = async () => {
    setBusy(true);
    await onClick();
    setBusy(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <button
      type="button"
      onClick={handle}
      disabled={disabled || busy}
      className="flex items-center gap-1.5 px-4 py-1.5 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
      style={{ background: 'var(--cs-accent)' }}
      onMouseEnter={e => (e.currentTarget.style.background = '#00c09a')}
      onMouseLeave={e => (e.currentTarget.style.background = 'var(--cs-accent)')}
    >
      {saved ? (
        <>
          <Check className="w-3.5 h-3.5 text-green-300" />
          <span className="text-green-300">Saved</span>
        </>
      ) : (
        label
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// 1. Retention section
// ---------------------------------------------------------------------------

export function RetentionSection() {
  const [maxSpans,       setMaxSpans]       = useState<number>(50_000);
  const [retentionDays,  setRetentionDays]  = useState<number>(30);
  const [stats,          setStats]          = useState<DbStats | null>(null);
  const [error,          setError]          = useState('');

  useEffect(() => {
    fetch('/api/db-stats')
      .then(r => r.json())
      .then((raw: any) => {
        const d = parseDbStats(raw);
        setStats(d);
        setMaxSpans(d.maxSpans);
        setRetentionDays(d.retentionDays);
      })
      .catch(() => { setError('Failed to load retention settings'); });
  }, []);

  const save = useCallback(async () => {
    setError('');
    const res = await fetch('/api/db-stats/retention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxSpans, retentionDays }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({})) as { error?: string };
      setError(d.error ?? 'Failed to save');
      throw new Error(d.error ?? 'Failed to save');
    }
    const updated = await res.json() as Partial<DbStats>;
    setStats(prev => prev ? { ...prev, ...updated } : prev);
  }, [maxSpans, retentionDays]);

  return (
    <div className="space-y-4 mt-3">
      {stats && (
        <div className="flex gap-4 flex-wrap text-[11px] text-slate-500 font-mono">
          <span>Stored spans: <span className="text-slate-300">{stats.spanCount.toLocaleString()}</span></span>
          <span>DB size: <span className="text-slate-300">{formatBytes(stats.dbSizeBytes)}</span></span>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Max Spans</label>
          <input
            type="number"
            min={100}
            max={10_000_000}
            value={maxSpans}
            onChange={e => setMaxSpans(Number(e.target.value))}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Retention Days</label>
          <input
            type="number"
            min={1}
            max={3650}
            value={retentionDays}
            onChange={e => setRetentionDays(Number(e.target.value))}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
          />
        </div>
      </div>

      {error && <p className="text-[11px] text-red-400 font-mono">{error}</p>}

      <div className="flex justify-end">
        <SaveButton onClick={save} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 2. Rate limiting section
// ---------------------------------------------------------------------------

export function RateLimitSection() {
  const [info, setInfo] = useState<RateLimitInfo>({ rps: 50, burst: 200, maxSpansBatch: 500 });

  useEffect(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then((d: { rateLimiting?: RateLimitInfo }) => {
        if (d.rateLimiting) setInfo(d.rateLimiting);
      })
      .catch(() => {});
  }, []);

  const rows: { label: string; value: number; unit: string; envKey: string }[] = [
    { label: 'Requests / second',  value: info.rps,           unit: 'rps',   envKey: 'CLAUDESEC_RATE_LIMIT_RPS'       },
    { label: 'Burst limit',        value: info.burst,         unit: 'reqs',  envKey: 'CLAUDESEC_RATE_LIMIT_BURST'     },
    { label: 'Max spans per batch', value: info.maxSpansBatch, unit: 'spans', envKey: 'CLAUDESEC_MAX_SPANS_BATCH'      },
  ];

  return (
    <div className="space-y-3 mt-3">
      <div className="space-y-2">
        {rows.map(row => (
          <div key={row.envKey} className="flex items-center justify-between text-xs">
            <span className="text-slate-400">{row.label}</span>
            <div className="flex items-center gap-2">
              <span className="font-mono text-slate-200">{row.value} <span className="text-slate-500">{row.unit}</span></span>
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-600 italic mt-2">
        Configure via environment variables: <code className="font-mono text-slate-500">CLAUDESEC_RATE_LIMIT_RPS</code>,{' '}
        <code className="font-mono text-slate-500">CLAUDESEC_RATE_LIMIT_BURST</code>,{' '}
        <code className="font-mono text-slate-500">CLAUDESEC_MAX_SPANS_BATCH</code>
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 3. Webhook section
// ---------------------------------------------------------------------------

export function WebhookSection() {
  const [url,         setUrl]         = useState('');
  const [urlPreview,  setUrlPreview]  = useState<string | null>(null);
  const [threshold,   setThreshold]   = useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [configured,  setConfigured]  = useState(false);
  const [testMsg,     setTestMsg]     = useState('');
  const [testOk,      setTestOk]      = useState<boolean | null>(null);
  const [error,       setError]       = useState('');

  const load = useCallback(() => {
    fetch('/api/webhook')
      .then(r => r.json())
      .then((d: Partial<WebhookConfig>) => {
        if (d.configured) { setConfigured(true); setUrlPreview(d.urlPreview ?? null); }
        if (d.threshold) setThreshold(d.threshold);
      })
      .catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = useCallback(async () => {
    setError('');
    const res = await fetch('/api/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim(), threshold }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({})) as { error?: string };
      setError(d.error ?? 'Failed to save webhook');
      throw new Error(d.error ?? 'Failed to save webhook');
    }
    setConfigured(!!url.trim());
    setUrl('');
    load();
  }, [url, threshold, load]);

  const handleDelete = async () => {
    setError('');
    const res = await fetch('/api/webhook', { method: 'DELETE' });
    if (res.ok) {
      setUrl('');
      setUrlPreview(null);
      setConfigured(false);
      setTestMsg('');
      setTestOk(null);
    } else {
      setError('Failed to delete webhook');
    }
  };

  const handleTest = async () => {
    setTestMsg('');
    setTestOk(null);
    try {
      const res = await fetch('/api/webhook/test', { method: 'POST' });
      if (res.ok) {
        setTestMsg('Test payload sent successfully.');
        setTestOk(true);
      } else {
        const d = await res.json().catch(() => ({})) as { error?: string };
        setTestMsg(d.error ?? 'Test failed.');
        setTestOk(false);
      }
    } catch {
      setTestMsg('Network error during test.');
      setTestOk(false);
    }
  };

  return (
    <div className="space-y-4 mt-3">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="sm:col-span-2">
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Webhook URL</label>
          <input
            type="url"
            value={url}
            onChange={e => { setUrl(e.target.value); setError(''); }}
            placeholder={configured ? 'Enter a new URL to replace' : 'https://hooks.example.com/...'}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
          />
          {configured && (
            <p className="text-[11px] font-mono mt-1 flex items-center gap-1.5" style={{ color: 'var(--cs-text-muted)' }}>
              <Check className="w-3 h-3" style={{ color: 'var(--cs-accent)' }} />
              Configured: <span style={{ color: 'var(--cs-text-faint)' }}>{urlPreview ?? '••••'}</span>
            </p>
          )}
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Min Threshold</label>
          <select
            value={threshold}
            onChange={e => setThreshold(e.target.value as 'low' | 'medium' | 'high' | 'critical')}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      {error && <p className="text-[11px] text-red-400 font-mono">{error}</p>}
      {testMsg && (
        <p className={`text-[11px] font-mono ${testOk ? 'text-green-400' : 'text-red-400'}`}>
          {testMsg}
        </p>
      )}

      <div className="flex items-center gap-2 justify-end">
        {configured && (
          <>
            <button
              type="button"
              onClick={handleTest}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded-lg text-xs text-slate-300 transition-colors"
            >
              Test
            </button>
            <button
              type="button"
              onClick={handleDelete}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/30 hover:bg-red-900/50 border border-red-700/30 rounded-lg text-xs text-red-400 transition-colors"
            >
              Delete
            </button>
          </>
        )}
        <SaveButton onClick={save} disabled={!url.trim()} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 4. Display preferences section
// ---------------------------------------------------------------------------

export function DisplaySection() {
  const [hideNone, setHideNone] = useState(() => localStorage.getItem('claudesec.hideNone') === 'true');

  const toggle = (key: string, value: boolean, setter: (v: boolean) => void) => {
    setter(value);
    localStorage.setItem(key, String(value));
    window.dispatchEvent(new Event('claudesec:hideNoneChange'));
  };

  return (
    <div className="space-y-3 mt-3">
      <ToggleRow
        label="Hide safe spans"
        description="Hide spans with no threat (severity: none) from the spans list."
        checked={hideNone}
        onChange={v => toggle('claudesec.hideNone', v, setHideNone)}
      />
      <p className="text-xs text-slate-600 italic">Settings are saved locally in your browser.</p>
    </div>
  );
}

interface ToggleRowProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleRow({ label, description, checked, onChange }: ToggleRowProps) {
  return (
    <div className="flex items-start gap-3">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 transition-colors duration-200 focus:outline-none ${
          checked ? '' : 'bg-slate-700 border-slate-700'
        }`}
        style={checked ? { background: 'var(--cs-accent)', borderColor: 'var(--cs-accent)' } : undefined}
      >
        <span
          className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transform transition-transform duration-200 translate-y-[-1px] ${
            checked ? 'translate-x-[14px]' : 'translate-x-0'
          }`}
        />
      </button>
      <div>
        <p className="text-xs text-slate-300 font-medium leading-none mb-0.5">{label}</p>
        <p className="text-xs text-slate-500">{description}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 5. Config / enablement status section
// ---------------------------------------------------------------------------

type StatusState = 'active' | 'default' | 'off' | 'caution';

interface SettingStatus {
  key: string;
  category: string;
  description: string;
  isSet: boolean;
  effectiveValue: string;
  enabled: boolean;
  state: StatusState;
  detail?: string;
}

interface ConfigStatusResponse {
  settings: SettingStatus[];
  summary: { active: number; caution: number; off: number; default: number };
  categoryOrder: string[];
  generatedAt: string;
}

/** Icon + text + color per state — a11y: never color alone. */
function StatusBadge({ state }: { state: StatusState }) {
  const map: Record<StatusState, { label: string; icon: React.ReactNode; bg: string; fg: string; border: string }> = {
    active:  { label: 'ACTIVE',  icon: <CheckCircle2 className="w-3 h-3" />,   bg: 'rgba(0,212,170,0.12)', fg: 'var(--cs-accent)', border: 'var(--cs-accent-dim)' },
    caution: { label: 'CAUTION', icon: <AlertTriangle className="w-3 h-3" />,  bg: 'rgba(255,178,36,0.12)', fg: 'var(--cs-warn)',   border: 'rgba(255,178,36,0.30)' },
    off:     { label: 'OFF',     icon: <CircleSlash className="w-3 h-3" />,    bg: 'rgba(139,144,160,0.10)', fg: 'var(--cs-text-muted)', border: 'var(--cs-border-soft)' },
    default: { label: 'DEFAULT', icon: <CircleSlash className="w-3 h-3" />,    bg: 'rgba(139,144,160,0.10)', fg: 'var(--cs-text-muted)', border: 'var(--cs-border-soft)' },
  };
  const s = map[state];
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wide shrink-0"
      style={{ background: s.bg, color: s.fg, border: `1px solid ${s.border}` }}
    >
      {s.icon}{s.label}
    </span>
  );
}

function ConfigStatusSection() {
  const [data,  setData]  = useState<ConfigStatusResponse | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    fetch('/api/config/status')
      .then(r => r.json())
      .then((d: ConfigStatusResponse) => { setData(d); setError(''); })
      .catch(() => setError('Failed to load config status'));
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000); // live-refresh derived signals
    return () => clearInterval(id);
  }, [load]);

  if (error) return <p className="text-[11px] text-red-400 font-mono mt-3">{error}</p>;
  if (!data) return <p className="text-[11px] text-slate-500 font-mono mt-3">Loading runtime status…</p>;

  const cats = data.categoryOrder.filter(c => data.settings.some(s => s.category === c));

  return (
    <div className="space-y-4 mt-3">
      {/* Summary chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
          style={{ background: 'rgba(0,212,170,0.12)', color: 'var(--cs-accent)', border: '1px solid var(--cs-accent-dim)' }}>
          <CheckCircle2 className="w-3 h-3" /> {data.summary.active} active
        </span>
        {data.summary.caution > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
            style={{ background: 'rgba(255,178,36,0.12)', color: 'var(--cs-warn)', border: '1px solid rgba(255,178,36,0.30)' }}>
            <AlertTriangle className="w-3 h-3" /> {data.summary.caution} need attention
          </span>
        )}
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
          style={{ background: 'rgba(139,144,160,0.10)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border-soft)' }}>
          <CircleSlash className="w-3 h-3" /> {data.summary.off + data.summary.default} default/off
        </span>
        <span className="inline-flex items-center gap-1 text-[10px] text-slate-600 font-mono ml-auto">
          <Activity className="w-3 h-3" /> live
        </span>
      </div>

      {cats.map(cat => (
        <div key={cat}>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2">{cat}</p>
          <div className="space-y-2">
            {data.settings.filter(s => s.category === cat).map(s => (
              <div
                key={s.key}
                className="flex flex-col sm:flex-row sm:items-start gap-1.5 sm:gap-3 px-3 py-2.5 bg-slate-800/50 rounded-lg border border-slate-800"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-[11px] font-mono text-slate-200 break-all">{s.key}</code>
                    <StatusBadge state={s.state} />
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1 leading-relaxed">{s.description}</p>
                  {s.detail && (
                    <p className="text-[10px] text-slate-600 mt-0.5 italic">{s.detail}</p>
                  )}
                </div>
                <div className="shrink-0 sm:text-right sm:max-w-[42%] sm:pl-2">
                  <p className="text-[9px] uppercase tracking-wider text-slate-600 mb-0.5">Effective</p>
                  <code className="text-[11px] font-mono text-slate-300 break-all">{s.effectiveValue}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 6. Env Reference section
// ---------------------------------------------------------------------------

function EnvCopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="p-1 rounded hover:bg-slate-700 transition-colors"
      title="Copy"
    >
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3 text-slate-500" />}
    </button>
  );
}

interface EnvVar {
  key: string;
  description: string;
  default: string;
  category: string;
  sensitive?: boolean;
  currentValue: string;
  isSet: boolean;
}

function EnvReferenceSection() {
  const [vars, setVars] = useState<EnvVar[]>([]);

  useEffect(() => {
    fetch('/api/config/env-reference')
      .then(r => r.json())
      .then(d => setVars(d.envVars ?? []))
      .catch(() => {});
  }, []);

  const categories = [...new Set(vars.map(v => v.category))];

  return (
    <div className="space-y-4 mt-3">
      {/* Quick setup command */}
      <div className="flex items-center gap-2 px-3 py-2 bg-slate-800 rounded-lg">
        <Terminal className="w-3.5 h-3.5" style={{ color: 'var(--cs-accent)' }} />
        <code className="text-xs text-slate-300 font-mono flex-1">npx claudesec init</code>
        <EnvCopyButton text="npx claudesec init" />
      </div>

      {categories.map(cat => (
        <div key={cat}>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2">{cat}</p>
          <div className="space-y-1">
            {vars.filter(v => v.category === cat).map(v => (
              <div key={v.key} className="flex items-start gap-2 px-3 py-2 bg-slate-800/50 rounded-lg group">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="text-[11px] font-mono text-slate-200">{v.key}</code>
                    {v.isSet && (
                      <span className="px-1 py-0.5 rounded text-[9px] font-mono bg-green-900/30 text-green-400 border border-green-800/30">SET</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500 mt-0.5">{v.description}</p>
                  {v.default && (
                    <p className="text-[11px] text-slate-600 mt-0.5">Default: <code className="font-mono">{v.default}</code></p>
                  )}
                </div>
                <EnvCopyButton text={v.key} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Data management — clear synthetic demo data (always safe) and the gated full reset
// ---------------------------------------------------------------------------
function DataManagementSection(): React.ReactElement {
  const [demoSessions, setDemoSessions] = useState(0);
  const [resetEnabled, setResetEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  // Two-click confirm for the destructive full reset — no native confirm() dialog,
  // which ad blockers and some browsers suppress.
  const [confirmAll, setConfirmAll] = useState(false);
  // Hold the confirm-window timer so it's cleared on unmount (no state update
  // after the Settings tab is closed mid-confirm).
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (confirmTimer.current) clearTimeout(confirmTimer.current); }, []);

  const load = useCallback(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then(d => { setDemoSessions(d.demoSessions ?? 0); setResetEnabled(!!d.resetEnabled); })
      .catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  const clearDemo = async () => {
    setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/demo/clear', { method: 'POST' });
      const d = await r.json();
      setMsg(`Cleared ${d.clearedSpans ?? 0} demo spans across ${d.clearedSessions ?? 0} session(s).`);
      load();
    } catch { setMsg('Failed to clear demo data.'); }
    finally { setBusy(false); }
  };

  const clearAll = async () => {
    if (!confirmAll) {
      setConfirmAll(true);
      if (confirmTimer.current) clearTimeout(confirmTimer.current);
      confirmTimer.current = setTimeout(() => setConfirmAll(false), 4000);
      return;
    }
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    setConfirmAll(false); setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/reset', { method: 'POST' });
      if (r.ok) { setMsg('All data cleared.'); load(); }
      else { const d = await r.json().catch(() => ({})); setMsg(d.hint ?? d.error ?? 'Reset failed.'); }
    } catch { setMsg('Reset failed.'); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-3">
      {/* Demo data — ungated, only ever deletes demo-* rows */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="text-xs font-medium text-slate-200">Demo data</div>
          <div className="text-[11px] text-slate-500">
            {demoSessions > 0
              ? `${demoSessions} synthetic demo session(s) present. Safe to remove anytime — only demo rows are deleted.`
              : 'No demo data present.'}
          </div>
        </div>
        <button
          type="button"
          onClick={clearDemo}
          disabled={busy || demoSessions === 0}
          className="px-3 py-1.5 text-xs rounded-lg shrink-0 transition-colors"
          style={{
            border: '1px solid var(--cs-border)', background: 'var(--cs-bg-elevated)',
            color: demoSessions === 0 ? 'var(--cs-text-faint)' : 'var(--cs-text-base)',
            opacity: busy || demoSessions === 0 ? 0.5 : 1,
          }}
        >
          Clear demo data
        </button>
      </div>

      {/* Full reset — gated behind CLAUDESEC_ALLOW_RESET; visible and explained either way */}
      <div className="flex items-center justify-between gap-3 flex-wrap pt-2" style={{ borderTop: '1px solid var(--cs-border)' }}>
        <div className="min-w-0">
          <div className="text-xs font-medium text-slate-200">Clear all data</div>
          <div className="text-[11px] text-slate-500">
            {resetEnabled
              ? 'Permanently deletes every span, session, and alert. This cannot be undone.'
              : 'Disabled for safety. Start the server with CLAUDESEC_ALLOW_RESET=1 to enable this.'}
          </div>
        </div>
        <button
          type="button"
          onClick={clearAll}
          disabled={busy || !resetEnabled}
          className="px-3 py-1.5 text-xs rounded-lg shrink-0 transition-colors"
          style={{
            border: `1px solid ${confirmAll ? '#ef4444' : 'var(--cs-border)'}`,
            background: confirmAll ? 'rgba(239,68,68,0.15)' : 'var(--cs-bg-elevated)',
            color: !resetEnabled ? 'var(--cs-text-faint)' : confirmAll ? '#fca5a5' : 'var(--cs-text-base)',
            opacity: busy || !resetEnabled ? 0.5 : 1,
          }}
        >
          {confirmAll ? 'Click again to confirm' : 'Clear all data'}
        </button>
      </div>

      {msg && <p className="text-[11px]" style={{ color: 'var(--cs-text-muted)' }}>{msg}</p>}
    </div>
  );
}

export function SettingsTab(): React.ReactElement {
  return (
    <div className="flex-1 overflow-auto p-5 min-h-0" style={{ background: 'var(--cs-bg-primary)' }}>
      <div className="max-w-2xl mx-auto space-y-4">

        {/* Header */}
        <div className="flex items-center gap-2 mb-2">
          <Settings className="w-5 h-5" style={{ color: 'var(--cs-accent)' }} />
          <h2 className="text-sm font-bold text-slate-200">Settings</h2>
        </div>

        <Section icon={<ShieldCheck className="w-4 h-4" />} title="Configuration Status">
          <p className="text-xs text-slate-500 mb-1 leading-relaxed">
            Live runtime state of each setting — whether the feature is actually
            <span className="text-slate-300"> active</span>, at its
            <span className="text-slate-300"> default</span>, or needs
            <span style={{ color: 'var(--cs-warn)' }}> attention</span>. Secrets are masked.
            Refreshes automatically.
          </p>
          <ConfigStatusSection />
        </Section>

        <Section icon={<Database className="w-4 h-4" />} title="Retention">
          <RetentionSection />
        </Section>

        <Section icon={<Trash2 className="w-4 h-4" />} title="Data">
          <DataManagementSection />
        </Section>

        <Section icon={<Terminal className="w-4 h-4" />} title="Environment Variables" defaultOpen={false}>
          <p className="text-xs text-slate-500 mb-1 leading-relaxed">
            All configuration options available via environment variables.
            Set these before starting the server. Sensitive values are masked.
          </p>
          <EnvReferenceSection />
        </Section>

        <Section icon={<Monitor className="w-4 h-4" />} title="Rate Limiting">
          <RateLimitSection />
        </Section>

        <Section icon={<Globe className="w-4 h-4" />} title="Webhook">
          <WebhookSection />
        </Section>

        <Section icon={<Monitor className="w-4 h-4" />} title="Display">
          <DisplaySection />
        </Section>

        <Section icon={<BellRing className="w-4 h-4" />} title="Threshold Rules" defaultOpen={false}>
          <p className="text-xs text-slate-500 mb-1 leading-relaxed">
            Trigger alerts when a session metric exceeds a threshold within a time window.
            Fired alerts appear in the Alerts tab.
          </p>
          <ThresholdRulesSection />
        </Section>

        <Section icon={<History className="w-4 h-4" />} title="Webhook Delivery Log" defaultOpen={false}>
          <p className="text-xs text-slate-500 mb-1 leading-relaxed">
            Every webhook attempt is logged here. Failed deliveries auto-retry up to 3×
            with exponential backoff. Manually retry or clear history below.
          </p>
          <WebhookDeliverySection />
        </Section>

      </div>
    </div>
  );
}
