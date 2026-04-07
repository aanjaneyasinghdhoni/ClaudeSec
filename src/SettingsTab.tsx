import React, { useEffect, useState, useCallback } from 'react';
import { Settings, Database, Globe, Monitor, ChevronDown, ChevronUp, Check, BellRing } from 'lucide-react';
import { ThresholdRulesSection } from './ThresholdRulesSection';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DbStats {
  spanCount: number;
  maxSpans: number;
  retentionDays: number;
  dbSizeBytes: number;
}

interface RateLimitInfo {
  rps: number;
  burst: number;
  maxSpansBatch: number;
}

interface WebhookConfig {
  url: string;
  threshold: 'low' | 'medium' | 'high';
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

function Section({ icon, title, children, defaultOpen = true }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-slate-800/40 transition-colors"
      >
        <span className="text-blue-400">{icon}</span>
        <span className="text-sm font-semibold text-slate-200 flex-1">{title}</span>
        {open
          ? <ChevronUp className="w-4 h-4 text-slate-500" />
          : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>

      <div
        className="overflow-hidden transition-all duration-200"
        style={{ maxHeight: open ? '2000px' : '0px' }}
      >
        <div className="px-4 pb-4 pt-1 border-t border-slate-800">
          {children}
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
      className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
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

function RetentionSection() {
  const [maxSpans,       setMaxSpans]       = useState<number>(50_000);
  const [retentionDays,  setRetentionDays]  = useState<number>(30);
  const [stats,          setStats]          = useState<DbStats | null>(null);
  const [error,          setError]          = useState('');

  useEffect(() => {
    fetch('/api/db-stats')
      .then(r => r.json())
      .then((d: DbStats) => {
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
          <label className="block text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Max Spans</label>
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
          <label className="block text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Retention Days</label>
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

function RateLimitSection() {
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
      <p className="text-[10px] text-slate-600 italic mt-2">
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

function WebhookSection() {
  const [url,         setUrl]         = useState('');
  const [threshold,   setThreshold]   = useState<'low' | 'medium' | 'high'>('high');
  const [configured,  setConfigured]  = useState(false);
  const [testMsg,     setTestMsg]     = useState('');
  const [testOk,      setTestOk]      = useState<boolean | null>(null);
  const [error,       setError]       = useState('');

  const load = useCallback(() => {
    fetch('/api/webhook')
      .then(r => r.json())
      .then((d: Partial<WebhookConfig>) => {
        if (d.url) { setUrl(d.url); setConfigured(true); }
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
  }, [url, threshold]);

  const handleDelete = async () => {
    setError('');
    const res = await fetch('/api/webhook', { method: 'DELETE' });
    if (res.ok) {
      setUrl('');
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
          <label className="block text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Webhook URL</label>
          <div className="relative">
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://hooks.example.com/..."
              className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500 pr-20"
            />
            {configured && (
              <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] font-mono px-1.5 py-0.5 rounded bg-green-900/40 text-green-300 border border-green-700/40">
                configured
              </span>
            )}
          </div>
        </div>
        <div>
          <label className="block text-[10px] text-slate-500 mb-1 uppercase tracking-wider">Min Threshold</label>
          <select
            value={threshold}
            onChange={e => setThreshold(e.target.value as 'low' | 'medium' | 'high')}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
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
        <SaveButton onClick={save} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 4. Display preferences section
// ---------------------------------------------------------------------------

function DisplaySection() {
  const [hideNone,    setHideNone]    = useState(() => localStorage.getItem('claudesec.hideNone')    === 'true');
  const [autoLayout,  setAutoLayout]  = useState(() => localStorage.getItem('claudesec.autoLayout')  !== 'false');

  const toggle = (key: string, value: boolean, setter: (v: boolean) => void) => {
    setter(value);
    localStorage.setItem(key, String(value));
  };

  return (
    <div className="space-y-3 mt-3">
      <ToggleRow
        label="Hide safe spans in graph"
        description="Suppress spans with no threat (severity: none) from the React Flow canvas."
        checked={hideNone}
        onChange={v => toggle('claudesec.hideNone', v, setHideNone)}
      />
      <ToggleRow
        label="Auto-layout on update"
        description="Re-run Dagre layout automatically when new spans arrive."
        checked={autoLayout}
        onChange={v => toggle('claudesec.autoLayout', v, setAutoLayout)}
      />
      <p className="text-[10px] text-slate-600 italic">Settings are saved locally in your browser.</p>
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
          checked ? 'bg-blue-600 border-blue-600' : 'bg-slate-700 border-slate-700'
        }`}
      >
        <span
          className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transform transition-transform duration-200 translate-y-[-1px] ${
            checked ? 'translate-x-[14px]' : 'translate-x-0'
          }`}
        />
      </button>
      <div>
        <p className="text-xs text-slate-300 font-medium leading-none mb-0.5">{label}</p>
        <p className="text-[10px] text-slate-500">{description}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function SettingsTab(): React.ReactElement {
  return (
    <div className="flex-1 overflow-auto p-5 bg-slate-950 min-h-0">
      <div className="max-w-2xl mx-auto space-y-4">

        {/* Header */}
        <div className="flex items-center gap-2 mb-2">
          <Settings className="w-5 h-5 text-blue-400" />
          <h2 className="text-sm font-bold text-slate-200">Settings</h2>
        </div>

        <Section icon={<Database className="w-4 h-4" />} title="Retention">
          <RetentionSection />
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
          <p className="text-[10px] text-slate-500 mb-1 leading-relaxed">
            Trigger alerts when a session metric exceeds a threshold within a time window.
            Fired alerts appear in the Alerts tab.
          </p>
          <ThresholdRulesSection />
        </Section>

      </div>
    </div>
  );
}
