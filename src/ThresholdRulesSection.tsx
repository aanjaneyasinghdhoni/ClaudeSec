import React, { useEffect, useState, useCallback } from 'react';
import { Plus, Trash2, Loader2, Sparkles, BellRing } from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ThresholdRule {
  id: number;
  name: string;
  metric: string;
  operator: string;
  value: number;
  window_min: number;
  enabled: number;
  createdAt: string;
}

interface RulesResponse {
  rules: ThresholdRule[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const METRIC_LABELS: Record<string, string> = {
  tokens_in:        'Input Tokens',
  tokens_out:       'Output Tokens',
  threat_count:     'Threat Count',
  span_count:       'Span Count',
  high_threat_count: 'HIGH Threat Count',
};

const OPERATOR_LABELS: Record<string, string> = {
  '>':  '>',
  '>=': '≥',
  '<':  '<',
  '<=': '≤',
  '=':  '=',
};

const METRIC_OPTIONS = Object.entries(METRIC_LABELS);
const OPERATOR_OPTIONS = Object.entries(OPERATOR_LABELS);

// A worked example, not a blank form. This is what most operators actually
// want first — a runaway session firing enough HIGH-severity detections in a
// short window to be worth an interrupt — so the empty state can hand it over
// as one click instead of five decisions.
const EXAMPLE_RULE = {
  name: 'Runaway session',
  metric: 'high_threat_count',
  operator: '>=',
  value: 3,
  windowMin: 15,
} as const;

// ---------------------------------------------------------------------------
// Toggle switch (reused from SettingsTab style)
// ---------------------------------------------------------------------------

interface ToggleSwitchProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}

function ToggleSwitch({ checked, onChange, disabled }: ToggleSwitchProps): React.ReactElement {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 transition-colors duration-200 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
      style={checked
        ? { background: 'var(--cs-accent)', borderColor: 'var(--cs-accent)' }
        : { background: 'var(--cs-bg-overlay)', borderColor: 'var(--cs-rule-strong)' }}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full shadow transform transition-transform duration-200 translate-y-[-1px] ${
          checked ? 'translate-x-[14px]' : 'translate-x-0'
        }`}
        style={{ background: 'var(--cs-text-invert)' }}
      />
    </button>
  );
}

const inputCls = 'w-full px-3 py-1.5 rounded-lg text-xs focus:outline-none';
const inputStyle: React.CSSProperties = { background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' };
const labelStyle: React.CSSProperties = { fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' };

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ThresholdRulesSection(): React.ReactElement {
  const [rules,   setRules]   = useState<ThresholdRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  // Form state
  const [name,      setName]      = useState('');
  const [metric,    setMetric]    = useState('tokens_in');
  const [operator,  setOperator]  = useState('>');
  const [value,     setValue]     = useState<number>(0);
  const [windowMin, setWindowMin] = useState<number>(60);
  const [submitting, setSubmitting] = useState(false);
  const [formError,  setFormError]  = useState('');

  // Per-row loading state for toggle/delete
  const [busyIds, setBusyIds] = useState<Set<number>>(new Set());

  const fetchRules = useCallback(() => {
    fetch('/api/threshold-rules')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<RulesResponse>;
      })
      .then(d => { setRules(d.rules ?? []); setLoading(false); setError(''); })
      .catch(() => { setError('Failed to load threshold rules'); setLoading(false); });
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  // Toggle enabled
  const handleToggle = async (rule: ThresholdRule) => {
    setBusyIds(prev => new Set(prev).add(rule.id));
    try {
      const res = await fetch(`/api/threshold-rules/${rule.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: rule.enabled ? 0 : 1 }),
      });
      if (res.ok) {
        setRules(prev =>
          prev.map(r => r.id === rule.id ? { ...r, enabled: r.enabled ? 0 : 1 } : r)
        );
      }
    } finally {
      setBusyIds(prev => { const s = new Set(prev); s.delete(rule.id); return s; });
    }
  };

  // Delete rule
  const handleDelete = async (id: number) => {
    setBusyIds(prev => new Set(prev).add(id));
    try {
      const res = await fetch(`/api/threshold-rules/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setRules(prev => prev.filter(r => r.id !== id));
      }
    } finally {
      setBusyIds(prev => { const s = new Set(prev); s.delete(id); return s; });
    }
  };

  // Add rule
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    if (!name.trim()) { setFormError('Name is required'); return; }
    if (isNaN(value))  { setFormError('Value must be a number'); return; }
    if (windowMin < 1) { setFormError('Window must be at least 1 minute'); return; }

    setSubmitting(true);
    try {
      const res = await fetch('/api/threshold-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          metric,
          operator,
          value,
          window_min: windowMin,
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({})) as { error?: string };
        setFormError(d.error ?? 'Failed to add rule');
      } else {
        setName(''); setMetric('tokens_in'); setOperator('>');
        setValue(0); setWindowMin(60);
        fetchRules();
      }
    } catch {
      setFormError('Network error');
    } finally {
      setSubmitting(false);
    }
  };

  // Load the worked example straight into the form — the empty state's "try
  // this" affordance. It only fills the fields; the operator still has to
  // submit, so nothing is created without an explicit action.
  const useExample = () => {
    setName(EXAMPLE_RULE.name);
    setMetric(EXAMPLE_RULE.metric);
    setOperator(EXAMPLE_RULE.operator);
    setValue(EXAMPLE_RULE.value);
    setWindowMin(EXAMPLE_RULE.windowMin);
    setFormError('');
  };

  return (
    <div className="space-y-4 mt-3">

      {/* Error loading */}
      {error && (
        <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>{error}</p>
      )}

      {/* Loading state */}
      {loading && (
        <div className="space-y-2" aria-busy="true" aria-label="Loading threshold rules">
          {[0, 1].map(i => (
            <div key={i} className="h-9 w-full rounded-lg animate-pulse" style={{ background: 'var(--cs-bg-raised)' }} />
          ))}
        </div>
      )}

      {/* Rules table */}
      {!loading && (
        <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}>
          {rules.length === 0 ? (
            // threshold_rules has had zero rows across every install so far —
            // this feature has never had a first user see it fire. The bare
            // "no rules yet" line looked like a broken table; this instead
            // explains the job (session-level metric alerts, not per-span
            // rules) and hands over one concrete, good first rule to try.
            <div className="flex flex-col items-center gap-3 px-6 py-8 text-center">
              <BellRing className="w-6 h-6" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
              <div className="space-y-1 max-w-sm">
                <p style={{ fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-medium)', color: 'var(--cs-text-body)' }}>
                  No threshold rules yet
                </p>
                <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', lineHeight: 'var(--cs-leading-normal)' }}>
                  A threshold rule watches a <em>session</em>, not a single span — it fires when a
                  metric like token volume or threat count crosses a value within a rolling time
                  window, and the fired alert lands in the Alerts tab just like a detection rule.
                  Good for catching a session that is quietly getting worse rather than tripping
                  one bad line.
                </p>
              </div>
              <div
                className="w-full max-w-sm rounded-lg p-3 text-left"
                style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule)' }}
              >
                <p className="flex items-center gap-1.5 mb-1" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
                  <Sparkles className="w-3 h-3" aria-hidden="true" /> A good first rule
                </p>
                <p className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>
                  "{EXAMPLE_RULE.name}" — {METRIC_LABELS[EXAMPLE_RULE.metric]} {OPERATOR_LABELS[EXAMPLE_RULE.operator]} {EXAMPLE_RULE.value} within {EXAMPLE_RULE.windowMin}m
                </p>
                <p className="mt-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
                  Three or more HIGH-severity detections in the same session inside 15 minutes —
                  a pattern worth an interrupt, not just a log line.
                </p>
                <button
                  type="button"
                  onClick={useExample}
                  className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
                  style={{ background: 'var(--cs-accent)', color: 'var(--cs-text-invert)' }}
                >
                  Use this example below
                </button>
              </div>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--cs-rule)' }}>
                  {['Name', 'Metric', 'Condition', 'Window', 'Enabled', ''].map(h => (
                    <th
                      key={h}
                      className={`px-3 py-2.5 text-left ${h === '' ? 'w-8' : ''}`}
                      style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => {
                  const busy = busyIds.has(rule.id);
                  return (
                    <tr
                      key={rule.id}
                      className="transition-colors hover:bg-[var(--cs-bg-raised)]"
                      style={{ borderBottom: '1px solid var(--cs-rule)' }}
                    >
                      <td className="px-3 py-2 font-medium max-w-[120px] truncate" style={{ color: 'var(--cs-text-body)' }} title={rule.name}>
                        {rule.name}
                      </td>
                      <td className="px-3 py-2" style={{ color: 'var(--cs-text-muted)' }}>
                        {METRIC_LABELS[rule.metric] ?? rule.metric}
                      </td>
                      <td className="px-3 py-2 cs-mono" style={{ color: 'var(--cs-text-body)' }}>
                        {OPERATOR_LABELS[rule.operator] ?? rule.operator}{' '}
                        <span style={{ color: 'var(--cs-info)' }}>{rule.value.toLocaleString()}</span>
                      </td>
                      <td className="px-3 py-2" style={{ color: 'var(--cs-text-muted)' }}>
                        {rule.window_min}m
                      </td>
                      <td className="px-3 py-2">
                        <ToggleSwitch
                          checked={!!rule.enabled}
                          onChange={() => handleToggle(rule)}
                          disabled={busy}
                        />
                      </td>
                      <td className="px-3 py-2">
                        <button
                          type="button"
                          onClick={() => handleDelete(rule.id)}
                          disabled={busy}
                          className="p-1 rounded transition-colors disabled:opacity-40 hover:bg-[var(--cs-bg-raised)]"
                          style={{ color: 'var(--cs-text-faint)' }}
                          title="Delete rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Add Rule form */}
      <form
        onSubmit={handleSubmit}
        className="rounded-xl p-4 space-y-3"
        style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}
      >
        <p className="flex items-center gap-1.5 font-bold" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
          <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add rule
        </p>

        {/* Name */}
        <div>
          <label className="block mb-1" style={labelStyle}>Name</label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. High token alert"
            className={inputCls}
            style={inputStyle}
          />
        </div>

        {/* Metric + Operator + Value */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          <div>
            <label className="block mb-1" style={labelStyle}>Metric</label>
            <select
              value={metric}
              onChange={e => setMetric(e.target.value)}
              className={inputCls}
              style={inputStyle}
            >
              {METRIC_OPTIONS.map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block mb-1" style={labelStyle}>Operator</label>
            <select
              value={operator}
              onChange={e => setOperator(e.target.value)}
              className={inputCls}
              style={inputStyle}
            >
              {OPERATOR_OPTIONS.map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block mb-1" style={labelStyle}>Value</label>
            <input
              type="number"
              value={value}
              onChange={e => setValue(Number(e.target.value))}
              className={inputCls}
              style={inputStyle}
            />
          </div>
        </div>

        {/* Window */}
        <div className="w-1/3">
          <label className="block mb-1" style={labelStyle}>Window (minutes)</label>
          <input
            type="number"
            min={1}
            value={windowMin}
            onChange={e => setWindowMin(Number(e.target.value))}
            className={inputCls}
            style={inputStyle}
          />
        </div>

        {formError && (
          <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>{formError}</p>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={submitting}
            className="flex items-center gap-1.5 px-4 py-1.5 disabled:opacity-50 rounded-lg text-xs font-medium transition-colors hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
            style={{ background: 'var(--cs-accent)', color: 'var(--cs-text-invert)' }}
          >
            {submitting
              ? <><Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> Adding…</>
              : <><Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add rule</>
            }
          </button>
        </div>
      </form>
    </div>
  );
}
