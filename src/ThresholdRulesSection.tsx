import React, { useEffect, useState, useCallback } from 'react';
import { Plus, Trash2, Loader2 } from 'lucide-react';

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
      className={`relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 transition-colors duration-200 focus:outline-none disabled:opacity-50 ${
        checked ? 'bg-blue-600 border-blue-600' : 'bg-slate-700 border-slate-700'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow transform transition-transform duration-200 translate-y-[-1px] ${
          checked ? 'translate-x-[14px]' : 'translate-x-0'
        }`}
      />
    </button>
  );
}

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
      .then(d => { setRules(d.rules ?? []); setLoading(false); })
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

  return (
    <div className="space-y-4 mt-3">

      {/* Error loading */}
      {error && (
        <p className="text-[11px] text-red-400 font-mono">{error}</p>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center gap-2 py-4 text-slate-500 text-xs">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          Loading rules…
        </div>
      )}

      {/* Rules table */}
      {!loading && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          {rules.length === 0 ? (
            <p className="px-4 py-6 text-center text-[12px] text-slate-600 italic">
              No threshold rules yet. Add one below.
            </p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
                  <th className="px-3 py-2.5 text-left">Name</th>
                  <th className="px-3 py-2.5 text-left">Metric</th>
                  <th className="px-3 py-2.5 text-left">Condition</th>
                  <th className="px-3 py-2.5 text-left">Window</th>
                  <th className="px-3 py-2.5 text-left">Enabled</th>
                  <th className="px-3 py-2.5 text-left w-8" />
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => {
                  const busy = busyIds.has(rule.id);
                  return (
                    <tr
                      key={rule.id}
                      className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors"
                    >
                      <td className="px-3 py-2 text-slate-200 font-medium max-w-[120px] truncate" title={rule.name}>
                        {rule.name}
                      </td>
                      <td className="px-3 py-2 text-slate-400">
                        {METRIC_LABELS[rule.metric] ?? rule.metric}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-300">
                        {OPERATOR_LABELS[rule.operator] ?? rule.operator}{' '}
                        <span className="text-blue-300">{rule.value.toLocaleString()}</span>
                      </td>
                      <td className="px-3 py-2 text-slate-400">
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
                          className="p-1 hover:bg-slate-700 rounded text-slate-600 hover:text-red-400 transition-colors disabled:opacity-40"
                          title="Delete rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
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
        className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3"
      >
        <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5" /> Add Rule
        </p>

        {/* Name */}
        <div>
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Name</label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. High token alert"
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
          />
        </div>

        {/* Metric + Operator + Value */}
        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Metric</label>
            <select
              value={metric}
              onChange={e => setMetric(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
            >
              {METRIC_OPTIONS.map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Operator</label>
            <select
              value={operator}
              onChange={e => setOperator(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
            >
              {OPERATOR_OPTIONS.map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Value</label>
            <input
              type="number"
              value={value}
              onChange={e => setValue(Number(e.target.value))}
              className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
            />
          </div>
        </div>

        {/* Window */}
        <div className="w-1/3">
          <label className="block text-xs text-slate-500 mb-1 uppercase tracking-wider">Window (minutes)</label>
          <input
            type="number"
            min={1}
            value={windowMin}
            onChange={e => setWindowMin(Number(e.target.value))}
            className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
          />
        </div>

        {formError && (
          <p className="text-[11px] text-red-400 font-mono">{formError}</p>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={submitting}
            className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
          >
            {submitting
              ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Adding…</>
              : <><Plus className="w-3.5 h-3.5" /> Add Rule</>
            }
          </button>
        </div>
      </form>
    </div>
  );
}
