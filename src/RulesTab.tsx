import React, { useEffect, useState } from 'react';
import { Shield, Trash2, Plus, FlaskConical, Clock, X } from 'lucide-react';
import { socket } from './socket';

type Severity = 'none' | 'low' | 'medium' | 'high';

interface RuleRow {
  id: string;
  pattern: string;
  flags: string;
  severity: Severity;
  label: string;
  builtin?: boolean;
}

interface Suppression {
  id: number;
  ruleKey: string;
  suppressUntil: string;
  reason: string;
  createdAt: string;
}

interface RulesResponse {
  builtIn: RuleRow[];
  custom: RuleRow[];
}

const SEV_BADGE: Record<string, string> = {
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  none:   'bg-slate-800 text-slate-400',
};

const SNOOZE_OPTIONS: { label: string; ms: number }[] = [
  { label: '1 hour',  ms: 1 * 60 * 60 * 1000 },
  { label: '4 hours', ms: 4 * 60 * 60 * 1000 },
  { label: '24 hours', ms: 24 * 60 * 60 * 1000 },
  { label: '7 days',  ms: 7 * 24 * 60 * 60 * 1000 },
];

function formatCountdown(until: string): string {
  const ms = new Date(until).getTime() - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h > 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0)  return `${h}h ${m}m`;
  return `${m}m`;
}

export function RulesTab() {
  const [rules,        setRules]        = useState<{ builtIn: RuleRow[]; custom: RuleRow[] }>({ builtIn: [], custom: [] });
  const [suppressions, setSuppressions] = useState<Suppression[]>([]);
  const [snoozeMenuId, setSnoozeMenuId] = useState<string | null>(null);
  const [, setTick]  = useState(0); // force re-render for countdowns

  // Form state
  const [pattern,    setPattern]    = useState('');
  const [severity,   setSeverity]   = useState<'low' | 'medium' | 'high'>('medium');
  const [label,      setLabel]      = useState('');
  const [testInput,  setTestInput]  = useState('');
  const [testResult, setTestResult] = useState<null | boolean>(null);
  const [error,      setError]      = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchRules = () =>
    fetch('/api/rules')
      .then(r => r.json())
      .then((data: RulesResponse) => setRules(data))
      .catch(() => {});

  const fetchSuppressions = () =>
    fetch('/api/suppressions')
      .then(r => r.json())
      .then(({ suppressions: s }: { suppressions: Suppression[] }) => setSuppressions(s ?? []))
      .catch(() => {});

  useEffect(() => {
    fetchRules();
    fetchSuppressions();
    socket.on('rules-update', () => { fetchRules(); fetchSuppressions(); });
    return () => { socket.off('rules-update'); };
  }, []);

  // Countdown refresh every 30s
  useEffect(() => {
    const iv = setInterval(() => setTick(n => n + 1), 30_000);
    return () => clearInterval(iv);
  }, []);

  const activeSuppression = (ruleId: string): Suppression | undefined =>
    suppressions.find(s => s.ruleKey === ruleId && new Date(s.suppressUntil) > new Date());

  const handleSnooze = async (ruleId: string, ms: number) => {
    setSnoozeMenuId(null);
    await fetch('/api/suppressions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleKey: ruleId, durationMs: ms, reason: 'manual snooze' }),
    });
    fetchSuppressions();
  };

  const handleCancelSnooze = async (suppressionId: number) => {
    await fetch(`/api/suppressions/${suppressionId}`, { method: 'DELETE' });
    fetchSuppressions();
  };

  const handleTest = () => {
    if (!pattern || !testInput) { setTestResult(null); return; }
    try {
      const re = new RegExp(pattern, 'i');
      setTestResult(re.test(testInput));
    } catch {
      setTestResult(null);
      setError('Invalid regex pattern');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!pattern.trim() || !label.trim()) { setError('Pattern and label are required'); return; }
    try { new RegExp(pattern); } catch { setError('Invalid regex pattern'); return; }
    setSubmitting(true);
    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: pattern.trim(), severity, label: label.trim() }),
      });
      if (!res.ok) {
        const d = await res.json();
        setError(d.error ?? 'Failed to add rule');
      } else {
        setPattern(''); setLabel(''); setTestInput(''); setTestResult(null);
      }
    } catch { setError('Network error'); }
    setSubmitting(false);
  };

  const handleDelete = async (id: string) => {
    await fetch(`/api/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  };

  const allRules: (RuleRow & { type: 'built-in' | 'custom' })[] = [
    ...rules.builtIn.map(r => ({ ...r, type: 'built-in' as const })),
    ...rules.custom.map(r => ({ ...r, type: 'custom' as const })),
  ];

  return (
    <div className="flex-1 overflow-auto p-5 bg-slate-950 min-h-0" onClick={() => setSnoozeMenuId(null)}>
      <div className="max-w-5xl mx-auto space-y-6">

        {/* Header */}
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <h2 className="text-sm font-bold text-slate-200">Threat Detection Rules</h2>
          <span className="ml-auto text-[10px] font-mono text-slate-500">
            {rules.builtIn.length} built-in · {rules.custom.length} custom
            {suppressions.length > 0 && (
              <span className="ml-1 text-yellow-400">· {suppressions.length} snoozed</span>
            )}
          </span>
        </div>

        {/* Add custom rule form */}
        <form
          onSubmit={handleSubmit}
          className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3"
          onClick={e => e.stopPropagation()}
        >
          <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5" /> Add Custom Rule
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-[10px] text-slate-500 mb-1">Pattern (regex)</label>
              <input
                type="text"
                value={pattern}
                onChange={e => { setPattern(e.target.value); setTestResult(null); setError(''); }}
                placeholder="e.g. curl\s+.*\|\s*(ba)?sh"
                className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
              />
            </div>
            <div>
              <label className="block text-[10px] text-slate-500 mb-1">Severity</label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value as 'low' | 'medium' | 'high')}
                className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-slate-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] text-slate-500 mb-1">Label</label>
            <input
              type="text"
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="e.g. Suspicious curl pipe"
              className="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
            />
          </div>

          {/* Test input */}
          <div>
            <label className="block text-[10px] text-slate-500 mb-1">
              Test input (optional)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={testInput}
                onChange={e => { setTestInput(e.target.value); setTestResult(null); }}
                placeholder="Paste a sample span attribute value to test…"
                className="flex-1 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-slate-500"
              />
              <button
                type="button"
                onClick={handleTest}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded-lg text-xs text-slate-300 transition-colors"
              >
                <FlaskConical className="w-3.5 h-3.5" /> Test
              </button>
            </div>
            {testResult !== null && (
              <p className={`mt-1 text-[11px] font-mono ${testResult ? 'text-green-400' : 'text-red-400'}`}>
                {testResult ? 'Match found' : 'No match'}
              </p>
            )}
          </div>

          {error && <p className="text-[11px] text-red-400 font-mono">{error}</p>}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={submitting}
              className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
            >
              <Plus className="w-3.5 h-3.5" /> Add Rule
            </button>
          </div>
        </form>

        {/* Rules table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-2.5 text-left">Label</th>
                <th className="px-4 py-2.5 text-left">Pattern</th>
                <th className="px-4 py-2.5 text-left">Severity</th>
                <th className="px-4 py-2.5 text-left">Type</th>
                <th className="px-4 py-2.5 text-left w-32">Snooze</th>
                <th className="px-4 py-2.5 text-left w-10"></th>
              </tr>
            </thead>
            <tbody>
              {allRules.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-600 text-[11px]">
                    No rules loaded
                  </td>
                </tr>
              )}
              {allRules.map(rule => {
                const supp = activeSuppression(rule.id);
                const isSnoozed = !!supp;
                return (
                  <tr
                    key={rule.id}
                    className={`border-b border-slate-800/50 transition-colors ${isSnoozed ? 'opacity-60' : 'hover:bg-slate-800/30'}`}
                  >
                    <td className={`px-4 py-2.5 font-medium ${isSnoozed ? 'text-slate-500' : 'text-slate-200'}`}>
                      {rule.label}
                    </td>
                    <td className="px-4 py-2.5">
                      <code className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                        {rule.pattern.length > 60 ? rule.pattern.slice(0, 60) + '…' : rule.pattern}
                      </code>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${SEV_BADGE[rule.severity] ?? SEV_BADGE.none}`}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] ${rule.type === 'built-in' ? 'text-slate-500' : 'text-blue-400'}`}>
                        {rule.type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                      {isSnoozed ? (
                        <div className="flex items-center gap-1.5">
                          <span className="flex items-center gap-1 text-[10px] text-yellow-400 font-mono">
                            <Clock className="w-3 h-3" />
                            {formatCountdown(supp.suppressUntil)}
                          </span>
                          <button
                            onClick={() => handleCancelSnooze(supp.id)}
                            className="p-0.5 rounded text-slate-600 hover:text-red-400 hover:bg-slate-700 transition-colors"
                            title="Cancel snooze"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                      ) : (
                        <div className="relative">
                          <button
                            onClick={() => setSnoozeMenuId(snoozeMenuId === rule.id ? null : rule.id)}
                            className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] text-slate-500 hover:text-yellow-400 hover:bg-slate-800 transition-colors border border-transparent hover:border-slate-700"
                          >
                            <Clock className="w-3 h-3" /> Snooze
                          </button>
                          {snoozeMenuId === rule.id && (
                            <div className="absolute left-0 top-full mt-1 z-50 bg-slate-800 border border-slate-700 rounded-lg shadow-xl py-1 min-w-[110px]">
                              {SNOOZE_OPTIONS.map(opt => (
                                <button
                                  key={opt.label}
                                  onClick={() => handleSnooze(rule.id, opt.ms)}
                                  className="w-full text-left px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                                >
                                  {opt.label}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {rule.type === 'custom' && (
                        <button
                          onClick={() => handleDelete(rule.id)}
                          className="p-1 hover:bg-slate-700 rounded text-slate-600 hover:text-red-400 transition-colors"
                          title="Delete rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
