import React, { useEffect, useState } from 'react';
import { Shield, Trash2, Plus, FlaskConical } from 'lucide-react';
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

export function RulesTab() {
  const [rules, setRules] = useState<{ builtIn: RuleRow[]; custom: RuleRow[] }>({ builtIn: [], custom: [] });

  // Form state
  const [pattern,   setPattern]   = useState('');
  const [severity,  setSeverity]  = useState<'low' | 'medium' | 'high'>('medium');
  const [label,     setLabel]     = useState('');
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<null | boolean>(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchRules = () =>
    fetch('/api/rules')
      .then(r => r.json())
      .then((data: RulesResponse) => setRules(data))
      .catch(() => {});

  useEffect(() => {
    fetchRules();
    socket.on('rules-update', fetchRules);
    return () => { socket.off('rules-update', fetchRules); };
  }, []);

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
    <div className="flex-1 overflow-auto p-5 bg-slate-950 min-h-0">
      <div className="max-w-5xl mx-auto space-y-6">

        {/* Header */}
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <h2 className="text-sm font-bold text-slate-200">Threat Detection Rules</h2>
          <span className="ml-auto text-[10px] font-mono text-slate-500">
            {rules.builtIn.length} built-in · {rules.custom.length} custom
          </span>
        </div>

        {/* Add custom rule form */}
        <form
          onSubmit={handleSubmit}
          className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3"
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
                <th className="px-4 py-2.5 text-left w-10"></th>
              </tr>
            </thead>
            <tbody>
              {allRules.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-600 text-[11px]">
                    No rules loaded
                  </td>
                </tr>
              )}
              {allRules.map(rule => (
                <tr
                  key={rule.id}
                  className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"
                >
                  <td className="px-4 py-2.5 text-slate-200 font-medium">{rule.label}</td>
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
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
