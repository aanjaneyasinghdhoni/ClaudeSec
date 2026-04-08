import React, { useEffect, useState } from 'react';
import { Terminal, AlertTriangle, Shield, Search } from 'lucide-react';

interface CommandEntry {
  spanId:    string;
  traceId:   string;
  harness:   string;
  command:   string;
  severity:  string;
  riskScore: number;
  tool:      string;
  timestamp: string;
}

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316', 'github-copilot': '#6366f1', 'openhands': '#22c55e',
  'cursor': '#a855f7', 'aider': '#ec4899', 'cline': '#14b8a6', 'goose': '#f59e0b',
  'continue': '#0ea5e9', 'windsurf': '#38bdf8', 'codex': '#10b981', 'unknown': '#64748b',
};

function RiskBar({ score }: { score: number }) {
  const color = score >= 60 ? '#ef4444' : score >= 30 ? '#f97316' : score >= 10 ? '#eab308' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="w-14 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-xs font-mono tabular-nums w-6 text-right" style={{ color }}>{score}</span>
    </div>
  );
}

export function CommandAuditTab() {
  const [commands, setCommands] = useState<CommandEntry[]>([]);
  const [total, setTotal]       = useState(0);
  const [filter, setFilter]     = useState('');

  useEffect(() => {
    fetch('/api/command-audit?limit=200')
      .then(r => r.json())
      .then(d => { setCommands(d.commands ?? []); setTotal(d.total ?? 0); })
      .catch(() => {});
  }, []);

  const filtered = filter
    ? commands.filter(c => c.command.toLowerCase().includes(filter.toLowerCase()) || c.harness.includes(filter.toLowerCase()))
    : commands;

  const highRisk = commands.filter(c => c.riskScore >= 50).length;

  return (
    <div className="space-y-4 mt-3">
      {/* Summary */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4" style={{ color: '#00d4aa' }} />
          <span className="text-xs font-bold text-slate-200">Command Audit</span>
          <span className="text-xs font-mono text-slate-500">{total} commands</span>
        </div>
        {highRisk > 0 && (
          <span className="flex items-center gap-1 px-2 py-0.5 bg-red-900/30 border border-red-700/30 rounded-lg text-xs text-red-400 font-medium">
            <AlertTriangle className="w-3 h-3" /> {highRisk} high-risk
          </span>
        )}
        <div className="ml-auto relative">
          <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter commands..."
            className="pl-7 pr-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 w-48"
          />
        </div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2">
          <Shield className="w-6 h-6 text-slate-700" />
          <p className="text-xs text-slate-500">{filter ? 'No matching commands' : 'No shell commands recorded'}</p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-3 py-2 text-left w-20">Risk</th>
                <th className="px-3 py-2 text-left w-24">Agent</th>
                <th className="px-3 py-2 text-left">Command</th>
                <th className="px-3 py-2 text-left w-16">Severity</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map(cmd => (
                <tr key={cmd.spanId} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                  <td className="px-3 py-2.5">
                    <RiskBar score={cmd.riskScore} />
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: HARNESS_COLORS[cmd.harness] ?? '#64748b' }} />
                      <span className="text-slate-300 truncate text-[11px]">{cmd.harness}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <code className="text-xs font-mono text-slate-400 break-all line-clamp-2" title={cmd.command}>
                      {cmd.command.length > 120 ? cmd.command.slice(0, 120) + '...' : cmd.command}
                    </code>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                      cmd.severity === 'high' ? 'bg-red-900/40 text-red-300'
                      : cmd.severity === 'medium' ? 'bg-orange-900/40 text-orange-300'
                      : cmd.severity === 'low' ? 'bg-yellow-900/40 text-yellow-300'
                      : 'bg-slate-800 text-slate-500'
                    }`}>
                      {cmd.severity.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length > 50 && (
            <p className="text-xs text-slate-600 text-center py-2">Showing 50 of {filtered.length} commands</p>
          )}
        </div>
      )}
    </div>
  );
}
