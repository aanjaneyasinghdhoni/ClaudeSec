import React, { useEffect, useState } from 'react';
import { FileText, AlertTriangle, Eye, Edit2, Search } from 'lucide-react';

interface FileEntry {
  path:      string;
  reads:     number;
  writes:    number;
  total:     number;
  agents:    string[];
  threats:   number;
  sensitive: boolean;
}

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316', 'github-copilot': '#6366f1', 'openhands': '#22c55e',
  'cursor': '#a855f7', 'aider': '#ec4899', 'cline': '#14b8a6', 'goose': '#f59e0b',
  'codex': '#10b981', 'unknown': '#64748b',
};

export function FileAccessPanel() {
  const [files, setFiles]   = useState<FileEntry[]>([]);
  const [total, setTotal]   = useState(0);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetch('/api/file-access')
      .then(r => r.json())
      .then(d => { setFiles(d.files ?? []); setTotal(d.total ?? 0); })
      .catch(() => {});
  }, []);

  const filtered = filter
    ? files.filter(f => f.path.toLowerCase().includes(filter.toLowerCase()))
    : files;

  const sensitiveCount = files.filter(f => f.sensitive).length;

  return (
    <div className="space-y-4 mt-3">
      {/* Summary */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4" style={{ color: '#00d4aa' }} />
          <span className="text-xs font-bold text-slate-200">File Access</span>
          <span className="text-xs font-mono text-slate-500">{total} files accessed</span>
        </div>
        {sensitiveCount > 0 && (
          <span className="flex items-center gap-1 px-2 py-0.5 bg-red-900/30 border border-red-700/30 rounded-lg text-xs text-red-400 font-medium">
            <AlertTriangle className="w-3 h-3" /> {sensitiveCount} sensitive
          </span>
        )}
        <div className="ml-auto relative">
          <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter files..."
            className="pl-7 pr-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 w-48"
          />
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2">
          <FileText className="w-6 h-6 text-slate-700" />
          <p className="text-xs text-slate-500">{filter ? 'No matching files' : 'No file access recorded'}</p>
        </div>
      ) : (
        <div className="space-y-1.5">
          {filtered.slice(0, 40).map(f => {
            const maxAccess = Math.max(...files.map(x => x.total), 1);
            const pct = Math.round((f.total / maxAccess) * 100);
            return (
              <div
                key={f.path}
                className={`relative bg-slate-900 border rounded-lg px-3 py-2 overflow-hidden ${
                  f.sensitive ? 'border-red-700/40' : 'border-slate-800'
                }`}
              >
                {/* Heat bar background */}
                <div
                  className="absolute inset-y-0 left-0 opacity-10"
                  style={{ width: `${pct}%`, background: f.sensitive ? '#ef4444' : f.threats > 0 ? '#f97316' : '#3b82f6' }}
                />

                <div className="relative flex items-center gap-3">
                  {/* File path */}
                  <code className="text-[11px] font-mono text-slate-300 flex-1 truncate" title={f.path}>
                    {f.sensitive && <AlertTriangle className="w-3 h-3 text-red-400 inline mr-1" />}
                    {f.path}
                  </code>

                  {/* Read/Write counts */}
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="flex items-center gap-1 text-xs text-green-400 font-mono">
                      <Eye className="w-3 h-3" /> {f.reads}
                    </span>
                    <span className="flex items-center gap-1 text-xs text-orange-400 font-mono">
                      <Edit2 className="w-3 h-3" /> {f.writes}
                    </span>
                  </div>

                  {/* Agent dots */}
                  <div className="flex items-center gap-1 shrink-0">
                    {f.agents.map(a => (
                      <span
                        key={a}
                        className="w-2 h-2 rounded-full"
                        style={{ background: HARNESS_COLORS[a] ?? '#64748b' }}
                        title={a}
                      />
                    ))}
                  </div>

                  {/* Threat badge */}
                  {f.threats > 0 && (
                    <span className="px-1.5 py-0.5 bg-red-900/40 text-red-300 text-[11px] font-bold rounded shrink-0">
                      {f.threats} threat{f.threats > 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
          {filtered.length > 40 && (
            <p className="text-xs text-slate-600 text-center py-1">Showing 40 of {filtered.length} files</p>
          )}
        </div>
      )}
    </div>
  );
}
