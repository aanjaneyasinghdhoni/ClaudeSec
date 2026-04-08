import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Monitor, RefreshCw, AlertTriangle, Activity, Cpu, MemoryStick, Skull, XCircle, Pause, Play, X } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface AgentProcess {
  pid:            number;
  harness:        string;
  harnessName:    string;
  cmd:            string;
  cpuPct:         number;
  memMb:          number;
  startedAt:      string | null;
  user:           string;
  recentSessions: { traceId: string; name: string }[];
}

interface ProcessesResponse {
  processes:  AgentProcess[];
  total:      number;
  scannedAt:  string;
  platform:   string;
  supported:  boolean;
}

const HARNESS_COLORS: Record<string, string> = {
  'claude-code':    '#f97316',
  'github-copilot': '#6366f1',
  'openhands':      '#22c55e',
  'cursor':         '#a855f7',
  'aider':          '#ec4899',
  'cline':          '#14b8a6',
  'goose':          '#f59e0b',
  'continue':       '#0ea5e9',
  'windsurf':       '#38bdf8',
  'codex':          '#10b981',
  'amazon-q':       '#f59e0b',
  'gemini-cli':     '#4f46e5',
  'roo-code':       '#8b5cf6',
  'bolt':           '#06b6d4',
  'unknown':        '#64748b',
};

function CpuBar({ pct }: { pct: number }) {
  const clamped = Math.min(100, pct);
  const color = clamped > 80 ? '#ef4444' : clamped > 40 ? '#f97316' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${clamped}%`, background: color }} />
      </div>
      <span className="text-xs font-mono tabular-nums" style={{ color }}>
        {pct.toFixed(1)}%
      </span>
    </div>
  );
}

interface Toast { id: number; msg: string; type: 'success' | 'error' | 'warning' }
let toastId = 0;

export function ProcessesTab({ onSelectSession }: { onSelectSession?: (traceId: string) => void }) {
  const [data,      setData]      = useState<ProcessesResponse | null>(null);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [killing, setKilling]   = useState<Set<number>>(new Set());
  const [toasts,  setToasts]    = useState<Toast[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const addToast = useCallback((msg: string, type: Toast['type'] = 'success') => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const fetchProcesses = async () => {
    try {
      const res = await fetch('/api/processes');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: ProcessesResponse = await res.json();
      setData(json);
      setError('');
    } catch (e: any) {
      setError(e.message ?? 'Failed to fetch processes');
    } finally {
      setLoading(false);
    }
  };

  const killProcess = async (pid: number, name: string) => {
    if (!window.confirm(`Kill ${name} (PID ${pid})? This sends SIGTERM.`)) return;
    setKilling(prev => new Set(prev).add(pid));
    try {
      const res = await fetch(`/api/processes/${pid}`, { method: 'DELETE' });
      if (res.ok) {
        addToast(`Killed ${name} (PID ${pid})`, 'success');
        setTimeout(fetchProcesses, 1000);
      } else {
        const d = await res.json();
        addToast(d.error ?? 'Failed to kill process', 'error');
      }
    } catch { addToast('Failed to kill process', 'error'); }
    setKilling(prev => { const s = new Set(prev); s.delete(pid); return s; });
  };

  const killAll = async () => {
    if (!window.confirm(`Kill ALL ${data?.total ?? 0} agent processes? This sends SIGTERM to each.`)) return;
    try {
      const res = await fetch('/api/processes/kill-all', { method: 'POST' });
      const d = await res.json();
      addToast(`Killed ${d.killed}/${d.total} agents`, d.failed > 0 ? 'warning' : 'success');
      setTimeout(fetchProcesses, 1500);
    } catch { addToast('Kill-all failed', 'error'); }
  };

  const pauseAll = async () => {
    try {
      const res = await fetch('/api/processes/pause-all', { method: 'POST' });
      const d = await res.json();
      addToast(`Paused ${d.paused} agents (SIGSTOP)`, 'success');
    } catch { addToast('Pause-all failed', 'error'); }
  };

  const resumeAll = async () => {
    try {
      const res = await fetch('/api/processes/resume-all', { method: 'POST' });
      const d = await res.json();
      addToast(`Resumed ${d.resumed} agents (SIGCONT)`, 'success');
    } catch { addToast('Resume-all failed', 'error'); }
  };

  useEffect(() => {
    fetchProcesses();
  }, []);

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchProcesses, 5000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh]);

  const procs = data?.processes ?? [];

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ background: 'var(--cs-bg-primary)' }}>

      {/* Toolbar */}
      <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-800 bg-slate-900/40 shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4" style={{ color: '#00d4aa' }} />
          <span className="text-sm font-bold text-slate-200">Agent Processes</span>
          {data && (
            <span className="text-[11px] font-mono text-slate-500">
              {data.total} detected · {data.platform}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 ml-auto flex-wrap">
          {/* Bulk actions */}
          {procs.length > 0 && (
            <>
              <button
                onClick={killAll}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/30 hover:bg-red-900/50 rounded-lg border border-red-700/30 text-xs text-red-400 transition-colors"
                title="Send SIGTERM to all agent processes"
              >
                <XCircle className="w-3.5 h-3.5" /> Kill All
              </button>
              <button
                onClick={pauseAll}
                className="flex items-center gap-1.5 px-3 py-1.5 hover:brightness-110 rounded-lg text-xs transition-colors"
                style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
                title="Send SIGSTOP to all agent processes"
              >
                <Pause className="w-3.5 h-3.5" /> Pause All
              </button>
              <button
                onClick={resumeAll}
                className="flex items-center gap-1.5 px-3 py-1.5 hover:brightness-110 rounded-lg text-xs transition-colors"
                style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
                title="Send SIGCONT to all agent processes"
              >
                <Play className="w-3.5 h-3.5" /> Resume All
              </button>
              <div className="w-px h-5 bg-slate-700" />
            </>
          )}
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors"
            style={autoRefresh
              ? { background: 'rgba(0,212,170,0.1)', color: '#00d4aa', border: '1px solid rgba(0,212,170,0.2)' }
              : { background: '#1e293b', color: '#64748b', border: '1px solid #334155' }
            }
          >
            <Activity className="w-3.5 h-3.5" />
            {autoRefresh ? 'Live (5s)' : 'Paused'}
          </button>
          <button
            onClick={fetchProcesses}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-xs text-slate-300 disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-5">
        {!data?.supported && !loading && (
          <div className="flex flex-col items-center justify-center h-48 gap-3 text-slate-600">
            <AlertTriangle className="w-8 h-8 text-yellow-600" />
            <p className="text-sm font-medium text-slate-500">Process scanning not supported</p>
            <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
              Process scanning requires macOS or Linux.
            </p>
          </div>
        )}

        {error && (
          <div className="mb-4 px-4 py-3 bg-red-900/20 border border-red-700/40 rounded-lg text-xs text-red-400 font-mono">
            {error}
          </div>
        )}

        {procs.length === 0 && !loading && data?.supported !== false && (
          <div className="flex flex-col items-center justify-center h-48 gap-3 text-slate-600">
            <Monitor className="w-8 h-8 text-slate-700" />
            <p className="text-sm font-medium text-slate-500">No agent processes detected</p>
            <p className="text-xs text-slate-600 max-w-sm text-center leading-relaxed">
              ClaudeSec scans for Claude, Aider, Goose, Copilot, OpenHands, Cursor, Cline, Continue, Windsurf, Codex, and more.
              Start an agent to see it appear here.
            </p>
          </div>
        )}

        {procs.length > 0 && (
          <div className="space-y-3 max-w-5xl">

            {/* Summary cards */}
            <div className="grid grid-cols-3 gap-3 mb-5">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-center">
                <div className="text-2xl font-bold font-mono" style={{ color: '#00d4aa' }}>{procs.length}</div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mt-1">Processes</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-center">
                <div className="text-2xl font-bold font-mono text-orange-400">
                  {procs.reduce((s, p) => s + p.cpuPct, 0).toFixed(1)}%
                </div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mt-1">Total CPU</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 text-center">
                <div className="text-2xl font-bold font-mono text-purple-400">
                  {procs.reduce((s, p) => s + p.memMb, 0).toFixed(0)} MB
                </div>
                <div className="text-xs text-slate-500 uppercase tracking-wider mt-1">Total Memory</div>
              </div>
            </div>

            {/* Process table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
                    <th className="px-4 py-2.5 text-left">Agent</th>
                    <th className="px-4 py-2.5 text-left">PID</th>
                    <th className="px-4 py-2.5 text-left">User</th>
                    <th className="px-4 py-2.5 text-left w-28">CPU</th>
                    <th className="px-4 py-2.5 text-left">Memory</th>
                    <th className="px-4 py-2.5 text-left">Recent Sessions</th>
                    <th className="px-4 py-2.5 text-left">Command</th>
                    <th className="px-4 py-2.5 text-left w-14">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {procs.map(proc => (
                    <tr key={proc.pid} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{ background: HARNESS_COLORS[proc.harness] ?? '#64748b' }}
                          />
                          <span className="font-medium text-slate-200">{proc.harnessName}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">{proc.pid}</td>
                      <td className="px-4 py-3 text-slate-500 font-mono text-[11px]">{proc.user}</td>
                      <td className="px-4 py-3">
                        <CpuBar pct={proc.cpuPct} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-slate-400 font-mono text-[11px]">
                          <MemoryStick className="w-3 h-3 text-purple-400 shrink-0" />
                          {proc.memMb.toFixed(0)} MB
                          {proc.memMb > 1024 && (
                            <span className="px-1 py-0.5 bg-red-900/30 text-red-400 text-[11px] font-bold rounded" title="Memory > 1 GB">HIGH</span>
                          )}
                          {proc.memMb > 500 && proc.memMb <= 1024 && (
                            <span className="px-1 py-0.5 bg-orange-900/30 text-orange-400 text-[11px] font-bold rounded" title="Memory > 500 MB">WARN</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {proc.recentSessions.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {proc.recentSessions.slice(0, 2).map(s => (
                              <button
                                key={s.traceId}
                                onClick={() => onSelectSession?.(s.traceId)}
                                className="px-1.5 py-0.5 bg-slate-800 hover:bg-blue-900/30 border border-slate-700 hover:border-blue-700/40 rounded text-xs text-slate-400 hover:text-blue-300 transition-colors truncate max-w-[120px]"
                                title={s.name}
                              >
                                {s.name}
                              </button>
                            ))}
                            {proc.recentSessions.length > 2 && (
                              <span className="text-xs text-slate-600">+{proc.recentSessions.length - 2}</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-700">No recent sessions</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <code className="text-xs font-mono text-slate-500 break-all line-clamp-2" title={proc.cmd}>
                          {proc.cmd.length > 80 ? proc.cmd.slice(0, 80) + '…' : proc.cmd}
                        </code>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          disabled={killing.has(proc.pid)}
                          onClick={() => killProcess(proc.pid, proc.harnessName)}
                          className="flex items-center gap-1 px-2 py-1 bg-slate-800 hover:bg-red-900/40 border border-slate-700 hover:border-red-700/40 rounded text-xs text-slate-500 hover:text-red-400 transition-colors disabled:opacity-40"
                          title={`Kill ${proc.harnessName} (PID ${proc.pid})`}
                        >
                          <Skull className="w-3 h-3" />
                          Kill
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {data?.scannedAt && (
              <p className="text-xs text-slate-700 text-right">
                Last scanned: {new Date(data.scannedAt).toLocaleTimeString()}
                {autoRefresh && ' · auto-refreshing every 5s'}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Toast notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map(t => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -10, scale: 0.95 }}
              className={`pointer-events-auto flex items-center gap-2 px-4 py-2.5 rounded-xl border shadow-lg text-xs font-medium ${
                t.type === 'success' ? 'bg-green-900/90 border-green-700/50 text-green-200'
                : t.type === 'error' ? 'bg-red-900/90 border-red-700/50 text-red-200'
                : 'bg-yellow-900/90 border-yellow-700/50 text-yellow-200'
              }`}
            >
              <span>{t.msg}</span>
              <button onClick={() => removeToast(t.id)} className="ml-1 opacity-60 hover:opacity-100">
                <X className="w-3 h-3" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
