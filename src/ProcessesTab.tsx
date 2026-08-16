/**
 * ProcessesTab — the running agent processes, with kill/pause/resume.
 *
 * These are destructive controls on real processes on the operator's own
 * machine, so every path to Kill says the PID out loud — in the row, in the
 * button, and in the confirm dialog — rather than trusting proximity on the
 * page to make the target obvious.
 */
import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Monitor, RefreshCw, AlertTriangle, Activity, MemoryStick, Skull, XCircle,
  Pause, Play, X, Terminal, Copy, Check, CheckCircle,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { HARNESSES, type HarnessConfig } from './harnesses';
import { apiErrorMessage, apiSend } from './lib/api';
import {
  DataTable, type DataColumn,
  Toolbar, ToolButton, ToolbarTitle,
  EmptyState, ErrorState,
  useRowDensity, RowDensityToggle,
} from './components/data';

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

// The agent's identity colour — fixed hue per harness, same set used
// everywhere else in the app. Identity, not risk, so it stays outside the
// severity ramp.
const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

function getHarnessConfig(harnessId: string): HarnessConfig | undefined {
  return HARNESSES.find(h => h.id === harnessId);
}

/** Inline connect hint shown when a detected process has no trace sessions. */
function ConnectHint({ harness }: { harness: string }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const config = getHarnessConfig(harness);
  if (!config || config.id === 'unknown') return null;

  const envLines = config.envVars.map(v =>
    `export ${v.key}=${v.value.replace('{{ENDPOINT}}', `${window.location.origin}/v1/traces`)}`
  ).join('\n');

  const handleCopy = async () => {
    await navigator.clipboard.writeText(envLines);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="mt-0.5">
      <button
        type="button"
        onClick={() => setExpanded(v => !v)}
        className="inline-flex items-center gap-1 transition-colors"
        style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-sev-medium-fg)' }}
      >
        <Terminal className="w-3 h-3" aria-hidden="true" />
        Not sending traces
      </button>
      {expanded && (
        <div className="mt-1.5 p-2 rounded-md" style={{ background: 'var(--cs-bg-sunken)' }}>
          <div className="flex items-start justify-between gap-2">
            <pre className="cs-mono whitespace-pre leading-relaxed select-all" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-body)' }}>
              {envLines}
            </pre>
            <button
              type="button"
              onClick={handleCopy}
              className="shrink-0 p-1 rounded transition-colors"
              style={{ color: 'var(--cs-text-faint)' }}
              title="Copy to clipboard"
            >
              {copied ? <Check className="w-3 h-3" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
            </button>
          </div>
          <p style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', marginTop: 6 }}>
            Set these in the terminal where {config.name} runs, then restart it.
          </p>
        </div>
      )}
    </div>
  );
}

function CpuBar({ pct }: { pct: number }) {
  const clamped = Math.min(100, pct);
  // CPU pressure isn't a security severity, but the app only ever teaches one
  // colour language, so a hot process borrows the same ramp a hot alert would.
  const color = clamped > 80 ? 'var(--cs-sev-high)' : clamped > 40 ? 'var(--cs-sev-medium)' : 'var(--cs-accent)';
  return (
    <span className="flex items-center gap-2">
      <span className="w-14 h-1 rounded-full overflow-hidden shrink-0" style={{ background: 'var(--cs-bg-raised)' }}>
        <span className="block h-full rounded-full transition-all" style={{ width: `${clamped}%`, background: color }} />
      </span>
      <span className="cs-mono shrink-0" style={{ color }}>{pct.toFixed(1)}%</span>
    </span>
  );
}

interface Toast { id: number; msg: string; type: 'success' | 'error' | 'warning' }
let toastId = 0;

const TOAST_STYLE: Record<Toast['type'], { color: string; bg: string; Icon: typeof CheckCircle }> = {
  success: { color: 'var(--cs-accent)',        bg: 'var(--cs-accent-soft)',      Icon: CheckCircle   },
  error:   { color: 'var(--cs-sev-critical-fg)', bg: 'var(--cs-sev-critical-bg)', Icon: XCircle       },
  warning: { color: 'var(--cs-sev-medium-fg)',   bg: 'var(--cs-sev-medium-bg)',   Icon: AlertTriangle },
};

export function ProcessesTab({ onSelectSession }: { onSelectSession?: (traceId: string) => void }) {
  const [data,      setData]      = useState<ProcessesResponse | null>(null);
  const [loading,   setLoading]   = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [killing, setKilling]   = useState<Set<number>>(new Set());
  const [toasts,  setToasts]    = useState<Toast[]>([]);
  const [density, setDensity]   = useRowDensity('processes');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const addToast = useCallback((msg: string, type: Toast['type'] = 'success') => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const fetchProcesses = useCallback(async () => {
    try {
      const res = await fetch('/api/processes');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: ProcessesResponse = await res.json();
      setData(json);
      setLoadError(null);
    } catch (e: any) {
      setLoadError(e?.message ?? 'Failed to fetch processes');
    } finally {
      setLoading(false);
    }
  }, []);

  const killProcess = async (pid: number, name: string) => {
    if (!window.confirm(`Kill ${name} — PID ${pid}? This sends SIGTERM and cannot be undone.`)) return;
    setKilling(prev => new Set(prev).add(pid));
    try {
      await apiSend(`/api/processes/${pid}`, 'DELETE');
      addToast(`Killed ${name} — PID ${pid}`, 'success');
      setTimeout(fetchProcesses, 1000);
    } catch (err: unknown) {
      addToast(apiErrorMessage(err, 'Failed to kill process'), 'error');
    }
    setKilling(prev => { const s = new Set(prev); s.delete(pid); return s; });
  };

  // Every bulk action reports the counts the SERVER returned. A refused request
  // now raises instead of reaching the toast, which is what used to render the
  // reassuring "Killed undefined/undefined agents" in success green.
  const killAll = async () => {
    if (!window.confirm(`Kill ALL ${data?.total ?? 0} agent processes? This sends SIGTERM to each and cannot be undone.`)) return;
    try {
      const d = await apiSend<{ killed: number; total: number; failed: number }>('/api/processes/kill-all', 'POST');
      addToast(`Killed ${d.killed}/${d.total} agents`, d.failed > 0 ? 'warning' : 'success');
      setTimeout(fetchProcesses, 1500);
    } catch (err: unknown) { addToast(apiErrorMessage(err, 'Kill-all failed'), 'error'); }
  };

  const pauseAll = async () => {
    try {
      const d = await apiSend<{ paused: number }>('/api/processes/pause-all', 'POST');
      addToast(`Paused ${d.paused} agents (SIGSTOP)`, 'success');
    } catch (err: unknown) { addToast(apiErrorMessage(err, 'Pause-all failed'), 'error'); }
  };

  const resumeAll = async () => {
    try {
      const d = await apiSend<{ resumed: number }>('/api/processes/resume-all', 'POST');
      addToast(`Resumed ${d.resumed} agents (SIGCONT)`, 'success');
    } catch (err: unknown) { addToast(apiErrorMessage(err, 'Resume-all failed'), 'error'); }
  };

  useEffect(() => {
    fetchProcesses();
  }, [fetchProcesses]);

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchProcesses, 5000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, fetchProcesses]);

  const procs = data?.processes ?? [];
  const unsupported = !!data && !data.supported;

  const columns: DataColumn<AgentProcess>[] = [
    {
      id: 'agent', header: 'Agent', width: 'minmax(0,1fr)',
      cell: p => (
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: HARNESS_COLORS[p.harness] ?? HARNESS_COLORS.unknown }} aria-hidden="true" />
          <span className="truncate" style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>{p.harnessName}</span>
        </span>
      ),
    },
    {
      id: 'pid', header: 'PID', width: '76px', align: 'end', mono: true,
      cell: p => <span style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-semibold)' }}>{p.pid}</span>,
    },
    {
      id: 'user', header: 'User', width: '90px', hideBelow: 'xl', mono: true,
      cell: p => <span>{p.user}</span>,
    },
    {
      id: 'cpu', header: 'CPU', width: '130px', hideBelow: 'xl',
      cell: p => <CpuBar pct={p.cpuPct} />,
    },
    {
      id: 'mem', header: 'Memory', width: '140px', hideBelow: '2xl',
      cell: p => (
        <span className="flex items-center gap-1.5 cs-mono">
          <MemoryStick className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          {p.memMb.toFixed(0)} MB
          {p.memMb > 1024 && (
            <span
              className="uppercase shrink-0"
              title="Memory over 1 GB"
              style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)' }}
            >
              High
            </span>
          )}
          {p.memMb > 500 && p.memMb <= 1024 && (
            <span
              className="uppercase shrink-0"
              title="Memory over 500 MB"
              style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)' }}
            >
              Warn
            </span>
          )}
        </span>
      ),
    },
    {
      id: 'sessions', header: 'Sessions', width: 'minmax(0,1.2fr)', hideBelow: '2xl',
      cell: p => p.recentSessions.length > 0 ? (
        <span className="flex flex-wrap items-center gap-1" onClick={e => e.stopPropagation()}>
          {p.recentSessions.slice(0, 2).map(s => (
            <button
              key={s.traceId}
              type="button"
              onClick={() => onSelectSession?.(s.traceId)}
              className="px-1.5 py-0.5 rounded transition-colors truncate max-w-[110px]"
              style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-2xs)' }}
              title={s.name}
            >
              {s.name}
            </button>
          ))}
          {p.recentSessions.length > 2 && (
            <span style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>+{p.recentSessions.length - 2}</span>
          )}
        </span>
      ) : (
        <span onClick={e => e.stopPropagation()}>
          <span style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>None yet</span>
          <ConnectHint harness={p.harness} />
        </span>
      ),
    },
    {
      id: 'cmd', header: 'Command', width: 'minmax(0,1.6fr)', hideBelow: '3xl', mono: true,
      cell: p => <span title={p.cmd}>{p.cmd.length > 90 ? p.cmd.slice(0, 90) + '…' : p.cmd}</span>,
    },
    {
      id: 'action', header: 'Kill', width: '92px', align: 'end',
      cell: p => (
        <span onClick={e => e.stopPropagation()}>
          <button
            type="button"
            disabled={killing.has(p.pid)}
            onClick={() => killProcess(p.pid, p.harnessName)}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors disabled:opacity-40"
            style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-xs)' }}
            title={`Kill ${p.harnessName} — PID ${p.pid}. Sends SIGTERM. Cannot be undone.`}
          >
            <Skull className="w-3 h-3" aria-hidden="true" />
            <span className="cs-mono">{p.pid}</span>
          </button>
        </span>
      ),
    },
  ];

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <Toolbar>
        <ToolbarTitle
          icon={<Monitor className="w-3.5 h-3.5" />}
          count={data ? `${data.total} detected · ${data.platform}` : undefined}
        >
          Agent processes
        </ToolbarTitle>

        <div className="flex items-center gap-1 ml-auto flex-wrap">
          {procs.length > 0 && (
            <>
              <ToolButton danger onClick={killAll} title={`Send SIGTERM to all ${data?.total ?? 0} agent processes — cannot be undone`}>
                <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden xl:inline">Kill all</span>
              </ToolButton>
              <ToolButton onClick={pauseAll} title="Send SIGSTOP to all agent processes">
                <Pause className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden xl:inline">Pause all</span>
              </ToolButton>
              <ToolButton onClick={resumeAll} title="Send SIGCONT to all agent processes">
                <Play className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden xl:inline">Resume all</span>
              </ToolButton>
            </>
          )}
          <RowDensityToggle density={density} onChange={setDensity} className="mx-1" />
          <ToolButton
            active={autoRefresh}
            aria-pressed={autoRefresh}
            onClick={() => setAutoRefresh(v => !v)}
            title={autoRefresh ? 'Auto-refreshing every 5s — click to pause' : 'Auto-refresh paused — click to resume'}
          >
            <Activity className="w-3.5 h-3.5" aria-hidden="true" />
            {autoRefresh ? 'Live' : 'Paused'}
          </ToolButton>
          <ToolButton onClick={fetchProcesses} disabled={loading} title="Refresh now">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
          </ToolButton>
        </div>
      </Toolbar>

      {unsupported ? (
        <EmptyState
          icon={<AlertTriangle className="w-6 h-6" aria-hidden="true" />}
          title="Process scanning not supported"
          description="Process scanning requires macOS or Linux."
        />
      ) : (
        <>
          {/* Summary tiles */}
          {procs.length > 0 && (
            <div className="grid grid-cols-3 gap-3 p-3 shrink-0">
              <div className="rounded-lg p-3 text-center" style={{ background: 'var(--cs-bg-surface)' }}>
                <div className="cs-mono" style={{ fontSize: 'var(--cs-text-xl)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>{procs.length}</div>
                <div className="cs-eyebrow mt-1">Processes</div>
              </div>
              <div className="rounded-lg p-3 text-center" style={{ background: 'var(--cs-bg-surface)' }}>
                <div className="cs-mono" style={{ fontSize: 'var(--cs-text-xl)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>
                  {procs.reduce((s, p) => s + p.cpuPct, 0).toFixed(1)}%
                </div>
                <div className="cs-eyebrow mt-1">Total CPU</div>
              </div>
              <div className="rounded-lg p-3 text-center" style={{ background: 'var(--cs-bg-surface)' }}>
                <div className="cs-mono" style={{ fontSize: 'var(--cs-text-xl)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>
                  {procs.reduce((s, p) => s + p.memMb, 0).toFixed(0)} MB
                </div>
                <div className="cs-eyebrow mt-1">Total memory</div>
              </div>
            </div>
          )}

          <DataTable
            rows={procs}
            columns={columns}
            rowKey={p => p.pid}
            label="Agent processes"
            density={density}
            minWidth={720}
            loading={loading}
            error={loadError && procs.length === 0 ? (
              <ErrorState
                description={`The process list did not respond (${loadError}).`}
                onRetry={() => { setLoading(true); fetchProcesses(); }}
              />
            ) : undefined}
            empty={
              <EmptyState
                icon={<Monitor className="w-6 h-6" aria-hidden="true" />}
                title="No agent processes detected"
                description="ClaudeSec scans for running Claude Code processes. Start Claude Code to see it appear here."
              />
            }
          />

          {data?.scannedAt && (
            <p className="cs-mono px-3 py-1 text-right shrink-0" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
              Last scanned {new Date(data.scannedAt).toLocaleTimeString()}
              {autoRefresh && ' · auto-refreshing every 5s'}
            </p>
          )}
        </>
      )}

      {/* Toast notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map(t => {
            const style = TOAST_STYLE[t.type];
            return (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, y: 20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.95 }}
                className="pointer-events-auto flex items-center gap-2 px-4 py-2.5 rounded-lg"
                style={{
                  background: 'var(--cs-bg-overlay)',
                  border: '1px solid var(--cs-rule-strong)',
                  boxShadow: 'var(--cs-shadow-overlay)',
                  fontSize: 'var(--cs-text-xs)',
                  color: 'var(--cs-text-body)',
                }}
              >
                <style.Icon className="w-3.5 h-3.5 shrink-0" style={{ color: style.color }} aria-hidden="true" />
                <span>{t.msg}</span>
                <button
                  type="button"
                  onClick={() => removeToast(t.id)}
                  className="ml-1 shrink-0"
                  style={{ color: 'var(--cs-text-faint)' }}
                  aria-label="Dismiss"
                >
                  <X className="w-3 h-3" aria-hidden="true" />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}
