import React, { useEffect, useState, useCallback } from 'react';
import { Activity } from 'lucide-react';
import { socket } from './socket';

// ---------------------------------------------------------------------------
// Constants — redefined inline (do not import from App.tsx)
// ---------------------------------------------------------------------------

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

const HARNESS_NAMES: Record<string, string> = {
  'claude-code':    'Claude Code',
  'github-copilot': 'GitHub Copilot',
  'openhands':      'OpenHands',
  'cursor':         'Cursor',
  'aider':          'Aider',
  'cline':          'Cline',
  'goose':          'Goose',
  'continue':       'Continue.dev',
  'windsurf':       'Windsurf',
  'codex':          'Codex CLI',
  'amazon-q':       'Amazon Q Dev',
  'gemini-cli':     'Gemini CLI',
  'roo-code':       'Roo-Code',
  'bolt':           'Bolt.new',
  'unknown':        'Unknown Agent',
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HarnessStats {
  harness: string;
  spanCount: number;
  sessionCount: number;
  threatHigh: number;
  threatMedium: number;
  threatLow: number;
  tokensIn: number;
  tokensOut: number;
  firstSeen: string;
  lastSeen: string;
}

interface Props {
  onFilterHarness: (harness: string | null) => void;
  activeFilter: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  if (isNaN(diff) || diff < 0) return '—';
  const s = Math.floor(diff / 1000);
  if (s < 60)   return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)   return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24)   return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function harnessColor(harness: string): string {
  return HARNESS_COLORS[harness] ?? HARNESS_COLORS['unknown'];
}

function harnessName(harness: string): string {
  return HARNESS_NAMES[harness] ?? harness;
}

// ---------------------------------------------------------------------------
// HarnessCard
// ---------------------------------------------------------------------------

interface CardProps {
  stats: HarnessStats;
  isActive: boolean;
  onFilter: () => void;
  key?: React.Key;
}

function HarnessCard({ stats, isActive, onFilter }: CardProps) {
  const color = harnessColor(stats.harness);
  const name  = harnessName(stats.harness);

  return (
    <div
      className={`rounded-xl p-4 space-y-3 transition-all duration-150 ${
        isActive
          ? ''
          : 'hover:border-slate-700'
      }`}
      style={isActive
        ? { background: 'var(--cs-bg-surface)', border: '1px solid rgba(0,212,170,0.4)', boxShadow: '0 0 0 2px rgba(0,212,170,0.2)' }
        : { background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }
      }
    >
      {/* Header row */}
      <div className="flex items-center gap-2">
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{ backgroundColor: color }}
        />
        <span className="text-sm font-semibold text-slate-200 flex-1 truncate">{name}</span>
        <button
          type="button"
          onClick={onFilter}
          className={`text-xs px-2 py-0.5 rounded-md border transition-colors ${
            isActive
              ? ''
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-300'
          }`}
          style={isActive
            ? { background: 'rgba(0,212,170,0.15)', borderColor: 'rgba(0,212,170,0.4)', color: 'rgba(0,212,170,0.85)' }
            : { background: 'rgba(0,212,170,0.1)', color: '#00d4aa', border: '1px solid rgba(0,212,170,0.2)' }
          }
        >
          {isActive ? 'Filtered' : 'Filter'}
        </button>
      </div>

      {/* Span count (big) + session count */}
      <div className="flex items-end gap-3">
        <div>
          <p className="text-2xl font-bold text-slate-100 leading-none">
            {stats.spanCount.toLocaleString()}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">spans</p>
        </div>
        <div className="pb-0.5">
          <p className="text-sm font-medium text-slate-300">{stats.sessionCount.toLocaleString()}</p>
          <p className="text-xs text-slate-500">sessions</p>
        </div>
      </div>

      {/* Threat badges — only non-zero */}
      {(stats.threatHigh > 0 || stats.threatMedium > 0 || stats.threatLow > 0) && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {stats.threatHigh > 0 && (
            <span className="px-1.5 py-0.5 rounded text-xs font-mono uppercase bg-red-900/40 text-red-300 border border-red-700/40">
              HIGH {stats.threatHigh}
            </span>
          )}
          {stats.threatMedium > 0 && (
            <span className="px-1.5 py-0.5 rounded text-xs font-mono uppercase bg-orange-900/40 text-orange-300 border border-orange-700/40">
              MED {stats.threatMedium}
            </span>
          )}
          {stats.threatLow > 0 && (
            <span className="px-1.5 py-0.5 rounded text-xs font-mono uppercase bg-yellow-900/40 text-yellow-300 border border-yellow-700/40">
              LOW {stats.threatLow}
            </span>
          )}
        </div>
      )}

      {/* Token bar */}
      {(stats.tokensIn > 0 || stats.tokensOut > 0) && (
        <p className="text-[11px] font-mono text-slate-400">
          ↑ {stats.tokensIn.toLocaleString()}&nbsp;&nbsp;↓ {stats.tokensOut.toLocaleString()}
        </p>
      )}

      {/* Last seen */}
      <p className="text-xs text-slate-600">
        Last seen: <span className="text-slate-500">{relativeTime(stats.lastSeen)}</span>
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function HarnessTab({ onFilterHarness, activeFilter }: Props): React.ReactElement {
  const [harnesses, setHarnesses] = useState<HarnessStats[]>([]);

  const fetchHarnesses = useCallback(() => {
    fetch('/api/harnesses')
      .then(r => r.json())
      .then((d: { harnesses: HarnessStats[] }) => {
        const sorted = [...(d.harnesses ?? [])].sort((a, b) => b.spanCount - a.spanCount);
        setHarnesses(sorted);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchHarnesses();
    socket.on('graph-update', fetchHarnesses);
    return () => { socket.off('graph-update', fetchHarnesses); };
  }, [fetchHarnesses]);

  const handleFilter = (harness: string) => {
    onFilterHarness(activeFilter === harness ? null : harness);
  };

  return (
    <div className="flex-1 overflow-auto p-5 min-h-0" style={{ background: 'var(--cs-bg-primary)' }}>
      <div className="max-w-5xl mx-auto space-y-4">

        {/* Header */}
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5" style={{ color: '#00d4aa' }} />
          <h2 className="text-sm font-bold text-slate-200">Agent Harnesses</h2>
          <span className="ml-auto text-xs font-mono text-slate-500">
            {harnesses.length} harness{harnesses.length !== 1 ? 'es' : ''} detected
          </span>
          {activeFilter && (
            <button
              type="button"
              onClick={() => onFilterHarness(null)}
              className="text-xs px-2 py-0.5 rounded-md border transition-colors"
              style={{ background: 'rgba(0,212,170,0.12)', borderColor: 'rgba(0,212,170,0.3)', color: 'rgba(0,212,170,0.85)' }}
            >
              Clear filter
            </button>
          )}
        </div>

        {/* Cards grid */}
        {harnesses.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Activity className="w-10 h-10 text-slate-700 mb-3" />
            <p className="text-slate-500 text-sm">No agent activity recorded yet.</p>
            <p className="text-slate-600 text-xs mt-1">
              Connect an agent harness and send OTLP traces to see stats here.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {harnesses.map(h => (
              <HarnessCard
                key={h.harness}
                stats={h}
                isActive={activeFilter === h.harness}
                onFilter={() => handleFilter(h.harness)}
              />
            ))}
          </div>
        )}

      </div>
    </div>
  );
}
