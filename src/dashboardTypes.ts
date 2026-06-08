import type { ReactNode } from 'react';
import type { Severity } from './shared/types';
import type { Category } from './CategoryNav';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FilterMode = 'all' | 'normal' | 'malicious';
export type Tab        = 'timeline' | 'orchestration' | 'alerts' | 'rules' | 'enforce' | 'mcpscan' | 'costs' | 'harnesses' | 'settings' | 'heatmap' | 'search' | 'processes' | 'bookmarks';

// Category → Tab mapping for the navigation rail
export const CATEGORY_TABS: Record<Category, { id: Tab; icon: ReactNode; label: string; badge?: number }[]> = {
  observe: [
    { id: 'timeline',      icon: null, label: 'Timeline' },
    { id: 'orchestration', icon: null, label: 'Orchestration' },
    { id: 'heatmap',       icon: null, label: 'Heatmap' },
    { id: 'processes',     icon: null, label: 'Processes' },
  ],
  detect: [
    { id: 'alerts', icon: null, label: 'Alerts' },
    { id: 'search', icon: null, label: 'Search' },
  ],
  protect: [
    { id: 'rules',   icon: null, label: 'Rules' },
    { id: 'enforce', icon: null, label: 'Enforce' },
    { id: 'mcpscan', icon: null, label: 'MCP Scan' },
  ],
  review: [
    { id: 'bookmarks', icon: null, label: 'Bookmarks' },
  ],
  manage: [
    { id: 'harnesses', icon: null, label: 'Harnesses' },
    { id: 'costs',     icon: null, label: 'Costs' },
    { id: 'settings',  icon: null, label: 'Settings' },
  ],
};

// Find which category a tab belongs to
export function categoryForTab(tab: Tab): Category {
  for (const [cat, tabs] of Object.entries(CATEGORY_TABS)) {
    if (tabs.some(t => t.id === tab)) return cat as Category;
  }
  return 'observe';
}

export interface Workflow {
  id: string;
  label: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  traceId: string;
  startNano: string;
  endNano: string;
  attributes: Record<string, string>;
  timestamp: string;
}

export type SessionLabel = 'normal' | 'incident' | 'investigation' | 'automated' | 'other';

export interface Session {
  traceId: string;
  name: string;
  createdAt: string;
  pinned: number;
  label: SessionLabel;
  notes: string;
  spanCount: number;
  threatCount: number;
  maxSeverityRank: number;
  harnesses: string | null;
  healthScore?: number;
}

export const LABEL_COLORS: Record<SessionLabel, { dot: string; bg: string; text: string }> = {
  normal:        { dot: '#64748b', bg: 'bg-slate-800',       text: 'text-slate-400' },
  incident:      { dot: '#ef4444', bg: 'bg-red-900/30',      text: 'text-red-300'   },
  investigation: { dot: '#f97316', bg: 'bg-orange-900/30',   text: 'text-orange-300'},
  automated:     { dot: '#3b82f6', bg: 'bg-blue-900/30',     text: 'text-blue-300'  },
  other:         { dot: '#a855f7', bg: 'bg-purple-900/30',   text: 'text-purple-300'},
};

export interface TickerSpan {
  spanId: string;
  name: string;
  harness: string;
  severity: Severity;
  ts: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

export const HARNESS_NAMES: Record<string, string> = {
  'claude-code': 'Claude Code',
  'copilot':     'GitHub Copilot CLI',
  'codex':       'Codex',
  'unknown':     'Unknown Agent',
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  none: 'OK', low: 'LOW', medium: 'MED', high: 'HIGH',
};

export const SEVERITY_COLORS: Record<Severity, { row: string; badge: string; text: string; icon: string }> = {
  none:   { row: 'bg-green-500/10 border-green-500/30 hover:bg-green-500/20',    badge: 'bg-green-900/40 text-green-300',   text: 'text-green-200',  icon: 'text-green-400'  },
  low:    { row: 'bg-yellow-500/10 border-yellow-500/30 hover:bg-yellow-500/20', badge: 'bg-yellow-900/40 text-yellow-300', text: 'text-yellow-200', icon: 'text-yellow-400' },
  medium: { row: 'bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/20', badge: 'bg-orange-900/40 text-orange-300', text: 'text-orange-200', icon: 'text-orange-400' },
  high:   { row: 'bg-red-500/10 border-red-500/40 hover:bg-red-500/20',          badge: 'bg-red-900/40 text-red-300',       text: 'text-red-200',   icon: 'text-red-400'    },
};

export const SEV_RANK: Record<number, Severity> = { 3: 'high', 2: 'medium', 1: 'low', 0: 'none' };
