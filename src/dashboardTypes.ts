import type { ReactNode } from 'react';
import type { Severity } from './shared/types';
import type { Category } from './CategoryNav';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FilterMode = 'all' | 'normal' | 'malicious';
export type Tab        = 'timeline' | 'orchestration' | 'alerts' | 'rules' | 'enforce' | 'mcpscan' | 'costs' | 'harnesses' | 'settings' | 'heatmap' | 'search' | 'processes' | 'bookmarks' | 'governance';

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
  govern: [
    { id: 'governance', icon: null, label: 'Policies' },
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
  repo: string | null;
  healthScore?: number;
}

// Per-repository rollup row from GET /api/repos — one per distinct git-root
// grouping key (see server/repoIdentity.ts). The 'unknown' bucket holds activity
// captured before repository tracking or from agents without a working dir.
export interface Repo {
  repo: string;
  spanCount: number;
  sessionCount: number;
  harnesses: string | null;
  threatHigh: number;
  threatMedium: number;
  threatLow: number;
  firstSeen: string | null;
  lastSeen: string | null;
  healthScore: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export const UNKNOWN_REPO = 'unknown';

// A short, human-readable label for a repo grouping key. Git-root keys are stored
// as full (scrubbed) paths, so we show the basename; the 'unknown' bucket gets an
// explicit, honest label rather than the bare word.
export function repoLabel(repo: string): string {
  if (!repo || repo === UNKNOWN_REPO) return 'Unknown / pre-tracking';
  const parts = repo.replace(/[/\\]+$/, '').split(/[/\\]/);
  return parts[parts.length - 1] || repo;
}

// ---------------------------------------------------------------------------
// Session labels
// ---------------------------------------------------------------------------
//
// A session is born with a name nobody chose — server/index.ts stamps
// "<harness> · <time>" (or the PID/import variants below) onto every new
// trace, and with ~6,500 sessions in the same harness that timestamp is the
// only thing that tells two of them apart. sessionDisplayLabel() swaps the
// harness word for the repo that produced it, which is the thing an operator
// actually wants to filter, search, and recognize by. It never touches the
// stored `name` — a rename is real data and must win every time.

// Matches every shape server/index.ts writes for an UN-renamed session:
// "<harness> · 11:17:10 AM", "<harness> · PID 4821 (auto-detected)", and
// "Import · 11:17:10 AM". A user rename will not match this — the moment a
// stored name diverges from one of these three shapes, it's a real name and
// sessionDisplayLabel() leaves it alone.
const AUTO_SESSION_NAME_RE = /^.+ · (?:PID \d+ \(auto-detected\)|\d{1,2}:\d{2}(?::\d{2})?\s?(?:AM|PM)?)$/i;

/** True when `name` still looks like the default server/index.ts assigns — i.e. nobody has renamed this session yet. */
export function isAutoSessionName(name: string): boolean {
  return AUTO_SESSION_NAME_RE.test(name.trim());
}

// The `repo` column on a session row is a newline-joined, de-duplicated list of
// every git root the trace's spans carried (see the repo_agg CTE in
// server/routes/sessions.ts) — one real session touched 26 of them in one
// sitting. This pulls out the tracked repos, dropping the 'unknown' bucket:
// that value means "no repo data for this span," not a repository, and
// counting it as one would overstate how scattered a session actually was.
export function sessionRepos(repo: string | null): string[] {
  if (!repo) return [];
  return repo.split('\n').filter(r => r && r !== UNKNOWN_REPO);
}

// Trimmed to "11:17 AM" — the seconds in the raw default name never
// distinguished anything real; the repo does that job now.
function shortSessionTime(createdAt: string): string {
  const d = new Date(createdAt);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

/**
 * The label a session row shows. A rename always wins (isAutoSessionName()
 * guards that). Otherwise: one known repo names the session directly, several
 * known repos are counted rather than guessed at — the aggregate query has no
 * per-repo weight to pick a "dominant" one honestly — and no known repo (still
 * true for part of the 'unknown' bucket left after tonight's migration) says
 * so plainly instead of inventing one.
 */
export function sessionDisplayLabel(session: Pick<Session, 'name' | 'repo' | 'createdAt'>): string {
  if (!isAutoSessionName(session.name)) return session.name;

  const time = shortSessionTime(session.createdAt);
  const repos = sessionRepos(session.repo);
  const what = repos.length === 0 ? 'Unknown repo'
    : repos.length === 1 ? repoLabel(repos[0])
    : `${repos.length} repos`;
  return time ? `${what} · ${time}` : what;
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

// First (or only) harness that produced this session — session.harnesses is
// the SQL layer's GROUP_CONCAT(DISTINCT harness), comma-joined — used to color
// the small dot next to the label so the words freed up by dropping "Claude
// Code" from the text don't also erase which agent this was.
export function primarySessionHarness(harnesses: string | null): string {
  const [first] = (harnesses ?? '').split(',').map(h => h.trim()).filter(Boolean);
  return first ?? 'unknown';
}

/** Tooltip text for the harness dot — every distinct harness in the session, by display name. */
export function sessionHarnessTitle(harnesses: string | null): string {
  const ids = (harnesses ?? '').split(',').map(h => h.trim()).filter(Boolean);
  if (ids.length === 0) return HARNESS_NAMES.unknown;
  return ids.map(id => HARNESS_NAMES[id] ?? id).join(', ');
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  none: 'OK', low: 'LOW', medium: 'MED', high: 'HIGH', critical: 'CRIT',
};

export const SEVERITY_COLORS: Record<Severity, { row: string; badge: string; text: string; icon: string }> = {
  none:   { row: 'bg-green-500/10 border-green-500/30 hover:bg-green-500/20',    badge: 'bg-green-900/40 text-green-300',   text: 'text-green-200',  icon: 'text-green-400'  },
  low:    { row: 'bg-yellow-500/10 border-yellow-500/30 hover:bg-yellow-500/20', badge: 'bg-yellow-900/40 text-yellow-300', text: 'text-yellow-200', icon: 'text-yellow-400' },
  medium: { row: 'bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/20', badge: 'bg-orange-900/40 text-orange-300', text: 'text-orange-200', icon: 'text-orange-400' },
  high:   { row: 'bg-red-500/10 border-red-500/40 hover:bg-red-500/20',          badge: 'bg-red-900/40 text-red-300',       text: 'text-red-200',   icon: 'text-red-400'    },
  // critical = active exfiltration. A screaming rose/pink badge that pulses, kept
  // visually distinct from high (red) so an operator can't mistake one for the other.
  critical: { row: 'bg-rose-500/15 border-rose-500/60 hover:bg-rose-500/25',     badge: 'bg-rose-900/60 text-rose-200 border border-rose-500/60 animate-pulse', text: 'text-rose-200', icon: 'text-rose-400' },
};

export const SEV_RANK: Record<number, Severity> = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'none' };
