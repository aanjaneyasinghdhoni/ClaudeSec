import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  useNodesState, useEdgesState,
  addEdge, type Node, type Edge,
} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import {
  Shield, AlertTriangle, Activity, Terminal, Trash2,
  Play, CheckCircle, Search, Download, X,
  Clock, Layers, Edit2, FileText, Cpu, Zap,
  Bell, BellOff, Upload, Settings, StickyNote, Flame, Star,
  Sun, Moon, Server, GitCompare, Monitor, Bookmark,
  ChevronDown, MoreHorizontal,
} from 'lucide-react';
import { socket } from './socket';
import { CategoryNav, type Category, CATEGORIES } from './CategoryNav';
import { ContextSidebar } from './ContextSidebar';
import { RulesTab } from './RulesTab';
import { AlertsTab } from './AlertsTab';
import { OrchestrationTab } from './OrchestrationTab';
import { CostTab } from './CostTab';
import { ActivitySparkline } from './Sparkline';
import { SettingsTab } from './SettingsTab';
import { HarnessTab } from './HarnessTab';
import { HeatmapTab } from './HeatmapTab';
import { type ReplayState } from './GraphReplay';
import { ComparePanel } from './ComparePanel';
import { SearchTab } from './SearchTab';
import { ProcessesTab } from './ProcessesTab';
import { BookmarksTab } from './BookmarksTab';
import { WelcomeScreen } from './WelcomeScreen';
import { LiveActivityPanel } from './LiveActivityPanel';
import { motion, AnimatePresence } from 'motion/react';

// ---------------------------------------------------------------------------
// Layout engine — radial (default) or dagre fallback
// ---------------------------------------------------------------------------

const NODE_W = 180;
const NODE_H = 52;

type LayoutMode = 'radial' | 'dagre';

// Severity-based node styling — applied to all layouts
function styleNodeBySeverity(n: Node): Node {
  const sev = (n.data as any).severity as string | undefined;
  const isRoot = n.type === 'input' || (n.data as any).isRoot;

  // Severity → border color + glow
  let borderColor = 'var(--cs-border)';
  let shadow = '0 4px 16px rgba(0,0,0,0.25)';
  let nodeWidth = NODE_W;
  let nodeHeight = NODE_H;

  if (isRoot) {
    borderColor = '#00d4aa';
    shadow = '0 0 24px rgba(0,212,170,0.2), 0 4px 16px rgba(0,0,0,0.3)';
    nodeWidth = 200;
    nodeHeight = 60;
  } else if (sev === 'high') {
    borderColor = '#ff3b5c';
    shadow = '0 0 24px rgba(255,59,92,0.3), 0 4px 16px rgba(0,0,0,0.3)';
    nodeWidth = 200;
    nodeHeight = 56;
  } else if (sev === 'medium') {
    borderColor = '#f97316';
    shadow = '0 0 16px rgba(249,115,22,0.2), 0 4px 16px rgba(0,0,0,0.3)';
    nodeWidth = 190;
    nodeHeight = 54;
  } else if (sev === 'low') {
    borderColor = '#ffb224';
    shadow = '0 0 12px rgba(255,178,36,0.15), 0 4px 16px rgba(0,0,0,0.25)';
  }

  return {
    ...n,
    style: {
      ...n.style,
      border: `2px solid ${borderColor}`,
      boxShadow: shadow,
      borderRadius: 14,
      width: nodeWidth,
      minHeight: nodeHeight,
    },
  };
}

function applyRadialLayout(nodes: Node[], edges: Edge[]): Node[] {
  if (nodes.length === 0) return nodes;

  // Build adjacency from edges
  const children: Record<string, string[]> = {};
  const hasParent = new Set<string>();
  edges.forEach(e => {
    if (!children[e.source]) children[e.source] = [];
    children[e.source].push(e.target);
    hasParent.add(e.target);
  });

  // Find root nodes (no incoming edges)
  const roots = nodes.filter(n => !hasParent.has(n.id)).map(n => n.id);
  if (roots.length === 0) roots.push(nodes[0].id);

  // Separate threat nodes from clean nodes
  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const threatIds = new Set<string>();
  const highIds = new Set<string>();
  nodes.forEach(n => {
    const sev = (n.data as any).severity;
    if (sev === 'high') { threatIds.add(n.id); highIds.add(n.id); }
    else if (sev === 'medium') { threatIds.add(n.id); }
    else if (sev === 'low') { threatIds.add(n.id); }
  });

  // BFS to assign layers
  const layer: Record<string, number> = {};
  const queue: string[] = [...roots];
  roots.forEach(r => { layer[r] = 0; });
  const visited = new Set<string>(roots);
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const child of (children[current] ?? [])) {
      if (!visited.has(child)) {
        visited.add(child);
        layer[child] = (layer[current] ?? 0) + 1;
        queue.push(child);
      }
    }
  }

  nodes.forEach(n => { if (layer[n.id] === undefined) layer[n.id] = 0; });

  // Group clean nodes by BFS layer, threats go to a special outer ring
  const cleanLayers: Record<number, string[]> = {};
  const threatList: string[] = [];
  let maxCleanLayer = 0;
  nodes.forEach(n => {
    if (n.type === 'input' || (n.data as any).isRoot) {
      // Root always at center
      if (!cleanLayers[0]) cleanLayers[0] = [];
      cleanLayers[0].push(n.id);
    } else if (threatIds.has(n.id)) {
      threatList.push(n.id);
    } else {
      const l = layer[n.id] ?? 1;
      if (!cleanLayers[l]) cleanLayers[l] = [];
      cleanLayers[l].push(n.id);
      maxCleanLayer = Math.max(maxCleanLayer, l);
    }
  });

  const RING_SPACING = 180;
  const CENTER_X = 0;
  const CENTER_Y = 0;
  const positions: Record<string, { x: number; y: number }> = {};

  // Place clean nodes in inner rings
  for (let l = 0; l <= maxCleanLayer; l++) {
    const ids = cleanLayers[l] ?? [];
    if (l === 0 && ids.length === 1) {
      positions[ids[0]] = { x: CENTER_X - NODE_W / 2, y: CENTER_Y - NODE_H / 2 };
    } else if (ids.length > 0) {
      const radius = l * RING_SPACING + 80;
      const angleStep = (2 * Math.PI) / ids.length;
      ids.forEach((id, i) => {
        const angle = -Math.PI / 2 + i * angleStep;
        positions[id] = {
          x: CENTER_X + radius * Math.cos(angle) - NODE_W / 2,
          y: CENTER_Y + radius * Math.sin(angle) - NODE_H / 2,
        };
      });
    }
  }

  // Place threat nodes in an outer "danger ring" — clearly separated
  if (threatList.length > 0) {
    const dangerRadius = (maxCleanLayer + 1) * RING_SPACING + 160;
    const angleStep = (2 * Math.PI) / threatList.length;
    // Sort: high first, then medium, then low for visual grouping
    threatList.sort((a, b) => {
      const sa = (nodeMap.get(a)?.data as any)?.severity ?? 'none';
      const sb = (nodeMap.get(b)?.data as any)?.severity ?? 'none';
      const rank: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };
      return (rank[sa] ?? 3) - (rank[sb] ?? 3);
    });
    threatList.forEach((id, i) => {
      const angle = -Math.PI / 2 + i * angleStep;
      positions[id] = {
        x: CENTER_X + dangerRadius * Math.cos(angle) - NODE_W / 2,
        y: CENTER_Y + dangerRadius * Math.sin(angle) - NODE_H / 2,
      };
    });
  }

  return nodes.map(n => styleNodeBySeverity({
    ...n,
    position: positions[n.id] ?? { x: 0, y: 0 },
    type: n.type === 'input' ? 'input' : 'default',
  }));
}

function applyDagreLayout(nodes: Node[], edges: Edge[]): Node[] {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', ranksep: 80, nodesep: 24, marginx: 40, marginy: 40 });
  nodes.forEach(n => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach(e => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map(n => {
    const pos = g.node(n.id);
    return styleNodeBySeverity({ ...n, position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 } });
  });
}

function applyLayout(nodes: Node[], edges: Edge[], mode: LayoutMode): Node[] {
  return mode === 'radial' ? applyRadialLayout(nodes, edges) : applyDagreLayout(nodes, edges);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toMs(nano: string): number {
  try { return Number(BigInt(nano) / 1_000_000n); }
  catch { return 0; }
}

function formatDuration(startNano: string, endNano: string): string {
  try {
    const ms = Number((BigInt(endNano) - BigInt(startNano)) / 1_000_000n);
    if (ms < 0)       return '—';
    if (ms < 1000)    return `${ms}ms`;
    if (ms < 60_000)  return `${(ms / 1000).toFixed(2)}s`;
    return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  } catch { return '—'; }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity  = 'none' | 'low' | 'medium' | 'high';
type FilterMode = 'all' | 'normal' | 'malicious';
type Tab        = 'timeline' | 'orchestration' | 'alerts' | 'rules' | 'costs' | 'harnesses' | 'settings' | 'heatmap' | 'search' | 'processes' | 'bookmarks';

// Category → Tab mapping for the navigation rail
const CATEGORY_TABS: Record<Category, { id: Tab; icon: React.ReactNode; label: string; badge?: number }[]> = {
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
    { id: 'rules', icon: null, label: 'Rules' },
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

const TAB_ICONS: Record<Tab, React.ReactNode> = {
  timeline:      <Clock className="w-3.5 h-3.5" />,
  orchestration: <Cpu className="w-3.5 h-3.5" />,
  heatmap:       <Flame className="w-3.5 h-3.5" />,
  processes:     <Monitor className="w-3.5 h-3.5" />,
  alerts:        <AlertTriangle className="w-3.5 h-3.5" />,
  search:        <Search className="w-3.5 h-3.5" />,
  rules:         <Shield className="w-3.5 h-3.5" />,
  bookmarks:     <Bookmark className="w-3.5 h-3.5" />,
  harnesses:     <Cpu className="w-3.5 h-3.5" />,
  costs:         <Zap className="w-3.5 h-3.5" />,
  settings:      <Settings className="w-3.5 h-3.5" />,
};

// Find which category a tab belongs to
function categoryForTab(tab: Tab): Category {
  for (const [cat, tabs] of Object.entries(CATEGORY_TABS)) {
    if (tabs.some(t => t.id === tab)) return cat as Category;
  }
  return 'observe';
}

interface Workflow {
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

type SessionLabel = 'normal' | 'incident' | 'investigation' | 'automated' | 'other';

interface Session {
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

const LABEL_COLORS: Record<SessionLabel, { dot: string; bg: string; text: string }> = {
  normal:        { dot: '#64748b', bg: 'bg-slate-800',       text: 'text-slate-400' },
  incident:      { dot: '#ef4444', bg: 'bg-red-900/30',      text: 'text-red-300'   },
  investigation: { dot: '#f97316', bg: 'bg-orange-900/30',   text: 'text-orange-300'},
  automated:     { dot: '#3b82f6', bg: 'bg-blue-900/30',     text: 'text-blue-300'  },
  other:         { dot: '#a855f7', bg: 'bg-purple-900/30',   text: 'text-purple-300'},
};

interface TickerSpan {
  spanId: string;
  name: string;
  harness: string;
  severity: Severity;
  ts: string;
}

// ---------------------------------------------------------------------------
// Constants
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

const SEVERITY_LABEL: Record<Severity, string> = {
  none: 'OK', low: 'LOW', medium: 'MED', high: 'HIGH',
};

const SEVERITY_COLORS: Record<Severity, { row: string; badge: string; text: string; icon: string }> = {
  none:   { row: 'bg-green-500/10 border-green-500/30 hover:bg-green-500/20',    badge: 'bg-green-900/40 text-green-300',   text: 'text-green-200',  icon: 'text-green-400'  },
  low:    { row: 'bg-yellow-500/10 border-yellow-500/30 hover:bg-yellow-500/20', badge: 'bg-yellow-900/40 text-yellow-300', text: 'text-yellow-200', icon: 'text-yellow-400' },
  medium: { row: 'bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/20', badge: 'bg-orange-900/40 text-orange-300', text: 'text-orange-200', icon: 'text-orange-400' },
  high:   { row: 'bg-red-500/10 border-red-500/40 hover:bg-red-500/20',          badge: 'bg-red-900/40 text-red-300',       text: 'text-red-200',   icon: 'text-red-400'    },
};

const SEV_RANK: Record<number, Severity> = { 3: 'high', 2: 'medium', 1: 'low', 0: 'none' };

// ---------------------------------------------------------------------------
// Timeline component
// ---------------------------------------------------------------------------

function Timeline({
  workflows, onSelect, selectedId,
}: {
  workflows: Workflow[];
  onSelect: (id: string) => void;
  selectedId?: string;
}) {
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  const timed = useMemo(() =>
    workflows
      .filter(wf => wf.startNano !== '0' && wf.endNano !== '0')
      .sort((a, b) => {
        try {
          const diff = BigInt(a.startNano) - BigInt(b.startNano);
          return diff > 0n ? 1 : diff < 0n ? -1 : 0;
        } catch { return 0; }
      }),
    [workflows],
  );

  // Reset page when workflow count changes significantly
  useEffect(() => { setPage(1); }, [timed.length > 0]);

  if (timed.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-500">
        <Clock className="w-8 h-8 text-slate-700" />
        <p className="text-sm font-medium">No timing data yet</p>
        <p className="text-xs text-slate-600 max-w-xs text-center leading-relaxed">
          Spans need <code className="font-mono bg-slate-800 px-1 rounded">startTimeUnixNano</code> /{' '}
          <code className="font-mono bg-slate-800 px-1 rounded">endTimeUnixNano</code> to appear here.
          Simulated traces include timing.
        </p>
      </div>
    );
  }

  const totalPages = Math.ceil(timed.length / PAGE_SIZE);
  const pagedTimed = timed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const starts = pagedTimed.map(wf => toMs(wf.startNano));
  const ends   = pagedTimed.map(wf => toMs(wf.endNano));
  const minT   = Math.min(...starts);
  const maxT   = Math.max(...ends);
  const range  = maxT - minT || 1;

  const ROW_H   = 38;
  const LABEL_W = 152;
  const AXIS_H  = 28;
  const CHART_W = 920;
  const AVAIL_W = CHART_W - LABEL_W - 20;
  const SVG_H   = pagedTimed.length * ROW_H + AXIS_H + 8;

  const sevColor = (sev: Severity) =>
    sev === 'high' ? '#ef4444' : sev === 'medium' ? '#f97316' : sev === 'low' ? '#eab308' : '#22c55e';

  return (
    <div className="flex-1 overflow-auto p-5" style={{ background: 'var(--cs-bg-primary)' }}>
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-bold uppercase tracking-wider font-mono flex items-center gap-1.5" style={{ color: 'var(--cs-text-faint)' }}>
          <Clock className="w-3 h-3" />
          Timeline — {timed.length} spans · {range}ms window
        </p>
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-2 py-1 text-[11px] font-medium rounded transition-all disabled:opacity-30"
              style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
            >Prev</button>
            <span className="text-[11px] font-mono" style={{ color: 'var(--cs-text-faint)' }}>
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2 py-1 text-[11px] font-medium rounded transition-all disabled:opacity-30"
              style={{ background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-border)' }}
            >Next</button>
          </div>
        )}
      </div>
      <div className="rounded-xl overflow-hidden p-4" style={{ border: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}>
      <svg viewBox={`0 0 ${CHART_W} ${SVG_H}`} className="w-full" style={{ minWidth: 420 }}>
        {/* Grid lines + axis labels */}
        {[0, 0.25, 0.5, 0.75, 1].map(frac => (
          <g key={frac}>
            <line
              x1={LABEL_W + frac * AVAIL_W} y1={0}
              x2={LABEL_W + frac * AVAIL_W} y2={SVG_H - AXIS_H}
              stroke="var(--cs-svg-grid)" strokeWidth="1"
            />
            <text
              x={LABEL_W + frac * AVAIL_W} y={SVG_H - 8}
              fill="var(--cs-svg-text)" fontSize="9" fontFamily="monospace" textAnchor="middle"
            >
              {Math.round(frac * range)}ms
            </text>
          </g>
        ))}
        <line
          x1={LABEL_W} y1={SVG_H - AXIS_H}
          x2={CHART_W - 8} y2={SVG_H - AXIS_H}
          stroke="var(--cs-svg-axis)" strokeWidth="1"
        />

        {pagedTimed.map((wf, i) => {
          const startMs = toMs(wf.startNano) - minT;
          const endMs   = toMs(wf.endNano)   - minT;
          const durMs   = endMs - startMs;
          const x = LABEL_W + (startMs / range) * AVAIL_W;
          const w = Math.max(3, (durMs / range) * AVAIL_W);
          const y = i * ROW_H + 4;
          const isSelected = wf.id === selectedId;
          const col = sevColor(wf.severity);

          return (
            <g key={wf.id} onClick={() => onSelect(wf.id)} style={{ cursor: 'pointer' }}>
              {isSelected && (
                <rect x={0} y={y} width={CHART_W} height={ROW_H - 2} fill="var(--cs-svg-selected)" rx={2} />
              )}
              {/* Harness dot */}
              <circle cx={10} cy={y + ROW_H / 2 - 2} r={3.5}
                fill={HARNESS_COLORS[wf.harness] ?? '#64748b'} />
              {/* Label */}
              <text
                x={LABEL_W - 6} y={y + ROW_H / 2 + 3}
                fill={isSelected ? 'var(--cs-svg-label)' : 'var(--cs-svg-text)'}
                fontSize="10" fontFamily="monospace" textAnchor="end"
              >
                {wf.label.length > 17 ? wf.label.slice(0, 17) + '…' : wf.label}
              </text>
              {/* Track background */}
              <rect x={LABEL_W} y={y + 6} width={AVAIL_W} height={ROW_H - 12}
                fill="var(--cs-svg-track)" rx={2} />
              {/* Bar */}
              <rect x={x} y={y + 6} width={w} height={ROW_H - 12}
                fill={col} fillOpacity={isSelected ? 1 : 0.75} rx={2} />
              {/* Duration inside bar */}
              {w > 44 && (
                <text x={x + w / 2} y={y + ROW_H / 2 + 3}
                  fill="var(--cs-svg-track)" fontSize="9" fontFamily="monospace"
                  textAnchor="middle" fontWeight="bold"
                >
                  {durMs}ms
                </text>
              )}
            </g>
          );
        })}
      </svg>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

const initialNodes: Node[] = [
  { id: 'agent', data: { label: 'AI Agent' }, position: { x: 0, y: 0 }, type: 'input' },
];

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function App() {
  // ── Graph state ───────────────────────────────────────────────────────────
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // ── UI state ──────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab]           = useState<Tab>('timeline');
  const [activeCategory, setActiveCategory] = useState<Category>('observe');
  const [selectedNode, setSelectedNode]     = useState<Node | null>(null);

  // When category changes, jump to its first tab
  const handleCategoryChange = (cat: Category) => {
    setActiveCategory(cat);
    const firstTab = CATEGORY_TABS[cat][0];
    if (firstTab) setActiveTab(firstTab.id);
  };

  // Keep category in sync when tab is set directly
  const handleTabChange = (tab: Tab) => {
    setActiveTab(tab);
    setActiveCategory(categoryForTab(tab));
  };
  const [layoutMode, setLayoutMode]         = useState<LayoutMode>('radial');

  // ── Data state ────────────────────────────────────────────────────────────
  const [workflows, setWorkflows]           = useState<Workflow[]>([]);
  const [sessions, setSessions]             = useState<Session[]>([]);
  const [activeSession, setActiveSession]   = useState<string | null>(null);
  const [hasEverHadData, setHasEverHadData] = useState(false);
  const [showWelcome, setShowWelcome] = useState(false);

  // ── Session rename ────────────────────────────────────────────────────────
  const [editingSession, setEditingSession] = useState<string | null>(null);
  const [editName, setEditName]             = useState('');

  // ── Filter state ──────────────────────────────────────────────────────────
  const [search, setSearch]                 = useState('');
  const [filterMode, setFilterMode]         = useState<FilterMode>('all');
  const [harnessFilter, setHarnessFilter]   = useState<string | null>(null);

  // ── Notification state ────────────────────────────────────────────────────
  const [notifyEnabled, setNotifyEnabled] = useState(false);
  const notifyEnabledRef = useRef(false);
  const seenHighIds = useRef<Set<string>>(new Set());

  // ── Alert count ───────────────────────────────────────────────────────────
  const [alertCount, setAlertCount] = useState(0);

  // ── Import ────────────────────────────────────────────────────────────────
  const importInputRef = useRef<HTMLInputElement>(null);
  const [importStatus, setImportStatus] = useState<{ msg: string; ok: boolean } | null>(null);

  // ── Theme (s53) ───────────────────────────────────────────────────────────
  const [liveActivityOpen, setLiveActivityOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('claudesec.theme') as 'dark' | 'light' | null;
      if (saved) return saved;
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    } catch { return 'dark'; }
  });

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    try { localStorage.setItem('claudesec.theme', theme); } catch { /* ignore */ }
  }, [theme]);

  // ── Session compare (s49) ─────────────────────────────────────────────────
  const [compareIds, setCompareIds] = useState<[string, string] | null>(null);
  // When exactly one session is Ctrl-clicked, hold it here until the 2nd pick
  const [comparePending, setComparePending] = useState<string | null>(null);

  // ── Graph replay (s51) ────────────────────────────────────────────────────
  const [replay, setReplay] = useState<ReplayState>({
    active: false, playing: false, speed: 1, progress: 0, currentStep: 0, totalSteps: 0,
  });
  const replayIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Live span ticker (s57) ────────────────────────────────────────────────
  const [tickerSpans, setTickerSpans] = useState<TickerSpan[]>([]);
  const tickerTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [tickerQuiet, setTickerQuiet] = useState(false);

  // ── Graph search (s46) ────────────────────────────────────────────────────
  const [graphSearchOpen,  setGraphSearchOpen]  = useState(false);
  const [graphSearchQuery, setGraphSearchQuery] = useState('');
  const [graphSearchIdx,   setGraphSearchIdx]   = useState(0);

  // ── Annotations ───────────────────────────────────────────────────────────
  interface Annotation { id: number; spanId: string; text: string; author: string; createdAt: string }
  const [annotations, setAnnotations]       = useState<Annotation[]>([]);
  const [annotationText, setAnnotationText] = useState('');
  const [annotationSaving, setAnnotationSaving] = useState(false);

  // ── Span Tags ─────────────────────────────────────────────────────────────
  const [spanTags,    setSpanTags]    = useState<string[]>([]);
  const [tagInput,    setTagInput]    = useState('');
  const [tagAdding,   setTagAdding]   = useState(false);
  const [showTagInput, setShowTagInput] = useState(false);

  // ── Span Bookmarks ────────────────────────────────────────────────────────
  const [isBookmarked, setIsBookmarked] = useState(false);

  // ── Graph export menu ─────────────────────────────────────────────────────
  const [showGraphExport, setShowGraphExport] = useState(false);
  const graphExportRef = useRef<HTMLDivElement>(null);

  // ── Session labels & notes ────────────────────────────────────────────────
  const [labelFilter,      setLabelFilter]      = useState<SessionLabel | 'all'>('all');
  const [notesSession,     setNotesSession]      = useState<string | null>(null); // traceId with notes panel open
  const [notesText,        setNotesText]         = useState('');
  const [labelMenuSession, setLabelMenuSession]  = useState<string | null>(null);

  const seenIds      = useRef<Set<string>>(new Set());
  const prevWorkflows = useRef<Workflow[]>([]);

  const onConnect = useCallback(
    (params: any) => setEdges(eds => addEdge(params, eds)),
    [setEdges],
  );

  // ── Data sync ─────────────────────────────────────────────────────────────

  function syncWorkflows(rawNodes: Node[]) {
    const spans = rawNodes.filter(n => !(n.data as any).isRoot && n.id !== 'agent');
    setWorkflows(spans.map(n => ({
      id:        n.id,
      label:     String(n.data.label),
      protocol:  String((n.data as any).protocol  ?? 'HTTPS'),
      reason:    String((n.data as any).reason     ?? '—'),
      severity:  ((n.data as any).severity ?? 'none') as Severity,
      harness:   String((n.data as any).harness   ?? 'unknown'),
      traceId:   String((n.data as any).traceId   ?? 'unknown'),
      startNano: String((n.data as any).startNano ?? '0'),
      endNano:   String((n.data as any).endNano   ?? '0'),
      attributes: ((n.data as any).attributes ?? {}) as Record<string, string>,
      timestamp: seenIds.current.has(n.id)
        ? (prevWorkflows.current.find(w => w.id === n.id)?.timestamp ?? new Date().toLocaleTimeString())
        : new Date().toLocaleTimeString(),
    })));
    spans.forEach(n => seenIds.current.add(n.id));
  }

  const fetchSessions = () =>
    fetch('/api/sessions').then(r => r.json()).then(({ sessions: s }) => {
      const list = s ?? [];
      setSessions(list);
      if (list.length > 0) setHasEverHadData(true);
    });

  const fetchAlertCount = () =>
    fetch('/api/alerts?limit=1')
      .then(r => r.json())
      .then(({ total }: { total: number }) => setAlertCount(total ?? 0))
      .catch(() => {});

  const requestNotifications = async () => {
    if (!('Notification' in window)) return;
    if (notifyEnabled) {
      setNotifyEnabled(false);
      notifyEnabledRef.current = false;
      return;
    }
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
      setNotifyEnabled(true);
      notifyEnabledRef.current = true;
    }
  };

  // ── Import handler ────────────────────────────────────────────────────────
  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        const body = JSON.parse(ev.target?.result as string);
        const res = await fetch('/api/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const data = await res.json();
        if (res.ok) {
          setImportStatus({ msg: `Imported ${data.imported} spans`, ok: true });
        } else {
          setImportStatus({ msg: data.error ?? 'Import failed', ok: false });
        }
      } catch {
        setImportStatus({ msg: 'Invalid JSON file', ok: false });
      }
      setTimeout(() => setImportStatus(null), 4000);
      if (importInputRef.current) importInputRef.current.value = '';
    };
    reader.readAsText(file);
  };

  // Initial load
  useEffect(() => {
    const graphUrl = activeSession ? `/api/graph?session=${encodeURIComponent(activeSession)}` : '/api/graph';
    fetch(graphUrl)
      .then(r => r.json())
      .then(({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
        setNodes(applyLayout(n, e, layoutMode));
        setEdges(e);
        syncWorkflows(n);
      });
    fetchSessions();
    fetchAlertCount();
  }, [activeSession]);

  useEffect(() => { prevWorkflows.current = workflows; }, [workflows]);

  // Fetch annotations when a span is selected
  useEffect(() => {
    if (!selectedNode || selectedNode.id === 'agent') { setAnnotations([]); setAnnotationText(''); return; }
    fetch(`/api/spans/${encodeURIComponent(selectedNode.id)}/annotations`)
      .then(r => r.json())
      .then(({ annotations: a }) => setAnnotations(a ?? []))
      .catch(() => {});
  }, [selectedNode]);

  // Fetch span tags + bookmark state when a span is selected
  useEffect(() => {
    if (!selectedNode || selectedNode.id === 'agent') {
      setSpanTags([]); setTagInput(''); setShowTagInput(false); setIsBookmarked(false);
      return;
    }
    const sid = encodeURIComponent(selectedNode.id);
    fetch(`/api/spans/${sid}/tags`)
      .then(r => r.json())
      .then(({ tags }: { tags: string[] }) => setSpanTags(tags ?? []))
      .catch(() => {});
    fetch(`/api/bookmarks?session=${encodeURIComponent((selectedNode.data as any).traceId ?? '')}`)
      .then(r => r.json())
      .then((rows: { spanId: string }[]) => {
        setIsBookmarked((rows ?? []).some(b => b.spanId === selectedNode.id));
      })
      .catch(() => {});
  }, [selectedNode]);

  // Close graph export menu on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (graphExportRef.current && !graphExportRef.current.contains(e.target as Element)) {
        setShowGraphExport(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // Socket events
  useEffect(() => {
    const handleGraphUpdate = ({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
      // When scoped to a session, re-fetch the scoped graph instead of using the broadcast
      if (activeSession) {
        fetch(`/api/graph?session=${encodeURIComponent(activeSession)}`)
          .then(r => r.json())
          .then(({ nodes: sn, edges: se }: { nodes: Node[]; edges: Edge[] }) => {
            setNodes(applyLayout(sn, se, layoutMode));
            setEdges(se);
            syncWorkflows(sn);
          });
        return;
      }
      setNodes(applyLayout(n, e, layoutMode));
      setEdges(e);
      syncWorkflows(n);

      // Desktop notifications for new HIGH severity spans
      if (notifyEnabledRef.current) {
        const highSpans = n.filter(
          node => (node.data as any).severity === 'high' && !seenHighIds.current.has(node.id),
        );
        highSpans.forEach(node => {
          const label = String(node.data.label ?? '');
          const rule  = String((node.data as any).attributes?.['claudesec.threat.rule'] ?? '');
          new Notification('ClaudeSec — HIGH Alert', {
            body: `${label}${rule ? ': ' + rule : ''}`,
            tag:  node.id,
          });
          seenHighIds.current.add(node.id);
        });
        // Also mark already-known high spans so we don't re-fire on later updates
        n.filter(node => (node.data as any).severity === 'high')
          .forEach(node => seenHighIds.current.add(node.id));
      }
    };

    const handleSpanAdded = (span: TickerSpan) => {
      setTickerSpans(prev => [span, ...prev].slice(0, 5));
      setTickerQuiet(false);
      if (tickerTimeoutRef.current) clearTimeout(tickerTimeoutRef.current);
      tickerTimeoutRef.current = setTimeout(() => setTickerQuiet(true), 10_000);
    };

    socket.on('graph-update', handleGraphUpdate);
    socket.on('sessions-update', fetchSessions);
    socket.on('alerts-update', fetchAlertCount);
    socket.on('span-added', handleSpanAdded);
    return () => {
      socket.off('graph-update', handleGraphUpdate);
      socket.off('sessions-update', fetchSessions);
      socket.off('alerts-update', fetchAlertCount);
      socket.off('span-added', handleSpanAdded);
    };
  }, [setNodes, setEdges]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const onNodeClick = (_: any, node: Node) => setSelectedNode(node);

  const resetGraph = async () => {
    await fetch('/api/reset', { method: 'POST' });
    setSelectedNode(null);
    setWorkflows([]);
    setSessions([]);
    seenIds.current.clear();
    seenHighIds.current.clear();
    setSearch('');
    setFilterMode('all');
    setHarnessFilter(null);
    setActiveSession(null);
    setAlertCount(0);
    setReplay({ active: false, playing: false, speed: 1, progress: 0, currentStep: 0, totalSteps: 0 });
    setCompareIds(null);
    setComparePending(null);
  };

  // ── Replay ────────────────────────────────────────────────────────────────

  const allSpansSorted = useMemo(() =>
    nodes
      .filter(n => n.id !== 'agent' && !(n.data as any).isRoot)
      .sort((a, b) => {
        try {
          const diff = BigInt((a.data as any).startNano ?? '0') - BigInt((b.data as any).startNano ?? '0');
          return diff > 0n ? 1 : diff < 0n ? -1 : 0;
        } catch { return 0; }
      }),
    [nodes],
  );

  const startReplay = useCallback(() => {
    if (allSpansSorted.length === 0) return;
    if (replayIntervalRef.current) clearInterval(replayIntervalRef.current);
    setReplay({ active: true, playing: true, speed: 1, progress: 0, currentStep: 0, totalSteps: allSpansSorted.length });
  }, [allSpansSorted]);

  // Replay tick
  useEffect(() => {
    if (!replay.active || !replay.playing) {
      if (replayIntervalRef.current) { clearInterval(replayIntervalRef.current); replayIntervalRef.current = null; }
      return;
    }
    const TICK_MS = 300;
    replayIntervalRef.current = setInterval(() => {
      setReplay(prev => {
        const next = Math.min(prev.currentStep + prev.speed, prev.totalSteps);
        const done  = next >= prev.totalSteps;
        if (done && replayIntervalRef.current) { clearInterval(replayIntervalRef.current); replayIntervalRef.current = null; }
        return { ...prev, currentStep: next, progress: next / prev.totalSteps, playing: !done };
      });
    }, TICK_MS);
    return () => { if (replayIntervalRef.current) { clearInterval(replayIntervalRef.current); replayIntervalRef.current = null; } };
  }, [replay.active, replay.playing, replay.speed]);

  const handleReplayPlay    = useCallback(() => setReplay(p => ({ ...p, playing: true })), []);
  const handleReplayPause   = useCallback(() => setReplay(p => ({ ...p, playing: false })), []);
  const handleReplayRestart = useCallback(() => setReplay(p => ({ ...p, playing: true, currentStep: 0, progress: 0 })), []);
  const handleReplayStop    = useCallback(() => {
    if (replayIntervalRef.current) { clearInterval(replayIntervalRef.current); replayIntervalRef.current = null; }
    setReplay({ active: false, playing: false, speed: 1, progress: 0, currentStep: 0, totalSteps: 0 });
  }, []);
  const handleReplaySetSpeed = useCallback((s: 1 | 2 | 5) => setReplay(p => ({ ...p, speed: s })), []);
  const handleReplayScrub    = useCallback((frac: number) => {
    setReplay(p => {
      const step = Math.round(frac * p.totalSteps);
      return { ...p, currentStep: step, progress: frac, playing: false };
    });
  }, []);

  const startRename = (s: Session) => {
    setEditingSession(s.traceId);
    setEditName(s.name);
  };

  const commitRename = async () => {
    if (!editingSession || !editName.trim()) { setEditingSession(null); return; }
    await fetch(`/api/sessions/${encodeURIComponent(editingSession)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: editName.trim() }),
    });
    setEditingSession(null);
    fetchSessions();
  };

  const simulateTrace = async (type: 'normal' | 'high' | 'multi' = 'normal') => {
    const traceId = Math.random().toString(36).substring(2, 18);
    const now     = Date.now();

    if (type === 'multi') {
      // Simulate 3 spans from different harnesses
      const harnesses = ['claude-code', 'openhands', 'aider'] as const;
      for (let i = 0; i < harnesses.length; i++) {
        const spanId = Math.random().toString(36).substring(7);
        await fetch('/v1/traces', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            resourceSpans: [{
              resource: { attributes: [
                { key: 'service.name',       value: { stringValue: harnesses[i] } },
                { key: 'telemetry.sdk.name', value: { stringValue: harnesses[i] } },
              ]},
              scopeSpans: [{ scope: {}, spans: [{
                traceId, spanId,
                name:  `${HARNESS_NAMES[harnesses[i]]} · task-${i + 1}`,
                kind: 1,
                startTimeUnixNano: String((now + i * 80) * 1_000_000),
                endTimeUnixNano:   String((now + i * 80 + 200) * 1_000_000),
                attributes: [
                  { key: 'protocol', value: { stringValue: 'MCP' } },
                  { key: 'reason',   value: { stringValue: `Orchestrated sub-task from agent ${i + 1}` } },
                  { key: 'gen_ai.usage.input_tokens',  value: { intValue: 120 + i * 40 } },
                  { key: 'gen_ai.usage.output_tokens', value: { intValue: 60  + i * 20 } },
                ],
                status: { code: 0 },
              }]}],
            }],
          }),
        });
      }
      return;
    }

    const isHigh  = type === 'high';
    const payload = isHigh ? 'cat /etc/passwd' : 'GET /api/v1/data';
    const reason  = isHigh ? 'Attempting unauthorized access' : 'Fetching workspace data';

    await fetch('/v1/traces', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resourceSpans: [{
          resource: { attributes: [
            { key: 'service.name',       value: { stringValue: 'claude-code' } },
            { key: 'telemetry.sdk.name', value: { stringValue: 'claude-code' } },
          ]},
          scopeSpans: [{ scope: {}, spans: [{
            traceId,
            spanId: Math.random().toString(36).substring(7),
            name: isHigh ? 'Malicious Command' : 'Fetch Data',
            kind: 1,
            startTimeUnixNano: String(now * 1_000_000),
            endTimeUnixNano:   String((now + 120) * 1_000_000),
            attributes: [
              { key: 'protocol', value: { stringValue: 'HTTPS' } },
              { key: 'reason',   value: { stringValue: reason } },
              { key: 'payload',  value: { stringValue: payload } },
              { key: 'gen_ai.usage.input_tokens',  value: { intValue: 250 } },
              { key: 'gen_ai.usage.output_tokens', value: { intValue: 80  } },
              { key: 'gen_ai.tool.name',           value: { stringValue: isHigh ? 'bash' : 'read_file' } },
            ],
            status: { code: 0 },
          }]}],
        }],
      }),
    });
  };

  // ── Derived state ─────────────────────────────────────────────────────────

  const activeHarnesses = useMemo(
    () => [...new Set(workflows.map(wf => wf.harness))],
    [workflows],
  );

  const visibleWorkflows = useMemo(() => {
    return workflows.filter(wf => {
      if (activeSession && wf.traceId !== activeSession) return false;

      const matchSeverity =
        filterMode === 'all' ||
        (filterMode === 'normal'    && wf.severity === 'none') ||
        (filterMode === 'malicious' && wf.severity !== 'none');

      const matchHarness = !harnessFilter || wf.harness === harnessFilter;

      const matchSearch = (() => {
        if (!search) return true;
        const term = search.toLowerCase();
        if (term.includes('=')) {
          const eqIdx = term.indexOf('=');
          const key   = term.slice(0, eqIdx).trim();
          const val   = term.slice(eqIdx + 1).trim();
          return String(wf.attributes[key] ?? '').toLowerCase().includes(val);
        }
        return (
          wf.label.toLowerCase().includes(term)     ||
          wf.reason.toLowerCase().includes(term)    ||
          wf.protocol.toLowerCase().includes(term)  ||
          wf.harness.toLowerCase().includes(term)   ||
          Object.values(wf.attributes).some(v => String(v).toLowerCase().includes(term))
        );
      })();

      return matchSeverity && matchHarness && matchSearch;
    });
  }, [workflows, filterMode, harnessFilter, search, activeSession]);

  const counts = useMemo(() => ({
    ok:     workflows.filter(w => w.severity === 'none').length,
    low:    workflows.filter(w => w.severity === 'low').length,
    medium: workflows.filter(w => w.severity === 'medium').length,
    high:   workflows.filter(w => w.severity === 'high').length,
  }), [workflows]);

  const metrics = useMemo(() => {
    const tokenIn  = workflows.reduce((s, wf) =>
      s + Number(wf.attributes['gen_ai.usage.input_tokens']  ?? wf.attributes['llm.usage.input_tokens']  ?? 0), 0);
    const tokenOut = workflows.reduce((s, wf) =>
      s + Number(wf.attributes['gen_ai.usage.output_tokens'] ?? wf.attributes['llm.usage.output_tokens'] ?? 0), 0);
    const toolCalls = workflows.filter(wf =>
      wf.attributes['gen_ai.tool.name'] || wf.attributes['tool.name']).length;
    const timed = workflows.filter(wf => wf.startNano !== '0' && wf.endNano !== '0');
    const avgMs = timed.length
      ? Math.round(timed.reduce((s, wf) => {
          try { return s + Number((BigInt(wf.endNano) - BigInt(wf.startNano)) / 1_000_000n); }
          catch { return s; }
        }, 0) / timed.length)
      : 0;
    return { tokenIn, tokenOut, toolCalls, avgMs };
  }, [workflows]);

  // selected workflow from timeline click
  const timelineSelected = selectedNode?.id;
  const onTimelineSelect = (id: string) => {
    const n = nodes.find(n => n.id === id);
    if (n) setSelectedNode(n);
  };

  // ── Graph search derived state ────────────────────────────────────────────
  const graphSearchMatchIds = useMemo(() => {
    const q = graphSearchQuery.trim().toLowerCase();
    if (!q) return [];
    return nodes
      .filter(n => {
        if (n.id === 'agent') return false;
        const label = String(n.data.label ?? '').toLowerCase();
        const attrs = JSON.stringify((n.data as any).attributes ?? {}).toLowerCase();
        return label.includes(q) || attrs.includes(q);
      })
      .map(n => n.id);
  }, [graphSearchQuery, nodes]);

  // Apply search highlighting: dim non-matching nodes
  const displayNodes = useMemo(() => {
    // Replay takes precedence: only show nodes up to current replay step
    if (replay.active) {
      const visibleIds = new Set<string>(['agent', ...allSpansSorted.slice(0, replay.currentStep).map(n => n.id)]);
      return nodes.map(n => ({
        ...n,
        style: { ...n.style, opacity: visibleIds.has(n.id) ? 1 : 0 },
      }));
    }
    if (!graphSearchQuery.trim() || graphSearchMatchIds.length === 0) return nodes;
    const matchSet = new Set(graphSearchMatchIds);
    const current  = graphSearchMatchIds[graphSearchIdx];
    return nodes.map(n => ({
      ...n,
      style: {
        ...n.style,
        opacity: matchSet.has(n.id) ? 1 : 0.15,
        outline: n.id === current ? '2px solid #3b82f6' : undefined,
        outlineOffset: n.id === current ? '2px' : undefined,
      },
    }));
  }, [nodes, graphSearchMatchIds, graphSearchIdx, graphSearchQuery, replay.active, replay.currentStep, allSpansSorted]);


  // ── Render ────────────────────────────────────────────────────────────────

  // ── Export menu state ──────────────────────────────────────────────────
  const [showExportMenu, setShowExportMenu] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Element)) setShowExportMenu(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div className="w-screen h-screen flex flex-col overflow-hidden" style={{ background: 'var(--cs-bg-primary)', color: 'var(--cs-text-base)' }}>

      {/* ── Header ── */}
      <header className="h-11 flex items-center justify-between px-4 z-10 shrink-0" style={{
        borderBottom: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}>
        {/* Left cluster: logo + sparkline */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: 'linear-gradient(135deg, #00d4aa, #009e7f)' }}>
              <Shield className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="font-display font-bold text-[13px] tracking-tight" style={{ color: 'var(--cs-text-base)' }}>ClaudeSec</span>
          </div>
          <div className="hidden lg:flex items-center gap-2 pl-3" style={{ borderLeft: '1px solid var(--cs-border)' }}>
            <ActivitySparkline />
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full" style={{ background: 'rgba(0,212,170,0.08)' }}>
              <div className="w-1.5 h-1.5 rounded-full status-live" style={{ background: '#00d4aa' }} />
              <span className="text-[10px] font-mono font-semibold" style={{ color: '#00d4aa' }}>LIVE</span>
            </div>
          </div>
        </div>

        {/* Import status toast */}
        {importStatus && (
          <div className={`absolute top-14 left-1/2 -translate-x-1/2 px-4 py-2 rounded-lg text-xs font-medium z-50 shadow-lg backdrop-blur-md ${importStatus.ok ? 'bg-green-900/80 text-green-200 border border-green-700/50' : 'bg-red-900/80 text-red-200 border border-red-700/50'}`}>
            {importStatus.msg}
          </div>
        )}

        {/* Right cluster: actions, grouped */}
        <div className="flex items-center gap-0.5">
          {/* Notification toggle */}
          <button
            onClick={requestNotifications}
            className="p-1.5 rounded-lg transition-all"
            style={{
              background: notifyEnabled ? 'rgba(0,212,170,0.1)' : 'transparent',
              color: notifyEnabled ? '#00d4aa' : 'var(--cs-text-faint)',
            }}
            title={notifyEnabled ? 'Notifications enabled' : 'Enable desktop notifications'}
          >
            {notifyEnabled ? <Bell className="w-3.5 h-3.5" /> : <BellOff className="w-3.5 h-3.5" />}
          </button>

          {/* Export dropdown */}
          <div ref={exportMenuRef} className="relative">
            <button
              onClick={() => setShowExportMenu(v => !v)}
              className="flex items-center gap-1 px-2 py-1.5 rounded-lg text-[11px] font-medium transition-all"
              style={{
                background: showExportMenu ? 'var(--cs-bg-elevated)' : 'transparent',
                color: 'var(--cs-text-muted)',
              }}
              onMouseEnter={e => { if (!showExportMenu) (e.target as HTMLElement).style.background = 'var(--cs-bg-elevated)'; }}
              onMouseLeave={e => { if (!showExportMenu) (e.target as HTMLElement).style.background = 'transparent'; }}
            >
              <Download className="w-3 h-3" /> Export <ChevronDown className="w-2.5 h-2.5" />
            </button>
            {showExportMenu && (
              <div className="absolute right-0 top-full mt-1.5 z-50 dropdown-menu py-1 min-w-[180px]">
                <label className="flex items-center gap-2 px-3 py-2 text-xs cursor-pointer transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Upload className="w-3.5 h-3.5" /> Import JSON
                  <input ref={importInputRef} type="file" accept=".json,application/json" className="hidden" onChange={handleImportFile} />
                </label>
                <div style={{ borderTop: '1px solid var(--cs-border)', margin: '2px 0' }} />
                <button onClick={() => { setShowExportMenu(false); window.open('/api/export', '_blank'); }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Download className="w-3.5 h-3.5" /> Export JSON
                </button>
                <button onClick={() => { setShowExportMenu(false); window.open('/api/export/csv', '_blank'); }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <FileText className="w-3.5 h-3.5" /> Export CSV
                </button>
                <div style={{ borderTop: '1px solid var(--cs-border)', margin: '2px 0' }} />
                <button onClick={async () => {
                    setShowExportMenu(false);
                    const params = activeSession ? `?session=${activeSession}` : '';
                    const res = await fetch(`/api/graph/mermaid${params}`);
                    const text = await res.text();
                    await navigator.clipboard.writeText(text);
                  }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Layers className="w-3.5 h-3.5" /> Copy Mermaid
                </button>
                <button onClick={() => {
                    setShowExportMenu(false);
                    const params = activeSession ? `?session=${activeSession}` : '';
                    window.open(`/api/graph/dot${params}`, '_blank');
                  }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Layers className="w-3.5 h-3.5" /> Download .dot
                </button>
                <button onClick={() => { setShowExportMenu(false); window.open('/api/collector-config', '_blank'); }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Server className="w-3.5 h-3.5" /> Collector Config
                </button>
              </div>
            )}
          </div>

          <div className="header-divider" />

          {/* Setup guide */}
          <button
            onClick={() => setShowWelcome(v => !v)}
            className="p-1.5 rounded-lg transition-all"
            style={{
              background: showWelcome ? 'rgba(0,212,170,0.1)' : 'transparent',
              color: showWelcome ? '#00d4aa' : 'var(--cs-text-faint)',
            }}
            title="Setup Guide"
          >
            <Shield className="w-3.5 h-3.5" />
          </button>

          {/* Live activity */}
          <button
            onClick={() => setLiveActivityOpen(v => !v)}
            className="p-1.5 rounded-lg transition-all"
            style={{
              background: liveActivityOpen ? 'rgba(59,158,255,0.1)' : 'transparent',
              color: liveActivityOpen ? '#3b9eff' : 'var(--cs-text-faint)',
            }}
            title="Live Agent Activity"
          >
            <Zap className="w-3.5 h-3.5" />
          </button>

          {/* Theme toggle */}
          <button
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            className="p-1.5 rounded-lg transition-all"
            style={{ color: 'var(--cs-text-faint)' }}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>

          <div className="header-divider" />

          {/* Reset */}
          <button
            onClick={resetGraph}
            className="p-1.5 rounded-lg transition-all hover:text-red-400"
            style={{ color: 'var(--cs-text-faint)' }}
            title="Reset all data"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Live Activity floating panel */}
      <LiveActivityPanel open={liveActivityOpen} onClose={() => setLiveActivityOpen(false)} />

      <div className="flex-1 flex overflow-hidden min-h-0">

        {/* ── Category Rail ── */}
        <CategoryNav active={activeCategory} onChange={handleCategoryChange} alertCount={alertCount} />

        {/* ── Contextual Sidebar ── */}
        <ContextSidebar
          category={activeCategory}
          alertCount={alertCount}
          activeTab={activeTab}
          onTabChange={(tab) => handleTabChange(tab as Tab)}
          observeContent={<>

          {/* Sessions */}
          <div className="p-2.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
            <div className="flex items-center justify-between mb-2">
              <p className="sidebar-section-label">
                <Layers className="w-3 h-3" /> Sessions
              </p>
              <div className="flex items-center gap-1.5">
                {comparePending ? (
                  <>
                    <span className="text-[11px] text-blue-400 font-mono animate-pulse">pick 2nd…</span>
                    <button
                      onClick={() => setComparePending(null)}
                      className="text-slate-500 hover:text-slate-300"
                      title="Cancel comparison"
                    >
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </>
                ) : compareIds ? (
                  <button
                    onClick={() => setCompareIds(null)}
                    className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-0.5"
                    title="Close comparison"
                  >
                    <GitCompare className="w-2.5 h-2.5" /> Close
                  </button>
                ) : null}
                <span className="text-[10px] text-slate-600 font-mono tabular-nums">{sessions.length}</span>
              </div>
            </div>
            {/* Label filter pills */}
            <div className="flex flex-wrap gap-1 mb-2">
              {(['all', 'incident', 'investigation', 'automated', 'other'] as const).map(l => (
                <button
                  key={l}
                  onClick={() => setLabelFilter(l)}
                  className="px-1.5 py-0.5 rounded text-[11px] font-medium transition-all capitalize"
                  style={
                    labelFilter === l
                      ? l === 'all'
                        ? { background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-base)', border: '1px solid var(--cs-border-soft)' }
                        : { background: (LABEL_COLORS[l as SessionLabel]?.dot ?? '#64748b') + '22', color: LABEL_COLORS[l as SessionLabel]?.dot, border: `1px solid ${(LABEL_COLORS[l as SessionLabel]?.dot ?? '#64748b')}44` }
                      : { background: 'transparent', color: 'var(--cs-text-faint)', border: '1px solid transparent' }
                  }
                >
                  {l === 'all' ? 'All' : l}
                </button>
              ))}
            </div>

            <div className="space-y-1 max-h-36 overflow-y-auto">
              <button
                onClick={() => setActiveSession(null)}
                className="w-full text-left px-2 py-1.5 rounded-md text-xs font-medium transition-all"
                style={activeSession === null
                  ? { background: 'rgba(0,212,170,0.12)', color: '#00d4aa', border: '1px solid rgba(0,212,170,0.2)' }
                  : { background: 'transparent', color: 'var(--cs-text-muted)', border: '1px solid transparent' }
                }
              >
                All sessions · {workflows.length} spans
              </button>
              {sessions.filter(s => labelFilter === 'all' || (s.label ?? 'normal') === labelFilter).map(s => {
                const sev = SEV_RANK[s.maxSeverityRank] ?? 'none';
                const sevCol = sev === 'high' ? '#ef4444' : sev === 'medium' ? '#f97316' : sev === 'low' ? '#eab308' : '#22c55e';
                const isActive  = activeSession === s.traceId;
                const isEditing = editingSession === s.traceId;
                const isPinned  = !!s.pinned;
                const sessionLabel = (s.label ?? 'normal') as SessionLabel;
                const lc = LABEL_COLORS[sessionLabel];
                return (
                  <React.Fragment key={s.traceId}>
                  <div
                    className="session-row relative flex items-center gap-1.5 px-2 py-2 text-xs group"
                    style={{
                      ...(isActive
                        ? { background: 'rgba(0,212,170,0.1)', color: '#00d4aa', borderLeftColor: '#00d4aa' }
                        : comparePending === s.traceId
                        ? { background: 'rgba(59,158,255,0.08)', color: '#3b9eff', borderLeftColor: '#3b9eff' }
                        : isPinned
                        ? { background: 'rgba(255,178,36,0.05)', color: 'var(--cs-text-base)', borderLeftColor: '#ffb224' }
                        : { borderLeftColor: sevCol + '66' }),
                    }}
                  >
                    {isPinned && !isActive && <Star className="w-2 h-2 text-yellow-400 shrink-0" />}
                    {!isPinned && !isActive && (
                      <span
                        className="w-2 h-2 rounded-full shrink-0 border"
                        style={{
                          background: sessionLabel !== 'normal' ? lc.dot + '33' : sevCol + '33',
                          borderColor: sessionLabel !== 'normal' ? lc.dot : sevCol,
                        }}
                        title={`Label: ${sessionLabel}`}
                      />
                    )}
                    {!isPinned && isActive && <span className="w-1.5 h-1.5 rounded-full shrink-0 bg-white/60" />}
                    {s.healthScore !== undefined && !isActive && (
                      <span
                        className={`shrink-0 text-[11px] font-mono font-bold px-1 rounded ${
                          s.healthScore >= 80 ? 'text-green-400 bg-green-900/30'
                            : s.healthScore >= 50 ? 'text-yellow-400 bg-yellow-900/30'
                            : 'text-red-400 bg-red-900/30'
                        }`}
                        title={`Health score: ${s.healthScore}/100`}
                      >
                        {s.healthScore}
                      </span>
                    )}
                    {isEditing ? (
                      <form
                        className="flex-1 flex items-center gap-1"
                        onSubmit={e => { e.preventDefault(); commitRename(); }}
                      >
                        <input
                          autoFocus
                          value={editName}
                          onChange={e => setEditName(e.target.value)}
                          onBlur={commitRename}
                          className="flex-1 bg-slate-700 text-white text-xs rounded px-1 py-0.5 outline-none min-w-0"
                        />
                      </form>
                    ) : (
                      <>
                        <button
                          className="flex-1 text-left truncate min-w-0"
                          onClick={e => {
                            if (e.ctrlKey || e.metaKey) {
                              // Compare mode: pick two sessions
                              if (!comparePending) {
                                setComparePending(s.traceId);
                              } else if (comparePending !== s.traceId) {
                                setCompareIds([comparePending, s.traceId]);
                                setComparePending(null);
                              } else {
                                setComparePending(null);
                              }
                            } else {
                              setActiveSession(isActive ? null : s.traceId);
                            }
                          }}
                          title="Click to filter · Ctrl+click to compare"
                        >
                          <span className="text-[12px] font-medium">{s.name}</span>
                        </button>
                        <span className="shrink-0 text-[10px] font-mono opacity-40 tabular-nums">{s.spanCount}</span>
                        {/* Pin / unpin */}
                        <button
                          onClick={async e => {
                            e.stopPropagation();
                            await fetch(`/api/sessions/${encodeURIComponent(s.traceId)}`, {
                              method: 'PATCH',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({ pinned: !isPinned }),
                            });
                            fetchSessions();
                          }}
                          className={`shrink-0 transition-opacity ${isPinned ? 'opacity-60 hover:opacity-100' : 'opacity-0 group-hover:opacity-100'} hover:text-yellow-400`}
                          title={isPinned ? 'Unpin session' : 'Pin session'}
                        >
                          <Star className="w-2.5 h-2.5" />
                        </button>
                        <button
                          onClick={e => { e.stopPropagation(); startRename(s); }}
                          className="shrink-0 opacity-0 group-hover:opacity-100 hover:text-white transition-opacity"
                          title="Rename"
                        >
                          <Edit2 className="w-2.5 h-2.5" />
                        </button>
                        <a
                          href={`/api/sessions/${encodeURIComponent(s.traceId)}/report`}
                          target="_blank"
                          rel="noreferrer"
                          onClick={e => e.stopPropagation()}
                          className="shrink-0 opacity-0 group-hover:opacity-100 hover:text-blue-400 transition-opacity"
                          title="Download HTML report"
                        >
                          <FileText className="w-2.5 h-2.5" />
                        </a>
                        {/* Notes / label toggle */}
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setNotesSession(notesSession === s.traceId ? null : s.traceId);
                            setNotesText(s.notes ?? '');
                          }}
                          className={`shrink-0 transition-opacity ${notesSession === s.traceId ? 'opacity-100 text-yellow-400' : 'opacity-0 group-hover:opacity-100 hover:text-yellow-400'}`}
                          title="Session notes & label"
                        >
                          <StickyNote className="w-2.5 h-2.5" />
                        </button>
                      </>
                    )}
                  </div>
                  {/* Inline notes + label panel */}
                  {notesSession === s.traceId && (
                    <div className="mx-1 mb-1 p-2 bg-slate-800/80 border border-slate-700 rounded-lg space-y-2">
                      {/* Label selector */}
                      <div>
                        <p className="text-[11px] text-slate-600 uppercase font-bold mb-1">Label</p>
                        <div className="flex flex-wrap gap-1">
                          {(Object.keys(LABEL_COLORS) as SessionLabel[]).map(l => (
                            <button
                              key={l}
                              onClick={async () => {
                                await fetch(`/api/sessions/${encodeURIComponent(s.traceId)}`, {
                                  method: 'PATCH',
                                  headers: { 'Content-Type': 'application/json' },
                                  body: JSON.stringify({ label: l }),
                                });
                                fetchSessions();
                              }}
                              className={`px-1.5 py-0.5 rounded text-[11px] capitalize transition-colors ${
                                sessionLabel === l
                                  ? 'font-bold'
                                  : 'opacity-60 hover:opacity-100'
                              }`}
                              style={{
                                background: LABEL_COLORS[l].dot + '22',
                                color: LABEL_COLORS[l].dot,
                                border: sessionLabel === l ? `1px solid ${LABEL_COLORS[l].dot}` : '1px solid transparent',
                              }}
                            >
                              {l}
                            </button>
                          ))}
                        </div>
                      </div>
                      {/* Notes textarea */}
                      <div>
                        <p className="text-[11px] text-slate-600 uppercase font-bold mb-1">Notes</p>
                        <textarea
                          value={notesText}
                          onChange={e => setNotesText(e.target.value)}
                          onBlur={async () => {
                            await fetch(`/api/sessions/${encodeURIComponent(s.traceId)}`, {
                              method: 'PATCH',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({ notes: notesText }),
                            });
                            fetchSessions();
                          }}
                          placeholder="Add investigation notes…"
                          rows={3}
                          className="w-full bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-600 resize-none focus:outline-none focus:border-blue-500/50"
                        />
                      </div>
                    </div>
                  )}
                  </React.Fragment>
                );
              })}
            </div>
          </div>

          {/* Simulate */}
          <div className="p-3 space-y-1.5 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
            <p className="text-[11px] font-bold uppercase tracking-wider font-mono mb-1.5" style={{ color: 'var(--cs-text-faint)' }}>Simulate</p>
            <div className="flex gap-1.5">
              <button
                onClick={() => simulateTrace('normal')}
                className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg transition-all group"
                style={{ background: 'rgba(0,212,170,0.08)', border: '1px solid rgba(0,212,170,0.15)' }}
                title="Normal Trace"
              >
                <Play className="w-3 h-3 group-hover:scale-110 transition-transform" style={{ color: '#00d4aa' }} />
                <span className="text-[11px] font-medium" style={{ color: '#00d4aa' }}>Normal</span>
              </button>
              <button
                onClick={() => simulateTrace('high')}
                className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg transition-all group"
                style={{ background: 'rgba(255,59,92,0.08)', border: '1px solid rgba(255,59,92,0.15)' }}
                title="Malicious Trace"
              >
                <AlertTriangle className="w-3 h-3 group-hover:scale-110 transition-transform" style={{ color: '#ff3b5c' }} />
                <span className="text-[11px] font-medium" style={{ color: '#ff3b5c' }}>Threat</span>
              </button>
              <button
                onClick={() => simulateTrace('multi')}
                className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg transition-all group"
                style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.15)' }}
                title="Multi-Agent"
              >
                <Cpu className="w-3 h-3 group-hover:scale-110 transition-transform" style={{ color: '#8b5cf6' }} />
                <span className="text-[11px] font-medium" style={{ color: '#8b5cf6' }}>Multi</span>
              </button>
            </div>
          </div>

          {/* Search + filters */}
          <div className="p-2.5 space-y-2 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
            <p className="sidebar-section-label mb-1.5"><Search className="w-3 h-3" /> Filters</p>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search spans..."
                className="w-full pl-8 pr-7 py-1.5 rounded-lg text-xs font-mono focus:outline-none"
                style={{
                  background: 'var(--cs-bg-primary)',
                  border: '1px solid var(--cs-border)',
                  color: 'var(--cs-text-base)',
                }}
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--cs-text-faint)' }}>
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
            <div className="flex gap-1">
              {(['all', 'normal', 'malicious'] as FilterMode[]).map(mode => (
                <button
                  key={mode}
                  onClick={() => setFilterMode(mode)}
                  className="flex-1 py-1 text-[11px] font-medium rounded capitalize transition-all"
                  style={
                    filterMode === mode
                      ? { background: 'var(--cs-accent)', color: '#fff' }
                      : { background: 'var(--cs-bg-primary)', color: 'var(--cs-text-faint)', border: '1px solid var(--cs-border)' }
                  }
                >
                  {mode}
                </button>
              ))}
            </div>
            {/* Harness filter chips */}
            {activeHarnesses.length > 1 && (
              <div className="flex flex-wrap gap-1">
                <button
                  onClick={() => setHarnessFilter(null)}
                  className="px-2 py-0.5 text-[11px] rounded font-medium transition-all"
                  style={harnessFilter === null
                    ? { background: 'var(--cs-bg-elevated)', color: 'var(--cs-text-base)', border: '1px solid var(--cs-border-soft)' }
                    : { background: 'transparent', color: 'var(--cs-text-faint)', border: '1px solid transparent' }
                  }
                >
                  All
                </button>
                {activeHarnesses.map(h => (
                  <button
                    key={h}
                    onClick={() => setHarnessFilter(harnessFilter === h ? null : h)}
                    className="px-2 py-0.5 text-[11px] rounded font-medium transition-all flex items-center gap-1"
                    style={harnessFilter === h
                      ? { background: (HARNESS_COLORS[h] ?? '#64748b') + '22', color: HARNESS_COLORS[h] ?? '#64748b', border: `1px solid ${(HARNESS_COLORS[h] ?? '#64748b')}44` }
                      : { background: 'transparent', color: 'var(--cs-text-faint)', border: '1px solid transparent' }
                    }
                  >
                    <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: HARNESS_COLORS[h] ?? '#64748b' }} />
                    {h.replace('-', '\u00a0')}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Workflow list */}
          <div className="flex-1 overflow-y-auto p-3">
            <div className="flex items-center justify-between mb-2">
              <p className="text-[11px] font-bold uppercase tracking-wider font-mono" style={{ color: 'var(--cs-text-faint)' }}>Spans</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono">
                <span style={{ color: '#00d4aa' }}>{counts.ok}<span style={{ opacity: 0.5 }}>ok</span></span>
                {counts.low    > 0 && <span style={{ color: '#ffb224' }}>{counts.low}<span style={{ opacity: 0.5 }}>low</span></span>}
                {counts.medium > 0 && <span style={{ color: '#f97316' }}>{counts.medium}<span style={{ opacity: 0.5 }}>med</span></span>}
                {counts.high   > 0 && <span style={{ color: '#ff3b5c' }}>{counts.high}<span style={{ opacity: 0.5 }}>hi</span></span>}
              </div>
            </div>

            <AnimatePresence initial={false}>
              {visibleWorkflows.length === 0 ? (
                <div className="text-center py-10 px-4 border border-dashed border-slate-800 rounded-xl mt-2">
                  <Activity className="w-6 h-6 text-slate-700 mx-auto mb-2" />
                  <p className="text-[11px] text-slate-500 italic">
                    {workflows.length === 0 ? 'Awaiting traces…' : 'No matches'}
                  </p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  {visibleWorkflows.map(wf => {
                    const c = SEVERITY_COLORS[wf.severity];
                    return (
                      <motion.button
                        key={wf.id}
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        onClick={() => {
                          const n = nodes.find(n => n.id === wf.id);
                          if (n) setSelectedNode(n);
                        }}
                        className={`w-full text-left p-2.5 rounded-lg border transition-all ${c.row}`}
                      >
                        <div className="flex items-center gap-1.5 mb-1">
                          {wf.severity === 'none'
                            ? <CheckCircle className={`w-3 h-3 shrink-0 ${c.icon}`} />
                            : <AlertTriangle className={`w-3 h-3 shrink-0 ${c.icon}`} />
                          }
                          <span
                            className="w-2 h-2 rounded-full shrink-0 inline-block"
                            style={{ background: HARNESS_COLORS[wf.harness] ?? '#64748b' }}
                            title={HARNESS_NAMES[wf.harness]}
                          />
                          <span className={`text-[11px] font-semibold truncate ${c.text}`}>{wf.label}</span>
                          <span className="ml-auto text-[11px] font-mono text-slate-500 shrink-0">{wf.timestamp}</span>
                        </div>
                        <div className="flex items-center gap-1.5 pl-4">
                          <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${c.badge}`}>
                            {wf.severity === 'none' ? wf.protocol : SEVERITY_LABEL[wf.severity]}
                          </span>
                          <span className="text-[11px] text-slate-400 truncate">{wf.reason}</span>
                        </div>
                      </motion.button>
                    );
                  })}
                </div>
              )}
            </AnimatePresence>
          </div>
        </>}
        />

        {/* ── Main Area ── */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">

          {/* Welcome screen — shown on first run OR via Setup button */}
          {(showWelcome || (sessions.length === 0 && !hasEverHadData)) && (
            <WelcomeScreen onDemoLoaded={() => { setHasEverHadData(true); setShowWelcome(false); fetchSessions(); }} />
          )}

          {/* Sub-tab strip — filtered by active category */}
          <div className={`flex items-center gap-0.5 px-3 shrink-0 overflow-x-auto ${(showWelcome || (sessions.length === 0 && !hasEverHadData)) ? 'hidden' : ''}`} style={{
            borderBottom: '1px solid var(--cs-border)',
            background: 'var(--cs-bg-surface)',
          }}>
            {/* Category pill */}
            <span className="text-[10px] font-bold uppercase tracking-wider font-mono mr-1 shrink-0 px-2 py-1 rounded-md" style={{ color: 'var(--cs-text-faint)', background: 'var(--cs-bg-elevated)' }}>
              {CATEGORIES.find(c => c.id === activeCategory)?.label}
            </span>
            <div className="header-divider" />
            {CATEGORY_TABS[activeCategory].map(tab => (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`sub-tab-btn relative px-3 py-2 text-[11px] font-medium flex items-center gap-1.5 whitespace-nowrap ${
                  activeTab === tab.id ? 'tab-active' : ''
                }`}
                style={{
                  color: activeTab === tab.id ? '#00d4aa' : 'var(--cs-text-faint)',
                }}
              >
                {TAB_ICONS[tab.id]} {tab.label}
                {tab.id === 'alerts' && alertCount > 0 && (
                  <span className="min-w-[16px] h-4 px-1 text-[10px] font-bold rounded-full flex items-center justify-center leading-none"
                    style={{ background: '#ff3b5c', color: '#fff' }}>
                    {alertCount > 99 ? '99+' : alertCount}
                  </span>
                )}
              </button>
            ))}
          </div>



          {/* Timeline view */}
          {activeTab === 'timeline' && (
            <Timeline
              workflows={activeSession ? visibleWorkflows : workflows}
              onSelect={onTimelineSelect}
              selectedId={timelineSelected ?? undefined}
            />
          )}

          {/* Orchestration view */}
          {activeTab === 'orchestration' && <OrchestrationTab />}

          {/* Alerts view */}
          {activeTab === 'alerts' && <AlertsTab />}

          {/* Rules view */}
          {activeTab === 'rules' && <RulesTab />}

          {/* Costs + Webhook view */}
          {activeTab === 'costs' && <CostTab />}

          {/* Harnesses view */}
          {activeTab === 'harnesses' && (
            <HarnessTab
              onFilterHarness={h => { setHarnessFilter(h); if (h) setActiveTab('timeline'); }}
              activeFilter={harnessFilter}
            />
          )}

          {/* Settings view */}
          {activeTab === 'settings' && <SettingsTab />}

          {/* Heatmap view */}
          {activeTab === 'heatmap' && <HeatmapTab />}

          {/* Search view */}
          {activeTab === 'search' && <SearchTab />}

          {/* Processes view */}
          {activeTab === 'processes' && (
            <ProcessesTab
              onSelectSession={traceId => {
                setActiveSession(traceId);
                setActiveTab('timeline');
              }}
            />
          )}

          {/* Bookmarks view */}
          {activeTab === 'bookmarks' && (
            <BookmarksTab
              onSelectSession={traceId => {
                setActiveSession(traceId);
                setActiveTab('timeline');
              }}
            />
          )}
        </div>
      </div>

      {/* ── Footer ── */}
      <footer className="h-7 px-4 flex items-center justify-between z-10 shrink-0 gap-3 overflow-hidden" style={{
        borderTop: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}>
        <div className="flex items-center gap-2 shrink-0">
          <Terminal className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} />
          <span className="text-[11px] font-mono hidden sm:inline" style={{ color: 'var(--cs-text-faint)' }}>
            OTLP <span style={{ color: 'var(--cs-accent)', opacity: 0.7 }}>→</span> localhost:3000/v1/traces
          </span>
          <span className="text-[11px] font-mono px-1.5 py-0.5 rounded" style={{
            color: 'var(--cs-text-muted)',
            background: 'var(--cs-bg-elevated)',
          }}>{sessions.length} sessions</span>
        </div>

        {/* Live span ticker */}
        <div className="flex items-center gap-2 flex-1 overflow-hidden min-w-0">
          {tickerSpans.length > 0 && !tickerQuiet ? (
            <div className="flex items-center gap-1.5 overflow-hidden min-w-0">
              <span className="w-1.5 h-1.5 rounded-full shrink-0 status-live" style={{ background: '#00d4aa' }} />
              <div className="flex items-center gap-1.5 overflow-hidden min-w-0">
                {tickerSpans.slice(0, 3).map((sp, i) => (
                  <span key={sp.spanId} className={`flex items-center gap-1 text-[11px] font-mono shrink-0`} style={{ opacity: i > 0 ? 0.4 : 1 }}>
                    <span
                      className="w-1.5 h-1.5 rounded-full inline-block"
                      style={{ background: HARNESS_COLORS[sp.harness] ?? '#64748b' }}
                    />
                    <span style={{
                      color: sp.severity === 'high' ? '#ff3b5c' :
                        sp.severity === 'medium' ? '#f97316' :
                        sp.severity === 'low' ? '#ffb224' : 'var(--cs-text-muted)'
                    }}>
                      {sp.name.length > 24 ? sp.name.slice(0, 24) + '...' : sp.name}
                    </span>
                    {i < Math.min(tickerSpans.length, 3) - 1 && <span style={{ color: 'var(--cs-text-faint)' }}>·</span>}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <span className="text-[11px] font-mono italic" style={{ color: 'var(--cs-text-faint)' }}>idle</span>
          )}
        </div>

        <span className="text-[11px] font-mono shrink-0" style={{ color: 'var(--cs-text-faint)' }}>v1.0</span>
      </footer>

      {/* ── Session Compare Panel (s49) ── */}
      <AnimatePresence>
        {compareIds && (
          <ComparePanel
            aId={compareIds[0]}
            bId={compareIds[1]}
            onClose={() => setCompareIds(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
