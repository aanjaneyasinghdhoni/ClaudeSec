import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  ReactFlow, Controls, Background, useNodesState, useEdgesState,
  addEdge, Panel, MarkerType, type Node, type Edge,
} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import {
  Shield, AlertTriangle, Activity, Terminal, Trash2,
  Play, CheckCircle, Search, Download, X,
  Clock, Layers, Edit2, FileText, Cpu, Zap,
  Bell, BellOff,
} from 'lucide-react';
import { socket } from './socket';
import { RulesTab } from './RulesTab';
import { AlertsTab } from './AlertsTab';
import { OrchestrationTab } from './OrchestrationTab';
import { CostTab } from './CostTab';
import { motion, AnimatePresence } from 'motion/react';

// ---------------------------------------------------------------------------
// Dagre layout
// ---------------------------------------------------------------------------

const NODE_W = 180;
const NODE_H = 50;

function applyDagreLayout(nodes: Node[], edges: Edge[]): Node[] {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'TB', ranksep: 70, nodesep: 40 });
  nodes.forEach(n => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach(e => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map(n => {
    const pos = g.node(n.id);
    return { ...n, position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 } };
  });
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
type Tab        = 'graph' | 'timeline' | 'orchestration' | 'alerts' | 'rules' | 'costs';

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

interface Session {
  traceId: string;
  name: string;
  createdAt: string;
  spanCount: number;
  threatCount: number;
  maxSeverityRank: number;
  harnesses: string | null;
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

  const starts = timed.map(wf => toMs(wf.startNano));
  const ends   = timed.map(wf => toMs(wf.endNano));
  const minT   = Math.min(...starts);
  const maxT   = Math.max(...ends);
  const range  = maxT - minT || 1;

  const ROW_H   = 32;
  const LABEL_W = 152;
  const AXIS_H  = 28;
  const CHART_W = 920;
  const AVAIL_W = CHART_W - LABEL_W - 20;
  const SVG_H   = timed.length * ROW_H + AXIS_H + 8;

  const sevColor = (sev: Severity) =>
    sev === 'high' ? '#ef4444' : sev === 'medium' ? '#f97316' : sev === 'low' ? '#eab308' : '#22c55e';

  return (
    <div className="flex-1 overflow-auto p-4 bg-slate-950">
      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
        <Clock className="w-3 h-3" />
        Timeline — {timed.length} spans · {range}ms window
      </p>
      <svg viewBox={`0 0 ${CHART_W} ${SVG_H}`} className="w-full" style={{ minWidth: 420 }}>
        {/* Grid lines + axis labels */}
        {[0, 0.25, 0.5, 0.75, 1].map(frac => (
          <g key={frac}>
            <line
              x1={LABEL_W + frac * AVAIL_W} y1={0}
              x2={LABEL_W + frac * AVAIL_W} y2={SVG_H - AXIS_H}
              stroke="#1e293b" strokeWidth="1"
            />
            <text
              x={LABEL_W + frac * AVAIL_W} y={SVG_H - 8}
              fill="#475569" fontSize="9" fontFamily="monospace" textAnchor="middle"
            >
              {Math.round(frac * range)}ms
            </text>
          </g>
        ))}
        <line
          x1={LABEL_W} y1={SVG_H - AXIS_H}
          x2={CHART_W - 8} y2={SVG_H - AXIS_H}
          stroke="#334155" strokeWidth="1"
        />

        {timed.map((wf, i) => {
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
                <rect x={0} y={y} width={CHART_W} height={ROW_H - 2} fill="#1e293b" rx={2} />
              )}
              {/* Harness dot */}
              <circle cx={10} cy={y + ROW_H / 2 - 2} r={3.5}
                fill={HARNESS_COLORS[wf.harness] ?? '#64748b'} />
              {/* Label */}
              <text
                x={LABEL_W - 6} y={y + ROW_H / 2 + 3}
                fill={isSelected ? '#e2e8f0' : '#64748b'}
                fontSize="10" fontFamily="monospace" textAnchor="end"
              >
                {wf.label.length > 17 ? wf.label.slice(0, 17) + '…' : wf.label}
              </text>
              {/* Track background */}
              <rect x={LABEL_W} y={y + 7} width={AVAIL_W} height={ROW_H - 14}
                fill="#0f172a" rx={2} />
              {/* Bar */}
              <rect x={x} y={y + 7} width={w} height={ROW_H - 14}
                fill={col} fillOpacity={isSelected ? 1 : 0.75} rx={2} />
              {/* Duration inside bar */}
              {w > 44 && (
                <text x={x + w / 2} y={y + ROW_H / 2 + 3}
                  fill="#0f172a" fontSize="9" fontFamily="monospace"
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
  const [activeTab, setActiveTab]           = useState<Tab>('graph');
  const [selectedNode, setSelectedNode]     = useState<Node | null>(null);

  // ── Data state ────────────────────────────────────────────────────────────
  const [workflows, setWorkflows]           = useState<Workflow[]>([]);
  const [sessions, setSessions]             = useState<Session[]>([]);
  const [activeSession, setActiveSession]   = useState<string | null>(null);

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
    fetch('/api/sessions').then(r => r.json()).then(({ sessions: s }) => setSessions(s ?? []));

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

  // Initial load
  useEffect(() => {
    fetch('/api/graph')
      .then(r => r.json())
      .then(({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
        setNodes(applyDagreLayout(n, e));
        setEdges(e);
        syncWorkflows(n);
      });
    fetchSessions();
    fetchAlertCount();
  }, []);

  useEffect(() => { prevWorkflows.current = workflows; }, [workflows]);

  // Socket events
  useEffect(() => {
    const handleGraphUpdate = ({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
      setNodes(applyDagreLayout(n, e));
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

    socket.on('graph-update', handleGraphUpdate);
    socket.on('sessions-update', fetchSessions);
    socket.on('alerts-update', fetchAlertCount);
    return () => {
      socket.off('graph-update', handleGraphUpdate);
      socket.off('sessions-update', fetchSessions);
      socket.off('alerts-update', fetchAlertCount);
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
  };

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

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="w-screen h-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden">

      {/* ── Header ── */}
      <header className="h-14 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md flex items-center justify-between px-6 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-1.5 bg-blue-500/20 rounded-lg">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight leading-none">ClaudeSec</h1>
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest mt-0.5">
              Local AI Agent Observatory
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 rounded-full border border-slate-700">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[11px] font-medium text-slate-300">Live</span>
          </div>
          <button
            onClick={requestNotifications}
            className={`p-1.5 rounded-lg transition-colors border ${
              notifyEnabled
                ? 'bg-green-900/30 border-green-700/50 text-green-400 hover:bg-green-900/50'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
            }`}
            title={notifyEnabled ? 'Notifications enabled — click to disable' : 'Enable desktop notifications for HIGH alerts'}
          >
            {notifyEnabled ? <Bell className="w-4 h-4" /> : <BellOff className="w-4 h-4" />}
          </button>
          <button
            onClick={() => window.open('/api/export', '_blank')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-xs text-slate-300 transition-colors"
            title="Export as JSON"
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
          <button
            onClick={() => window.open('/api/export/csv', '_blank')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-xs text-slate-300 transition-colors"
            title="Export as CSV"
          >
            <FileText className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={resetGraph}
            className="p-1.5 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-red-400"
            title="Reset all data"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden min-h-0">

        {/* ── Left Sidebar ── */}
        <aside className="w-72 border-r border-slate-800 bg-slate-900/30 flex flex-col overflow-hidden shrink-0">

          {/* Sessions */}
          <div className="p-3 border-b border-slate-800 shrink-0">
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                <Layers className="w-3 h-3" /> Sessions
              </p>
              <span className="text-[9px] text-slate-600 font-mono">{sessions.length}</span>
            </div>
            <div className="space-y-1 max-h-28 overflow-y-auto">
              <button
                onClick={() => setActiveSession(null)}
                className={`w-full text-left px-2 py-1 rounded text-[10px] transition-colors ${
                  activeSession === null
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                }`}
              >
                All sessions · {workflows.length} spans
              </button>
              {sessions.map(s => {
                const sev = SEV_RANK[s.maxSeverityRank] ?? 'none';
                const sevCol = sev === 'high' ? '#ef4444' : sev === 'medium' ? '#f97316' : sev === 'low' ? '#eab308' : '#22c55e';
                const isActive = activeSession === s.traceId;
                const isEditing = editingSession === s.traceId;
                return (
                  <div
                    key={s.traceId}
                    className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] transition-colors group ${
                      isActive ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                    }`}
                  >
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sevCol }} />
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
                          className="flex-1 bg-slate-700 text-white text-[10px] rounded px-1 py-0.5 outline-none min-w-0"
                        />
                      </form>
                    ) : (
                      <>
                        <button
                          className="flex-1 text-left truncate min-w-0"
                          onClick={() => setActiveSession(isActive ? null : s.traceId)}
                        >
                          {s.name}
                        </button>
                        <span className="shrink-0 text-[9px] opacity-50">{s.spanCount}</span>
                        <button
                          onClick={e => { e.stopPropagation(); startRename(s); }}
                          className="shrink-0 opacity-0 group-hover:opacity-100 hover:text-white transition-opacity"
                          title="Rename"
                        >
                          <Edit2 className="w-2.5 h-2.5" />
                        </button>
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Simulate */}
          <div className="p-3 border-b border-slate-800 space-y-1.5 shrink-0">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1.5">Simulate</p>
            <button
              onClick={() => simulateTrace('normal')}
              className="w-full flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-all group"
            >
              <Play className="w-3.5 h-3.5 text-green-400 group-hover:scale-110 transition-transform" />
              <span className="text-xs font-medium">Normal Trace</span>
            </button>
            <button
              onClick={() => simulateTrace('high')}
              className="w-full flex items-center gap-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 rounded-lg border border-red-500/30 transition-all group"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 group-hover:scale-110 transition-transform" />
              <span className="text-xs font-medium text-red-200">Malicious Trace</span>
            </button>
            <button
              onClick={() => simulateTrace('multi')}
              className="w-full flex items-center gap-2 px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 rounded-lg border border-purple-500/30 transition-all group"
            >
              <Cpu className="w-3.5 h-3.5 text-purple-400 group-hover:scale-110 transition-transform" />
              <span className="text-xs font-medium text-purple-200">Multi-Agent</span>
            </button>
          </div>

          {/* Search + filters */}
          <div className="p-3 border-b border-slate-800 space-y-2 shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search or key=value…"
                className="w-full pl-8 pr-7 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-500"
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
            <div className="flex gap-1">
              {(['all', 'normal', 'malicious'] as FilterMode[]).map(mode => (
                <button
                  key={mode}
                  onClick={() => setFilterMode(mode)}
                  className={`flex-1 py-1 text-[10px] font-medium rounded capitalize transition-colors ${
                    filterMode === mode ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
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
                  className={`px-2 py-0.5 text-[9px] rounded-full font-medium transition-colors ${
                    harnessFilter === null ? 'bg-slate-500 text-white' : 'bg-slate-800 text-slate-500 hover:bg-slate-700'
                  }`}
                >
                  All
                </button>
                {activeHarnesses.map(h => (
                  <button
                    key={h}
                    onClick={() => setHarnessFilter(harnessFilter === h ? null : h)}
                    className={`px-2 py-0.5 text-[9px] rounded-full font-medium transition-colors flex items-center gap-1`}
                    style={harnessFilter === h
                      ? { background: HARNESS_COLORS[h] ?? '#64748b', color: '#fff' }
                      : { background: '#1e293b', color: '#64748b' }
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
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Workflows</p>
              <div className="flex items-center gap-1.5 text-[9px] font-mono">
                <span className="text-green-400">{counts.ok}ok</span>
                {counts.low    > 0 && <span className="text-yellow-400">{counts.low}low</span>}
                {counts.medium > 0 && <span className="text-orange-400">{counts.medium}med</span>}
                {counts.high   > 0 && <span className="text-red-400">{counts.high}high</span>}
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
                          <span className="ml-auto text-[9px] font-mono text-slate-500 shrink-0">{wf.timestamp}</span>
                        </div>
                        <div className="flex items-center gap-1.5 pl-4">
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${c.badge}`}>
                            {wf.severity === 'none' ? wf.protocol : SEVERITY_LABEL[wf.severity]}
                          </span>
                          <span className="text-[9px] text-slate-400 truncate">{wf.reason}</span>
                        </div>
                      </motion.button>
                    );
                  })}
                </div>
              )}
            </AnimatePresence>
          </div>
        </aside>

        {/* ── Main Area ── */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">

          {/* Tab switcher */}
          <div className="flex border-b border-slate-800 bg-slate-900/30 shrink-0">
            <button
              onClick={() => setActiveTab('graph')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                activeTab === 'graph' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <Activity className="w-3.5 h-3.5" /> Graph
            </button>
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                activeTab === 'timeline' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <Clock className="w-3.5 h-3.5" /> Timeline
            </button>
            <button
              onClick={() => setActiveTab('orchestration')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                activeTab === 'orchestration' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" /> Orchestration
            </button>
            <button
              onClick={() => setActiveTab('alerts')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors relative ${
                activeTab === 'alerts' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" /> Alerts
              {alertCount > 0 && (
                <span className="absolute -top-0.5 right-1 min-w-[16px] h-4 px-1 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center leading-none">
                  {alertCount > 99 ? '99+' : alertCount}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                activeTab === 'rules' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <Shield className="w-3.5 h-3.5" /> Rules
            </button>
            <button
              onClick={() => setActiveTab('costs')}
              className={`px-4 py-2 text-xs font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                activeTab === 'costs' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              <Zap className="w-3.5 h-3.5" /> Costs
            </button>
          </div>

          {/* Graph view */}
          {activeTab === 'graph' && (
            <main className="flex-1 relative bg-slate-950 min-h-0" style={{ height: '100%' }}>
              <ReactFlow
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                onConnect={onConnect} onNodeClick={onNodeClick}
                fitView colorMode="dark"
                defaultEdgeOptions={{ markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' } }}
              >
                <Background color="#1e293b" gap={20} size={1} />
                <Controls className="bg-slate-800 border-slate-700 fill-slate-300" />
                <Panel position="top-right" className="bg-slate-900/80 backdrop-blur-md border border-slate-800 p-3 rounded-xl shadow-2xl">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="w-3.5 h-3.5 text-blue-400" />
                    <h3 className="text-xs font-bold">Stats</h3>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Nodes</p>
                      <p className="text-lg font-mono font-bold">{nodes.length}</p>
                    </div>
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Edges</p>
                      <p className="text-lg font-mono font-bold">{edges.length}</p>
                    </div>
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Threats</p>
                      <p className={`text-lg font-mono font-bold ${counts.high > 0 ? 'text-red-400' : counts.medium > 0 ? 'text-orange-400' : 'text-slate-400'}`}>
                        {counts.low + counts.medium + counts.high}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Clean</p>
                      <p className="text-lg font-mono font-bold text-green-400">{counts.ok}</p>
                    </div>
                  </div>
                  {(metrics.tokenIn > 0 || metrics.tokenOut > 0) && (
                    <div className="border-t border-slate-700 mt-2 pt-2 space-y-1">
                      <p className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1">
                        <Zap className="w-2.5 h-2.5" /> Tokens
                      </p>
                      <div className="flex gap-3">
                        <div>
                          <p className="text-[8px] text-slate-600">In</p>
                          <p className="text-sm font-mono font-bold text-blue-400">{metrics.tokenIn.toLocaleString()}</p>
                        </div>
                        <div>
                          <p className="text-[8px] text-slate-600">Out</p>
                          <p className="text-sm font-mono font-bold text-purple-400">{metrics.tokenOut.toLocaleString()}</p>
                        </div>
                      </div>
                    </div>
                  )}
                  {metrics.toolCalls > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Tool Calls</p>
                      <p className="text-lg font-mono font-bold text-cyan-400">{metrics.toolCalls}</p>
                    </div>
                  )}
                  {metrics.avgMs > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] text-slate-500 uppercase font-bold">Avg Latency</p>
                      <p className="text-lg font-mono font-bold text-green-400">{metrics.avgMs}ms</p>
                    </div>
                  )}
                </Panel>
              </ReactFlow>

              {/* Detail panel */}
              <AnimatePresence>
                {selectedNode && (
                  <motion.div
                    initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
                    transition={{ type: 'spring', damping: 25, stiffness: 200 }}
                    className="absolute top-0 right-0 h-full bg-slate-900 border-l border-slate-800 z-20 shadow-[-20px_0_40px_rgba(0,0,0,0.5)] p-5 overflow-y-auto"
                    style={{ width: '300px' }}
                  >
                    <div className="flex items-center justify-between mb-5">
                      <h3 className="font-bold">Span Details</h3>
                      <button onClick={() => setSelectedNode(null)} className="p-1 hover:bg-slate-800 rounded-md text-slate-500">
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="space-y-3">
                      <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
                        <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Span Name</p>
                        <p className="text-sm font-mono font-bold text-blue-400">{String(selectedNode.data.label)}</p>
                      </div>

                      {/* Threat alert */}
                      {(selectedNode.data as any).severity && (selectedNode.data as any).severity !== 'none' && (
                        <div className={`p-3 rounded-xl border ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].row}`}>
                          <div className="flex items-center gap-2 mb-1">
                            <AlertTriangle className={`w-3.5 h-3.5 ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].icon}`} />
                            <p className={`text-[10px] font-bold uppercase ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].icon}`}>
                              {SEVERITY_LABEL[(selectedNode.data as any).severity as Severity]} Severity Alert
                            </p>
                          </div>
                          {(selectedNode.data as any).attributes?.['claudesec.threat.rule'] && (
                            <p className="text-[11px] text-slate-300 font-mono mt-1">
                              Rule: {(selectedNode.data as any).attributes['claudesec.threat.rule']}
                            </p>
                          )}
                        </div>
                      )}

                      {/* Harness */}
                      {(selectedNode.data as any).harness && (
                        <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
                          <p className="text-[10px] text-slate-500 uppercase font-bold mb-1.5">Agent Harness</p>
                          <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 rounded-full" style={{ background: HARNESS_COLORS[(selectedNode.data as any).harness] ?? '#64748b' }} />
                            <p className="text-sm font-mono text-slate-200">
                              {HARNESS_NAMES[(selectedNode.data as any).harness] ?? 'Unknown'}
                            </p>
                          </div>
                        </div>
                      )}

                      {/* Session */}
                      {(selectedNode.data as any).traceId && (
                        <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
                          <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Session</p>
                          <p className="text-xs font-mono text-slate-300 truncate">
                            {sessions.find(s => s.traceId === (selectedNode.data as any).traceId)?.name
                              ?? (selectedNode.data as any).traceId}
                          </p>
                        </div>
                      )}

                      {/* Duration */}
                      {(selectedNode.data as any).startNano && (selectedNode.data as any).startNano !== '0' && (
                        <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
                          <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Duration</p>
                          <p className="text-sm font-mono font-bold text-cyan-400">
                            {formatDuration((selectedNode.data as any).startNano, (selectedNode.data as any).endNano)}
                          </p>
                        </div>
                      )}

                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">Protocol & Reason</p>
                        <div className="flex flex-wrap gap-1.5">
                          <span className="px-2 py-1 bg-slate-800 rounded text-[10px] font-mono border border-slate-700">
                            {String((selectedNode.data as any).protocol ?? 'HTTPS')}
                          </span>
                          <span className="px-2 py-1 bg-slate-800 rounded text-[10px] font-mono border border-slate-700">
                            {String((selectedNode.data as any).reason ?? '—')}
                          </span>
                        </div>
                      </div>

                      <div>
                        <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">Attributes</p>
                        <div className="space-y-1.5">
                          {Object.entries((selectedNode.data as any).attributes || {})
                            .filter(([k]) => k !== 'claudesec.threat.rule')
                            .map(([key, value]) => (
                              <div key={key} className="p-2 bg-slate-950 rounded border border-slate-800">
                                <p className="text-[9px] text-slate-600 font-mono mb-0.5">{key}</p>
                                <p className="text-[11px] text-slate-300 font-mono break-all">{String(value)}</p>
                              </div>
                            ))}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </main>
          )}

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
        </div>
      </div>

      {/* ── Footer ── */}
      <footer className="h-7 border-t border-slate-800 bg-slate-900/80 px-4 flex items-center justify-between z-10 shrink-0">
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3 h-3 text-slate-600" />
          <span className="text-[9px] text-slate-600 font-mono">
            OTLP → http://localhost:3000/v1/traces · {sessions.length} sessions
          </span>
        </div>
        <span className="text-[9px] text-slate-600 font-mono">v0.4.0</span>
      </footer>
    </div>
  );
}
