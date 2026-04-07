import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Panel,
  MarkerType,
  type Node,
  type Edge,
} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import { io } from 'socket.io-client';
import {
  Shield, AlertTriangle, Activity, Terminal, Trash2,
  Play, CheckCircle, Search, Download, X, Filter,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

const socket = io();

// ---------------------------------------------------------------------------
// Dagre auto-layout
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
// Types
// ---------------------------------------------------------------------------

type Severity = 'none' | 'low' | 'medium' | 'high';
type FilterMode = 'all' | 'normal' | 'malicious';

interface Workflow {
  id: string;
  label: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  timestamp: string;
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
  'unknown':        '#64748b',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  none:   'OK',
  low:    'LOW',
  medium: 'MED',
  high:   'HIGH',
};

const SEVERITY_COLORS: Record<Severity, { row: string; badge: string; text: string; icon: string }> = {
  none:   { row: 'bg-green-500/10 border-green-500/30 hover:bg-green-500/20',   badge: 'bg-green-900/40 text-green-300',   text: 'text-green-200',  icon: 'text-green-400' },
  low:    { row: 'bg-yellow-500/10 border-yellow-500/30 hover:bg-yellow-500/20', badge: 'bg-yellow-900/40 text-yellow-300', text: 'text-yellow-200', icon: 'text-yellow-400' },
  medium: { row: 'bg-orange-500/10 border-orange-500/30 hover:bg-orange-500/20', badge: 'bg-orange-900/40 text-orange-300', text: 'text-orange-200', icon: 'text-orange-400' },
  high:   { row: 'bg-red-500/10 border-red-500/40 hover:bg-red-500/20',          badge: 'bg-red-900/40 text-red-300',       text: 'text-red-200',   icon: 'text-red-400' },
};

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

const initialNodes: Node[] = [
  { id: 'agent', data: { label: 'AI Agent' }, position: { x: 0, y: 0 }, type: 'input' },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNode, setSelectedNode]  = useState<Node | null>(null);
  const [workflows, setWorkflows]         = useState<Workflow[]>([]);
  const [search, setSearch]              = useState('');
  const [filterMode, setFilterMode]      = useState<FilterMode>('all');
  const seenIds = useRef<Set<string>>(new Set());
  const prevWorkflows = useRef<Workflow[]>([]);

  const onConnect = useCallback(
    (params: any) => setEdges(eds => addEdge(params, eds)),
    [setEdges],
  );

  // Load initial graph from server (handles persistence across restarts)
  useEffect(() => {
    fetch('/api/graph')
      .then(r => r.json())
      .then(({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
        const laid = applyDagreLayout(n, e);
        setNodes(laid);
        setEdges(e);
        syncWorkflows(n);
      });
  }, []);

  function syncWorkflows(rawNodes: Node[]) {
    const spans = rawNodes.filter(n => !(n.data as any).isRoot && n.id !== 'agent');
    setWorkflows(spans.map(n => ({
      id:       n.id,
      label:    String(n.data.label),
      protocol: String((n.data as any).protocol ?? 'HTTPS'),
      reason:   String((n.data as any).reason   ?? '—'),
      severity: ((n.data as any).severity ?? 'none') as Severity,
      harness:  String((n.data as any).harness ?? 'unknown'),
      timestamp: seenIds.current.has(n.id)
        ? (prevWorkflows.current.find(w => w.id === n.id)?.timestamp ?? new Date().toLocaleTimeString())
        : new Date().toLocaleTimeString(),
    })));
    spans.forEach(n => seenIds.current.add(n.id));
  }

  useEffect(() => {
    prevWorkflows.current = workflows;
  }, [workflows]);

  useEffect(() => {
    socket.on('graph-update', ({ nodes: n, edges: e }: { nodes: Node[]; edges: Edge[] }) => {
      const laid = applyDagreLayout(n, e);
      setNodes(laid);
      setEdges(e);
      syncWorkflows(n);
    });
    return () => { socket.off('graph-update'); };
  }, [setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => setSelectedNode(node);

  const resetGraph = async () => {
    await fetch('/api/reset', { method: 'POST' });
    setSelectedNode(null);
    setWorkflows([]);
    seenIds.current.clear();
    setSearch('');
    setFilterMode('all');
  };

  const exportSession = () => {
    window.open('/api/export', '_blank');
  };

  const simulateTrace = async (severity: 'none' | 'high' = 'none') => {
    const spanId  = Math.random().toString(36).substring(7);
    const now     = Date.now();
    const payload = severity === 'high' ? 'cat /etc/passwd' : 'GET /api/v1/data';
    const reason  = severity === 'high' ? 'Attempting unauthorized access' : 'Requesting public API';

    await fetch('/v1/traces', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resourceSpans: [{
          resource: {},
          scopeSpans: [{
            scope: {},
            spans: [{
              traceId: 'sim-trace',
              spanId,
              name:    severity === 'high' ? 'Malicious Command' : 'Fetch Data',
              kind:    1,
              startTimeUnixNano: String(now * 1_000_000),
              endTimeUnixNano:   String((now + 120) * 1_000_000),
              attributes: [
                { key: 'protocol', value: { stringValue: 'HTTPS' } },
                { key: 'reason',   value: { stringValue: reason } },
                { key: 'payload',  value: { stringValue: payload } },
              ],
              status: { code: 0 },
            }],
          }],
        }],
      }),
    });
  };

  // Filtered + searched workflow list
  const visibleWorkflows = useMemo(() => {
    return workflows.filter(wf => {
      const matchFilter =
        filterMode === 'all' ||
        (filterMode === 'normal'    && wf.severity === 'none') ||
        (filterMode === 'malicious' && wf.severity !== 'none');
      const term = search.toLowerCase();
      const matchSearch =
        !term ||
        wf.label.toLowerCase().includes(term) ||
        wf.reason.toLowerCase().includes(term) ||
        wf.protocol.toLowerCase().includes(term);
      return matchFilter && matchSearch;
    });
  }, [workflows, filterMode, search]);

  const counts = useMemo(() => ({
    ok:     workflows.filter(w => w.severity === 'none').length,
    low:    workflows.filter(w => w.severity === 'low').length,
    medium: workflows.filter(w => w.severity === 'medium').length,
    high:   workflows.filter(w => w.severity === 'high').length,
  }), [workflows]);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="w-screen h-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden">

      {/* Header */}
      <header className="h-14 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md flex items-center justify-between px-6 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-1.5 bg-blue-500/20 rounded-lg">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight leading-none">AI Agent Observability</h1>
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest mt-0.5">Real-time Communication Visualizer</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 rounded-full border border-slate-700">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[11px] font-medium text-slate-300">Live</span>
          </div>
          <button
            onClick={exportSession}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-xs text-slate-300 transition-colors"
            title="Export session"
          >
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
          <button
            onClick={resetGraph}
            className="p-1.5 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-red-400"
            title="Reset"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden min-h-0">

        {/* Left Sidebar */}
        <aside className="w-72 border-r border-slate-800 bg-slate-900/30 flex flex-col overflow-hidden shrink-0">

          {/* Simulation buttons */}
          <div className="p-3 border-b border-slate-800 space-y-2 shrink-0">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Simulate</p>
            <button
              onClick={() => simulateTrace('none')}
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
          </div>

          {/* Search + filter */}
          <div className="p-3 border-b border-slate-800 space-y-2 shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search workflows…"
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
                    filterMode === mode
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
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
                          <span style={{background: HARNESS_COLORS[wf.harness] ?? '#64748b'}} className="w-2 h-2 rounded-full shrink-0 inline-block" />
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

        {/* Main Canvas */}
        <main className="flex-1 relative bg-slate-950 min-h-0" style={{ height: '100%' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            fitView
            colorMode="dark"
            defaultEdgeOptions={{
              markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' },
            }}
          >
            <Background color="#1e293b" gap={20} size={1} />
            <Controls className="bg-slate-800 border-slate-700 fill-slate-300" />
            <Panel position="top-right" className="bg-slate-900/80 backdrop-blur-md border border-slate-800 p-3 rounded-xl shadow-2xl">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-3.5 h-3.5 text-blue-400" />
                <h3 className="text-xs font-bold">Stats</h3>
              </div>
              <div className="grid grid-cols-2 gap-3">
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
            </Panel>
          </ReactFlow>

          {/* Node detail panel */}
          <AnimatePresence>
            {selectedNode && (
              <motion.div
                initial={{ x: '100%' }}
                animate={{ x: 0 }}
                exit={{ x: '100%' }}
                transition={{ type: 'spring', damping: 25, stiffness: 200 }}
                className="absolute top-0 right-0 h-full w-76 bg-slate-900 border-l border-slate-800 z-20 shadow-[-20px_0_40px_rgba(0,0,0,0.5)] p-5 overflow-y-auto"
                style={{ width: '300px' }}
              >
                <div className="flex items-center justify-between mb-5">
                  <h3 className="font-bold">Span Details</h3>
                  <button onClick={() => setSelectedNode(null)} className="p-1 hover:bg-slate-800 rounded-md text-slate-500">
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="p-3 bg-slate-800/50 rounded-xl border border-slate-700">
                    <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Span Name</p>
                    <p className="text-sm font-mono font-bold text-blue-400">{String(selectedNode.data.label)}</p>
                  </div>

                  {(selectedNode.data as any).severity && (selectedNode.data as any).severity !== 'none' && (
                    <div className={`p-3 rounded-xl border ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].row}`}>
                      <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className={`w-3.5 h-3.5 ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].icon}`} />
                        <p className={`text-[10px] font-bold uppercase ${SEVERITY_COLORS[(selectedNode.data as any).severity as Severity].icon}`}>
                          {SEVERITY_LABEL[(selectedNode.data as any).severity as Severity]} Severity Alert
                        </p>
                      </div>
                      <p className="text-[11px] text-slate-300 leading-relaxed">
                        This span matched a known malicious pattern and has been flagged by the security gateway.
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
                      {Object.entries((selectedNode.data as any).attributes || {}).map(([key, value]) => (
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
      </div>

      {/* Footer */}
      <footer className="h-7 border-t border-slate-800 bg-slate-900/80 px-4 flex items-center justify-between z-10 shrink-0">
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3 h-3 text-slate-600" />
          <span className="text-[9px] text-slate-600 font-mono">OTLP → http://localhost:3000/v1/traces</span>
        </div>
        <span className="text-[9px] text-slate-600 font-mono">v0.2.0</span>
      </footer>
    </div>
  );
}
