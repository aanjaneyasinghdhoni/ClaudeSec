import React, { useEffect, useState } from 'react';
import { Cpu, Wrench, GitBranch, ChevronDown, ChevronRight, LayoutGrid, List } from 'lucide-react';
import { socket } from './socket';

// ── Interfaces ────────────────────────────────────────────────────────────────

interface AgentStat {
  harness: string;
  spanCount: number;
  threatCount: number;
  tools: string[];
}

interface OrchEdge {
  from: string;
  to: string;
  count: number;
}

interface ToolEntry {
  toolName: string;
  harness: string;
  count: number;
  threatCount: number;
}

interface SpawnTreeNode {
  traceId: string;
  harness: string;
  sessionName: string;
  spanCount: number;
  threatCount: number;
  children: SpawnTreeNode[];
}

interface OrchData {
  agents: AgentStat[];
  edges: OrchEdge[];
  tools: ToolEntry[];
  spawnTree: SpawnTreeNode[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

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
  'github-copilot': 'Copilot',
  'openhands':      'OpenHands',
  'cursor':         'Cursor',
  'aider':          'Aider',
  'cline':          'Cline',
  'goose':          'Goose',
  'continue':       'Continue',
  'windsurf':       'Windsurf',
  'unknown':        'Unknown',
};

const SUSPICIOUS_TOOLS = new Set(['bash', 'eval', 'exec', 'curl', 'wget', 'rm', 'sh', 'python', 'node']);

const SVG_W = 700;
const SVG_H = 260;
const R     = 36;

// ── Helper functions ──────────────────────────────────────────────────────────

function agentPositions(count: number): { x: number; y: number }[] {
  if (count === 0) return [];
  if (count === 1) return [{ x: SVG_W / 2, y: SVG_H / 2 }];
  const cx = SVG_W / 2;
  const cy = SVG_H / 2;
  const radius = Math.min(SVG_W, SVG_H) * 0.33;
  return Array.from({ length: count }, (_, i) => {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2;
    return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
  });
}

function harnessShort(id: string) {
  const name = HARNESS_NAMES[id] ?? id;
  return name.length > 10 ? name.slice(0, 9) + '…' : name;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SpawnTreeItem({ node, depth = 0 }: { node: SpawnTreeNode; depth?: number; key?: React.Key }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const color = HARNESS_COLORS[node.harness] ?? '#64748b';
  const hasChildren = node.children.length > 0;

  return (
    <div>
      <div
        className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-slate-800/50 cursor-pointer transition-colors select-none"
        style={{ paddingLeft: `${8 + depth * 20}px` }}
        onClick={() => hasChildren && setExpanded(e => !e)}
      >
        {/* Expand/collapse icon */}
        <span className="w-4 h-4 shrink-0 text-slate-600">
          {hasChildren
            ? (expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />)
            : <span className="w-3 h-3 block" />}
        </span>

        {/* Agent color dot */}
        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: color }} />

        {/* Agent name */}
        <span className="text-xs font-medium text-slate-200 shrink-0">
          {HARNESS_NAMES[node.harness] ?? node.harness}
        </span>

        {/* Session name */}
        <span className="text-[10px] text-slate-500 font-mono truncate max-w-[160px]" title={node.sessionName}>
          {node.sessionName}
        </span>

        {/* Stats pills */}
        <div className="ml-auto flex items-center gap-1.5 shrink-0">
          <span className="text-[10px] text-slate-500 font-mono">{node.spanCount} spans</span>
          {node.threatCount > 0 && (
            <span className="text-[10px] text-red-400 font-mono font-bold bg-red-950/40 px-1.5 py-0.5 rounded">
              {node.threatCount} threats
            </span>
          )}
          {node.children.length > 0 && (
            <span className="text-[10px] text-blue-400 font-mono bg-blue-950/40 px-1.5 py-0.5 rounded">
              {node.children.length} sub-agent{node.children.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div className="border-l border-slate-800 ml-[20px]">
          {node.children.map(child => (
            <SpawnTreeItem key={child.traceId} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function ToolHeatmap({ tools }: { tools: ToolEntry[] }) {
  // Build unique tool names and harness ids
  const toolNames = [...new Set(tools.map(t => t.toolName))].slice(0, 20);
  const harnesses = [...new Set(tools.map(t => t.harness))];

  // Build lookup: toolName → harness → {count, threatCount}
  const cell = new Map<string, { count: number; threatCount: number }>();
  for (const t of tools) cell.set(`${t.toolName}::${t.harness}`, t);

  // Max count for color intensity normalization
  const maxCount = Math.max(1, ...tools.map(t => t.count));

  return (
    <div className="overflow-x-auto">
      <table className="text-[10px] border-collapse">
        <thead>
          <tr>
            <th className="px-3 py-2 text-left text-slate-500 font-medium sticky left-0 bg-slate-900 z-10 min-w-[120px]">
              Tool ╲ Agent
            </th>
            {harnesses.map(h => (
              <th key={h} className="px-2 py-2 text-center" style={{ minWidth: 64 }}>
                <div className="flex flex-col items-center gap-0.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: HARNESS_COLORS[h] ?? '#64748b' }} />
                  <span className="text-slate-400 font-mono">{harnessShort(h)}</span>
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {toolNames.map(toolName => {
            const isSuspicious = SUSPICIOUS_TOOLS.has(toolName.toLowerCase());
            return (
              <tr key={toolName} className="border-t border-slate-800/50">
                <td className="px-3 py-1.5 sticky left-0 bg-slate-900 z-10">
                  <div className="flex items-center gap-1.5">
                    {isSuspicious && <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" />}
                    <code className={`font-mono ${isSuspicious ? 'text-orange-300' : 'text-slate-300'}`}>
                      {toolName}
                    </code>
                  </div>
                </td>
                {harnesses.map(h => {
                  const data = cell.get(`${toolName}::${h}`);
                  const count = data?.count ?? 0;
                  const intensity = count / maxCount;
                  const base = HARNESS_COLORS[h] ?? '#64748b';
                  const hasThreat = (data?.threatCount ?? 0) > 0;
                  return (
                    <td key={h} className="text-center py-1.5 px-2">
                      {count > 0 ? (
                        <div
                          className="inline-flex items-center justify-center rounded text-[10px] font-mono font-medium min-w-[28px] px-1.5 py-0.5 transition-all"
                          style={{
                            background: `${base}${Math.round(intensity * 220).toString(16).padStart(2, '0')}`,
                            color: intensity > 0.4 ? '#fff' : '#94a3b8',
                            border: hasThreat ? '1px solid #ef4444' : '1px solid transparent',
                          }}
                          title={`${count} call${count !== 1 ? 's' : ''}${hasThreat ? ` · ${data!.threatCount} threat${data!.threatCount !== 1 ? 's' : ''}` : ''}`}
                        >
                          {count}
                        </div>
                      ) : (
                        <span className="text-slate-800">—</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function OrchestrationTab() {
  const [data, setData] = useState<OrchData>({ agents: [], edges: [], tools: [], spawnTree: [] });
  const [toolView, setToolView] = useState<'table' | 'heatmap'>('table');

  const fetchData = () =>
    fetch('/api/orchestration')
      .then(r => r.json())
      .then((d: OrchData) => setData(d))
      .catch(() => {});

  useEffect(() => {
    fetchData();
    socket.on('graph-update', fetchData);
    return () => { socket.off('graph-update', fetchData); };
  }, []);

  const { agents, edges, tools, spawnTree } = data;
  const positions = agentPositions(agents.length);

  const posMap = new Map<string, { x: number; y: number }>();
  agents.forEach((a, i) => posMap.set(a.harness, positions[i]));

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-slate-950 overflow-auto">

      {/* ── Agent DAG ──────────────────────────────────────────────────────── */}
      <div className="shrink-0 border-b border-slate-800 bg-slate-900/30 p-4">
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 mb-3">
          <Cpu className="w-3 h-3" /> Agent Orchestration Graph
        </p>

        {agents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-44 gap-2 text-slate-700">
            <Cpu className="w-8 h-8" />
            <p className="text-sm text-slate-500">No agent data yet</p>
            <p className="text-xs text-slate-600">Send traces to see agent interactions.</p>
          </div>
        ) : (
          <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} className="w-full" style={{ maxHeight: 280 }}>
            <defs>
              {agents.map(a => (
                <radialGradient key={a.harness} id={`grad-${a.harness}`} cx="50%" cy="50%" r="50%">
                  <stop offset="0%"   stopColor={HARNESS_COLORS[a.harness] ?? '#64748b'} stopOpacity={0.25} />
                  <stop offset="100%" stopColor={HARNESS_COLORS[a.harness] ?? '#64748b'} stopOpacity={0.05} />
                </radialGradient>
              ))}
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="#475569" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map(edge => {
              const src = posMap.get(edge.from);
              const tgt = posMap.get(edge.to);
              if (!src || !tgt) return null;
              const dx = tgt.x - src.x;
              const dy = tgt.y - src.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const sx = src.x + (dx / dist) * R;
              const sy = src.y + (dy / dist) * R;
              const ex = tgt.x - (dx / dist) * R;
              const ey = tgt.y - (dy / dist) * R;
              return (
                <g key={`${edge.from}-${edge.to}`}>
                  <line
                    x1={sx} y1={sy} x2={ex} y2={ey}
                    stroke="#475569" strokeWidth={1.5}
                    strokeDasharray="5 3"
                    markerEnd="url(#arrow)"
                  />
                  <text
                    x={(sx + ex) / 2} y={(sy + ey) / 2 - 5}
                    fill="#64748b" fontSize={9} textAnchor="middle" fontFamily="monospace"
                  >
                    {edge.count} trace{edge.count !== 1 ? 's' : ''}
                  </text>
                </g>
              );
            })}

            {/* Agent nodes */}
            {agents.map((agent, i) => {
              const pos      = positions[i];
              const color    = HARNESS_COLORS[agent.harness] ?? '#64748b';
              const isThreat = agent.threatCount > 0;
              return (
                <g key={agent.harness} transform={`translate(${pos.x},${pos.y})`}>
                  {isThreat && (
                    <circle r={R + 8} fill="none" stroke="#ef4444" strokeWidth={1.5} strokeOpacity={0.5} strokeDasharray="4 3">
                      <animate attributeName="r"              values={`${R+6};${R+12};${R+6}`} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="stroke-opacity" values="0.6;0.1;0.6"              dur="2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <circle r={R} fill={`url(#grad-${agent.harness})`} stroke={color} strokeWidth={2} />
                  <text y={-8} fill="#e2e8f0" fontSize={10} textAnchor="middle" fontFamily="sans-serif" fontWeight="600">
                    {harnessShort(agent.harness)}
                  </text>
                  <text y={6} fill="#94a3b8" fontSize={9} textAnchor="middle" fontFamily="monospace">
                    {agent.spanCount} span{agent.spanCount !== 1 ? 's' : ''}
                  </text>
                  {isThreat && (
                    <text y={19} fill="#ef4444" fontSize={9} textAnchor="middle" fontFamily="monospace" fontWeight="bold">
                      {agent.threatCount} threat{agent.threatCount !== 1 ? 's' : ''}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* ── Sub-Agent Spawn Tree ───────────────────────────────────────────── */}
      <div className="shrink-0 border-b border-slate-800 p-4">
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 mb-3">
          <GitBranch className="w-3 h-3" /> Sub-Agent Spawn Tree
          <span className="ml-auto text-[9px] text-slate-600 normal-case font-normal tracking-normal">
            cross-trace parent-child relationships
          </span>
        </p>

        {spawnTree.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 gap-2">
            <GitBranch className="w-7 h-7 text-slate-800" />
            <p className="text-sm text-slate-500">No sub-agent spawns detected</p>
            <p className="text-xs text-slate-600">
              Detected when spans reference parent spans from a different trace (cross-trace spawning).
            </p>
          </div>
        ) : (
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
            {spawnTree.map(root => (
              <SpawnTreeItem key={root.traceId} node={root} depth={0} />
            ))}
          </div>
        )}
      </div>

      {/* ── Tool Inventory ────────────────────────────────────────────────── */}
      <div className="flex-1 p-4">
        <div className="flex items-center gap-2 mb-3">
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
            <Wrench className="w-3 h-3" /> Tool Inventory
          </p>
          {/* View toggle */}
          {tools.length > 0 && (
            <div className="ml-auto flex items-center bg-slate-800 rounded-lg p-0.5">
              <button
                className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] transition-colors ${toolView === 'table' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                onClick={() => setToolView('table')}
                title="Table view"
              >
                <List className="w-3 h-3" /> Table
              </button>
              <button
                className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] transition-colors ${toolView === 'heatmap' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                onClick={() => setToolView('heatmap')}
                title="Heatmap view"
              >
                <LayoutGrid className="w-3 h-3" /> Heatmap
              </button>
            </div>
          )}
        </div>

        {tools.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 gap-2">
            <Wrench className="w-7 h-7 text-slate-800" />
            <p className="text-sm text-slate-500">No tool calls recorded</p>
            <p className="text-xs text-slate-600">
              Tools appear when spans include{' '}
              <code className="font-mono bg-slate-800 px-1 rounded">gen_ai.tool.name</code>.
            </p>
          </div>
        ) : toolView === 'heatmap' ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden p-2">
            <ToolHeatmap tools={tools} />
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                  <th className="px-4 py-2.5 text-left">Tool</th>
                  <th className="px-4 py-2.5 text-left">Agent</th>
                  <th className="px-4 py-2.5 text-right">Calls</th>
                  <th className="px-4 py-2.5 text-right">Threats</th>
                </tr>
              </thead>
              <tbody>
                {tools.map(tool => {
                  const isSuspicious  = SUSPICIOUS_TOOLS.has(tool.toolName.toLowerCase());
                  const harnessColor  = HARNESS_COLORS[tool.harness] ?? '#64748b';
                  return (
                    <tr
                      key={`${tool.toolName}::${tool.harness}`}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          {isSuspicious && (
                            <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" title="Suspicious tool" />
                          )}
                          <code className={`font-mono text-[11px] ${isSuspicious ? 'text-orange-300' : 'text-slate-200'}`}>
                            {tool.toolName}
                          </code>
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: harnessColor }} />
                          <span className="text-slate-400 text-[10px]">
                            {HARNESS_NAMES[tool.harness] ?? tool.harness}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-300">{tool.count}</td>
                      <td className="px-4 py-2.5 text-right font-mono">
                        {tool.threatCount > 0
                          ? <span className="text-red-400 font-bold">{tool.threatCount}</span>
                          : <span className="text-slate-700">0</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
