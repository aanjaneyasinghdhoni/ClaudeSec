import React, { useEffect, useState } from 'react';
import { Cpu, Wrench } from 'lucide-react';
import { socket } from './socket';

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

interface OrchData {
  agents: AgentStat[];
  edges: OrchEdge[];
  tools: ToolEntry[];
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

const SUSPICIOUS_TOOLS = new Set(['bash', 'eval', 'exec', 'curl', 'wget', 'rm']);

const SVG_W = 700;
const SVG_H = 260;
const R     = 36; // node radius

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

export function OrchestrationTab() {
  const [data, setData] = useState<OrchData>({ agents: [], edges: [], tools: [] });

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

  const { agents, edges, tools } = data;
  const positions = agentPositions(agents.length);

  // Index for quick position lookup
  const posMap = new Map<string, { x: number; y: number }>();
  agents.forEach((a, i) => posMap.set(a.harness, positions[i]));

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-slate-950 overflow-auto">

      {/* Agent DAG */}
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
          <svg
            viewBox={`0 0 ${SVG_W} ${SVG_H}`}
            className="w-full"
            style={{ maxHeight: 280 }}
          >
            <defs>
              {agents.map(a => (
                <radialGradient key={a.harness} id={`grad-${a.harness}`} cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={HARNESS_COLORS[a.harness] ?? '#64748b'} stopOpacity={0.25} />
                  <stop offset="100%" stopColor={HARNESS_COLORS[a.harness] ?? '#64748b'} stopOpacity={0.05} />
                </radialGradient>
              ))}
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
              const mx = (sx + ex) / 2;
              const my = (sy + ey) / 2;
              return (
                <g key={`${edge.from}-${edge.to}`}>
                  <line
                    x1={sx} y1={sy} x2={ex} y2={ey}
                    stroke="#475569" strokeWidth={1.5}
                    strokeDasharray="5 3"
                    markerEnd="url(#arrow)"
                  />
                  <text x={mx} y={my - 5} fill="#64748b" fontSize={9} textAnchor="middle" fontFamily="monospace">
                    {edge.count} trace{edge.count !== 1 ? 's' : ''}
                  </text>
                </g>
              );
            })}

            {/* Arrow marker */}
            <defs>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="#475569" />
              </marker>
            </defs>

            {/* Agent nodes */}
            {agents.map((agent, i) => {
              const pos   = positions[i];
              const color = HARNESS_COLORS[agent.harness] ?? '#64748b';
              const name  = HARNESS_NAMES[agent.harness] ?? agent.harness;
              const short = name.length > 10 ? name.slice(0, 9) + '…' : name;
              const isThreat = agent.threatCount > 0;
              return (
                <g key={agent.harness} transform={`translate(${pos.x},${pos.y})`}>
                  {/* Pulsing threat ring */}
                  {isThreat && (
                    <circle r={R + 8} fill="none" stroke="#ef4444" strokeWidth={1.5} strokeOpacity={0.5} strokeDasharray="4 3">
                      <animate attributeName="r" values={`${R + 6};${R + 12};${R + 6}`} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="stroke-opacity" values="0.6;0.1;0.6" dur="2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  {/* Node circle */}
                  <circle r={R} fill={`url(#grad-${agent.harness})`} stroke={color} strokeWidth={2} />
                  {/* Agent name */}
                  <text y={-8} fill="#e2e8f0" fontSize={10} textAnchor="middle" fontFamily="sans-serif" fontWeight="600">
                    {short}
                  </text>
                  {/* Span count */}
                  <text y={6} fill="#94a3b8" fontSize={9} textAnchor="middle" fontFamily="monospace">
                    {agent.spanCount} span{agent.spanCount !== 1 ? 's' : ''}
                  </text>
                  {/* Threat count */}
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

      {/* Tool Inventory */}
      <div className="flex-1 p-4">
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 mb-3">
          <Wrench className="w-3 h-3" /> Tool Inventory
        </p>

        {tools.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 gap-2 text-slate-700">
            <Wrench className="w-7 h-7" />
            <p className="text-sm text-slate-500">No tool calls recorded</p>
            <p className="text-xs text-slate-600">Tools appear when spans include <code className="font-mono bg-slate-800 px-1 rounded">gen_ai.tool.name</code>.</p>
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
                  const isSuspicious = SUSPICIOUS_TOOLS.has(tool.toolName.toLowerCase());
                  const harnessColor = HARNESS_COLORS[tool.harness] ?? '#64748b';
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
                      <td className="px-4 py-2.5 text-right font-mono text-slate-300">
                        {tool.count}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono">
                        {tool.threatCount > 0 ? (
                          <span className="text-red-400 font-bold">{tool.threatCount}</span>
                        ) : (
                          <span className="text-slate-700">0</span>
                        )}
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
