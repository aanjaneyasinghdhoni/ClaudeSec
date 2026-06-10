import React, { useEffect, useMemo, useState } from 'react';
import { Cpu, Wrench, GitBranch, ChevronDown, ChevronRight, LayoutGrid, List, Copy, Check } from 'lucide-react';
import { socket } from './socket';
import { CommandAuditTab } from './CommandAuditTab';
import { FileAccessPanel } from './FileAccessPanel';
import { ExperimentalBadge } from './ExperimentalBadge';
import { useListControls, FilterBar, ListFooter, type FacetConfig } from './FilterControls';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import { SpanSearchDrawer, type SpanSearchTarget } from './SpanSearchDrawer';

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
  // true → parentage was INFERRED by the server's fallback heuristic (no real
  // cross-trace spawn edges existed). Rendered visually distinct so a viewer
  // can't mistake a guessed grouping for an observed spawn edge.
  synthetic?: boolean;
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
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

const HARNESS_NAMES: Record<string, string> = {
  'claude-code': 'Claude Code',
  'copilot':     'GitHub Copilot CLI',
  'codex':       'Codex',
  'unknown':     'Unknown',
};

const SUSPICIOUS_TOOLS = new Set(['bash', 'eval', 'exec', 'curl', 'wget', 'rm', 'sh', 'python', 'node']);

const toolSearchText = (t: ToolEntry) => t.toolName;

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
  return name.length > 14 ? name.slice(0, 13) + '…' : name;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SpawnTreeItem({ node, depth = 0 }: { node: SpawnTreeNode; depth?: number; key?: React.Key }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const [copied, setCopied] = useState(false);
  const color = HARNESS_COLORS[node.harness] ?? '#64748b';
  const hasChildren = node.children.length > 0;
  const synthetic = node.synthetic === true;

  // No `onSelectSession` prop reaches OrchestrationTab today, so "view session"
  // is a copy-traceId affordance rather than a navigation. See the App-level
  // wiring note at the bottom of this file.
  const copyTrace = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(node.traceId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }).catch(() => {});
  };

  return (
    <div>
      <div
        className={`flex items-center gap-2 py-1.5 px-2 rounded hover:bg-slate-800/50 cursor-pointer transition-colors select-none${synthetic ? ' opacity-60' : ''}`}
        style={{
          paddingLeft: `${8 + depth * 20}px`,
          // Inferred (synthetic) nodes get a dashed left accent so they read as
          // "not an observed edge" at a glance.
          ...(synthetic ? { borderLeft: '2px dashed #475569' } : {}),
        }}
        onClick={() => hasChildren && setExpanded(e => !e)}
        title={synthetic ? 'Inferred grouping — no observed cross-trace spawn edge' : undefined}
      >
        {/* Expand/collapse icon */}
        <span className="w-4 h-4 shrink-0 text-slate-600">
          {hasChildren
            ? (expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />)
            : <span className="w-3 h-3 block" />}
        </span>

        {/* Agent color dot — hollow ring when inferred, solid when observed */}
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={synthetic
            ? { border: `1.5px dashed ${color}`, background: 'transparent' }
            : { background: color }}
        />

        {/* Agent name */}
        <span className={`text-xs font-medium shrink-0${synthetic ? ' text-slate-400 italic' : ' text-slate-200'}`}>
          {HARNESS_NAMES[node.harness] ?? node.harness}
        </span>

        {/* Session name */}
        <span className="text-xs text-slate-500 font-mono truncate max-w-[160px]" title={node.sessionName}>
          {node.sessionName}
        </span>

        {/* Inferred marker */}
        {synthetic && (
          <span
            className="text-[10px] uppercase tracking-wide font-mono text-slate-500 bg-slate-800/60 border border-dashed border-slate-600 px-1.5 py-0.5 rounded shrink-0"
            title="Inferred grouping — the server guessed this parentage; no observed cross-trace spawn edge exists"
          >
            inferred
          </span>
        )}

        {/* Stats pills */}
        <div className="ml-auto flex items-center gap-1.5 shrink-0">
          {/* View session — copies the traceId until App wires real navigation. */}
          <button
            type="button"
            onClick={copyTrace}
            className="flex items-center gap-1 text-[10px] font-mono text-slate-500 hover:text-slate-300 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 px-1.5 py-0.5 rounded transition-colors"
            title={`Copy trace ID ${node.traceId} (session navigation needs App-level wiring)`}
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            {copied ? 'copied' : 'trace'}
          </button>
          <span className="text-xs text-slate-500 font-mono">{node.spanCount} spans</span>
          {node.threatCount > 0 && (
            <span className="text-xs text-red-400 font-mono font-bold bg-red-950/40 px-1.5 py-0.5 rounded">
              {node.threatCount} threats
            </span>
          )}
          {node.children.length > 0 && (
            <span className="text-xs font-mono bg-emerald-950/40 px-1.5 py-0.5 rounded" style={{ color: 'var(--cs-accent)' }}>
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
  const toolNames = [...new Set(tools.map(t => t.toolName))];
  const harnesses = [...new Set(tools.map(t => t.harness))];

  // Build lookup: toolName → harness → {count, threatCount}
  const cell = new Map<string, { count: number; threatCount: number }>();
  for (const t of tools) cell.set(`${t.toolName}::${t.harness}`, t);

  // Max count for color intensity normalization
  const maxCount = Math.max(1, ...tools.map(t => t.count));

  return (
    <div className="overflow-x-auto">
      <table className="text-xs border-collapse">
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
                          className="inline-flex items-center justify-center rounded text-xs font-mono font-medium min-w-[28px] px-1.5 py-0.5 transition-all"
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
  const [drawer, setDrawer] = useState<SpanSearchTarget | null>(null);

  const fetchData = () =>
    fetch('/api/orchestration')
      .then(r => r.json())
      .then((d: OrchData) => setData(d))
      .catch(() => {});

  // `/api/orchestration` aggregates across all spans. Debounce the socket-driven
  // refresh so a burst of `graph-update` events triggers one refetch, not many;
  // the initial fetch stays immediate.
  const debouncedFetch = useDebouncedCallback(fetchData);

  useEffect(() => {
    fetchData();
    socket.on('graph-update', debouncedFetch);
    return () => { socket.off('graph-update', debouncedFetch); };
  }, [debouncedFetch]);

  const { agents, edges, tools, spawnTree } = data;
  const positions = agentPositions(agents.length);

  const posMap = new Map<string, { x: number; y: number }>();
  agents.forEach((a, i) => posMap.set(a.harness, positions[i]));

  const toolFacets = useMemo<FacetConfig<ToolEntry>[]>(() => {
    const harnesses = [...new Set(tools.map(t => t.harness))].sort();
    return [
      {
        key: 'harness',
        label: 'Agents',
        accessor: t => t.harness,
        options: harnesses.map(h => ({ value: h, label: HARNESS_NAMES[h] ?? h })),
      },
    ];
  }, [tools]);

  const {
    query, setQuery, facetValues, setFacet,
    visible: visibleTools, total: toolTotal, shown: toolShown, showMore: toolShowMore, showAll: toolShowAll,
  } = useListControls(tools, { searchText: toolSearchText, facets: toolFacets });

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-auto p-5" style={{ background: 'var(--cs-bg-primary)' }}>

      {/* ── Agent DAG ──────────────────────────────────────────────────────── */}
      <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
        <p className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 mb-3">
          <Cpu className="w-3 h-3" /> Agent Orchestration Graph
          <span className="ml-1">
            <ExperimentalBadge title="Cross-agent edges only appear when multiple agents share a trace" />
          </span>
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
                <path d="M0,0 L0,6 L6,3 z" fill="var(--cs-svg-text)" />
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
                    stroke="var(--cs-svg-text)" strokeWidth={1.5}
                    strokeDasharray="5 3"
                    markerEnd="url(#arrow)"
                  />
                  <text
                    x={(sx + ex) / 2} y={(sy + ey) / 2 - 5}
                    fill="var(--cs-svg-label-muted)" fontSize={9} textAnchor="middle" fontFamily="monospace"
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
                  <text y={-8} fill="var(--cs-svg-label)" fontSize={10} textAnchor="middle" fontFamily="sans-serif" fontWeight="600">
                    {harnessShort(agent.harness)}
                  </text>
                  <text y={6} fill="var(--cs-svg-label-muted)" fontSize={9} textAnchor="middle" fontFamily="monospace">
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
      <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
        <p className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5 mb-3">
          <GitBranch className="w-3 h-3" /> Sub-Agent Spawn Tree
          <span className="ml-1">
            <ExperimentalBadge title="Heuristic — agents don't emit cross-trace spawn parentage yet" />
          </span>
          <span className="ml-auto text-[11px] text-slate-600 normal-case font-normal tracking-normal">
            Heuristic grouping of related sessions — experimental
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
            {spawnTree.some(r => r.synthetic) && (
              <div className="flex items-start gap-2 px-3 py-2 text-[11px] text-amber-300/90 bg-amber-950/20 border-b border-dashed border-amber-800/40">
                <span className="font-mono uppercase tracking-wide shrink-0">inferred</span>
                <span>
                  No observed cross-trace spawn edges — this tree is an inferred grouping of
                  related sessions, not measured parentage. Dashed/greyed rows are not real spawn edges.
                </span>
              </div>
            )}
            {spawnTree.map(root => (
              <SpawnTreeItem key={root.traceId} node={root} depth={0} />
            ))}
          </div>
        )}
      </div>

      {/* ── Tool Inventory ────────────────────────────────────────────────── */}
      <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
        <div className="flex items-center gap-2 mb-3">
          <p className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
            <Wrench className="w-3 h-3" /> Tool Inventory
          </p>
          {tools.length > 0 && (
            <div className="ml-auto">
              <FilterBar
                query={query}
                setQuery={setQuery}
                facetValues={facetValues}
                setFacet={setFacet}
                facets={toolFacets}
                placeholder="Filter tools..."
              />
            </div>
          )}
          {/* View toggle */}
          {tools.length > 0 && (
            <div className="flex items-center bg-slate-800 rounded-lg p-0.5">
              <button
                className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${toolView !== 'table' ? 'text-slate-400 hover:text-slate-200' : ''}`}
                style={toolView === 'table' ? { background: 'var(--cs-accent)', color: '#fff' } : undefined}
                onClick={() => setToolView('table')}
                title="Table view"
              >
                <List className="w-3 h-3" /> Table
              </button>
              <button
                className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${toolView !== 'heatmap' ? 'text-slate-400 hover:text-slate-200' : ''}`}
                style={toolView === 'heatmap' ? { background: 'var(--cs-accent)', color: '#fff' } : undefined}
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
        ) : toolTotal === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 gap-2">
            <Wrench className="w-7 h-7 text-slate-800" />
            <p className="text-sm text-slate-500">No matching tools</p>
          </div>
        ) : toolView === 'heatmap' ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden p-2">
            <ToolHeatmap tools={visibleTools} />
            <ListFooter shown={toolShown} total={toolTotal} showMore={toolShowMore} showAll={toolShowAll} noun="tools" />
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
                  <th className="px-4 py-2.5 text-left">Tool</th>
                  <th className="px-4 py-2.5 text-left">Agent</th>
                  <th className="px-4 py-2.5 text-right">Calls</th>
                  <th className="px-4 py-2.5 text-right">Threats</th>
                </tr>
              </thead>
              <tbody>
                {visibleTools.map(tool => {
                  const isSuspicious  = SUSPICIOUS_TOOLS.has(tool.toolName.toLowerCase());
                  const harnessColor  = HARNESS_COLORS[tool.harness] ?? '#64748b';
                  return (
                    <tr
                      key={`${tool.toolName}::${tool.harness}`}
                      onClick={() => setDrawer({ query: tool.toolName, title: tool.toolName, kind: 'Tool' })}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors cursor-pointer"
                      title="View spans for this tool"
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
                          <span className="text-slate-400 text-xs">
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
            <ListFooter shown={toolShown} total={toolTotal} showMore={toolShowMore} showAll={toolShowAll} noun="tools" />
          </div>
        )}
      </div>

      {/* ── Command Audit Trail ─────────────────────────────────────────── */}
      <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
        <CommandAuditTab />
      </div>

      {/* ── File Access Heatmap ─────────────────────────────────────────── */}
      <div className="rounded-xl p-4 mb-4" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-border)' }}>
        <FileAccessPanel />
      </div>

      {/* Tool drill-down drawer — opened by clicking a tool-inventory row. */}
      <SpanSearchDrawer target={drawer} onClose={() => setDrawer(null)} />
    </div>
  );
}
