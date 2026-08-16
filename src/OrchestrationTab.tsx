/**
 * OrchestrationTab — the agent/subagent graph: who ran, what they called, and
 * who spawned whom.
 *
 * The spawn tree mixes two node kinds. A `session` node is one trace; an
 * `agent` node is one delegated sub-agent inside it, placed from the launch
 * record its parent wrote. Sub-agents run under their parent's session id, so
 * without that second kind the whole hierarchy collapses into a flat list.
 *
 * Where no launch record exists the server falls back to grouping sessions by
 * harness and marks the result `synthetic`; this tab's job with that flag is to
 * keep the guess visually distinct from an observed edge — dashed, hollow,
 * labelled "estimated" — never to quietly promote a guess into a fact.
 */
import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { Cpu, Wrench, GitBranch, Bot, ChevronDown, ChevronRight, LayoutGrid, List, Copy, Check, ExternalLink, Info } from 'lucide-react';
import { socket } from './socket';
import { CommandAuditTab } from './CommandAuditTab';
import { FileAccessPanel } from './FileAccessPanel';
import { ExperimentalBadge } from './ExperimentalBadge';
import { sessionDisplayLabel } from './dashboardTypes';
import { useListControls, FilterBar, ListFooter, type FacetConfig } from './FilterControls';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import { SpanSearchDrawer, type SpanSearchTarget } from './SpanSearchDrawer';
import {
  DataTable, type DataColumn,
  ToolButton,
  EmptyState, ErrorState,
} from './components/data';

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
  /** 'session' → one trace; 'agent' → one delegated sub-agent within it. */
  kind?: 'session' | 'agent';
  traceId: string;
  agentId?: string;
  agentType?: string;
  harness: string;
  sessionName: string;
  /** Session nodes only — feeds sessionDisplayLabel() below. */
  repo?: string | null;
  /** Session nodes only — feeds sessionDisplayLabel() below. */
  createdAt?: string;
  spanCount: number;
  threatCount: number;
  // true → parentage was INFERRED by the server's fallback heuristic (no launch
  // record existed). Rendered visually distinct so a viewer can't mistake a
  // guessed grouping for an observed spawn edge.
  synthetic?: boolean;
  children: SpawnTreeNode[];
}

/** How much of the tree is measured rather than guessed. */
interface LineageSummary {
  /** Delegated agents seen working. */
  agents: number;
  /** Of those, how many had their launch call observed. */
  resolved: number;
  /** Whether the opt-in transcript recovery overlay contributed. */
  recovered: boolean;
}

interface OrchData {
  agents: AgentStat[];
  edges: OrchEdge[];
  tools: ToolEntry[];
  spawnTree: SpawnTreeNode[];
  lineage?: LineageSummary;
}

// ── Constants ─────────────────────────────────────────────────────────────────

// The agent's identity colour — fixed hue per harness, same set as every
// other tab. Identity, not risk, so it stays outside the severity ramp.
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

/** Section label shared by every panel in this tab — the eyebrow token plus
 *  an icon, so the four panels read as one family without repeating markup. */
function PanelHeading({ icon, children, badge }: { icon: React.ReactNode; children: React.ReactNode; badge?: React.ReactNode }) {
  return (
    <p className="cs-eyebrow flex items-center gap-1.5 mb-3">
      {icon} {children}
      {badge && <span className="ml-1 normal-case tracking-normal">{badge}</span>}
    </p>
  );
}

function SpawnTreeItem({
  node,
  depth = 0,
  onSelectSession,
}: {
  node: SpawnTreeNode;
  depth?: number;
  key?: React.Key;
  onSelectSession?: (traceId: string) => void;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const [copied, setCopied] = useState(false);
  const color = HARNESS_COLORS[node.harness] ?? HARNESS_COLORS.unknown;
  const hasChildren = node.children.length > 0;
  const synthetic = node.synthetic === true;
  const isAgent = node.kind === 'agent';
  // Sub-agents share their parent's trace, so the session id on an agent row is
  // the parent's — the agent's own identity is the one worth copying.
  const copyValue = isAgent ? (node.agentId ?? node.traceId) : node.traceId;
  // Same derivation as the session rail (src/shell/SessionList.tsx): trade the
  // raw "<harness> · <time>" default for the repo that ran, and leave a real
  // rename alone. Agent rows already carry their own label (the agent type).
  const displayName = isAgent
    ? node.sessionName
    : sessionDisplayLabel({ name: node.sessionName, repo: node.repo ?? null, createdAt: node.createdAt ?? '' });

  const copyTrace = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(copyValue).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }).catch(() => {});
  };

  const viewSession = (e: React.MouseEvent) => {
    e.stopPropagation();
    onSelectSession?.(node.traceId);
  };

  return (
    <div>
      <div
        className="flex items-center gap-2 py-1.5 px-2 rounded transition-colors select-none"
        style={{
          paddingLeft: `${8 + depth * 20}px`,
          cursor: hasChildren ? 'pointer' : 'default',
          opacity: synthetic ? 0.7 : 1,
          borderLeft: synthetic ? '2px dashed var(--cs-rule-strong)' : '2px solid transparent',
        }}
        onClick={() => hasChildren && setExpanded(e => !e)}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--cs-bg-raised)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
        title={synthetic ? 'Estimated grouping — a best guess, not an observed cross-trace spawn edge' : undefined}
      >
        <span className="w-4 h-4 shrink-0 flex items-center justify-center" style={{ color: 'var(--cs-text-faint)' }}>
          {hasChildren
            ? (expanded ? <ChevronDown className="w-3 h-3" aria-hidden="true" /> : <ChevronRight className="w-3 h-3" aria-hidden="true" />)
            : null}
        </span>

        {isAgent ? (
          <Bot className="w-3 h-3 shrink-0" style={{ color }} aria-hidden="true" />
        ) : (
          <span
            className="w-2.5 h-2.5 rounded-full shrink-0"
            style={synthetic
              ? { border: `1.5px dashed ${color}`, background: 'transparent' }
              : { background: color }}
            aria-hidden="true"
          />
        )}

        <span
          className="shrink-0"
          style={{
            fontSize: 'var(--cs-text-xs)',
            fontWeight: 'var(--cs-weight-medium)',
            color: synthetic ? 'var(--cs-text-muted)' : 'var(--cs-text-strong)',
            fontStyle: synthetic ? 'italic' : 'normal',
          }}
        >
          {isAgent ? (node.agentType ?? 'sub-agent') : (HARNESS_NAMES[node.harness] ?? node.harness)}
        </span>

        <span
          className="cs-mono truncate max-w-[160px]"
          style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}
          title={isAgent ? `Sub-agent ${node.agentId} · launched by the agent above` : node.sessionName}
        >
          {isAgent ? node.agentId : displayName}
        </span>

        {synthetic && (
          <span
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded shrink-0 cursor-help"
            style={{
              fontSize: 'var(--cs-text-2xs)',
              letterSpacing: 'var(--cs-tracking-wide)',
              color: 'var(--cs-info)',
              background: 'rgba(var(--cs-info-rgb),0.10)',
              border: '1px dashed rgba(var(--cs-info-rgb),0.40)',
            }}
            title="Estimated, not observed. No agent reported spawning this session; it was grouped here because it runs the same agent. This is a best-effort guess, not an error."
          >
            <Info className="w-2.5 h-2.5" aria-hidden="true" /> estimated
          </span>
        )}

        <span className="ml-auto flex items-center gap-1.5 shrink-0">
          {onSelectSession && (
            <button
              type="button"
              onClick={viewSession}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded cs-mono transition-colors"
              style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-muted)', background: 'var(--cs-bg-raised)' }}
              title={isAgent
                ? `View session ${node.traceId} in the timeline — a sub-agent shares its parent's session`
                : `View session ${node.traceId} in the timeline`}
            >
              <ExternalLink className="w-3 h-3" aria-hidden="true" /> view
            </button>
          )}
          <button
            type="button"
            onClick={copyTrace}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded cs-mono transition-colors"
            style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', background: 'var(--cs-bg-raised)' }}
            title={isAgent ? `Copy agent ID ${copyValue}` : `Copy trace ID ${copyValue}`}
          >
            {copied ? <Check className="w-3 h-3" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
            {copied ? 'copied' : isAgent ? 'agent' : 'trace'}
          </button>
          <span className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{node.spanCount} spans</span>
          {node.threatCount > 0 && (
            <span
              className="cs-mono px-1.5 py-0.5 rounded"
              style={{ fontSize: 'var(--cs-text-xs)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-sev-critical-fg)', background: 'var(--cs-sev-critical-bg)' }}
            >
              {node.threatCount} threats
            </span>
          )}
          {node.children.length > 0 && (
            <span
              className="cs-mono px-1.5 py-0.5 rounded"
              style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-accent)', background: 'var(--cs-accent-soft)' }}
            >
              {node.children.length} sub-agent{node.children.length !== 1 ? 's' : ''}
            </span>
          )}
        </span>
      </div>

      {expanded && hasChildren && (
        <div style={{ borderLeft: '1px solid var(--cs-rule)', marginLeft: 20 }}>
          {node.children.map(child => (
            // A session can host many agents under one trace id, so the key has
            // to be the agent's own identity where it has one.
            <SpawnTreeItem key={child.agentId ?? child.traceId} node={child} depth={depth + 1} onSelectSession={onSelectSession} />
          ))}
        </div>
      )}
    </div>
  );
}

function ToolHeatmap({ tools }: { tools: ToolEntry[] }) {
  const toolNames = [...new Set(tools.map(t => t.toolName))];
  const harnesses = [...new Set(tools.map(t => t.harness))];

  const cell = new Map<string, { count: number; threatCount: number }>();
  for (const t of tools) cell.set(`${t.toolName}::${t.harness}`, t);

  const maxCount = Math.max(1, ...tools.map(t => t.count));

  return (
    <div className="overflow-x-auto">
      <table className="border-collapse" style={{ fontSize: 'var(--cs-text-xs)' }}>
        <thead>
          <tr>
            <th
              className="px-3 py-2 text-left sticky left-0 z-10"
              style={{ minWidth: 120, color: 'var(--cs-text-faint)', fontWeight: 'var(--cs-weight-medium)', background: 'var(--cs-bg-surface)' }}
            >
              Tool ╲ Agent
            </th>
            {harnesses.map(h => (
              <th key={h} className="px-2 py-2 text-center" style={{ minWidth: 64 }}>
                <span className="flex flex-col items-center gap-0.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: HARNESS_COLORS[h] ?? HARNESS_COLORS.unknown }} aria-hidden="true" />
                  <span className="cs-mono" style={{ color: 'var(--cs-text-muted)' }}>{harnessShort(h)}</span>
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {toolNames.map(toolName => {
            const isSuspicious = SUSPICIOUS_TOOLS.has(toolName.toLowerCase());
            return (
              <tr key={toolName} style={{ borderTop: '1px solid var(--cs-rule)' }}>
                <td className="px-3 py-1.5 sticky left-0 z-10" style={{ background: 'var(--cs-bg-surface)' }}>
                  <span className="flex items-center gap-1.5">
                    {isSuspicious && <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--cs-sev-medium)' }} aria-hidden="true" />}
                    <code className="cs-mono" style={{ color: isSuspicious ? 'var(--cs-sev-medium-fg)' : 'var(--cs-text-body)' }}>
                      {toolName}
                    </code>
                  </span>
                </td>
                {harnesses.map(h => {
                  const d = cell.get(`${toolName}::${h}`);
                  const count = d?.count ?? 0;
                  const intensity = count / maxCount;
                  const base = HARNESS_COLORS[h] ?? HARNESS_COLORS.unknown;
                  const hasThreat = (d?.threatCount ?? 0) > 0;
                  return (
                    <td key={h} className="text-center py-1.5 px-2">
                      {count > 0 ? (
                        <span
                          className="inline-flex items-center justify-center rounded cs-mono font-medium"
                          style={{
                            minWidth: 28,
                            padding: '2px 6px',
                            background: `${base}${Math.round(intensity * 220).toString(16).padStart(2, '0')}`,
                            color: intensity > 0.4 ? 'var(--cs-text-invert)' : 'var(--cs-text-muted)',
                            border: hasThreat ? '1px solid var(--cs-sev-critical)' : '1px solid transparent',
                          }}
                          title={`${count} call${count !== 1 ? 's' : ''}${hasThreat ? ` · ${d!.threatCount} threat${d!.threatCount !== 1 ? 's' : ''}` : ''}`}
                        >
                          {count}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--cs-text-faint)' }}>—</span>
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

export function OrchestrationTab({ onSelectSession }: { onSelectSession?: (traceId: string) => void }) {
  const [data, setData]     = useState<OrchData>({ agents: [], edges: [], tools: [], spawnTree: [] });
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [toolView, setToolView] = useState<'table' | 'heatmap'>('table');
  const [drawer, setDrawer] = useState<SpanSearchTarget | null>(null);

  const fetchData = useCallback(() => {
    fetch('/api/orchestration')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: OrchData) => { setData(d); setLoadError(null); })
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, []);

  // `/api/orchestration` aggregates across all spans. Debounce the socket-driven
  // refresh so a burst of `graph-update` events triggers one refetch, not many;
  // the initial fetch stays immediate.
  const debouncedFetch = useDebouncedCallback(fetchData);

  useEffect(() => {
    fetchData();
    socket.on('graph-update', debouncedFetch);
    return () => { socket.off('graph-update', debouncedFetch); };
  }, [fetchData, debouncedFetch]);

  const { agents, edges, tools, spawnTree, lineage } = data;
  // Delegation is "observed" the moment any agent's launch call was recorded.
  // Until then the tree is the server's fallback grouping and says so.
  const observedLineage = (lineage?.resolved ?? 0) > 0;
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

  const toolColumns: DataColumn<ToolEntry>[] = [
    {
      id: 'tool', header: 'Tool', width: 'minmax(0,1.3fr)', mono: true,
      cell: t => {
        const suspicious = SUSPICIOUS_TOOLS.has(t.toolName.toLowerCase());
        return (
          <span className="flex items-center gap-1.5 min-w-0">
            {suspicious && <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: 'var(--cs-sev-medium)' }} aria-hidden="true" />}
            <span style={{ color: suspicious ? 'var(--cs-sev-medium-fg)' : 'var(--cs-text-body)' }}>{t.toolName}</span>
          </span>
        );
      },
    },
    {
      id: 'agent', header: 'Agent', width: 'minmax(0,1fr)', hideBelow: 'xl',
      cell: t => (
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: HARNESS_COLORS[t.harness] ?? HARNESS_COLORS.unknown }} aria-hidden="true" />
          <span className="truncate">{HARNESS_NAMES[t.harness] ?? t.harness}</span>
        </span>
      ),
    },
    {
      id: 'calls', header: 'Calls', width: '80px', align: 'end', mono: true,
      cell: t => <span style={{ color: 'var(--cs-text-body)' }}>{t.count}</span>,
    },
    {
      id: 'threats', header: 'Threats', width: '80px', align: 'end', mono: true,
      cell: t => t.threatCount > 0
        ? <span style={{ color: 'var(--cs-sev-critical-fg)', fontWeight: 'var(--cs-weight-bold)' }}>{t.threatCount}</span>
        : <span style={{ color: 'var(--cs-text-faint)' }}>0</span>,
    },
  ];

  const hasOrchData = agents.length > 0 || spawnTree.length > 0 || tools.length > 0;

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-auto p-4 gap-4" style={{ background: 'var(--cs-bg-canvas)' }}>

      {loadError && !hasOrchData ? (
        <ErrorState
          description={`The orchestration view did not respond (${loadError}).`}
          onRetry={() => { setLoading(true); fetchData(); }}
        />
      ) : (
      <>
      {/* ── Agent DAG ──────────────────────────────────────────────────────── */}
      <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
        <PanelHeading
          icon={<Cpu className="w-3 h-3" aria-hidden="true" />}
          badge={
            <ExperimentalBadge
              label="Estimated"
              title="ClaudeSec infers agent relationships from timing and naming — a best-effort estimate, not an error. Cross-agent edges only appear when multiple agents share a trace."
            />
          }
        >
          Agent orchestration graph
        </PanelHeading>

        {!loading && agents.length === 0 ? (
          <EmptyState
            icon={<Cpu className="w-6 h-6" aria-hidden="true" />}
            title="No agent data yet"
            description="Send traces to see agent interactions."
          />
        ) : (
          <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} className="w-full" style={{ maxHeight: 280 }} role="img" aria-label="Agent orchestration graph">
            <defs>
              {agents.map(a => (
                <radialGradient key={a.harness} id={`grad-${a.harness}`} cx="50%" cy="50%" r="50%">
                  <stop offset="0%"   stopColor={HARNESS_COLORS[a.harness] ?? HARNESS_COLORS.unknown} stopOpacity={0.25} />
                  <stop offset="100%" stopColor={HARNESS_COLORS[a.harness] ?? HARNESS_COLORS.unknown} stopOpacity={0.05} />
                </radialGradient>
              ))}
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="var(--cs-svg-text)" />
              </marker>
            </defs>

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

            {agents.map((agent, i) => {
              const pos      = positions[i];
              const color    = HARNESS_COLORS[agent.harness] ?? HARNESS_COLORS.unknown;
              const isThreat = agent.threatCount > 0;
              return (
                <g key={agent.harness} transform={`translate(${pos.x},${pos.y})`}>
                  {isThreat && (
                    <circle r={R + 8} fill="none" stroke="var(--cs-sev-critical)" strokeWidth={1.5} strokeOpacity={0.5} strokeDasharray="4 3">
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
                    <text y={19} fill="var(--cs-sev-critical)" fontSize={9} textAnchor="middle" fontFamily="monospace" fontWeight="bold">
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
      <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
        <PanelHeading
          icon={<GitBranch className="w-3 h-3" aria-hidden="true" />}
          badge={
            observedLineage ? undefined : (
              <ExperimentalBadge
                label="Estimated hierarchy"
                title="No agent here recorded launching another, so ClaudeSec groups sessions by agent as a best-effort estimate. Not an error."
              />
            )
          }
        >
          Sub-agent spawn tree
        </PanelHeading>
        <p className="-mt-1.5 mb-3" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>
          Every session in the database, not scoped to whatever is selected in the
          session rail — pick a row below and use "view" to jump into that one
          session's timeline. {observedLineage ? (
            <>
              Built from launch records: {lineage!.resolved} of {lineage!.agents} sub-agent
              {lineage!.agents !== 1 ? 's' : ''} placed under the exact call that started
              {lineage!.resolved !== 1 ? ' them' : ' it'}. Agents whose launch was never
              recorded — an interrupted run, a transcript already rotated away — are listed
              under the session they ran in rather than invented a parent.
            </>
          ) : (
            <>
              Shown honestly: no agent here recorded launching another, so sessions are grouped
              by agent as a best guess. Those rows are marked "estimated" below, never presented
              as an observed hierarchy.
            </>
          )}
        </p>

        {!loading && spawnTree.length === 0 ? (
          <EmptyState
            icon={<GitBranch className="w-6 h-6" aria-hidden="true" />}
            title="No sub-agent spawns detected"
            description="Appears once an agent delegates work — the launch record ties the sub-agent's spans back to the call that started it."
          />
        ) : spawnTree.length > 0 && (
          <div className="rounded-md overflow-hidden" style={{ background: 'var(--cs-bg-sunken)' }}>
            {spawnTree.some(r => r.synthetic) && (
              <div
                className="flex items-start gap-2 px-3 py-2"
                style={{
                  fontSize: 'var(--cs-text-xs)',
                  color: 'var(--cs-info)',
                  background: 'rgba(var(--cs-info-rgb),0.08)',
                  borderBottom: '1px dashed rgba(var(--cs-info-rgb),0.30)',
                }}
              >
                <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" aria-hidden="true" />
                <span style={{ color: 'var(--cs-text-muted)' }}>
                  <span style={{ color: 'var(--cs-info)', fontWeight: 'var(--cs-weight-medium)' }}>Estimated: </span>
                  no agent here reported spawning another, so ClaudeSec grouped sessions from the same
                  agent together as a best guess. Dashed/greyed rows are that estimate — not a
                  confirmed spawn link, and not an error.
                </span>
              </div>
            )}
            {spawnTree.map(root => (
              <SpawnTreeItem key={root.traceId} node={root} depth={0} onSelectSession={onSelectSession} />
            ))}
          </div>
        )}
      </div>

      {/* ── Tool Inventory ────────────────────────────────────────────────── */}
      <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <p className="cs-eyebrow flex items-center gap-1.5">
            <Wrench className="w-3 h-3" aria-hidden="true" /> Tool inventory
          </p>
          {tools.length > 0 && (
            <div className="ml-auto flex items-center gap-2">
              <FilterBar
                query={query}
                setQuery={setQuery}
                facetValues={facetValues}
                setFacet={setFacet}
                facets={toolFacets}
                placeholder="Filter tools…"
              />
              <div className="flex items-center gap-0.5" role="group" aria-label="Tool inventory view">
                <ToolButton active={toolView === 'table'} aria-pressed={toolView === 'table'} onClick={() => setToolView('table')} title="Table view">
                  <List className="w-3.5 h-3.5" aria-hidden="true" />
                </ToolButton>
                <ToolButton active={toolView === 'heatmap'} aria-pressed={toolView === 'heatmap'} onClick={() => setToolView('heatmap')} title="Heatmap view">
                  <LayoutGrid className="w-3.5 h-3.5" aria-hidden="true" />
                </ToolButton>
              </div>
            </div>
          )}
        </div>

        {!loading && tools.length === 0 ? (
          <EmptyState
            icon={<Wrench className="w-6 h-6" aria-hidden="true" />}
            title="No tool calls recorded"
            description="Tools appear when spans include gen_ai.tool.name."
          />
        ) : toolTotal === 0 ? (
          <EmptyState
            icon={<Wrench className="w-6 h-6" aria-hidden="true" />}
            title="Nothing matches this filter"
            description="No tool calls match the current search or agent filter."
          />
        ) : toolView === 'heatmap' ? (
          <div className="rounded-md p-2" style={{ background: 'var(--cs-bg-sunken)' }}>
            <ToolHeatmap tools={visibleTools} />
            <ListFooter shown={toolShown} total={toolTotal} showMore={toolShowMore} showAll={toolShowAll} noun="tools" />
          </div>
        ) : (
          <>
            <DataTable
              rows={visibleTools}
              columns={toolColumns}
              rowKey={t => `${t.toolName}::${t.harness}`}
              label="Tool inventory"
              minWidth={480}
              onActivate={t => setDrawer({ query: t.toolName, title: t.toolName, kind: 'Tool' })}
            />
            <ListFooter shown={toolShown} total={toolTotal} showMore={toolShowMore} showAll={toolShowAll} noun="tools" />
          </>
        )}
      </div>

      {/* ── Command Audit Trail — hosted here, owned by another engineer ────── */}
      <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
        <CommandAuditTab />
      </div>

      {/* ── File Access Heatmap — hosted here, owned by another engineer ────── */}
      <div className="rounded-lg p-4" style={{ background: 'var(--cs-bg-surface)' }}>
        <FileAccessPanel />
      </div>
      </>
      )}

      {/* Tool drill-down drawer — opened by clicking a tool-inventory row. */}
      <SpanSearchDrawer target={drawer} onClose={() => setDrawer(null)} />
    </div>
  );
}
