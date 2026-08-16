import type { Express } from 'express';
import { db } from '../db.js';
import type { SpanRecord } from '../types.js';
import { HARNESSES } from '../../src/harnesses.js';
import { scanTranscriptLineage, type TranscriptLineage } from '../transcriptWatcher.js';
import type { RouteContext } from './context.js';

// Per-harness rollup over the FULL table — counts must stay accurate as the
// span table grows, so they come straight from SQL (the (harness, severity)
// index satisfies this) rather than an in-memory scan.
const harnessStats = db.prepare(`
  SELECT harness,
         COUNT(*) AS spanCount,
         SUM(CASE WHEN severity != 'none' THEN 1 ELSE 0 END) AS threatCount
  FROM spans
  GROUP BY harness
`);

// Per-trace rollup over the FULL table. Powers the spawn-tree node stats.
const traceStats = db.prepare(`
  SELECT traceId, harness,
         COUNT(*) AS spanCount,
         SUM(CASE WHEN severity != 'none' THEN 1 ELSE 0 END) AS threatCount
  FROM spans
  GROUP BY traceId
`);

// The tool matrix, harness edges, and spawn tree need each span's attributes
// JSON and parentage, which can't be aggregated in SQL. Bound that work to the
// most-recent spans so the endpoint stops being O(total table) — older history
// stays available via Search/Sessions. Override with CLAUDESEC_ORCH_LIMIT.
const ORCH_LIMIT = (() => {
  const n = parseInt(String(process.env.CLAUDESEC_ORCH_LIMIT ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : 20000;
})();

const getRecentSpans = db.prepare(`
  SELECT * FROM (
    SELECT * FROM spans ORDER BY startNano DESC LIMIT ?
  ) ORDER BY startNano ASC
`);

// ── Sub-agent lineage ───────────────────────────────────────────────────────
// server/transcriptWatcher.ts stamps two facts on the spans it writes: which
// delegated agent produced a span (`claudesec.agent.id`), and which agent a
// spawning tool call launched (`claudesec.agent.spawned_id`, on that call's
// result span, whose parentId is the call itself). Joining the two rebuilds the
// tree — including agents that delegate further — without depending on which
// transcript the watcher happened to read first.
//
// Full-table on purpose: an agent's spans are worth counting whether or not they
// fall in the recent working window, and a tree that silently truncated its own
// branches would be worse than no tree. The `LIKE` prefilter is what makes that
// affordable — measured at ~0.17 s over 277k spans / 731 MB, against ~0.8 s for
// an unfiltered json_extract scan. It over-matches (any span whose text merely
// mentions the key), so the extracted values are re-checked below.
const AGENT_ID_KEY    = '$."claudesec.agent.id"';
const AGENT_TYPE_KEY  = '$."claudesec.agent.type"';
const AGENT_SPAWN_KEY = '$."claudesec.agent.spawned_id"';

interface LineageRow {
  spanId: string;
  parentId: string;
  traceId: string;
  harness: string;
  severity: string;
  agentId: string | null;
  agentType: string | null;
  spawnedId: string | null;
}

const getLineageSpans = db.prepare(`
  SELECT spanId, parentId, traceId, harness, severity,
         json_extract(attributes, '${AGENT_ID_KEY}')    AS agentId,
         json_extract(attributes, '${AGENT_TYPE_KEY}')  AS agentType,
         json_extract(attributes, '${AGENT_SPAWN_KEY}') AS spawnedId
    FROM spans
   WHERE attributes LIKE '%"claudesec.agent.%'
`);

// Identity columns only — no attributes, so this is index-served and costs
// ~5 ms even on a mature database. Only the recovery overlay below needs it.
const getSpanIdentities = db.prepare(`
  SELECT spanId, parentId, traceId, harness, severity FROM spans
`);

/**
 * Lineage recovered from transcripts for spans recorded before the watcher
 * stamped it. Opt-in via CLAUDESEC_LINEAGE_BACKFILL=1, and read-only by
 * construction: `parentId` is covered by the spans audit chain, so history is
 * joined at query time and never written back. Cached because the scan is a
 * full pass over the transcript tree; TTL so a long-running dashboard still
 * picks up agents that have finished since.
 */
const RECOVERY_TTL_MS = 10 * 60_000;
let recoveryCache: { at: number; lineage: TranscriptLineage } | undefined;

function recoveredLineage(): TranscriptLineage | undefined {
  if (process.env.CLAUDESEC_LINEAGE_BACKFILL !== '1') return undefined;
  const now = Date.now();
  if (recoveryCache && now - recoveryCache.at < RECOVERY_TTL_MS) return recoveryCache.lineage;
  try {
    recoveryCache = { at: now, lineage: scanTranscriptLineage() };
  } catch {
    // A missing or unreadable transcript tree costs the overlay, nothing else.
    return recoveryCache?.lineage;
  }
  return recoveryCache.lineage;
}

/** One delegated agent, as the graph needs it. */
interface AgentFacts {
  agentId: string;
  agentType: string;
  traceId: string;
  harness: string;
  spanCount: number;
  threatCount: number;
  /** The `Agent` call that launched it, when a launch record was observed. */
  spawnCallId: string;
  /** The agent that made that call — set only when the spawner was itself delegated. */
  spawnedBy: string;
}

function agentEntry(map: Map<string, AgentFacts>, agentId: string): AgentFacts {
  let entry = map.get(agentId);
  if (!entry) {
    entry = { agentId, agentType: '', traceId: '', harness: 'unknown', spanCount: 0, threatCount: 0, spawnCallId: '', spawnedBy: '' };
    map.set(agentId, entry);
  }
  return entry;
}

/**
 * Roll every delegated agent up from the spans it produced, plus the launch
 * records that name it. Returns agents keyed by id; the caller shapes the tree.
 */
function collectAgents(): Map<string, AgentFacts> {
  const agents = new Map<string, AgentFacts>();

  const observe = (row: LineageRow): void => {
    if (row.agentId) {
      const entry = agentEntry(agents, row.agentId);
      entry.spanCount++;
      if (row.severity !== 'none') entry.threatCount++;
      if (!entry.traceId) entry.traceId = row.traceId;
      if (entry.harness === 'unknown') entry.harness = row.harness;
      if (!entry.agentType && row.agentType) entry.agentType = row.agentType;
    }
    if (row.spawnedId) {
      const child = agentEntry(agents, row.spawnedId);
      // The launch fact lives on the call's RESULT span, whose parentId is the
      // call. Fall back to the span itself so a differently-shaped launch
      // record still yields an edge rather than none.
      if (!child.spawnCallId) child.spawnCallId = row.parentId || row.spanId;
      if (!child.spawnedBy && row.agentId) child.spawnedBy = row.agentId;
      if (!child.traceId) child.traceId = row.traceId;
      if (child.harness === 'unknown') child.harness = row.harness;
    }
  };

  // Spans already counted from their own stored attributes. The recovery pass
  // below covers the SAME transcripts, so without this every agent whose work
  // straddles the two eras would have its spans counted twice.
  const counted = new Set<string>();
  for (const raw of getLineageSpans.iterate()) {
    const row = raw as LineageRow;
    // The LIKE prefilter matches any span that merely mentions the key.
    if (!row.agentId && !row.spawnedId) continue;
    if (row.agentId) counted.add(row.spanId);
    observe(row);
  }

  const recovered = recoveredLineage();
  if (recovered && recovered.agentBySpanId.size > 0) {
    for (const raw of getSpanIdentities.iterate()) {
      const id = raw as { spanId: string; parentId: string; traceId: string; harness: string; severity: string };
      const agentId = recovered.agentBySpanId.get(id.spanId);
      if (!agentId || counted.has(id.spanId)) continue;
      observe({ ...id, agentId, agentType: recovered.typeByAgentId.get(agentId) ?? null, spawnedId: null });
    }
    for (const [agentId, callId] of recovered.spawnCallByAgentId) {
      const entry = agentEntry(agents, agentId);
      if (!entry.spawnCallId) entry.spawnCallId = callId;
      if (!entry.agentType) entry.agentType = recovered.typeByAgentId.get(agentId) ?? '';
    }
  }

  // An agent whose spawning call is known but which is itself delegated needs
  // that spawner resolved to an AGENT, not just a span. The stamped path gets
  // this from the launch row; the recovered path has to look it up.
  const agentBySpanId = new Map<string, string>();
  if (recovered) for (const [spanId, agentId] of recovered.agentBySpanId) agentBySpanId.set(spanId, agentId);
  for (const entry of agents.values()) {
    if (entry.spawnedBy || !entry.spawnCallId) continue;
    entry.spawnedBy = agentBySpanId.get(entry.spawnCallId) ?? '';
  }

  // An agent that left no span in this database is one we know ran but have no
  // record of — a transcript this install never ingested, or one whose spans
  // have since aged out under retention. Naming it in the graph would put a row
  // on screen that no stored evidence backs, so drop it.
  for (const [agentId, entry] of agents) {
    if (entry.spanCount === 0) agents.delete(agentId);
  }
  return agents;
}

export function registerOrchestrationRoutes(app: Express, _ctx: RouteContext): void {
  // ── Orchestration ────────────────────────────────────────────────────────
  app.get('/api/orchestration', (_req, res) => {
    const recentSpans = getRecentSpans.all(ORCH_LIMIT) as SpanRecord[];

    // Per-harness stats (full-table counts via SQL; tool set from recent window)
    const harnessRows = harnessStats.all() as { harness: string; spanCount: number; threatCount: number }[];
    const agentMap = new Map<string, { harness: string; spanCount: number; threatCount: number; tools: Set<string> }>();
    for (const row of harnessRows) {
      agentMap.set(row.harness, { harness: row.harness, spanCount: row.spanCount, threatCount: row.threatCount, tools: new Set() });
    }
    for (const span of recentSpans) {
      const entry = agentMap.get(span.harness);
      if (!entry) continue;
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['tool'] || attrs['gen_ai.tool.name'] || attrs['tool.name'] || span.name || '';
        if (toolName) entry.tools.add(String(toolName));
      } catch {}
    }

    const agents = [...agentMap.values()].map(a => ({
      harness:     a.harness,
      spanCount:   a.spanCount,
      threatCount: a.threatCount,
      tools:       [...a.tools],
    }));

    // Group spans by traceId to find co-occurring harnesses
    const traceHarnesses = new Map<string, { harness: string; startNano: string }[]>();
    for (const span of recentSpans) {
      if (!traceHarnesses.has(span.traceId)) traceHarnesses.set(span.traceId, []);
      traceHarnesses.get(span.traceId)!.push({ harness: span.harness, startNano: span.startNano });
    }

    const edgeMap = new Map<string, { from: string; to: string; count: number }>();
    for (const [, spans] of traceHarnesses) {
      const unique = [...new Map(spans.map(s => [s.harness, s])).values()];
      if (unique.length < 2) continue;
      unique.sort((a, b) => {
        try { return Number(BigInt(a.startNano) - BigInt(b.startNano) > 0n ? 1 : -1); }
        catch { return 0; }
      });
      for (let i = 0; i < unique.length - 1; i++) {
        const key = `${unique[i].harness}→${unique[i + 1].harness}`;
        if (!edgeMap.has(key)) edgeMap.set(key, { from: unique[i].harness, to: unique[i + 1].harness, count: 0 });
        edgeMap.get(key)!.count++;
      }
    }

    const edges = [...edgeMap.values()];

    // Tool inventory (full matrix: toolName × harness)
    const toolMap = new Map<string, { toolName: string; harness: string; count: number; threatCount: number }>();
    for (const span of recentSpans) {
      try {
        const attrs = JSON.parse(span.attributes);
        const toolName = attrs['tool'] || attrs['gen_ai.tool.name'] || attrs['tool.name'] || span.name || '';
        if (!toolName) continue;
        const key = `${toolName}::${span.harness}`;
        if (!toolMap.has(key)) toolMap.set(key, { toolName: String(toolName), harness: span.harness, count: 0, threatCount: 0 });
        const entry = toolMap.get(key)!;
        entry.count++;
        if (span.severity !== 'none') entry.threatCount++;
      } catch {}
    }
    const tools = [...toolMap.values()].sort((a, b) => b.count - a.count).slice(0, 50);

    // ── Sub-agent spawn tree detection ──────────────────────────────────────
    // A spawn event is when span.parentId references a span from a DIFFERENT traceId.
    // This happens when Claude Code's Agent tool (or similar) creates child agents.

    // Build span index for O(1) parent lookup
    const spanIdx = new Map<string, { traceId: string; harness: string; name: string }>();
    // Earliest startNano per trace within the working window — feeds the
    // fallback sort below without re-scanning the span array per trace.
    const traceFirstNano = new Map<string, string>();
    for (const span of recentSpans) {
      spanIdx.set(span.spanId, { traceId: span.traceId, harness: span.harness, name: span.name });
      if (!traceFirstNano.has(span.traceId)) traceFirstNano.set(span.traceId, span.startNano);
    }

    // Pre-fetch sessions for display names. `repo` isn't a sessions column — it's
    // derived from the spans a trace touched, same repo_agg shape as the session
    // list (server/routes/sessions.ts) — so the UI can run sessionDisplayLabel()
    // on these nodes instead of showing the raw "<harness> · <time>" default.
    const sessionInfo = new Map<string, { name: string; repo: string | null; createdAt: string }>();
    const sessionRows = db.prepare(`
      WITH repo_agg AS (
        SELECT traceId, GROUP_CONCAT(repo, char(10)) AS repo
        FROM (SELECT DISTINCT traceId, repo FROM spans)
        GROUP BY traceId
      )
      SELECT se.traceId, se.name, se.createdAt, ra.repo AS repo
      FROM sessions se
      LEFT JOIN repo_agg ra ON ra.traceId = se.traceId
    `).all() as { traceId: string; name: string; createdAt: string; repo: string | null }[];
    for (const s of sessionRows) sessionInfo.set(s.traceId, { name: s.name, repo: s.repo, createdAt: s.createdAt });

    // Per-trace stats over the FULL table (SQL GROUP BY) — node counts stay
    // accurate even for traces outside the recent working window.
    const traceStatMap = new Map<string, { traceId: string; harness: string; spanCount: number; threatCount: number }>();
    for (const row of traceStats.all() as { traceId: string; harness: string; spanCount: number; threatCount: number }[]) {
      traceStatMap.set(row.traceId, { traceId: row.traceId, harness: row.harness, spanCount: row.spanCount, threatCount: row.threatCount });
    }

    // Find cross-trace parent-child edges (unique by parentTrace→childTrace)
    const spawnChildMap = new Map<string, Set<string>>(); // parentTraceId → Set<childTraceId>
    const hasSpawnParent = new Set<string>();             // traceIds that are children

    for (const span of recentSpans) {
      // parentId could be a harness root id (not a real span) — skip those
      const isHarnessRoot = HARNESSES.some(h => h.id === span.parentId);
      if (isHarnessRoot || !span.parentId) continue;

      const parentSpan = spanIdx.get(span.parentId);
      if (parentSpan && parentSpan.traceId !== span.traceId) {
        if (!spawnChildMap.has(parentSpan.traceId)) spawnChildMap.set(parentSpan.traceId, new Set());
        spawnChildMap.get(parentSpan.traceId)!.add(span.traceId);
        hasSpawnParent.add(span.traceId);
      }
    }

    // Also detect spawn-like spans by name/attribute patterns (agent.tool.name = "Agent", sub_agent, etc.)
    for (const span of recentSpans) {
      const isSpawnSpan = /\b(sub.?agent|spawn|agent.tool|delegate)\b/i.test(span.name);
      if (!isSpawnSpan) continue;
      try {
        const attrs = JSON.parse(span.attributes);
        const childTraceId = attrs['agent.child_trace_id'] || attrs['subagent.trace_id'];
        if (childTraceId && typeof childTraceId === 'string' && childTraceId !== span.traceId) {
          if (!spawnChildMap.has(span.traceId)) spawnChildMap.set(span.traceId, new Set());
          spawnChildMap.get(span.traceId)!.add(childTraceId);
          hasSpawnParent.add(childTraceId);
        }
      } catch {}
    }

    interface SpawnTreeNode {
      // A session (one trace) or one delegated agent within it. Sub-agents run
      // under their parent's session id, so a trace-only tree cannot express
      // them — the two node kinds are what make delegation visible.
      kind: 'session' | 'agent';
      traceId: string;
      /** Set on agent nodes: the harness's own id for the delegated agent. */
      agentId?: string;
      /** Set on agent nodes where the transcript declares one (e.g. "code-reviewer"). */
      agentType?: string;
      harness: string;
      sessionName: string;
      /** Session nodes only — feeds sessionDisplayLabel() on the frontend. Null/absent when the trace carried no tracked repo. */
      repo?: string | null;
      /** Session nodes only — feeds sessionDisplayLabel() on the frontend. */
      createdAt?: string;
      spanCount: number;
      threatCount: number;
      // true when this node's parentage was INFERRED by the fallback heuristic
      // (no real spawn edges existed) rather than OBSERVED from a launch record.
      // The UI renders these distinctly so a viewer can never mistake a guessed
      // grouping for a measured one. Agent nodes are never synthetic.
      synthetic: boolean;
      children: SpawnTreeNode[];
    }

    // ── Observed delegation ─────────────────────────────────────────────────
    const agentFacts = collectAgents();
    // Agents nested under the agent that launched them; the rest hang off the
    // session they ran in.
    const agentChildren = new Map<string, AgentFacts[]>();  // parent agentId → children
    const sessionAgents = new Map<string, AgentFacts[]>();  // traceId → top-level agents
    for (const agent of agentFacts.values()) {
      if (agent.spawnedBy && agentFacts.has(agent.spawnedBy) && agent.spawnedBy !== agent.agentId) {
        const list = agentChildren.get(agent.spawnedBy) ?? [];
        list.push(agent);
        agentChildren.set(agent.spawnedBy, list);
      } else {
        const list = sessionAgents.get(agent.traceId) ?? [];
        list.push(agent);
        sessionAgents.set(agent.traceId, list);
      }
    }
    const byFirstSeen = (a: AgentFacts, b: AgentFacts) => b.spanCount - a.spanCount || a.agentId.localeCompare(b.agentId);

    function buildAgentNode(agent: AgentFacts, visited: Set<string>): SpawnTreeNode {
      const label = agent.agentType || 'sub-agent';
      const node: SpawnTreeNode = {
        kind:        'agent',
        traceId:     agent.traceId,
        agentId:     agent.agentId,
        agentType:   agent.agentType || undefined,
        harness:     agent.harness,
        sessionName: `${label} · ${agent.agentId.slice(0, 8)}`,
        spanCount:   agent.spanCount,
        threatCount: agent.threatCount,
        synthetic:   false,
        children:    [],
      };
      // A launch record is written by the agent that made the call, so a cycle
      // should be impossible — guard anyway rather than recurse forever on a
      // corrupt or hand-edited transcript.
      if (visited.has(agent.agentId)) return node;
      visited.add(agent.agentId);
      node.children = (agentChildren.get(agent.agentId) ?? []).sort(byFirstSeen).map(c => buildAgentNode(c, visited));
      return node;
    }

    function buildSpawnNode(traceId: string, synthetic: boolean, visited = new Set<string>()): SpawnTreeNode {
      if (visited.has(traceId)) {
        return { kind: 'session', traceId, harness: 'unknown', sessionName: traceId.slice(0, 8), spanCount: 0, threatCount: 0, synthetic, children: [] };
      }
      visited.add(traceId);
      const stats = traceStatMap.get(traceId);
      const session = sessionInfo.get(traceId);
      const children = [...(spawnChildMap.get(traceId) ?? [])].map(c => buildSpawnNode(c, synthetic, visited));
      const seenAgents = new Set<string>();
      for (const agent of (sessionAgents.get(traceId) ?? []).sort(byFirstSeen)) {
        children.push(buildAgentNode(agent, seenAgents));
      }
      return {
        kind:        'session',
        traceId,
        harness:     stats?.harness     ?? 'unknown',
        sessionName: session?.name ?? traceId.slice(0, 8),
        repo:        session?.repo ?? null,
        createdAt:   session?.createdAt,
        spanCount:   stats?.spanCount   ?? 0,
        threatCount: stats?.threatCount ?? 0,
        synthetic,
        children,
      };
    }

    // Root spawn nodes: traces that host delegated agents, or that have
    // cross-trace children, and are not themselves someone else's child.
    let rootSpawnTraces = [...traceStatMap.keys()].filter(id =>
      (spawnChildMap.has(id) || sessionAgents.has(id)) && !hasSpawnParent.has(id)
    );

    // Track whether the tree below was built from real spawn edges or fabricated
    // by the fallback. The fallback only runs when NO real edges exist, so when
    // it fires the ENTIRE tree is inferred.
    let spawnTreeIsSynthetic = false;

    // Fallback heuristic: with no observed delegation and no cross-trace spawns,
    // group sessions by harness so the tree still shows something useful. It is
    // labelled "estimated" end to end — it must never run alongside real edges,
    // or a guess would sit next to a measurement wearing the same styling.
    if (rootSpawnTraces.length === 0 && traceStatMap.size > 0) {
      spawnTreeIsSynthetic = true;
      const harnessTraces = new Map<string, string[]>();
      for (const [traceId, stats] of traceStatMap) {
        if (!harnessTraces.has(stats.harness)) harnessTraces.set(stats.harness, []);
        harnessTraces.get(stats.harness)!.push(traceId);
      }
      for (const [, traceIds] of harnessTraces) {
        if (traceIds.length < 2) continue;
        // Sort by start time (earliest first) — use first span's startNano
        traceIds.sort((a, b) =>
          (traceFirstNano.get(a) ?? '0').localeCompare(traceFirstNano.get(b) ?? '0'),
        );
        const [root, ...children] = traceIds;
        for (const child of children) {
          if (!spawnChildMap.has(root)) spawnChildMap.set(root, new Set());
          spawnChildMap.get(root)!.add(child);
          hasSpawnParent.add(child);
        }
      }
      rootSpawnTraces = [...traceStatMap.keys()].filter(id =>
        spawnChildMap.has(id) && !hasSpawnParent.has(id)
      );
    }

    const spawnTree = rootSpawnTraces.map(id => buildSpawnNode(id, spawnTreeIsSynthetic));

    // What the tree is actually built on, so the UI can say so rather than
    // hedging. `resolved` counts agents whose launch call was observed —
    // everything else is an agent we can see working but cannot place, and the
    // difference is the honest measure of how complete this view is.
    const lineage = {
      agents:    agentFacts.size,
      resolved:  [...agentFacts.values()].filter(a => a.spawnCallId !== '').length,
      recovered: recoveredLineage() !== undefined,
    };

    res.json({ agents, edges, tools, spawnTree, lineage });
  });
}
