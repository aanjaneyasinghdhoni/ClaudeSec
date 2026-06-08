import type { Express } from 'express';
import { db } from '../db.js';
import type { Severity } from '../../src/shared/types.js';
import { HARNESSES } from '../../src/harnesses.js';
import type { RouteContext } from './context.js';

interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}

const getAllSpans = db.prepare(`SELECT * FROM spans`);

export function registerOrchestrationRoutes(app: Express, _ctx: RouteContext): void {
  // ── Orchestration ────────────────────────────────────────────────────────
  app.get('/api/orchestration', (_req, res) => {
    const allSpans = getAllSpans.all() as SpanRecord[];

    // Per-harness stats
    const agentMap = new Map<string, { harness: string; spanCount: number; threatCount: number; tools: Set<string> }>();
    for (const span of allSpans) {
      if (!agentMap.has(span.harness)) {
        agentMap.set(span.harness, { harness: span.harness, spanCount: 0, threatCount: 0, tools: new Set() });
      }
      const entry = agentMap.get(span.harness)!;
      entry.spanCount++;
      if (span.severity !== 'none') entry.threatCount++;
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
    for (const span of allSpans) {
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
    for (const span of allSpans) {
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
    for (const span of allSpans) {
      spanIdx.set(span.spanId, { traceId: span.traceId, harness: span.harness, name: span.name });
    }

    // Pre-fetch sessions for display names
    const sessionNames = new Map<string, string>();
    const sessionRows = db.prepare('SELECT traceId, name FROM sessions').all() as { traceId: string; name: string }[];
    for (const s of sessionRows) sessionNames.set(s.traceId, s.name);

    // Per-trace stats (reuse agentMap data, aggregate by traceId)
    const traceStatMap = new Map<string, { traceId: string; harness: string; spanCount: number; threatCount: number }>();
    for (const span of allSpans) {
      if (!traceStatMap.has(span.traceId)) {
        traceStatMap.set(span.traceId, { traceId: span.traceId, harness: span.harness, spanCount: 0, threatCount: 0 });
      }
      const ts = traceStatMap.get(span.traceId)!;
      ts.spanCount++;
      if (span.severity !== 'none') ts.threatCount++;
    }

    // Find cross-trace parent-child edges (unique by parentTrace→childTrace)
    const spawnChildMap = new Map<string, Set<string>>(); // parentTraceId → Set<childTraceId>
    const hasSpawnParent = new Set<string>();             // traceIds that are children

    for (const span of allSpans) {
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
    for (const span of allSpans) {
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
      traceId: string;
      harness: string;
      sessionName: string;
      spanCount: number;
      threatCount: number;
      // true when this node's parentage was INFERRED by the fallback heuristic
      // (no real cross-trace spawn edges existed) rather than OBSERVED from
      // actual span parentage. The UI renders these distinctly so a viewer can
      // never mistake a guessed grouping for a measured one.
      synthetic: boolean;
      children: SpawnTreeNode[];
    }

    function buildSpawnNode(traceId: string, synthetic: boolean, visited = new Set<string>()): SpawnTreeNode {
      if (visited.has(traceId)) {
        return { traceId, harness: 'unknown', sessionName: traceId.slice(0, 8), spanCount: 0, threatCount: 0, synthetic, children: [] };
      }
      visited.add(traceId);
      const stats = traceStatMap.get(traceId);
      const children = [...(spawnChildMap.get(traceId) ?? [])].map(c => buildSpawnNode(c, synthetic, visited));
      return {
        traceId,
        harness:     stats?.harness     ?? 'unknown',
        sessionName: sessionNames.get(traceId) ?? traceId.slice(0, 8),
        spanCount:   stats?.spanCount   ?? 0,
        threatCount: stats?.threatCount ?? 0,
        synthetic,
        children,
      };
    }

    // Root spawn nodes: traces that have children but are not themselves children of another
    let rootSpawnTraces = [...traceStatMap.keys()].filter(id =>
      spawnChildMap.has(id) && !hasSpawnParent.has(id)
    );

    // Track whether the tree below was built from real spawn edges or fabricated
    // by the fallback. The fallback only runs when NO real edges exist, so when
    // it fires the ENTIRE tree is inferred.
    let spawnTreeIsSynthetic = false;

    // Fallback heuristic: if no cross-trace spawns detected, group sessions by harness
    // so the spawn tree always shows something useful
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
        traceIds.sort((a, b) => {
          const aSpan = allSpans.find(s => s.traceId === a);
          const bSpan = allSpans.find(s => s.traceId === b);
          return (aSpan?.startNano ?? '0').localeCompare(bSpan?.startNano ?? '0');
        });
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

    res.json({ agents, edges, tools, spawnTree });
  });
}
