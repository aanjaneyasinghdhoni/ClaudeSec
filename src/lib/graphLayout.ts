import dagre from '@dagrejs/dagre';
import type { Node, Edge } from '@xyflow/react';

// ---------------------------------------------------------------------------
// Layout engine — radial (default) or dagre fallback
// ---------------------------------------------------------------------------

export const NODE_W = 180;
export const NODE_H = 52;

export type LayoutMode = 'radial' | 'dagre';

// Severity-based node styling — applied to all layouts
export function styleNodeBySeverity(n: Node): Node {
  const sev = (n.data as any).severity as string | undefined;
  const isRoot = n.type === 'input' || (n.data as any).isRoot;

  // Severity → border color + glow
  let borderColor = 'var(--cs-border)';
  let shadow = '0 4px 16px rgba(0,0,0,0.25)';
  let nodeWidth = NODE_W;
  let nodeHeight = NODE_H;

  if (isRoot) {
    borderColor = 'var(--cs-accent)';
    shadow = '0 0 24px rgba(var(--cs-accent-rgb),0.2), 0 4px 16px rgba(0,0,0,0.3)';
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

export function applyRadialLayout(nodes: Node[], edges: Edge[]): Node[] {
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

export function applyDagreLayout(nodes: Node[], edges: Edge[]): Node[] {
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

export function applyLayout(nodes: Node[], edges: Edge[], mode: LayoutMode): Node[] {
  return mode === 'radial' ? applyRadialLayout(nodes, edges) : applyDagreLayout(nodes, edges);
}
