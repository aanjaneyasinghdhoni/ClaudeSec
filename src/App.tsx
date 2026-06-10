import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  useNodesState, useEdgesState,
  addEdge, type Node, type Edge,
} from '@xyflow/react';
import {
  Shield, AlertTriangle, Activity, Terminal,
  CheckCircle, Search, Download, X,
  Clock, Layers, Edit2, FileText, Cpu, Zap,
  Bell, BellOff, Upload, Settings, StickyNote, Flame, Star, ShieldAlert,
  Server, GitCompare, Monitor, Bookmark, ScanLine,
  ChevronDown, MoreHorizontal, HelpCircle, Menu,
} from 'lucide-react';
import { socket } from './socket';
import { CategoryNav, type Category, CATEGORIES } from './CategoryNav';
import { DocsView } from './docs/DocsView';
import { CommandPalette } from './docs/CommandPalette';
import { ContextSidebar } from './ContextSidebar';
import type { TimeRange } from './ContextSidebar';
import { RulesTab } from './RulesTab';
import { EnforceTab } from './EnforceTab';
import { McpScanTab } from './McpScanTab';
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
import { ThemeSwitcher, LIGHT_THEMES, type ThemeId } from './ThemeSwitcher';
import { BookmarksTab } from './BookmarksTab';
import { LiveActivityPanel } from './LiveActivityPanel';
import { motion, AnimatePresence } from 'motion/react';
import type { Severity } from './shared/types';
import { applyLayout, type LayoutMode } from './lib/graphLayout';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import { toMs, formatSpanName } from './lib/format';
import { Timeline } from './Timeline';
import {
  type FilterMode, type Tab, type Workflow, type SessionLabel, type Session, type TickerSpan,
  CATEGORY_TABS, categoryForTab,
  LABEL_COLORS, HARNESS_COLORS, HARNESS_NAMES, SEVERITY_LABEL, SEVERITY_COLORS, SEV_RANK,
} from './dashboardTypes';

const TAB_ICONS: Record<Tab, React.ReactNode> = {
  timeline:      <Clock className="w-3.5 h-3.5" />,
  orchestration: <Cpu className="w-3.5 h-3.5" />,
  heatmap:       <Flame className="w-3.5 h-3.5" />,
  processes:     <Monitor className="w-3.5 h-3.5" />,
  alerts:        <AlertTriangle className="w-3.5 h-3.5" />,
  search:        <Search className="w-3.5 h-3.5" />,
  rules:         <Shield className="w-3.5 h-3.5" />,
  enforce:       <ShieldAlert className="w-3.5 h-3.5" />,
  mcpscan:       <ScanLine className="w-3.5 h-3.5" />,
  bookmarks:     <Bookmark className="w-3.5 h-3.5" />,
  harnesses:     <Cpu className="w-3.5 h-3.5" />,
  costs:         <Zap className="w-3.5 h-3.5" />,
  settings:      <Settings className="w-3.5 h-3.5" />,
};

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
  // When the unscoped graph shows only the most-recent N spans (older spans stay
  // searchable, never deleted), the server reports a window so we can say so.
  const [graphWindow, setGraphWindow] = useState<{ shown: number; total: number } | null>(null);

  // ── UI state ──────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab]           = useState<Tab>('timeline');
  const [activeCategory, setActiveCategory] = useState<Category>('observe');
  const [docsOpen, setDocsOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [selectedNode, setSelectedNode]     = useState<Node | null>(null);
  // When jumping to a span bookmark, the scoped graph loads asynchronously; hold
  // the target span id here and let an effect select it once `nodes` contains it.
  const [pendingSpanSelect, setPendingSpanSelect] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(v => !v);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

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
  // The socket effect registers its handlers once and never re-runs on session
  // switches (re-registering would risk duplicate handlers), so read the live
  // session through a ref instead of the value captured at registration time.
  const activeSessionRef = useRef(activeSession);
  useEffect(() => { activeSessionRef.current = activeSession; }, [activeSession]);
  const [connectionStatus, setConnectionStatus] = useState<'live' | 'idle' | 'setup'>('setup');
  // Surfaces a small "failed to load" notice when a core fetch (sessions / graph)
  // rejects, instead of letting the promise reject unhandled in the console.
  const [loadError, setLoadError] = useState<string | null>(null);
  const [timelineIntroShown, setTimelineIntroShown] = useState(
    () => localStorage.getItem('claudesec-timeline-intro-dismissed') !== 'true'
  );

  // ── Session rename ────────────────────────────────────────────────────────
  const [editingSession, setEditingSession] = useState<string | null>(null);
  const [editName, setEditName]             = useState('');

  // ── Filter state ──────────────────────────────────────────────────────────
  const [search, setSearch]                 = useState('');
  const [filterMode, setFilterMode]         = useState<FilterMode>('all');
  const [harnessFilter, setHarnessFilter]   = useState<string | null>(null);
  const [timeRange, setTimeRange]           = useState<TimeRange>('all');
  const [hideNone, setHideNone]             = useState(() => localStorage.getItem('claudesec.hideNone') === 'true');

  useEffect(() => {
    const sync = () => setHideNone(localStorage.getItem('claudesec.hideNone') === 'true');
    window.addEventListener('claudesec:hideNoneChange', sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener('claudesec:hideNoneChange', sync);
      window.removeEventListener('storage', sync);
    };
  }, []);

  // ── Notification state ────────────────────────────────────────────────────
  const [notifyEnabled, setNotifyEnabled] = useState(false);
  const notifyEnabledRef = useRef(false);
  const seenHighIds = useRef<Set<string>>(new Set());

  // ── Alert count ───────────────────────────────────────────────────────────
  const [alertCount, setAlertCount] = useState(0);

  // ── Import ────────────────────────────────────────────────────────────────
  const importInputRef = useRef<HTMLInputElement>(null);
  const [importStatus, setImportStatus] = useState<{ msg: string; ok: boolean } | null>(null);

  // ── Copy Mermaid feedback ─────────────────────────────────────────────────
  // 'copied' / 'error' shows for ~2s on the menu item, then resets to idle.
  const [mermaidCopy, setMermaidCopy] = useState<'idle' | 'copied' | 'error'>('idle');

  // ── Theme (s53) ───────────────────────────────────────────────────────────
  const [liveActivityOpen, setLiveActivityOpen] = useState(false);
  // Off-canvas sidebar drawer (below lg). Static in-row sidebar at >=lg.
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [theme, setTheme] = useState<ThemeId>(() => {
    try {
      const saved = localStorage.getItem('claudesec.theme');
      if (saved === 'dark') return 'midnight';
      if (saved === 'light') return 'daylight';
      if (saved === 'midnight' || saved === 'carbon' || saved === 'daylight' || saved === 'paper') return saved;
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'daylight' : 'midnight';
    } catch { return 'midnight'; }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.classList.toggle('light', LIGHT_THEMES.includes(theme));
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
  // Signature of the last graph we laid out (sorted node + edge ids + layout mode).
  // dagre layout is the expensive step on every graph-update; skipping it when the
  // structure is unchanged keeps a stream of identical broadcasts cheap.
  const lastLayoutSig = useRef<string>('');

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
      setSessions(s ?? []);
      setLoadError(null);
    }).catch((err: unknown) => {
      console.warn('ClaudeSec: failed to load sessions', err);
      setLoadError('Failed to load sessions');
    });

  const fetchAlertCount = () =>
    fetch('/api/alerts?limit=1')
      .then(r => r.json())
      .then(({ total }: { total: number }) => setAlertCount(total ?? 0))
      .catch(() => {});

  // Lay out the graph, but skip the dagre pass when the node/edge set and layout
  // mode are unchanged since the last render — a no-op broadcast then just refreshes
  // edges without re-running the expensive layout.
  const layoutGraph = (n: Node[], e: Edge[]) => {
    const sig = `${layoutMode}|${n.map(node => node.id).sort().join(',')}|${e.map(edge => edge.id).sort().join(',')}`;
    if (sig !== lastLayoutSig.current) {
      lastLayoutSig.current = sig;
      setNodes(applyLayout(n, e, layoutMode));
    }
    setEdges(e);
  };

  // Collapse bursts of socket events into a single trailing refetch (~400ms) so a
  // batch of broadcasts does not stampede the API with one call per event.
  const debouncedFetchSessions   = useDebouncedCallback(fetchSessions, 400);
  const debouncedFetchAlertCount = useDebouncedCallback(fetchAlertCount, 400);

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
      .then(({ nodes: n, edges: e, windowed, shown, total }: { nodes: Node[]; edges: Edge[]; windowed?: boolean; shown?: number; total?: number }) => {
        layoutGraph(n, e);
        syncWorkflows(n);
        setGraphWindow(windowed ? { shown: shown ?? n.length, total: total ?? 0 } : null);
        setLoadError(null);
      })
      .catch((err: unknown) => {
        console.warn('ClaudeSec: failed to load graph', err);
        setLoadError('Failed to load activity graph');
      });
    // Independent of the graph fetch above; fire concurrently rather than awaiting it.
    fetchSessions();
    fetchAlertCount();
  }, [activeSession]);

  useEffect(() => { prevWorkflows.current = workflows; }, [workflows]);

  // Resolve a pending span-bookmark jump: once the scoped graph has loaded and
  // `nodes` contains the target span, select it (which highlights it in the
  // timeline / detail panel) and clear the pending marker.
  useEffect(() => {
    if (!pendingSpanSelect) return;
    const target = nodes.find(n => n.id === pendingSpanSelect);
    if (target) {
      setSelectedNode(target);
      setPendingSpanSelect(null);
    }
  }, [pendingSpanSelect, nodes]);

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
      .then(({ bookmarks }: { bookmarks: { spanId: string }[] }) => {
        setIsBookmarked((bookmarks ?? []).some(b => b.spanId === selectedNode.id));
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
    const handleGraphUpdate = ({ nodes: n, edges: e, windowed, shown, total }: { nodes: Node[]; edges: Edge[]; windowed?: boolean; shown?: number; total?: number }) => {
      // When scoped to a session, re-fetch the scoped graph instead of using the
      // broadcast. Read the live session via a ref — this handler is registered
      // once and would otherwise close over the session from first render.
      const scopedSession = activeSessionRef.current;
      if (scopedSession) {
        fetch(`/api/graph?session=${encodeURIComponent(scopedSession)}`)
          .then(r => r.json())
          .then(({ nodes: sn, edges: se }: { nodes: Node[]; edges: Edge[] }) => {
            layoutGraph(sn, se);
            syncWorkflows(sn);
            setGraphWindow(null); // a single session is shown in full
            setLoadError(null);
          })
          .catch((err: unknown) => {
            console.warn('ClaudeSec: failed to refresh session graph', err);
            setLoadError('Failed to refresh session activity');
          });
        return;
      }
      layoutGraph(n, e);
      syncWorkflows(n);
      setGraphWindow(windowed ? { shown: shown ?? n.length, total: total ?? 0 } : null);

      // Desktop notifications for new HIGH severity spans
      if (notifyEnabledRef.current) {
        const highSpans = n.filter(
          node => (node.data as any).severity === 'high' && !seenHighIds.current.has(node.id),
        );
        highSpans.forEach(node => {
          const label = String(node.data.label ?? '');
          const rule  = String((node.data as any).attributes?.['claudesec.threat.rule'] ?? '');
          // Some browsers throw on `new Notification(...)` (e.g. permission
          // revoked between checks, or constructor blocked on mobile). Never let
          // a notification failure break the graph-update handler.
          try {
            new Notification('ClaudeSec — HIGH Alert', {
              body: `${label}${rule ? ': ' + rule : ''}`,
              tag:  node.id,
            });
          } catch (err) {
            console.warn('ClaudeSec: desktop notification failed', err);
          }
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
    socket.on('sessions-update', debouncedFetchSessions);
    socket.on('alerts-update', debouncedFetchAlertCount);
    socket.on('span-added', handleSpanAdded);
    return () => {
      socket.off('graph-update', handleGraphUpdate);
      socket.off('sessions-update', debouncedFetchSessions);
      socket.off('alerts-update', debouncedFetchAlertCount);
      socket.off('span-added', handleSpanAdded);
    };
  }, [setNodes, setEdges, debouncedFetchSessions, debouncedFetchAlertCount]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const onNodeClick = (_: any, node: Node) => setSelectedNode(node);

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

      const matchHideNone = !hideNone || wf.severity !== 'none';

      const matchTime = (() => {
        if (timeRange === 'all') return true;
        const windowMs =
          timeRange === '1h'  ? 60 * 60 * 1000 :
          timeRange === '24h' ? 24 * 60 * 60 * 1000 :
          7 * 24 * 60 * 60 * 1000;
        return toMs(wf.startNano) >= Date.now() - windowMs;
      })();

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
          formatSpanName(wf.label).toLowerCase().includes(term) ||
          wf.reason.toLowerCase().includes(term)    ||
          wf.protocol.toLowerCase().includes(term)  ||
          wf.harness.toLowerCase().includes(term)   ||
          Object.values(wf.attributes).some(v => String(v).toLowerCase().includes(term))
        );
      })();

      return matchSeverity && matchHarness && matchSearch && matchHideNone && matchTime;
    });
  }, [workflows, filterMode, harnessFilter, search, activeSession, hideNone, timeRange]);

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

  const toggleBookmark = async () => {
    if (!selectedNode || selectedNode.id === 'agent') return;
    const spanId = selectedNode.id;
    const traceId = String((selectedNode.data as any).traceId ?? '');
    if (isBookmarked) {
      setIsBookmarked(false);
      await fetch(`/api/bookmarks/span/${encodeURIComponent(spanId)}`, { method: 'DELETE' }).catch(() => {});
    } else {
      setIsBookmarked(true);
      await fetch('/api/bookmarks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ spanId, traceId }),
      }).catch(() => {});
    }
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

  useEffect(() => {
    if (sessions.length === 0) {
      setConnectionStatus('setup');
      return;
    }
    setConnectionStatus('idle');
    let idleTimer: ReturnType<typeof setTimeout>;
    const resetIdle = () => {
      setConnectionStatus('live');
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => setConnectionStatus('idle'), 60_000);
    };
    socket.on('span-added', resetIdle);
    return () => {
      socket.off('span-added', resetIdle);
      clearTimeout(idleTimer);
    };
  }, [sessions.length]);

  return (
    <div className="w-full lg:w-screen min-h-dvh lg:h-screen flex flex-col overflow-x-hidden lg:overflow-hidden" style={{ background: 'var(--cs-bg-primary)', color: 'var(--cs-text-base)' }}>

      {/* ── Header ── */}
      <header className="h-11 flex items-center justify-between px-4 z-10 shrink-0" style={{
        borderBottom: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}>
        {/* Left cluster: logo + sparkline */}
        <div className="flex items-center gap-3">
          {/* Hamburger — opens contextual sidebar drawer (below lg only) */}
          <button
            onClick={() => { setDocsOpen(false); setSidebarOpen(true); }}
            className="lg:hidden -ml-1 inline-flex items-center justify-center w-11 h-11 rounded-lg transition-all"
            style={{ color: 'var(--cs-text-muted)' }}
            aria-label="Open sidebar"
            aria-expanded={sidebarOpen}
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: 'linear-gradient(135deg, var(--cs-accent), #009e7f)' }}>
              <Shield className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="font-display font-bold text-[13px] tracking-tight" style={{ color: 'var(--cs-text-base)' }}>ClaudeSec</span>
          </div>
          <div className="hidden lg:flex items-center gap-2 pl-3" style={{ borderLeft: '1px solid var(--cs-border)' }}>
            <ActivitySparkline />
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full" style={{ background: 'rgba(var(--cs-accent-rgb),0.08)' }}>
              <div className="w-1.5 h-1.5 rounded-full status-live" style={{ background: 'var(--cs-accent)' }} />
              <span className="text-[10px] font-mono font-semibold" style={{ color: 'var(--cs-accent)' }}>LIVE</span>
            </div>
          </div>
        </div>

        {/* Import status toast */}
        {importStatus && (
          <div className={`absolute top-14 left-1/2 -translate-x-1/2 px-4 py-2 rounded-lg text-xs font-medium z-50 shadow-lg backdrop-blur-md ${importStatus.ok ? 'bg-green-900/80 text-green-200 border border-green-700/50' : 'bg-red-900/80 text-red-200 border border-red-700/50'}`}>
            {importStatus.msg}
          </div>
        )}

        {/* Data load error — surfaced instead of an unhandled promise rejection */}
        {loadError && (
          <div className="absolute top-14 left-1/2 -translate-x-1/2 flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium z-50 shadow-lg backdrop-blur-md bg-red-900/80 text-red-200 border border-red-700/50">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            {loadError}
            <button
              onClick={() => setLoadError(null)}
              className="ml-1 p-0.5 rounded hover:bg-red-800/60 transition-colors"
              aria-label="Dismiss"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        )}

        {/* Right cluster: actions, grouped */}
        <div className="flex items-center gap-0.5">
          {/* Notification toggle */}
          <button
            onClick={requestNotifications}
            className="p-1.5 rounded-lg transition-all"
            style={{
              background: notifyEnabled ? 'rgba(var(--cs-accent-rgb),0.1)' : 'transparent',
              color: notifyEnabled ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
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
                    const params = activeSession ? `?session=${activeSession}` : '';
                    try {
                      const res = await fetch(`/api/graph/mermaid${params}`);
                      const text = await res.text();
                      await navigator.clipboard.writeText(text);
                      setMermaidCopy('copied');
                    } catch (err) {
                      console.warn('ClaudeSec: copy Mermaid failed', err);
                      setMermaidCopy('error');
                    }
                    // Keep the menu open briefly so the inline feedback is seen,
                    // then reset and close.
                    setTimeout(() => { setMermaidCopy('idle'); setShowExportMenu(false); }, 2000);
                  }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors hover:bg-slate-800/50" style={{ color: 'var(--cs-text-muted)' }}>
                  <Layers className="w-3.5 h-3.5" />
                  {mermaidCopy === 'copied' ? 'Copied!' : mermaidCopy === 'error' ? 'Copy failed' : 'Copy Mermaid'}
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

          {/* Theme picker */}
          <ThemeSwitcher theme={theme} onChange={setTheme} />

          {/* Docs */}
          <button
            onClick={() => setDocsOpen(true)}
            className="p-1.5 rounded-lg transition-all"
            style={{ color: docsOpen ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
            title="Documentation"
          >
            <HelpCircle className="w-3.5 h-3.5" />
          </button>

        </div>
      </header>

      {/* Live Activity floating panel */}
      <LiveActivityPanel open={liveActivityOpen} onClose={() => setLiveActivityOpen(false)} />

      {/* Docs command palette (⌘K) */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onSelect={slug => {
          window.location.hash = '#/docs/' + slug;
          setDocsOpen(true);
          setPaletteOpen(false);
        }}
      />

      <div className="flex-1 flex lg:overflow-hidden min-h-0 relative">

        {/* ── Category Rail (hidden below md — replaced by bottom tab bar) ── */}
        <CategoryNav active={activeCategory} onChange={handleCategoryChange} alertCount={alertCount} onOpenDocs={() => setDocsOpen(true)} docsActive={docsOpen} />

        {/* Drawer scrim — tap to close (below lg only) */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/50 z-30 lg:hidden"
            onClick={() => setSidebarOpen(false)}
            aria-hidden="true"
          />
        )}

        {docsOpen ? (
          <DocsView onClose={() => setDocsOpen(false)} />
        ) : (
        <>
        {/* ── Contextual Sidebar (static in-row at >=lg, off-canvas drawer below) ── */}
        <ContextSidebar
          category={activeCategory}
          alertCount={alertCount}
          activeTab={activeTab}
          onTabChange={(tab) => handleTabChange(tab as Tab)}
          timeRange={timeRange}
          onTimeRangeChange={setTimeRange}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          observeContent={<>

          {/* Connection Status */}
          <div className="px-3 py-2 flex items-center gap-2 shrink-0" style={{ borderBottom: '1px solid var(--cs-border)' }}>
            <span className={`w-2 h-2 rounded-full shrink-0 ${
              connectionStatus === 'live' ? 'bg-green-500 status-live' :
              connectionStatus === 'idle' ? 'bg-amber-500' :
              'bg-red-500'
            }`} />
            <span className="text-[11px] font-mono" style={{
              color: connectionStatus === 'live' ? 'var(--cs-accent)' :
                     connectionStatus === 'idle' ? '#f59e0b' :
                     '#ef4444'
            }}>
              {connectionStatus === 'live' ? 'Live' :
               connectionStatus === 'idle' ? 'Idle' :
               'Setup needed'}
            </span>
          </div>

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
                  ? { background: 'rgba(var(--cs-accent-rgb),0.12)', color: 'var(--cs-accent)', border: '1px solid rgba(var(--cs-accent-rgb),0.2)' }
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
                        ? { background: 'rgba(var(--cs-accent-rgb),0.1)', color: 'var(--cs-accent)', borderLeftColor: 'var(--cs-accent)' }
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
                        // Align badge colors with the letter-grade bands
                        // (90/75/60/40): green = A (>=90), yellow = B/C (>=60),
                        // red = D/F (<60). Previously 80/50, which disagreed.
                        className={`shrink-0 text-[11px] font-mono font-bold px-1 rounded ${
                          s.healthScore >= 90 ? 'text-green-400 bg-green-900/30'
                            : s.healthScore >= 60 ? 'text-yellow-400 bg-yellow-900/30'
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
                <span style={{ color: 'var(--cs-accent)' }}>{counts.ok}<span style={{ opacity: 0.5 }}>ok</span></span>
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
                          <span className={`text-[11px] font-semibold truncate ${c.text}`}>{formatSpanName(wf.label)}</span>
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
        <div className="flex-1 flex flex-col min-h-0 min-w-0 pb-[calc(56px+env(safe-area-inset-bottom))] md:pb-0">

          {/* Sub-tab strip — filtered by active category */}
          <div className="flex items-center gap-0.5 px-3 shrink-0 overflow-x-auto flex-nowrap cs-scroll-x" style={{
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
                  color: activeTab === tab.id ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
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
            <>
            {timelineIntroShown && (
              <div className="mx-4 mt-3 mb-1 px-4 py-3 rounded-xl text-xs leading-relaxed flex items-start gap-3" style={{
                background: 'rgba(var(--cs-accent-rgb),0.06)',
                border: '1px solid rgba(var(--cs-accent-rgb),0.15)',
                color: 'var(--cs-text-muted)',
              }}>
                <Activity className="w-4 h-4 shrink-0 mt-0.5" style={{ color: 'var(--cs-accent)' }} />
                <div>
                  <strong style={{ color: 'var(--cs-text-base)' }}>How to read the timeline:</strong>{' '}
                  Spans are individual operations (LLM calls, tool uses, bash commands).
                  Sessions group related spans by trace ID.
                  Severity: <span className="text-green-400">Low</span> = audit trail,{' '}
                  <span className="text-orange-400">Medium</span> = suspicious pattern,{' '}
                  <span className="text-red-400">High</span> = active threat.
                </div>
                <button
                  onClick={() => {
                    setTimelineIntroShown(false);
                    localStorage.setItem('claudesec-timeline-intro-dismissed', 'true');
                  }}
                  className="shrink-0 hover:opacity-70 transition-opacity"
                  style={{ color: 'var(--cs-text-faint)' }}
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            {graphWindow && !activeSession && (
              <p className="mx-4 mt-1 mb-1 text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
                Showing the most recent {graphWindow.shown.toLocaleString()} events.
                Older events remain available via Search and Sessions.
              </p>
            )}
            <Timeline
              workflows={visibleWorkflows}
              onSelect={onTimelineSelect}
              selectedId={timelineSelected ?? undefined}
            />
            {selectedNode && selectedNode.id !== 'agent' && (
              <div className="mx-4 mb-3 px-4 py-2.5 rounded-xl flex items-center gap-3" style={{
                background: 'var(--cs-bg-surface)',
                border: '1px solid var(--cs-border)',
              }}>
                <span className="text-[11px] font-semibold truncate" style={{ color: 'var(--cs-text-base)' }}>
                  {formatSpanName(String(selectedNode.data.label ?? selectedNode.id))}
                </span>
                <code className="text-[11px] font-mono truncate" style={{ color: 'var(--cs-text-faint)' }}>
                  {selectedNode.id}
                </code>
                <button
                  onClick={toggleBookmark}
                  className="ml-auto shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium transition-colors"
                  style={{
                    color: isBookmarked ? 'var(--cs-accent)' : 'var(--cs-text-muted)',
                    border: '1px solid var(--cs-border)',
                    background: isBookmarked ? 'rgba(var(--cs-accent-rgb),0.08)' : 'transparent',
                  }}
                  title={isBookmarked ? 'Remove bookmark' : 'Bookmark this span'}
                >
                  <Bookmark className="w-3.5 h-3.5" fill={isBookmarked ? 'currentColor' : 'none'} />
                  {isBookmarked ? 'Bookmarked' : 'Bookmark'}
                </button>
              </div>
            )}
            </>
          )}

          {/* Orchestration view */}
          {activeTab === 'orchestration' && <OrchestrationTab />}

          {/* Alerts view */}
          {activeTab === 'alerts' && <AlertsTab />}

          {/* Rules view */}
          {activeTab === 'rules' && <RulesTab />}

          {/* Enforcement view */}
          {activeTab === 'enforce' && <EnforceTab />}

          {/* MCP / skill static scanner view */}
          {activeTab === 'mcpscan' && <McpScanTab />}

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
              onSelectSession={(traceId, spanId) => {
                setActiveSession(traceId);
                // Use handleTabChange (not setActiveTab) so the category rail,
                // sub-tabs and sidebar stay in sync — otherwise the rail keeps
                // showing 'review' and the jump looks like a no-op.
                handleTabChange('timeline');
                // For a span bookmark, remember the span so it gets selected and
                // highlighted once the scoped graph for this session loads.
                setPendingSpanSelect(spanId ?? null);
              }}
            />
          )}
        </div>
        </>
        )}
      </div>

      {/* ── Footer (hidden below md — replaced by bottom tab bar) ── */}
      <footer className="h-7 px-4 hidden md:flex items-center justify-between z-10 shrink-0 gap-3 overflow-hidden" style={{
        borderTop: '1px solid var(--cs-border)',
        background: 'var(--cs-bg-surface)',
      }}>
        <div className="flex items-center gap-2 shrink-0">
          <Terminal className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} />
          <span className="text-[11px] font-mono hidden sm:inline" style={{ color: 'var(--cs-text-faint)' }}>
            Local watcher <span style={{ color: 'var(--cs-accent)', opacity: 0.7 }}>+</span> OTLP :3000
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
              <span className="w-1.5 h-1.5 rounded-full shrink-0 status-live" style={{ background: 'var(--cs-accent)' }} />
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
                      {(() => { const n = formatSpanName(sp.name); return n.length > 24 ? n.slice(0, 24) + '...' : n; })()}
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

      {/* ── Bottom tab bar (below md only) — 5 categories ── */}
      <nav
        className="md:hidden fixed bottom-0 inset-x-0 z-20 flex items-stretch pb-[env(safe-area-inset-bottom)]"
        style={{ borderTop: '1px solid var(--cs-border)', background: 'var(--cs-bg-surface)' }}
        aria-label="Primary"
      >
        {CATEGORIES.map(cat => {
          const isActive = !docsOpen && activeCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => { setDocsOpen(false); setSidebarOpen(false); handleCategoryChange(cat.id); }}
              className="category-btn relative flex-1 flex flex-col items-center justify-center gap-0.5 min-h-[56px] py-1.5"
              style={{ color: isActive ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
              aria-current={isActive ? 'page' : undefined}
            >
              {isActive && (
                <span className="absolute top-0 left-1/2 -translate-x-1/2 w-8 h-[2px] rounded-b-full" style={{ background: 'var(--cs-accent)' }} />
              )}
              {cat.icon}
              <span className="text-[10px] font-medium tracking-wide leading-none">{cat.label}</span>
              {cat.id === 'detect' && alertCount > 0 && (
                <span className="absolute top-1.5 right-[calc(50%-1.25rem)] min-w-[15px] h-[15px] px-1 text-[9px] font-bold rounded-full flex items-center justify-center leading-none bg-rose-500 text-white">
                  {alertCount > 99 ? '99+' : alertCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );
}
