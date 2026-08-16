import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
// Build-time version from package.json — keeps the footer in lockstep with
// releases instead of a hand-maintained string that drifts.
import { version as appVersion } from '../package.json';
import { useNodesState, type Node, type Edge } from '@xyflow/react';
import {
  AlertTriangle, Activity, Terminal, Search, Download, X,
  FileText, Zap, Bell, BellOff, Upload, Server, Layers,
  HelpCircle, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { socket } from './socket';
import { DocsView } from './docs/DocsView';
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
import { ComparePanel } from './ComparePanel';
import { SearchTab } from './SearchTab';
import { ProcessesTab } from './ProcessesTab';
import { ThemeSwitcher, LIGHT_THEMES, type ThemeId } from './ThemeSwitcher';
import { BookmarksTab } from './BookmarksTab';
import { GovernTab } from './GovernTab';
import { LiveActivityPanel } from './LiveActivityPanel';
import { AnimatePresence } from 'motion/react';
import type { Severity } from './shared/types';
import { applyLayout } from './lib/graphLayout';
import { useDebouncedCallback } from './lib/useDebouncedCallback';
import { toMs, formatSpanName } from './lib/format';
import { useRouteNav } from './lib/useRouteNav';
import { Timeline } from './Timeline';
import { Button } from './components/ui/button';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from './components/ui/dropdown-menu';
import { AppShell } from './shell/AppShell';
import { FilterBar, type FacetOption } from './shell/FilterBar';
import { CommandPalette } from './shell/CommandPalette';
import { useFilters, graphQueryParams } from './shell/filterState';
import type { DetailTarget } from './shell/DetailPane';
import type { Category } from './CategoryNav';
import {
  type Tab, type Workflow, type SessionLabel, type Session, type TickerSpan, type Repo,
  CATEGORY_TABS, UNKNOWN_REPO, repoLabel, categoryForTab,
  HARNESS_COLORS, HARNESS_NAMES,
} from './dashboardTypes';

// Tabs that operate on the span stream, and therefore sit under the filter bar.
// Everything else (rules, settings, costs …) owns its own controls.
const FILTERABLE_TABS: Tab[] = ['timeline'];

const initialNodes: Node[] = [
  { id: 'agent', data: { label: 'AI Agent' }, position: { x: 0, y: 0 }, type: 'input' },
];

export default function App() {
  // ── Graph state ───────────────────────────────────────────────────────────
  const [nodes, setNodes] = useNodesState(initialNodes);
  // Edges are consumed as layout input only — they position the nodes and are
  // never drawn, so there is no edge state to keep.

  // When the unscoped graph shows only the most-recent N spans (older spans stay
  // searchable, never deleted), the server reports a window so we can say so.
  const [graphWindow, setGraphWindow] = useState<{ shown: number; total: number } | null>(null);

  // ── Navigation ────────────────────────────────────────────────────────────
  // Category/tab/docs come from the URL path; filters come from the URL query.
  // Both live in the address bar so a view is deep-linkable, and neither is
  // duplicated in component state where the two could drift apart.
  const { activeTab, activeCategory, docsOpen, docsSlug, openDocs, closeDocs } = useRouteNav();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Navigating between tabs carries the filter query along: a tab change is a
  // change of view, not a reset of what you were looking at.
  const withFilters = useCallback((path: string) => {
    const qs = searchParams.toString();
    return qs ? `${path}?${qs}` : path;
  }, [searchParams]);

  // `extraParams` lets a caller land on a tab pre-filtered — e.g. a Govern
  // policy's "View in Alert log" jumping to Alerts scoped to exactly the rule
  // labels that back it, rather than the full unfiltered log. It merges onto
  // (not replaces) whatever is already in the query string, same as every
  // other filter write in the shell, so the destination tab's own params
  // (severity, repo, …) survive the hop.
  const navigateTab = useCallback((tab: Tab, extraParams?: Record<string, string[]>) => {
    const path = `/${categoryForTab(tab)}/${tab}`;
    if (!extraParams) { navigate(withFilters(path)); return; }
    const qs = new URLSearchParams(searchParams);
    for (const [key, values] of Object.entries(extraParams)) {
      qs.delete(key);
      for (const v of values) qs.append(key, v);
    }
    const s = qs.toString();
    navigate(s ? `${path}?${s}` : path);
  }, [navigate, withFilters, searchParams]);

  const navigateCategory = useCallback((category: Category) => {
    const first = CATEGORY_TABS[category]?.[0]?.id ?? 'timeline';
    navigate(withFilters(`/${category}/${first}`));
  }, [navigate, withFilters]);

  const { filters, active: filtersActive, toggle, applyView } = useFilters();
  // Read via refs inside the socket effect below, which registers its handlers
  // once (see the empty-ish dep array on that effect) and would otherwise close
  // over the filters/session in place at mount instead of the current ones.
  const filtersRef = useRef(filters);
  useEffect(() => { filtersRef.current = filters; }, [filters]);
  const filtersActiveRef = useRef(filtersActive);
  useEffect(() => { filtersActiveRef.current = filtersActive; }, [filtersActive]);

  const [paletteOpen, setPaletteOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
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

  // ── Data state ────────────────────────────────────────────────────────────
  const [workflows, setWorkflows]           = useState<Workflow[]>([]);
  const [sessions, setSessions]             = useState<Session[]>([]);
  const [repos, setRepos]                   = useState<Repo[]>([]);
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

  // ── Session rename / notes ────────────────────────────────────────────────
  const [editingSession, setEditingSession] = useState<string | null>(null);
  const [editName, setEditName]             = useState('');
  const [notesSession, setNotesSession]     = useState<string | null>(null);
  const [notesText, setNotesText]           = useState('');

  // A Settings toggle, not a filter: when on, clean spans never enter the list
  // at all, so the severity scale in the bar counts only what could matter.
  const [hideNone, setHideNone] = useState(() => localStorage.getItem('claudesec.hideNone') === 'true');
  useEffect(() => {
    const sync = () => setHideNone(localStorage.getItem('claudesec.hideNone') === 'true');
    window.addEventListener('claudesec:hideNoneChange', sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener('claudesec:hideNoneChange', sync);
      window.removeEventListener('storage', sync);
    };
  }, []);

  // Track whether the DB currently holds synthetic demo sessions. Refreshed when
  // sessions change so the banner appears on seed and disappears once cleared.
  const [demoSessions, setDemoSessions] = useState(0);
  const [demoBannerDismissed, setDemoBannerDismissed] = useState(false);
  useEffect(() => {
    const refresh = () => {
      fetch('/api/health')
        .then(r => r.json())
        .then(d => setDemoSessions(d.demoSessions ?? 0))
        .catch(() => {});
    };
    refresh();
    socket.on('sessions-update', refresh);
    return () => { socket.off('sessions-update', refresh); };
  }, []);

  // ── Enforcement standing-state (status bar indicator) ─────────────────────
  // Tri-state standing posture — honest about what actually blocks:
  //   'enforce' → hook registered AND enforce mode: every high-severity match blocks.
  //   'floor'   → hook registered but monitor mode: the always-on catastrophic floor,
  //               protected paths, and read-protection still block; rule matches only log.
  //   'off'     → hook not registered: nothing is blocked before it runs.
  const [enforceState, setEnforceState] = useState<'enforce' | 'floor' | 'off' | null>(null);
  const [enforceMode, setEnforceMode] = useState<'enforce' | 'monitor' | null>(null);
  useEffect(() => {
    const refreshEnforce = () => {
      fetch('/api/enforce/config')
        .then(r => r.json())
        .then((c: { mode?: string; effectiveMode?: string; hookStatus?: { installed?: string } }) => {
          const effective = c.effectiveMode ?? c.mode;
          const registered = c.hookStatus?.installed === 'yes';
          setEnforceMode(c.mode === 'enforce' ? 'enforce' : 'monitor');
          setEnforceState(!registered ? 'off' : effective === 'enforce' ? 'enforce' : 'floor');
        })
        .catch(() => { setEnforceState(null); setEnforceMode(null); });
    };
    refreshEnforce();
    socket.on('enforce-config', refreshEnforce);
    return () => { socket.off('enforce-config', refreshEnforce); };
  }, []);

  const toggleEnforceMode = useCallback(() => {
    const next = enforceMode === 'enforce' ? 'monitor' : 'enforce';
    fetch('/api/enforce/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: next }),
    }).then(() => setEnforceMode(next)).catch(() => {});
  }, [enforceMode]);

  // ── Notification state ────────────────────────────────────────────────────
  const [notifyEnabled, setNotifyEnabled] = useState(false);
  const notifyEnabledRef = useRef(false);
  const seenHighIds = useRef<Set<string>>(new Set());

  const [alertCount, setAlertCount] = useState(0);

  // ── Import / export ───────────────────────────────────────────────────────
  const importInputRef = useRef<HTMLInputElement>(null);
  const [importStatus, setImportStatus] = useState<{ msg: string; ok: boolean } | null>(null);
  // 'copied' / 'error' shows for ~2s on the menu item, then resets to idle.
  const [mermaidCopy, setMermaidCopy] = useState<'idle' | 'copied' | 'error'>('idle');

  const [liveActivityOpen, setLiveActivityOpen] = useState(false);
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

  // ── Session compare ───────────────────────────────────────────────────────
  const [compareIds, setCompareIds] = useState<[string, string] | null>(null);
  // When exactly one session is Ctrl-clicked, hold it here until the 2nd pick
  const [comparePending, setComparePending] = useState<string | null>(null);

  // ── Live span ticker ──────────────────────────────────────────────────────
  const [tickerSpans, setTickerSpans] = useState<TickerSpan[]>([]);
  const tickerTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [tickerQuiet, setTickerQuiet] = useState(false);

  const seenIds = useRef<Set<string>>(new Set());
  const prevWorkflows = useRef<Workflow[]>([]);
  // Signature of the last graph we laid out (sorted node + edge ids). dagre
  // layout is the expensive step on every graph-update; skipping it when the
  // structure is unchanged keeps a stream of identical broadcasts cheap.
  const lastLayoutSig = useRef<string>('');

  // ── Data sync ─────────────────────────────────────────────────────────────

  function syncWorkflows(rawNodes: Node[]) {
    const spans = rawNodes.filter(n => !(n.data as any).isRoot && n.id !== 'agent');
    // A span keeps the wall-clock time it was FIRST seen, so the list does not
    // re-stamp itself on every broadcast. Index the previous pass by id once:
    // a linear scan per span turned a 2,000-span window into ~4M comparisons
    // per graph-update, and the server can broadcast several times a second.
    const prevTimestamps = new Map<string, string>();
    // First-wins, matching the `find` this replaced — ids are unique in practice,
    // but the lookup must not change answers if that ever stops being true.
    for (const w of prevWorkflows.current) if (!prevTimestamps.has(w.id)) prevTimestamps.set(w.id, w.timestamp);
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
        ? (prevTimestamps.get(n.id) ?? new Date().toLocaleTimeString())
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

  const fetchRepos = () =>
    fetch('/api/repos').then(r => r.json()).then(({ repos: r }) => {
      setRepos(r ?? []);
    }).catch((err: unknown) => {
      console.warn('ClaudeSec: failed to load repos', err);
    });

  const fetchAlertCount = () =>
    fetch('/api/alerts?limit=1')
      .then(r => r.json())
      .then(({ total }: { total: number }) => setAlertCount(total ?? 0))
      .catch(() => {});

  // Lay out the graph, but skip the layout pass when the node/edge set is
  // unchanged since the last render — a no-op broadcast then costs nothing
  // beyond building the signature.
  const layoutGraph = (n: Node[], e: Edge[]) => {
    const sig = `${n.map(node => node.id).sort().join(',')}|${e.map(edge => edge.id).sort().join(',')}`;
    if (sig === lastLayoutSig.current) return;
    lastLayoutSig.current = sig;
    setNodes(applyLayout(n, e, 'radial'));
  };

  // Collapse bursts of socket events into a single trailing refetch (~400ms) so a
  // batch of broadcasts does not stampede the API with one call per event.
  // The anomaly sweep emits `sessions-update` every 2.5s whether or not anything
  // changed, so a 400ms debounce coalesced nothing — one idle tab pulled the full
  // session list twelve times per thirty seconds (2.4MB each), and every click the
  // user made queued behind that on the server's single thread. These two are the
  // heavy fetches, so they keep the short debounce for genuine bursts but cap the
  // refresh at once per 15s. The cap, not a longer debounce, is the fix: widening
  // the window past 2.5s would restart the timer on every tick and never fire.
  // The list is a directory, not a live feed, and spans still stream in real time
  // over `graph-update`. The alert count stays responsive — small query, quieter
  // event.
  const debouncedFetchSessions   = useDebouncedCallback(fetchSessions, 400, 15_000);
  const debouncedFetchRepos      = useDebouncedCallback(fetchRepos, 400, 15_000);
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
      // Treat everything already on screen as seen. Turning notifications on is a
      // request to hear about what happens NEXT — without this the first update
      // replays the entire window as a burst of desktop alerts.
      for (const wf of workflows) {
        if (wf.severity === 'high' || wf.severity === 'critical') seenHighIds.current.add(wf.id);
      }
      setNotifyEnabled(true);
      notifyEnabledRef.current = true;
    }
  };

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

  // Initial load — and reload whenever a filter changes, so a cold load of
  // e.g. #/observe/timeline?repo=… fetches that repo's spans directly instead
  // of fetching the newest 2,000 spans globally and filtering them away to
  // nothing in the browser (the bug this replaces: a repo the newest 2,000
  // spans never reached looked "broken" rather than merely unfetched).
  useEffect(() => {
    const qs = graphQueryParams(filters, activeSession).toString();
    fetch(`/api/graph${qs ? `?${qs}` : ''}`)
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
  }, [activeSession, filters]);

  // Sessions/repos/alerts are independent of the filtered graph fetch above —
  // scoped only to the active session, not to every filter axis — so they stay
  // a separate effect rather than re-firing on every filter change too.
  useEffect(() => {
    fetchSessions();
    fetchRepos();
    fetchAlertCount();
  }, [activeSession]);

  useEffect(() => { prevWorkflows.current = workflows; }, [workflows]);

  // Resolve a pending span-bookmark jump: once the scoped graph has loaded and
  // `nodes` contains the target span, select it and clear the pending marker.
  useEffect(() => {
    if (!pendingSpanSelect) return;
    const target = nodes.find(n => n.id === pendingSpanSelect);
    if (target) {
      setSelectedNode(target);
      setPendingSpanSelect(null);
    }
  }, [pendingSpanSelect, nodes]);

  // Socket events
  useEffect(() => {
    const handleGraphUpdate = ({ nodes: n, edges: e, windowed, shown, total }: { nodes: Node[]; edges: Edge[]; windowed?: boolean; shown?: number; total?: number }) => {
      // The broadcast payload is always the unfiltered, most-recent-N-spans
      // graph (see emitGraphUpdateThrottled in server/index.ts) — it exists so
      // an unfiltered dashboard doesn't need a round trip per update. A client
      // scoped to a session or any filter axis would have that view clobbered
      // by it, so instead re-fetch the *filtered* graph here. Read session and
      // filters via refs — this handler is registered once (see the effect's
      // dep array below) and would otherwise close over whatever was current
      // at mount instead of what's in view now.
      const scopedSession = activeSessionRef.current;
      const isFiltered = Boolean(scopedSession) || filtersActiveRef.current;
      if (isFiltered) {
        const qs = graphQueryParams(filtersRef.current, scopedSession).toString();
        fetch(`/api/graph${qs ? `?${qs}` : ''}`)
          .then(r => r.json())
          .then(({ nodes: sn, edges: se, windowed: sw, shown: ss, total: st }: { nodes: Node[]; edges: Edge[]; windowed?: boolean; shown?: number; total?: number }) => {
            layoutGraph(sn, se);
            syncWorkflows(sn);
            // A single session always loads in full; a filter (without a
            // session) can still exceed GRAPH_LIMIT, so honor its own windowing.
            setGraphWindow(scopedSession ? null : (sw ? { shown: ss ?? sn.length, total: st ?? 0 } : null));
            setLoadError(null);
          })
          .catch((err: unknown) => {
            console.warn('ClaudeSec: failed to refresh filtered graph', err);
            setLoadError('Failed to refresh activity graph');
          });
        return;
      }
      layoutGraph(n, e);
      syncWorkflows(n);
      setGraphWindow(windowed ? { shown: shown ?? n.length, total: total ?? 0 } : null);

      // Desktop notifications for new HIGH and CRITICAL severity spans
      // (critical is the higher exfiltration tier — it must notify too).
      if (notifyEnabledRef.current) {
        const isAlerting = (s: unknown) => s === 'high' || s === 'critical';
        const highSpans = n.filter(
          node => isAlerting((node.data as any).severity) && !seenHighIds.current.has(node.id),
        );
        highSpans.forEach(node => {
          const label = String(node.data.label ?? '');
          const rule  = String((node.data as any).attributes?.['claudesec.threat.rule'] ?? '');
          // Some browsers throw on `new Notification(...)` (e.g. permission
          // revoked between checks, or constructor blocked on mobile). Never let
          // a notification failure break the graph-update handler.
          try {
            const sevLabel = (node.data as any).severity === 'critical' ? 'CRITICAL' : 'HIGH';
            new Notification(`ClaudeSec — ${sevLabel} Alert`, {
              body: `${label}${rule ? ': ' + rule : ''}`,
              tag:  node.id,
            });
          } catch (err) {
            console.warn('ClaudeSec: desktop notification failed', err);
          }
          seenHighIds.current.add(node.id);
        });
        // Also mark already-known high/critical spans so we don't re-fire on later updates
        n.filter(node => isAlerting((node.data as any).severity))
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
    socket.on('sessions-update', debouncedFetchRepos);
    socket.on('alerts-update', debouncedFetchAlertCount);
    socket.on('span-added', handleSpanAdded);
    return () => {
      socket.off('graph-update', handleGraphUpdate);
      socket.off('sessions-update', debouncedFetchRepos);
      socket.off('sessions-update', debouncedFetchSessions);
      socket.off('alerts-update', debouncedFetchAlertCount);
      socket.off('span-added', handleSpanAdded);
    };
  }, [setNodes, debouncedFetchSessions, debouncedFetchRepos, debouncedFetchAlertCount]);

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

  // ── Session mutations ─────────────────────────────────────────────────────

  const patchSession = useCallback(async (traceId: string, body: Record<string, unknown>) => {
    await fetch(`/api/sessions/${encodeURIComponent(traceId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).catch(() => {});
    fetchSessions();
  }, []);

  const commitRename = useCallback(() => {
    if (!editingSession || !editName.trim()) { setEditingSession(null); return; }
    const id = editingSession;
    setEditingSession(null);
    patchSession(id, { name: editName.trim() });
  }, [editingSession, editName, patchSession]);

  const handleCompare = useCallback((traceId: string) => {
    setComparePending(pending => {
      if (!pending) return traceId;
      if (pending !== traceId) { setCompareIds([pending, traceId]); }
      return null;
    });
  }, []);

  // ── Derived state ─────────────────────────────────────────────────────────

  // Spans don't carry a repo of their own, but sessions do (one repo per trace).
  // Build a traceId → repo lookup so the repository filter can scope the span
  // list by the repo of each span's owning session. A session's repo column is
  // GROUP_CONCAT'd on a NEWLINE (a path can legally contain a comma), so a
  // multi-value string is treated as membership below.
  const repoByTrace = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of sessions) m.set(s.traceId, s.repo ?? UNKNOWN_REPO);
    return m;
  }, [sessions]);

  // One predicate per filter axis. They are split out so a facet's count can be
  // computed with that facet's own predicate left off — a count of 0 next to an
  // option you have already selected is worse than no count at all.
  const predicates = useMemo(() => {
    const windowMs =
      filters.time === '1h'  ? 60 * 60 * 1000 :
      filters.time === '24h' ? 24 * 60 * 60 * 1000 :
      filters.time === '7d'  ? 7 * 24 * 60 * 60 * 1000 : 0;
    const term = filters.q.trim().toLowerCase();
    return {
      session: (wf: Workflow) => !activeSession || wf.traceId === activeSession,
      severity: (wf: Workflow) => filters.sev.length === 0 || filters.sev.includes(wf.severity),
      harness: (wf: Workflow) => filters.harness.length === 0 || filters.harness.includes(wf.harness),
      repo: (wf: Workflow) => {
        if (filters.repo.length === 0) return true;
        const traceRepo = repoByTrace.get(wf.traceId) ?? UNKNOWN_REPO;
        const owned = traceRepo.split('\n');
        return filters.repo.some(r => traceRepo === r || owned.includes(r));
      },
      time: (wf: Workflow) => !windowMs || toMs(wf.startNano) >= Date.now() - windowMs,
      hideNone: (wf: Workflow) => !hideNone || wf.severity !== 'none',
      search: (wf: Workflow) => {
        if (!term) return true;
        if (term.includes('=')) {
          const eqIdx = term.indexOf('=');
          const key = term.slice(0, eqIdx).trim();
          const val = term.slice(eqIdx + 1).trim();
          return String(wf.attributes[key] ?? '').toLowerCase().includes(val);
        }
        return (
          formatSpanName(wf.label).toLowerCase().includes(term) ||
          wf.reason.toLowerCase().includes(term) ||
          wf.protocol.toLowerCase().includes(term) ||
          wf.harness.toLowerCase().includes(term) ||
          Object.values(wf.attributes).some(v => String(v).toLowerCase().includes(term))
        );
      },
    };
  }, [filters, activeSession, repoByTrace, hideNone]);

  /** Everything the non-facet filters let through — the base for facet counts. */
  const base = useMemo(
    () => workflows.filter(wf =>
      predicates.session(wf) && predicates.time(wf) && predicates.search(wf) && predicates.hideNone(wf)),
    [workflows, predicates],
  );

  const visibleWorkflows = useMemo(
    () => base.filter(wf => predicates.severity(wf) && predicates.harness(wf) && predicates.repo(wf)),
    [base, predicates],
  );

  const severityCounts = useMemo(() => {
    const out: Record<Severity, number> = { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const wf of base) {
      if (predicates.harness(wf) && predicates.repo(wf)) out[wf.severity] += 1;
    }
    return out;
  }, [base, predicates]);

  const harnessOptions = useMemo<FacetOption[]>(() => {
    const counts = new Map<string, number>();
    for (const wf of base) {
      if (predicates.severity(wf) && predicates.repo(wf)) {
        counts.set(wf.harness, (counts.get(wf.harness) ?? 0) + 1);
      }
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: HARNESS_NAMES[value] ?? value, count }));
  }, [base, predicates]);

  const repoOptions = useMemo<FacetOption[]>(() => {
    const counts = new Map<string, number>();
    for (const wf of base) {
      if (!predicates.severity(wf) || !predicates.harness(wf)) continue;
      const repo = repoByTrace.get(wf.traceId) ?? UNKNOWN_REPO;
      for (const key of repo.split('\n')) counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return repos.map(r => ({
      value: r.repo,
      label: repoLabel(r.repo),
      count: counts.get(r.repo) ?? 0,
      alert: r.threatHigh > 0,
    }));
  }, [base, predicates, repoByTrace, repos]);

  // ── Detail pane target ────────────────────────────────────────────────────
  const detail = useMemo<DetailTarget | null>(() => {
    if (!selectedNode || selectedNode.id === 'agent') return null;
    const data = selectedNode.data as any;
    return {
      spanId: selectedNode.id,
      traceId: String(data.traceId ?? ''),
      label: String(data.label ?? selectedNode.id),
      severity: (data.severity ?? 'none') as Severity,
      reason: String(data.reason ?? ''),
      attributes: (data.attributes ?? {}) as Record<string, unknown>,
    };
  }, [selectedNode]);

  const onTimelineSelect = (id: string) => {
    const n = nodes.find(node => node.id === id);
    if (n) setSelectedNode(n);
  };

  // Escape closes whatever is floating, innermost first.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (compareIds) setCompareIds(null);
      else if (selectedNode) setSelectedNode(null);
      else if (liveActivityOpen) setLiveActivityOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [compareIds, selectedNode, liveActivityOpen]);

  // ── Render ────────────────────────────────────────────────────────────────

  const headerActions = (
    <>
      <span className="mr-2 hidden 2xl:flex"><ActivitySparkline /></span>
      <Button
        variant="ghost"
        size="icon-sm"
        onClick={requestNotifications}
        title={notifyEnabled ? 'Notifications enabled' : 'Enable desktop notifications'}
        style={{ color: notifyEnabled ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
      >
        {notifyEnabled ? <Bell /> : <BellOff />}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" style={{ color: 'var(--cs-text-muted)' }}>
            <Download className="size-3" /> Export
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuItem asChild>
            <label className="cursor-pointer">
              <Upload className="size-3.5" /> Import JSON
              <input ref={importInputRef} type="file" accept=".json,application/json" className="hidden" onChange={handleImportFile} />
            </label>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => window.open('/api/export', '_blank')}>
            <Download className="size-3.5" /> Export JSON
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => window.open('/api/export/csv', '_blank')}>
            <FileText className="size-3.5" /> Export CSV
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={async e => {
              // Keep the menu open briefly so the inline result is readable.
              e.preventDefault();
              const params = activeSession ? `?session=${activeSession}` : '';
              try {
                const res = await fetch(`/api/graph/mermaid${params}`);
                await navigator.clipboard.writeText(await res.text());
                setMermaidCopy('copied');
              } catch (err) {
                console.warn('ClaudeSec: copy Mermaid failed', err);
                setMermaidCopy('error');
              }
              setTimeout(() => setMermaidCopy('idle'), 2000);
            }}
          >
            <Layers className="size-3.5" />
            {mermaidCopy === 'copied' ? 'Copied!' : mermaidCopy === 'error' ? 'Copy failed' : 'Copy Mermaid'}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => window.open(`/api/graph/dot${activeSession ? `?session=${activeSession}` : ''}`, '_blank')}>
            <Layers className="size-3.5" /> Download .dot
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => window.open('/api/collector-config', '_blank')}>
            <Server className="size-3.5" /> Collector Config
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Button
        variant="ghost"
        size="icon-sm"
        onClick={() => setLiveActivityOpen(v => !v)}
        title="Live agent activity"
        style={{ color: liveActivityOpen ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
      >
        <Zap />
      </Button>

      <ThemeSwitcher theme={theme} onChange={setTheme} />

      <Button
        variant="ghost"
        size="icon-sm"
        onClick={() => openDocs(docsSlug ?? '')}
        title="Documentation"
        style={{ color: docsOpen ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
      >
        <HelpCircle />
      </Button>
    </>
  );

  const statusBar = (
    <footer
      className="hidden h-7 shrink-0 items-center gap-3 overflow-hidden px-3 md:flex"
      style={{ borderTop: '1px solid var(--cs-rule)', background: 'var(--cs-bg-surface)' }}
    >
      <span className="flex shrink-0 items-center gap-2">
        <Terminal className="size-3" style={{ color: 'var(--cs-text-faint)' }} />
        <span className="hidden font-mono text-[11px] sm:inline" style={{ color: 'var(--cs-text-faint)' }}>
          Local watcher + OTLP :{window.location.port || (window.location.protocol === 'https:' ? '443' : '80')}
        </span>
        <span
          className="rounded px-1.5 py-0.5 font-mono text-[11px]"
          style={{ color: 'var(--cs-text-muted)', background: 'var(--cs-bg-raised)' }}
        >
          {sessions.length} sessions
        </span>
        <span className="flex items-center gap-1.5 font-mono text-[11px]" style={{
          color: connectionStatus === 'live' ? 'var(--cs-accent)'
            : connectionStatus === 'idle' ? 'var(--cs-sev-medium-fg)' : 'var(--cs-sev-critical-fg)',
        }}>
          <span className="size-1.5 rounded-full" style={{ background: 'currentColor' }} />
          {connectionStatus === 'live' ? 'Live' : connectionStatus === 'idle' ? 'Idle' : 'Setup needed'}
        </span>
      </span>

      <span className="flex min-w-0 flex-1 items-center gap-1.5 overflow-hidden">
        {tickerSpans.length > 0 && !tickerQuiet ? (
          tickerSpans.slice(0, 3).map((sp, i) => (
            <span key={sp.spanId} className="flex shrink-0 items-center gap-1 font-mono text-[11px]" style={{ opacity: i > 0 ? 0.4 : 1 }}>
              <span className="inline-block size-1.5 rounded-full" style={{ background: HARNESS_COLORS[sp.harness] ?? 'var(--cs-sev-none)' }} />
              <span style={{ color: `var(--cs-sev-${sp.severity}-fg)` }}>
                {(() => { const n = formatSpanName(sp.name); return n.length > 24 ? `${n.slice(0, 24)}…` : n; })()}
              </span>
            </span>
          ))
        ) : (
          <span className="font-mono text-[11px] italic" style={{ color: 'var(--cs-text-faint)' }}>idle</span>
        )}
      </span>

      {enforceState !== null && (() => {
        const pill = {
          enforce: {
            fg: 'var(--cs-accent)', bg: 'rgba(var(--cs-accent-rgb),0.10)',
            label: 'Blocking active', Icon: ShieldCheck,
            title: 'Pre-execution blocking is active — every high-severity match is denied (enforce mode + hook registered).',
          },
          floor: {
            fg: 'var(--cs-sev-medium-fg)', bg: 'var(--cs-sev-medium-bg)',
            label: 'Floor only', Icon: ShieldAlert,
            title: 'Monitor mode: the always-on catastrophic floor, protected paths, and read-protection still block — but other rule matches are only logged. Switch to Enforce to block every high-severity match.',
          },
          off: {
            fg: 'var(--cs-sev-critical-fg)', bg: 'var(--cs-sev-critical-bg)',
            label: 'Not blocking', Icon: ShieldAlert,
            title: 'Nothing is blocked before it runs — the PreToolUse hook is not registered. Open the Enforce tab to install it.',
          },
        }[enforceState];
        const { Icon } = pill;
        return (
          <button
            type="button"
            onClick={() => navigateTab('enforce')}
            className="flex shrink-0 items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-[11px] transition-opacity hover:opacity-80"
            title={pill.title}
            style={{ background: pill.bg, color: pill.fg }}
          >
            <Icon className="size-3" /> {pill.label}
          </button>
        );
      })()}

      <span className="shrink-0 font-mono text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>v{appVersion}</span>
    </footer>
  );

  const banner = (
    <>
      {demoSessions > 0 && !demoBannerDismissed && (
        <div
          className="flex shrink-0 items-center gap-2 px-4 py-1.5 text-xs"
          style={{ background: 'var(--cs-sev-medium-bg)', borderBottom: '1px solid var(--cs-rule)', color: 'var(--cs-sev-medium-fg)' }}
        >
          <AlertTriangle className="size-3.5 shrink-0" />
          <span className="min-w-0">
            <strong>Demo data</strong> — these {demoSessions} session(s) are synthetic, not real agent activity. Clear them anytime in Settings → Data.
          </span>
          <button type="button" onClick={() => setDemoBannerDismissed(true)} className="ml-auto shrink-0 rounded p-0.5" aria-label="Dismiss demo-data notice">
            <X className="size-3.5" />
          </button>
        </div>
      )}
      {importStatus && (
        <div
          className="shrink-0 px-4 py-1.5 text-xs font-medium"
          style={{
            background: importStatus.ok ? 'rgba(var(--cs-accent-rgb),0.12)' : 'var(--cs-sev-critical-bg)',
            color: importStatus.ok ? 'var(--cs-accent)' : 'var(--cs-sev-critical-fg)',
          }}
        >
          {importStatus.msg}
        </div>
      )}
      {loadError && (
        <div
          className="flex shrink-0 items-center gap-2 px-4 py-1.5 text-xs font-medium"
          style={{ background: 'var(--cs-sev-critical-bg)', color: 'var(--cs-sev-critical-fg)' }}
        >
          <AlertTriangle className="size-3.5 shrink-0" />
          {loadError}
          <button type="button" onClick={() => setLoadError(null)} className="ml-auto rounded p-0.5" aria-label="Dismiss">
            <X className="size-3" />
          </button>
        </div>
      )}
    </>
  );

  if (docsOpen) {
    return (
      <div className="flex h-svh w-full flex-col" style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}>
        <DocsView slug={docsSlug ?? ''} onClose={closeDocs} onNavigate={openDocs} />
      </div>
    );
  }

  return (
    <>
      <AppShell
        activeCategory={activeCategory}
        activeTab={activeTab}
        docsOpen={docsOpen}
        onCategoryChange={navigateCategory}
        onTabChange={navigateTab}
        onOpenDocs={() => openDocs(docsSlug ?? '')}
        onOpenPalette={() => setPaletteOpen(true)}
        alertCount={alertCount}
        sessions={sessions}
        repos={repos}
        activeSession={activeSession}
        spanTotal={workflows.length}
        comparePending={comparePending}
        onCancelCompare={() => setComparePending(null)}
        editingSession={editingSession}
        editName={editName}
        notesSession={notesSession}
        notesText={notesText}
        selectedRepos={filters.repo}
        onToggleRepo={repo => toggle('repo', repo)}
        onSelect={setActiveSession}
        onCompare={handleCompare}
        onTogglePin={s => patchSession(s.traceId, { pinned: !s.pinned })}
        onStartRename={s => { setEditingSession(s.traceId); setEditName(s.name); }}
        onCommitRename={commitRename}
        onEditNameChange={setEditName}
        onToggleNotes={s => {
          setNotesSession(prev => (prev === s.traceId ? null : s.traceId));
          setNotesText(s.notes ?? '');
        }}
        onNotesChange={setNotesText}
        onNotesCommit={s => patchSession(s.traceId, { notes: notesText })}
        onLabelChange={(s, label: SessionLabel) => patchSession(s.traceId, { label })}
        headerActions={headerActions}
        statusBar={statusBar}
        banner={banner}
        detail={detail}
        onCloseDetail={() => setSelectedNode(null)}
        filterBar={FILTERABLE_TABS.includes(activeTab) ? (
          <FilterBar
            severityCounts={severityCounts}
            repoOptions={repoOptions}
            harnessOptions={harnessOptions}
            resultCount={visibleWorkflows.length}
            totalCount={workflows.length}
          />
        ) : undefined}
      >
        {activeTab === 'timeline' && (
          <>
            {timelineIntroShown && (
              <div
                className="mx-3 mt-3 flex items-start gap-3 rounded-xl px-4 py-3 text-xs leading-relaxed"
                style={{ background: 'rgba(var(--cs-accent-rgb),0.06)', color: 'var(--cs-text-muted)' }}
              >
                <Activity className="mt-0.5 size-4 shrink-0" style={{ color: 'var(--cs-accent)' }} />
                <div>
                  <strong style={{ color: 'var(--cs-text-strong)' }}>How to read the timeline:</strong>{' '}
                  Spans are individual operations (LLM calls, tool uses, bash commands).
                  Sessions group related spans by trace ID. Use the severity scale in the bar
                  above to narrow to what matters.
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setTimelineIntroShown(false);
                    localStorage.setItem('claudesec-timeline-intro-dismissed', 'true');
                  }}
                  className="shrink-0 rounded p-0.5"
                  style={{ color: 'var(--cs-text-faint)' }}
                  aria-label="Dismiss"
                >
                  <X className="size-3.5" />
                </button>
              </div>
            )}
            {graphWindow && !activeSession && (
              <p className="mx-3 mt-2 text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
                Showing the most recent {graphWindow.shown.toLocaleString()} events.
                Older events remain available via Search and Sessions.
              </p>
            )}
            {visibleWorkflows.length === 0 ? (
              <div className="p-10 text-center">
                <Search className="mx-auto mb-2 size-6" style={{ color: 'var(--cs-text-faint)' }} />
                <p className="text-[11px]" style={{ color: 'var(--cs-text-faint)' }}>
                  {workflows.length === 0 ? 'Awaiting traces…' : 'No span matches these filters.'}
                </p>
              </div>
            ) : (
              <Timeline
                workflows={visibleWorkflows}
                onSelect={onTimelineSelect}
                selectedId={selectedNode?.id ?? undefined}
              />
            )}
          </>
        )}

        {activeTab === 'orchestration' && (
          <OrchestrationTab
            onSelectSession={traceId => { setActiveSession(traceId); navigateTab('timeline'); }}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsTab
            onInvestigate={(traceId, spanId) => {
              setActiveSession(traceId);
              navigateTab('timeline');
              // Remember the span so it gets selected once the scoped graph loads.
              setPendingSpanSelect(spanId);
            }}
          />
        )}

        {activeTab === 'rules' && <RulesTab />}
        {activeTab === 'enforce' && <EnforceTab />}
        {activeTab === 'mcpscan' && <McpScanTab />}
        {activeTab === 'costs' && <CostTab />}
        {activeTab === 'harnesses' && (
          <HarnessTab
            onFilterHarness={h => { if (h) { toggle('harness', h); navigateTab('timeline'); } }}
            activeFilter={filters.harness[0] ?? null}
          />
        )}
        {activeTab === 'settings' && <SettingsTab />}
        {activeTab === 'heatmap' && <HeatmapTab />}
        {activeTab === 'search' && <SearchTab />}
        {activeTab === 'processes' && (
          <ProcessesTab
            onSelectSession={traceId => { setActiveSession(traceId); navigateTab('timeline'); }}
          />
        )}
        {activeTab === 'bookmarks' && (
          <BookmarksTab
            onSelectSession={(traceId, spanId) => {
              setActiveSession(traceId);
              navigateTab('timeline');
              setPendingSpanSelect(spanId ?? null);
            }}
          />
        )}
        {activeTab === 'governance' && <GovernTab onNavigateTab={navigateTab} />}
      </AppShell>

      <LiveActivityPanel open={liveActivityOpen} onClose={() => setLiveActivityOpen(false)} />

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        sessions={sessions}
        repos={repos}
        theme={theme}
        enforceMode={enforceMode}
        onSelectSession={traceId => { setActiveSession(traceId); navigateTab('timeline'); }}
        onSelectRepo={repo => { toggle('repo', repo); navigateTab('timeline'); }}
        onNavigateTab={navigateTab}
        onApplyView={applyView}
        onThemeChange={setTheme}
        onOpenDocs={openDocs}
        onToggleEnforce={toggleEnforceMode}
      />

      <AnimatePresence>
        {compareIds && (
          <ComparePanel aId={compareIds[0]} bId={compareIds[1]} onClose={() => setCompareIds(null)} />
        )}
      </AnimatePresence>
    </>
  );
}
