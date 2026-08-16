/**
 * EnforceTab — what the PreToolUse hook is actually doing right now.
 *
 * This tab is status-heavy rather than list-heavy, and it has one job it must
 * never get wrong: saying whether tool calls are being blocked. Every bug this
 * screen has had was a variant of the same failure — the dashboard claiming a
 * protection that was not in force — so the standing state is derived from
 * three independent facts and all three are always on screen:
 *
 *   1. the configured toggle,
 *   2. the *effective* mode the hook resolves (file → env → default) and which
 *      layer supplied it,
 *   3. whether a PreToolUse hook is registered at all.
 *
 * Green is earned only when enforce is effective **and** a hook is registered.
 * Enforce-with-no-hook is the most dangerous state on this screen — it looks
 * protected and blocks nothing — so it is the one that gets the critical
 * treatment, louder than plain monitor mode.
 *
 * Below the banner the layout is fixed-height: the state region never scrolls
 * away, and the would-block feed owns the rest of the viewport and its own
 * scroll, so the answer to "am I protected?" is never below the fold.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck, ShieldAlert, Ban, Eye, AlertTriangle, RefreshCw, Copy, Check,
  Radio, ListX, BarChart3, ChevronDown, ChevronRight, Info,
} from 'lucide-react';
import { socket } from './socket';
import type { Severity } from './shared/types';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, SEVERITY_META, normalizeSeverity,
  EmptyState, ErrorState,
  Toolbar, ToolButton, ToolbarTitle,
} from './components/data';

// ── Types ────────────────────────────────────────────────────────────────────
type EnforceMode = 'monitor' | 'enforce';
type EnforceAction = 'alert' | 'block';

interface EnforceLogEvent {
  ts: number;
  mode: string;
  label: string;
  severity: string;
  command: string;
  wouldBlock: boolean;
  // True when the call was actually denied (catastrophic floor or enforce rule).
  // Optional for back-compat with events buffered before the server set it; the
  // feed falls back to inferring it from mode.
  blocked?: boolean;
}

// ── Impact preview (GET /api/enforce/impact) ─────────────────────────────────
// Mirrors the shapes in server/routes/enforceImpact.ts. The replay answers the
// question the toggle asks and never states: what does turning this on cost?
interface ImpactExample {
  text: string;
  tool: string;
  atMs: number | null;
}

interface ImpactRuleRow {
  label: string;
  severity: string;
  count: number;
  /** Distinct call texts, so a rule that fired on one repeated command is visible as such. */
  distinctCalls: number;
  share: number;
  cumulativeShare: number;
  examples: ImpactExample[];
}

interface ImpactGroup {
  total: number;
  bySeverity: Record<string, number>;
  rules: ImpactRuleRow[];
  top10Share: number;
  rulesToReach80: number;
}

interface ImpactReport {
  window: { days: number; sinceMs: number };
  scanned: {
    candidateRows: number;
    evaluated: number;
    distinctCalls: number;
    cacheHitRate: number;
    truncated: boolean;
    byTool: Record<string, { evaluated: number; blocked: number }>;
  };
  wouldBlockInEnforce: ImpactGroup;
  blocksTodayAnyMode: ImpactGroup;
  oldestCallMs: number | null;
  newestCallMs: number | null;
  blockRulesCompiled: number;
  effectiveMode: EnforceMode;
  timing: { totalMs: number; pages: number };
  computedAtMs: number;
  cached: boolean;
  caveats: string[];
}

/** Which of the two populations the rule table is showing. */
type ImpactGroupKey = 'wouldBlockInEnforce' | 'blocksTodayAnyMode';

// Lookback options. "All" is the route's ceiling, which is past any retention
// window, so it means "everything still on disk".
// The panel is open by default — the number is only useful if it is already on
// screen when someone reaches for the toggle — but it is a tall panel on a tab
// whose feed owns the viewport, so a deliberate collapse is remembered rather
// than re-imposed on every visit. Matches the localStorage idiom used by
// useRowDensity.
const IMPACT_OPEN_KEY = 'claudesec.enforce.impactOpen';

function readImpactOpen(): boolean {
  try {
    return localStorage.getItem(IMPACT_OPEN_KEY) !== '0';
  } catch {
    return true; // private mode / storage blocked — default to showing it
  }
}

const IMPACT_WINDOWS: { days: number; label: string }[] = [
  { days: 7,   label: '7d' },
  { days: 30,  label: '30d' },
  { days: 90,  label: '90d' },
  { days: 400, label: 'All' },
];

type ModeSource = 'config-file' | 'env' | 'default';
type HookInstalled = 'yes' | 'no' | 'unknown';

interface HookStatus {
  installed: HookInstalled;
  scopes: string[];
}

interface EnforceConfig {
  mode: EnforceMode;
  overrides: Record<string, EnforceAction>;
  configFile?: string;
  envMode?: string | null;
  bypassEnabled?: boolean;
  // The mode the hook will actually run, after file → env → default precedence,
  // and which layer supplied it. May differ from `mode` (the configured toggle).
  effectiveMode?: EnforceMode;
  modeSource?: ModeSource;
  // Whether a PreToolUse hook running our enforcer is registered in Claude Code.
  // 'unknown' inside a container (host settings aren't visible there).
  hookStatus?: HookStatus;
}

const SCOPE_LABEL: Record<string, string> = {
  user: 'user settings',
  project: 'project settings',
  'project-local': 'project-local settings',
};

const SOURCE_LABEL: Record<ModeSource, string> = {
  'config-file': 'enforce-config.json',
  env: 'the CLAUDESEC_MODE env var',
  default: 'the monitor default',
};

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function relTime(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const LOG_LIMIT = 500;

// The one command that registers the PreToolUse enforcement hook in Claude Code.
// Kept as a constant so the copy button and the inline prose can't drift apart.
const HOOK_INSTALL_CMD = 'node cli/init.mjs install-hook';

// A small inline "command + copy" affordance, matching the copy-button pattern
// used elsewhere (ProcessesTab / SettingsTab): navigator.clipboard + a 2s tick.
function CopyableCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard may be blocked (insecure context) — ignore */ }
  };
  return (
    <span className="inline-flex items-center gap-1.5 align-middle">
      <code
        className="cs-mono px-1.5 py-0.5 rounded"
        style={{ background: 'var(--cs-bg-sunken)', color: 'var(--cs-text-body)' }}
      >
        {command}
      </code>
      <button
        type="button"
        onClick={handleCopy}
        className="shrink-0 inline-flex items-center justify-center p-1 rounded transition-colors"
        style={{ color: copied ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}
        title={copied ? 'Copied' : 'Copy command'}
        aria-label={copied ? 'Command copied' : 'Copy command to clipboard'}
      >
        {copied ? <Check className="w-3 h-3" aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
      </button>
    </span>
  );
}

/** One of the three standing truths, as a label/value pair on one line. */
function Truth({ label, value, title }: { label: string; value: React.ReactNode; title?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0" title={title}>
      <span style={{ color: 'var(--cs-text-faint)' }}>{label}</span>
      <span className="cs-mono" style={{ fontWeight: 'var(--cs-weight-semibold)' }}>{value}</span>
    </span>
  );
}

/**
 * A warning band inside the state region. Severity is passed rather than a
 * colour, so these can never drift out of the one colour language the rest of
 * the app speaks.
 */
function Notice({
  severity,
  icon,
  children,
}: {
  severity: Severity;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      className="flex items-start gap-2 px-2.5 py-2 rounded-md"
      style={{
        background: severity === 'none' ? 'var(--cs-bg-sunken)' : `var(--cs-sev-${severity}-bg)`,
        borderLeft: `var(--cs-spine-width) solid var(--cs-sev-${severity})`,
        color: 'var(--cs-text-muted)',
        fontSize: 'var(--cs-text-sm)',
        lineHeight: 'var(--cs-leading-normal)',
      }}
    >
      <span className="shrink-0 mt-0.5" style={{ color: `var(--cs-sev-${severity})` }} aria-hidden="true">{icon}</span>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

/**
 * A compact count. Severity counts use the ramp; the total stays achromatic.
 *
 * Laid out on one line rather than as a stacked stat card: five cards cost 70px
 * of a 1366×768 screen and these are orientation, not the thing being read.
 */
function Counter({
  label,
  value,
  severity,
}: {
  label: string;
  value: number;
  severity?: Severity;
}) {
  const meta = severity ? SEVERITY_META[severity] : null;
  return (
    <div
      className="flex items-baseline gap-1.5 px-2 py-1 rounded-md min-w-0"
      style={{ background: 'var(--cs-bg-surface)' }}
    >
      <span
        className="flex items-center gap-1 uppercase truncate"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {meta && <meta.Icon className="w-3 h-3 shrink-0 self-center" style={{ color: `var(--cs-sev-${severity})` }} aria-hidden="true" />}
        {label}
      </span>
      <span
        className="cs-mono ml-auto"
        style={{
          color: value > 0 && severity ? `var(--cs-sev-${severity}-fg)` : 'var(--cs-text-strong)',
          fontSize: 'var(--cs-text-md)',
          fontWeight: 'var(--cs-weight-semibold)',
        }}
      >
        {value}
      </span>
    </div>
  );
}

/**
 * One of the impact preview's two headline numbers.
 *
 * They are deliberately the same size and sit side by side, because the mistake
 * this panel exists to prevent is reading one of them as the whole answer: the
 * left number is a forecast you control with the toggle, the right one is
 * already happening. `tone` is 'critical' for the consequence of flipping and
 * 'chrome' for the standing fact — the ramp is reserved for the thing that
 * changes if you act.
 */
function ImpactHeadline({
  value,
  label,
  caption,
  tone,
}: {
  value: number;
  label: string;
  caption: string;
  tone: 'critical' | 'chrome';
}) {
  const color = value === 0
    ? 'var(--cs-text-faint)'
    : tone === 'critical' ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-strong)';
  return (
    <div
      className="flex-1 min-w-0 px-2.5 py-2 rounded-md flex flex-col gap-0.5"
      style={{ background: 'var(--cs-bg-sunken)' }}
    >
      <span
        className="uppercase truncate"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {label}
      </span>
      <span
        className="cs-mono"
        style={{ color, fontSize: 'var(--cs-text-xl)', fontWeight: 'var(--cs-weight-semibold)', lineHeight: 'var(--cs-leading-tight)' }}
      >
        {value.toLocaleString()}
      </span>
      <span style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-snug)' }}>
        {caption}
      </span>
    </div>
  );
}

export function EnforceTab() {
  const [config, setConfig]   = useState<EnforceConfig | null>(null);
  const [events, setEvents]   = useState<EnforceLogEvent[]>([]);
  const [saving, setSaving]   = useState(false);
  const [error,  setError]    = useState('');
  const [feedLoading, setFeedLoading] = useState(true);
  const [feedError,   setFeedError]   = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [density, setDensity] = useRowDensity('enforce');
  const [, setTick]           = useState(0); // re-render for relative times

  // ── Impact preview state ──────────────────────────────────────────────────
  const [impact, setImpact]             = useState<ImpactReport | null>(null);
  const [impactLoading, setImpactLoading] = useState(true);
  const [impactError, setImpactError]   = useState<string | null>(null);
  const [impactDays, setImpactDays]     = useState(30);
  const [impactOpen, setImpactOpen]     = useState(readImpactOpen);
  const [impactGroup, setImpactGroup]   = useState<ImpactGroupKey>('wouldBlockInEnforce');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [showCaveats, setShowCaveats]   = useState(false);

  // Fetch config + log on mount.
  const fetchConfig = useCallback(() => {
    fetch('/api/enforce/config')
      .then(r => r.json())
      .then((c: EnforceConfig) => setConfig(c))
      .catch(() => setError('Could not load enforcement config'));
  }, []);

  const fetchLog = useCallback(() => {
    fetch(`/api/enforce-log?limit=${LOG_LIMIT}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: { events: EnforceLogEvent[] }) => {
        setEvents(Array.isArray(d.events) ? d.events : []);
        setFeedError(null);
      })
      .catch((e: Error) => setFeedError(e.message || 'Request failed'))
      .finally(() => setFeedLoading(false));
  }, []);

  // The replay is a multi-second scan of the whole span history, so it is fetched
  // once per window rather than polled, and the server memoizes the result for a
  // minute — reopening this tab is free. It runs on mount rather than on demand
  // because the number is only useful if it is already on screen when someone
  // reaches for the toggle.
  const fetchImpact = useCallback((days: number) => {
    setImpactLoading(true);
    fetch(`/api/enforce/impact?days=${days}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: ImpactReport) => {
        setImpact(d);
        setImpactError(null);
      })
      .catch((e: Error) => setImpactError(e.message || 'Request failed'))
      .finally(() => setImpactLoading(false));
  }, []);

  useEffect(() => {
    fetchConfig();
    fetchLog();
  }, [fetchConfig, fetchLog]);

  // The replay runs whether or not the panel is expanded: the toolbar chip
  // beside the Enforce button needs the number even when the detail is collapsed.
  useEffect(() => {
    fetchImpact(impactDays);
  }, [fetchImpact, impactDays]);

  useEffect(() => {
    try { localStorage.setItem(IMPACT_OPEN_KEY, impactOpen ? '1' : '0'); } catch { /* storage blocked */ }
  }, [impactOpen]);

  // Live updates: new would-block events + config changes from elsewhere.
  useEffect(() => {
    const onLog = (evt: EnforceLogEvent) => {
      setEvents(prev => [evt, ...prev].slice(0, LOG_LIMIT));
    };
    const onConfig = (c: { mode: EnforceMode; overrides: Record<string, EnforceAction> }) => {
      // Apply the live mode/overrides immediately for snappy UI, then refetch so
      // the derived truths (effectiveMode / modeSource / hookStatus) re-resolve
      // against the new config-file state rather than going stale.
      setConfig(prev => (prev ? { ...prev, mode: c.mode, overrides: c.overrides } : prev));
      fetchConfig();
    };
    socket.on('enforce-log', onLog);
    socket.on('enforce-config', onConfig);
    return () => {
      socket.off('enforce-log', onLog);
      socket.off('enforce-config', onConfig);
    };
  }, [fetchConfig]);

  // Tick every 5s so relative timestamps stay fresh.
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 5000);
    return () => clearInterval(id);
  }, []);

  const mode = config?.mode ?? 'monitor';
  const isEnforce = mode === 'enforce';

  // ── Honest standing-state derivation ──────────────────────────────────────
  // The configured toggle (`mode`) is NOT necessarily what the hook runs. The
  // hook resolves file → env → default; the server reports the resolved value as
  // `effectiveMode` plus the `modeSource` that won. Fall back to the toggle only
  // when the server hasn't reported one (older server / fetch in flight).
  const effectiveMode: EnforceMode = config?.effectiveMode ?? mode;
  const modeSource: ModeSource = config?.modeSource ?? 'config-file';
  const effEnforce = effectiveMode === 'enforce';

  // Null means config hasn't loaded yet (or the fetch failed permanently).
  // We distinguish null from 'unknown' so transient/error states don't trigger
  // the container warning — that banner should only fire when the server has
  // positively reported 'unknown' (i.e. it detected it is inside a container).
  const hookInstalled: HookInstalled | null = config
    ? (config.hookStatus?.installed ?? 'unknown')
    : null;
  const hookScopes = config?.hookStatus?.scopes ?? [];

  // A live feed proves the hook FIRED, never that blocking is wired up correctly —
  // so green is earned ONLY when enforce is effective AND a hook is registered.
  const protectionActive = effEnforce && hookInstalled === 'yes';

  // The precedence trap: an operator set CLAUDESEC_MODE but the config file's mode
  // is what the hook actually obeys, and the two disagree. Name it explicitly.
  const envMode = config?.envMode ?? null;
  const envTrap =
    !!envMode && modeSource === 'config-file' && envMode !== effectiveMode;

  // The standing state, as one value the whole banner reads from. `blind` is
  // the dangerous one: enforce is set, so the screen looks armed, but no hook
  // is registered and nothing can be blocked or even observed.
  const standing: 'loading' | 'blocking' | 'blind' | 'unverified' | 'monitoring' =
    hookInstalled === null ? 'loading' :
    protectionActive      ? 'blocking' :
    effEnforce && hookInstalled === 'no' ? 'blind' :
    effEnforce            ? 'unverified' :
    'monitoring';

  const BANNER: Record<Exclude<typeof standing, 'loading'>, {
    severity: Severity;
    Icon: typeof ShieldCheck;
    headline: string;
  }> = {
    blocking:   { severity: 'none',     Icon: ShieldCheck, headline: 'Blocking active — matching tool calls are denied' },
    blind:      { severity: 'critical', Icon: ShieldAlert, headline: 'Enforce is set, but no hook is registered — nothing is blocked' },
    unverified: { severity: 'medium',   Icon: AlertTriangle, headline: 'Enforce is set — hook registration cannot be verified from here' },
    monitoring: { severity: 'none',     Icon: Eye,         headline: 'Monitor mode — logging only, nothing is blocked' },
  };
  const banner = standing === 'loading' ? null : BANNER[standing];
  // "Blocking active" is the one state that earns the accent: it is chrome
  // saying "this is on", not the severity ramp saying "this is dangerous".
  const bannerMark = standing === 'blocking'
    ? 'var(--cs-accent)'
    : `var(--cs-sev-${banner?.severity ?? 'none'})`;

  const setMode = async (next: EnforceMode) => {
    if (saving || next === mode) return;
    setSaving(true);
    setError('');
    try {
      const res = await fetch('/api/enforce/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: next }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const updated = await res.json();
      setConfig(prev => (prev ? { ...prev, mode: updated.mode, overrides: updated.overrides } : prev));
      // The toggle just rewrote enforce-config.json, which is the top precedence
      // layer — refetch so effectiveMode / modeSource re-resolve against it.
      fetchConfig();
    } catch (e) {
      setError((e as Error).message || 'Failed to update mode');
    } finally {
      setSaving(false);
    }
  };

  // Aggregate counts by rule label + severity over the visible feed.
  const stats = useMemo(() => {
    const byRule = new Map<string, { count: number; severity: string }>();
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const e of events) {
      const r = byRule.get(e.label) ?? { count: 0, severity: e.severity };
      r.count += 1;
      byRule.set(e.label, r);
      if (bySeverity[e.severity] !== undefined) bySeverity[e.severity] += 1;
    }
    const topRules = [...byRule.entries()]
      .map(([label, v]) => ({ label, ...v }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12);
    return { total: events.length, bySeverity, topRules };
  }, [events]);

  // A stable key per event: the feed is prepended to live, so the array index
  // would re-key every row on each arrival and throw away the expanded row.
  const eventKey = (e: EnforceLogEvent) => `${e.ts}-${e.label}-${e.command}`;

  // ── Feed columns ─────────────────────────────────────────────────────────
  // Read in the order the event is judged: how bad, which rule, what command,
  // whether it was actually stopped, and when.
  const columns: DataColumn<EnforceLogEvent>[] = [
    {
      id: 'severity', header: 'Severity', width: '96px',
      cell: e => <SeverityBadge severity={normalizeSeverity(e.severity)} />,
    },
    {
      id: 'rule', header: 'Rule', width: 'minmax(0,1.1fr)',
      cell: e => (
        <span title={e.label} style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>
          {e.label}
        </span>
      ),
    },
    {
      id: 'command', header: 'Command', width: 'minmax(0,1.7fr)', mono: true,
      cell: e => <span title={e.command} style={{ color: 'var(--cs-text-body)' }}>{e.command}</span>,
    },
    {
      id: 'outcome', header: 'Outcome', width: '96px',
      // Key the pill off the explicit `blocked` flag. The catastrophic floor
      // blocks even in monitor mode, so `mode` alone mislabels it; fall back to
      // mode only for legacy events that lack the flag.
      cell: e => {
        const wasBlocked = e.blocked ?? (e.mode === 'enforce');
        return (
          <span
            className="inline-flex items-center gap-1"
            style={{
              color: wasBlocked ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-faint)',
              fontSize: 'var(--cs-text-xs)',
            }}
            title={wasBlocked
              ? 'The call was denied before it ran.'
              : 'The call matched a blocking rule but was allowed — monitor mode.'}
          >
            {wasBlocked
              ? <Ban className="w-3 h-3 shrink-0" aria-hidden="true" />
              : <Eye className="w-3 h-3 shrink-0" aria-hidden="true" />}
            {wasBlocked ? 'Blocked' : 'Would block'}
          </span>
        );
      },
    },
    {
      id: 'mode', header: 'Mode', width: '76px', hideBelow: '3xl',
      cell: e => <span>{e.mode}</span>,
    },
    {
      id: 'time', header: 'Time', width: '72px', align: 'end', mono: true,
      cell: e => <span title={fmtTime(e.ts)}>{relTime(e.ts)}</span>,
    },
  ];

  // The command truncates hard in its column, and the whole command is the
  // reason to look at one of these rows at all.
  const renderDetail = (e: EnforceLogEvent) => {
    if (expanded !== eventKey(e)) return null;
    const wasBlocked = e.blocked ?? (e.mode === 'enforce');
    return (
      <div className="flex flex-col gap-1.5 py-1.5" style={{ fontSize: 'var(--cs-text-xs)' }}>
        <code
          className="cs-mono block px-2 py-1 rounded whitespace-pre-wrap break-all"
          style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}
        >
          {e.command}
        </code>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1" style={{ color: 'var(--cs-text-faint)' }}>
          <span className="cs-mono">{new Date(e.ts).toLocaleString()}</span>
          <span>recorded in {e.mode} mode</span>
          <span>
            {wasBlocked
              ? 'Denied before it ran.'
              : 'Allowed through — this is what would have been denied in enforce mode.'}
          </span>
        </div>
      </div>
    );
  };

  const maxRuleCount = stats.topRules[0]?.count || 1;

  // ── Impact preview: derived view ──────────────────────────────────────────
  const shownGroup = impact ? impact[impactGroup] : null;
  const enforceOnlyTotal = impact?.wouldBlockInEnforce.total ?? null;

  // How much history the reply actually covered. The requested window is a
  // ceiling, not a promise — a fresh install has days, not months — so the panel
  // reports the extent of the evidence rather than the number that was asked for.
  const evidenceDays = impact?.oldestCallMs && impact?.newestCallMs
    ? Math.max(1, Math.round((impact.newestCallMs - impact.oldestCallMs) / 86_400_000))
    : null;

  const impactColumns: DataColumn<ImpactRuleRow>[] = [
    {
      id: 'severity', header: 'Severity', width: '96px', hideBelow: 'xl',
      cell: r => <SeverityBadge severity={normalizeSeverity(r.severity)} />,
    },
    {
      id: 'rule', header: 'Rule', width: 'minmax(0,1.6fr)',
      cell: r => (
        <span title={r.label} style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>
          {r.label}
        </span>
      ),
    },
    {
      id: 'share', header: 'Share', width: 'minmax(80px,0.7fr)',
      // A bar rather than a second number: the entire argument for re-baselining
      // is that a handful of rules dominate, and that is a shape, not a figure.
      cell: r => (
        <span className="flex items-center gap-1.5 min-w-0 w-full" title={`${r.share.toFixed(1)}% of this group`}>
          <span className="relative flex-1 min-w-0 h-1.5 rounded overflow-hidden" style={{ background: 'var(--cs-bg-sunken)' }}>
            <span
              className="absolute inset-y-0 left-0"
              style={{ width: `${Math.max(2, r.share)}%`, background: 'var(--cs-accent-dim)' }}
              aria-hidden="true"
            />
          </span>
          <span className="cs-mono shrink-0" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
            {r.share.toFixed(0)}%
          </span>
        </span>
      ),
    },
    {
      id: 'count', header: 'Calls', width: '68px', align: 'end', mono: true,
      cell: r => <span style={{ color: 'var(--cs-text-strong)' }}>{r.count.toLocaleString()}</span>,
    },
    {
      id: 'distinct', header: 'Distinct', width: '76px', align: 'end', mono: true, hideBelow: '2xl',
      cell: r => (
        <span
          style={{ color: 'var(--cs-text-faint)' }}
          title={`${r.distinctCalls.toLocaleString()} different commands — the rest were repeats`}
        >
          {r.distinctCalls.toLocaleString()}
        </span>
      ),
    },
    {
      id: 'cumulative', header: 'Cum.', width: '68px', align: 'end', mono: true, hideBelow: '3xl',
      cell: r => (
        <span style={{ color: 'var(--cs-text-faint)' }} title="Running share once rules are ranked by frequency">
          {r.cumulativeShare.toFixed(0)}%
        </span>
      ),
    },
  ];

  // The whole point of a per-rule ranking is judging "true positive vs my own
  // workflow", and that judgement needs the actual commands.
  const renderImpactDetail = (r: ImpactRuleRow) => {
    if (expandedRule !== r.label) return null;
    return (
      <div className="flex flex-col gap-1.5 py-1.5" style={{ fontSize: 'var(--cs-text-xs)' }}>
        <p style={{ color: 'var(--cs-text-faint)' }}>
          {r.count.toLocaleString()} call{r.count === 1 ? '' : 's'} from{' '}
          {r.distinctCalls.toLocaleString()} distinct command{r.distinctCalls === 1 ? '' : 's'}
          {r.examples.length > 0 && ' — examples:'}
        </p>
        {r.examples.map((ex, i) => (
          <div key={i} className="flex flex-col gap-0.5">
            <span style={{ color: 'var(--cs-text-faint)' }}>
              {ex.tool}
              {ex.atMs !== null && ` · ${new Date(ex.atMs).toLocaleDateString()}`}
            </span>
            <code
              className="cs-mono block px-2 py-1 rounded whitespace-pre-wrap break-all"
              style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}
            >
              {ex.text}
            </code>
          </div>
        ))}
        {r.examples.length === 0 && (
          <span style={{ color: 'var(--cs-text-faint)' }}>No example was captured for this rule.</span>
        )}
      </div>
    );
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      <Toolbar>
        <ToolbarTitle
          icon={<ShieldCheck className="w-3.5 h-3.5" />}
          count={events.length}
          countTitle={`${events.length} enforcement events in the buffer`}
        >
          Enforcement
        </ToolbarTitle>

        {/* The mode switch. Monitor is chrome — it is the safe default. Enforce
            carries the critical token because turning it on changes what the
            machine is allowed to do. */}
        <div
          className="inline-flex items-center rounded-md p-0.5 gap-0.5"
          role="group"
          aria-label="Enforcement mode"
          style={{ background: 'var(--cs-bg-raised)' }}
        >
          <button
            type="button"
            onClick={() => setMode('monitor')}
            disabled={saving}
            aria-pressed={!isEnforce}
            title="Detect and log, never deny"
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded transition-colors disabled:opacity-50"
            style={{
              background: !isEnforce ? 'var(--cs-accent-soft)' : 'transparent',
              color: !isEnforce ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
              fontSize: 'var(--cs-text-xs)',
            }}
          >
            <Eye className="w-3.5 h-3.5" aria-hidden="true" /> Monitor
          </button>
          <button
            type="button"
            onClick={() => setMode('enforce')}
            disabled={saving}
            aria-pressed={isEnforce}
            title="Deny tool calls that match a blocking rule"
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded transition-colors disabled:opacity-50"
            style={{
              background: isEnforce ? 'var(--cs-sev-critical-bg)' : 'transparent',
              color: isEnforce ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-faint)',
              fontSize: 'var(--cs-text-xs)',
            }}
          >
            <Ban className="w-3.5 h-3.5" aria-hidden="true" /> Enforce
          </button>
        </div>
        {saving && (
          <span role="status" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>Saving…</span>
        )}

        {/* The consequence, next to the control that causes it. The panel below
            carries the reasoning; this is the one number that has to be in the
            operator's eye before their hand reaches the Enforce button. */}
        {enforceOnlyTotal !== null && !isEnforce && (
          <button
            type="button"
            onClick={() => setImpactOpen(o => !o)}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors"
            style={{
              background: enforceOnlyTotal > 0 ? 'var(--cs-sev-critical-bg)' : 'var(--cs-bg-raised)',
              color: enforceOnlyTotal > 0 ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-faint)',
              fontSize: 'var(--cs-text-xs)',
            }}
            title={`Turning Enforce on would additionally have denied ${enforceOnlyTotal.toLocaleString()} recorded tool calls over the last ${impactDays} days. Click for the per-rule breakdown.`}
          >
            <Ban className="w-3 h-3 shrink-0" aria-hidden="true" />
            <span className="cs-mono">+{enforceOnlyTotal.toLocaleString()}</span>
            <span className="hidden xl:inline">would be denied</span>
          </button>
        )}

        <div className="flex items-center gap-1 ml-auto">
          <RowDensityToggle density={density} onChange={setDensity} className="mr-1" />
          <ToolButton onClick={() => { fetchLog(); fetchConfig(); }} title="Re-read the config and the event log">
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden xl:inline">Refresh</span>
          </ToolButton>
        </div>
      </Toolbar>

      {/* ── Standing state ──────────────────────────────────────────────────
          Fixed at the top of the tab and never scrolled away: this is the one
          answer the tab exists to give. */}
      <div
        className="shrink-0 px-3 py-2.5 flex flex-col gap-2"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        <div className="flex items-start gap-2.5">
          <span
            aria-hidden="true"
            className="self-stretch shrink-0"
            style={{ width: 'var(--cs-spine-width)', borderRadius: 'var(--cs-radius-xs)', background: bannerMark }}
          />
          {banner
            ? <banner.Icon className="w-4 h-4 shrink-0 mt-0.5" style={{ color: bannerMark }} aria-hidden="true" />
            : <RefreshCw className="w-4 h-4 shrink-0 mt-0.5 animate-spin" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}

          <div className="min-w-0 flex-1 flex flex-col gap-1">
            <p
              role="status"
              style={{
                color: 'var(--cs-text-strong)',
                fontSize: 'var(--cs-text-md)',
                fontWeight: 'var(--cs-weight-semibold)',
                lineHeight: 'var(--cs-leading-snug)',
              }}
            >
              {banner?.headline ?? 'Reading enforcement state…'}
            </p>
            <p
              className="hidden xl:block"
              style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-sm)', lineHeight: 'var(--cs-leading-normal)' }}
            >
              {effEnforce
                ? 'The PreToolUse hook denies Bash / Edit / Write / MultiEdit calls that match a high-severity rule. The always-on catastrophic floor (rm -rf /, fork bombs, reverse shells) blocks in either mode. Fail-open: if the hook errors, the call is allowed through.'
                : 'The hook records “would-block” events for high-severity matches but allows every call. Flip to Enforce to actually deny them. The catastrophic floor and any protected paths still block regardless of mode.'}
            </p>

            {/* The three standing truths, always shown — including when they
                agree. A screen that only mentions the effective mode when it
                disagrees teaches operators to read silence as "fine". */}
            <div
              className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-0.5"
              style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}
            >
              <Truth label="Configured:" value={mode} title="The mode this dashboard's toggle is set to" />
              <Truth
                label="Effective:"
                value={
                  <span style={{ color: effEnforce ? 'var(--cs-sev-critical-fg)' : 'var(--cs-text-body)' }}>
                    {effectiveMode}
                  </span>
                }
                title={`What the hook actually runs, resolved from ${SOURCE_LABEL[modeSource]}`}
              />
              <span style={{ color: 'var(--cs-text-faint)' }}>from {SOURCE_LABEL[modeSource]}</span>
              <Truth
                label="Hook registered:"
                value={
                  hookInstalled === 'yes' ? (
                    <span style={{ color: 'var(--cs-accent)' }}>
                      yes{hookScopes.length > 0 && ` (${hookScopes.map(s => SCOPE_LABEL[s] ?? s).join(', ')})`}
                    </span>
                  ) : hookInstalled === 'no' ? (
                    <span style={{ color: 'var(--cs-sev-critical-fg)' }}>no</span>
                  ) : hookInstalled === 'unknown' ? (
                    <span style={{ color: 'var(--cs-sev-medium-fg)' }}>unknown (container)</span>
                  ) : (
                    <span style={{ color: 'var(--cs-text-faint)' }}>checking…</span>
                  )
                }
                title="Whether a Claude Code PreToolUse hook running our enforcer is installed"
              />
            </div>
          </div>

          {/* Installing the hook is the first thing a new operator needs, so the
              command is on screen rather than buried in prose. */}
          {hookInstalled !== null && hookInstalled !== 'yes' && (
            <div
              className="hidden 2xl:flex items-center gap-2 shrink-0"
              style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}
            >
              <span>Install the hook:</span>
              <CopyableCommand command={HOOK_INSTALL_CMD} />
            </div>
          )}
        </div>

        {/* ── Honest warnings ────────────────────────────────────────────────
            All gated on hookInstalled being non-null so they don't fire during
            the initial fetch or on a fetch failure — a missing config is not the
            same as "running in a container". */}
        {hookInstalled === 'no' && (
          <Notice severity="critical" icon={<ShieldAlert className="w-4 h-4" />}>
            <span style={{ color: 'var(--cs-sev-critical-fg)', fontWeight: 'var(--cs-weight-semibold)' }}>
              Observing only — nothing is being blocked before it runs.{' '}
            </span>
            No valid Claude Code PreToolUse hook is registered, so the dashboard cannot block or
            observe agent tool calls through the hook — events in the feed below, if any, do not
            prove blocking works. Install it with <CopyableCommand command={HOOK_INSTALL_CMD} /> from
            the ClaudeSec directory, then restart Claude Code.
          </Notice>
        )}

        {hookInstalled !== null && mode !== effectiveMode && (
          <Notice severity="medium" icon={<AlertTriangle className="w-4 h-4" />}>
            Your <span className="cs-mono">{mode}</span> toggle is overridden — the hook actually
            runs in <span className="cs-mono" style={{ fontWeight: 'var(--cs-weight-semibold)' }}>{effectiveMode}</span>{' '}
            mode, set by {SOURCE_LABEL[modeSource]}.
          </Notice>
        )}

        {hookInstalled !== null && envTrap && (
          <Notice severity="medium" icon={<AlertTriangle className="w-4 h-4" />}>
            <span className="cs-mono">CLAUDESEC_MODE={envMode}</span> is set, but{' '}
            <span className="cs-mono">enforce-config.json</span> (mode:{' '}
            <span className="cs-mono" style={{ fontWeight: 'var(--cs-weight-semibold)' }}>{effectiveMode}</span>) takes
            precedence. The env value is being ignored by the hook.
          </Notice>
        )}

        {hookInstalled === 'unknown' && (
          <Notice severity="none" icon={<AlertTriangle className="w-4 h-4" />}>
            Running inside a container — Claude Code hook registration can't be verified from here,
            since the host's settings aren't mounted. Confirm the hook on the host if you rely on
            hook-based enforcement.
          </Notice>
        )}

        {config?.bypassEnabled && (
          <Notice severity="medium" icon={<AlertTriangle className="w-4 h-4" />}>
            <span className="cs-mono">CLAUDESEC_HOOKS_BYPASS=1</span> is active in this server's
            environment — the hook allows everything, whatever the mode above says.
          </Notice>
        )}

        {error && (
          <Notice severity="critical" icon={<AlertTriangle className="w-4 h-4" />}>{error}</Notice>
        )}
      </div>

      {/* ── Impact preview ──────────────────────────────────────────────────
          Above the feed and below the standing state, because it answers a
          different question from either: not "am I protected?" and not "what
          fired?", but "what does turning this on cost?". It sits before the feed
          so the consequence is read before the history. */}
      <section
        className="shrink-0 flex flex-col"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
        aria-label="Enforcement impact preview"
      >
        <div className="flex items-center gap-2 px-3 py-1.5 flex-wrap">
          <button
            type="button"
            onClick={() => setImpactOpen(o => !o)}
            aria-expanded={impactOpen}
            className="inline-flex items-center gap-1.5 min-w-0"
            style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-semibold)' }}
          >
            {impactOpen
              ? <ChevronDown className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              : <ChevronRight className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />}
            <BarChart3 className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" />
            Impact preview
          </button>
          <span
            className="hidden xl:inline min-w-0 truncate"
            style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}
          >
            Recorded tool calls replayed through the current rule set
            {evidenceDays !== null && ` — ${evidenceDays} day${evidenceDays === 1 ? '' : 's'} of history`}
          </span>

          <div className="flex items-center gap-1 ml-auto">
            <div
              className="inline-flex items-center rounded-md p-0.5 gap-0.5"
              role="group"
              aria-label="Lookback window"
              style={{ background: 'var(--cs-bg-raised)' }}
            >
              {IMPACT_WINDOWS.map(w => (
                <button
                  key={w.days}
                  type="button"
                  onClick={() => setImpactDays(w.days)}
                  aria-pressed={impactDays === w.days}
                  disabled={impactLoading}
                  className="px-1.5 py-0.5 rounded transition-colors disabled:opacity-50"
                  style={{
                    background: impactDays === w.days ? 'var(--cs-accent-soft)' : 'transparent',
                    color: impactDays === w.days ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
                    fontSize: 'var(--cs-text-xs)',
                  }}
                >
                  {w.label}
                </button>
              ))}
            </div>
            <ToolButton
              onClick={() => fetchImpact(impactDays)}
              disabled={impactLoading}
              title="Re-run the replay against the current rule set"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${impactLoading ? 'animate-spin' : ''}`} aria-hidden="true" />
            </ToolButton>
          </div>
        </div>

        {impactOpen && (
          <div className="flex flex-col gap-2 px-3 pb-2">
            {impactError && !impact ? (
              <ErrorState
                description={`The impact preview did not respond (${impactError}). Enforcement is unaffected — this is only the forecast.`}
                onRetry={() => fetchImpact(impactDays)}
              />
            ) : (
              <>
                {/* The two populations, side by side and the same size. */}
                <div className="flex gap-2 flex-col sm:flex-row">
                  <ImpactHeadline
                    tone="critical"
                    value={impact?.wouldBlockInEnforce.total ?? 0}
                    label="Would block only in enforce"
                    caption={
                      impact
                        ? `${impact.wouldBlockInEnforce.rules.length} rule${impact.wouldBlockInEnforce.rules.length === 1 ? '' : 's'} firing, out of ${impact.blockRulesCompiled.toLocaleString()} that can block. Flipping the toggle adds exactly these denials.`
                        : 'Replaying recorded calls…'
                    }
                  />
                  <ImpactHeadline
                    tone="chrome"
                    value={impact?.blocksTodayAnyMode.total ?? 0}
                    label="Blocks today, in every mode"
                    caption={
                      impact
                        ? `${impact.blocksTodayAnyMode.rules.length} floor${impact.blocksTodayAnyMode.rules.length === 1 ? '' : 's'} firing. Catastrophic, self-protection and protected-path denials ignore the toggle — these already happened.`
                        : 'Replaying recorded calls…'
                    }
                  />
                </div>

                {/* The concentration claim, stated rather than left to be
                    inferred from the table — it is the actual finding. */}
                {shownGroup && shownGroup.total > 0 && (
                  <p style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}>
                    <span style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-semibold)' }}>
                      {shownGroup.rulesToReach80} of {shownGroup.rules.length} rules
                    </span>{' '}
                    account for 80% of these blocks; the ten most frequent account for{' '}
                    {shownGroup.top10Share.toFixed(0)}%. Expand a row to see the real commands it stopped.
                  </p>
                )}

                {/* Which population the table is showing. */}
                <div
                  className="inline-flex items-center rounded-md p-0.5 gap-0.5 self-start"
                  role="group"
                  aria-label="Which blocks to list"
                  style={{ background: 'var(--cs-bg-raised)' }}
                >
                  {([
                    ['wouldBlockInEnforce', 'Enforce-only', impact?.wouldBlockInEnforce.total],
                    ['blocksTodayAnyMode', 'Blocking today', impact?.blocksTodayAnyMode.total],
                  ] as const).map(([key, label, count]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => { setImpactGroup(key); setExpandedRule(null); }}
                      aria-pressed={impactGroup === key}
                      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded transition-colors"
                      style={{
                        background: impactGroup === key ? 'var(--cs-accent-soft)' : 'transparent',
                        color: impactGroup === key ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
                        fontSize: 'var(--cs-text-xs)',
                      }}
                    >
                      {label}
                      {count !== undefined && <span className="cs-mono">{count.toLocaleString()}</span>}
                    </button>
                  ))}
                </div>

                <div className="h-[176px] 2xl:h-[224px] flex flex-col min-h-0">
                  <DataTable
                    rows={shownGroup?.rules ?? []}
                    columns={impactColumns}
                    rowKey={r => r.label}
                    label="Rules by would-block frequency"
                    density={density}
                    minWidth={520}
                    severity={r => normalizeSeverity(r.severity)}
                    // Past the 80% mark is the long tail — dimming it makes the
                    // concentration legible without a second chart.
                    muted={r => r.cumulativeShare > 80}
                    onActivate={r => setExpandedRule(prev => (prev === r.label ? null : r.label))}
                    renderDetail={renderImpactDetail}
                    loading={impactLoading && !impact}
                    empty={
                      <EmptyState
                        icon={<ShieldCheck className="w-6 h-6" aria-hidden="true" />}
                        title="Nothing in this window would be blocked"
                        description={
                          impactGroup === 'wouldBlockInEnforce'
                            ? 'No recorded tool call in this window matches a blocking rule, so turning Enforce on would have denied nothing. Widen the window to test that against more history.'
                            : 'No recorded tool call in this window hit the catastrophic, self-protection or protected-path floors.'
                        }
                      />
                    }
                  />
                </div>

                {/* What the forecast cost, and what it cannot see. Both belong
                    on screen: a number without its limits invites more trust
                    than it earned. */}
                {impact && (
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>
                    <span className="cs-mono">
                      {impact.scanned.evaluated.toLocaleString()} calls · {impact.scanned.distinctCalls.toLocaleString()} distinct · {impact.timing.totalMs.toLocaleString()} ms
                      {impact.cached && ' (cached)'}
                    </span>
                    {impact.scanned.truncated && (
                      <span style={{ color: 'var(--cs-sev-medium-fg)' }}>partial scan — totals are a floor</span>
                    )}
                    <button
                      type="button"
                      onClick={() => setShowCaveats(s => !s)}
                      aria-expanded={showCaveats}
                      className="inline-flex items-center gap-1"
                      style={{ color: 'var(--cs-text-muted)' }}
                    >
                      <Info className="w-3 h-3" aria-hidden="true" />
                      {showCaveats ? 'Hide' : 'What this replay cannot see'}
                    </button>
                  </div>
                )}
                {impact && showCaveats && (
                  <ul
                    className="flex flex-col gap-1 pl-4 list-disc"
                    style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}
                  >
                    {impact.caveats.map((c, i) => <li key={i}>{c}</li>)}
                  </ul>
                )}
              </>
            )}
          </div>
        )}
      </section>

      {/* ── Counts ──────────────────────────────────────────────────────────
          Five compact counters rather than five cards: the vertical budget on a
          1366×768 screen belongs to the feed. */}
      <div className="shrink-0 grid grid-cols-3 xl:grid-cols-5 gap-1 px-3 py-1">
        <Counter label="Events" value={stats.total} />
        <Counter label="Critical" value={stats.bySeverity.critical} severity="critical" />
        <Counter label="High" value={stats.bySeverity.high} severity="high" />
        <Counter label="Medium" value={stats.bySeverity.medium} severity="medium" />
        <Counter label="Low" value={stats.bySeverity.low} severity="low" />
      </div>

      {/* ── Feed, and the rule summary derived from it ──────────────────────
          Side by side once there is width for it; stacked below 1440, where the
          summary is capped and scrolls so the feed keeps a definite height. */}
      <div className="flex-1 min-h-0 min-w-0 flex flex-col 2xl:flex-row">
        {stats.topRules.length > 0 && (
          <aside
            className="shrink-0 order-1 2xl:order-2 2xl:w-[248px] 3xl:w-[280px] max-h-[72px] 2xl:max-h-none overflow-auto px-3 py-1 flex flex-col gap-1"
            aria-label="Rules by would-block count"
            style={{ borderBottom: '1px solid var(--cs-rule)' }}
          >
            <p
              className="uppercase shrink-0"
              style={{
                color: 'var(--cs-text-faint)',
                fontSize: 'var(--cs-text-2xs)',
                letterSpacing: 'var(--cs-tracking-wide)',
              }}
            >
              Top rules
            </p>
            {stats.topRules.map(r => {
              const sev = normalizeSeverity(r.severity);
              return (
                <div key={r.label} className="flex items-center gap-2 min-w-0">
                  {/* The bar measures, it does not warn, so it is drawn in the
                      accent rather than the severity ramp — the badge beside
                      the label is what carries the risk. The two greys that
                      would have done the job here are a hair apart in the light
                      themes, and a bar you cannot see is not a bar. */}
                  <div
                    className="relative flex-1 min-w-0 h-5 rounded overflow-hidden"
                    style={{ background: 'var(--cs-bg-sunken)' }}
                  >
                    <div
                      className="absolute inset-y-0 left-0"
                      style={{ width: `${(r.count / maxRuleCount) * 100}%`, background: 'var(--cs-accent-soft)' }}
                      aria-hidden="true"
                    />
                    <div className="absolute inset-0 flex items-center gap-1.5 px-1.5 min-w-0">
                      <SeverityBadge severity={sev} showLabel={false} />
                      <span
                        className="truncate"
                        title={r.label}
                        style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }}
                      >
                        {r.label}
                      </span>
                    </div>
                  </div>
                  <span
                    className="cs-mono shrink-0 text-right w-6"
                    style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
                  >
                    {r.count}
                  </span>
                </div>
              );
            })}
          </aside>
        )}

        <div className="order-2 2xl:order-1 flex-1 min-h-0 min-w-0 flex flex-col">
          <DataTable
            rows={events.slice(0, 200)}
            columns={columns}
            rowKey={eventKey}
            label="Enforcement events"
            density={density}
            minWidth={620}
            severity={e => normalizeSeverity(e.severity)}
            onActivate={e => setExpanded(prev => (prev === eventKey(e) ? null : eventKey(e)))}
            renderDetail={renderDetail}
            loading={feedLoading}
            error={feedError && events.length === 0 ? (
              <ErrorState
                description={`The enforcement log did not respond (${feedError}). The hook is unaffected — this is only the view.`}
                onRetry={() => { setFeedLoading(true); fetchLog(); }}
              />
            ) : undefined}
            empty={
              <EmptyState
                icon={standing === 'blocking'
                  ? <Radio className="w-6 h-6" aria-hidden="true" />
                  : <ListX className="w-6 h-6" aria-hidden="true" />}
                title="No enforcement events yet"
                description={protectionActive
                  ? 'A row lands here the moment an agent runs a tool call that matches a blocking rule — and that call is denied before it runs.'
                  : 'A row lands here the moment an agent runs a tool call that matches a blocking rule. In monitor mode it is recorded as a would-block and allowed through.'}
              />
            }
          />
        </div>
      </div>
    </div>
  );
}
