/**
 * HarnessTab — one stat tile per agent that has ever talked to this instance.
 *
 * This is the only surface in the app that is not a list. There are a handful
 * of harnesses, each with a number worth reading at a glance, so the shape is a
 * tile: one big metric, a couple of supporting figures, and the severity spine
 * down the leading edge carrying the worst thing that agent has done. That
 * makes the row of tiles readable as a single line of colour, exactly like the
 * lists elsewhere — which is the point of the spine.
 *
 * Every tile is also the filter control for its agent, so choosing "show me
 * only Codex" is one click on the thing you were already looking at rather than
 * a separate control somewhere else.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Activity, Filter, X } from 'lucide-react';
import { socket } from './socket';
import { formatTokens } from './lib/format';
import type { Severity } from './shared/types';
import {
  SeveritySpine, SEVERITY_META, severityText,
  EmptyState, ErrorState,
} from './components/data';
import { Skeleton } from './components/ui/skeleton';

// ---------------------------------------------------------------------------
// Constants — redefined inline (do not import from App.tsx)
// ---------------------------------------------------------------------------

// Identity, not risk. Agents keep a fixed hue outside the severity ramp so no
// agent's brand colour can ever be mistaken for a threat level.
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
  'unknown':     'Unknown Agent',
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HarnessStats {
  harness: string;
  spanCount: number;
  sessionCount: number;
  threatHigh: number;
  threatMedium: number;
  threatLow: number;
  tokensIn: number;
  tokensOut: number;
  firstSeen: string;
  lastSeen: string;
}

interface Props {
  onFilterHarness: (harness: string | null) => void;
  activeFilter: string | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  if (isNaN(diff) || diff < 0) return '—';
  const s = Math.floor(diff / 1000);
  if (s < 60)   return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)   return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24)   return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function harnessColor(harness: string): string {
  return HARNESS_COLORS[harness] ?? HARNESS_COLORS.unknown;
}

function harnessName(harness: string): string {
  return HARNESS_NAMES[harness] ?? harness;
}

/** The worst level this agent has produced — what its spine is coloured by. */
function worstSeverity(s: HarnessStats): Severity {
  if (s.threatHigh > 0)   return 'high';
  if (s.threatMedium > 0) return 'medium';
  if (s.threatLow > 0)    return 'low';
  return 'none';
}

/**
 * A count at one severity level. The glyph and the word travel with the colour,
 * so the level survives greyscale — the same contract the badge in a table row
 * keeps.
 */
function ThreatCount({ severity, count }: { severity: Severity; count: number }) {
  const { label, Icon, meaning } = SEVERITY_META[severity];
  return (
    <span
      className="inline-flex items-center gap-1"
      title={`${count} ${label.toLowerCase()}-severity detections — ${meaning}`}
    >
      <Icon className="w-3 h-3 shrink-0" style={{ color: `var(--cs-sev-${severity})` }} aria-hidden="true" />
      <span className="cs-mono tabular-nums" style={{ color: severityText(severity), fontSize: 'var(--cs-text-xs)' }}>
        {count.toLocaleString()}
      </span>
      <span
        className="uppercase"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {label}
      </span>
    </span>
  );
}

/** A supporting figure under the hero metric. */
function SubStat({ value, label, title }: { value: string; label: string; title?: string }) {
  return (
    <span className="flex flex-col" title={title}>
      <span
        className="cs-mono tabular-nums"
        style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-medium)' }}
      >
        {value}
      </span>
      <span
        className="uppercase"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-2xs)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {label}
      </span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// The tile
// ---------------------------------------------------------------------------

function HarnessTile({
  stats,
  isActive,
  tabbable,
  onActivate,
  onFocus,
  onKeyDown,
}: {
  stats: HarnessStats;
  isActive: boolean;
  tabbable: boolean;
  onActivate: () => void;
  onFocus: () => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLDivElement>) => void;
}) {
  const sev  = worstSeverity(stats);
  const name = harnessName(stats.harness);
  const hasThreats = stats.threatHigh > 0 || stats.threatMedium > 0 || stats.threatLow > 0;
  const hasTokens  = stats.tokensIn > 0 || stats.tokensOut > 0;

  return (
    <div
      data-tile
      role="button"
      aria-pressed={isActive}
      tabIndex={tabbable ? 0 : -1}
      onClick={onActivate}
      onFocus={onFocus}
      onKeyDown={onKeyDown}
      title={isActive ? `Showing only ${name} — activate to clear` : `Show only ${name} in the timeline`}
      className="flex items-stretch gap-3 rounded-lg p-3 cursor-pointer transition-colors hover:bg-[var(--cs-bg-raised)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
      style={{
        background: 'var(--cs-bg-surface)',
        // Selection is chrome, so it is the accent — never a severity colour.
        boxShadow: isActive ? 'inset 0 0 0 1px var(--cs-accent-line)' : undefined,
      }}
    >
      <SeveritySpine severity={sev} />

      <div className="flex-1 min-w-0 flex flex-col gap-2">
        {/* Who */}
        <div className="flex items-center gap-1.5 min-w-0">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: harnessColor(stats.harness) }}
            aria-hidden="true"
          />
          <span
            className="truncate"
            style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-semibold)' }}
          >
            {name}
          </span>
          {isActive && (
            <span
              className="ml-auto inline-flex items-center gap-1 shrink-0"
              style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-2xs)', letterSpacing: 'var(--cs-tracking-wide)' }}
            >
              <Filter className="w-3 h-3" aria-hidden="true" /> FILTERED
            </span>
          )}
        </div>

        {/* The hero metric, and the figures that qualify it. */}
        <div className="flex items-end gap-4 flex-wrap">
          <span className="flex flex-col">
            <span
              className="tabular-nums"
              title={`${stats.spanCount.toLocaleString()} spans recorded`}
              style={{
                fontFamily: 'var(--cs-font-display)',
                fontSize: 'var(--cs-text-2xl)',
                fontWeight: 'var(--cs-weight-bold)',
                letterSpacing: 'var(--cs-tracking-tight)',
                lineHeight: 'var(--cs-leading-tight)',
                color: 'var(--cs-text-strong)',
              }}
            >
              {stats.spanCount.toLocaleString()}
            </span>
            <span
              className="uppercase"
              style={{
                color: 'var(--cs-text-faint)',
                fontSize: 'var(--cs-text-2xs)',
                letterSpacing: 'var(--cs-tracking-wide)',
              }}
            >
              Spans
            </span>
          </span>

          <SubStat
            value={stats.sessionCount.toLocaleString()}
            label="Sessions"
            title={`${stats.sessionCount.toLocaleString()} distinct sessions`}
          />

          {hasTokens && (
            <>
              <SubStat
                value={`↑ ${formatTokens(stats.tokensIn)}`}
                label="Tokens in"
                title={`${stats.tokensIn.toLocaleString()} tokens in`}
              />
              <SubStat
                value={`↓ ${formatTokens(stats.tokensOut)}`}
                label="Tokens out"
                title={`${stats.tokensOut.toLocaleString()} tokens out`}
              />
            </>
          )}
        </div>

        {/* What it tripped. Only levels with a non-zero count appear, so a quiet
            agent's tile stays quiet rather than showing three zeroes. */}
        {hasThreats && (
          <div className="flex items-center gap-3 flex-wrap">
            {stats.threatHigh   > 0 && <ThreatCount severity="high"   count={stats.threatHigh} />}
            {stats.threatMedium > 0 && <ThreatCount severity="medium" count={stats.threatMedium} />}
            {stats.threatLow    > 0 && <ThreatCount severity="low"    count={stats.threatLow} />}
          </div>
        )}

        <p
          className="mt-auto"
          title={stats.lastSeen ? new Date(stats.lastSeen).toLocaleString() : undefined}
          style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
        >
          Last seen {relativeTime(stats.lastSeen)}
        </p>
      </div>
    </div>
  );
}

/** A tile-shaped skeleton, so nothing jumps when the real numbers land. */
function TileSkeleton() {
  return (
    <div className="rounded-lg p-3 space-y-3" style={{ background: 'var(--cs-bg-surface)' }} aria-hidden="true">
      <Skeleton className="h-3 w-32" />
      <Skeleton className="h-7 w-24" />
      <Skeleton className="h-2.5 w-40" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function HarnessTab({ onFilterHarness, activeFilter }: Props): React.ReactElement {
  const [harnesses, setHarnesses] = useState<HarnessStats[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [focused,   setFocused]   = useState<string | null>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  const fetchHarnesses = useCallback(() => {
    fetch('/api/harnesses')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: { harnesses: HarnessStats[] }) => {
        const sorted = [...(d.harnesses ?? [])].sort((a, b) => b.spanCount - a.spanCount);
        setHarnesses(sorted);
        setLoadError(null);
      })
      // "No agents" and "we could not ask" look identical on an empty grid, and
      // they mean very different things when you are watching for activity.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchHarnesses();
    socket.on('graph-update', fetchHarnesses);
    return () => { socket.off('graph-update', fetchHarnesses); };
  }, [fetchHarnesses]);

  const handleFilter = (harness: string) => {
    onFilterHarness(activeFilter === harness ? null : harness);
  };

  // The grid is one tab stop and the arrow keys walk it, matching the row
  // contract the lists elsewhere keep.
  const moveFocus = (from: HTMLElement, delta: number | 'first' | 'last') => {
    const all = Array.from(gridRef.current?.querySelectorAll<HTMLElement>('[data-tile]') ?? []);
    if (all.length === 0) return;
    const here = all.indexOf(from);
    const next =
      delta === 'first' ? 0 :
      delta === 'last'  ? all.length - 1 :
      Math.min(all.length - 1, Math.max(0, here + delta));
    all[next]?.focus();
  };

  const onTileKeyDown = (e: React.KeyboardEvent<HTMLDivElement>, harness: string) => {
    if (e.target !== e.currentTarget) return;
    switch (e.key) {
      case 'Enter':
      case ' ':
        e.preventDefault(); handleFilter(harness); break;
      case 'ArrowRight':
      case 'ArrowDown': e.preventDefault(); moveFocus(e.currentTarget, 1); break;
      case 'ArrowLeft':
      case 'ArrowUp':   e.preventDefault(); moveFocus(e.currentTarget, -1); break;
      case 'Home':      e.preventDefault(); moveFocus(e.currentTarget, 'first'); break;
      case 'End':       e.preventDefault(); moveFocus(e.currentTarget, 'last'); break;
      default: break;
    }
  };

  const firstKey = harnesses[0]?.harness ?? null;

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div
        className="flex items-center gap-2 xl:gap-3 px-3 py-1.5 shrink-0 flex-wrap"
        style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
      >
        <div className="flex items-center gap-2 shrink-0">
          <Activity className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          <h2 style={{ fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
            Agent harnesses
          </h2>
          <span
            className="cs-mono"
            title={`${harnesses.length} agents have reported activity`}
            style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}
          >
            {harnesses.length}
          </span>
        </div>

        {activeFilter && (
          <button
            type="button"
            onClick={() => onFilterHarness(null)}
            className="ml-auto inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors"
            style={{ background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
            title={`Stop filtering the timeline by ${harnessName(activeFilter)}`}
          >
            <X className="w-3.5 h-3.5" aria-hidden="true" />
            Clear filter
          </button>
        )}
      </div>

      {/* ── Tiles ────────────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-y-auto p-3">
        {loading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 3xl:grid-cols-4 gap-3">
            {[0, 1, 2].map(i => <TileSkeleton key={i} />)}
          </div>
        ) : loadError ? (
          <ErrorState
            title="Could not read agent activity"
            description={`The harness summary did not respond (${loadError}). Recording is unaffected — this is only the view.`}
            onRetry={() => { setLoading(true); fetchHarnesses(); }}
          />
        ) : harnesses.length === 0 ? (
          <EmptyState
            icon={<Activity className="w-6 h-6" aria-hidden="true" />}
            title="No agent activity recorded"
            description="A tile appears here the first time an agent produces a span — from a local transcript, or from any harness pointed at this instance over OTLP."
          />
        ) : (
          <div
            ref={gridRef}
            className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 3xl:grid-cols-4 gap-3"
          >
            {harnesses.map(h => (
              <HarnessTile
                key={h.harness}
                stats={h}
                isActive={activeFilter === h.harness}
                tabbable={(focused ?? firstKey) === h.harness}
                onActivate={() => handleFilter(h.harness)}
                onFocus={() => setFocused(h.harness)}
                onKeyDown={e => onTileKeyDown(e, h.harness)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
