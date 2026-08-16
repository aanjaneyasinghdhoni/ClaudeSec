/**
 * AlertDetailDrawer — a slide-in panel that shows the full detail of a single
 * alert in place, so clicking an alert row populates a detail view (matching the
 * on-screen "Select an alert to see details" promise) instead of silently
 * navigating away. A clearly-labelled secondary "Open in Timeline →" action is
 * offered for users who want the surrounding session context.
 *
 * It renders from the AlertRow the list already holds (server-scrubbed), so it
 * needs no extra fetch — the same fields the table shows, expanded and labelled.
 */
import React, { useEffect, useRef } from 'react';
import { X, ExternalLink, Shield, Clock, Cpu, Hash, FileCode2, Waypoints } from 'lucide-react';
import type { Severity } from './shared/types';
import { SeverityBadge } from './components/data';

export interface AlertDetail {
  id: number;
  ts: string;
  ruleLabel: string;
  severity: Severity;
  spanId: string;
  traceId: string;
  harness: string;
  spanName: string;
  matchedText: string;
  count: number;
}

const HARNESS_NAMES: Record<string, string> = {
  'claude-code': 'Claude Code',
  'copilot':     'GitHub Copilot CLI',
  'codex':       'Codex',
  'unknown':     'Unknown',
};

const HARNESS_COLORS: Record<string, string> = {
  'claude-code': '#f97316',
  'copilot':     '#22c55e',
  'codex':       '#a855f7',
  'unknown':     '#64748b',
};

function formatTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); }
  catch { return ts; }
}

// ── Sequence chain parsing ───────────────────────────────────────────────────
//
// A sequence-rule finding's evidence IS the chain — see server/sequenceRules.ts
// `renderChain()`. It arrives here as one pre-rendered, scrubbed string in
// `matchedText`:
//
//   1. 2026-08-15T10:23:11.045Z  [Read a1b2c3d4e5f6]  credential read: .env
//   2. 2026-08-15T10:24:02.881Z  [Bash 9f8e7d6c5b4a]  network egress: curl -X POST …
//   (2 steps over 51.8s)
//
// That is the product's best evidence — the story, not a label — so it earns
// its own step-list rendering instead of sitting in a <pre> block. Parsing is
// deliberately strict: anything that doesn't fully match falls back to the
// plain snippet rendering below rather than showing a mangled list.
interface ParsedStep { n: number; ts: string; span: string; spanId: string; step: string; detail: string }
interface ParsedChain { steps: ParsedStep[]; stepCount: number; elapsedSec: string }

const STEP_LINE = /^(\d+)\.\s+(\S+)\s+\[(\S+)\s+([^\]]+)\]\s+([^:]+):\s*(.*)$/;
const FOOTER_LINE = /^\((\d+)\s+steps?\s+over\s+([\d.]+)s\)$/;

function parseChain(text: string): ParsedChain | null {
  const lines = text.split('\n').filter(l => l.length > 0);
  if (lines.length < 2) return null;
  const footer = lines[lines.length - 1].match(FOOTER_LINE);
  if (!footer) return null;
  const steps: ParsedStep[] = [];
  for (const line of lines.slice(0, -1)) {
    const m = line.match(STEP_LINE);
    if (!m) return null;
    steps.push({ n: Number(m[1]), ts: m[2], span: m[3], spanId: m[4], step: m[5].trim(), detail: m[6] });
  }
  if (steps.length === 0) return null;
  return { steps, stepCount: Number(footer[1]), elapsedSec: footer[2] };
}

function SequenceChain({ chain }: { chain: ParsedChain }) {
  return (
    <div className="px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-rule)' }}>
      <p
        className="flex items-center gap-1.5 mb-2"
        style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}
      >
        <Waypoints className="w-3 h-3" aria-hidden="true" />
        Sequence — {chain.stepCount} step{chain.stepCount === 1 ? '' : 's'} over {chain.elapsedSec}s
      </p>
      <ol className="relative">
        {chain.steps.map((s, i) => (
          <li key={i} className="relative flex gap-3 pb-3 last:pb-0">
            {/* The connecting line reads as a single ordered story rather than
                a set of independent facts — the whole point of a sequence
                finding over a stateless regex hit. */}
            {i < chain.steps.length - 1 && (
              <span
                aria-hidden="true"
                className="absolute left-[9px] top-5 bottom-0 w-px"
                style={{ background: 'var(--cs-rule)' }}
              />
            )}
            <span
              className="relative shrink-0 mt-0.5 flex items-center justify-center rounded-full cs-mono"
              style={{
                width: 18, height: 18,
                background: 'var(--cs-bg-raised)',
                color: 'var(--cs-text-muted)',
                fontSize: 'var(--cs-text-2xs)',
                fontWeight: 'var(--cs-weight-bold)',
              }}
            >
              {s.n}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-medium)' }}>
                  {s.step}
                </span>
                <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>
                  {s.span} · {s.spanId}
                </span>
              </div>
              <p className="cs-mono mt-0.5 break-words" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)', overflowWrap: 'anywhere' }}>
                {s.detail}
              </p>
              <p className="cs-mono mt-0.5" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>
                {formatTime(s.ts)}
              </p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** A single label / value row in the detail list. */
function DetailRow({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)' }}>
      <span className="mt-0.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }}>{icon}</span>
      <div className="min-w-0 flex-1">
        <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', marginBottom: 2 }}>
          {label}
        </p>
        <div style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)', wordBreak: 'break-word' }}>{children}</div>
      </div>
    </div>
  );
}

/**
 * Focus trap + Escape-to-close + focus restore, shared by every slide-in
 * panel in this file set (this drawer, the span search drawer, the compare
 * panel) so keyboard behaviour is identical wherever one appears rather than
 * reinvented per surface.
 */
export function useDrawerA11y(
  open: boolean,
  onClose: () => void,
  containerRef: React.RefObject<HTMLElement | null>,
) {
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreRef.current = document.activeElement as HTMLElement | null;

    const focusables = () => {
      const el = containerRef.current;
      if (!el) return [] as HTMLElement[];
      return Array.from(
        el.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter(f => f.offsetParent !== null);
    };

    // Move focus into the drawer as soon as it opens, so Tab starts from a
    // sane place and focus is never left behind on the trigger element.
    const first = focusables()[0];
    (first ?? containerRef.current)?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); return; }
      if (e.key !== 'Tab') return;
      const items = focusables();
      if (items.length === 0) return;
      const firstEl = items[0];
      const lastEl  = items[items.length - 1];
      if (e.shiftKey && document.activeElement === firstEl) { e.preventDefault(); lastEl.focus(); }
      else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); firstEl.focus(); }
    };
    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      // Hand focus back to whatever opened the drawer, if it's still around —
      // a triage loop that ends with focus stranded on a closed panel is a
      // loop the keyboard can't continue.
      const back = restoreRef.current;
      if (back && document.contains(back)) back.focus();
    };
  }, [open, onClose, containerRef]);
}

export function AlertDetailDrawer({
  alert,
  onClose,
  onInvestigate,
}: {
  alert: AlertDetail | null;
  onClose: () => void;
  onInvestigate?: (traceId: string, spanId: string) => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  useDrawerA11y(alert != null, onClose, panelRef);

  if (!alert) return null;

  const harnessName = HARNESS_NAMES[alert.harness] ?? alert.harness;
  const canInvestigate = !!onInvestigate && !!alert.spanId && !!alert.traceId;
  const hitCount = alert.count ?? 1;
  const chain = alert.matchedText ? parseChain(alert.matchedText) : null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        ref={panelRef}
        className="relative w-full max-w-md h-full overflow-y-auto"
        style={{ background: 'var(--cs-bg-overlay)', boxShadow: 'var(--cs-shadow-drawer)' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Alert detail"
        tabIndex={-1}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between px-5 py-4 sticky top-0 z-10"
          style={{ background: 'var(--cs-bg-overlay)', borderBottom: '1px solid var(--cs-rule)' }}
        >
          <div className="min-w-0 pr-4">
            <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', marginBottom: 4 }}>
              Alert detail
            </p>
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={alert.severity} />
              {hitCount > 1 && (
                <span className="cs-mono" style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}>fired {hitCount}×</span>
              )}
            </div>
            <h2 style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', marginTop: 6 }}>
              {alert.ruleLabel}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="transition-colors flex-shrink-0 rounded p-1"
            style={{ color: 'var(--cs-text-muted)' }}
            aria-label="Close"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-2">
          <DetailRow icon={<Shield className="w-3.5 h-3.5" aria-hidden="true" />} label="Rule matched">
            {alert.ruleLabel}
          </DetailRow>

          <DetailRow icon={<Clock className="w-3.5 h-3.5" aria-hidden="true" />} label="When">
            <span className="cs-mono">{formatTime(alert.ts)}</span>
          </DetailRow>

          <DetailRow icon={<Cpu className="w-3.5 h-3.5" aria-hidden="true" />} label="Agent">
            <span className="inline-flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: HARNESS_COLORS[alert.harness] ?? HARNESS_COLORS.unknown }} aria-hidden="true" />
              {harnessName}
            </span>
          </DetailRow>

          <DetailRow icon={<FileCode2 className="w-3.5 h-3.5" aria-hidden="true" />} label="Span name">
            <span className="cs-mono">{alert.spanName || '—'}</span>
          </DetailRow>

          <DetailRow icon={<Hash className="w-3.5 h-3.5" aria-hidden="true" />} label="Session / trace">
            <span className="cs-mono" style={{ color: 'var(--cs-text-muted)' }}>{alert.traceId || '—'}</span>
          </DetailRow>

          <DetailRow icon={<Hash className="w-3.5 h-3.5" aria-hidden="true" />} label="Span ID">
            <span className="cs-mono" style={{ color: 'var(--cs-text-muted)' }}>{alert.spanId || '—'}</span>
          </DetailRow>

          {/* Evidence: a sequence finding's ordered chain, rendered as a step
              list, or — for every other rule — the scrubbed matched snippet. */}
          {chain ? (
            <SequenceChain chain={chain} />
          ) : (
            <div className="px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)' }}>
              <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', marginBottom: 4 }}>
                Matched snippet (scrubbed)
              </p>
              {alert.matchedText ? (
                <code
                  className="cs-mono block px-2 py-1.5 rounded break-words"
                  style={{ background: 'var(--cs-bg-sunken)', color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)', overflowWrap: 'anywhere' }}
                >
                  {alert.matchedText}
                </code>
              ) : (
                <span style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>No snippet captured.</span>
              )}
            </div>
          )}

          {/* Secondary action — full session context lives in the timeline. */}
          {canInvestigate && (
            <button
              type="button"
              onClick={() => onInvestigate!(alert.traceId, alert.spanId)}
              className="w-full flex items-center justify-center gap-1.5 px-4 py-2 mt-2 rounded-lg transition-opacity"
              style={{ background: 'var(--cs-accent)', color: '#fff', fontSize: 'var(--cs-text-xs)', fontWeight: 'var(--cs-weight-medium)' }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.9')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" /> Open in Timeline
            </button>
          )}
          <p className="text-center" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)' }}>
            Opens the full session timeline with this span selected.
          </p>
        </div>
      </div>
    </div>
  );
}
