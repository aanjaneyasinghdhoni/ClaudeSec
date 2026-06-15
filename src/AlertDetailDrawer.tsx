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
import React from 'react';
import { X, ExternalLink, Shield, Clock, Cpu, Hash, FileCode2 } from 'lucide-react';
import type { Severity } from './shared/types';

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

// Mirror of the table's severity badge palette so the drawer reads consistently.
const SEV_BADGE: Record<string, string> = {
  critical: 'bg-rose-900/60 text-rose-200 border border-rose-500/60',
  high:   'bg-red-900/40 text-red-300 border border-red-700/40',
  medium: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  low:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  none:   'bg-slate-800 text-slate-400',
};

function formatTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); }
  catch { return ts; }
}

/** A single label / value row in the detail list. */
function DetailRow({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)' }}>
      <span className="mt-0.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }}>{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--cs-text-faint)' }}>{label}</p>
        <div className="text-xs break-all" style={{ color: 'var(--cs-text-base)' }}>{children}</div>
      </div>
    </div>
  );
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
  if (!alert) return null;

  const harnessName = HARNESS_NAMES[alert.harness] ?? alert.harness;
  const canInvestigate = !!onInvestigate && !!alert.spanId && !!alert.traceId;
  const hitCount = alert.count ?? 1;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="relative w-full max-w-md h-full overflow-y-auto shadow-2xl"
        style={{ background: 'var(--cs-bg-surface)', borderLeft: '1px solid var(--cs-border)' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-label="Alert detail"
      >
        {/* Header */}
        <div
          className="flex items-start justify-between px-5 py-4 sticky top-0 z-10"
          style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-border)' }}
        >
          <div className="min-w-0 pr-4">
            <p className="text-[11px] uppercase tracking-wider mb-1" style={{ color: 'var(--cs-text-faint)' }}>Alert detail</p>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`px-1.5 py-0.5 rounded text-[11px] font-mono uppercase ${SEV_BADGE[alert.severity] ?? SEV_BADGE.none}`}>
                {alert.severity}
              </span>
              {hitCount > 1 && (
                <span className="text-[11px] font-mono" style={{ color: 'var(--cs-text-muted)' }}>fired {hitCount}×</span>
              )}
            </div>
            <h2 className="text-sm font-semibold mt-1.5" style={{ color: 'var(--cs-text-base)' }}>{alert.ruleLabel}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="transition-colors flex-shrink-0"
            style={{ color: 'var(--cs-text-muted)' }}
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-2">
          <DetailRow icon={<Shield className="w-3.5 h-3.5" />} label="Rule matched">
            {alert.ruleLabel}
          </DetailRow>

          <DetailRow icon={<Clock className="w-3.5 h-3.5" />} label="When">
            <span className="font-mono">{formatTime(alert.ts)}</span>
          </DetailRow>

          <DetailRow icon={<Cpu className="w-3.5 h-3.5" />} label="Agent">
            <span className="inline-flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: HARNESS_COLORS[alert.harness] ?? '#64748b' }} />
              {harnessName}
            </span>
          </DetailRow>

          <DetailRow icon={<FileCode2 className="w-3.5 h-3.5" />} label="Span name">
            <span className="font-mono">{alert.spanName || '—'}</span>
          </DetailRow>

          <DetailRow icon={<Hash className="w-3.5 h-3.5" />} label="Session / trace">
            <span className="font-mono" style={{ color: 'var(--cs-text-muted)' }}>{alert.traceId || '—'}</span>
          </DetailRow>

          <DetailRow icon={<Hash className="w-3.5 h-3.5" />} label="Span ID">
            <span className="font-mono" style={{ color: 'var(--cs-text-muted)' }}>{alert.spanId || '—'}</span>
          </DetailRow>

          {/* Matched snippet — the scrubbed text that tripped the rule. */}
          <div className="px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)', border: '1px solid var(--cs-border)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--cs-text-faint)' }}>Matched snippet (scrubbed)</p>
            {alert.matchedText ? (
              <code className="block text-[11px] font-mono text-red-300 bg-red-900/20 px-2 py-1.5 rounded break-all">
                {alert.matchedText}
              </code>
            ) : (
              <span className="text-xs" style={{ color: 'var(--cs-text-faint)' }}>No snippet captured.</span>
            )}
          </div>

          {/* Secondary action — full session context lives in the timeline. */}
          {canInvestigate && (
            <button
              type="button"
              onClick={() => onInvestigate!(alert.traceId, alert.spanId)}
              className="w-full flex items-center justify-center gap-1.5 px-4 py-2 mt-2 rounded-lg text-xs font-medium text-white transition-colors"
              style={{ background: 'var(--cs-accent)' }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.9')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              <ExternalLink className="w-3.5 h-3.5" /> Open in Timeline
            </button>
          )}
          <p className="text-[10px] text-center" style={{ color: 'var(--cs-text-faint)' }}>
            Opens the full session timeline with this span selected.
          </p>
        </div>
      </div>
    </div>
  );
}
