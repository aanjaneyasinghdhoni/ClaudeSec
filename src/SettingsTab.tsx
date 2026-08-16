import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Settings, Database, Globe, ChevronDown, ChevronUp, Check, BellRing,
  History, Copy, Terminal, ShieldCheck, AlertTriangle, CircleSlash, CheckCircle2, Activity, Trash2,
  Lock, Pencil, ArrowRight, Gauge, SlidersHorizontal, RefreshCw, Loader2, HardDrive,
} from 'lucide-react';
import { ThresholdRulesSection } from './ThresholdRulesSection';
import { WebhookDeliverySection } from './WebhookDeliverySection';

// ---------------------------------------------------------------------------
// Types — kept in step with server/routes/dbStats.ts and server/retentionProfiles.ts.
// Nothing here invents a fallback number: a row with no data yet shows a
// skeleton or an error, never a stale-looking guess like the old "50,000".
// ---------------------------------------------------------------------------

interface RetentionEffective {
  limitingFactor: 'age' | 'capacity' | 'none' | 'unknown';
  effectiveWindowDays: number | null;
  spansPerDay: number | null;
  projectedSpansInWindow: number | null;
  ingestStopsAtSpans: number | null;
  ingestStopsAfterDays: number | null;
  estimatedBytes: number | null;
  warning: string | null;
}

type RetentionSource = 'env' | 'config' | 'default';
type RetentionProfileId = 'minimum' | 'audit-year' | 'forensic' | 'custom';

interface RetentionConfig {
  // Legacy shape: 0 means unbounded, not zero.
  maxSpans: number;
  retentionDays: number;
  profile: RetentionProfileId;
  profileLabel: string;
  sources: { retentionDays: RetentionSource; maxSpans: RetentionSource };
  envOverride: string | null;
  effective: RetentionEffective;
}

interface RetentionProfileCatalogEntry {
  id: 'minimum' | 'audit-year' | 'forensic';
  label: string;
  days: number;
  maxSpans: number;
  summary: string;
}

interface DbStatsResponse {
  spansTotal: number;
  sessionsTotal: number;
  alertsTotal: number;
  dbSizeBytes: number;
  dbSizeHuman: string;
  retentionConfig: RetentionConfig;
  retentionProfiles: RetentionProfileCatalogEntry[];
}

interface ProfileProjection {
  id: 'minimum' | 'audit-year' | 'forensic';
  label: string;
  days: number | null;
  maxSpans: number | null;
  summary: string;
  active: boolean;
  /** What this profile would really deliver here, at the measured ingest rate. */
  deliversDays: number | null;
}

interface RetentionProfilesResponse {
  current: string;
  spansPerDay: number | null;
  profiles: ProfileProjection[];
}

interface RateLimitInfo {
  rps: number;
  burst: number;
  maxSpansBatch: number;
}

interface WebhookConfig {
  configured: boolean;
  urlPreview: string | null;
  threshold: 'low' | 'medium' | 'high' | 'critical';
  envOverride: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDays(n: number | null): string {
  return n == null ? 'unbounded' : `${n.toLocaleString()} day${n === 1 ? '' : 's'}`;
}

function formatSpans(n: number | null): string {
  return n == null ? 'unbounded' : n.toLocaleString();
}

// ---------------------------------------------------------------------------
// Group header — a quiet eyebrow + rule that clusters Sections by concern.
// Not interactive: it is furniture, not another accordion.
// ---------------------------------------------------------------------------

function GroupHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 pt-3 first:pt-0">
      <span
        style={{
          fontSize: 'var(--cs-text-2xs)',
          fontWeight: 'var(--cs-weight-semibold)',
          letterSpacing: 'var(--cs-tracking-wide)',
          color: 'var(--cs-text-faint)',
          textTransform: 'uppercase',
          whiteSpace: 'nowrap',
        }}
      >
        {children}
      </span>
      <span className="flex-1 h-px" style={{ background: 'var(--cs-rule)' }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section wrapper — collapsible accordion
// ---------------------------------------------------------------------------

interface SectionProps {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
  /** Optional tag shown next to the title (e.g. "Editable here"). */
  badge?: React.ReactNode;
}

export function Section({ icon, title, children, defaultOpen = true, badge }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--cs-bg-surface)', border: '1px solid var(--cs-rule)' }}>
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--cs-bg-raised)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
      >
        <span style={{ color: 'var(--cs-accent)' }} aria-hidden="true">{icon}</span>
        <span style={{ fontSize: 'var(--cs-text-base)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>{title}</span>
        {badge}
        <span className="flex-1" />
        {open
          ? <ChevronUp className="w-4 h-4" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
          : <ChevronDown className="w-4 h-4" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}
      </button>

      {/* Grid-rows 0fr→1fr animates height without a fixed cap, so tall sections
          are never clipped and the collapsing panel never grows past its real
          height to overlap the next section's header. The inner wrapper must own
          `overflow-hidden`. While closed, `pointer-events-none` + aria-hidden keep
          the collapsed content from intercepting clicks meant for siblings. */}
      <div
        className="grid transition-[grid-template-rows] duration-200 ease-out"
        style={{ gridTemplateRows: open ? '1fr' : '0fr' }}
      >
        <div className={`overflow-hidden ${open ? '' : 'pointer-events-none'}`} aria-hidden={!open}>
          <div className="px-4 pb-4 pt-1" style={{ borderTop: '1px solid var(--cs-rule)' }}>
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Read-only vs editable tags
//
// Settings come in two flavours and used to look identical: status cards that
// only *display* an env-driven value, and controls you can actually change in
// the dashboard. These small tags make the difference obvious at a glance.
// ---------------------------------------------------------------------------

/** Marks a whole section's controls as changeable here in the dashboard. */
function EditableTag() {
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium uppercase tracking-wide shrink-0"
      style={{ background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)', border: '1px solid var(--cs-accent-dim)' }}
      title="You can change this here in the dashboard."
    >
      <Pencil className="w-2.5 h-2.5" aria-hidden="true" /> Editable here
    </span>
  );
}

/** Marks a value as read-only — it is set via an environment variable and needs a restart. */
function ReadOnlyTag() {
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium uppercase tracking-wide shrink-0"
      style={{ background: 'rgba(var(--cs-info-rgb),0.10)', color: 'var(--cs-info)', border: '1px solid rgba(var(--cs-info-rgb),0.30)' }}
      title="This value is set via an environment variable, read once at startup — restart the server for a change to take effect."
    >
      <Lock className="w-2.5 h-2.5" aria-hidden="true" /> Set via env — restart required
    </span>
  );
}

// ---------------------------------------------------------------------------
// SaveButton — shows "✓ Saved" for 2 s
// ---------------------------------------------------------------------------

interface SaveButtonProps {
  onClick: () => Promise<void>;
  disabled?: boolean;
  label?: string;
}

function SaveButton({ onClick, disabled, label = 'Save' }: SaveButtonProps) {
  const [saved, setSaved] = useState(false);
  const [busy,  setBusy]  = useState(false);

  const handle = async () => {
    setBusy(true);
    try {
      // Only show "Saved" if onClick resolves. A validation/network failure
      // rejects, so the success state never flashes on a save that didn't happen.
      await onClick();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      /* caller surfaces the error inline; don't claim success */
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      onClick={handle}
      disabled={disabled || busy}
      className="flex items-center gap-1.5 px-4 py-1.5 disabled:opacity-50 rounded-lg text-xs font-medium transition-colors hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
      style={{ background: 'var(--cs-accent)', color: 'var(--cs-text-invert)' }}
    >
      {busy ? (
        <><Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> Saving…</>
      ) : saved ? (
        <><Check className="w-3.5 h-3.5" aria-hidden="true" /> Saved</>
      ) : (
        label
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// 1. Retention section — the profile picker
//
// The old version was two bare number inputs with no way to tell, before
// saving, whether the pair you typed would actually deliver the window it
// claimed. That gap is exactly what let 183 days / 50,000 spans ship: the
// span ceiling silently won on day 13 and nobody could see it coming. Every
// choice here — a named profile or a custom pair — shows its real
// consequence (which limit governs, the effective window in days, when
// ingest would stop) before and after it is applied.
// ---------------------------------------------------------------------------

function RetentionSkeleton() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 mt-3" aria-busy="true" aria-label="Loading retention settings">
      {[0, 1, 2].map(i => (
        <div key={i} className="rounded-lg p-3 space-y-2" style={{ background: 'var(--cs-bg-raised)' }}>
          <div className="h-3 w-20 rounded animate-pulse" style={{ background: 'var(--cs-bg-overlay)' }} />
          <div className="h-2.5 w-full rounded animate-pulse" style={{ background: 'var(--cs-bg-overlay)' }} />
          <div className="h-2.5 w-3/4 rounded animate-pulse" style={{ background: 'var(--cs-bg-overlay)' }} />
        </div>
      ))}
    </div>
  );
}

function EnvOverrideBanner({ text }: { text: React.ReactNode }) {
  return (
    <div
      className="flex items-start gap-2 px-3 py-2 rounded-lg text-[11px] leading-relaxed"
      style={{ background: 'rgba(var(--cs-info-rgb),0.08)', border: '1px solid rgba(var(--cs-info-rgb),0.25)', color: 'var(--cs-text-muted)' }}
    >
      <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--cs-info)' }} aria-hidden="true" />
      <span>{text}</span>
    </div>
  );
}

function RetentionWarningBanner({ text }: { text: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 px-3 py-2 rounded-lg text-[11px] leading-relaxed"
      style={{ background: 'rgba(var(--cs-sev-medium-rgb),0.10)', border: '1px solid rgba(var(--cs-sev-medium-rgb),0.35)', color: 'var(--cs-text-body)' }}
    >
      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--cs-warn)' }} aria-hidden="true" />
      <span><span style={{ color: 'var(--cs-warn)', fontWeight: 'var(--cs-weight-semibold)' }}>Ingestion will stop early. </span>{text}</span>
    </div>
  );
}

/** What a candidate profile would really deliver, in one sentence, derived
 *  entirely from server-reported numbers (never re-guessed on the client). */
function profileConsequence(p: ProfileProjection): string {
  if (p.days === null && p.maxSpans === null) {
    return 'Never prunes — growth is bounded only by free disk space.';
  }
  if (p.deliversDays === null) {
    return 'Not enough ingest history yet to project this — the summary above is the design target.';
  }
  if (p.deliversDays < (p.days ?? Infinity)) {
    return `Capacity-limited here: ingestion would stop after ~${p.deliversDays} of its ${p.days}-day window — the ${(p.maxSpans ?? 0).toLocaleString()}-span ceiling fills first.`;
  }
  return `Delivers the full ${p.days}-day window at your current ingest rate.`;
}

function ProfileCard({
  projection,
  applying,
  onApply,
}: {
  projection: ProfileProjection;
  applying: boolean;
  onApply: () => void;
}) {
  const capacityLimited = projection.deliversDays !== null && projection.deliversDays < (projection.days ?? Infinity);
  return (
    <div
      className="rounded-lg p-3 flex flex-col gap-2"
      style={{
        background: projection.active ? 'var(--cs-accent-soft)' : 'var(--cs-bg-raised)',
        border: `1px solid ${projection.active ? 'var(--cs-accent-dim)' : 'var(--cs-rule)'}`,
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <span style={{ fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
          {projection.label}
        </span>
        {projection.active && (
          <span
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold uppercase tracking-wide shrink-0"
            style={{ background: 'var(--cs-accent-dim)', color: 'var(--cs-accent)' }}
          >
            <CheckCircle2 className="w-2.5 h-2.5" aria-hidden="true" /> Active
          </span>
        )}
      </div>
      <p className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
        {formatDays(projection.days)} · {formatSpans(projection.maxSpans)} spans
      </p>
      <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)', lineHeight: 'var(--cs-leading-normal)' }}>
        {projection.summary}
      </p>
      {/* The consequence, before you commit: which limit bites first and the
          real effective window, at THIS install's measured ingest rate. */}
      <p
        style={{
          fontSize: 'var(--cs-text-xs)',
          lineHeight: 'var(--cs-leading-normal)',
          color: capacityLimited ? 'var(--cs-warn)' : 'var(--cs-text-faint)',
        }}
      >
        {profileConsequence(projection)}
      </p>
      <button
        type="button"
        onClick={onApply}
        disabled={projection.active || applying}
        className="mt-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors disabled:opacity-60 hover:opacity-90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
        style={{
          background: projection.active ? 'transparent' : 'var(--cs-accent)',
          color: projection.active ? 'var(--cs-text-faint)' : 'var(--cs-text-invert)',
        }}
      >
        {applying
          ? <><Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" /> Applying…</>
          : projection.active ? 'Current profile' : 'Use this profile'}
      </button>
    </div>
  );
}

export function RetentionSection() {
  const [stats,      setStats]      = useState<DbStatsResponse | null>(null);
  const [catalog,    setCatalog]    = useState<RetentionProfilesResponse | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [loadError,  setLoadError]  = useState('');
  const [applying,   setApplying]   = useState<string | null>(null);
  const [applyError, setApplyError] = useState('');

  // Custom-pair form state, seeded from the live config once it loads.
  const [customSpans, setCustomSpans] = useState<number>(1_000_000);
  const [customDays,  setCustomDays]  = useState<number>(183);
  const [customError, setCustomError] = useState('');

  const load = useCallback(async () => {
    try {
      const [dbRes, profRes] = await Promise.all([
        fetch('/api/db-stats'),
        fetch('/api/db-stats/retention/profiles'),
      ]);
      if (!dbRes.ok || !profRes.ok) throw new Error(`HTTP ${dbRes.status}/${profRes.status}`);
      const db = await dbRes.json() as DbStatsResponse;
      const prof = await profRes.json() as RetentionProfilesResponse;
      setStats(db);
      setCatalog(prof);
      setCustomSpans(db.retentionConfig.maxSpans || 1_000_000);
      setCustomDays(db.retentionConfig.retentionDays || 183);
      setLoadError('');
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const applyProfile = async (id: 'minimum' | 'audit-year' | 'forensic') => {
    setApplying(id);
    setApplyError('');
    try {
      const res = await fetch('/api/db-stats/retention', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile: id }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(d.error ?? 'Failed to apply profile');
      }
      // Re-read from the canonical endpoint rather than trusting the POST echo,
      // so the picker can never show a consequence the rest of the app disagrees with.
      await load();
    } catch (e) {
      setApplyError(e instanceof Error ? e.message : 'Failed to apply profile');
    } finally {
      setApplying(null);
    }
  };

  const saveCustom = useCallback(async () => {
    setCustomError('');
    if (!Number.isFinite(customSpans) || customSpans < 100) {
      setCustomError('Max spans must be a number ≥ 100.');
      throw new Error('invalid maxSpans');
    }
    if (!Number.isFinite(customDays) || customDays < 1) {
      setCustomError('Retention days must be a number ≥ 1.');
      throw new Error('invalid retentionDays');
    }
    const res = await fetch('/api/db-stats/retention', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxSpans: customSpans, retentionDays: customDays }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({})) as { error?: string };
      setCustomError(d.error ?? 'Failed to save');
      throw new Error(d.error ?? 'Failed to save');
    }
    await load();
  }, [customSpans, customDays, load]);

  if (loading) return <RetentionSkeleton />;

  if (loadError && !stats) {
    return (
      <div className="mt-3 space-y-2">
        <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>
          Could not load retention settings ({loadError}).
        </p>
        <button
          type="button"
          onClick={() => { setLoading(true); load(); }}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors hover:opacity-90"
          style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)' }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Try again
        </button>
      </div>
    );
  }

  if (!stats || !catalog) return null;
  const { retentionConfig } = stats;
  const eff = retentionConfig.effective;

  return (
    <div className="space-y-4 mt-3">
      {retentionConfig.envOverride && (
        <EnvOverrideBanner text={retentionConfig.envOverride} />
      )}
      {eff.warning && <RetentionWarningBanner text={eff.warning} />}

      {/* The three named profiles — each knows what it would really deliver at
          this install's own measured ingest rate before you click it. */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        {catalog.profiles.map(p => (
          <ProfileCard
            key={p.id}
            projection={p}
            applying={applying === p.id}
            onApply={() => applyProfile(p.id)}
          />
        ))}
      </div>
      {applyError && <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>{applyError}</p>}

      {/* Custom pair — a legitimate fourth choice when none of the named
          profiles fit, reported honestly as "Custom" rather than rounded to
          the nearest preset. */}
      <div className="rounded-lg p-3" style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule)' }}>
        <div className="flex items-center gap-2 mb-2">
          <span style={{ fontSize: 'var(--cs-text-sm)', fontWeight: 'var(--cs-weight-semibold)', color: 'var(--cs-text-strong)' }}>
            Custom
          </span>
          {retentionConfig.profile === 'custom' && (
            <span
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold uppercase tracking-wide"
              style={{ background: 'var(--cs-accent-dim)', color: 'var(--cs-accent)' }}
            >
              <CheckCircle2 className="w-2.5 h-2.5" aria-hidden="true" /> Active
            </span>
          )}
        </div>
        <p className="mb-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>
          A pair of values that doesn't match a named profile above. Set both together —
          a day window alone is exactly what let the old 183-day / 50,000-span default
          stop recording after two weeks.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block mb-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
              Max spans
            </label>
            <input
              type="number"
              min={100}
              max={10_000_000}
              value={customSpans}
              onChange={e => setCustomSpans(Number(e.target.value))}
              className="w-full px-3 py-1.5 rounded-lg text-xs focus:outline-none"
              style={{ background: 'var(--cs-bg-canvas)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' }}
            />
          </div>
          <div>
            <label className="block mb-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
              Retention days
            </label>
            <input
              type="number"
              min={1}
              max={3650}
              value={customDays}
              onChange={e => setCustomDays(Number(e.target.value))}
              className="w-full px-3 py-1.5 rounded-lg text-xs focus:outline-none"
              style={{ background: 'var(--cs-bg-canvas)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' }}
            />
          </div>
        </div>
        {customError && <p className="text-[11px] mt-2" style={{ color: 'var(--cs-danger)' }}>{customError}</p>}
        <div className="flex justify-end mt-2">
          <SaveButton onClick={saveCustom} label="Save custom pair" />
        </div>
      </div>

      {/* What the currently-active configuration really delivers — the same
          consequence reporting as the cards above, but for what is live now. */}
      <div className="rounded-lg p-3 space-y-1.5" style={{ background: 'var(--cs-bg-canvas)', border: '1px solid var(--cs-rule)' }}>
        <p style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
          Currently delivers
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1.5 cs-mono" style={{ fontSize: 'var(--cs-text-xs)' }}>
          <span style={{ color: 'var(--cs-text-faint)' }}>Limited by</span>
          <span style={{ color: eff.limitingFactor === 'capacity' ? 'var(--cs-warn)' : 'var(--cs-text-body)' }}>
            {eff.limitingFactor === 'capacity' ? 'span ceiling' : eff.limitingFactor === 'age' ? 'age window' : eff.limitingFactor === 'none' ? 'nothing (unbounded)' : 'unknown yet'}
          </span>
          <span style={{ color: 'var(--cs-text-faint)' }}>Effective window</span>
          <span style={{ color: 'var(--cs-text-body)' }}>{formatDays(eff.effectiveWindowDays)}</span>
          <span style={{ color: 'var(--cs-text-faint)' }}>Measured rate</span>
          <span style={{ color: 'var(--cs-text-body)' }}>{eff.spansPerDay != null ? `${eff.spansPerDay.toLocaleString()}/day` : 'not enough history'}</span>
          <span style={{ color: 'var(--cs-text-faint)' }}>Ingest stops at</span>
          <span style={{ color: 'var(--cs-text-body)' }}>
            {eff.ingestStopsAtSpans != null
              ? `${eff.ingestStopsAtSpans.toLocaleString()} spans${eff.ingestStopsAfterDays != null ? ` (~${eff.ingestStopsAfterDays}d)` : ''}`
              : 'never (no ceiling)'}
          </span>
          <span style={{ color: 'var(--cs-text-faint)' }}>Est. disk for the window</span>
          <span style={{ color: 'var(--cs-text-body)' }}>{formatBytes(eff.estimatedBytes)}</span>
          <span style={{ color: 'var(--cs-text-faint)' }}>Stored now</span>
          <span style={{ color: 'var(--cs-text-body)' }}>{stats.spansTotal.toLocaleString()} spans / {stats.dbSizeHuman}</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 2. Rate limiting section
// ---------------------------------------------------------------------------

export function RateLimitSection() {
  const [info,    setInfo]    = useState<RateLimitInfo | null>(null);
  const [error,   setError]   = useState('');

  const load = useCallback(() => {
    fetch('/api/health')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: { rateLimiting?: RateLimitInfo }) => {
        if (d.rateLimiting) { setInfo(d.rateLimiting); setError(''); }
      })
      .catch((e: Error) => setError(e.message || 'Request failed'));
  }, []);

  useEffect(() => { load(); }, [load]);

  if (!info && !error) {
    return (
      <div className="space-y-2 mt-3" aria-busy="true" aria-label="Loading rate limits">
        {[0, 1, 2].map(i => (
          <div key={i} className="h-4 w-full rounded animate-pulse" style={{ background: 'var(--cs-bg-raised)' }} />
        ))}
      </div>
    );
  }

  if (error && !info) {
    return (
      <div className="mt-3 space-y-2">
        <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>Could not load rate limits ({error}).</p>
        <button
          type="button"
          onClick={load}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors hover:opacity-90"
          style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)' }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Try again
        </button>
      </div>
    );
  }

  const rows: { label: string; value: number; unit: string; envKey: string }[] = [
    { label: 'Requests / second',   value: info!.rps,           unit: 'rps',   envKey: 'CLAUDESEC_RATE_LIMIT_RPS'   },
    { label: 'Burst limit',         value: info!.burst,         unit: 'reqs',  envKey: 'CLAUDESEC_RATE_LIMIT_BURST' },
    { label: 'Max spans per batch', value: info!.maxSpansBatch, unit: 'spans', envKey: 'CLAUDESEC_MAX_SPANS_BATCH'  },
  ];

  return (
    <div className="space-y-3 mt-3">
      <div className="space-y-2">
        {rows.map(row => (
          <div key={row.envKey} className="flex items-center justify-between text-xs">
            <span style={{ color: 'var(--cs-text-muted)' }}>{row.label}</span>
            <span className="cs-mono" style={{ color: 'var(--cs-text-body)' }}>
              {row.value} <span style={{ color: 'var(--cs-text-faint)' }}>{row.unit}</span>
            </span>
          </div>
        ))}
      </div>
      <p className="italic mt-2" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
        Change via environment variable — <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_RATE_LIMIT_RPS</code>,{' '}
        <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_RATE_LIMIT_BURST</code>,{' '}
        <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_MAX_SPANS_BATCH</code> — then restart the server.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 3. Webhook section
// ---------------------------------------------------------------------------

export function WebhookSection() {
  const [url,         setUrl]         = useState('');
  const [urlPreview,  setUrlPreview]  = useState<string | null>(null);
  const [threshold,   setThreshold]   = useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [configured,  setConfigured]  = useState(false);
  const [envOverride, setEnvOverride] = useState(false);
  const [testMsg,     setTestMsg]     = useState('');
  const [testOk,      setTestOk]      = useState<boolean | null>(null);
  const [error,       setError]       = useState('');

  const load = useCallback(() => {
    fetch('/api/webhook')
      .then(r => r.json())
      .then((d: Partial<WebhookConfig>) => {
        if (d.configured) { setConfigured(true); setUrlPreview(d.urlPreview ?? null); }
        if (d.threshold) setThreshold(d.threshold);
        setEnvOverride(!!d.envOverride);
      })
      .catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = useCallback(async () => {
    setError('');
    const res = await fetch('/api/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim(), threshold }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({})) as { error?: string };
      setError(d.error ?? 'Failed to save webhook');
      throw new Error(d.error ?? 'Failed to save webhook');
    }
    setConfigured(!!url.trim());
    setUrl('');
    load();
  }, [url, threshold, load]);

  const handleDelete = async () => {
    setError('');
    const res = await fetch('/api/webhook', { method: 'DELETE' });
    if (res.ok) {
      setUrl('');
      setUrlPreview(null);
      setConfigured(false);
      setTestMsg('');
      setTestOk(null);
    } else {
      setError('Failed to delete webhook');
    }
  };

  const handleTest = async () => {
    setTestMsg('');
    setTestOk(null);
    try {
      const res = await fetch('/api/webhook/test', { method: 'POST' });
      if (res.ok) {
        setTestMsg('Test payload sent successfully.');
        setTestOk(true);
      } else {
        const d = await res.json().catch(() => ({})) as { error?: string };
        setTestMsg(d.error ?? 'Test failed.');
        setTestOk(false);
      }
    } catch {
      setTestMsg('Network error during test.');
      setTestOk(false);
    }
  };

  return (
    <div className="space-y-4 mt-3">
      {envOverride && (
        <EnvOverrideBanner
          text={<>The webhook is currently pinned by the <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_WEBHOOK_URL</code> environment variable — edits here are disabled until you unset it and restart.</>}
        />
      )}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="sm:col-span-2">
          <label className="block mb-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
            Webhook URL
          </label>
          <input
            type="url"
            value={url}
            onChange={e => { setUrl(e.target.value); setError(''); }}
            disabled={envOverride}
            placeholder={configured ? 'Enter a new URL to replace' : 'https://hooks.example.com/...'}
            className="w-full px-3 py-1.5 rounded-lg text-xs focus:outline-none disabled:opacity-50"
            style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' }}
          />
          {configured && (
            <p className="mt-1 flex items-center gap-1.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>
              <Check className="w-3 h-3" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" />
              Configured: <span className="cs-mono" style={{ color: 'var(--cs-text-faint)' }}>{urlPreview ?? '••••'}</span>
            </p>
          )}
        </div>
        <div>
          <label className="block mb-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)' }}>
            Min threshold
          </label>
          <select
            value={threshold}
            onChange={e => setThreshold(e.target.value as 'low' | 'medium' | 'high' | 'critical')}
            disabled={envOverride}
            className="w-full px-3 py-1.5 rounded-lg text-xs focus:outline-none disabled:opacity-50"
            style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' }}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      {error && <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>{error}</p>}
      {testMsg && (
        <p className="text-[11px]" style={{ color: testOk ? 'var(--cs-accent)' : 'var(--cs-danger)' }}>
          {testMsg}
        </p>
      )}

      <div className="flex items-center gap-2 justify-end">
        {configured && (
          <>
            <button
              type="button"
              onClick={handleTest}
              disabled={envOverride}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors disabled:opacity-50 hover:opacity-90"
              style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule-strong)', color: 'var(--cs-text-body)' }}
            >
              Test
            </button>
            <button
              type="button"
              onClick={handleDelete}
              disabled={envOverride}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors disabled:opacity-50 hover:opacity-90"
              style={{ background: 'rgba(var(--cs-sev-critical-rgb),0.10)', border: '1px solid rgba(var(--cs-sev-critical-rgb),0.30)', color: 'var(--cs-danger)' }}
            >
              Delete
            </button>
          </>
        )}
        <SaveButton onClick={save} disabled={!url.trim() || envOverride} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 4. Display preferences section
// ---------------------------------------------------------------------------

export function DisplaySection() {
  const [hideNone, setHideNone] = useState(() => localStorage.getItem('claudesec.hideNone') === 'true');

  const toggle = (key: string, value: boolean, setter: (v: boolean) => void) => {
    setter(value);
    localStorage.setItem(key, String(value));
    window.dispatchEvent(new Event('claudesec:hideNoneChange'));
  };

  return (
    <div className="space-y-3 mt-3">
      <ToggleRow
        label="Hide safe spans"
        description="Hide spans with no threat (severity: none) from the spans list."
        checked={hideNone}
        onChange={v => toggle('claudesec.hideNone', v, setHideNone)}
      />
      <p className="italic" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
        Saved locally in your browser — takes effect immediately, no restart needed.
      </p>
    </div>
  );
}

interface ToggleRowProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleRow({ label, description, checked, onChange }: ToggleRowProps) {
  return (
    <div className="flex items-start gap-3">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className="relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--cs-accent)]"
        style={checked
          ? { background: 'var(--cs-accent)', borderColor: 'var(--cs-accent)' }
          : { background: 'var(--cs-bg-raised)', borderColor: 'var(--cs-rule-strong)' }}
      >
        <span
          className={`inline-block h-3.5 w-3.5 rounded-full shadow transform transition-transform duration-200 translate-y-[-1px] ${
            checked ? 'translate-x-[14px]' : 'translate-x-0'
          }`}
          style={{ background: 'var(--cs-text-invert)' }}
        />
      </button>
      <div>
        <p className="font-medium leading-none mb-0.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>{label}</p>
        <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{description}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 5. Config / enablement status section
// ---------------------------------------------------------------------------

type StatusState = 'active' | 'default' | 'off' | 'caution';

interface SettingStatus {
  key: string;
  category: string;
  description: string;
  isSet: boolean;
  effectiveValue: string;
  enabled: boolean;
  state: StatusState;
  detail?: string;
}

interface ConfigStatusResponse {
  settings: SettingStatus[];
  summary: { active: number; caution: number; off: number; default: number };
  categoryOrder: string[];
  generatedAt: string;
}

// The Enforce tab's source of truth for the running mode. We read the SAME
// endpoint and fields it uses (`effectiveMode` + `modeSource`) so the
// CLAUDESEC_MODE status row can't disagree with it. `effectiveMode` is what the
// hook actually runs after the file → env → default precedence; `modeSource` is
// the layer that won. (See EnforceTab.tsx / GET /api/enforce/config.)
type EffectiveMode = 'monitor' | 'enforce';
type EnforceModeSource = 'config-file' | 'env' | 'default';

interface EnforceModeStatus {
  effectiveMode: EffectiveMode;
  modeSource: EnforceModeSource;
  envMode: string | null;
}

/** Icon + text + color per state — a11y: never color alone. */
function StatusBadge({ state }: { state: StatusState }) {
  const map: Record<StatusState, { label: string; icon: React.ReactNode; bg: string; fg: string; border: string }> = {
    active:  { label: 'ACTIVE',  icon: <CheckCircle2 className="w-3 h-3" aria-hidden="true" />,  bg: 'var(--cs-accent-soft)', fg: 'var(--cs-accent)', border: 'var(--cs-accent-dim)' },
    caution: { label: 'CAUTION', icon: <AlertTriangle className="w-3 h-3" aria-hidden="true" />, bg: 'rgba(var(--cs-sev-medium-rgb),0.12)', fg: 'var(--cs-warn)', border: 'rgba(var(--cs-sev-medium-rgb),0.30)' },
    off:     { label: 'OFF',     icon: <CircleSlash className="w-3 h-3" aria-hidden="true" />,   bg: 'var(--cs-bg-overlay)', fg: 'var(--cs-text-muted)', border: 'var(--cs-rule-strong)' },
    default: { label: 'DEFAULT', icon: <CircleSlash className="w-3 h-3" aria-hidden="true" />,   bg: 'var(--cs-bg-overlay)', fg: 'var(--cs-text-muted)', border: 'var(--cs-rule-strong)' },
  };
  const s = map[state];
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wide shrink-0"
      style={{ background: s.bg, color: s.fg, border: `1px solid ${s.border}` }}
    >
      {s.icon}{s.label}
    </span>
  );
}

/**
 * The CLAUDESEC_MODE status row, rendered from the Enforce tab's source of truth.
 * Unlike the generic env-driven rows, the running enforcement mode is governed by
 * the Enforce-tab toggle (which writes enforce-config.json); CLAUDESEC_MODE is only
 * a fallback used when no toggle/config value exists. We surface the EFFECTIVE mode
 * (what the hook actually runs) so this row can never claim "monitor / nothing is
 * blocked" while enforcement is live.
 */
function EnforceModeRow({ status }: { status: EnforceModeStatus }) {
  const { effectiveMode, modeSource, envMode } = status;
  const isEnforce = effectiveMode === 'enforce';
  const sourceLabel =
    modeSource === 'config-file' ? 'the Enforce tab toggle (enforce-config.json)'
    : modeSource === 'env'       ? 'the CLAUDESEC_MODE env var'
    :                              'the built-in monitor default';

  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1.5 sm:gap-3 px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule)' }}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <code className="cs-mono break-all" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>CLAUDESEC_MODE</code>
          <StatusBadge state={isEnforce ? 'active' : 'default'} />
        </div>
        <p className="mt-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
          Effective enforcement mode is{' '}
          <span className="cs-mono font-semibold" style={{ color: isEnforce ? 'var(--cs-warn)' : 'var(--cs-text-body)' }}>{effectiveMode}</span>
          {' '}— {isEnforce ? 'high-severity tool calls are blocked before they run.' : 'would-block events are logged only; nothing is blocked.'}
        </p>
        <p className="mt-0.5 italic" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
          Resolved from {sourceLabel}.
          {modeSource !== 'env' && envMode != null && (
            <> The <code className="cs-mono not-italic" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_MODE={envMode}</code> env var is set but overridden.</>
          )}
        </p>
        {/* The blessed control is the Enforce tab toggle, not this env var. Point
            there explicitly and make CLAUDESEC_MODE's fallback role unambiguous. */}
        <p className="mt-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
          Change this from the{' '}
          <a
            href="#/protect/enforce"
            className="inline-flex items-center gap-0.5 font-medium hover:underline"
            style={{ color: 'var(--cs-accent)' }}
          >
            Enforce tab <ArrowRight className="w-2.5 h-2.5" aria-hidden="true" />
          </a>
          . The <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>CLAUDESEC_MODE</code> env var is only a fallback used when no toggle value is set.
        </p>
      </div>
      <div className="shrink-0 sm:text-right sm:max-w-[42%] sm:pl-2">
        <p className="mb-0.5" style={{ fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', color: 'var(--cs-text-faint)' }}>Effective</p>
        <code className="cs-mono break-all" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>{effectiveMode}</code>
      </div>
    </div>
  );
}

function ConfigStatusSection() {
  const [data,  setData]  = useState<ConfigStatusResponse | null>(null);
  const [error, setError] = useState('');
  // The running enforcement mode, pulled from the SAME endpoint the Enforce tab
  // uses so this section can never disagree with the blessed control. Null until
  // the first fetch resolves (or if it fails — then we fall back to the raw
  // env-derived row rather than guessing).
  const [enforce, setEnforce] = useState<EnforceModeStatus | null>(null);

  const load = useCallback(() => {
    fetch('/api/config/status')
      .then(r => r.json())
      .then((d: ConfigStatusResponse) => { setData(d); setError(''); })
      .catch(() => setError('Failed to load config status'));
    // Effective mode is governed by the Enforce-tab toggle (enforce-config.json),
    // not primarily by CLAUDESEC_MODE — read it from the enforce config endpoint.
    fetch('/api/enforce/config')
      .then(r => r.json())
      .then((c: { effectiveMode?: EffectiveMode; modeSource?: EnforceModeSource; envMode?: string | null }) => {
        if (c && c.effectiveMode && c.modeSource) {
          setEnforce({ effectiveMode: c.effectiveMode, modeSource: c.modeSource, envMode: c.envMode ?? null });
        }
      })
      .catch(() => { /* fall back to the raw env-derived row */ });
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000); // live-refresh derived signals
    return () => clearInterval(id);
  }, [load]);

  if (error && !data) return <p className="text-[11px] mt-3" style={{ color: 'var(--cs-danger)' }}>{error}</p>;
  if (!data) {
    return (
      <div className="space-y-2 mt-3" aria-busy="true" aria-label="Loading runtime status">
        {[0, 1, 2, 3].map(i => (
          <div key={i} className="h-10 w-full rounded-lg animate-pulse" style={{ background: 'var(--cs-bg-raised)' }} />
        ))}
      </div>
    );
  }

  // Retention's three env keys (CLAUDESEC_RETENTION_PROFILE / _MAX_SPANS /
  // _RETENTION_DAYS) are editable from the dedicated Retention section further
  // down this same page, not read-only-only-via-env like everything else here
  // — showing them a second time, tagged read-only, is exactly the mislabeling
  // this rebuild set out to fix. Point there instead of duplicating the row.
  const cats = data.categoryOrder.filter(c => c !== 'Retention' && data.settings.some(s => s.category === c));

  return (
    <div className="space-y-4 mt-3">
      {/* Summary chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
          style={{ background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)', border: '1px solid var(--cs-accent-dim)' }}>
          <CheckCircle2 className="w-3 h-3" aria-hidden="true" /> {data.summary.active} active
        </span>
        {data.summary.caution > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
            style={{ background: 'rgba(var(--cs-sev-medium-rgb),0.12)', color: 'var(--cs-warn)', border: '1px solid rgba(var(--cs-sev-medium-rgb),0.30)' }}>
            <AlertTriangle className="w-3 h-3" aria-hidden="true" /> {data.summary.caution} need attention
          </span>
        )}
        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono"
          style={{ background: 'var(--cs-bg-overlay)', color: 'var(--cs-text-muted)', border: '1px solid var(--cs-rule-strong)' }}>
          <CircleSlash className="w-3 h-3" aria-hidden="true" /> {data.summary.off + data.summary.default} default/off
        </span>
        <span className="inline-flex items-center gap-1 ml-auto" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
          <Activity className="w-3 h-3" aria-hidden="true" /> live
        </span>
      </div>

      <p className="italic" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
        Retention is now its own editable section below — see <strong style={{ color: 'var(--cs-text-muted)' }}>Storage &amp; retention</strong>.
      </p>

      {cats.map(cat => (
        <div key={cat}>
          <p className="font-bold mb-2" style={{ fontSize: 'var(--cs-text-xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', color: 'var(--cs-text-faint)' }}>{cat}</p>
          <div className="space-y-2">
            {data.settings.filter(s => s.category === cat).map(s => {
              // CLAUDESEC_MODE is special: the running mode is controlled by the
              // Enforce-tab toggle (enforce-config.json), and the env var is only
              // a fallback. The /api/config/status row only knows the raw env
              // value, so it would mislead (e.g. "monitor / nothing is blocked")
              // while the hook is actually enforcing. Render it from the Enforce
              // tab's source of truth instead.
              if (s.key === 'CLAUDESEC_MODE' && enforce) {
                return <EnforceModeRow key={s.key} status={enforce} />;
              }
              return (
              <div
                key={s.key}
                className="flex flex-col sm:flex-row sm:items-start gap-1.5 sm:gap-3 px-3 py-2.5 rounded-lg"
                style={{ background: 'var(--cs-bg-raised)', border: '1px solid var(--cs-rule)' }}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="cs-mono break-all" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>{s.key}</code>
                    <StatusBadge state={s.state} />
                    <ReadOnlyTag />
                  </div>
                  <p className="mt-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{s.description}</p>
                  {s.detail && (
                    <p className="mt-0.5 italic" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>{s.detail}</p>
                  )}
                  {/* The setting key IS the env var name — tell the user exactly
                      how to change a read-only value, and that it needs a restart. */}
                  <p className="mt-1 cs-mono" style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)' }}>
                    Change with the <code className="cs-mono" style={{ color: 'var(--cs-info)' }}>{s.key}</code> environment variable, then restart the server.
                  </p>
                </div>
                <div className="shrink-0 sm:text-right sm:max-w-[42%] sm:pl-2">
                  <p className="mb-0.5" style={{ fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', color: 'var(--cs-text-faint)' }}>Effective</p>
                  <code className="cs-mono break-all" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>{s.effectiveValue}</code>
                </div>
              </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 6. Env Reference section
// ---------------------------------------------------------------------------

function EnvCopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="p-1 rounded transition-colors hover:bg-[var(--cs-bg-raised)]"
      title="Copy"
    >
      {copied ? <Check className="w-3 h-3" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" /> : <Copy className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />}
    </button>
  );
}

interface EnvVar {
  key: string;
  description: string;
  default: string;
  category: string;
  sensitive?: boolean;
  currentValue: string;
  isSet: boolean;
}

function EnvReferenceSection() {
  const [vars, setVars] = useState<EnvVar[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    fetch('/api/config/env-reference')
      .then(r => r.json())
      .then(d => setVars(d.envVars ?? []))
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, []);

  const categories = [...new Set(vars.map(v => v.category))];

  return (
    <div className="space-y-4 mt-3">
      {/* Quick setup command */}
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'var(--cs-bg-raised)' }}>
        <Terminal className="w-3.5 h-3.5" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" />
        <code className="cs-mono flex-1" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>node cli/init.mjs</code>
        <EnvCopyButton text="node cli/init.mjs" />
      </div>

      {!loaded && (
        <div className="space-y-2" aria-busy="true" aria-label="Loading environment reference">
          {[0, 1, 2].map(i => <div key={i} className="h-8 w-full rounded-lg animate-pulse" style={{ background: 'var(--cs-bg-raised)' }} />)}
        </div>
      )}

      {categories.map(cat => (
        <div key={cat}>
          <p className="font-bold mb-2" style={{ fontSize: 'var(--cs-text-xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', color: 'var(--cs-text-faint)' }}>{cat}</p>
          <div className="space-y-1">
            {vars.filter(v => v.category === cat).map(v => (
              <div key={v.key} className="flex items-start gap-2 px-3 py-2 rounded-lg" style={{ background: 'var(--cs-bg-raised)' }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="cs-mono" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>{v.key}</code>
                    {v.isSet && (
                      <span className="px-1 py-0.5 rounded font-mono" style={{ fontSize: '9px', background: 'var(--cs-accent-soft)', color: 'var(--cs-accent)', border: '1px solid var(--cs-accent-dim)' }}>SET</span>
                    )}
                  </div>
                  <p className="mt-0.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>{v.description}</p>
                  {v.default && (
                    <p className="mt-0.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>Default: <code className="cs-mono">{v.default}</code></p>
                  )}
                </div>
                <EnvCopyButton text={v.key} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Data management — clear synthetic demo data (always safe) and the gated full reset
// ---------------------------------------------------------------------------
function DataManagementSection(): React.ReactElement {
  const [demoSessions, setDemoSessions] = useState(0);
  const [resetEnabled, setResetEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [loadFailed, setLoadFailed] = useState(false);
  // Two-click confirm for the destructive full reset — no native confirm() dialog,
  // which ad blockers and some browsers suppress.
  const [confirmAll, setConfirmAll] = useState(false);
  // Hold the confirm-window timer so it's cleared on unmount (no state update
  // after the Settings tab is closed mid-confirm).
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (confirmTimer.current) clearTimeout(confirmTimer.current); }, []);

  const load = useCallback(() => {
    fetch('/api/health')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(d => { setDemoSessions(d.demoSessions ?? 0); setResetEnabled(!!d.resetEnabled); setLoadFailed(false); })
      .catch(() => setLoadFailed(true));
  }, []);
  useEffect(() => { load(); }, [load]);

  const clearDemo = async () => {
    setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/demo/clear', { method: 'POST' });
      const d = await r.json();
      setMsg(`Cleared ${d.clearedSpans ?? 0} demo spans across ${d.clearedSessions ?? 0} session(s).`);
      load();
    } catch { setMsg('Failed to clear demo data.'); }
    finally { setBusy(false); }
  };

  const clearAll = async () => {
    if (!confirmAll) {
      setConfirmAll(true);
      if (confirmTimer.current) clearTimeout(confirmTimer.current);
      confirmTimer.current = setTimeout(() => setConfirmAll(false), 4000);
      return;
    }
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    setConfirmAll(false); setBusy(true); setMsg('');
    try {
      const r = await fetch('/api/reset', { method: 'POST' });
      if (r.ok) { setMsg('All data cleared.'); load(); }
      else { const d = await r.json().catch(() => ({})); setMsg(d.hint ?? d.error ?? 'Reset failed.'); }
    } catch { setMsg('Reset failed.'); }
    finally { setBusy(false); }
  };

  if (loadFailed) {
    return (
      <div className="space-y-2">
        <p className="text-[11px]" style={{ color: 'var(--cs-danger)' }}>Could not load data management status.</p>
        <button
          type="button"
          onClick={load}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors hover:opacity-90"
          style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)' }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Try again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Demo data — ungated, only ever deletes demo-* rows */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="font-medium" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>Demo data</div>
          <div style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            {demoSessions > 0
              ? `${demoSessions} synthetic demo session(s) present. Safe to remove anytime — only demo rows are deleted.`
              : 'No demo data present.'}
          </div>
        </div>
        <button
          type="button"
          onClick={clearDemo}
          disabled={busy || demoSessions === 0}
          className="px-3 py-1.5 text-xs rounded-lg shrink-0 transition-colors hover:opacity-90"
          style={{
            border: '1px solid var(--cs-rule-strong)', background: 'var(--cs-bg-raised)',
            color: demoSessions === 0 ? 'var(--cs-text-faint)' : 'var(--cs-text-body)',
            opacity: busy || demoSessions === 0 ? 0.5 : 1,
          }}
        >
          Clear demo data
        </button>
      </div>

      {/* Full reset — gated behind CLAUDESEC_ALLOW_RESET; visible and explained either way */}
      <div className="flex items-center justify-between gap-3 flex-wrap pt-2" style={{ borderTop: '1px solid var(--cs-rule)' }}>
        <div className="min-w-0">
          <div className="font-medium" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-body)' }}>Clear all data</div>
          <div style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            {resetEnabled
              ? 'Permanently deletes every span, session, and alert. This cannot be undone.'
              : 'Disabled for safety. Start the server with CLAUDESEC_ALLOW_RESET=1 to enable this.'}
          </div>
        </div>
        <button
          type="button"
          onClick={clearAll}
          disabled={busy || !resetEnabled}
          className="px-3 py-1.5 text-xs rounded-lg shrink-0 transition-colors"
          style={{
            border: `1px solid ${confirmAll ? 'var(--cs-danger)' : 'var(--cs-rule-strong)'}`,
            background: confirmAll ? 'rgba(var(--cs-sev-critical-rgb),0.15)' : 'var(--cs-bg-raised)',
            color: !resetEnabled ? 'var(--cs-text-faint)' : confirmAll ? 'var(--cs-danger)' : 'var(--cs-text-body)',
            opacity: busy || !resetEnabled ? 0.5 : 1,
          }}
        >
          {confirmAll ? 'Click again to confirm' : 'Clear all data'}
        </button>
      </div>

      {msg && <p style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>{msg}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function SettingsTab(): React.ReactElement {
  return (
    <div className="flex-1 overflow-auto p-5 min-h-0" style={{ background: 'var(--cs-bg-canvas)' }}>
      <div className="max-w-2xl mx-auto space-y-3">

        {/* Header */}
        <div className="flex items-center gap-2 mb-2">
          <Settings className="w-5 h-5" style={{ color: 'var(--cs-accent)' }} aria-hidden="true" />
          <h2 style={{ fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-bold)', color: 'var(--cs-text-strong)' }}>Settings</h2>
        </div>

        <GroupHeader>Runtime status</GroupHeader>

        <Section icon={<ShieldCheck className="w-4 h-4" />} title="Configuration status">
          <div
            className="flex items-start gap-2 px-3 py-2 mb-3 rounded-lg text-[11px] leading-relaxed"
            style={{ background: 'rgba(var(--cs-info-rgb),0.08)', border: '1px solid rgba(var(--cs-info-rgb),0.25)', color: 'var(--cs-text-muted)' }}
          >
            <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--cs-info)' }} aria-hidden="true" />
            <span>
              Every row below is <span style={{ color: 'var(--cs-info)' }} className="font-medium">read-only</span> — set through
              an environment variable and read once at process start, shown here so you can confirm what's actually live.
              To change one, set its env var (named on each row) and <span style={{ color: 'var(--cs-info)' }} className="font-medium">restart the server</span>.
              Sections elsewhere on this page tagged
              <span style={{ color: 'var(--cs-accent)' }} className="font-medium"> Editable here</span> are the ones you can
              change from this dashboard, live, with no restart.
            </span>
          </div>
          <p className="mb-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            Live runtime state of each setting — whether the feature is actually
            <span style={{ color: 'var(--cs-text-body)' }}> active</span>, at its
            <span style={{ color: 'var(--cs-text-body)' }}> default</span>, or needs
            <span style={{ color: 'var(--cs-warn)' }}> attention</span>. Secrets are masked.
            Refreshes automatically.
          </p>
          <ConfigStatusSection />
        </Section>

        <Section icon={<Terminal className="w-4 h-4" />} title="Environment variable reference" defaultOpen={false} badge={<ReadOnlyTag />}>
          <p className="mb-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            All configuration options available via environment variables.
            Set these before starting the server. Sensitive values are masked.
          </p>
          <EnvReferenceSection />
        </Section>

        <GroupHeader>Storage &amp; retention</GroupHeader>

        <Section icon={<Database className="w-4 h-4" />} title="Retention" badge={<EditableTag />}>
          <RetentionSection />
        </Section>

        <Section icon={<HardDrive className="w-4 h-4" />} title="Data management" badge={<EditableTag />}>
          <DataManagementSection />
        </Section>

        <GroupHeader>Alerting &amp; integrations</GroupHeader>

        <Section icon={<Globe className="w-4 h-4" />} title="Webhook" badge={<EditableTag />}>
          <WebhookSection />
        </Section>

        <Section icon={<BellRing className="w-4 h-4" />} title="Threshold rules" defaultOpen={false} badge={<EditableTag />}>
          <p className="mb-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            Trigger alerts when a session metric exceeds a threshold within a time window.
            Fired alerts appear in the Alerts tab.
          </p>
          <ThresholdRulesSection />
        </Section>

        <Section icon={<History className="w-4 h-4" />} title="Webhook delivery log" defaultOpen={false}>
          <p className="mb-1 leading-relaxed" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-faint)' }}>
            Every webhook attempt is logged here. Failed deliveries auto-retry up to 3×
            with exponential backoff. Manually retry or clear history below.
          </p>
          <WebhookDeliverySection />
        </Section>

        <GroupHeader>Network &amp; display</GroupHeader>

        <Section icon={<Gauge className="w-4 h-4" />} title="Rate limiting" badge={<ReadOnlyTag />}>
          <RateLimitSection />
        </Section>

        <Section icon={<SlidersHorizontal className="w-4 h-4" />} title="Display" badge={<EditableTag />}>
          <DisplaySection />
        </Section>

      </div>
    </div>
  );
}
