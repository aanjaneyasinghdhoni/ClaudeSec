/**
 * GovernTab — the Govern › Policies screen.
 *
 * This tab adds no detection and no enforcement of its own. Every fact it
 * shows already exists in `alerts`, `enforce_log`, `operator_audit_log` and
 * the hash chains — this is only a reading of it, grouped into the twelve
 * policy statements `server/governance.ts` defines and rendered honestly
 * enough that a security lead can open it without learning what a
 * PreToolUse hook is. `docs/govern/policies.mdx` states what each policy
 * claims and where it stops.
 *
 * Three rules this file cannot violate, because a reviewer will check them:
 *   1. No score, no percentage. Twelve rows, three words each.
 *   2. `held` reads grey. Saturated colour means risk in this product, never
 *      "safe" — see src/governance/policyVisual.ts for the mapping.
 *   3. The two configuration policies (no rule behind them) stay visibly
 *      separate from the ten rule-backed ones — a config flag is not a
 *      detection, and folding them into one list would blur that.
 *
 * Built on the same primitives as the reference implementation
 * (src/AlertsTab.tsx): DataTable for the dense, keyboard-navigable list, the
 * shared toolbar shapes, and the empty/loading/error triad.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Scale, Database, Radio, Link2, Link2Off, Webhook, WebhookOff, Users,
  Download, CircleDashed, CircleHelp, ShieldAlert, ChevronDown, ChevronRight,
  TriangleAlert, X, ExternalLink, FileWarning, Sparkles,
} from 'lucide-react';
import { socket } from './socket';
import type { Severity } from './shared/types';
import type { Tab } from './dashboardTypes';
import { HARNESS_NAMES } from './dashboardTypes';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  EmptyState, ErrorState, TableSkeleton,
  Toolbar, ToolButton, ToolbarTitle,
  severityMark, severityText,
} from './components/data';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from './components/ui/dropdown-menu';
import {
  policyStatusVisual, describeDataHeld, summarizeChain, isPeriodDays,
  HELD_HONESTY_LINE, PERIOD_OPTIONS,
  type PolicyStatus, type PeriodDays,
} from './governance/policyVisual';

// ── API shape ─────────────────────────────────────────────────────────────
// GET /api/governance/policies?days=N. Mirrors server/governance.ts exactly —
// verified against the live response rather than guessed.

interface ChainCheckDetail {
  ok: boolean;
  status: string;
  detail: string;
}

interface Coverage {
  dataHeld: { configuredDays: number; effectiveDays: number; cappedByMaxSpans: boolean; warning: string | null };
  mode: string;
  effectiveMode: string;
  modeSource: string;
  hook: { installed: string; scopes: string[] };
  chain: { ok: boolean; audit: ChainCheckDetail; enforce: ChainCheckDetail; spans: ChainCheckDetail };
  agentsSeen: { harness: string; sessions: number; spans: number }[];
}

interface PolicyEvidence {
  alerts: number;
  blocked: number;
  disabledCount: number;
  suppressedCount: number;
}

interface Policy {
  id: string;
  sentence: string;
  status: PolicyStatus;
  reasons: string[];
  severityFloor: Severity | null;
  enforcement: 'floor' | 'enforce' | 'detect' | 'config';
  enforcementNote: string;
  ruleLabels: string[];
  ruleLabelCount: number;
  evidence: PolicyEvidence;
  evidenceDescription: string;
  doesNotProve: string[];
  frameworks: { nist: string[]; iso: string[] };
  configPolicy: boolean;
}

interface GovernancePayload {
  generatedAt: string;
  period: { days: number; from: string; to: string };
  coverage: Coverage;
  policies: Policy[];
}

const ENFORCEMENT_LABEL: Record<Policy['enforcement'], string> = {
  floor:   'always-on floor',
  enforce: 'enforce mode only',
  detect:  'detect only',
  config:  'configuration',
};

const STATUS_ICON: Record<PolicyStatus, typeof CircleDashed> = {
  held: CircleDashed,
  violated: ShieldAlert,
  'not-provable': CircleHelp,
};

// ── Status badge ─────────────────────────────────────────────────────────

function PolicyStatusBadge({ status, severityFloor }: { status: PolicyStatus; severityFloor: Severity | null }) {
  const { word, severity } = policyStatusVisual(status, severityFloor);
  const Icon = STATUS_ICON[status];
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0">
      <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: severityMark(severity) }} aria-hidden="true" />
      <span
        className="uppercase truncate"
        style={{
          color: severityText(severity),
          fontSize: 'var(--cs-text-2xs)',
          fontWeight: 'var(--cs-weight-bold)',
          letterSpacing: 'var(--cs-tracking-wide)',
        }}
      >
        {word}
      </span>
    </span>
  );
}

// ── Coverage strip ───────────────────────────────────────────────────────
// The block the spec calls non-negotiable: data held / mode / hook / chain /
// agents seen, above the policy rows, on screen at first paint — the "am I
// compliant" question does not need a click to start answering.

function CoverageItem({
  icon: Icon, label, value, tone, title, warn,
}: {
  icon: typeof Database;
  label: string;
  value: React.ReactNode;
  tone?: 'warn' | 'danger';
  title?: string;
  warn?: boolean;
}) {
  const color =
    tone === 'danger' ? 'var(--cs-sev-critical-fg)' :
    tone === 'warn'   ? 'var(--cs-sev-medium-fg)'   :
    'var(--cs-text-body)';
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0" title={title}>
      <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
      <span
        className="uppercase shrink-0"
        style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', letterSpacing: 'var(--cs-tracking-wide)' }}
      >
        {label}
      </span>
      {warn && <TriangleAlert className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-sev-medium-fg)' }} aria-hidden="true" />}
      <span className="cs-mono truncate" style={{ fontSize: 'var(--cs-text-xs)', color }}>{value}</span>
    </span>
  );
}

function CoverageStrip({ coverage }: { coverage: Coverage }) {
  const heldText = describeDataHeld(coverage.dataHeld);
  const chain = summarizeChain(coverage.chain);
  const hookOk = coverage.hook.installed === 'yes';
  const modeTitle = coverage.effectiveMode !== coverage.mode
    ? `Configured ${coverage.mode}, effective mode is ${coverage.effectiveMode}. Source: ${coverage.modeSource}.`
    : `Source: ${coverage.modeSource}.`;
  const agentsLine = coverage.agentsSeen.length > 0
    ? coverage.agentsSeen
        .map(a => `${HARNESS_NAMES[a.harness] ?? a.harness} (${a.sessions.toLocaleString()} session${a.sessions === 1 ? '' : 's'})`)
        .join(' · ')
    : 'No agent activity recorded in this window.';

  return (
    <div
      className="shrink-0 px-3 py-2.5 flex flex-col gap-1.5"
      style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}
    >
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <CoverageItem
          icon={Database}
          label="Data held"
          value={heldText}
          tone={coverage.dataHeld.cappedByMaxSpans || coverage.dataHeld.warning ? 'warn' : undefined}
          warn={coverage.dataHeld.cappedByMaxSpans}
          title="The configured retention window vs. the timestamp of the oldest span still on disk. A configured window is not a proven one — this is the number that matters."
        />
        <CoverageItem icon={Radio} label="Mode" value={coverage.mode} title={modeTitle} />
        <CoverageItem
          icon={hookOk ? Webhook : WebhookOff}
          label="Hook"
          value={hookOk ? `Registered (${coverage.hook.scopes.join(', ') || 'unknown scope'})` : 'Not installed'}
          tone={hookOk ? undefined : 'danger'}
          title={hookOk
            ? 'The PreToolUse hook is installed, so floor-enforcement policies can actually block, not just detect.'
            : 'The hook is not installed. Floor-enforcement policies below still detect, but nothing on this machine can block yet.'}
        />
        <CoverageItem
          icon={chain.ok ? Link2 : Link2Off}
          label="Chain"
          value={chain.label}
          tone={chain.ok ? undefined : 'danger'}
          title={[coverage.chain.audit.detail, coverage.chain.enforce.detail, coverage.chain.spans.detail].join(' ')}
        />
      </div>
      <div className="flex items-start gap-1.5" style={{ fontSize: 'var(--cs-text-xs)', color: 'var(--cs-text-muted)' }}>
        <Users className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
        <span>{agentsLine}</span>
      </div>
      {/* The line the spec requires on screen, not buried in a doc. Every
          qualifier can independently be false while a row still reads
          "Held" — this is why "not provable" exists as its own outcome. */}
      <p style={{ fontSize: 'var(--cs-text-2xs)', color: 'var(--cs-text-faint)', lineHeight: 'var(--cs-leading-normal)', maxWidth: '72ch' }}>
        {HELD_HONESTY_LINE}
      </p>
    </div>
  );
}

// ── Policy table ─────────────────────────────────────────────────────────

function buildColumns(): DataColumn<Policy>[] {
  return [
    {
      id: 'status', header: 'Status', width: '148px',
      cell: p => <PolicyStatusBadge status={p.status} severityFloor={p.severityFloor} />,
    },
    {
      id: 'policy', header: 'Policy', width: 'minmax(0,2fr)',
      // The sentence is written for a human, so it is sans and full strength —
      // the one thing in the row set at full text weight, per DESIGN.md §3.
      cell: p => (
        <span title={p.sentence}>
          <span className="cs-mono" style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', marginRight: 6 }}>
            {p.id}
          </span>
          <span style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}>{p.sentence}</span>
        </span>
      ),
    },
    {
      id: 'enforcement', header: 'Enforcement', width: '108px', hideBelow: 'xl', mono: true,
      cell: p => <span style={{ color: 'var(--cs-text-faint)' }}>{p.enforcement}</span>,
    },
    {
      id: 'rules', header: 'Rules', width: '56px', align: 'end', hideBelow: 'xl', mono: true,
      cell: p => <span style={{ color: 'var(--cs-text-faint)' }}>{p.configPolicy ? '—' : p.ruleLabelCount}</span>,
    },
    {
      id: 'frameworks', header: 'Frameworks', width: '146px', hideBelow: '2xl', mono: true,
      cell: p => (
        <span style={{ color: 'var(--cs-text-faint)' }}>
          {p.frameworks.nist.length} NIST · {p.frameworks.iso.length} ISO
        </span>
      ),
    },
    {
      id: 'open', header: '', width: '20px', align: 'end',
      cell: () => <ChevronRight className="w-3.5 h-3.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />,
    },
  ];
}

/** The subtext line under each row — the evidence counts and, when they
 *  exist, the reasons a status landed where it did. Always rendered (not
 *  click-to-expand): with only twelve rows total, the screen can afford to
 *  spend the vertical space on the number that actually earns the word
 *  above it. */
function renderPolicyDetail(p: Policy) {
  const bits = [
    `${p.evidence.alerts} alert${p.evidence.alerts === 1 ? '' : 's'}`,
    `${p.evidence.blocked} blocked`,
    ENFORCEMENT_LABEL[p.enforcement],
  ];
  if (p.evidence.disabledCount > 0) bits.push(`${p.evidence.disabledCount} rule(s) disabled`);
  if (p.evidence.suppressedCount > 0) bits.push(`${p.evidence.suppressedCount} suppressed`);
  return (
    <div className="py-1.5 flex flex-wrap items-baseline gap-x-1.5" style={{ fontSize: 'var(--cs-text-xs)' }}>
      <span className="cs-mono" style={{ color: 'var(--cs-text-faint)' }}>{bits.join(' · ')}</span>
      {p.reasons.length > 0 && (
        <span style={{ color: 'var(--cs-sev-medium-fg)' }}>— {p.reasons.join('; ')}</span>
      )}
    </div>
  );
}

// ── Drawer ────────────────────────────────────────────────────────────────

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2.5 rounded-lg" style={{ background: 'var(--cs-bg-elevated)' }}>
      <p
        style={{
          color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)',
          textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', marginBottom: 6,
        }}
      >
        {label}
      </p>
      {children}
    </div>
  );
}

function PolicyDrawer({
  policy, onClose, onNavigateTab,
}: {
  policy: Policy | null;
  onClose: () => void;
  onNavigateTab?: (tab: Tab, extraParams?: Record<string, string[]>) => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!policy) return;
    closeRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [policy, onClose]);

  if (!policy) return null;

  const { word, severity } = policyStatusVisual(policy.status, policy.severityFloor);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        ref={panelRef}
        className="relative w-full max-w-md h-full overflow-y-auto"
        style={{ background: 'var(--cs-bg-overlay)', boxShadow: 'var(--cs-shadow-drawer)' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={`Policy detail — ${policy.sentence}`}
        tabIndex={-1}
      >
        <div
          className="flex items-start justify-between px-5 py-4 sticky top-0 z-10"
          style={{ background: 'var(--cs-bg-overlay)', borderBottom: '1px solid var(--cs-rule)' }}
        >
          <div className="min-w-0 pr-4">
            <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', textTransform: 'uppercase', letterSpacing: 'var(--cs-tracking-wide)', marginBottom: 4 }}>
              {policy.id} · Policy detail
            </p>
            <PolicyStatusBadge status={policy.status} severityFloor={policy.severityFloor} />
            <h2 style={{ color: 'var(--cs-text-strong)', fontSize: 'var(--cs-text-md)', fontWeight: 'var(--cs-weight-semibold)', marginTop: 6 }}>
              {policy.sentence}
            </h2>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="transition-colors flex-shrink-0 rounded p-1"
            style={{ color: 'var(--cs-text-muted)' }}
            aria-label="Close"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-2">
          <Section label="What this means">
            <p style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}>
              {policy.severityFloor
                ? <>Floor: <strong>{policy.severityFloor}</strong> · </>
                : null}
              Enforcement: {policy.enforcementNote}
            </p>
          </Section>

          <Section label={policy.configPolicy ? 'What backs it' : `What implements it — ${policy.ruleLabelCount} rule${policy.ruleLabelCount === 1 ? '' : 's'}`}>
            {policy.configPolicy ? (
              <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}>
                No rule behind this policy — it is a settings state, not a detection. {policy.evidenceDescription}
              </p>
            ) : (
              <>
                <ul className="space-y-1">
                  {policy.ruleLabels.map(label => (
                    <li key={label} className="cs-mono truncate" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }} title={label}>
                      {label}
                    </li>
                  ))}
                </ul>
                {onNavigateTab && (
                  <button
                    type="button"
                    onClick={() => { onClose(); onNavigateTab('rules'); }}
                    className="inline-flex items-center gap-1 mt-2"
                    style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
                  >
                    Open in Rules <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  </button>
                )}
              </>
            )}
          </Section>

          <Section label="What happened">
            <p className="cs-mono" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }}>
              {policy.evidence.alerts} alert{policy.evidence.alerts === 1 ? '' : 's'} · {policy.evidence.blocked} blocked
              {policy.evidence.disabledCount > 0 && <> · {policy.evidence.disabledCount} rule(s) disabled</>}
              {policy.evidence.suppressedCount > 0 && <> · {policy.evidence.suppressedCount} suppressed</>}
            </p>
            {policy.reasons.length > 0 && (
              <p style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-xs)', marginTop: 4 }}>
                {policy.reasons.join('; ')}
              </p>
            )}
            <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)', marginTop: 6 }}>
              {policy.evidenceDescription}
            </p>
            {onNavigateTab && !policy.configPolicy && (
              <button
                type="button"
                // Scope the destination to exactly the rules this policy is
                // backed by — the whole point of the link is "show me THIS
                // policy's evidence", not every alert in the system.
                onClick={() => { onClose(); onNavigateTab('alerts', { rule: policy.ruleLabels }); }}
                className="inline-flex items-center gap-1 mt-2"
                style={{ color: 'var(--cs-accent)', fontSize: 'var(--cs-text-xs)' }}
              >
                View in Alert log <ExternalLink className="w-3 h-3" aria-hidden="true" />
              </button>
            )}
          </Section>

          {(policy.frameworks.nist.length > 0 || policy.frameworks.iso.length > 0) && (
            <Section label="What it maps to">
              {policy.frameworks.nist.length > 0 && (
                <p className="cs-mono" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)', marginBottom: 4 }}>
                  NIST AI RMF: {policy.frameworks.nist.join(', ')}
                </p>
              )}
              {policy.frameworks.iso.length > 0 && (
                <p className="cs-mono" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-xs)' }}>
                  ISO 42001 Annex A: {policy.frameworks.iso.join(', ')}
                </p>
              )}
              <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', marginTop: 6, lineHeight: 'var(--cs-leading-normal)' }}>
                Annex A is a control menu, not certification — clauses 4–10 are the actual certification
                requirement, and no software feature satisfies them.
              </p>
            </Section>
          )}

          <Section label="What this does not prove">
            <ul className="space-y-1.5">
              {policy.doesNotProve.map((line, i) => (
                <li key={i} className="flex gap-1.5" style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)', lineHeight: 'var(--cs-leading-normal)' }}>
                  <FileWarning className="w-3 h-3 shrink-0 mt-0.5" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </Section>
        </div>
      </div>
    </div>
  );
}

// ── Tab ───────────────────────────────────────────────────────────────────

export interface GovernTabProps {
  onNavigateTab?: (tab: Tab, extraParams?: Record<string, string[]>) => void;
}

export function GovernTab({ onNavigateTab }: GovernTabProps = {}) {
  const [days, setDays] = useState<PeriodDays>(90);
  const [data, setData] = useState<GovernancePayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Twelve rows, read and decided on rather than scanned — GOVERNANCE.md
  // calls for comfy density specifically, unlike the compact default every
  // other data surface in this app opens with.
  const [density, setDensity] = useRowDensity('governance', 'comfy');

  const fetchPolicies = useCallback((d: PeriodDays) => {
    fetch(`/api/governance/policies?days=${d}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((payload: GovernancePayload) => {
        setData(payload);
        setLoadError(null);
      })
      // A governance screen that silently shows stale "Held" rows during an
      // outage is the exact theatre this design exists to avoid — surface it.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchPolicies(days); }, [fetchPolicies, days]);

  // A new alert can flip a policy from Held to Violated — keep the board live.
  useEffect(() => {
    const handler = () => fetchPolicies(days);
    socket.on('alerts-update', handler);
    return () => { socket.off('alerts-update', handler); };
  }, [fetchPolicies, days]);

  const selectedPolicy = data?.policies.find(p => p.id === selectedId) ?? null;

  const ruleBacked = data?.policies.filter(p => !p.configPolicy) ?? [];
  const configPolicies = data?.policies.filter(p => p.configPolicy) ?? [];
  const heldCount = data?.policies.filter(p => p.status === 'held').length ?? 0;
  const violatedCount = data?.policies.filter(p => p.status === 'violated').length ?? 0;
  const notProvableCount = data?.policies.filter(p => p.status === 'not-provable').length ?? 0;

  const columns = buildColumns();
  const staleWarning = loadError && data != null;

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>
      <Toolbar>
        <ToolbarTitle
          icon={<Scale className="w-3.5 h-3.5" aria-hidden="true" />}
          count={data ? `${violatedCount} violated · ${notProvableCount} not provable · ${heldCount} held` : undefined}
          countTitle="Twelve policies. No score, no percentage — the words are the answer."
        >
          Policies
        </ToolbarTitle>
        {staleWarning && (
          <span
            role="status"
            title={`Last refresh failed (${loadError}). Showing the last successful read — this is only the view, not detection.`}
            style={{ color: 'var(--cs-sev-medium-fg)', fontSize: 'var(--cs-text-xs)' }}
          >
            Stale
          </span>
        )}
        <div className="flex items-center gap-1 ml-auto">
          <RowDensityToggle density={density} onChange={setDensity} className="mr-1" />
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <ToolButton title="Change the reporting window — the export uses the same one">
                Last {days} days <ChevronDown className="w-3 h-3" aria-hidden="true" />
              </ToolButton>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {PERIOD_OPTIONS.map(d => (
                <DropdownMenuItem key={d} onSelect={() => isPeriodDays(d) && setDays(d)}>
                  Last {d} days
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <ToolButton
            onClick={() => window.open(`/api/governance/evidence?days=${days}`, '_blank')}
            title="Download the evidence pack for this window — manifest, summary and the underlying rows, scrubbed"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden xl:inline">Export pack</span>
          </ToolButton>
        </div>
      </Toolbar>

      {loading && !data ? (
        <>
          <div className="shrink-0 px-3 py-2.5" style={{ background: 'var(--cs-bg-surface)', borderBottom: '1px solid var(--cs-rule)' }}>
            <TableSkeleton rows={2} columns={4} rowHeight="20px" />
          </div>
          <TableSkeleton rows={10} columns={5} />
        </>
      ) : loadError && !data ? (
        <ErrorState
          description={`The governance read did not respond (${loadError}). Detection is unaffected — this is only the view.`}
          onRetry={() => { setLoading(true); fetchPolicies(days); }}
        />
      ) : data ? (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <CoverageStrip coverage={data.coverage} />

          <div className="px-3 pt-3 pb-1 flex items-center gap-1.5">
            <Sparkles className="w-3 h-3" style={{ color: 'var(--cs-text-faint)' }} aria-hidden="true" />
            <span
              className="uppercase"
              style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)', letterSpacing: 'var(--cs-tracking-wide)' }}
            >
              Rule-backed policies · {ruleBacked.length}
            </span>
          </div>
          <DataTable
            rows={ruleBacked}
            columns={columns}
            rowKey={p => p.id}
            label="Rule-backed governance policies"
            density={density}
            minWidth={620}
            severity={p => policyStatusVisual(p.status, p.severityFloor).severity}
            onActivate={p => setSelectedId(p.id)}
            renderDetail={renderPolicyDetail}
            empty={
              <EmptyState
                icon={<Scale className="w-6 h-6" aria-hidden="true" />}
                title="No rule-backed policies returned"
                description="The policy set is defined in code and should always return ten rule-backed policies. An empty list here means the read failed silently upstream — worth reporting."
              />
            }
          />

          {/* Kept as a visibly separate list, not a footer row in the table
              above: a config flag is not a detection, and folding the two
              together would make it read like one. */}
          <div className="px-3 pt-4 pb-1">
            <div className="flex items-center gap-1.5">
              <span
                className="uppercase"
                style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', fontWeight: 'var(--cs-weight-bold)', letterSpacing: 'var(--cs-tracking-wide)' }}
              >
                Configuration policies · {configPolicies.length}
              </span>
            </div>
            <p style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-2xs)', marginTop: 2 }}>
              No rule behind these — backed by settings, not detection.
            </p>
          </div>
          <DataTable
            rows={configPolicies}
            columns={columns}
            rowKey={p => p.id}
            label="Configuration governance policies"
            density={density}
            minWidth={620}
            severity={p => policyStatusVisual(p.status, p.severityFloor).severity}
            onActivate={p => setSelectedId(p.id)}
            renderDetail={renderPolicyDetail}
            empty={
              <EmptyState
                icon={<Scale className="w-6 h-6" aria-hidden="true" />}
                title="No configuration policies returned"
                description="Retention (P11) and local-only storage (P12) should always be present. An empty list here means the read failed silently upstream."
              />
            }
          />
        </div>
      ) : null}

      <PolicyDrawer policy={selectedPolicy} onClose={() => setSelectedId(null)} onNavigateTab={onNavigateTab} />
    </div>
  );
}
