/**
 * RulesTab — the detection rule catalogue.
 *
 * Around 650 rules live here, which makes this the densest list in the app and
 * the one that decides whether the table shell actually works. Three things
 * follow from that count:
 *
 *   - The rules are the screen. The two forms this tab used to stack above the
 *     table (add a custom rule, protect a path) cost more vertical space than
 *     the table had rows, and both are things an operator does once a month.
 *     They now open as dialogs from the toolbar, so the list keeps the body.
 *   - Nothing is browsable at 650 rows without search and a severity filter, so
 *     both are permanent, and both are applied in the client — the whole
 *     catalogue is already in memory.
 *   - The snooze menu has to be a portalled overlay. Rows use
 *     `content-visibility`, which brings paint containment, so an absolutely
 *     positioned menu inside a row is clipped at the row's edge.
 *
 * The per-rule Block/Monitor control is deliberately monochrome. It is on every
 * row, and spending the severity ramp on a control that appears 650 times would
 * leave nothing for the spine, which is the signal the eye is meant to catch.
 * Block and Monitor are told apart by glyph, weight and ground instead.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  Shield, Trash2, Plus, FlaskConical, Clock, X, Lock, Ban, Eye, SearchX,
  FileWarning, ShieldOff,
} from 'lucide-react';
import { socket } from './socket';
import type { Severity } from './shared/types';
import {
  DataTable, type DataColumn,
  RowDensityToggle, useRowDensity,
  SeverityBadge, SEVERITY_ORDER, SEVERITY_META, normalizeSeverity,
  EmptyState, ErrorState,
  Toolbar, ToolButton, ToolbarTitle, ToolSearch,
} from './components/data';
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger,
} from './components/ui/dialog';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from './components/ui/dropdown-menu';
import { Popover, PopoverContent, PopoverTrigger } from './components/ui/popover';

type EnforceAction = 'alert' | 'block';

// Catastrophic-floor labels block ALWAYS and can never be demoted to monitor —
// mirrors the server guard (server/detection.ts CATASTROPHIC_DETECTION_LABELS).
// Kept in sync by the catastrophic-parity test gate.
const CATASTROPHIC_LABELS: ReadonlySet<string> = new Set([
  'Recursive root deletion',
  'Filesystem format command',
  'Raw disk write via dd',
  'Remote code execution via curl',
  'Remote code execution via wget',
  'Bash TCP reverse shell',
]);

/** A rule's natural action from its severity: the two top tiers block in enforce. */
function actionForSeverity(severity: string): EnforceAction {
  return severity === 'high' || severity === 'critical' ? 'block' : 'alert';
}

interface RuleRow {
  id: string;
  pattern: string;
  flags: string;
  severity: Severity;
  label: string;
  builtin?: boolean;
}

type RuleListRow = RuleRow & { type: 'built-in' | 'custom' };

interface ProtectedPath {
  id: string;
  path: string;
  label: string;
  createdAt?: string;
}

interface Suppression {
  id: number;
  ruleKey: string;
  suppressUntil: string;
  reason: string;
  createdAt: string;
}

interface RulesResponse {
  builtIn: RuleRow[];
  custom: RuleRow[];
}

type SeverityFilter = 'all' | Severity;
type TypeFilter = 'all' | 'built-in' | 'custom';

const SNOOZE_OPTIONS: { label: string; ms: number }[] = [
  { label: '1 hour',   ms: 1 * 60 * 60 * 1000 },
  { label: '4 hours',  ms: 4 * 60 * 60 * 1000 },
  { label: '24 hours', ms: 24 * 60 * 60 * 1000 },
  { label: '7 days',   ms: 7 * 24 * 60 * 60 * 1000 },
];

function formatCountdown(until: string): string {
  const ms = new Date(until).getTime() - Date.now();
  if (ms <= 0) return 'expired';
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h > 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0)  return `${h}h ${m}m`;
  return `${m}m`;
}

/** Shared shape for the two dialog forms, so the fields line up across both. */
function Field({
  label,
  hint,
  className = '',
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <label className={`flex flex-col gap-1 min-w-0 ${className}`}>
      <span style={{ color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-xs)' }}>
        {label}
        {hint && <span style={{ color: 'var(--cs-text-faint)' }}> — {hint}</span>}
      </span>
      {children}
    </label>
  );
}

// A form field is a well you type into, so it takes the sunken ground rather
// than the raised one. In the light themes "raised" is only a faint tint, and a
// field that reads as plain text on a white dialog is a field nobody fills in.
const fieldStyle: React.CSSProperties = {
  background: 'var(--cs-bg-sunken)',
  color: 'var(--cs-text-body)',
  fontSize: 'var(--cs-text-sm)',
  borderRadius: 'var(--cs-radius-sm)',
};

const fieldClass =
  'w-full px-2 py-1.5 outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--cs-accent)]';

export function RulesTab() {
  const [rules,        setRules]        = useState<RulesResponse>({ builtIn: [], custom: [] });
  const [suppressions, setSuppressions] = useState<Suppression[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [loadError,    setLoadError]    = useState<string | null>(null);
  const [, setTick]  = useState(0); // force re-render for countdowns

  // Per-rule enforcement action overrides (Block ⇄ Monitor). Persisted in
  // enforce-config.json via PUT /api/enforce/config; this map is { label → action }.
  const [overrides,     setOverrides]    = useState<Record<string, EnforceAction>>({});
  const [enforceMode,   setEnforceMode]  = useState<string>('monitor');
  const [savingLabel,   setSavingLabel]  = useState<string | null>(null);

  // Browsing state. All three are applied client-side: the whole catalogue is
  // already in memory, so a round trip per keystroke would only add latency.
  const [query,          setQuery]          = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [typeFilter,     setTypeFilter]     = useState<TypeFilter>('all');
  const [expanded,       setExpanded]       = useState<string | null>(null);
  const [density,        setDensity]        = useRowDensity('rules');

  // Custom-rule form state.
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [pattern,    setPattern]    = useState('');
  const [severity,   setSeverity]   = useState<'low' | 'medium' | 'high'>('medium');
  const [label,      setLabel]      = useState('');
  const [testInput,  setTestInput]  = useState('');
  const [testResult, setTestResult] = useState<null | boolean>(null);
  const [error,      setError]      = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Protected paths — the always-on block floor (distinct from regex rules).
  const [protectedPaths, setProtectedPaths] = useState<ProtectedPath[]>([]);
  const [ppPath,   setPpPath]   = useState('');
  const [ppLabel,  setPpLabel]  = useState('');
  const [ppError,  setPpError]  = useState('');
  const [ppBusy,   setPpBusy]   = useState(false);

  const fetchRules = () =>
    fetch('/api/rules')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: RulesResponse) => {
        setRules({ builtIn: data.builtIn ?? [], custom: data.custom ?? [] });
        setLoadError(null);
      })
      // A rules screen that silently shows zero rules reads as "detection is
      // off", which is the most alarming thing this app can say by accident.
      .catch((e: Error) => setLoadError(e.message || 'Request failed'))
      .finally(() => setLoading(false));

  const fetchSuppressions = () =>
    fetch('/api/suppressions')
      .then(r => r.json())
      .then(({ suppressions: s }: { suppressions: Suppression[] }) => setSuppressions(s ?? []))
      .catch(() => {});

  const fetchProtectedPaths = () =>
    fetch('/api/protected-paths')
      .then(r => r.json())
      .then(({ protectedPaths: p }: { protectedPaths: ProtectedPath[] }) => setProtectedPaths(p ?? []))
      .catch(() => {});

  const fetchEnforceConfig = () =>
    fetch('/api/enforce/config')
      .then(r => r.json())
      .then((c: { overrides?: Record<string, EnforceAction>; effectiveMode?: string }) => {
        setOverrides(c.overrides ?? {});
        setEnforceMode(c.effectiveMode ?? 'monitor');
      })
      .catch(() => {});

  useEffect(() => {
    fetchRules();
    fetchSuppressions();
    fetchProtectedPaths();
    fetchEnforceConfig();
    // Named handlers so unsubscribing removes only ours — a bare
    // socket.off('rules-update') would also drop any other tab's listener.
    const onRules = () => { fetchRules(); fetchSuppressions(); };
    const onEnforceConfig = (c: { overrides?: Record<string, EnforceAction> }) =>
      setOverrides(c.overrides ?? {});
    socket.on('rules-update', onRules);
    socket.on('protected-paths-update', fetchProtectedPaths);
    socket.on('enforce-config', onEnforceConfig);
    return () => {
      socket.off('rules-update', onRules);
      socket.off('protected-paths-update', fetchProtectedPaths);
      socket.off('enforce-config', onEnforceConfig);
    };
  }, []);

  // Countdown refresh every 30s
  useEffect(() => {
    const iv = setInterval(() => setTick(n => n + 1), 30_000);
    return () => clearInterval(iv);
  }, []);

  const activeSuppression = (ruleId: string): Suppression | undefined =>
    suppressions.find(s => s.ruleKey === ruleId && new Date(s.suppressUntil) > new Date());

  const handleSnooze = async (ruleId: string, ms: number) => {
    await fetch('/api/suppressions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleKey: ruleId, durationMs: ms, reason: 'manual snooze' }),
    });
    fetchSuppressions();
  };

  const handleCancelSnooze = async (suppressionId: number) => {
    await fetch(`/api/suppressions/${suppressionId}`, { method: 'DELETE' });
    fetchSuppressions();
  };

  const handleTest = () => {
    if (!pattern || !testInput) { setTestResult(null); return; }
    try {
      const re = new RegExp(pattern, 'i');
      setTestResult(re.test(testInput));
    } catch {
      setTestResult(null);
      setError('Invalid regex pattern');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!pattern.trim() || !label.trim()) { setError('Pattern and label are required'); return; }
    try { new RegExp(pattern); } catch { setError('Invalid regex pattern'); return; }
    setSubmitting(true);
    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: pattern.trim(), severity, label: label.trim() }),
      });
      if (!res.ok) {
        const d = await res.json();
        setError(d.error ?? 'Failed to add rule');
      } else {
        setPattern(''); setLabel(''); setTestInput(''); setTestResult(null);
        setRuleDialogOpen(false);
      }
    } catch { setError('Network error'); }
    setSubmitting(false);
  };

  const handleDelete = async (id: string) => {
    await fetch(`/api/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  };

  // The effective action for a rule = an explicit override, else its natural
  // (severity-derived) action. Mirrors server/enforcementSnapshot.actionForSeverity
  // and enforceEval's override resolution.
  const effectiveAction = (rule: RuleRow): EnforceAction =>
    overrides[rule.label] ?? actionForSeverity(rule.severity);

  // Flip a rule between Block and Monitor. The PUT replaces the whole overrides
  // map, so we merge against the current one. We only write an override when it
  // diverges from the rule's natural action — matching the default removes the
  // key, keeping the persisted map minimal.
  const handleToggleAction = async (rule: RuleRow) => {
    if (CATASTROPHIC_LABELS.has(rule.label)) return; // locked — never demotable
    const current = effectiveAction(rule);
    const next: EnforceAction = current === 'block' ? 'alert' : 'block';
    const natural = actionForSeverity(rule.severity);

    const merged: Record<string, EnforceAction> = { ...overrides };
    if (next === natural) delete merged[rule.label];
    else merged[rule.label] = next;

    setSavingLabel(rule.label);
    setOverrides(merged); // optimistic
    try {
      const res = await fetch('/api/enforce/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overrides: merged }),
      });
      if (!res.ok) { fetchEnforceConfig(); return; } // server rejected → resync truth
      const updated = await res.json();
      setOverrides(updated.overrides ?? merged);
    } catch {
      fetchEnforceConfig(); // network error → resync
    } finally {
      setSavingLabel(null);
    }
  };

  const handleAddProtectedPath = async (e: React.FormEvent) => {
    e.preventDefault();
    setPpError('');
    if (!ppPath.trim()) { setPpError('A file path is required'); return; }
    setPpBusy(true);
    try {
      const res = await fetch('/api/protected-paths', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: ppPath.trim(), label: ppLabel.trim() || undefined }),
      });
      if (res.status === 409) {
        setPpError('That path is already protected.');
      } else if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        setPpError(d.error ?? 'Failed to add protected path');
      } else {
        setPpPath(''); setPpLabel('');
        // The socket event refreshes the list, but update optimistically too.
        fetchProtectedPaths();
      }
    } catch { setPpError('Network error'); }
    setPpBusy(false);
  };

  const handleDeleteProtectedPath = async (id: string) => {
    await fetch(`/api/protected-paths/${encodeURIComponent(id)}`, { method: 'DELETE' });
    fetchProtectedPaths();
  };

  const allRules: RuleListRow[] = useMemo(() => [
    ...rules.builtIn.map(r => ({ ...r, type: 'built-in' as const })),
    ...rules.custom.map(r => ({ ...r, type: 'custom' as const })),
  ], [rules]);

  // Live per-severity counts, so the filter row says how much is behind each
  // option instead of making the operator click to find out.
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const r of allRules) {
      const sev = normalizeSeverity(r.severity);
      counts[sev] = (counts[sev] ?? 0) + 1;
    }
    return counts;
  }, [allRules]);

  const visibleRules = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allRules.filter(r => {
      if (severityFilter !== 'all' && normalizeSeverity(r.severity) !== severityFilter) return false;
      if (typeFilter !== 'all' && r.type !== typeFilter) return false;
      if (!q) return true;
      // The id and the pattern are both searchable: an operator arriving from an
      // alert has the rule *label*, one arriving from a log has the rule *id*.
      return r.label.toLowerCase().includes(q)
        || r.pattern.toLowerCase().includes(q)
        || r.id.toLowerCase().includes(q);
    });
  }, [allRules, query, severityFilter, typeFilter]);

  const activeSnoozes = suppressions.filter(s => new Date(s.suppressUntil) > new Date()).length;
  const isFiltered = query.trim() !== '' || severityFilter !== 'all' || typeFilter !== 'all';
  const enforceActive = enforceMode === 'enforce';

  // ── Columns ──────────────────────────────────────────────────────────────
  // Read in the order a rule is judged: how bad, what it catches, what string
  // it matches, and what it does about it. The pattern is the first thing to go
  // when the viewport narrows — it is the detail you open a row for, not the
  // thing you scan — and the machine-facing id survives only at the widest tier.
  const columns: DataColumn<RuleListRow>[] = [
    {
      id: 'severity', header: 'Severity', width: '96px',
      cell: r => <SeverityBadge severity={normalizeSeverity(r.severity)} />,
    },
    {
      id: 'label', header: 'Rule', width: 'minmax(0,1.4fr)',
      // The label is a sentence written for a human, so it is sans, and it is
      // the one thing in the row set at full text strength.
      cell: r => (
        <span
          title={r.label}
          style={{ color: 'var(--cs-text-strong)', fontWeight: 'var(--cs-weight-medium)' }}
        >
          {r.label}
        </span>
      ),
    },
    {
      id: 'pattern', header: 'Pattern', width: 'minmax(0,1.6fr)', hideBelow: 'xl', mono: true,
      cell: r => <span title={r.pattern}>{r.pattern}</span>,
    },
    {
      id: 'action', header: 'Action', width: '104px',
      cell: r => {
        const locked   = CATASTROPHIC_LABELS.has(r.label);
        const action   = locked ? 'block' : effectiveAction(r);
        const isBlock  = action === 'block';
        const saving   = savingLabel === r.label;
        const overrode = !locked && overrides[r.label] !== undefined;
        const chip = 'inline-flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors';
        if (locked) {
          return (
            <span
              className={chip}
              style={{
                background: 'var(--cs-bg-raised)',
                color: 'var(--cs-text-muted)',
                fontSize: 'var(--cs-text-xs)',
              }}
              title="Catastrophic-floor rule — always blocks, in either mode, and cannot be set to monitor"
            >
              <Lock className="w-3 h-3" aria-hidden="true" /> Always
            </span>
          );
        }
        return (
          <span onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
            <button
              type="button"
              onClick={() => handleToggleAction(r)}
              disabled={saving}
              aria-pressed={isBlock}
              title={isBlock
                ? 'Blocks matching tool calls in enforce mode. Click to switch to Monitor (observe only).'
                : 'Observes only — never blocks. Click to switch to Block (deny in enforce mode).'}
              className={`${chip} disabled:opacity-50`}
              style={{
                background: isBlock ? 'var(--cs-bg-raised)' : 'transparent',
                color: isBlock ? 'var(--cs-text-body)' : 'var(--cs-text-faint)',
                fontWeight: isBlock ? 'var(--cs-weight-medium)' : 'var(--cs-weight-normal)',
                fontSize: 'var(--cs-text-xs)',
              }}
            >
              {isBlock ? <Ban className="w-3 h-3" aria-hidden="true" /> : <Eye className="w-3 h-3" aria-hidden="true" />}
              {isBlock ? 'Block' : 'Monitor'}
              {/* Accent means "you changed this", never "this is dangerous". */}
              {overrode && (
                <span
                  className="w-1 h-1 rounded-full shrink-0"
                  style={{ background: 'var(--cs-accent)' }}
                  title="Overridden — differs from this severity's default action"
                />
              )}
            </button>
          </span>
        );
      },
    },
    {
      id: 'type', header: 'Type', width: '78px', hideBelow: '2xl',
      cell: r => (
        <span style={{ color: r.type === 'custom' ? 'var(--cs-accent)' : 'var(--cs-text-faint)' }}>
          {r.type}
        </span>
      ),
    },
    {
      id: 'id', header: 'Rule ID', width: '132px', hideBelow: '3xl', mono: true,
      cell: r => <span title={r.id}>{r.id}</span>,
    },
    {
      id: 'snooze', header: 'Snooze', width: '76px',
      cell: r => {
        const supp = activeSuppression(r.id);
        return (
          <span
            className="flex items-center gap-1"
            onClick={e => e.stopPropagation()}
            onKeyDown={e => e.stopPropagation()}
          >
            {supp ? (
              <>
                <span
                  className="cs-mono inline-flex items-center gap-1"
                  style={{ color: 'var(--cs-warn)', fontSize: 'var(--cs-text-xs)' }}
                  title={`Snoozed until ${new Date(supp.suppressUntil).toLocaleString()}`}
                >
                  <Clock className="w-3 h-3" aria-hidden="true" />
                  {formatCountdown(supp.suppressUntil)}
                </span>
                <button
                  type="button"
                  onClick={() => handleCancelSnooze(supp.id)}
                  className="p-0.5 rounded transition-colors"
                  style={{ color: 'var(--cs-text-faint)' }}
                  title="Cancel snooze — resume alerting on this rule"
                >
                  <X className="w-3 h-3" aria-hidden="true" />
                </button>
              </>
            ) : (
              // Portalled, because the row is paint-contained and would clip an
              // in-row menu. Radix also gives Escape-to-close and arrow keys.
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  {/* Icon-only: the word repeated down 649 rows is noise, and
                      the column header already names the control. */}
                  <button
                    type="button"
                    className="p-1 rounded transition-colors"
                    style={{ color: 'var(--cs-text-faint)' }}
                    aria-label={`Snooze “${r.label}”`}
                    title="Stop this rule alerting for a while"
                  >
                    <Clock className="w-3 h-3" aria-hidden="true" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="min-w-[120px]">
                  {SNOOZE_OPTIONS.map(opt => (
                    <DropdownMenuItem key={opt.label} onSelect={() => handleSnooze(r.id, opt.ms)}>
                      {opt.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </span>
        );
      },
    },
    {
      id: 'delete', header: '', width: '28px', align: 'end',
      cell: r => r.type === 'custom' ? (
        <span onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
          <button
            type="button"
            onClick={() => handleDelete(r.id)}
            className="p-1 rounded transition-colors"
            style={{ color: 'var(--cs-text-faint)' }}
            title={`Delete the custom rule “${r.label}”`}
          >
            <Trash2 className="w-3 h-3" aria-hidden="true" />
          </button>
        </span>
      ) : null,
    },
  ];

  // The expanded strip. The pattern column truncates hard at this density, and
  // the full regex — plus its flags and its id — is the reason to open a row.
  const renderDetail = (r: RuleListRow) => {
    if (expanded !== r.id) return null;
    const locked = CATASTROPHIC_LABELS.has(r.label);
    const action = locked ? 'block' : effectiveAction(r);
    return (
      <div className="flex flex-col gap-1.5 py-1.5" style={{ fontSize: 'var(--cs-text-xs)' }}>
        <code
          className="cs-mono block px-2 py-1 rounded whitespace-pre-wrap break-all"
          style={{ background: 'var(--cs-bg-canvas)', color: 'var(--cs-text-body)' }}
        >
          /{r.pattern}/{r.flags}
        </code>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1" style={{ color: 'var(--cs-text-faint)' }}>
          <span className="cs-mono">{r.id}</span>
          <span>{r.type}</span>
          <span>
            {locked
              ? 'Catastrophic floor — blocks in monitor mode too.'
              : action === 'block'
                ? enforceActive
                  ? 'Blocks matching tool calls now.'
                  : 'Would block, but enforcement is set to monitor.'
                : 'Detects and alerts only. Never blocks.'}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0" style={{ background: 'var(--cs-bg-canvas)' }}>

      <Toolbar>
        <ToolbarTitle
          icon={<Shield className="w-3.5 h-3.5" />}
          count={isFiltered ? `${visibleRules.length}/${allRules.length}` : allRules.length}
          countTitle={`${rules.builtIn.length} built-in · ${rules.custom.length} custom${activeSnoozes ? ` · ${activeSnoozes} snoozed` : ''}`}
        >
          Detection rules
        </ToolbarTitle>

        {/* The standing enforcement mode. A rule set to Block does nothing at
            all in monitor mode, so this tab cannot be honest without saying
            which mode is live — the detail is one click away in the popover. */}
        <Popover>
          <PopoverTrigger asChild>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md transition-colors shrink-0"
              style={{
                background: 'var(--cs-bg-raised)',
                color: enforceActive ? 'var(--cs-text-body)' : 'var(--cs-text-muted)',
                fontSize: 'var(--cs-text-xs)',
              }}
              title="What Block and Monitor actually do"
            >
              {enforceActive
                ? <Ban className="w-3 h-3" aria-hidden="true" />
                : <Eye className="w-3 h-3" aria-hidden="true" />}
              {enforceActive ? 'Enforce' : 'Monitor'}
              <span className="hidden 3xl:inline">mode</span>
            </button>
          </PopoverTrigger>
          <PopoverContent
            align="start"
            className="max-w-sm"
            style={{ fontSize: 'var(--cs-text-sm)', lineHeight: 'var(--cs-leading-normal)' }}
          >
            <p style={{ color: 'var(--cs-text-body)' }}>
              The <strong>Action</strong> column decides whether a rule <strong>blocks</strong> a
              matching tool call or only <strong>monitors</strong> it — detecting and alerting,
              never denying.
            </p>
            <p className="mt-2" style={{ color: 'var(--cs-text-muted)' }}>
              {enforceActive
                ? 'Enforcement is set to enforce, so Block decisions are live right now.'
                : 'Enforcement is set to monitor, so nothing here blocks yet. Change it in the Enforce tab.'}
              {' '}Detection runs in both modes. Catastrophic-floor rules always block and cannot be changed.
            </p>
          </PopoverContent>
        </Popover>

        {/* Severity scale. The primary axis of this product, so it stays
            permanently visible; each option carries its own glyph, so the level
            is legible without the colour. Only levels that exist are offered. */}
        <div className="flex items-center gap-0.5" role="group" aria-label="Filter by severity">
          <ToolButton
            active={severityFilter === 'all'}
            aria-pressed={severityFilter === 'all'}
            onClick={() => setSeverityFilter('all')}
            title="All severities"
          >
            All
          </ToolButton>
          {SEVERITY_ORDER.filter(sev => (severityCounts[sev] ?? 0) > 0).map(sev => {
            const meta = SEVERITY_META[sev];
            const active = severityFilter === sev;
            return (
              <ToolButton
                key={sev}
                active={active}
                aria-pressed={active}
                onClick={() => setSeverityFilter(sev)}
                title={`${meta.label} — ${meta.meaning} (${severityCounts[sev]} rules)`}
              >
                <meta.Icon className="w-3 h-3" style={{ color: `var(--cs-sev-${sev})` }} aria-hidden="true" />
                {meta.label}
                <span className="cs-mono hidden 2xl:inline" style={{ color: 'var(--cs-text-faint)' }}>
                  {severityCounts[sev]}
                </span>
              </ToolButton>
            );
          })}
        </div>

        <div className="flex items-center gap-1 ml-auto">
          <ToolSearch
            value={query}
            onChange={setQuery}
            placeholder="Search rules…"
            label="Search rules by label, pattern or rule id"
            className="w-28 xl:w-32 2xl:w-48"
          />
          <ToolButton
            active={typeFilter === 'custom'}
            aria-pressed={typeFilter === 'custom'}
            onClick={() => setTypeFilter(t => (t === 'custom' ? 'all' : 'custom'))}
            aria-label="Show only custom rules"
            title={typeFilter === 'custom' ? 'Show every rule' : 'Show only the rules I added'}
          >
            <FileWarning className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden 2xl:inline">Custom</span>
          </ToolButton>
          <RowDensityToggle density={density} onChange={setDensity} className="mx-1" />

          {/* Protected paths and the custom-rule form are both once-a-month
              jobs. They open over the table instead of standing above it,
              because on a 1366×768 screen they cost more rows than they are
              worth. Radix handles Escape and the focus trap. */}
          <Dialog>
            <DialogTrigger asChild>
              <ToolButton aria-label="Protected paths" title="Paths that are blocked always, in either mode">
                <Lock className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden 2xl:inline">Protected paths</span>
                {protectedPaths.length > 0 && (
                  <span className="cs-mono" style={{ color: 'var(--cs-text-faint)' }}>{protectedPaths.length}</span>
                )}
              </ToolButton>
            </DialogTrigger>
            <DialogContent className="sm:max-w-xl">
              <DialogHeader>
                <DialogTitle>Protected paths</DialogTitle>
                <DialogDescription>
                  Protected paths are blocked <strong>immediately and always</strong> — even in monitor
                  mode. Any tool call that reads, writes to, or deletes one is denied before it runs.
                  Regex rules only detect by default; in enforce mode, high- and critical-severity
                  rules also block.
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleAddProtectedPath} className="flex flex-col gap-3">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <Field label="File path" className="sm:col-span-2">
                    <input
                      type="text"
                      value={ppPath}
                      onChange={e => { setPpPath(e.target.value); setPpError(''); }}
                      placeholder="~/.ssh/id_rsa"
                      className={`cs-mono ${fieldClass}`}
                      style={fieldStyle}
                    />
                  </Field>
                  <Field label="Label" hint="optional">
                    <input
                      type="text"
                      value={ppLabel}
                      onChange={e => setPpLabel(e.target.value)}
                      placeholder="SSH private key"
                      className={fieldClass}
                      style={fieldStyle}
                    />
                  </Field>
                </div>

                {ppError && (
                  <p style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-xs)' }}>{ppError}</p>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={ppBusy}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors disabled:opacity-50"
                    style={{
                      background: 'var(--cs-bg-raised)',
                      color: 'var(--cs-sev-critical-fg)',
                      fontSize: 'var(--cs-text-sm)',
                      fontWeight: 'var(--cs-weight-medium)',
                    }}
                  >
                    <Lock className="w-3.5 h-3.5" aria-hidden="true" /> Protect path
                  </button>
                </div>
              </form>

              {protectedPaths.length === 0 ? (
                <p
                  className="flex items-center gap-1.5 px-3 py-4 rounded-md"
                  style={{ background: 'var(--cs-bg-sunken)', color: 'var(--cs-text-faint)', fontSize: 'var(--cs-text-sm)' }}
                >
                  <ShieldOff className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                  No protected paths yet. Add the files an agent should never be able to read or
                  overwrite — private keys, credential stores, shell profiles.
                </p>
              ) : (
                <ul className="flex flex-col max-h-64 overflow-auto" aria-label="Protected paths">
                  {protectedPaths.map(pp => (
                    <li
                      key={pp.id}
                      className="flex items-center gap-2 py-1.5"
                      style={{ borderBottom: '1px solid var(--cs-rule)' }}
                    >
                      <Lock className="w-3 h-3 shrink-0" style={{ color: 'var(--cs-sev-critical)' }} aria-hidden="true" />
                      <div className="min-w-0 flex-1">
                        {pp.label && pp.label !== pp.path && (
                          <p className="truncate" style={{ color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-sm)' }}>
                            {pp.label}
                          </p>
                        )}
                        <code className="cs-mono block break-all" style={{ color: 'var(--cs-text-muted)', fontSize: 'var(--cs-text-xs)' }}>
                          {pp.path}
                        </code>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleDeleteProtectedPath(pp.id)}
                        className="p-1 rounded shrink-0 transition-colors"
                        style={{ color: 'var(--cs-text-faint)' }}
                        title="Stop protecting this path"
                      >
                        <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </DialogContent>
          </Dialog>

          <Dialog open={ruleDialogOpen} onOpenChange={setRuleDialogOpen}>
            <DialogTrigger asChild>
              <ToolButton aria-label="New rule" title="Add a custom detection rule">
                <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                <span className="hidden 2xl:inline">New rule</span>
              </ToolButton>
            </DialogTrigger>
            <DialogContent className="sm:max-w-xl">
              <DialogHeader>
                <DialogTitle>New detection rule</DialogTitle>
                <DialogDescription>
                  A rule is a regular expression matched against tool arguments — commands, file
                  paths, URLs. Test it against a sample below before saving; a pattern that matches
                  everything produces an alert log nobody reads.
                </DialogDescription>
              </DialogHeader>

              <form onSubmit={handleSubmit} className="flex flex-col gap-3">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <Field label="Pattern" hint="regex" className="sm:col-span-2">
                    <input
                      type="text"
                      value={pattern}
                      onChange={e => { setPattern(e.target.value); setTestResult(null); setError(''); }}
                      placeholder="curl\s+.*\|\s*(ba)?sh"
                      className={`cs-mono ${fieldClass}`}
                      style={fieldStyle}
                    />
                  </Field>
                  <Field label="Severity">
                    <select
                      value={severity}
                      onChange={e => setSeverity(e.target.value as 'low' | 'medium' | 'high')}
                      className={fieldClass}
                      style={fieldStyle}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </Field>
                </div>

                <Field label="Label" hint="what it catches, in a sentence">
                  <input
                    type="text"
                    value={label}
                    onChange={e => setLabel(e.target.value)}
                    placeholder="Suspicious curl pipe"
                    className={fieldClass}
                    style={fieldStyle}
                  />
                </Field>

                <Field label="Test input" hint="optional">
                  <span className="flex gap-2">
                    <input
                      type="text"
                      value={testInput}
                      onChange={e => { setTestInput(e.target.value); setTestResult(null); }}
                      placeholder="Paste a sample span attribute value…"
                      className="cs-mono flex-1 min-w-0 px-2 py-1.5 outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--cs-accent)]"
                      style={fieldStyle}
                    />
                    <button
                      type="button"
                      onClick={handleTest}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md shrink-0 transition-colors"
                      style={{ background: 'var(--cs-bg-raised)', color: 'var(--cs-text-body)', fontSize: 'var(--cs-text-sm)' }}
                    >
                      <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" /> Test
                    </button>
                  </span>
                </Field>

                {testResult !== null && (
                  <p
                    role="status"
                    className="cs-mono"
                    style={{
                      color: testResult ? 'var(--cs-accent)' : 'var(--cs-text-faint)',
                      fontSize: 'var(--cs-text-xs)',
                    }}
                  >
                    {testResult ? 'Match found' : 'No match'}
                  </p>
                )}

                {error && (
                  <p role="alert" style={{ color: 'var(--cs-sev-critical-fg)', fontSize: 'var(--cs-text-xs)' }}>
                    {error}
                  </p>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={submitting}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors disabled:opacity-50"
                    style={{
                      background: 'var(--cs-accent)',
                      color: 'var(--cs-text-invert)',
                      fontSize: 'var(--cs-text-sm)',
                      fontWeight: 'var(--cs-weight-medium)',
                    }}
                  >
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add rule
                  </button>
                </div>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </Toolbar>

      <DataTable
        rows={visibleRules}
        columns={columns}
        rowKey={r => r.id}
        label="Detection rules"
        density={density}
        minWidth={640}
        severity={r => normalizeSeverity(r.severity)}
        muted={r => !!activeSuppression(r.id)}
        onActivate={r => setExpanded(prev => (prev === r.id ? null : r.id))}
        renderDetail={renderDetail}
        loading={loading}
        error={loadError ? (
          <ErrorState
            description={`The rule catalogue did not load (${loadError}). Detection on the server is unaffected — this is only the view.`}
            onRetry={() => { setLoading(true); fetchRules(); }}
          />
        ) : undefined}
        empty={isFiltered ? (
          <EmptyState
            icon={<SearchX className="w-6 h-6" aria-hidden="true" />}
            title="No rule matches this filter"
            description="Nothing in the catalogue matches the current search, severity and type. Clear the search box or widen the severity scale above."
          />
        ) : (
          <EmptyState
            icon={<ShieldOff className="w-6 h-6" aria-hidden="true" />}
            title="No rules loaded"
            description="ClaudeSec ships with several hundred built-in detection rules, so an empty catalogue means the server returned none. Check the server log, then reload."
          />
        )}
      />
    </div>
  );
}
