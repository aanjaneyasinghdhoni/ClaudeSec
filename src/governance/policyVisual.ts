/**
 * Pure status → visual mapping for the Govern tab.
 *
 * Kept out of GovernTab.tsx on purpose: that file imports `./socket`, which
 * opens a live socket.io connection the moment the module loads, so it can
 * never be imported hermetically by a test. Everything here is a plain
 * function over plain data, so tests/governTabStatusTest.ts can exercise the
 * one rule this whole screen stands on — held reads grey, not green, and the
 * three statuses can never collide on screen — without mounting React or
 * touching the network.
 */
import type { Severity } from '../shared/types';

export type PolicyStatus = 'held' | 'violated' | 'not-provable';

export interface StatusVisual {
  /** The word rendered next to the glyph. Deliberately not a severity label
   *  ("High") — these are outcomes of a policy, not levels of a threat. */
  word: string;
  /** Which severity token drives the row's spine (and, for high/critical, its
   *  wash) — see src/components/data/severity.tsx and data-table.css. */
  severity: Severity;
}

/**
 * `held` never carries risk colour, no matter how severe the policy it
 * describes — DESIGN.md reserves saturated colour for risk, and green is a
 * colour this system never uses because it means "safe", which is a claim
 * this screen is built specifically not to make. `not-provable` is fixed at
 * `medium` regardless of the policy's own floor: it is not a scaled-down
 * violation, it is a distinct third outcome — "I wasn't looking" — and
 * scaling it by severity would make a not-provable critical policy look
 * indistinguishable from a violated high one.
 */
export function policyStatusVisual(status: PolicyStatus, severityFloor: Severity | null): StatusVisual {
  switch (status) {
    case 'held':
      return { word: 'Held', severity: 'none' };
    case 'not-provable':
      return { word: 'Not provable', severity: 'medium' };
    case 'violated':
    default:
      // Configuration policies (P11, P12) carry no rule and so no severity
      // floor. A violated configuration promise still undermines the whole
      // evidence pack, not just one rule, so it reads as 'high' rather than
      // falling back to something that looks calmer than a rule violation.
      return { word: 'Violated', severity: severityFloor ?? 'high' };
  }
}

export interface DataHeldCoverage {
  configuredDays: number;
  effectiveDays: number;
  cappedByMaxSpans: boolean;
  warning: string | null;
}

/** "183 days configured · 41 days actual — Effective coverage is capped by …" */
export function describeDataHeld(dataHeld: DataHeldCoverage): string {
  const day = (n: number) => `${n} day${n === 1 ? '' : 's'}`;
  const base = `${day(dataHeld.configuredDays)} configured · ${day(dataHeld.effectiveDays)} actual`;
  return dataHeld.warning ? `${base} — ${dataHeld.warning}` : base;
}

export interface ChainCheck {
  ok: boolean;
}

export interface ChainCoverage {
  ok: boolean;
  audit: ChainCheck;
  enforce: ChainCheck;
  spans: ChainCheck;
}

/**
 * One line for the coverage strip. Names exactly which of the three
 * independently hash-chained logs broke rather than a single ok/not-ok bit —
 * "the chain is broken" tells an operator nothing about whether it is the
 * audit log, the enforce log, or the substance-carrying spans table that no
 * longer hashes to what was recorded.
 */
export function summarizeChain(chain: ChainCoverage): { ok: boolean; label: string } {
  if (chain.ok) return { ok: true, label: 'Verified' };
  const broken: string[] = [];
  if (!chain.audit.ok) broken.push('audit log');
  if (!chain.enforce.ok) broken.push('enforce log');
  if (!chain.spans.ok) broken.push('spans');
  return { ok: false, label: broken.length > 0 ? `Broken — ${broken.join(', ')}` : 'Broken' };
}

export const PERIOD_OPTIONS = [30, 90, 180, 365] as const;
export type PeriodDays = (typeof PERIOD_OPTIONS)[number];

export function isPeriodDays(value: number): value is PeriodDays {
  return (PERIOD_OPTIONS as readonly number[]).includes(value);
}

/**
 * The honesty line the spec requires on screen, not just in the docs. Every
 * qualifier below can independently be false while the badge still reads
 * "Held" — that gap is the entire reason "not provable" exists as its own
 * status rather than being folded into "held".
 */
export const HELD_HONESTY_LINE =
  '"Held" means nothing ClaudeSec observed matched a rule it had enabled, in the window it still holds — not that nothing happened. ' +
  'An unmonitored agent, a disabled rule, a service outage, or a pruned retention window can each make this true when the honest answer is no.';
