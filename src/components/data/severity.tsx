/**
 * The severity vocabulary.
 *
 * Severity is the single most important signal this product produces, so it is
 * the one thing allowed to be saturated on an otherwise near-monochrome screen.
 * That privilege comes with a rule, taken straight from the design system:
 *
 *   > Colour never travels alone.
 *
 * Every level carries three independent signals — its colour, its own glyph,
 * and its own word — so a row is still readable in greyscale, on a bad monitor,
 * or to a viewer with a colour-vision deficiency. Nothing in this file lets a
 * caller render the colour without the other two.
 *
 * The colours themselves are never written here: they live in tokens.css as
 * `--cs-sev-{level}` (the 3px mark), `--cs-sev-{level}-fg` (text, clears 4.5:1)
 * and `--cs-sev-{level}-bg` (the row wash). Light mode needs all three to be
 * different values, which is why the token set is shaped this way.
 */
import { CircleMinus, Info, TriangleAlert, OctagonAlert, ShieldAlert } from 'lucide-react';
import type { Severity } from '@/src/shared/types';

export type { Severity };

/** Most severe first — the order a triage list is read in. */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'none'] as const;

/** Higher is worse. Use for sorting; never for deciding a colour. */
const SEVERITY_RANK: Record<Severity, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

/**
 * Coerce whatever the API returned into a level we can render. Anything
 * unrecognised falls back to `none` rather than throwing — a malformed
 * severity must never be able to blank out an alert row.
 */
export function normalizeSeverity(value: string | null | undefined): Severity {
  return value != null && value in SEVERITY_RANK ? (value as Severity) : 'none';
}

interface SeverityMeta {
  /** The word. Sentence case for prose, upper-cased by the badge itself. */
  label: string;
  /** The glyph. One per level, distinguishable by outline shape alone. */
  Icon: typeof Info;
  /** What the level asks the operator to do. Used as the accessible name. */
  meaning: string;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  none:     { label: 'None',     Icon: CircleMinus,  meaning: 'Nothing matched'  },
  low:      { label: 'Low',      Icon: Info,         meaning: 'Worth knowing'    },
  medium:   { label: 'Medium',   Icon: TriangleAlert, meaning: 'Review it'       },
  high:     { label: 'High',     Icon: OctagonAlert, meaning: 'Act today'        },
  critical: { label: 'Critical', Icon: ShieldAlert,  meaning: 'Act now'          },
};

/** The mark colour for a level — the 3px spine, icons, chart marks. */
export function severityMark(severity: Severity): string {
  return `var(--cs-sev-${severity})`;
}

/** The text colour for a level. Cleared for 4.5:1 in every theme. */
export function severityText(severity: Severity): string {
  return `var(--cs-sev-${severity}-fg)`;
}

/**
 * The badge that sits next to the spine.
 *
 * Deliberately unfilled: the spine already carries the colour and high/critical
 * rows already carry a wash, so adding a third tinted block per row would spend
 * the whole chroma budget on decoration. The glyph and the word are what make
 * the level unambiguous; the colour is the fast path, not the only path.
 */
export function SeverityBadge({
  severity,
  showLabel = true,
  className = '',
}: {
  severity: Severity;
  /** Drop to an icon-only badge in the tightest layouts. The accessible name
   *  still carries the word, so nothing is lost to a screen reader. */
  showLabel?: boolean;
  className?: string;
}) {
  const { label, Icon, meaning } = SEVERITY_META[severity] ?? SEVERITY_META.none;
  return (
    <span
      className={`inline-flex items-center gap-1 ${className}`}
      title={`${label} — ${meaning}`}
      aria-label={`Severity: ${label}`}
    >
      <Icon
        className="w-3 h-3 shrink-0"
        style={{ color: severityMark(severity) }}
        aria-hidden="true"
      />
      {showLabel && (
        <span
          className="uppercase"
          style={{
            color: severityText(severity),
            fontSize: 'var(--cs-text-2xs)',
            fontWeight: 'var(--cs-weight-bold)',
            letterSpacing: 'var(--cs-tracking-wide)',
          }}
        >
          {label}
        </span>
      )}
    </span>
  );
}

/**
 * A free-standing spine, for surfaces that are not <DataTable> rows — stat
 * tiles, session cards, the detail drawer header. Same 3px, same tokens, so it
 * lines up with the list it came from.
 */
export function SeveritySpine({ severity, className = '' }: { severity: Severity; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`self-stretch shrink-0 ${className}`}
      style={{
        width: 'var(--cs-spine-width)',
        borderRadius: 'var(--cs-radius-xs)',
        background: severityMark(severity),
      }}
    />
  );
}
