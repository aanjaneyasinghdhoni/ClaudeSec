/**
 * Empty, loading and error states for data surfaces.
 *
 * A list has four states, not one, and three of them get skipped when a screen
 * is built table-first. They are extracted here so every tab tells the same
 * story with the same shapes:
 *
 *   - **Loading** is a skeleton of the thing that is coming, not a spinner. A
 *     spinner says "wait"; a skeleton says "here is the shape of the answer",
 *     and it stops the header and toolbar jumping when the rows land.
 *   - **Empty** gets real copy. "No data" tells an operator nothing; the useful
 *     sentence is what *would* put a row here, so they can tell "quiet" apart
 *     from "broken".
 *   - **Error** names what failed and offers the retry, because a monitoring
 *     tool that silently shows zero rows during an outage is worse than one
 *     that shows nothing at all.
 */
import type { ReactNode } from 'react';
import { RefreshCw } from 'lucide-react';
import { Skeleton } from '@/src/components/ui/skeleton';

/**
 * A centred well used by both the empty and the error state.
 *
 * `flex-1` fills the space the rows would have taken when the parent is a flex
 * column (which is how <DataTable> renders it); `min-h-full` covers the case of
 * a plain block parent, so the well never collapses to a thin strip.
 */
function StateWell({ children }: { children: ReactNode }) {
  return (
    <div
      className="flex-1 min-h-full flex flex-col items-center justify-center gap-2 px-6 py-10 text-center"
      style={{ background: 'var(--cs-bg-sunken)' }}
    >
      {children}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  /** One short line naming the state, not the absence of data. */
  title: string;
  /** What would cause a row to appear here. This is the part that earns its keep. */
  description: string;
  action?: ReactNode;
}) {
  return (
    <StateWell>
      {icon && <span style={{ color: 'var(--cs-text-faint)' }}>{icon}</span>}
      <p
        style={{
          color: 'var(--cs-text-body)',
          fontSize: 'var(--cs-text-md)',
          fontWeight: 'var(--cs-weight-medium)',
        }}
      >
        {title}
      </p>
      <p
        className="max-w-sm"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-sm)',
          lineHeight: 'var(--cs-leading-normal)',
        }}
      >
        {description}
      </p>
      {action}
    </StateWell>
  );
}

export function ErrorState({
  title = 'Could not load this view',
  description,
  onRetry,
}: {
  title?: string;
  description: string;
  onRetry?: () => void;
}) {
  return (
    <StateWell>
      <p
        style={{
          color: 'var(--cs-sev-critical-fg)',
          fontSize: 'var(--cs-text-md)',
          fontWeight: 'var(--cs-weight-medium)',
        }}
      >
        {title}
      </p>
      <p
        className="max-w-sm"
        style={{
          color: 'var(--cs-text-faint)',
          fontSize: 'var(--cs-text-sm)',
          lineHeight: 'var(--cs-leading-normal)',
        }}
      >
        {description}
      </p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 mt-1 px-3 py-1.5 rounded-md transition-colors"
          style={{
            background: 'var(--cs-bg-raised)',
            color: 'var(--cs-text-body)',
            fontSize: 'var(--cs-text-sm)',
          }}
        >
          <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> Try again
        </button>
      )}
    </StateWell>
  );
}

/**
 * A skeleton shaped like the table that is loading. `columns` should be the
 * same widths the real table uses so nothing shifts when the data arrives.
 */
export function TableSkeleton({
  rows = 12,
  columns = 5,
  rowHeight = 'var(--cs-row-compact)',
}: {
  rows?: number;
  columns?: number;
  rowHeight?: string;
}) {
  return (
    <div className="px-3 py-1" aria-busy="true" aria-label="Loading rows">
      {Array.from({ length: rows }, (_, r) => (
        <div
          key={r}
          className="flex items-center gap-3"
          style={{ height: rowHeight, borderBottom: '1px solid var(--cs-rule)' }}
        >
          {Array.from({ length: columns }, (_, c) => (
            // Widths taper across the row so the block reads as a table rather
            // than as a stack of identical bars.
            <Skeleton key={c} className="h-2.5" style={{ width: `${Math.max(8, 34 - c * 5)}%` }} />
          ))}
        </div>
      ))}
    </div>
  );
}
