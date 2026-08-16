/**
 * DataTable — the dense list shell every data-heavy tab is built on.
 *
 * ## Why this is a grid and not a <table>
 *
 * The list has to hold thousands of rows on a laptop without virtualizing. The
 * cheap way to do that is `content-visibility: auto`, which lets the browser
 * skip layout and paint for off-screen rows while leaving them in the DOM — so
 * Ctrl-F, the sticky header, anchor links and screen readers keep working, and
 * we do not inherit the usual virtualized-list bugs.
 *
 * CSS containment does not apply to internal table elements, so
 * `content-visibility` on a `<tr>` is silently a no-op. Rows therefore have to
 * be block-level boxes. Each row is its own CSS grid sharing one track list via
 * a custom property, which is what keeps the columns — and the severity spine —
 * aligned down the whole list. ARIA table roles restore the semantics a
 * `<table>` would have given for free.
 *
 * If a surface ever outgrows this (tens of thousands of rows), the replacement
 * is virtualization behind the same props, not a different component API.
 *
 * ## Density
 *
 * Compact by default. See `RowDensity.tsx` for why 32px rows rather than 40px
 * decide what fits on a 1366×768 screen.
 *
 * ## Responsive columns
 *
 * A column declares `hideBelow`, and the shell emits one grid track list per
 * tier (base / 1280 / 1440 / 1920) containing exactly the columns visible at
 * that tier. Cells and tracks are derived from the same list, so they cannot
 * drift apart. Below the base tier the table scrolls horizontally inside its
 * own container — the page body never does.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Severity } from '@/src/shared/types';
import type { RowDensity } from './RowDensity';
import { TableSkeleton } from './states';
import './data-table.css';

/** The narrowest viewport tier at which a column still earns its width. */
export type ColumnTier = 'xl' | '2xl' | '3xl';

const TIERS = ['base', 'xl', '2xl', '3xl'] as const;
type Tier = (typeof TIERS)[number];
const TIER_RANK: Record<Tier, number> = { base: 0, xl: 1, '2xl': 2, '3xl': 3 };

export interface DataColumn<T> {
  /** Stable id, used as the React key for the cell. */
  id: string;
  /** Column header. Rendered as a 10px uppercase eyebrow — keep it to a word or two. */
  header: React.ReactNode;
  /** A CSS grid track: `'88px'`, `'minmax(0,1.4fr)'`, `'max-content'`. */
  width: string;
  /** Drop the column entirely below this tier. Omit to always show it. */
  hideBelow?: ColumnTier;
  /** `'end'` for numbers and anything else that should line up on the right. */
  align?: 'start' | 'end';
  /** Machine-authored strings and numbers: tabular monospace, optically scaled. */
  mono?: boolean;
  cell: (row: T) => React.ReactNode;
}

export interface DataTableProps<T> {
  rows: T[];
  columns: DataColumn<T>[];
  /** Stable identity per row. Must not be the array index — rows stream in live. */
  rowKey: (row: T) => React.Key;
  /** Accessible name for the table. */
  label: string;
  density?: RowDensity;
  /** Horizontal floor, in px, before the table scrolls inside itself. */
  minWidth?: number;
  /** The row's severity. Drives the spine, and the wash on high/critical. */
  severity?: (row: T) => Severity | undefined;
  /** Dim a row without removing it — dismissed, or lingering in an undo window. */
  muted?: (row: T) => boolean;
  /** Click or Enter/Space on the row. Controls inside a row must stop propagation. */
  onActivate?: (row: T) => void;
  /** An expanded strip rendered under a row, spanning every column. */
  renderDetail?: (row: T) => React.ReactNode | null;
  /** Show a skeleton instead of the body. */
  loading?: boolean;
  /** Rendered in place of the body when there are no rows and no error. */
  empty?: React.ReactNode;
  /** Rendered in place of the body when the fetch failed. Takes precedence. */
  error?: React.ReactNode;
}

/** The grid track list for one tier — only the columns visible at that tier. */
function trackList<T>(columns: DataColumn<T>[], tier: Tier): string {
  return columns
    .filter(c => TIER_RANK[tier] >= TIER_RANK[c.hideBelow ?? 'base'])
    .map(c => c.width)
    .join(' ');
}

/** The class that removes a cell from the flow below its tier. */
function hideClass<T>(column: DataColumn<T>): string {
  return column.hideBelow ? `cs-dt-hb-${column.hideBelow}` : '';
}

/** Below this a scroll region is a sliver, not a list. */
const MIN_SCROLL_HEIGHT = 160;

/**
 * Whether an element scrolls vertically, as opposed to merely clipping.
 *
 * Only the vertical value decides, because the shorthand hides the case that
 * matters: `overflow-x: hidden` on its own computes `overflow-y` to `auto`, and
 * such an element really is a vertical scrollport. Conversely `hidden` and
 * `clip` never scroll the user anywhere — they are how a collapsible panel
 * animates its own height (Settings' sections) or how a card keeps its rounded
 * corners. Treating those as scrollports pins any table inside them to a sliver.
 */
function scrollsVertically(el: HTMLElement): boolean {
  const overflowY = getComputedStyle(el).overflowY;
  return overflowY === 'auto' || overflowY === 'scroll';
}

/** The bottom edge of the nearest scrollport, clamped to the viewport. */
function scrollportBottom(from: HTMLElement): number {
  for (let el = from.parentElement; el; el = el.parentElement) {
    if (scrollsVertically(el)) {
      return Math.min(el.getBoundingClientRect().bottom, window.innerHeight);
    }
  }
  return window.innerHeight;
}

/**
 * Bound the table's own height so it always owns its vertical scroll.
 *
 * A sticky column header only sticks against the nearest scroll container, so
 * the table has to be that container. It is one when a flex ancestor hands it a
 * definite height — but a page shell that wraps the tab in an auto-height
 * column and scrolls further up would silently take the scroll away, and the
 * header would slide off the top of the screen.
 *
 * Measuring from the table's own top edge to the bottom of the enclosing
 * scrollport gives it a definite height under either shell. The measurement is
 * stable: once the ceiling is applied the outer container no longer scrolls, so
 * the top edge stops moving.
 *
 * That stability argument only holds while the table is what makes the
 * scrollport scroll. A table embedded well down a long page — one panel among
 * several — starts below the fold, so there is no room between its top edge and
 * the scrollport's bottom to measure. It cannot own a scroll the page has
 * already taken, so it takes no ceiling at all and grows inline. Rows still cost
 * nothing off screen: `content-visibility` lives on the row, not the container.
 */
function useOwnScrollHeight(ref: React.RefObject<HTMLDivElement | null>) {
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const apply = () => {
      const top = el.getBoundingClientRect().top;
      const available = Math.round(scrollportBottom(el) - top);
      if (available < MIN_SCROLL_HEIGHT) el.style.removeProperty('--cs-dt-max-h');
      else el.style.setProperty('--cs-dt-max-h', `${available}px`);
    };
    apply();
    const observer = new ResizeObserver(apply);
    if (el.parentElement) observer.observe(el.parentElement);
    window.addEventListener('resize', apply);
    return () => { observer.disconnect(); window.removeEventListener('resize', apply); };
  }, [ref]);
}

export function DataTable<T>({
  rows,
  columns,
  rowKey,
  label,
  density = 'compact',
  minWidth = 640,
  severity,
  muted,
  onActivate,
  renderDetail,
  loading = false,
  empty,
  error,
}: DataTableProps<T>) {
  const rootRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  useOwnScrollHeight(rootRef);
  // Roving tabindex: the list is one tab stop, and arrow keys walk it. With
  // thousands of alerts, one tab stop per row would make the Tab key useless.
  const [focusedKey, setFocusedKey] = useState<React.Key | null>(null);

  const trackVars = useMemo(() => ({
    '--cs-dt-cols-base': trackList(columns, 'base'),
    '--cs-dt-cols-xl':   trackList(columns, 'xl'),
    '--cs-dt-cols-2xl':  trackList(columns, '2xl'),
    '--cs-dt-cols-3xl':  trackList(columns, '3xl'),
    '--cs-dt-min-width': `${minWidth}px`,
  } as React.CSSProperties), [columns, minWidth]);

  const moveFocus = useCallback((from: HTMLElement, delta: number | 'first' | 'last') => {
    const all = Array.from(bodyRef.current?.querySelectorAll<HTMLElement>('[data-dt-row]') ?? []);
    if (all.length === 0) return;
    const here = all.indexOf(from);
    const next =
      delta === 'first' ? 0 :
      delta === 'last'  ? all.length - 1 :
      Math.min(all.length - 1, Math.max(0, here + delta));
    all[next]?.focus();
  }, []);

  const onRowKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>, row: T) => {
    // Let a button or link inside the row handle its own keys first.
    if (e.target !== e.currentTarget) return;
    switch (e.key) {
      case 'Enter':
      case ' ':
        if (onActivate) { e.preventDefault(); onActivate(row); }
        break;
      case 'ArrowDown': e.preventDefault(); moveFocus(e.currentTarget, 1); break;
      case 'ArrowUp':   e.preventDefault(); moveFocus(e.currentTarget, -1); break;
      case 'Home':      e.preventDefault(); moveFocus(e.currentTarget, 'first'); break;
      case 'End':       e.preventDefault(); moveFocus(e.currentTarget, 'last'); break;
      default: break;
    }
  }, [moveFocus, onActivate]);

  const interactive = !!onActivate;

  // Exactly one of the three non-row states, in priority order. A failed fetch
  // outranks an empty result, because "we could not ask" and "the answer is
  // nothing" mean very different things to someone watching for threats.
  const state =
    error   ? 'error'   :
    loading ? 'loading' :
    rows.length === 0 ? 'empty' : undefined;

  return (
    <div ref={rootRef} className="cs-dt" data-density={density} data-state={state} style={trackVars}>
      <div className="cs-dt-scroll">
        <div className="cs-dt-track" role="table" aria-label={label} aria-rowcount={rows.length}>

          <div className="cs-dt-head" role="rowgroup">
            <div className="cs-dt-row" role="row">
              {columns.map(col => (
                <div
                  key={col.id}
                  role="columnheader"
                  className={`cs-dt-cell cs-dt-col-head ${hideClass(col)}`}
                  data-align={col.align ?? 'start'}
                >
                  {col.header}
                </div>
              ))}
            </div>
          </div>

          <div className="cs-dt-body" role="rowgroup" ref={bodyRef}>
            {state === undefined && (
              rows.map((row, index) => {
                const key    = rowKey(row);
                const sev    = severity?.(row);
                const detail = renderDetail?.(row);
                // One tab stop for the whole list: the row the user last
                // touched, or the first row if they have not touched one yet.
                const tabbable = focusedKey != null ? key === focusedKey : index === 0;
                return (
                  <React.Fragment key={key}>
                    <div
                      data-dt-row
                      role="row"
                      className="cs-dt-row"
                      data-severity={sev}
                      data-muted={muted?.(row) ? 'true' : undefined}
                      data-interactive={interactive ? 'true' : undefined}
                      tabIndex={interactive ? (tabbable ? 0 : -1) : undefined}
                      onFocus={interactive ? () => setFocusedKey(key) : undefined}
                      onClick={onActivate ? () => onActivate(row) : undefined}
                      onKeyDown={interactive ? e => onRowKeyDown(e, row) : undefined}
                    >
                      {columns.map(col => (
                        <div
                          key={col.id}
                          role="cell"
                          className={`cs-dt-cell ${hideClass(col)}`}
                          data-align={col.align ?? 'start'}
                          data-mono={col.mono ? 'true' : undefined}
                        >
                          {col.cell(row)}
                        </div>
                      ))}
                    </div>
                    {detail && (
                      // Spans the full width, and continues the row's spine so
                      // the vertical line stays unbroken down the list.
                      <div className="cs-dt-detail" role="row" data-severity={sev}>
                        <div role="cell">{detail}</div>
                      </div>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </div>

        </div>
      </div>

      {state && (
        <div className="cs-dt-state">
          {state === 'error'   && error}
          {state === 'loading' && <TableSkeleton columns={Math.min(columns.length, 5)} rowHeight={`var(--cs-dt-row-h)`} />}
          {state === 'empty'   && empty}
        </div>
      )}
    </div>
  );
}
