/**
 * Shared data-surface primitives.
 *
 * Everything a data-heavy tab needs to look like the rest of the dashboard:
 * the dense table shell, the severity vocabulary, the density control and the
 * empty / loading / error states. Import from here rather than from the
 * individual files, so a tab has one line of dependency on the design system.
 *
 * The alert log is the reference implementation — see `src/AlertsTab.tsx`.
 */
export { DataTable } from './DataTable';
export type { DataColumn, DataTableProps, ColumnTier } from './DataTable';

export { RowDensityToggle, useRowDensity } from './RowDensity';
export type { RowDensity } from './RowDensity';

export {
  SeverityBadge,
  SeveritySpine,
  SEVERITY_META,
  SEVERITY_ORDER,
  severityMark,
  severityText,
  severityRank,
  normalizeSeverity,
} from './severity';

export { EmptyState, ErrorState, TableSkeleton } from './states';

export { Toolbar, ToolButton, ToolbarTitle, ToolSearch } from './toolbar';
