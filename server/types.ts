import type { Severity } from '../src/shared/types.js';

/**
 * A raw span row as stored in the `spans` SQLite table.
 *
 * This mirrors the columns the analytics/export/search route modules read off a
 * `SELECT * FROM spans` (or `SELECT s.* ...`) result. It is the single source of
 * truth for that row shape — keep it in sync with the `spans` table schema.
 */
export interface SpanRecord {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: Severity;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
}
