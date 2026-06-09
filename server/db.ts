import Database from 'better-sqlite3';
import fs from 'fs';

// ---------------------------------------------------------------------------
// SQLite setup
// ---------------------------------------------------------------------------

// DB path is configurable via CLAUDESEC_DB so test/throwaway server instances
// can point at an isolated database and NEVER touch the live spans.db.
export const DB_PATH = process.env.CLAUDESEC_DB ?? 'spans.db';
export const db = new Database(DB_PATH);

// SECURITY: WAL mode allows concurrent reads during writes — prevents blocking under load
db.pragma('journal_mode = WAL');

for (const dbFile of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
  try { fs.chmodSync(dbFile, 0o600); } catch {}
}

db.exec(`
  CREATE TABLE IF NOT EXISTS spans (
    spanId     TEXT PRIMARY KEY,
    traceId    TEXT NOT NULL DEFAULT 'unknown',
    parentId   TEXT NOT NULL,
    name       TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'none',
    harness    TEXT NOT NULL DEFAULT 'unknown',
    attributes TEXT NOT NULL DEFAULT '{}',
    startNano  TEXT NOT NULL DEFAULT '0',
    endNano    TEXT NOT NULL DEFAULT '0'
  );
`);

// Safe schema migrations for existing databases
try { db.exec(`ALTER TABLE spans ADD COLUMN traceId TEXT NOT NULL DEFAULT 'unknown'`); } catch {}
try { db.exec(`ALTER TABLE spans ADD COLUMN harness TEXT NOT NULL DEFAULT 'unknown'`); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    traceId   TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    pinned    INTEGER NOT NULL DEFAULT 0
  );
`);
// Safe migrations for existing databases
try { db.exec(`ALTER TABLE sessions ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN label TEXT NOT NULL DEFAULT 'normal'`); } catch {}
try { db.exec(`ALTER TABLE sessions ADD COLUMN notes TEXT NOT NULL DEFAULT ''`); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS watch_offsets (
    path      TEXT PRIMARY KEY,
    offset    INTEGER NOT NULL DEFAULT 0,
    updatedAt TEXT NOT NULL DEFAULT ''
  );
`);

// Query accelerators — covers the hot-path reads (session filter, severity
// dashboards, per-harness aggregation).  Safe to add on existing DBs.
for (const stmt of [
  `CREATE INDEX IF NOT EXISTS idx_spans_traceId_startNano ON spans(traceId, startNano)`,
  `CREATE INDEX IF NOT EXISTS idx_spans_severity          ON spans(severity)`,
  `CREATE INDEX IF NOT EXISTS idx_spans_harness           ON spans(harness)`,
  // Time-ordered reads (recent-N graph window, time-range search) sort/filter
  // on startNano/endNano; these let SQLite use an index instead of a full scan.
  `CREATE INDEX IF NOT EXISTS idx_spans_startNano         ON spans(startNano)`,
  `CREATE INDEX IF NOT EXISTS idx_spans_endNano           ON spans(endNano)`,
  // Per-harness and per-session threat rollups (orchestration, metrics, cost)
  // GROUP BY on these pairs and filter severity; the composite indexes let
  // SQLite satisfy the aggregation from the index alone.
  `CREATE INDEX IF NOT EXISTS idx_spans_harness_severity  ON spans(harness, severity)`,
  `CREATE INDEX IF NOT EXISTS idx_spans_traceId_severity  ON spans(traceId, severity)`,
  `CREATE INDEX IF NOT EXISTS idx_alerts_traceId          ON alerts(traceId)`,
  `CREATE INDEX IF NOT EXISTS idx_alerts_dismissed_ts     ON alerts(dismissed, ts)`,
]) {
  try { db.prepare(stmt).run(); } catch {}
}

// ---------------------------------------------------------------------------
// Alerts table
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    ruleLabel   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    spanId      TEXT NOT NULL,
    traceId     TEXT NOT NULL,
    harness     TEXT NOT NULL DEFAULT 'unknown',
    spanName    TEXT NOT NULL,
    matchedText TEXT NOT NULL DEFAULT ''
  );
`);

// Safe migrations for alert triage columns (Phase 14) and deduplication (Phase 15 / s66)
try { db.exec(`ALTER TABLE alerts ADD COLUMN dismissed    INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE alerts ADD COLUMN fp           INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE alerts ADD COLUMN fingerprint  TEXT    NOT NULL DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE alerts ADD COLUMN count        INTEGER NOT NULL DEFAULT 1`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, ts)`); } catch {}

// ---------------------------------------------------------------------------
// Span bookmarks table (Phase 15 / s67)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS span_bookmarks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    spanId    TEXT NOT NULL,
    traceId   TEXT NOT NULL DEFAULT '',
    note      TEXT NOT NULL DEFAULT '',
    createdAt TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_bookmarks_spanId  ON span_bookmarks(spanId);
  CREATE INDEX IF NOT EXISTS idx_bookmarks_traceId ON span_bookmarks(traceId);
`);

// ---------------------------------------------------------------------------
// Suppressions table — snooze a security rule until suppressUntil (Phase 14)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS suppressions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ruleKey       TEXT NOT NULL,
    suppressUntil TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    createdAt     TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_suppressions_ruleKey ON suppressions(ruleKey);
`);

// ---------------------------------------------------------------------------
// Span tags table — custom labels on spans (Phase 14)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS span_tags (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    spanId    TEXT NOT NULL,
    tag       TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    UNIQUE (spanId, tag)
  );
  CREATE INDEX IF NOT EXISTS idx_span_tags_spanId ON span_tags(spanId);
  CREATE INDEX IF NOT EXISTS idx_span_tags_tag    ON span_tags(tag);
`);

// ---------------------------------------------------------------------------
// Threshold alert rules — numeric trigger conditions
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS threshold_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    metric     TEXT NOT NULL,
    operator   TEXT NOT NULL,
    value      REAL NOT NULL,
    window_min INTEGER NOT NULL DEFAULT 60,
    enabled    INTEGER NOT NULL DEFAULT 1,
    createdAt  TEXT NOT NULL
  );
`);

// ---------------------------------------------------------------------------
// Annotations table — user investigation notes on spans
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS annotations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    spanId    TEXT NOT NULL,
    text      TEXT NOT NULL,
    author    TEXT NOT NULL DEFAULT 'analyst',
    createdAt TEXT NOT NULL
  );
`);
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_annotations_spanId ON annotations(spanId)`); } catch {}

// ---------------------------------------------------------------------------
// FTS5 full-text search — spans_fts mirrors spans(name, attributes)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE VIRTUAL TABLE IF NOT EXISTS spans_fts USING fts5(
    spanId    UNINDEXED,
    name,
    attributes,
    tokenize  = 'unicode61 remove_diacritics 1'
  );
  CREATE TRIGGER IF NOT EXISTS spans_fts_insert AFTER INSERT ON spans BEGIN
    INSERT OR IGNORE INTO spans_fts(spanId, name, attributes)
    VALUES (new.spanId, new.name, new.attributes);
  END;
`);

// ---------------------------------------------------------------------------
// Webhook delivery log — tracks every attempt with retry support
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ruleLabel     TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'low',
    urlPreview    TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    httpCode      INTEGER,
    latencyMs     INTEGER,
    error         TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0,
    createdAt     TEXT NOT NULL,
    lastAttemptAt TEXT
  );
`);

// ---------------------------------------------------------------------------
// Config table (webhook URL, thresholds, etc.)
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// ---------------------------------------------------------------------------
// Operator audit log — an append-only record of every config-mutating action
// (who changed what, when). Read-only over the API; there is deliberately no
// delete endpoint — an audit log that can be cleared from the UI is not an
// audit log. Growth is bounded by pruning the oldest rows on insert past a cap
// (see server/auditLog.ts), so it can never grow without limit on a long-lived
// install. The `detail` column is scrubbed before insert so secrets that pass
// through a config payload never land here.
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS operator_audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    actor    TEXT NOT NULL DEFAULT 'local',
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT '{}',
    sourceIp TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_operator_audit_log_ts ON operator_audit_log(ts);
`);

// ---------------------------------------------------------------------------
// Per-rule enable/disable overrides — lets an operator permanently silence a
// noisy built-in or custom rule (distinct from a time-boxed suppression).
// Only the enable/disable flag is persisted; severity is not overridable here.
// The catastrophic-floor rules can never be disabled — that constraint is
// enforced in the API + detection path, not the schema.
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS rule_overrides (
    ruleLabel TEXT PRIMARY KEY,
    enabled   INTEGER NOT NULL DEFAULT 1,
    updatedTs INTEGER NOT NULL
  );
`);
