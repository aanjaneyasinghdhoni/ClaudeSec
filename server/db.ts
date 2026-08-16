import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import {
  adoptChainBaseline, anchorIsSigned, auditKeyId, canonicalString, computeRowHash,
  flushChainAnchors, getChainAnchor, isAuditSigned, recordChainSegment,
  registerChainProbe, type ChainProbe, type ChainProbeReading,
} from './auditChain.js';

// ---------------------------------------------------------------------------
// SQLite setup
// ---------------------------------------------------------------------------

// DB path is configurable via CLAUDESEC_DB so test/throwaway server instances
// can point at an isolated database and NEVER touch the live database. The
// default lives under ~/.claudesec so the file lands in a predictable, owner-only
// home directory rather than wherever the process happened to start.
export const DEFAULT_DB_PATH = path.join(os.homedir(), '.claudesec', 'spans.db');

export const DB_PATH = process.env.CLAUDESEC_DB ?? DEFAULT_DB_PATH;

// Make sure the parent directory exists before better-sqlite3 tries to open the
// file — otherwise the first boot in a fresh ~/.claudesec would throw.
try { fs.mkdirSync(path.dirname(DB_PATH), { recursive: true }); } catch {}

// ---------------------------------------------------------------------------
// One-time move from the pre-2.0 database location
// ---------------------------------------------------------------------------
//
// Up to and including 1.3.0 the default was the bare string 'spans.db', which
// SQLite resolved against the PROCESS WORKING DIRECTORY — in practice the repo
// checkout the user started the server from. 2.0.0 resolves it to an absolute
// ~/.claudesec/spans.db instead, and the rename migration that used to bridge a
// path change was dropped along the way. The result for an upgrading 1.3.0 user
// is a dashboard reporting zero spans, zero sessions and zero alerts, with
// nothing on screen to say that their history is still on disk one directory
// away. For a tool whose headline claim is an immutable record, "looks like we
// wiped your data" is the worst possible upgrade experience.
//
// WHY MOVE RATHER THAN JUST WARN. A warning in a log file is not seen by the
// person staring at an empty dashboard, and the manual fix ("move this file
// there, but only if the other one doesn't exist, and bring the -wal along")
// is exactly the kind of instruction that gets half-followed on the one copy of
// a security ledger. The move is a single atomic rename of a file we have
// already proved is an unused SQLite database, which is strictly less risky
// than talking a user through doing it by hand.
//
// WHY MOVE RATHER THAN COPY. A copy leaves the original as a safety net, but it
// doubles the space for a file that is routinely hundreds of megabytes (the
// maintainer's own is 700 MB), and it leaves two databases with the same name
// and diverging contents — the next person to go looking has no way to tell
// which one the server is actually writing to. A rename never has an
// intermediate state where the data exists in neither place or in both.
//
// THE HASH CHAIN IS THE CONSTRAINT. The database carries a tamper-evident chain
// over span content, so the migration must not rewrite a single byte of any
// span. A rename moves a directory entry and touches no page of the file. The
// one write we do make is a WAL checkpoint (below), which relocates already-
// committed pages into the main file — a routine SQLite operation that changes
// no column of any row, and therefore no hash. Nothing here reads, re-encodes
// or re-hashes span data.
//
// SAFETY RULES, all of which the decision table in tests/legacyDbMigrationTest.ts
// pins down:
//   • Only for the DEFAULT path. If CLAUDESEC_DB is set the operator has chosen
//     where the database lives and we do not second-guess them.
//   • Never overwrite. If the new location already holds a database we stop,
//     and say so once, rather than touching either file.
//   • Only a real SQLite file. The legacy candidate must carry SQLite's magic
//     header, so an empty placeholder or some unrelated file that happens to be
//     called spans.db is left alone.
//   • Only an idle database. We take the write lock and checkpoint before
//     moving; if another process (an old 1.3.0 server still running) holds it,
//     we abort rather than move a live database out from under it.
//   • One file, one atomic step. The checkpoint folds the -wal into the main
//     file so the whole database IS one file at the moment of the rename. There
//     is no window in which the .db has moved and its -wal has not — the failure
//     mode that makes a multi-file move unsafe. An interruption before the
//     rename leaves the legacy database untouched and the next boot retries; an
//     interruption after it leaves the new location populated and the next boot
//     is a no-op.
//   • Idempotent, and silent on a fresh install: with no legacy file there is
//     nothing to do, and once the move has happened the target-exists guard
//     ends every subsequent boot immediately.

/** `SQLite format 3\0` — the first 16 bytes of every SQLite database file. */
const SQLITE_MAGIC = Buffer.from('SQLite format 3\u0000', 'latin1');

export interface LegacyDbMigration {
  /** What we did: nothing, an atomic rename, or a copy (cross-filesystem only). */
  action: 'none' | 'moved' | 'copied';
  /** Machine-readable why, so the test can assert the decision and not the prose. */
  reason:
    | 'pinned'          // CLAUDESEC_DB is set — operator's choice, hands off
    | 'target-exists'   // a database is already at the new location
    | 'no-legacy'       // fresh install, or already migrated and cleaned up
    | 'same-file'       // legacy path and target path are the same file
    | 'not-sqlite'      // candidate exists but is not a SQLite database
    | 'busy'            // in use elsewhere, unopenable, or its -wal would not drain
    | 'failed'          // the move itself failed; legacy left untouched
    | 'ok';
  from?: string;
  to?: string;
  /** Human-facing line, already logged by the caller that ran the migration. */
  message?: string;
}

/**
 * Legacy database locations to look in, most likely first.
 *
 * 1.3.0 resolved 'spans.db' against the process working directory, so that is
 * the primary candidate. The repo root is checked as well, because a user who
 * started the server from a subdirectory (or through a wrapper that changed
 * directory) would have left the file next to the checkout instead.
 */
export function legacyDbCandidates(cwd: string = process.cwd()): string[] {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const seen = new Set<string>();
  const out: string[] = [];
  for (const dir of [cwd, repoRoot]) {
    const candidate = path.resolve(dir, 'spans.db');
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    out.push(candidate);
  }
  return out;
}

/** True when the file starts with SQLite's magic header. */
function looksLikeSqlite(file: string): boolean {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(SQLITE_MAGIC.length);
    const read = fs.readSync(fd, head, 0, head.length, 0);
    return read === head.length && head.equals(SQLITE_MAGIC);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
  }
}

/**
 * Fold the -wal back into the main file and prove nothing else is using it.
 *
 * `BEGIN IMMEDIATE` takes the write lock: if an old server is still running
 * against this database it fails here, which is precisely when we must NOT
 * move the file. The TRUNCATE checkpoint then leaves the database as a single
 * self-contained file so the rename below can be one atomic step.
 *
 * Returns false if the database could not be opened, locked or drained.
 */
function drainLegacyWal(file: string): boolean {
  let handle: Database.Database | undefined;
  try {
    handle = new Database(file);
    handle.pragma('busy_timeout = 2000');
    handle.exec('BEGIN IMMEDIATE');
    handle.exec('ROLLBACK');
    handle.pragma('wal_checkpoint(TRUNCATE)');
    handle.close();
    handle = undefined;
  } catch {
    if (handle) { try { handle.close(); } catch {} }
    return false;
  }
  // A clean close removes the sidecars outright; a TRUNCATE checkpoint leaves a
  // zero-length -wal at worst. Anything else — including a rollback journal left
  // by a database that was never in WAL mode — means committed pages are still
  // outside the main file and a single-file move would silently lose them.
  for (const sidecar of [`${file}-wal`, `${file}-journal`]) {
    try {
      if (fs.statSync(sidecar).size > 0) return false;
    } catch { /* absent is the expected, best case */ }
  }
  return true;
}

/** Delete a sidecar only when it is empty — it then holds nothing to lose. */
function dropEmptySidecar(file: string): void {
  try {
    if (fs.statSync(file).size === 0) fs.rmSync(file, { force: true });
  } catch {}
}

/**
 * Move a pre-2.0 database into the current default location, once.
 *
 * Pure with respect to its inputs so the decision table can be tested without
 * environment variables; the module-level call below supplies the real ones.
 * Never throws — a migration failure must degrade to "start with an empty
 * database and say why", never to a server that will not boot.
 */
export function migrateLegacyDbLocation(opts: {
  targetPath: string;
  /** True when CLAUDESEC_DB was set explicitly. */
  pinned: boolean;
  candidates: string[];
  log?: (message: string) => void;
}): LegacyDbMigration {
  const log = opts.log ?? (() => {});
  const target = path.resolve(opts.targetPath);

  const done = (result: LegacyDbMigration): LegacyDbMigration => {
    if (result.message) log(result.message);
    return result;
  };

  if (opts.pinned) return { action: 'none', reason: 'pinned' };

  const legacy = opts.candidates
    .map(candidate => path.resolve(candidate))
    .find(candidate => candidate !== target && fs.existsSync(candidate));

  if (legacy === undefined) return { action: 'none', reason: 'no-legacy' };

  if (fs.existsSync(target)) {
    // Two names for one file (a symlink, or the same directory reached twice).
    // Nothing to move, and nothing worth warning about.
    let sameFile = false;
    try { sameFile = fs.realpathSync(legacy) === fs.realpathSync(target); } catch {}
    if (sameFile) return { action: 'none', reason: 'same-file', from: legacy, to: target };

    return done({
      action: 'none',
      reason: 'target-exists',
      from: legacy,
      to: target,
      message:
        `[db] A pre-2.0 database is still at ${legacy}. ${target} already exists, so nothing was ` +
        `moved — the server is using ${target}. If the older file is the history you want, stop ` +
        `the server, move ${target} aside, and restart.`,
    });
  }

  if (!looksLikeSqlite(legacy)) {
    // A zero-byte spans.db is the usual cause (a placeholder, or a database that
    // was created and never written) and warning about it every boot would be
    // noise. Anything with content is a file we are declining to move, which the
    // person looking at an empty dashboard deserves to hear about.
    let size = 0;
    try { size = fs.statSync(legacy).size; } catch {}
    return size === 0
      ? { action: 'none', reason: 'not-sqlite', from: legacy, to: target }
      : done({
          action: 'none',
          reason: 'not-sqlite',
          from: legacy,
          to: target,
          message:
            `[db] ${legacy} is not a SQLite database, so it was left alone. If that is your ` +
            `pre-2.0 history it is damaged; restore it from a backup and move it to ${target}.`,
        });
  }

  if (!drainLegacyWal(legacy)) {
    return done({
      action: 'none',
      reason: 'busy',
      from: legacy,
      to: target,
      message:
        `[db] Found a pre-2.0 database at ${legacy} but could not take its write lock — another ` +
        `ClaudeSec process is probably still running against it. Stop it and restart to migrate; ` +
        `until then this server records into ${target}.`,
    });
  }

  try { fs.mkdirSync(path.dirname(target), { recursive: true }); } catch {}

  try {
    // The whole migration, in one atomic filesystem operation.
    fs.renameSync(legacy, target);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EXDEV') {
      return done({
        action: 'none',
        reason: 'failed',
        from: legacy,
        to: target,
        message:
          `[db] Could not move the pre-2.0 database from ${legacy} to ${target} ` +
          `(${(err as Error).message}). Nothing was changed — your data is still at ${legacy}. ` +
          `Move it by hand, or set CLAUDESEC_DB=${legacy} to keep using it where it is.`,
      });
    }
    // Cross-filesystem: rename(2) cannot span devices, so copy into a temp file
    // ON THE TARGET filesystem and rename that into place — the rename is still
    // atomic, and a crash mid-copy leaves only a temp file nothing ever opens.
    // The original is deliberately LEFT BEHIND: we cannot make "copy succeeded"
    // and "original removed" a single step across devices, and of the two ways
    // to be wrong, wasting disk beats deleting the only copy.
    const staging = `${target}.migrating`;
    try {
      fs.rmSync(staging, { force: true });
      fs.copyFileSync(legacy, staging);
      try { fs.chmodSync(staging, 0o600); } catch {}
      // Force the bytes out before the rename publishes the name, so a power
      // loss cannot leave a complete directory entry pointing at a partial file.
      const fd = fs.openSync(staging, 'r+');
      try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      fs.renameSync(staging, target);
    } catch (copyErr) {
      try { fs.rmSync(staging, { force: true }); } catch {}
      return done({
        action: 'none',
        reason: 'failed',
        from: legacy,
        to: target,
        message:
          `[db] Could not copy the pre-2.0 database from ${legacy} to ${target} ` +
          `(${(copyErr as Error).message}). Nothing was changed — your data is still at ${legacy}.`,
      });
    }
    try { fs.chmodSync(target, 0o600); } catch {}
    return done({
      action: 'copied',
      reason: 'ok',
      from: legacy,
      to: target,
      message:
        `[db] Copied your pre-2.0 database from ${legacy} to ${target} (the two are on different ` +
        `filesystems, so it could not be moved). The original was left in place and can be ` +
        `deleted once you have confirmed your history is back.`,
    });
  }

  try { fs.chmodSync(target, 0o600); } catch {}
  // All three are zero-length or absent by now — drainLegacyWal() guaranteed it
  // for -wal/-journal, and -shm is a pure shared-memory index SQLite rebuilds on
  // demand. Clearing them stops a future ./spans.db from inheriting stale ones.
  dropEmptySidecar(`${legacy}-wal`);
  dropEmptySidecar(`${legacy}-shm`);
  dropEmptySidecar(`${legacy}-journal`);

  return done({
    action: 'moved',
    reason: 'ok',
    from: legacy,
    to: target,
    message:
      `[db] Moved your existing database from ${legacy} to ${target}. ClaudeSec 2.0 stores it ` +
      `under your home directory instead of the working directory, so it no longer depends on ` +
      `where the server was started from. Your spans, sessions and alerts are unchanged.`,
  });
}

migrateLegacyDbLocation({
  targetPath: DB_PATH,
  pinned: process.env.CLAUDESEC_DB !== undefined,
  candidates: legacyDbCandidates(),
  log: message => console.warn(message),
});

export const db = new Database(DB_PATH);

// SECURITY: WAL mode allows concurrent reads during writes — prevents blocking under load
db.pragma('journal_mode = WAL');
// Under WAL a second writer can still collide with an in-flight write. busy_timeout
// makes the loser WAIT (up to 5s) for the lock to clear instead of throwing
// SQLITE_BUSY immediately — the transcript watcher, OTLP ingest, and retention
// sweep all write, so a momentary contention should retry, not surface an error.
db.pragma('busy_timeout = 5000');

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
try { db.prepare(`ALTER TABLE spans ADD COLUMN traceId TEXT NOT NULL DEFAULT 'unknown'`).run(); } catch {}
try { db.prepare(`ALTER TABLE spans ADD COLUMN harness TEXT NOT NULL DEFAULT 'unknown'`).run(); } catch {}
// Per-repository identity (Per-Repository Dashboard). Defaults to 'unknown' so
// existing rows stay valid immediately; a startup backfill fills in the real
// repo for rows whose attributes carry a cwd. Additive + idempotent, same as
// the columns above.
try { db.prepare(`ALTER TABLE spans ADD COLUMN repo TEXT NOT NULL DEFAULT 'unknown'`).run(); } catch {}

// Hash-chain columns for the spans ledger. `chainSeq` is the position in the
// chain — a counter of our own rather than the rowid, so the chain survives
// SQLite reusing rowids after a VACUUM. Nullable, because every row that
// predates the chain legitimately has no position until the backfill gives it
// one. See the "Spans hash chain" section below for the full design.
try { db.prepare(`ALTER TABLE spans ADD COLUMN chainSeq INTEGER`).run(); } catch {}
try { db.prepare(`ALTER TABLE spans ADD COLUMN prevHash TEXT NOT NULL DEFAULT ''`).run(); } catch {}
try { db.prepare(`ALTER TABLE spans ADD COLUMN rowHash  TEXT NOT NULL DEFAULT ''`).run(); } catch {}

// Identity columns, deliberately added now and left unpopulated.
//
// AIUC-1 E.15 wants execution chains that show "tool calls, sub-agent
// delegations, authorization events". We record the tool calls today; the
// delegation and authorization halves need fields that only mean anything if
// they were captured AT THE TIME. A column added in 2030 can be filled in from
// 2030 onward and never for anything before it — an un-backfillable gap exactly
// where the liability questions land. Adding three nullable columns costs
// nothing today (SQLite's ALTER TABLE ADD COLUMN is O(1) and NULLs occupy no
// row space) and keeps the option open.
//
//   principal      — the human or service account on whose authority the agent
//                    acted. NOT the agent: the OpenID Foundation's position on
//                    AI-agent identity is that identity alone is insufficient —
//                    it has to be bound to the specific action taken, which is
//                    why these live on the span and not in a side table.
//   agent_identity — the acting agent's own credential/identity.
//   delegation_id  — reference to the delegation that authorized this action,
//                    so a sub-agent's span can be traced to the grant that let
//                    it run.
//
// All three are inside the chain's canonical field order from day one, so
// whenever they do start being populated they are covered by the same integrity
// guarantee as everything else — no second migration, no re-hashing.
try { db.prepare(`ALTER TABLE spans ADD COLUMN principal      TEXT`).run(); } catch {}
try { db.prepare(`ALTER TABLE spans ADD COLUMN agent_identity TEXT`).run(); } catch {}
try { db.prepare(`ALTER TABLE spans ADD COLUMN delegation_id  TEXT`).run(); } catch {}

// ---------------------------------------------------------------------------
// Stored-content cap
// ---------------------------------------------------------------------------
// A `Write` span carries the entire file the agent just wrote. Measured on a real
// 265k-span database that is 9.2 KB per Write span on average and 148 KB at the
// tail — 34 MB of file bodies for 3,816 spans, and the full-text index has to
// tokenize every byte of it. The database is a security ledger, not a copy of
// the working tree, so a single attribute value gets a ceiling.
//
// 4 KiB, because that is where the cost stops buying anything. Across 1.95M
// stored attribute values only 3,417 (0.18%) exceed it, and capping there sheds
// ~22 MB of stored text plus the index terms that text generates — while 4 KiB
// still holds roughly sixty lines of code, enough to see what an agent actually
// did when reviewing a span by hand.
//
// This CANNOT weaken detection. ingestSpan() runs detectSeverity() over the raw,
// uncapped attributes and records the verdict (plus the matched evidence, which
// lands in the `alerts` table) BEFORE anything is written; the cap applies only
// to the copy being persisted. Truncation is marked inline so a reader is never
// misled into thinking a file was shorter than it was.
export const SPAN_VALUE_CAP_BYTES = (() => {
  const n = parseInt(String(process.env.CLAUDESEC_MAX_ATTR_BYTES ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : 4096;
})();

/**
 * Cap every string value in a span's attributes at SPAN_VALUE_CAP_BYTES.
 *
 * Returns a new object; the caller's attributes are left intact, so anything
 * still working from the pre-persistence copy (detection, alerting, the webhook
 * payload) sees the full text.
 */
export function capSpanAttributes(
  attrs: Record<string, unknown>,
  cap: number = SPAN_VALUE_CAP_BYTES,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === 'string' && value.length > cap) {
      const dropped = value.length - cap;
      // slice() splits by UTF-16 code unit, which can cut a surrogate pair in
      // half and leave a lone surrogate that JSON.stringify happily stores and
      // some consumers choke on. Trimming the orphan is cheaper than measuring
      // real byte lengths, and the cap is approximate by nature.
      let kept = value.slice(0, cap);
      const last = kept.charCodeAt(kept.length - 1);
      if (last >= 0xd800 && last <= 0xdbff) kept = kept.slice(0, -1);
      out[key] = `${kept}\n… [ClaudeSec truncated ${dropped} characters — detection ran on the full value]`;
    } else {
      out[key] = value;
    }
  }
  return out;
}

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
// dashboards, per-harness aggregation). Safe to add on existing DBs.
//
// This set replaces six narrower single/composite indexes (traceId+startNano,
// severity, traceId+severity, repo, repo+severity, endNano) with four indexes
// shaped after the query, not the column. Re-verified on a real 271k-span
// database against every query in server/index.ts, server/routes/** (and
// server/sequenceRules.ts / server/governance.ts, which turned out to hold no
// direct SQL against `spans` — they consume rows already read elsewhere) that
// filters, joins or orders on `spans`: EXPLAIN QUERY PLAN plus timing,
// before and after, for all 29 query shapes found. Measured: harness search
// 439 ms → 0.03 ms, the DISTINCT repo/session rollup 138 ms → 24 ms, the repos
// rollup 370 ms → 274 ms, repoIdentity's backfill scan 123 ms → 16 ms.
//
// TWO of those 29 shapes regressed on the composite-only set the audit
// proposed, and both indexes below exist solely to undo that — this is the
// "don't take it on trust" checkpoint, not decoration:
//
//  • idx_spans_harness_severity (harness, severity) — /api/search's COUNT(*)
//    when a caller filters by harness AND severity together (no ORDER BY, so
//    nothing needs startNano) used to be a direct covering-index equality
//    seek: 0.02 ms. Point it at idx_spans_harness_start_sev instead — the
//    audit's proposed replacement — and startNano sitting between harness and
//    severity in the key means SQLite can only seek on harness and then has to
//    filter every one of that harness's rows for the severity match: 9.6 ms
//    on the busiest harness. Cheap fix (6.8 MB) for a query the Search tab
//    hits on every combined filter.
//
//  • idx_spans_harness (harness) is the OTHER exception, kept for the same
//    reason it was already here: `WHERE harness = ? ORDER BY rowid DESC LIMIT
//    n` (live-activity's model-lookback, server/routes/liveActivity.ts) reads
//    a single-column index's entries in rowid order for free. Fold startNano
//    into the key and SQLite has to materialize and sort the whole harness
//    (270k rows for the busiest one) before it can take the top 200 — 1 ms →
//    174 ms measured.
//
//  • idx_spans_traceId (traceId) — the anomaly sweep's tail read (`WHERE
//    traceId = ? ORDER BY rowid DESC LIMIT 10`, runs after every OTLP batch on
//    the live session) doesn't get to skip a sort either way — even the old
//    (traceId, severity) index needed one — but the FIVE-column idx_spans_trace
//    is wide enough per entry that the sort itself got 6x slower on this
//    install's largest session (21k spans): 1.2 ms → 8.9 ms. A bare
//    single-column index sidesteps the sort entirely, the same trick as
//    idx_spans_harness above: SQLite reads a (traceId) index's matching
//    entries in rowid order with no temp b-tree at all, landing at 0.003 ms —
//    faster than the original — for 12.3 MB.
//
// Net effect on this database: 108.95 MB of index pages before → 116.65 MB
// after (+7.1%). The four query-shaped composites remove more than they add
// on their own; the two exceptions above put some of it back, on purpose,
// because "smaller" was never the goal — "nothing gets slower" was, and
// these two are exactly where blindly trusting the audit's index list would
// have broken that.
for (const stmt of [
  `DROP INDEX IF EXISTS idx_spans_traceId_startNano`,
  `DROP INDEX IF EXISTS idx_spans_severity`,
  `DROP INDEX IF EXISTS idx_spans_endNano`,
  `DROP INDEX IF EXISTS idx_spans_traceId_severity`,
  `DROP INDEX IF EXISTS idx_spans_repo`,
  `DROP INDEX IF EXISTS idx_spans_repo_severity`,

  `CREATE INDEX IF NOT EXISTS idx_spans_harness           ON spans(harness)`,
  // Time-ordered reads (recent-N graph window, time-range search) sort/filter
  // on startNano; the graph window and orchestration's recent-spans read both
  // want this directly, and it stays cheaper than folding startNano into a
  // composite for a query that has no other filter column.
  `CREATE INDEX IF NOT EXISTS idx_spans_startNano         ON spans(startNano)`,
  // /api/live-activity's bounded per-harness "latest span" lookup (see
  // server/routes/liveActivity.ts) is WHERE harness = ? ORDER BY endNano DESC
  // LIMIT 1 — this composite answers it as a single index seek instead of the
  // GROUP BY MAX(endNano) full-index scan it replaced.
  `CREATE INDEX IF NOT EXISTS idx_spans_harness_endNano   ON spans(harness, endNano)`,
  // See the regression note above — restores the direct (harness, severity)
  // equality seek that /api/search's combined-filter COUNT(*) needs.
  `CREATE INDEX IF NOT EXISTS idx_spans_harness_severity  ON spans(harness, severity)`,
  // See the regression note above — gives the anomaly sweep's per-batch tail
  // read a sort-free path to "this trace's rows in rowid order".
  `CREATE INDEX IF NOT EXISTS idx_spans_traceId           ON spans(traceId)`,

  // Session detail, the anomaly sweep, retention-by-session, and repoIdentity
  // all filter on traceId and then either order by startNano or read severity/
  // harness/repo straight out of the row; one covering composite answers all of
  // them instead of the three separate (traceId,startNano) / (traceId,severity)
  // indexes it replaces.
  `CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(traceId, startNano, severity, harness, repo)`,
  // /api/search and /api/spans filter on severity alone and order by startNano;
  // the old single-column severity index answered the filter but forced a temp
  // b-tree sort for the ORDER BY on every call.
  `CREATE INDEX IF NOT EXISTS idx_spans_severity_startNano ON spans(severity, startNano)`,
  // Mirrors the severity composite for the harness-filtered shape of the same
  // search/spans queries (WHERE harness = ? [AND severity = ?] ORDER BY
  // startNano), which idx_spans_harness alone could not satisfy without a sort.
  `CREATE INDEX IF NOT EXISTS idx_spans_harness_start_sev ON spans(harness, startNano, severity)`,
  // Per-repository rollup (GROUP BY repo, severity breakdown, MIN/MAX startNano
  // for first/last seen) — replaces the separate repo and (repo, severity)
  // indexes with one that also covers the firstSeen/lastSeen aggregates.
  `CREATE INDEX IF NOT EXISTS idx_spans_repo_sev_start ON spans(repo, severity, startNano)`,

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
// Config table (webhook URL, thresholds, migration markers, …)
// ---------------------------------------------------------------------------
// Declared ahead of the FTS block because the schema migration below records its
// progress here; a marker table that only exists further down the file would
// force the migration to guess whether it had already run.

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const readConfig  = db.prepare(`SELECT value FROM config WHERE key = ?`);
const writeConfig = db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`);
const dropConfig  = db.prepare(`DELETE FROM config WHERE key = ?`);

const getMarker = (key: string): string | undefined =>
  (readConfig.get(key) as { value: string } | undefined)?.value;

// ---------------------------------------------------------------------------
// FTS5 full-text search — spans_fts indexes spans(name, attributes)
// ---------------------------------------------------------------------------
// spans_fts is an EXTERNAL-CONTENT index (`content='spans'`). Without that
// clause FTS5 keeps its own verbatim copy of every value it is handed, in a
// shadow table named spans_fts_content — a second complete copy of the name and
// attributes of every span. On a real 265k-span database that copy was 176 MB
// against 240 MB of actual span data, and it grew in lockstep forever.
//
// Pointing FTS5 at `spans` as its content source deletes that duplication at the
// root: the index stores terms and postings only, and reads column values back
// out of `spans` by rowid when a query asks for them. `content_rowid='rowid'`
// names the join key, which is why every index row must be pinned to the rowid
// of the span it describes.
//
// The `spanId` column is retained (UNINDEXED, so it costs no index terms) purely
// so `SELECT spanId FROM spans_fts WHERE spans_fts MATCH ?` keeps working — with
// external content that value is fetched straight from `spans`.
const FTS_CREATE_SQL = `
  CREATE VIRTUAL TABLE spans_fts USING fts5(
    spanId        UNINDEXED,
    name,
    attributes,
    content       = 'spans',
    content_rowid = 'rowid',
    tokenize      = 'unicode61 remove_diacritics 1'
  );
`;

/** True when spans_fts is already declared against `spans` as external content. */
function ftsIsExternalContent(): boolean {
  const row = db.prepare(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'spans_fts'`,
  ).get() as { sql: string | null } | undefined;
  return row?.sql != null && /content\s*=\s*'spans'/i.test(row.sql);
}

const ftsTableExists = db.prepare(
  `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'spans_fts'`,
).get() !== undefined;

// Markers for the one-time conversion of an existing (own-content) index.
// `ceiling` freezes the highest span rowid that existed the moment the index was
// recreated, and `cursor` records how far the backfill has walked toward it.
// Keeping both in `config` is what makes the migration resumable: a process that
// dies halfway through picks up at the cursor instead of starting over, and a
// process that finishes writes the completion marker so it never runs again.
const FTS_MIGRATION_KEY = 'fts.external_content_v1';
const FTS_CEILING_KEY   = 'fts.external_content_v1.ceiling';
const FTS_CURSOR_KEY    = 'fts.external_content_v1.cursor';

/**
 * Recreate spans_fts as an external-content index and arm the backfill.
 *
 * The whole thing runs in ONE transaction, on purpose. Between dropping the old
 * table and snapshotting the ceiling there must be no window in which another
 * writer can insert a span: the insert trigger would fire against a table that
 * does not exist, and a span that landed after the drop but before the snapshot
 * would be missed by both the trigger and the backfill. Holding the write lock
 * for the swap makes a competing writer wait out its busy_timeout instead.
 */
function convertFtsToExternalContent(): void {
  db.transaction(() => {
    db.exec(`DROP TABLE IF EXISTS spans_fts`);
    db.exec(FTS_CREATE_SQL);
    const ceiling = (db.prepare(`SELECT COALESCE(MAX(rowid), 0) AS m FROM spans`).get() as { m: number }).m;
    writeConfig.run(FTS_CEILING_KEY, String(ceiling));
    writeConfig.run(FTS_CURSOR_KEY, '0');
    dropConfig.run(FTS_MIGRATION_KEY);
  })();
}

// The conversion happens at module load, synchronously, and deliberately so: the
// trigger set below speaks the external-content dialect ('delete' command rows),
// which a plain FTS5 table rejects. If the swap were deferred to the async
// backfill, every span DELETE in the interim would throw.
if (!ftsTableExists) {
  db.exec(FTS_CREATE_SQL);
  // A brand-new index over a brand-new (or already-consistent) table has nothing
  // to backfill, but the markers still have to be armed so reindexFtsMirror()
  // walks whatever rows are already in `spans`.
  const ceiling = (db.prepare(`SELECT COALESCE(MAX(rowid), 0) AS m FROM spans`).get() as { m: number }).m;
  writeConfig.run(FTS_CEILING_KEY, String(ceiling));
  writeConfig.run(FTS_CURSOR_KEY, '0');
  dropConfig.run(FTS_MIGRATION_KEY);
} else if (!ftsIsExternalContent()) {
  convertFtsToExternalContent();
}

// Trigger set for an external-content index. All three are required, and the
// shape of each is dictated by how FTS5 maintains its postings:
//
//  • INSERT — a plain insert pinned to new.rowid. This is the only trigger a
//    self-contained index needed, and it stays the same.
//  • DELETE — must be an `INSERT … VALUES('delete', …)` COMMAND row carrying the
//    OLD column values, not `DELETE FROM spans_fts`. An external-content index
//    cannot look up what it is removing (the span row is already gone by the
//    time an AFTER DELETE trigger runs), so it has to be handed the exact text
//    whose terms it must decrement. Retention correctness rides on this: get it
//    wrong and pruned spans stay searchable, or the index goes inconsistent.
//  • UPDATE — a 'delete' of the old values FOLLOWED BY an insert of the new
//    ones. There is no in-place update; without the explicit delete half, the
//    terms of the superseded text are never decremented and the row accumulates
//    stale postings that match text the span no longer contains. Scoped
//    `OF name, attributes` because those are the only columns the index derives
//    from: an update to any other column cannot change a single posting, so
//    firing on it would rewrite index entries for nothing. That matters — the
//    hash-chain backfill below updates three columns on every existing row, and
//    an unscoped trigger would drag the entire full-text index through a
//    delete-and-reinsert cycle it does not need.
//
//    `OF name, attributes` only checks whether those columns appear in the
//    UPDATE statement's SET clause — not whether their value actually changed.
//    endNano is the one column every span gets touched for after it is first
//    written (the transcript watcher closes it out once the tool call
//    finishes), and today that UPDATE never mentions name or attributes, so the
//    OF clause alone already keeps it out of this trigger. The WHEN guard below
//    is the second half of the same contract: it makes that true by construction
//    rather than by every future UPDATE happening to leave name/attributes out
//    of its SET list. Measured on a 265k-span real database, a span-close write
//    that DOES carry attributes in its SET clause (unchanged value) costs 0.75ms
//    rewriting postings it doesn't need to; with the guard that drops to 0.037ms
//    because the delete+insert pair never runs.
//
// Triggers are DROPped before being recreated because CREATE TRIGGER IF NOT
// EXISTS silently keeps an older definition — an existing database would never
// pick up the new dialect otherwise.
db.exec(`
  DROP TRIGGER IF EXISTS spans_fts_insert;
  CREATE TRIGGER spans_fts_insert AFTER INSERT ON spans BEGIN
    INSERT INTO spans_fts(rowid, spanId, name, attributes)
    VALUES (new.rowid, new.spanId, new.name, new.attributes);
  END;
  DROP TRIGGER IF EXISTS spans_fts_delete;
  CREATE TRIGGER spans_fts_delete AFTER DELETE ON spans BEGIN
    INSERT INTO spans_fts(spans_fts, rowid, spanId, name, attributes)
    VALUES ('delete', old.rowid, old.spanId, old.name, old.attributes);
  END;
  DROP TRIGGER IF EXISTS spans_fts_update;
  CREATE TRIGGER spans_fts_update AFTER UPDATE OF name, attributes ON spans
  WHEN old.name IS NOT new.name OR old.attributes IS NOT new.attributes BEGIN
    INSERT INTO spans_fts(spans_fts, rowid, spanId, name, attributes)
    VALUES ('delete', old.rowid, old.spanId, old.name, old.attributes);
    INSERT INTO spans_fts(rowid, spanId, name, attributes)
    VALUES (new.rowid, new.spanId, new.name, new.attributes);
  END;
`);

/**
 * Backfill the FTS index for every span that predates the current index.
 *
 * Called once from the boot sequence. On a database that was already converted
 * and backfilled this is a single marker read and returns immediately.
 *
 * The walk is CHUNKED into short implicit transactions with a yield between
 * them, so it can never hold the write lock long enough to stall ingest, and the
 * cursor is persisted after every chunk, so a process killed mid-backfill
 * resumes where it stopped instead of restarting. Rows above the frozen ceiling
 * are skipped: those spans arrived after the index was created and the insert
 * trigger has already indexed them — re-inserting them here would double their
 * postings.
 *
 * Interrupting it degrades search to partial results; it never makes search
 * wrong, because a partially-built index only ever under-matches.
 */
export async function reindexFtsMirror(
  opts: { chunkSize?: number; force?: boolean } = {},
): Promise<{ ran: boolean; rows: number }> {
  const chunkSize = Math.max(1, opts.chunkSize ?? 5_000);

  if (opts.force) convertFtsToExternalContent();
  else if (getMarker(FTS_MIGRATION_KEY) !== undefined) return { ran: false, rows: 0 };

  const ceiling = Number(getMarker(FTS_CEILING_KEY) ?? 0);
  let cursor    = Number(getMarker(FTS_CURSOR_KEY) ?? 0);

  const pickChunk = db.prepare(
    `SELECT MAX(rowid) AS maxRowid, COUNT(*) AS n
       FROM (SELECT rowid FROM spans WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT ?)`,
  );
  const copyChunk = db.prepare(
    `INSERT INTO spans_fts(rowid, spanId, name, attributes)
     SELECT rowid, spanId, name, attributes FROM spans WHERE rowid > ? AND rowid <= ?`,
  );

  let rows = 0;
  while (cursor < ceiling) {
    const { maxRowid, n } = pickChunk.get(cursor, ceiling, chunkSize) as
      { maxRowid: number | null; n: number };
    // No spans left below the ceiling — the remaining rowids were pruned.
    if (!n || maxRowid == null) break;
    copyChunk.run(cursor, maxRowid);
    rows += n;
    cursor = maxRowid;
    writeConfig.run(FTS_CURSOR_KEY, String(cursor));
    // Hand the event loop (and any concurrent writer) a turn between chunks.
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  writeConfig.run(FTS_MIGRATION_KEY, new Date().toISOString());
  dropConfig.run(FTS_CURSOR_KEY);
  dropConfig.run(FTS_CEILING_KEY);
  return { ran: true, rows };
}

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

// Tamper-evidence: each row carries the hash of the previous row (server/auditChain.ts),
// so editing an earlier row breaks the chain from that point on. Additive +
// idempotent, same migration style as the spans columns above. Existing rows get
// '' (empty) hashes and are treated as a legacy, unchained prefix by the verifier.
try { db.prepare(`ALTER TABLE operator_audit_log ADD COLUMN prevHash TEXT NOT NULL DEFAULT ''`).run(); } catch {}
try { db.prepare(`ALTER TABLE operator_audit_log ADD COLUMN rowHash  TEXT NOT NULL DEFAULT ''`).run(); } catch {}

// ---------------------------------------------------------------------------
// Persisted enforce/block feed — the PreToolUse hook's "would-block" / "blocked"
// events. Previously an in-memory ring buffer that vanished on restart; now
// persisted so the dashboard's Enforce feed survives a restart and carries the
// same tamper-evident hash chain as the audit log (server/auditChain.ts). Capped
// and pruned on insert (server/index.ts), so it can't grow without bound.
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS enforce_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    mode       TEXT NOT NULL DEFAULT 'monitor',
    label      TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',
    command    TEXT NOT NULL DEFAULT '',
    wouldBlock INTEGER NOT NULL DEFAULT 1,
    blocked    INTEGER NOT NULL DEFAULT 0,
    prevHash   TEXT NOT NULL DEFAULT '',
    rowHash    TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_enforce_log_ts ON enforce_log(ts);
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

// ---------------------------------------------------------------------------
// Spans hash chain
// ---------------------------------------------------------------------------
//
// WHY THE SPANS TABLE AND NOT JUST THE LOGS. The two capped logs were chained
// first because they were easy, but they are not the evidence. `enforce_log`
// holds 500 rows — about eleven days — and `operator_audit_log` records config
// changes. The substance is `spans`: every tool call, command and file access
// the agent made, kept for the full retention window. Chaining the records we
// throw away and leaving the record we keep unprotected had it backwards.
//
// THE HARD PART: A CHAIN AND A SLIDING RETENTION WINDOW.
//
// A hash chain is a statement about a complete sequence; retention deliberately
// destroys parts of that sequence. Delete a span from the middle and the next
// span's prevHash points at something that no longer exists — the chain reads as
// broken, and after a few months of retention every verification would fail for
// entirely legitimate reasons. Worse, "broken because retention ran" and "broken
// because someone deleted evidence" would look identical, which makes the whole
// mechanism useless.
//
// The two obvious answers are both bad. Re-threading the survivors (what the
// capped logs do) means rewriting 269,000 hashes on every retention sweep, and
// it destroys the original hashes — the very things a third party might have
// been handed earlier. Chaining per-session and dropping whole sessions leaves
// the count-based prune, which deletes the oldest spans regardless of session,
// punching holes anyway.
//
// WHAT WE DO: KEEP THE LINK WHEN YOU DELETE THE PAYLOAD.
//
// Deleting a span leaves a tombstone holding only its position, its hash, its
// predecessor's hash and when it went — 160-odd bytes against roughly a kilobyte
// for the span itself. The chain is then verified over the union of live rows
// and tombstones ordered by position, so it stays continuous and complete
// forever, while the data itself is genuinely gone. Retention still deletes what
// it is supposed to delete (that is a GDPR data-minimisation obligation, not an
// optional nicety); what it stops deleting is the proof.
//
// That inverts the failure mode into the one we want: a missing position with NO
// tombstone is not "retention ran", it is an unaccounted deletion, and the
// verifier reports the exact position where the record was cut. The tombstone
// itself is evidence in the useful direction too — hand it a span's content and
// it will tell you whether that span is the one that used to sit there, without
// ever having stored the content.
//
// The tombstone is written by a SQLite trigger, not by the pruning code. That is
// deliberate: it fires for EVERY delete through this handle, including code
// paths written later and ones that forget. What it does not cover is a delete
// issued from some other connection — and that is the point, because those show
// up as unaccounted gaps.
//
// COST. Tombstones accumulate for the life of the install: a few megabytes per
// hundred thousand spans ever ingested. That is the price of a record that can
// still answer "was anything removed" after the data is gone, and it is roughly
// a sixth of what keeping the spans would cost. Compacting long contiguous runs
// would shrink it further at the cost of the per-position links; we have not
// done that, because the links are the product.

db.exec(`
  CREATE TABLE IF NOT EXISTS span_chain_tombstones (
    chainSeq  INTEGER PRIMARY KEY,
    prevHash  TEXT NOT NULL DEFAULT '',
    rowHash   TEXT NOT NULL,
    deletedAt INTEGER NOT NULL
  );
`);

// Fires only for rows that are actually in the chain — spans that predate the
// backfill carry no hash and leave nothing behind, so an install that never runs
// the backfill pays nothing.
db.exec(`
  DROP TRIGGER IF EXISTS spans_chain_tombstone;
  CREATE TRIGGER spans_chain_tombstone AFTER DELETE ON spans
  WHEN old.rowHash <> '' AND old.chainSeq IS NOT NULL BEGIN
    INSERT OR IGNORE INTO span_chain_tombstones (chainSeq, prevHash, rowHash, deletedAt)
    VALUES (old.chainSeq, old.prevHash, old.rowHash, CAST(strftime('%s','now') AS INTEGER));
  END;
`);

// The chain's own index. Without it every chain read — the tail probe on the
// 5-second anchor sweep, the backfill's resume lookup, the mutable-field repair,
// and the pin check that keeps re-anchoring conditional — is a sequential scan
// of the whole spans table; measured at 289,923 rows that is ~50 ms a time, on a
// timer, forever. As an index seek it is two page reads.
//
// Partial (`WHERE chainSeq IS NOT NULL`) so it holds only rows that are actually
// in the chain and stays uninteresting to the query planner for anything else.
// chainSeq alone, NOT (chainSeq, rowHash): measured over 290,000 rows the covering
// form answers the probe 0.2 µs faster and costs 21 MB more, which is a bad trade
// against a lookup that runs twice every five seconds. chainSeq only ever
// increases, so maintaining this is an append at the right edge of the B-tree —
// no measurable ingest cost (7.31 µs/row either way).
db.exec(`CREATE INDEX IF NOT EXISTS idx_spans_chainSeq ON spans(chainSeq) WHERE chainSeq IS NOT NULL`);

const spanTailLive  = db.prepare(`SELECT chainSeq AS seq, rowHash FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq DESC LIMIT 1`);
const spanTailTomb  = db.prepare(`SELECT chainSeq AS seq, rowHash FROM span_chain_tombstones ORDER BY chainSeq DESC LIMIT 1`);
const spanHashAtSeq = db.prepare(`SELECT rowHash FROM spans WHERE chainSeq = ?`);
const tombHashAtSeq = db.prepare(`SELECT rowHash FROM span_chain_tombstones WHERE chainSeq = ?`);

// ── Anchor probes ───────────────────────────────────────────────────────────
// Registered here because this is the only module holding the database handle.
// Each probe reports the table's id high-water mark and its current tail; the
// anchor folds those in monotonically (see server/auditChain.ts). Doing it this
// way means no write path has to remember to update the anchor — including
// write paths added later — and the database stays a plain SQLite file that
// `sqlite3` can open.
//
// `sqlite_sequence` is the high-water mark for the two AUTOINCREMENT logs: it
// records the largest id ever allocated and, importantly, DELETE never lowers
// it. That is what turns "the table is empty" into "the table held 4,000 rows
// and now holds none".

// Each probe also answers `pin(id)` — the hash stored at one position — which is
// what lets the anchor refuse to move its pin over a rewritten history. It runs
// once per chain per sweep, so it has to be a point lookup: the two logs get one
// for free from their INTEGER PRIMARY KEY, and the spans chain gets
// idx_spans_chainSeq below.

function autoincrementProbe(table: string): ChainProbe {
  const seq  = db.prepare(`SELECT seq FROM sqlite_sequence WHERE name = ?`);
  const tail = db.prepare(`SELECT id, rowHash FROM ${table} ORDER BY id DESC LIMIT 1`);
  const head = db.prepare(`SELECT id FROM ${table} ORDER BY id ASC LIMIT 1`);
  const at   = db.prepare(`SELECT rowHash FROM ${table} WHERE id = ?`);
  return {
    read(): ChainProbeReading {
      const high = (seq.get(table) as { seq?: number } | undefined)?.seq ?? 0;
      const t    = tail.get() as { id?: number; rowHash?: string } | undefined;
      const h    = head.get() as { id?: number } | undefined;
      // Both of these logs are CAPPED: they drop their oldest rows on insert, so
      // a pin below the surviving head is retention, not tampering.
      return { appended: high, lastId: t?.id ?? 0, lastRowHash: t?.rowHash ?? '', firstId: h?.id ?? 0 };
    },
    pin(id: number): string | null {
      const r = at.get(id) as { rowHash?: string } | undefined;
      return r === undefined ? null : (r.rowHash ?? '');
    },
  };
}

registerChainProbe('operator_audit_log', autoincrementProbe('operator_audit_log'));
registerChainProbe('enforce_log',        autoincrementProbe('enforce_log'));

// The spans chain has its own counter (`chainSeq`), and a pruned span keeps its
// position in the tombstone table, so the high-water mark is the larger of the
// two — a deleted tail still counts as having existed. `pin` reads the same
// union: a tombstoned position is still a position the anchor can be held to,
// because the tombstone froze the hash that used to live there.
registerChainProbe('spans', {
  read(): ChainProbeReading {
    const live = spanTailLive.get() as { seq?: number; rowHash?: string } | undefined;
    const tomb = spanTailTomb.get() as { seq?: number; rowHash?: string } | undefined;
    const best = (live?.seq ?? 0) >= (tomb?.seq ?? 0) ? live : tomb;
    return { appended: best?.seq ?? 0, lastId: best?.seq ?? 0, lastRowHash: best?.rowHash ?? '' };
  },
  pin(seq: number): string | null {
    const live = spanHashAtSeq.get(seq) as { rowHash?: string } | undefined;
    if (live !== undefined) return live.rowHash ?? '';
    const tomb = tombHashAtSeq.get(seq) as { rowHash?: string } | undefined;
    return tomb === undefined ? null : (tomb.rowHash ?? '');
  },
});

// Backfill bookkeeping, in `config` for the same reason the FTS migration keeps
// its markers there: it is what makes the walk resumable across a restart.
//   ceiling  — highest rowid that existed when the backfill was armed.
//   cursor   — how far the walk has got.
//   seq      — the last chain position the walk assigned.
//   reserved — how many positions the walk needs. Live inserts start ABOVE this
//              so the two never collide, which is what lets ingest keep chaining
//              while the backfill is still running.
const SPAN_CHAIN_DONE     = 'spans.chain_v1';
const SPAN_CHAIN_CEILING  = 'spans.chain_v1.ceiling';
const SPAN_CHAIN_CURSOR   = 'spans.chain_v1.cursor';
const SPAN_CHAIN_SEQ      = 'spans.chain_v1.seq';
const SPAN_CHAIN_RESERVED = 'spans.chain_v1.reserved';

// Arm the backfill once, at open. Cheap on an already-armed or already-finished
// database (two marker reads).
if (getMarker(SPAN_CHAIN_DONE) === undefined && getMarker(SPAN_CHAIN_CEILING) === undefined) {
  const ceiling = (db.prepare(`SELECT COALESCE(MAX(rowid), 0) AS m FROM spans`).get() as { m: number }).m;
  const reserved = (db.prepare(
    `SELECT COUNT(*) AS c FROM spans WHERE rowid <= ? AND rowHash = ''`,
  ).get(ceiling) as { c: number }).c;
  writeConfig.run(SPAN_CHAIN_CEILING, String(ceiling));
  writeConfig.run(SPAN_CHAIN_CURSOR, '0');
  writeConfig.run(SPAN_CHAIN_SEQ, '0');
  writeConfig.run(SPAN_CHAIN_RESERVED, String(reserved));
  // A brand-new database has nothing to adopt, so the chain simply starts live.
  if (reserved === 0) writeConfig.run(SPAN_CHAIN_DONE, new Date().toISOString());
}

/** True once every pre-existing span has been given a chain position. */
export function spanChainBackfillComplete(): boolean {
  return getMarker(SPAN_CHAIN_DONE) !== undefined;
}

// Fixed canonical field order for a span — the chain contract, and not to be
// reordered: doing so invalidates every hash ever written. The chain position is
// hashed too, so a row cannot be lifted out and replayed at a different point in
// the sequence. The three identity columns are in from the start even though
// nothing populates them yet, so that the day something does, it is covered.
export interface ChainableSpan {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  protocol: string;
  reason: string;
  severity: string;
  harness: string;
  attributes: string;
  startNano: string;
  endNano: string;
  repo: string;
  principal?: string | null;
  agent_identity?: string | null;
  delegation_id?: string | null;
}

// ── The mutable-field defect, and why the fix is a split hash ──────────────
//
// The original canonical form hashed `endNano` and `repo` alongside everything
// else. Both are set AFTER a span's INSERT, on the same row, through this same
// database handle:
//   • `endNano` — the transcript watcher inserts a span when a tool call STARTS
//     and runs `UPDATE spans SET endNano = ? WHERE spanId = ?` when it finishes
//     (server/index.ts). A span is hashed before it has an end time and mutated
//     the moment it gets one. This happens to essentially every span, because
//     essentially every span closes.
//   • `repo` — inserted as 'unknown' when a span's working directory can't yet
//     be resolved, then corrected in place once it can (server/repoIdentity.ts:
//     the per-trace `settle` update and the startup backfill). Rarer than
//     endNano, but the same shape of bug, and it moved 131,020 rows in one
//     backfill run on this install alone.
//
// Neither is a security incident. Both are this server, through this same
// handle, finishing the record it already started — which is precisely what
// `verifyChain`'s own doc comment calls out as the boundary the chain checks:
// "changes made through this server's own database handle are recorded as
// legitimate." The bug was that the hash didn't know that yet.
//
// Three ways out were on the table:
//   (a) Amendment records — append a chained "endNano changed" entry instead of
//       mutating the row. Textbook, and it's the shape the two capped logs (and
//       this file's own tombstones) already use for "something happened to a
//       row after the fact." Rejected here on cost: `endNano` closes on very
//       nearly every span, so this doubles the chain-write rate on the busiest
//       write path in the process for a field whose forensic value is a
//       duration, not an attribution. tests/auditIntegrityTest.ts measures the
//       actual insert cost this file already pays (single-digit microseconds);
//       a second signed append per span-close is not free the same way.
//   (c) Chain at completion — hash a span only once endNano is known. Rejected
//       because a lot of spans never close (a killed process, a crashed
//       harness, a span whose 'end' event is lost) and because the dashboard
//       and the enforcement path both act on spans while they are still open —
//       making "in flight" mean "unchained" hides exactly the window this tool
//       exists to watch, for however long a call is running.
//   (b) Split the hash — hash only what is genuinely fixed at insert, and stop
//       claiming coverage of what isn't. THIS is what's implemented below.
//       Cheapest by construction (no extra write, no schema change to the write
//       path), and honest in the one way that matters: a tamperer who alters
//       `endNano` or `repo` after the fact will NOT be caught by this chain.
//       Say that once, plainly, instead of leaving an operator to infer it:
//       DURATION AND REPOSITORY ATTRIBUTION ARE NOT TAMPER-EVIDENT. Everything
//       else about a span — its identity, its content, its place in the
//       sequence — is. `repo` additionally only ever moves unknown → resolved,
//       exactly once per row (server/repoIdentity.ts is idempotent on that),
//       so in practice it settles before most operators would ever look; that
//       is a mitigating fact about this codebase's write pattern, not a
//       property the hash enforces.
//
// `spanCanonical` (below) is the CURRENT scheme — every span inserted from here
// on is hashed without endNano/repo, so neither field mutating after insert can
// ever break the chain again. `spanCanonicalLegacy` is the ORIGINAL scheme,
// field-for-field what shipped before this fix, kept ONLY so a row hashed under
// it can still be verified: exactly the role `computeLegacyHmacRowHash` already
// plays for the pre-Ed25519 rows in auditChain.ts, generalized from "old hash
// function, same fields" to "old hash function, wider field set." A row that
// verifies only under the legacy scheme is reported as such (`legacyFieldRows`
// in SpanChainStatus) rather than silently counted as fully current — that
// count is exactly the rows NOT protected against a future endNano/repo edit,
// the same way `legacyHmacRows` reports rows a third party can't check at all.
function spanCanonical(s: ChainableSpan & { chainSeq: number }): string {
  return canonicalString([
    s.chainSeq, s.spanId, s.traceId, s.parentId, s.name, s.protocol, s.reason,
    s.severity, s.harness, s.attributes, s.startNano,
    s.principal ?? null, s.agent_identity ?? null, s.delegation_id ?? null,
  ]);
}

/** The pre-fix canonical form, endNano and repo included. Verification-only —
 *  nothing computes a NEW hash with this any more. See the block comment above
 *  `spanCanonical` for why it still exists and what a row hashed under it does
 *  and does not tell you. */
function spanCanonicalLegacy(s: ChainableSpan & { chainSeq: number }): string {
  return canonicalString([
    s.chainSeq, s.spanId, s.traceId, s.parentId, s.name, s.protocol, s.reason,
    s.severity, s.harness, s.attributes, s.startNano, s.endNano, s.repo,
    s.principal ?? null, s.agent_identity ?? null, s.delegation_id ?? null,
  ]);
}

const insertSpanChained = db.prepare(`
  INSERT OR IGNORE INTO spans
    (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes,
     startNano, endNano, repo, chainSeq, prevHash, rowHash,
     principal, agent_identity, delegation_id)
  VALUES
    (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness, @attributes,
     @startNano, @endNano, @repo, @chainSeq, @prevHash, @rowHash,
     @principal, @agent_identity, @delegation_id)
`);

// O(1) appends: the tail position and hash are cached so chaining never rescans.
// Seeded lazily, from live rows AND tombstones (a pruned tail still counts) and
// never below the range the backfill reserved.
let spanTail: { seq: number; rowHash: string } | undefined;

function spanChainTail(): { seq: number; rowHash: string } {
  if (spanTail !== undefined) return spanTail;
  try {
    const live = db.prepare(
      `SELECT chainSeq AS seq, rowHash FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq DESC LIMIT 1`,
    ).get() as { seq: number; rowHash: string } | undefined;
    const tomb = db.prepare(
      `SELECT chainSeq AS seq, rowHash FROM span_chain_tombstones ORDER BY chainSeq DESC LIMIT 1`,
    ).get() as { seq: number; rowHash: string } | undefined;
    const best = [live, tomb]
      .filter((r): r is { seq: number; rowHash: string } => !!r)
      .sort((a, b) => b.seq - a.seq)[0];
    // While the backfill is still running, positions 1..reserved belong to it.
    // Live appends start above that range; the first of them has no predecessor
    // it can point at yet, so it opens a new segment (recorded in the anchor).
    const reserved = spanChainBackfillComplete() ? 0 : Number(getMarker(SPAN_CHAIN_RESERVED) ?? 0);
    spanTail = best && best.seq >= reserved ? best : { seq: reserved, rowHash: '' };
  } catch {
    spanTail = { seq: 0, rowHash: '' };
  }
  return spanTail;
}

/** Test seam: forget the cached tail so the next append re-reads it from the
 *  table. Needed by fixtures that rewrite the spans table through a second
 *  connection, which this process's cache cannot see. Not used by the server. */
export function resetSpanChainTailCacheForTests(): void {
  spanTail = undefined;
}

/**
 * Insert a span, hash-chained to the one before it.
 *
 * Drop-in for `insertSpan.run(record)` — same INSERT OR IGNORE semantics, same
 * return shape. The extra work per span is one JSON.stringify over the field
 * array and one SHA-256 over it; measured on this machine that is single-digit
 * microseconds against a SQLite insert costing tens, so it does not move the
 * ingest budget. See tests/auditIntegrityTest.ts, which measures and prints it.
 *
 * Fail-open, like every other write path here: if hashing throws, the span is
 * still stored, just unchained (empty hash), and the verifier reports it as an
 * unchained row instead of the record silently losing a span.
 */
export function insertChainedSpan(rec: ChainableSpan): { changes: number } {
  let chainSeq: number | null = null;
  let prevHash = '';
  let rowHash  = '';
  try {
    const tail = spanChainTail();
    chainSeq = tail.seq + 1;
    prevHash = tail.rowHash;
    rowHash  = computeRowHash(spanCanonical({ ...rec, chainSeq }), prevHash);
    if (rowHash === '') chainSeq = null;   // hashing failed → store unchained
  } catch {
    chainSeq = null; prevHash = ''; rowHash = '';
  }
  const info = insertSpanChained.run({
    ...rec,
    principal:      rec.principal ?? null,
    agent_identity: rec.agent_identity ?? null,
    delegation_id:  rec.delegation_id ?? null,
    chainSeq, prevHash, rowHash,
  });
  // INSERT OR IGNORE can drop a duplicate spanId. Advancing the tail on a row
  // that was never stored would leave a hole the verifier would (correctly)
  // report as an unaccounted deletion, so the position is only consumed when the
  // row actually landed.
  if (info.changes === 1 && chainSeq !== null) {
    spanTail = { seq: chainSeq, rowHash };
    if (prevHash === '') recordChainSegment('spans', chainSeq);
  }
  return { changes: info.changes };
}

/**
 * Give every pre-existing span a chain position, in resumable chunks.
 *
 * Modelled on reindexFtsMirror(): a frozen ceiling so rows that arrive during
 * the walk are left to the live path, a cursor persisted after every chunk so a
 * process killed halfway resumes instead of restarting, and a yield between
 * chunks so the write lock is never held long enough to stall ingest. Running it
 * twice is a no-op; running it after a crash picks up mid-walk.
 *
 * What it is NOT: a claim about the past. Hashing a row today proves it has not
 * changed since today. The adoption is stamped into the anchor (`adoptedAt`) so
 * nobody mistakes the two.
 */
export async function chainSpansBackfill(
  opts: { chunkSize?: number; force?: boolean } = {},
): Promise<{ ran: boolean; rows: number }> {
  const chunkSize = Math.max(1, opts.chunkSize ?? 2_000);

  if (opts.force) {
    // Re-arm from scratch: used by tests and by an operator who needs to rebuild
    // a chain after restoring a database.
    db.exec(`UPDATE spans SET chainSeq = NULL, prevHash = '', rowHash = ''`);
    db.exec(`DELETE FROM span_chain_tombstones`);
    const ceiling = (db.prepare(`SELECT COALESCE(MAX(rowid), 0) AS m FROM spans`).get() as { m: number }).m;
    const reserved = (db.prepare(`SELECT COUNT(*) AS c FROM spans WHERE rowid <= ?`).get(ceiling) as { c: number }).c;
    writeConfig.run(SPAN_CHAIN_CEILING, String(ceiling));
    writeConfig.run(SPAN_CHAIN_CURSOR, '0');
    writeConfig.run(SPAN_CHAIN_SEQ, '0');
    writeConfig.run(SPAN_CHAIN_RESERVED, String(reserved));
    dropConfig.run(SPAN_CHAIN_DONE);
    spanTail = undefined;
  } else if (spanChainBackfillComplete()) {
    return { ran: false, rows: 0 };
  }

  const ceiling = Number(getMarker(SPAN_CHAIN_CEILING) ?? 0);
  let cursor    = Number(getMarker(SPAN_CHAIN_CURSOR) ?? 0);
  let seq       = Number(getMarker(SPAN_CHAIN_SEQ) ?? 0);

  // Resume needs the hash of the last row the previous run wrote, otherwise the
  // chunk after a restart would chain onto nothing.
  let prev = seq > 0
    ? ((db.prepare(`SELECT rowHash FROM spans WHERE chainSeq = ?`).get(seq) as { rowHash?: string } | undefined)?.rowHash ?? '')
    : '';

  const pickChunk = db.prepare(
    `SELECT rowid AS rid, spanId, traceId, parentId, name, protocol, reason, severity,
            harness, attributes, startNano, endNano, repo, principal, agent_identity, delegation_id
       FROM spans
      WHERE rowid > ? AND rowid <= ? AND rowHash = ''
      ORDER BY rowid LIMIT ?`,
  );
  const applyChunk = db.prepare(
    `UPDATE spans SET chainSeq = @chainSeq, prevHash = @prevHash, rowHash = @rowHash WHERE rowid = @rid`,
  );

  let rows = 0;
  for (;;) {
    const chunk = pickChunk.all(cursor, ceiling, chunkSize) as Array<
      ChainableSpan & { rid: number }
    >;
    if (chunk.length === 0) break;

    // One transaction per chunk: a crash mid-chunk rolls the chunk back and the
    // persisted cursor still points at the last committed row, so the resume is
    // exact rather than approximate.
    const commit = db.transaction(() => {
      for (const r of chunk) {
        seq += 1;
        const rowHash = computeRowHash(spanCanonical({ ...r, chainSeq: seq }), prev);
        applyChunk.run({ chainSeq: seq, prevHash: prev, rowHash, rid: r.rid });
        prev = rowHash;
        cursor = r.rid;
      }
      writeConfig.run(SPAN_CHAIN_CURSOR, String(cursor));
      writeConfig.run(SPAN_CHAIN_SEQ, String(seq));
    });
    commit();
    rows += chunk.length;
    // Hand the event loop (and any concurrent writer) a turn between chunks.
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  writeConfig.run(SPAN_CHAIN_DONE, new Date().toISOString());
  dropConfig.run(SPAN_CHAIN_CURSOR);
  dropConfig.run(SPAN_CHAIN_CEILING);
  spanTail = undefined;

  // Adopt whatever is now chained as the baseline the anchor guards.
  const summary = db.prepare(
    `SELECT COUNT(*) AS c, COALESCE(MAX(chainSeq), 0) AS m FROM spans WHERE chainSeq IS NOT NULL`,
  ).get() as { c: number; m: number };
  const tail = db.prepare(
    `SELECT rowHash FROM spans WHERE chainSeq = ?`,
  ).get(summary.m) as { rowHash?: string } | undefined;
  const tombs = (db.prepare(`SELECT COUNT(*) AS c FROM span_chain_tombstones`).get() as { c: number }).c;
  adoptChainBaseline('spans', {
    rows: summary.c + tombs,
    lastId: summary.m,
    lastRowHash: tail?.rowHash ?? '',
  });

  return { ran: true, rows };
}

// ── Recovering a chain that was already broken by the mutable-field defect ──
//
// `chainSpansBackfill` above gives every PRE-EXISTING span a chain position; it
// has nothing to do with rows that already HAD a position but were hashed under
// the old (endNano/repo-included) scheme and then mutated — the actual live
// defect this file fixes. Those rows fall into two buckets once `spanCanonical`
// stops hashing endNano/repo:
//   • Never mutated since it was hashed → still verifies under the OLD scheme
//     (spanCanonicalLegacy) with today's field values, because today's values
//     are what it was hashed with. Left alone, forever — see the doc comment
//     on spanCanonicalLegacy for why rewriting these would cost more than it
//     buys and would need touching the whole table for no correctness gain.
//   • Mutated after it was hashed → verifies under NEITHER scheme, because the
//     stored hash was computed from a field value (a stale/empty endNano, an
//     'unknown' repo) that no longer exists anywhere to recompute against.
//     This is the one case that needs an actual write: recompute under the
//     CURRENT scheme and repair forward.
//
// "Repair forward" matters: fixing row N's rowHash changes what row N+1's
// prevHash needs to be, whether or not row N+1's own content is fine. So once a
// broken row is found, every row after it — to wherever the walk currently is —
// gets re-threaded, exactly like `reanchorChain` re-threads a pruned log, except
// this walk does NOT restart from prevHash=''; it carries the real prevHash
// forward so the newly-repaired stretch stays continuous with whatever came
// before it, live rows and tombstones alike (a tombstone's hash is frozen,
// unrepairable — its content is gone — and is simply passed through as the next
// row's prevHash unchanged).
//
// SAFE UNDER CONCURRENT INGEST, DELIBERATELY WITHOUT A FROZEN CEILING. Chunks
// are processed in ascending chainSeq order, so by the time this walk reaches
// any position, everything before it — original or freshly repaired in an
// earlier chunk of this SAME run — is already exactly what it needs to be. A
// row inserted live WHILE this runs is already hashed under the current scheme
// (insertChainedSpan uses spanCanonical, not the legacy form) and chains onto
// whatever the true tail is at insert time; when the walk reaches it, the link
// check simply confirms that and moves on. If a live insert instead raced onto
// a prevHash that this walk is about to change, the walk finds the same
// discontinuity it would for any other broken link and repairs it the same
// way — the two code paths cannot disagree about what "correct" looks like
// because both compute it with the same function. Nothing here freezes a
// ceiling or coordinates with `spanChainTail()`, unlike the position-backfill
// above, because nothing here needs to: nothing this walk does can invalidate
// a row it hasn't reached yet.
/** Spans-specific coverage limits, distinct from the generic AUDIT_LIMITS in
 *  auditChain.ts (which apply equally to the audit log and enforce log, neither
 *  of which has a mutable field). Surfaced by /api/audit/verify next to the
 *  spans result so an operator reading `legacyFieldRows` or `row_mismatch`
 *  doesn't have to find this comment to know what it means. */
export const SPAN_CHAIN_MUTABLE_FIELD_LIMITS: readonly string[] = [
  'endNano (a span\'s end time) and repo (its repository attribution) are stored but NOT part of the CURRENT span hash. Both are set by this server after a span is first written, so hashing them going forward would make the chain flag its own writer as a tamperer. On rows written under the current scheme, an attacker who edits ONLY these two fields leaves no trace in this chain.',
  'Rows hashed before this fix (legacyFieldRows in the spans result) DO still include endNano/repo in their hash, and an edit to either field on one of them breaks verification today — confirmed against a copy of the production database, not just claimed. This is not a maintained guarantee, though: it is an accident of when those rows happened to be hashed, not a contract this server keeps. The concrete risk it carries is the mirror image of the bug this fix closes — if a future maintenance pass ever needs to legitimately correct repo or endNano on one of these OLD rows, that legitimate write will trip the same detection a tamperer would, exactly the false positive spanCanonical exists to prevent on new rows. That is why these rows are never bulk-rewritten onto the current scheme: doing so would trade away real, working protection to close a landmine that only fires if this server\'s own code goes looking for it.',
  'row_mismatch on a span means its content fails to hash under BOTH the current scheme and the legacy (pre-fix) one. When mutableFieldFixComplete is true, that is not explained by this server\'s own endNano/repo writes and should be treated as a real break, not a false alarm from routine operation.',
];

const SPAN_CHAIN_MUTABLE_FIX_DONE   = 'spans.chain_mutable_fix_v1';
const SPAN_CHAIN_MUTABLE_FIX_CURSOR = 'spans.chain_mutable_fix_v1.cursor';

/** True once every span the mutable-field fix could reach has been checked
 *  (and, where it was actually broken, repaired). */
export function spanChainMutableFieldFixComplete(): boolean {
  return getMarker(SPAN_CHAIN_MUTABLE_FIX_DONE) !== undefined;
}

interface MutableFixRow {
  chainSeq: number;
  tomb: 0 | 1;
  spanId: string; traceId: string; parentId: string; name: string; protocol: string;
  reason: string; severity: string; harness: string; attributes: string; startNano: string;
  endNano: string; repo: string;
  principal: string | null; agent_identity: string | null; delegation_id: string | null;
  prevHash: string; rowHash: string;
}

const mutableFixChunk = db.prepare(`
  SELECT chainSeq, spanId, traceId, parentId, name, protocol, reason, severity, harness,
         attributes, startNano, endNano, repo, principal, agent_identity, delegation_id,
         prevHash, rowHash, 0 AS tomb
    FROM spans WHERE chainSeq IS NOT NULL AND chainSeq > @cursor
  UNION ALL
  SELECT chainSeq, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         prevHash, rowHash, 1 AS tomb
    FROM span_chain_tombstones WHERE chainSeq > @cursor
  ORDER BY chainSeq ASC LIMIT @limit
`);
const mutableFixRepairRow = db.prepare(
  `UPDATE spans SET prevHash = @prevHash, rowHash = @rowHash WHERE chainSeq = @chainSeq`,
);
const mutableFixTailHash = db.prepare(
  `SELECT rowHash FROM spans WHERE chainSeq = ?
   UNION ALL
   SELECT rowHash FROM span_chain_tombstones WHERE chainSeq = ?
   LIMIT 1`,
);

/**
 * Find and repair the chain positions the mutable-field defect actually broke.
 *
 * Chunked and yields between chunks (same shape as `chainSpansBackfill`), so it
 * never holds the write lock long enough to stall ingest even on a large table.
 * Idempotent: a chunk that finds nothing to repair still advances the cursor,
 * so re-running after this completes — or after a crash mid-walk — is cheap.
 * Only ever WRITES a row that genuinely fails to verify under both the current
 * and the legacy canonical form; everything else is read-only.
 */
export async function repairSpanChainMutableFields(
  opts: { chunkSize?: number } = {},
): Promise<{ ran: boolean; rows: number; repaired: number }> {
  if (spanChainMutableFieldFixComplete()) return { ran: false, rows: 0, repaired: 0 };
  const chunkSize = Math.max(1, opts.chunkSize ?? 2_000);
  // Positions where prevHash='' is BY DESIGN (a reserved-range or backfill
  // restart, not a severed link) — same set verifySpanChain consults. Without
  // this, a legitimate segment boundary reads as a break and everything after
  // it gets needlessly rewritten.
  const segments = new Set(getChainAnchor('spans')?.segments ?? []);

  let cursor = Number(getMarker(SPAN_CHAIN_MUTABLE_FIX_CURSOR) ?? 0);
  let prev = '';
  if (cursor > 0) {
    const t = mutableFixTailHash.get(cursor, cursor) as { rowHash?: string } | undefined;
    prev = t?.rowHash ?? '';
  }

  let rows = 0;
  let repaired = 0;
  for (;;) {
    const chunk = mutableFixChunk.all({ cursor, limit: chunkSize }) as MutableFixRow[];
    if (chunk.length === 0) break;

    const commit = db.transaction(() => {
      for (const row of chunk) {
        if (row.tomb) {
          // Frozen, content-less, unrepairable — pass its hash through as the
          // next row's link, exactly as verification already does.
          prev = row.rowHash;
          cursor = row.chainSeq;
          continue;
        }
        // A designed segment start supplies its OWN prevHash (by construction
        // '') rather than needing to match our running `prev`.
        const linkPrev = segments.has(row.chainSeq) ? row.prevHash : prev;
        const linked = row.prevHash === linkPrev;
        const current = linked && computeRowHash(spanCanonical(row), linkPrev) === row.rowHash;
        const legacy  = !current && linked && computeRowHash(spanCanonicalLegacy(row), linkPrev) === row.rowHash;
        if (current || legacy) {
          // Verifies as-is — under whichever scheme it was actually hashed
          // with. Never rewritten: history keeps the hash it was written with.
          prev = row.rowHash;
        } else {
          // Broken: either this row's own content was mutated after hashing
          // (the endNano/repo defect), or an earlier repair in this same walk
          // changed the prevHash it needs to link to. Either way the fix is
          // the same — recompute under the CURRENT scheme, chained to the real
          // predecessor (its own '' if this position is a designed segment
          // start, so a repair can never weld two segments together that were
          // deliberately kept apart), and the repair cascades to whatever
          // follows.
          const rowHash = computeRowHash(spanCanonical(row), linkPrev);
          mutableFixRepairRow.run({ prevHash: linkPrev, rowHash, chainSeq: row.chainSeq });
          repaired++;
          prev = rowHash;
        }
        cursor = row.chainSeq;
      }
      writeConfig.run(SPAN_CHAIN_MUTABLE_FIX_CURSOR, String(cursor));
    });
    commit();
    rows += chunk.length;
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  writeConfig.run(SPAN_CHAIN_MUTABLE_FIX_DONE, new Date().toISOString());
  // The tail this run ended on may carry a NEW hash even though its position
  // (chainSeq) is unchanged — adoptChainBaseline updates lastRowHash whenever
  // baseline.lastId >= the anchor's recorded lastId, which covers "same
  // position, repaired hash" as well as "chain grew further". A no-op repair
  // run (nothing broken) re-adopts the same values, which is harmless.
  const tail = db.prepare(
    `SELECT chainSeq AS seq, rowHash FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq DESC LIMIT 1`,
  ).get() as { seq?: number; rowHash?: string } | undefined;
  const tombTail = db.prepare(
    `SELECT chainSeq AS seq, rowHash FROM span_chain_tombstones ORDER BY chainSeq DESC LIMIT 1`,
  ).get() as { seq?: number; rowHash?: string } | undefined;
  const best = (tail?.seq ?? 0) >= (tombTail?.seq ?? 0) ? tail : tombTail;
  if (best?.seq) {
    const totalLive = (db.prepare(`SELECT COUNT(*) AS c FROM spans WHERE chainSeq IS NOT NULL`).get() as { c: number }).c;
    const totalTomb = (db.prepare(`SELECT COUNT(*) AS c FROM span_chain_tombstones`).get() as { c: number }).c;
    adoptChainBaseline('spans', { rows: totalLive + totalTomb, lastId: best.seq, lastRowHash: best.rowHash ?? '' });
  }
  // A repaired tail invalidates the cached spanTail (it may hold a now-stale
  // hash for the position this run just rewrote) — drop it so the next insert
  // re-reads the true, post-repair tail from the database.
  spanTail = undefined;

  return { ran: true, rows, repaired };
}

// ── Exact, cheap field-scheme coverage ──────────────────────────────────────
//
// THE DECISION RECORDED HERE: legacy rows (hashed under spanCanonicalLegacy,
// endNano/repo included) are NOT rewritten onto spanCanonical in bulk, and this
// is deliberate rather than merely unaddressed. Two independent reasons, both
// checked against the real 274k-row production database before landing this:
//
//   1. A mass rewrite is a mass RECOMPUTE. rowHash threads forward — repairing
//      row N changes what N+1 must link to — so "rehash everything from here"
//      is a general-purpose primitive (reanchorChain and the repair pass above
//      both already do it locally) and a fully deterministic function of public
//      code plus the row's own stored fields. Anyone who can write to the
//      database — this operator, or an attacker who already has that access —
//      can run the exact same recompute and produce a chain that verifies
//      end-to-end. The ONLY thing that would make a mass rewrite of the past
//      distinguishable from an attacker quietly doing the same thing is an
//      external witness over the pre-rewrite tail (server/auditAnchor.ts) —
//      and that anchoring is opt-in and OFF by default. Rewriting 269,872 rows
//      on an unanchored install is not a security improvement; it is producing,
//      at will, exactly the artifact a tamperer would also need to produce.
//   2. Rewriting would spend a property these rows already have, for nothing in
//      return. spanCanonicalLegacy DOES include endNano/repo, so an edit to
//      either field on one of these rows breaks verification TODAY — proven
//      against a .backup of the live database: a raw `UPDATE spans SET endNano
//      = ...` on a legacy-scheme row reliably produced row_mismatch, deep
//      verify catching it immediately. Converting that row to spanCanonical
//      would not add coverage anywhere else; it would remove this one, in
//      exchange only for consistency of scheme. The honest cost of the CURRENT
//      state is not "these rows are unprotected" — it is that this protection
//      is an accident of when they were hashed, not a maintained contract:
//      SPAN_CHAIN_MUTABLE_FIELD_LIMITS below says so plainly, because the same
//      mechanism that catches an attacker also catches this server's own code
//      if a future maintenance pass ever needs to legitimately correct repo or
//      endNano on an old row — the false-positive landmine spanCanonical exists
//      to defuse, still live on exactly the rows a rewrite would touch.
//
// What actually closes the gap an operator can act on today is visibility, not
// rewriting: knowing exactly how much of the record sits on each scheme without
// paying for a full recompute to find out. `legacyFieldRows` is a FIXED number
// once spanChainMutableFieldFixComplete() is true — every row inserted after
// that point is written under spanCanonical from birth (insertChainedSpan never
// uses the legacy form), so nothing can ever join the legacy count again. That
// makes it safe to compute once and cache, rather than re-deriving it from a
// deep verify on every request.
//
// This is a SEPARATE one-time pass from repairSpanChainMutableFields, not a
// piggyback on it, because an install that upgraded to the mutable-field fix
// before this counter existed already has mutableFieldFixComplete=true with no
// count ever recorded — exactly the live production database's actual state.
// Piggybacking would silently under-report on every install that predates this
// change; a standalone backfill classifies correctly regardless of when the
// repair itself ran.
//
// Read-only and independent of row order: unlike the repair pass, this walk
// never rewrites anything, so it needs no reconstructed `prev` — each row is
// checked against its OWN stored prevHash column, precisely what
// verifySpanChain's deep content check already does per row. Chunked, cursor-
// persisted, resumable, and safe to run concurrently with ingest for the same
// reason the repair pass is: it only ever reads.

const SPAN_FIELD_COVERAGE_DONE    = 'spans.field_coverage_v1';
const SPAN_FIELD_COVERAGE_CURSOR  = 'spans.field_coverage_v1.cursor';
const SPAN_FIELD_COVERAGE_LEGACY  = 'spans.field_coverage_v1.legacyFieldRows';
const SPAN_FIELD_COVERAGE_CURRENT = 'spans.field_coverage_v1.currentFieldRows';
const SPAN_FIELD_COVERAGE_WALKED  = 'spans.field_coverage_v1.rowsWalked';

/** True once the one-time classification walk has assigned every chained span
 *  to a scheme. Independent of spanChainMutableFieldFixComplete() — see the
 *  block comment above for why an install can have one true without the other. */
export function spanChainFieldCoverageComplete(): boolean {
  return getMarker(SPAN_FIELD_COVERAGE_DONE) !== undefined;
}

const fieldCoverageChunk = db.prepare(`
  SELECT chainSeq, spanId, traceId, parentId, name, protocol, reason, severity, harness,
         attributes, startNano, endNano, repo, principal, agent_identity, delegation_id,
         prevHash, rowHash
    FROM spans WHERE chainSeq IS NOT NULL AND chainSeq > @cursor
    ORDER BY chainSeq ASC LIMIT @limit
`);

/**
 * One-time, read-only classification of every chained span as current-scheme
 * or legacy-scheme, cached so `spanChainFieldCoverage()` below never has to pay
 * for a deep recompute. Only meaningful once repairSpanChainMutableFields has
 * completed — before that, a row failing both schemes is a known break already
 * being repaired, not a stable classification, so this declines to run and
 * reports nothing rather than a number that would have to be redone.
 *
 * Idempotent: a chunk that finds nothing new still advances the cursor, so a
 * process killed mid-walk resumes exactly, and a second call after completion
 * is a no-op that returns the cached total.
 */
export async function backfillSpanFieldCoverage(
  opts: { chunkSize?: number } = {},
): Promise<{ ran: boolean; rows: number; legacyFieldRows: number; currentFieldRows: number }> {
  if (!spanChainMutableFieldFixComplete()) return { ran: false, rows: 0, legacyFieldRows: 0, currentFieldRows: 0 };
  if (spanChainFieldCoverageComplete()) {
    return {
      ran: false, rows: 0,
      legacyFieldRows:  Number(getMarker(SPAN_FIELD_COVERAGE_LEGACY) ?? 0),
      currentFieldRows: Number(getMarker(SPAN_FIELD_COVERAGE_CURRENT) ?? 0),
    };
  }

  const chunkSize = Math.max(1, opts.chunkSize ?? 5_000);
  let cursor = Number(getMarker(SPAN_FIELD_COVERAGE_CURSOR) ?? 0);
  let legacyFieldRows  = Number(getMarker(SPAN_FIELD_COVERAGE_LEGACY) ?? 0);
  let currentFieldRows = Number(getMarker(SPAN_FIELD_COVERAGE_CURRENT) ?? 0);
  let walked = Number(getMarker(SPAN_FIELD_COVERAGE_WALKED) ?? 0);

  let rows = 0;
  for (;;) {
    const chunk = fieldCoverageChunk.all({ cursor, limit: chunkSize }) as Array<
      ChainableSpan & { chainSeq: number; prevHash: string; rowHash: string }
    >;
    if (chunk.length === 0) break;

    const commit = db.transaction(() => {
      for (const row of chunk) {
        // Same per-row check verifySpanChain's deep content pass makes: current
        // scheme first, legacy as the fallback. A row failing both is a break
        // this pass is not responsible for repairing — it is simply not
        // counted in either bucket, and the next deep verify surfaces it as
        // row_mismatch the same as it always would.
        if (computeRowHash(spanCanonical(row), row.prevHash) === row.rowHash) {
          currentFieldRows++;
        } else if (computeRowHash(spanCanonicalLegacy(row), row.prevHash) === row.rowHash) {
          legacyFieldRows++;
        }
        cursor = row.chainSeq;
        walked++;
      }
      writeConfig.run(SPAN_FIELD_COVERAGE_CURSOR, String(cursor));
      writeConfig.run(SPAN_FIELD_COVERAGE_LEGACY, String(legacyFieldRows));
      writeConfig.run(SPAN_FIELD_COVERAGE_CURRENT, String(currentFieldRows));
      writeConfig.run(SPAN_FIELD_COVERAGE_WALKED, String(walked));
    });
    commit();
    rows += chunk.length;
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  writeConfig.run(SPAN_FIELD_COVERAGE_DONE, new Date().toISOString());
  dropConfig.run(SPAN_FIELD_COVERAGE_CURSOR);
  return { ran: true, rows, legacyFieldRows, currentFieldRows };
}

let fieldCoverageBackfillStarted = false;

/** What an operator sees at a glance: how much of the record sits on each
 *  canonical scheme, without paying for a deep recompute to find out.
 *
 *  `exact: false` means the one-time classification walk (above) has not
 *  finished yet — on a fresh install this is seconds; on an install upgrading
 *  from before this counter existed, it is one read-only pass over the table.
 *  Calling this kicks that walk off in the background (fire-and-forget, at
 *  most once) so the NEXT call reports exact numbers; it never blocks the
 *  caller on it.
 *
 *  `currentFieldRows` folds in every row inserted AFTER the walk completed,
 *  without re-checking any of them: nothing in this codebase's write paths has
 *  ever produced a new legacy-scheme hash (insertChainedSpan and
 *  chainSpansBackfill both use spanCanonical unconditionally — see the block
 *  comment above this section), so growth since the walk can only be current-
 *  scheme BY CONSTRUCTION, not by re-verification. That is a claim about which
 *  FORMULA a row was hashed with, not that the hash still matches — a row
 *  tampered with after this counter last ran stays counted exactly as it was
 *  classified, until a fresh deep verify (a different, more expensive check)
 *  catches the mismatch. The two must not be conflated: this answers "how much
 *  of my record is on which scheme", not "has anything changed since I last
 *  looked". */
export function spanChainFieldCoverage(): {
  exact: boolean;
  legacyFieldRows: number | null;
  currentFieldRows: number | null;
  totalChainedRows: number;
  percentCurrentScheme: number | null;
} {
  const totalChainedRows = (db.prepare(`SELECT COUNT(*) AS c FROM spans WHERE chainSeq IS NOT NULL`).get() as { c: number }).c;

  if (!spanChainFieldCoverageComplete()) {
    if (!fieldCoverageBackfillStarted && spanChainMutableFieldFixComplete()) {
      fieldCoverageBackfillStarted = true;
      void backfillSpanFieldCoverage().catch(() => { fieldCoverageBackfillStarted = false; });
    }
    return { exact: false, legacyFieldRows: null, currentFieldRows: null, totalChainedRows, percentCurrentScheme: null };
  }

  const legacyFieldRows    = Number(getMarker(SPAN_FIELD_COVERAGE_LEGACY) ?? 0);
  const currentAtWalk      = Number(getMarker(SPAN_FIELD_COVERAGE_CURRENT) ?? 0);
  const rowsWalked         = Number(getMarker(SPAN_FIELD_COVERAGE_WALKED) ?? 0);
  const grownSinceWalk     = Math.max(0, totalChainedRows - rowsWalked);
  const currentFieldRows   = currentAtWalk + grownSinceWalk;
  const percentCurrentScheme = totalChainedRows > 0 ? (currentFieldRows / totalChainedRows) * 100 : null;
  return { exact: true, legacyFieldRows, currentFieldRows, totalChainedRows, percentCurrentScheme };
}

// ── Verifying the spans chain ───────────────────────────────────────────────

export type SpanChainVerdict =
  | 'ok'
  | 'unchained'         // nothing in the chain yet — the backfill has not run
  | 'row_mismatch'      // a span's content no longer hashes under EITHER canonical scheme
  | 'link_mismatch'     // two adjacent positions no longer link
  | 'unaccounted_gap'   // a position is missing and no tombstone explains it
  | 'truncated'         // fewer rows than the anchor accounts for
  | 'wiped'             // the anchor accounts for rows; nothing is left
  | 'tail_mismatch'     // the anchored position carries a different hash
  | 'tail_unpinned'     // the anchor counts positions but pins no hash to check them against
  | 'anchor_missing'
  | 'anchor_unsigned';

export interface SpanChainStatus {
  /** No evidence of tampering. NOT a claim that every span was ever recorded. */
  ok: boolean;
  status: SpanChainVerdict;
  detail: string;
  totalSpans: number;
  chainedSpans: number;
  unchainedSpans: number;
  tombstones: number;
  /** How many span hashes were actually recomputed from content in this run. */
  checkedHashes: number;
  /** Of checkedHashes, how many verified only under the pre-fix scheme (endNano
   *  and repo included in the hash) rather than the current one. These rows are
   *  NOT protected against a future endNano/repo edit — they simply haven't had
   *  one since they were hashed. See spanCanonicalLegacy's doc comment. Distinct
   *  from `row_mismatch`, which is a row that fails BOTH schemes: a genuine
   *  break, either external tampering or a mutation this migration has not
   *  reached yet. */
  legacyFieldRows: number;
  deep: boolean;
  brokenAtSeq?: number;
  expectedRows?: number;
  /** A signed anchor covers this chain's boundaries AND is still advancing. A
   *  frozen pin makes this false regardless of the signature: everything newer
   *  than the freeze is covered by nothing. */
  attested: boolean;
  /** How many times the anchor has ever refused to advance because the position
   *  it had pinned stopped carrying the hash it was pinned with. Never
   *  decreases — non-zero on a chain that verifies today still means the record
   *  was, at some moment, inconsistent with what had already been signed. */
  anchorPinBreaks?: number;
  pinFrozenAt?: string;
  pinFrozenSeq?: number;
  signed: boolean;
  keyId: string;
  backfillComplete: boolean;
  /** True once every existing span has been checked — and, where the
   *  endNano/repo defect had already broken it, repaired — under the current
   *  canonical scheme. False means some rows may still show row_mismatch for a
   *  cause this fix already knows how to repair; see /api/audit/verify's
   *  `spans.mutableFieldFixComplete`. */
  mutableFieldFixComplete: boolean;
}

/**
 * Verify the spans chain.
 *
 * Two levels, because the honest cost of a full check is real: recomputing every
 * hash means reading every span's attributes back off disk — a few hundred
 * megabytes and a minute on a mature database, which is not something an HTTP
 * handler should do by default.
 *
 *   • default — walks positions and links over live rows and tombstones (small,
 *     index-only columns), checks them against the signed anchor, and recomputes
 *     content hashes for the newest `window` spans. This is what catches the
 *     things that actually happen: deletions, truncation, a swapped database.
 *   • deep    — additionally recomputes the content hash of every chained span.
 *     Chunked with yields so it never blocks the event loop.
 */
export async function verifySpanChain(
  opts: { deep?: boolean; window?: number } = {},
): Promise<SpanChainStatus> {
  const deep   = opts.deep === true;
  const window = Math.max(0, opts.window ?? 5_000);
  const anchor = getChainAnchor('spans');
  const anchored = anchor !== null && anchor.appended > 0;
  // A frozen pin means the anchor stopped covering this table at some earlier
  // position, so however good its signature is there is nothing here it can
  // attest. See refreshChainAnchors in server/auditChain.ts.
  const pinFrozen = Boolean(anchor?.pinFrozenAt);
  const attested = anchored && anchorIsSigned() && !pinFrozen;
  const segments = new Set(anchor?.segments ?? []);

  const totalSpans   = (db.prepare(`SELECT COUNT(*) AS c FROM spans`).get() as { c: number }).c;
  const chainedSpans = (db.prepare(`SELECT COUNT(*) AS c FROM spans WHERE chainSeq IS NOT NULL`).get() as { c: number }).c;
  const tombstones   = (db.prepare(`SELECT COUNT(*) AS c FROM span_chain_tombstones`).get() as { c: number }).c;
  let checkedHashes = 0;
  let legacyFieldRows = 0;

  const out = (status: SpanChainVerdict, detail: string, extra: Partial<SpanChainStatus> = {}): SpanChainStatus => ({
    ok: status === 'ok' || status === 'unchained',
    status,
    detail,
    totalSpans,
    chainedSpans,
    unchainedSpans: totalSpans - chainedSpans,
    tombstones,
    checkedHashes,
    legacyFieldRows,
    deep,
    expectedRows: anchor ? anchor.appended : undefined,
    attested,
    ...(anchor?.pinBreaks ? { anchorPinBreaks: anchor.pinBreaks } : {}),
    ...(anchor?.pinFrozenAt ? { pinFrozenAt: anchor.pinFrozenAt, pinFrozenSeq: anchor.pinFrozenId } : {}),
    signed: isAuditSigned(),
    keyId: auditKeyId(),
    backfillComplete: spanChainBackfillComplete(),
    mutableFieldFixComplete: spanChainMutableFieldFixComplete(),
    ...extra,
  });

  if (chainedSpans === 0 && tombstones === 0) {
    if (anchored && anchor!.appended > 0) {
      return out('wiped', `The anchor accounts for ${anchor!.appended} chained span(s); none remain and not one tombstone explains where they went.`);
    }
    return out('unchained', totalSpans > 0
      ? `${totalSpans} span(s) are stored but none carry a chain position — run the backfill to bring them under the chain.`
      : 'No spans stored.');
  }

  // Ordered walk over live rows and tombstones. Only the chain columns are read,
  // so this stays index-and-integer cheap even at hundreds of thousands of rows.
  const walk = db.prepare(`
    SELECT chainSeq AS seq, prevHash, rowHash, 0 AS tomb FROM spans WHERE chainSeq IS NOT NULL
    UNION ALL
    SELECT chainSeq AS seq, prevHash, rowHash, 1 AS tomb FROM span_chain_tombstones
    ORDER BY seq ASC
  `);

  let prevSeq  = -1;
  let prevHash = '';
  let lastSeq  = 0;
  let lastHash = '';
  // The hash currently stored at the position the anchor pinned. Picked up
  // during the walk we are already doing, so checking the pin at its own
  // position — rather than only when it happens to be the last row — costs one
  // integer comparison per row and no extra query.
  let pinnedHash: string | undefined;
  const pinnedSeq = anchor?.lastId ?? 0;
  let n = 0;
  for (const raw of walk.iterate()) {
    const row = raw as { seq: number; prevHash: string; rowHash: string; tomb: number };
    if (row.seq === pinnedSeq) pinnedHash = row.rowHash;
    if (prevSeq >= 0) {
      if (row.seq !== prevSeq + 1) {
        return out('unaccounted_gap', `Chain position ${prevSeq + 1} is missing and no tombstone accounts for it — ${row.seq - prevSeq - 1} span(s) were deleted outside this server.`, { brokenAtSeq: prevSeq + 1 });
      }
      if (row.prevHash !== prevHash && !segments.has(row.seq)) {
        return out('link_mismatch', `Chain position ${row.seq} does not link to position ${prevSeq}.`, { brokenAtSeq: row.seq });
      }
    }
    prevSeq  = row.seq;
    prevHash = row.rowHash;
    lastSeq  = row.seq;
    lastHash = row.rowHash;
    if ((++n % 20_000) === 0) await new Promise(resolve => setTimeout(resolve, 0));
  }

  // Content check. Each rowHash is a function of the row's own fields and its
  // STORED prevHash, so any subset can be re-derived independently — which is
  // what makes a windowed check meaningful rather than a token gesture.
  const contentRows = deep
    ? db.prepare(
        `SELECT chainSeq, spanId, traceId, parentId, name, protocol, reason, severity, harness,
                attributes, startNano, endNano, repo, principal, agent_identity, delegation_id,
                prevHash, rowHash
           FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq ASC`,
      )
    : db.prepare(
        `SELECT chainSeq, spanId, traceId, parentId, name, protocol, reason, severity, harness,
                attributes, startNano, endNano, repo, principal, agent_identity, delegation_id,
                prevHash, rowHash
           FROM spans WHERE chainSeq IS NOT NULL ORDER BY chainSeq DESC LIMIT ${window}`,
      );

  let m = 0;
  for (const raw of contentRows.iterate()) {
    const r = raw as ChainableSpan & { chainSeq: number; prevHash: string; rowHash: string };
    checkedHashes++;
    // Current scheme first — every row inserted since this fix, and every row
    // this migration has already repaired, verifies here regardless of what
    // endNano/repo have done since. Rows still on the legacy (pre-fix) scheme
    // fall through to the second check: their endNano/repo happen to still
    // match what they were hashed with, which is expected and not a defect,
    // just not a guarantee that holds if those fields move again.
    if (computeRowHash(spanCanonical(r), r.prevHash) === r.rowHash) {
      // ok
    } else if (computeRowHash(spanCanonicalLegacy(r), r.prevHash) === r.rowHash) {
      legacyFieldRows++;
    } else {
      // Fails both. Before the fix this was indistinguishable from tampering —
      // it was, in fact, this server's own write path mutating endNano/repo
      // after hashing. After the fix (and once repairSpanChainMutableFields has
      // run — see mutableFieldFixComplete) neither field is hashed at all, so a
      // row that still can't be reconciled under either scheme is no longer
      // explained by our own write path. `mutableFieldFixComplete` in the
      // response is what separates "known, already-being-repaired self-
      // mutation" from "something we cannot explain": true here means this
      // break was NOT already accounted for by the migration and warrants
      // treating as tampering; false means the repair simply has not reached
      // this row yet.
      const cause = spanChainMutableFieldFixComplete()
        ? 'This is not explained by the endNano/repo mutation this server is known to make — its content was changed by something else after it was recorded.'
        : 'The endNano/repo mutation-repair migration has not reached this row yet (mutableFieldFixComplete=false); re-check after it completes before treating this as tampering.';
      return out('row_mismatch', `Span at chain position ${r.chainSeq} (spanId ${r.spanId}) no longer hashes to its stored value under either canonical scheme. ${cause}`, { brokenAtSeq: r.chainSeq });
    }
    if ((++m % 5_000) === 0) await new Promise(resolve => setTimeout(resolve, 0));
  }

  // Boundary checks against the signed anchor.
  if (!anchored) {
    return out('anchor_missing', 'Spans are chained but no signed anchor accounts for them, so the number of spans and the end of the chain cannot be checked.');
  }
  // Every chain position ever issued is either still a span or a tombstone.
  const expected = anchor!.appended;
  const present  = chainedSpans + tombstones;
  if (present < expected) {
    return out('truncated', `The anchor accounts for ${expected} chained span(s); ${present} remain (live plus tombstoned). ${expected - present} were removed outside this server.`);
  }
  if (anchor!.lastRowHash) {
    if (lastSeq < anchor!.lastId) {
      return out('truncated', `The anchor pins chain position ${anchor!.lastId} as the newest; the chain ends at ${lastSeq}. The end of the record was cut off.`);
    }
    // Checked AT THE PINNED POSITION, not only when the pin happens to be the
    // last row. The old form (`lastSeq === anchor.lastId`) silently checked
    // nothing the moment one more span landed, which — together with an anchor
    // that re-pinned unconditionally — let a rewritten and re-threaded history
    // verify clean without any key at all.
    if (pinnedHash === undefined) {
      return out('truncated', `The anchor pins chain position ${anchor!.lastId}, which is neither a live span nor a tombstone.`, { brokenAtSeq: anchor!.lastId });
    }
    if (pinnedHash !== anchor!.lastRowHash) {
      return out('tail_mismatch', `Chain position ${anchor!.lastId} carries a different hash than the anchor recorded — the record was rewritten and re-threaded beneath the anchor.`, { brokenAtSeq: anchor!.lastId });
    }
  } else {
    // Positions are accounted for, but the anchor holds no hash to check any of
    // them against. That is a verifier with nothing to compare to, not a pass.
    return out('tail_unpinned', `The anchor accounts for ${expected} chain position(s) but pins no tail hash, so the end of the chain cannot be checked at all.`);
  }
  if (pinFrozen) {
    return out('tail_mismatch', `The anchor stopped advancing at chain position ${anchor!.pinFrozenId ?? anchor!.lastId} (${anchor!.pinFrozenAt}) because the state it had pinned no longer verified. Nothing recorded since is covered by a signed boundary.`, { brokenAtSeq: anchor!.pinFrozenId ?? anchor!.lastId });
  }
  if (!attested) {
    return out('anchor_unsigned', 'The spans chain is internally consistent, but the anchor is unsigned or its signature does not verify — its boundaries cannot be trusted.');
  }

  // A chain that verifies today but whose anchor once refused to advance is not
  // the same thing as a chain that was never disturbed, so the count is said out
  // loud rather than left in a field nobody reads.
  const priorBreaks = anchor!.pinBreaks
    ? ` The anchor has refused to advance ${anchor!.pinBreaks} time(s) in the past (see anchorPinBreaks): this chain verifies now, but it did not always.`
    : '';
  return out('ok', `Chain intact across ${chainedSpans} live span(s) and ${tombstones} tombstone(s); ${checkedHashes} content hash(es) recomputed${deep ? '' : ' (windowed — pass deep=1 for all of them)'}, of which ${legacyFieldRows} verify only under the pre-fix scheme and are not protected against a future endNano/repo edit.${priorBreaks} Detection only — this is not proof that every event was recorded.`);
}

// ---------------------------------------------------------------------------
// Online binary backups
// ---------------------------------------------------------------------------
// A real, consistent copy of the live database — better-sqlite3's online backup
// API snapshots the file safely while it is open and being written, which a
// plain file copy cannot guarantee under WAL. This is DISTINCT from the hourly
// JSON auto-export (a human-readable logical dump in server/index.ts): this is a
// byte-for-byte .db a user can drop straight back in to restore.
//
// Backups land in <DB dir>/backups/ (i.e. ~/.claudesec/backups), 0600, and are
// pruned to the most recent N. Fail-open by contract — a backup must never crash
// or stall the server, so every caller wraps this and ignores a rejection.

const BACKUP_DIR = path.join(path.dirname(DB_PATH), 'backups');
const BACKUP_RETAIN = 7;

/**
 * Write a timestamped online backup of the live DB into ~/.claudesec/backups and
 * prune to the last BACKUP_RETAIN copies. Resolves to the backup path on success.
 * Never throws synchronously; rejects on failure so the (fail-open) caller can
 * log and move on.
 */
export async function backupDatabase(): Promise<string> {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const target = path.join(BACKUP_DIR, `spans-${stamp}.db`);

  // better-sqlite3's backup() returns a promise and copies the DB safely while
  // it is live (handles WAL + concurrent writes, unlike a raw file copy).
  await db.backup(target);

  // Owner-only — a backup must never be more readable than its source DB (0600).
  try { fs.chmodSync(target, 0o600); } catch {}

  // Retain only the most recent BACKUP_RETAIN backups; drop the rest.
  try {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('spans-') && f.endsWith('.db'))
      .sort()       // ISO timestamps sort lexically == chronologically
      .reverse();
    for (const old of files.slice(BACKUP_RETAIN)) {
      try { fs.rmSync(path.join(BACKUP_DIR, old), { force: true }); } catch {}
    }
  } catch {
    // Pruning is best-effort; a full backups dir is preferable to a thrown error.
  }
  return target;
}

/**
 * Flush the WAL back into the main DB file and close the handle cleanly. Called
 * from the graceful-shutdown path so launchd/Docker stopping the process can't
 * leave a half-applied WAL behind. Idempotent and fail-open — a checkpoint or
 * close error on the way down must not stop the process from exiting.
 */
export function checkpointAndClose(): void {
  // Seal the tail anchor before the handle goes away. Anchor writes are debounced
  // on the hot path, so without this a clean shutdown could leave the last second
  // of appends unsealed — they would still verify, just as rows newer than the
  // last checkpoint rather than as attested ones.
  try { flushChainAnchors(); } catch {}
  try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
  try { db.close(); } catch {}
}
