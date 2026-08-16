// repoIdentity.ts
//
// Derives a stable "repository identity" for every ingested span so activity can
// be grouped per git repository in the dashboard. Given an agent's working
// directory, we walk UP the filesystem to the nearest ancestor that contains a
// `.git` entry and treat that git-root as the repo. Spans that arrive without a
// resolvable cwd (e.g. OTLP traces from another machine) fall back to the cwd
// string unchanged.
//
// A cwd is not always there to work with, so identity is settled at two levels:
// per span from its cwd, and per TRACE from whichever sibling span had one (see
// attributeRepoForTrace). Only a span in a trace that never carried a cwd
// anywhere ends up at the literal 'unknown'.
//
// Design constraints (this runs on the span-ingest hot path):
//   • NEVER throws and NEVER hangs ingestion — every filesystem touch is wrapped
//     in try/catch and the upward walk is bounded. On any failure we fail open
//     and return the cwd (or 'unknown').
//   • Memoized — repeated spans from the same cwd resolve from a Map instead of
//     re-stat'ing the filesystem.
//   • Optionally scrubbed — when a ScrubOptions is supplied we apply the same
//     home-directory relativization the rest of the app uses for paths, so a
//     repo path is stored consistently (e.g. `~/code/myrepo`, `/Users/***/...`).

import fs from 'fs';
import path from 'path';
import type { Database, Statement } from 'better-sqlite3';
import { scrubText, type ScrubOptions } from './scrub.js';

// Upper bound on how far we climb the directory tree. A real repo root is found
// within a handful of levels; the cap is a guard against pathological inputs
// (deeply nested or adversarial paths) so the walk can never run unbounded.
const MAX_WALK_DEPTH = 40;

export const UNKNOWN_REPO = 'unknown';

// cwd → resolved repo. A local operator's agents run in a small, stable set of
// directories — but the cwd on an OTLP span is attacker-controlled input from a
// remote sender, so an unbounded map is a slow memory leak we hand out for free.
// Bounded FIFO, same as traceRepoCache below: the working set is tiny, so
// evicting the oldest entry costs at most one filesystem walk.
const repoCache = new Map<string, string>();
const REPO_CACHE_MAX = 5_000;

/**
 * Resolve the repository identity for an agent's working directory.
 *
 * @param cwd   The agent's working directory, or undefined when none was recorded.
 * @param opts  Optional scrub options; when supplied, the resolved path is run
 *              through the app's path relativization so it is stored scrubbed.
 * @returns     The git-root path containing `cwd`, else `cwd` unchanged, else
 *              the literal 'unknown'. Always scrubbed when `opts` is given.
 */
export function resolveRepo(cwd: string | undefined, opts?: ScrubOptions): string {
  if (!cwd || typeof cwd !== 'string' || cwd.trim() === '') return UNKNOWN_REPO;

  const cached = repoCache.get(cwd);
  if (cached !== undefined) return cached;

  const resolved = scrubMaybe(walkToGitRoot(cwd).path, opts);
  repoCache.set(cwd, resolved);
  if (repoCache.size > REPO_CACHE_MAX) {
    const oldest = repoCache.keys().next().value;
    if (oldest !== undefined) repoCache.delete(oldest);
  }
  return resolved;
}

interface GitRootResult {
  /** The resolved path: the git root when found, else `cwd` unchanged. */
  path: string;
  /** True only when a real `.git` entry was found on disk during the walk. */
  found: boolean;
}

/**
 * Walk up from `cwd` to the nearest ancestor containing a `.git` entry.
 *
 * Returns `{ path: <git-root>, found: true }` when a `.git` entry is located on
 * disk, else `{ path: cwd, found: false }` (fail-open) when no ancestor has one
 * or the path can't be inspected — e.g. a cwd that doesn't exist on this machine
 * (OTLP spans from elsewhere) or an already-scrubbed, home-redacted path.
 * Never throws; bounded depth.
 */
function walkToGitRoot(cwd: string): GitRootResult {
  try {
    // Only an absolute path can be checked against this machine's filesystem.
    // Resolving a relative or `~`-prefixed cwd would silently anchor it to the
    // SERVER's own working directory and attribute the span to ClaudeSec itself.
    if (!path.isAbsolute(cwd)) return { path: cwd, found: false };
    let dir = path.resolve(cwd);
    for (let depth = 0; depth < MAX_WALK_DEPTH; depth++) {
      // `.git` is a directory in a normal clone and a file in a worktree/submodule;
      // existsSync matches both. A single failing stat must not abort the walk.
      try {
        if (fs.existsSync(path.join(dir, '.git'))) return { path: dir, found: true };
      } catch {
        // ignore this level and keep climbing
      }
      const parent = path.dirname(dir);
      if (parent === dir) break; // reached filesystem root
      dir = parent;
    }
  } catch {
    // Fall through to the fail-open return below.
  }
  // No git root found (or cwd doesn't exist on disk) — keep the cwd as-is so the
  // dashboard still has a meaningful grouping key.
  return { path: cwd, found: false };
}

function scrubMaybe(value: string, opts?: ScrubOptions): string {
  if (!opts) return value;
  try { return scrubText(value, opts); } catch { return value; }
}

/** Test-only: clear the memoization cache between cases. */
export function _resetRepoCache(): void {
  repoCache.clear();
}

// ───────────────────────────────────────────────────────────────────────────
// Trace-level attribution
//
// A cwd is not enough on its own. The single largest span type — `llm_request`
// — never carries one, so resolving per-span from cwd alone parks the majority
// of an agent's activity at 'unknown' while its own siblings, in the SAME
// trace, know exactly which repository the work happened in. A trace is one
// agent session, so the repo is a property of the trace, not of the span.
//
// Two directions are needed because span order is not guaranteed:
//   • FORWARD  — a span with no usable cwd takes the repo its trace already has.
//   • BACKWARD — the first span that establishes a trace's repo settles it onto
//     the trace's earlier orphans, which may have been written minutes before.
//
// The result is PERSISTED on the row (not computed at read time) so every query,
// export and rollup sees the same value without joining back to the trace.
// ───────────────────────────────────────────────────────────────────────────

// traceId → repo, where UNKNOWN_REPO means "asked the DB, still nothing". The
// negative entry matters: it keeps a long unattributable trace from re-querying
// on every span. Bounded so a long-lived server can't grow it without limit.
const traceRepoCache = new Map<string, string>();
const TRACE_CACHE_MAX = 5_000;

/** Lazily-prepared per-database statements, keyed so tests can open many DBs. */
const traceStmts = new WeakMap<Database, { find: Statement; settle: Statement }>();

function stmtsFor(db: Database): { find: Statement; settle: Statement } {
  let s = traceStmts.get(db);
  if (!s) {
    s = {
      find: db.prepare(
        `SELECT repo FROM spans WHERE traceId = ? AND repo IS NOT NULL AND repo != '${UNKNOWN_REPO}' LIMIT 1`,
      ),
      settle: db.prepare(
        `UPDATE spans SET repo = ? WHERE traceId = ? AND (repo IS NULL OR repo = '${UNKNOWN_REPO}')`,
      ),
    };
    traceStmts.set(db, s);
  }
  return s;
}

function rememberTraceRepo(traceId: string, repo: string): void {
  traceRepoCache.set(traceId, repo);
  if (traceRepoCache.size > TRACE_CACHE_MAX) {
    const oldest = traceRepoCache.keys().next().value;
    if (oldest !== undefined) traceRepoCache.delete(oldest);
  }
}

/**
 * Settle the repository identity of a span against its trace, just before the
 * span is inserted.
 *
 * @param db       The spans database.
 * @param traceId  The span's trace.
 * @param repo     What `resolveRepo` derived from this span alone.
 * @returns        `repo` when it is already known, else the trace's repo, else
 *                 'unknown'. Never throws — on any error the input is returned
 *                 unchanged so ingestion proceeds.
 *
 * Runs on the ingest hot path: a hit costs one Map lookup, and the trace's
 * earlier orphans are swept exactly once, when its repo first becomes known.
 */
export function attributeRepoForTrace(db: Database, traceId: string, repo: string): string {
  if (!traceId || traceId === UNKNOWN_REPO) return repo;
  try {
    if (repo && repo !== UNKNOWN_REPO) {
      // First span to pin this trace (or a trace that moved): claim it and sweep
      // whatever landed earlier with no cwd of its own.
      if (traceRepoCache.get(traceId) !== repo) {
        rememberTraceRepo(traceId, repo);
        stmtsFor(db).settle.run(repo, traceId);
      }
      return repo;
    }

    const cached = traceRepoCache.get(traceId);
    if (cached !== undefined) return cached;

    const row = stmtsFor(db).find.get(traceId) as { repo: string } | undefined;
    const found = row?.repo || UNKNOWN_REPO;
    rememberTraceRepo(traceId, found);
    return found;
  } catch {
    // Fail open: an attribution problem must never cost us the span.
    return repo;
  }
}

/** Test-only: clear the trace→repo cache between cases. */
export function _resetTraceRepoCache(): void {
  traceRepoCache.clear();
}

// ───────────────────────────────────────────────────────────────────────────
// One-time startup backfill
//
// Existing rows predate the `repo` column and default to 'unknown'. This walks
// those rows, reads the `cwd` already stored in their attributes JSON, resolves
// the repo, and writes it back — so historical activity groups correctly in the
// dashboard without re-ingesting anything.
//
// DATA-SAFETY CONTRACT (this is the only code in this task that writes to the
// live DB on restart):
//   • Writes ONLY the `repo` column (UPDATE spans SET repo = ? WHERE spanId = ?)
//     — never touches attributes, severity, timestamps, or anything else.
//   • Idempotent: only scans rows where repo IS NULL OR repo = 'unknown', and
//     only updates a row when the resolved repo is a real value different from
//     'unknown'. A second run finds nothing left to do and is a no-op.
//   • Guarded: returns immediately when no candidate rows remain, so a
//     fully-backfilled DB pays only one cheap COUNT.
//   • Batched: processes rows in chunks inside short transactions so a large
//     historical table can't block startup or hold a long write lock.
//   • Fail-open: any error is swallowed; ingestion and the server proceed.
// ───────────────────────────────────────────────────────────────────────────

export interface BackfillResult {
  /** Candidate rows examined (rows whose repo is NULL or 'unknown'). */
  scanned: number;
  /** Rows written — or, in a dry run, rows that WOULD be written. */
  updated: number;
  /** Attributed by verifying the stored cwd against a real `.git` on disk. */
  fromGitRoot: number;
  /** Attributed from the stored cwd itself, unverifiable because it is scrubbed. */
  fromStoredPath: number;
  /** Attributed from another span in the same trace (rows with no usable cwd). */
  fromTraceSibling: number;
  /** Of the above stored-path rows, how many a trace sibling could also have fixed. */
  storedPathWithSibling: number;
  /** Candidates left at 'unknown' — no cwd and no sibling anywhere. */
  stillUnknown: number;
  /** Rows newly attributed, per repository. */
  byRepo: Record<string, number>;
  /** True when nothing was written. */
  dryRun: boolean;
}

export interface BackfillOptions {
  /** Report what WOULD change and write nothing. */
  dryRun?: boolean;
}

const BACKFILL_BATCH = 500;

export function backfillRepos(
  db: Database,
  opts?: ScrubOptions,
  log: (msg: string) => void = () => {},
  backfillOpts: BackfillOptions = {},
): BackfillResult {
  const dryRun = backfillOpts.dryRun === true;
  const result: BackfillResult = {
    scanned: 0, updated: 0, fromGitRoot: 0, fromStoredPath: 0, fromTraceSibling: 0,
    storedPathWithSibling: 0, stillUnknown: 0, byRepo: {}, dryRun,
  };
  try {
    // Guard: nothing to do if no row still carries the placeholder repo.
    const pending = db
      .prepare(`SELECT COUNT(*) AS c FROM spans WHERE repo IS NULL OR repo = '${UNKNOWN_REPO}'`)
      .get() as { c: number };
    if (!pending || pending.c === 0) return result;

    // The grouping keys live spans already use. A historical row whose scrubbed
    // cwd sits BELOW one of these belongs to that repository — folding it in is
    // what keeps one repo from being split across two keys.
    const knownRepos = new Set(
      (db
        .prepare(`SELECT DISTINCT repo FROM spans WHERE repo IS NOT NULL AND repo != '${UNKNOWN_REPO}'`)
        .all() as { repo: string }[]).map(r => r.repo),
    );
    // traceId → repo for every trace that already has one. Grown as we go, so a
    // row attributed in pass 1 can rescue its cwd-less siblings in pass 2.
    const traceRepos = new Map<string, string>();
    for (const r of db
      .prepare(`SELECT traceId, repo FROM spans WHERE repo IS NOT NULL AND repo != '${UNKNOWN_REPO}' GROUP BY traceId`)
      .all() as { traceId: string; repo: string }[]) {
      traceRepos.set(r.traceId, r.repo);
    }

    // Pull candidate rows in batches keyed by spanId so we can resume across
    // chunks deterministically. We only read spanId + traceId + attributes —
    // never write anything but the repo column below.
    const selectBatch = db.prepare(`
      SELECT spanId, traceId, attributes
      FROM spans
      WHERE (repo IS NULL OR repo = '${UNKNOWN_REPO}') AND spanId > ?
      ORDER BY spanId
      LIMIT ?
    `);
    // Surgical update: ONE column, ONE row, matched by primary key.
    const updateRepo = db.prepare(`UPDATE spans SET repo = ? WHERE spanId = ?`);

    type Row = { spanId: string; traceId: string; attributes: string };

    const record = (row: Row, repo: string): void => {
      if (!repo || repo === UNKNOWN_REPO) return;
      if (!dryRun) updateRepo.run(repo, row.spanId);
      if (row.traceId && !traceRepos.has(row.traceId)) traceRepos.set(row.traceId, repo);
      knownRepos.add(repo);
      result.updated++;
      result.byRepo[repo] = (result.byRepo[repo] ?? 0) + 1;
    };

    // ── Pass 1: rows that carry a cwd ───────────────────────────────────────
    // Prefer on-disk truth, then the grouping key an ancestor already owns, then
    // the trace, and finally the stored path itself. The stored cwd is almost
    // always ALREADY SCRUBBED (`/Users/***/code/myrepo/src`), so demanding a
    // `.git` walk over it — as this used to — can never succeed and stranded
    // real, well-identified activity at 'unknown'. An unverifiable path is still
    // a stable, honest grouping key, and it is exactly what live ingest stores
    // when resolveRepo fails open, so the two paths agree.
    const attributeWithCwd = (row: Row, cwd: string): void => {
      const onDisk = walkToGitRoot(cwd);
      if (onDisk.found) {
        result.fromGitRoot++;
        record(row, scrubMaybe(onDisk.path, opts));
        return;
      }
      const scrubbed = scrubMaybe(cwd, opts);
      const sibling = traceRepos.get(row.traceId);
      if (sibling) result.storedPathWithSibling++;

      result.fromStoredPath++;
      record(row, matchKnownRepo(scrubbed, knownRepos) ?? sibling ?? scrubbed);
    };

    const pass1 = (rows: Row[]) => {
      for (const row of rows) {
        result.scanned++;
        const cwd = extractCwd(row.attributes);
        if (cwd) attributeWithCwd(row, cwd);
      }
    };

    // ── Pass 2: rows with no cwd, rescued by a trace sibling ────────────────
    // `llm_request` spans never carry a cwd; their siblings do.
    const pass2 = (rows: Row[]) => {
      for (const row of rows) {
        if (extractCwd(row.attributes)) continue; // handled by pass 1
        const sibling = traceRepos.get(row.traceId);
        if (sibling) {
          result.fromTraceSibling++;
          record(row, sibling);
        } else {
          result.stillUnknown++;
        }
      }
    };

    // A transaction per batch keeps the write lock short; a dry run takes none.
    const runPass = (handle: (rows: Row[]) => void) => {
      const batched = dryRun ? handle : db.transaction(handle);
      let cursor = '';
      for (;;) {
        const rows = selectBatch.all(cursor, BACKFILL_BATCH) as Row[];
        if (rows.length === 0) break;
        batched(rows);
        cursor = rows[rows.length - 1].spanId;
        if (rows.length < BACKFILL_BATCH) break;
      }
    };

    runPass(pass1);
    runPass(pass2);

    if (result.updated > 0) {
      log(
        `[repo] ${dryRun ? 'would backfill' : 'backfilled'} repo for ${result.updated} of ` +
        `${result.scanned} span(s) — ${result.fromGitRoot} from a git root, ` +
        `${result.fromStoredPath} from the stored path, ${result.fromTraceSibling} from a trace sibling`,
      );
    }
  } catch {
    // Fail-open: never let a backfill error block startup or ingestion.
  }
  return result;
}

/**
 * Find the known grouping key that `cwd` sits under (or equals).
 *
 * Walks the stored path upward as plain strings — no filesystem touch, because
 * a scrubbed path has none to touch. Returns undefined when no ancestor is a
 * repository we already know about.
 */
function matchKnownRepo(cwd: string, knownRepos: Set<string>): string | undefined {
  let dir = cwd;
  for (let depth = 0; depth < MAX_WALK_DEPTH; depth++) {
    if (knownRepos.has(dir)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

/** Pull the `cwd` out of a stored attributes JSON string. Never throws. */
function extractCwd(attributes: string): string | undefined {
  try {
    const obj = JSON.parse(attributes) as Record<string, unknown>;
    const cwd = obj?.['cwd'];
    return typeof cwd === 'string' && cwd ? cwd : undefined;
  } catch {
    return undefined;
  }
}
