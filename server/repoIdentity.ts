// repoIdentity.ts
//
// Derives a stable "repository identity" for every ingested span so activity can
// be grouped per git repository in the dashboard. Given an agent's working
// directory, we walk UP the filesystem to the nearest ancestor that contains a
// `.git` entry and treat that git-root as the repo. Spans that arrive without a
// resolvable cwd (e.g. OTLP traces from another machine) fall back to the cwd
// string unchanged, or the literal 'unknown' when there is no cwd at all.
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
import type { Database } from 'better-sqlite3';
import { scrubText, type ScrubOptions } from './scrub.js';

// Upper bound on how far we climb the directory tree. A real repo root is found
// within a handful of levels; the cap is a guard against pathological inputs
// (deeply nested or adversarial paths) so the walk can never run unbounded.
const MAX_WALK_DEPTH = 40;

export const UNKNOWN_REPO = 'unknown';

// cwd → resolved repo. Unbounded growth is not a concern: the number of distinct
// working directories an operator's agents run in is small and stable.
const repoCache = new Map<string, string>();

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
  scanned: number;
  updated: number;
}

const BACKFILL_BATCH = 500;

export function backfillRepos(
  db: Database,
  opts?: ScrubOptions,
  log: (msg: string) => void = () => {},
): BackfillResult {
  const result: BackfillResult = { scanned: 0, updated: 0 };
  try {
    // Guard: nothing to do if no row still carries the placeholder repo.
    const pending = db
      .prepare(`SELECT COUNT(*) AS c FROM spans WHERE repo IS NULL OR repo = 'unknown'`)
      .get() as { c: number };
    if (!pending || pending.c === 0) return result;

    // Pull candidate rows in batches keyed by spanId so we can resume across
    // chunks deterministically. We only read spanId + attributes — never write
    // anything but the repo column below.
    const selectBatch = db.prepare(`
      SELECT spanId, attributes
      FROM spans
      WHERE (repo IS NULL OR repo = 'unknown') AND spanId > ?
      ORDER BY spanId
      LIMIT ?
    `);
    // Surgical update: ONE column, ONE row, matched by primary key.
    const updateRepo = db.prepare(`UPDATE spans SET repo = ? WHERE spanId = ?`);

    const runBatch = db.transaction((rows: { spanId: string; attributes: string }[]) => {
      for (const row of rows) {
        result.scanned++;
        const cwd = extractCwd(row.attributes);
        if (!cwd) continue;

        // CONSISTENCY: the stored `attributes.cwd` is the SCRUBBED path (e.g.
        // `/Users/***/code/myrepo/src`), so a `.git` walk over it cannot reach
        // the real repo on disk. We only backfill rows whose stored cwd is a
        // genuinely resolvable, on-disk git root — i.e. unscrubbed cwds such as
        // OTLP spans that carried a plain path. For scrubbed rows the walk fails
        // (`found === false`) and we deliberately leave `repo` as 'unknown'
        // rather than write a subdirectory key that would NOT match how live
        // spans for the same repo are grouped (live resolves the raw cwd to the
        // git root, then scrubs). Leaving them 'unknown' is honest and avoids
        // splitting a repository's activity across two grouping keys.
        const result1 = walkToGitRoot(cwd);
        if (!result1.found) continue;

        const repo = scrubMaybe(result1.path, opts);
        if (repo && repo !== UNKNOWN_REPO) {
          updateRepo.run(repo, row.spanId);
          result.updated++;
        }
      }
    });

    let cursor = '';
    for (;;) {
      const rows = selectBatch.all(cursor, BACKFILL_BATCH) as {
        spanId: string;
        attributes: string;
      }[];
      if (rows.length === 0) break;
      runBatch(rows);
      cursor = rows[rows.length - 1].spanId;
      if (rows.length < BACKFILL_BATCH) break;
    }

    if (result.updated > 0) {
      log(`[repo] backfilled repo for ${result.updated} of ${result.scanned} span(s)`);
    }
  } catch {
    // Fail-open: never let a backfill error block startup or ingestion.
  }
  return result;
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
