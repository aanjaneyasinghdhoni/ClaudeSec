// server/enforceLogStore.ts
//
// Persisted, tamper-evident store for the PreToolUse enforcement/block feed.
// Replaces the old in-memory ring buffer (which vanished on restart) with a
// capped SQLite table that carries the same hash chain as the operator audit
// log (server/auditChain.ts). The dashboard's Enforce feed reads through the
// same append/read API, so its contract is unchanged — it just survives restart.
//
// SECURITY / SAFETY:
//   • Inserts are fail-open: a hashing or DB error must never break the
//     enforcement path (the hook is mid-flight and fails open by contract).
//   • Inserts are O(1): the tail rowHash is cached, so chaining never rescans.
//   • Growth is bounded: the oldest rows are pruned once the table passes the cap.

import { db } from './db.js';
import {
  canonicalString, chainReadError, computeRowHash, reanchorChain, verifyChain,
  type ChainStatus,
} from './auditChain.js';
import type { EnforceLogEvent } from './routes/context.js';

// Keep the most recent N enforcement events — matches the old ring-buffer size.
export const ENFORCE_LOG_MAX = 500;

const insertEnforce = db.prepare(`
  INSERT INTO enforce_log (ts, mode, label, severity, command, wouldBlock, blocked, prevHash, rowHash)
  VALUES (@ts, @mode, @label, @severity, @command, @wouldBlock, @blocked, @prevHash, @rowHash)
`);

const countEnforce = db.prepare(`SELECT COUNT(*) AS c FROM enforce_log`);
const pruneEnforce = db.prepare(
  `DELETE FROM enforce_log WHERE id IN (
     SELECT id FROM enforce_log ORDER BY id ASC LIMIT ?
   )`,
);
// After a prune, the new-oldest surviving row's prevHash points at a now-deleted
// row, so the retained chain won't verify from a fresh '' seed. Re-anchor it:
// re-thread every surviving row from prevHash='' (see reanchorChain).
const selectEnforceSurvivors = db.prepare(
  `SELECT id, ts, mode, label, severity, command, wouldBlock, blocked, rowHash
     FROM enforce_log ORDER BY id ASC`,
);
const updateEnforceHashes = db.prepare(
  `UPDATE enforce_log SET prevHash = @prevHash, rowHash = @rowHash WHERE id = @id`,
);

/**
 * Prune the oldest `excess` rows, then re-anchor the retained chain so it verifies
 * standalone, all in one transaction so a verify never sees a half-pruned state.
 * Returns the new tail rowHash so the O(1) insert cache can be refreshed.
 */
const pruneAndReanchor = db.transaction((excess: number): string => {
  pruneEnforce.run(excess);
  const survivors = selectEnforceSurvivors.all() as Array<{
    id: number; ts: number; mode: string; label: string; severity: string;
    command: string; wouldBlock: number; blocked: number; rowHash: string;
  }>;
  return reanchorChain(
    survivors.map(r => ({ id: r.id, rowHash: r.rowHash, canonical: enforceCanonical(r) })),
    (id, prevHash, rowHash) => updateEnforceHashes.run({ id, prevHash, rowHash }),
  );
});
const readRecent = db.prepare(
  `SELECT ts, mode, label, severity, command, wouldBlock, blocked
     FROM enforce_log ORDER BY id DESC LIMIT ?`,
);

// O(1) inserts: cache the tail rowHash so each insert links without a rescan.
// Seeded lazily from the DB on first use (covers a restart over an existing log).
let lastRowHash: string | undefined;

function tailRowHash(): string {
  if (lastRowHash !== undefined) return lastRowHash;
  try {
    const row = db
      .prepare(`SELECT rowHash FROM enforce_log ORDER BY id DESC LIMIT 1`)
      .get() as { rowHash?: string } | undefined;
    lastRowHash = row?.rowHash ?? '';
  } catch {
    lastRowHash = '';
  }
  return lastRowHash;
}

// Fixed canonical field order for an enforce row — the hash-chain contract. The
// auto-increment id is unknown before insert, so it is NOT hashed; booleans are
// normalized to 0/1 to match how they round-trip through SQLite on verify.
function enforceCanonical(e: {
  ts: number; mode: string; label: string; severity: string; command: string;
  wouldBlock: boolean | number; blocked: boolean | number;
}): string {
  return canonicalString([
    e.ts, e.mode, e.label, e.severity, e.command,
    e.wouldBlock ? 1 : 0, e.blocked ? 1 : 0,
  ]);
}

/**
 * Persist one enforcement event, hash-chained to the previous row, then prune to
 * the cap. Fail-open: any error is swallowed so the enforcement path is never
 * broken by a logging failure.
 */
export function appendEnforceLog(evt: EnforceLogEvent): void {
  try {
    const row = {
      ts:         evt.ts,
      mode:       evt.mode,
      label:      evt.label,
      severity:   evt.severity,
      command:    evt.command,
      wouldBlock: evt.wouldBlock ? 1 : 0,
      blocked:    evt.blocked ? 1 : 0,
    };
    const prevHash = tailRowHash();
    const rowHash  = computeRowHash(enforceCanonical(row), prevHash);
    insertEnforce.run({ ...row, prevHash, rowHash });
    // Advance the cached tail only when the hash actually computed. A one-off
    // crypto failure fails-open to '' (see computeRowHash); caching that would
    // chain the next row onto '' and report the chain broken from here on. Leaving
    // the cache untouched re-links the next insert to the last good hash.
    if (rowHash !== '') lastRowHash = rowHash;

    // Prune past the cap, then re-anchor the survivors so the retained chain still
    // verifies, and refresh the tail cache from the re-threaded tail.
    const count = (countEnforce.get() as { c: number }).c;
    if (count > ENFORCE_LOG_MAX) {
      lastRowHash = pruneAndReanchor(count - ENFORCE_LOG_MAX);
    }
  } catch {
    /* never let enforce-log persistence break the enforcement path */
  }
}

/** Read the most-recent N events, newest first — same shape the feed always returned. */
export function readEnforceLog(limit: number): EnforceLogEvent[] {
  try {
    const n = Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 100;
    const rows = readRecent.all(n) as Array<{
      ts: number; mode: string; label: string; severity: string; command: string;
      wouldBlock: number; blocked: number;
    }>;
    return rows.map(r => ({
      ts:         r.ts,
      mode:       r.mode,
      label:      r.label,
      severity:   r.severity,
      command:    r.command,
      wouldBlock: !!r.wouldBlock,
      blocked:    !!r.blocked,
    }));
  } catch {
    return [];
  }
}

/** Total persisted event count. */
export function enforceLogCount(): number {
  try {
    return (countEnforce.get() as { c: number }).c;
  } catch {
    return 0;
  }
}

/** Count of events newer than `sinceMs` ago — used by the settings snapshot. */
export function enforceLogRecentCount(windowMs: number): number {
  try {
    const cutoff = Date.now() - windowMs;
    return (
      db.prepare(`SELECT COUNT(*) AS c FROM enforce_log WHERE ts >= ?`).get(cutoff) as { c: number }
    ).c;
  } catch {
    return 0;
  }
}

/**
 * Verify the enforce log's hash chain end-to-end. O(n). Legacy rows with empty
 * hashes are skipped cleanly. Fail-open: reports ok:false on error rather than
 * throwing.
 */
export function verifyEnforceChain(): ChainStatus {
  try {
    const rows = db
      .prepare(
        `SELECT id, ts, mode, label, severity, command, wouldBlock, blocked, prevHash, rowHash
           FROM enforce_log ORDER BY id ASC`,
      )
      .all() as Array<{
        id: number; ts: number; mode: string; label: string; severity: string;
        command: string; wouldBlock: number; blocked: number; prevHash: string; rowHash: string;
      }>;
    return verifyChain(
      rows.map(r => ({
        id: r.id,
        prevHash: r.prevHash,
        rowHash: r.rowHash,
        canonical: enforceCanonical(r),
      })),
      // Capped log — see the note in server/auditLog.ts on why the cap is all
      // the deletion bookkeeping a pruned-on-insert table needs.
      { chain: 'enforce_log', cap: ENFORCE_LOG_MAX },
    );
  } catch (e) {
    return chainReadError(`The enforcement feed could not be read for verification: ${(e as Error).message}`);
  }
}
