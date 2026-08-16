/**
 * tests/spanChainMutableFieldTest.ts
 *
 * Regression gate for the defect this fix exists to close: `endNano` and `repo`
 * are set on a span AFTER it is inserted, through this server's own database
 * handle, and the pre-fix chain hashed both at insert time — so finishing a
 * tool call (or resolving its repository) broke the very row that recorded it.
 * Deep verify on the live database read this back as `row_mismatch`,
 * indistinguishable from tampering, on every span that had ever closed.
 *
 * This file did not exist before the fix. Had it, case 1 below would have
 * failed the day `updateSpanEnd` first ran against a chained span.
 *
 *   1. Insert → close endNano through the EXACT SQL server/index.ts uses on the
 *      transcript-watcher 'end' path → deep verify still says ok. (The bug.)
 *   2. Insert → resolve repo through the EXACT SQL server/repoIdentity.ts uses
 *      → deep verify still says ok. (The other half of the same bug.)
 *   3. A row hashed under the PRE-FIX scheme (endNano/repo included) still
 *      verifies today, via the legacy fallback — old history is not discarded.
 *   4. Mutating endNano on a pre-fix-hashed row breaks it under BOTH schemes —
 *      proving the legacy fallback does not silently paper over a real defect,
 *      it only covers rows that were never mutated after hashing.
 *   5. repairSpanChainMutableFields() finds exactly that break, repairs it and
 *      everything chained after it, and the chain verifies clean again without
 *      rewriting anything that didn't need it.
 *   6. The repair is idempotent: a second run does nothing.
 *
 * Fully sandboxed: CLAUDESEC_DB, CLAUDESEC_HOME and HOME all point into a
 * throwaway directory under os.tmpdir(), set BEFORE any server module is
 * imported. The live spans DB is never opened.
 *
 * Run via:  npx tsx tests/spanChainMutableFieldTest.ts
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-span-mutable-'));
process.env.CLAUDESEC_DB   = path.join(TMP, 'spans.db');
process.env.CLAUDESEC_HOME = path.join(TMP, '.claudesec');
process.env.HOME           = TMP;

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}
async function checkAsync(name: string, fn: () => Promise<void>): Promise<void> {
  try { await fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

function sampleSpan(i: number, overrides: Partial<Record<string, string>> = {}) {
  return {
    spanId:     `span-${i}`,
    traceId:    'trace-mutable',
    parentId:   '',
    name:       `Bash tool call ${i}`,
    protocol:   'HTTPS',
    reason:     'Processing step',
    severity:   'none',
    harness:    'claude-code',
    attributes: JSON.stringify({ command: `echo ${i}`, cwd: '/work' }),
    startNano:  String(1_000_000_000_000n + BigInt(i)),
    // Mirrors real ingest: a span is inserted BEFORE it has an end time.
    endNano:    '0',
    repo:       'unknown',
    ...overrides,
  };
}

async function main(): Promise<void> {
  const {
    db, insertChainedSpan, verifySpanChain, repairSpanChainMutableFields,
    spanChainMutableFieldFixComplete,
  } = await import('../server/db.js');
  const { canonicalString, computeRowHash, flushChainAnchors, recordChainSegment } = await import('../server/auditChain.js');

  // The EXACT statements the real write paths issue — copied verbatim so a
  // change to either callsite that reintroduces the bug shows up here too.
  const updateSpanEndLikeIndexTs = db.prepare(`UPDATE spans SET endNano = ? WHERE spanId = ?`);
  const updateSpanRepoLikeRepoIdentityTs = db.prepare(`UPDATE spans SET repo = ? WHERE spanId = ?`);

  // ── Case 1: the endNano defect, through the real code path ───────────────
  await checkAsync('case1: insert then close endNano still verifies', async () => {
    const rec = sampleSpan(1);
    const { changes } = insertChainedSpan(rec);
    assert.strictEqual(changes, 1);

    // The tool call finishes: exactly what the transcript watcher's 'end'
    // event handler does in server/index.ts.
    updateSpanEndLikeIndexTs.run('2000000000000', rec.spanId);
    flushChainAnchors();

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.legacyFieldRows, 0, 'a freshly-inserted row must verify under the CURRENT scheme, not fall back to legacy');

    const stored = db.prepare(`SELECT endNano FROM spans WHERE spanId = ?`).get(rec.spanId) as { endNano: string };
    assert.strictEqual(stored.endNano, '2000000000000', 'the mutation itself still has to actually happen');
  });

  // ── Case 2: the repo defect, through the real code path ──────────────────
  await checkAsync('case2: insert then resolve repo still verifies', async () => {
    const rec = sampleSpan(2);
    insertChainedSpan(rec);

    // Repo resolves later: exactly what server/repoIdentity.ts's per-trace
    // `settle` and startup backfill both do.
    updateSpanRepoLikeRepoIdentityTs.run('/home/user/code/my-repo', rec.spanId);
    flushChainAnchors();

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);

    const stored = db.prepare(`SELECT repo FROM spans WHERE spanId = ?`).get(rec.spanId) as { repo: string };
    assert.strictEqual(stored.repo, '/home/user/code/my-repo');
  });

  // ── Seed a pre-fix (legacy-scheme) chain segment ──────────────────────────
  // Simulates what an install that ran the OLD server already has on disk:
  // rows hashed with endNano/repo baked in, at their FINAL values (the shape a
  // startup backfill produces once a span has stopped changing).
  const legacyCanonical = (chainSeq: number, s: ReturnType<typeof sampleSpan>) =>
    canonicalString([
      chainSeq, s.spanId, s.traceId, s.parentId, s.name, s.protocol, s.reason,
      s.severity, s.harness, s.attributes, s.startNano, s.endNano, s.repo,
      null, null, null,
    ]);

  const insertLegacyRaw = db.prepare(`
    INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness,
                        attributes, startNano, endNano, repo, chainSeq, prevHash, rowHash)
    VALUES (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness,
            @attributes, @startNano, @endNano, @repo, @chainSeq, @prevHash, @rowHash)
  `);

  // Continue from whatever the chain's real tail already is (cases 1 and 2
  // above already advanced it) — this segment must not collide with existing
  // chain positions.
  const legacyStart = (db.prepare(`SELECT COALESCE(MAX(chainSeq), 0) AS m FROM spans`).get() as { m: number }).m;
  let legacyTailSeq = legacyStart;
  let legacyTailHash = '';
  const LEGACY_ROWS = 20;
  // A deliberate new segment (prevHash='' at legacyStart+1), exactly the
  // shape a real backfill reserves for pre-existing rows — recorded so the
  // link walk knows this restart is by design, not a severed chain.
  recordChainSegment('spans', legacyStart + 1);
  {
    let prev = '';
    for (let i = 0; i < LEGACY_ROWS; i++) {
      const seq = legacyStart + i + 1;
      const rec = sampleSpan(1000 + i, { endNano: '9999999999', repo: 'demo-repo' });
      const rowHash = computeRowHash(legacyCanonical(seq, rec), prev);
      insertLegacyRaw.run({ ...rec, chainSeq: seq, prevHash: prev, rowHash });
      prev = rowHash;
    }
    legacyTailSeq = legacyStart + LEGACY_ROWS;
    legacyTailHash = prev;
  }
  // Adopt this synthetic history as the anchor's baseline, the way
  // chainSpansBackfill's completion does for a real backfill.
  const { adoptChainBaseline } = await import('../server/auditChain.js');
  adoptChainBaseline('spans', { rows: LEGACY_ROWS, lastId: legacyTailSeq, lastRowHash: legacyTailHash });
  // Mark the position-backfill done so verifySpanChain doesn't report `unchained`.
  db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('spans.chain_v1', ?)`).run(new Date().toISOString());

  // ── Case 3: an intact legacy row verifies via the fallback ───────────────
  await checkAsync('case3: a never-mutated legacy row verifies via the legacy scheme', async () => {
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.legacyFieldRows, LEGACY_ROWS, 'every seeded row is legacy and none has been touched');
    assert.strictEqual(v.mutableFieldFixComplete, false, 'the repair has not run yet');
  });

  // ── Case 4: mutating endNano on a legacy row reproduces the original defect ─
  const brokenSeq = legacyStart + 10;
  await checkAsync('case4: mutating endNano on a legacy row breaks it under both schemes', async () => {
    const target = db.prepare(`SELECT spanId FROM spans WHERE chainSeq = ?`).get(brokenSeq) as { spanId: string };
    // The exact real-world trigger: the tool call this span represents
    // finishes late, after the row was already hashed at its final(-looking)
    // state — mirrors a span whose 'end' event arrives after a repo/backfill
    // pass already ran once.
    updateSpanEndLikeIndexTs.run('123456789', target.spanId);

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'row_mismatch');
    assert.strictEqual(v.brokenAtSeq, brokenSeq);
    // Every position after the break also fails, once reached, because their
    // prevHash still points at the now-invalid old hash — the repair's job is
    // exactly this cascade. Confirmed here by construction only; the repair
    // case below proves it's actually fixed.
  });

  // ── Case 5: the repair fixes exactly the break, forward ──────────────────
  await checkAsync('case5: repairSpanChainMutableFields repairs the break and everything after it', async () => {
    const beforeHashes = db.prepare(
      `SELECT chainSeq, rowHash FROM spans WHERE chainSeq < ? ORDER BY chainSeq`,
    ).all(brokenSeq) as Array<{ chainSeq: number; rowHash: string }>;

    const result = await repairSpanChainMutableFields({ chunkSize: 3 });
    assert.strictEqual(result.ran, true);
    // Everything from the break to the (seeded-chain) tail needed rewriting;
    // nothing before it did.
    assert.strictEqual(result.repaired, legacyTailSeq - brokenSeq + 1, `repaired ${result.repaired}`);

    const afterHashes = db.prepare(
      `SELECT chainSeq, rowHash FROM spans WHERE chainSeq < ? ORDER BY chainSeq`,
    ).all(brokenSeq) as Array<{ chainSeq: number; rowHash: string }>;
    assert.deepStrictEqual(afterHashes, beforeHashes, 'rows before the break must keep the hash they were originally written with');

    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.mutableFieldFixComplete, true);
    assert.strictEqual(spanChainMutableFieldFixComplete(), true);
  });

  // ── Case 6: the repair is idempotent ──────────────────────────────────────
  await checkAsync('case6: a second repair run is a no-op', async () => {
    const result = await repairSpanChainMutableFields({ chunkSize: 3 });
    assert.deepStrictEqual(result, { ran: false, rows: 0, repaired: 0 });
    assert.strictEqual((await verifySpanChain({ deep: true })).status, 'ok');
  });

  // ── Case 7: a mutation on an already-repaired (now current-scheme) row ──
  // stays invisible to the chain forever, same as case 1 — proving the repair
  // didn't just patch a one-time break but actually moved those rows onto the
  // scheme that never breaks on endNano/repo again.
  await checkAsync('case7: the repaired tail tolerates further endNano/repo edits', async () => {
    const target = db.prepare(`SELECT spanId FROM spans WHERE chainSeq = ?`).get(brokenSeq) as { spanId: string };
    updateSpanEndLikeIndexTs.run('555555555', target.spanId);
    updateSpanRepoLikeRepoIdentityTs.run('/some/other/repo', target.spanId);
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
  });
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  spanChainMutableFieldTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('spanChainMutableFieldTest crashed:', e);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    process.exit(1);
  });
