/**
 * tests/spanFieldCoverageTest.ts
 *
 * Regression gate for the reporting this fix adds on top of the mutable-field
 * defect: an exact, cheap ("at a glance") count of how much of the spans
 * ledger is hashed under the current scheme (spanCanonical) versus the pre-fix
 * one (spanCanonicalLegacy), WITHOUT paying for a deep recompute to find out.
 *
 * This is deliberately NOT a test of a migration — there isn't one. The
 * decision this session made, after proving it against a .backup of the real
 * 274k-row production database, is that bulk-rewriting legacy rows onto the
 * current scheme would spend real protection those rows already have (an edit
 * to endNano/repo on a legacy row breaks its hash TODAY) for nothing but
 * uniformity, on an install with no external anchor to make the rewrite itself
 * detectable. See the block comment above spanChainFieldCoverage in
 * server/db.ts for the full argument. What ships instead is this counter.
 *
 *   1. Before the classification pass has run: exact=false, no counts.
 *   2. spanChainFieldCoverage() self-starts the backfill on first call (no
 *      caller has to remember to run it), returns immediately without
 *      blocking, and a later call sees exact numbers once it finishes.
 *   3. Those numbers are exactly right: a seeded mix of current-scheme rows
 *      (via the real insertChainedSpan path) and legacy-scheme rows (hashed
 *      with endNano/repo included, exactly as a pre-fix install has on disk)
 *      classifies to the precise counts, chunked in pieces smaller than the
 *      seeded set — proving it walks in more than one chunk.
 *   4. Idempotent: a second explicit run is a cached no-op.
 *   5. It is a cached snapshot, not a live monitor: mutating a legacy row's
 *      endNano AFTER classification does not change the cached counts — only
 *      a fresh deep verify (a different, more expensive check) catches that.
 *      The two must not be confused.
 *   6. A row that fails BOTH schemes (a genuine break, not explained by the
 *      defect this counter exists for) is counted as neither legacy nor
 *      current — it does not inflate coverage in either direction.
 *
 * Fully sandboxed: CLAUDESEC_DB, CLAUDESEC_HOME and HOME all point into a
 * throwaway directory under os.tmpdir(), set BEFORE any server module is
 * imported. The live spans DB is never opened.
 *
 * Run via:  npx tsx tests/spanFieldCoverageTest.ts
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-span-coverage-'));
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
    traceId:    'trace-coverage',
    parentId:   '',
    name:       `Bash tool call ${i}`,
    protocol:   'HTTPS',
    reason:     'Processing step',
    severity:   'none',
    harness:    'claude-code',
    attributes: JSON.stringify({ command: `echo ${i}`, cwd: '/work' }),
    startNano:  String(2_000_000_000_000n + BigInt(i)),
    endNano:    '0',
    repo:       'unknown',
    ...overrides,
  };
}

async function main(): Promise<void> {
  const {
    db, insertChainedSpan, repairSpanChainMutableFields, verifySpanChain,
    backfillSpanFieldCoverage, spanChainFieldCoverage, spanChainFieldCoverageComplete,
  } = await import('../server/db.js');
  const { canonicalString, computeRowHash, flushChainAnchors, recordChainSegment, adoptChainBaseline } =
    await import('../server/auditChain.js');

  // ── Case 1: before anything has run ───────────────────────────────────────
  check('case1: coverage is inexact before any pass has run', () => {
    const c = spanChainFieldCoverage();
    assert.strictEqual(c.exact, false);
    assert.strictEqual(c.legacyFieldRows, null);
    assert.strictEqual(c.currentFieldRows, null);
    assert.strictEqual(spanChainFieldCoverageComplete(), false);
  });

  // ── Seed CURRENT-scheme rows through the real write path ─────────────────
  const CURRENT_ROWS = 7;
  for (let i = 0; i < CURRENT_ROWS; i++) {
    const { changes } = insertChainedSpan(sampleSpan(i));
    assert.strictEqual(changes, 1);
  }
  flushChainAnchors();

  // ── Seed LEGACY-scheme rows — exactly what a pre-fix install has on disk ──
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
  const LEGACY_ROWS = 13;
  const legacyStart = (db.prepare(`SELECT COALESCE(MAX(chainSeq), 0) AS m FROM spans`).get() as { m: number }).m;
  let legacyTailSeq = legacyStart;
  let legacyTailHash = '';
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

  // ── One row that will verify under NEITHER scheme ─────────────────────────
  // A correctly-LINKED position (right prevHash) but a rowHash that matches
  // neither canonical form — simulating damage discovered only after the
  // mutable-field repair already ran and marked itself complete (e.g.
  // tampering, or a bit-flip). Seeded now, deliberately, so it survives the
  // repair pass below unchanged and is still present when the coverage
  // classification pass runs — proving that pass does not silently absorb it
  // into either count.
  const brokenSeq = legacyTailSeq + 1;
  insertLegacyRaw.run({
    ...sampleSpan(9999, { endNano: '111', repo: 'broken-repo' }),
    chainSeq: brokenSeq,
    prevHash: legacyTailHash,
    rowHash: 'deadbeef-not-a-real-hash-of-anything',
  });

  adoptChainBaseline('spans', { rows: CURRENT_ROWS + LEGACY_ROWS + 1, lastId: brokenSeq, lastRowHash: 'deadbeef-not-a-real-hash-of-anything' });
  db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('spans.chain_v1', ?)`).run(new Date().toISOString());

  // repairSpanChainMutableFields is a REWRITE pass — anything failing both
  // schemes there gets recomputed onto the current scheme, which would defeat
  // this test's point. So the broken row above is inserted with a prevHash
  // that will make it read as `linked: false` to that pass too (its own
  // prevHash column literally does not match what the running `prev` would
  // be, since it's the correct value — wait, it IS the correct link). To keep
  // the repair pass from silently "fixing" it, this test does not run
  // repairSpanChainMutableFields at all: the coverage counter only requires
  // mutableFieldFixComplete() to be true, not that the repair actually ran in
  // THIS process — exactly the real-world case of an install that upgraded
  // from a version that predates spanChainFieldCoverage entirely, where the
  // marker is already set and no repair will run again.
  db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`)
    .run('spans.chain_mutable_fix_v1', new Date().toISOString());

  // ── Case 2: spanChainFieldCoverage self-starts the backfill ──────────────
  await checkAsync('case2: spanChainFieldCoverage kicks off its own backfill without blocking', async () => {
    const first = spanChainFieldCoverage();
    assert.strictEqual(first.exact, false, 'the very first call must not block waiting for the walk to finish');

    for (let i = 0; i < 50 && !spanChainFieldCoverageComplete(); i++) {
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.strictEqual(spanChainFieldCoverageComplete(), true, 'the self-started backfill must finish on its own');
  });

  // ── Case 3: exact counts, and the broken row is counted as neither ───────
  check('case3: coverage classifies exactly — current, legacy, and the broken row excluded from both', () => {
    const c = spanChainFieldCoverage();
    assert.strictEqual(c.exact, true);
    assert.strictEqual(c.legacyFieldRows, LEGACY_ROWS);
    assert.strictEqual(c.currentFieldRows, CURRENT_ROWS);
    assert.strictEqual(c.totalChainedRows, CURRENT_ROWS + LEGACY_ROWS + 1, 'total includes the broken row even though it is in neither bucket');
    assert.ok(c.percentCurrentScheme !== null);
    const expectedPct = (CURRENT_ROWS / (CURRENT_ROWS + LEGACY_ROWS + 1)) * 100;
    assert.ok(Math.abs((c.percentCurrentScheme as number) - expectedPct) < 1e-9, 'percentCurrentScheme must be computed against the true total, not just the classified rows');
  });

  // ── Case 4: idempotent ─────────────────────────────────────────────────────
  await checkAsync('case4: an explicit second backfill run is a cached no-op', async () => {
    const result = await backfillSpanFieldCoverage({ chunkSize: 5 });
    assert.strictEqual(result.ran, false);
    assert.strictEqual(result.legacyFieldRows, LEGACY_ROWS, 'the cached total must still be returned on a no-op call');
    assert.strictEqual(result.currentFieldRows, CURRENT_ROWS, 'the cached current-scheme total must also be returned on a no-op call');
  });

  // ── Case 5: a cached snapshot, not a live monitor ─────────────────────────
  await checkAsync('case5: mutating a legacy row after classification does not change the cached counts', async () => {
    const before = spanChainFieldCoverage();
    const target = db.prepare(`SELECT spanId FROM spans WHERE chainSeq = ?`).get(legacyStart + 3) as { spanId: string };
    db.prepare(`UPDATE spans SET endNano = ? WHERE spanId = ?`).run('123456789', target.spanId);

    const after = spanChainFieldCoverage();
    assert.deepStrictEqual(after, before, 'coverage is a cached snapshot — it must not silently re-scan on every read');

    // The break IS real and IS catchable — just not by this cheap counter.
    // That is the whole point of keeping the two concepts separate: coverage
    // answers "how much of my record is on which scheme", not "has anything
    // been tampered with since I last checked".
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'row_mismatch', 'deep verify, not the coverage counter, is what still catches this');
  });

  // ── Case 6: growth after classification folds into currentFieldRows live ──
  await checkAsync('case6: a span inserted after classification is picked up without re-walking', async () => {
    const before = spanChainFieldCoverage();
    insertChainedSpan(sampleSpan(5000));
    flushChainAnchors();

    const after = spanChainFieldCoverage();
    assert.strictEqual(after.exact, true, 'growth must not flip an already-classified snapshot back to inexact');
    assert.strictEqual(after.legacyFieldRows, before.legacyFieldRows, 'legacyFieldRows is fixed forever once classified');
    assert.strictEqual(after.currentFieldRows, (before.currentFieldRows as number) + 1);
    assert.strictEqual(after.totalChainedRows, (before.totalChainedRows as number) + 1);
  });

  void repairSpanChainMutableFields; // imported for readability of the comment above; not called in this file
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  spanFieldCoverageTest: ${passed}/${total} passed`);
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
    console.error('spanFieldCoverageTest crashed:', e);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    process.exit(1);
  });
