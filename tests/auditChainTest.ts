/**
 * tests/auditChainTest.ts
 *
 * Gate for the tamper-evident hash chains on the two append-only logs:
 *   • operator_audit_log  (server/auditLog.ts  → verifyAuditChain)
 *   • enforce_log         (server/enforceLogStore.ts → verifyEnforceChain)
 *
 * Cases:
 *   1. Insert several audit rows → verifyAuditChain() is ok.
 *   2. Directly tamper a row's `detail` in the DB → verify reports broken AT that id.
 *   3. Enforce-log rows persist (re-read from a fresh module load) and chain-verify.
 *   4. Tampering an enforce row's `command` → verify reports broken at that id.
 *   5. Legacy rows (inserted with NO hash) don't break verification — the chain
 *      cleanly skips the unhashed prefix and validates only the hashed rows.
 *   6. Inserting MORE than the enforce-log cap fires the prune, which re-anchors
 *      the surviving chain — verify must still be ok (regression for the prune
 *      breaking the chain).
 *   7. Blanking every rowHash in a chained table → verify reports broken (reset/
 *      wipe detection), distinct from a genuinely empty table.
 *
 * Fully sandboxed: CLAUDESEC_DB points at a throwaway file under os.tmpdir(),
 * set BEFORE any server module is imported (the db module opens the file at
 * import time). The live spans DB and ~/.claudesec are never touched.
 *
 * Run via:  npx tsx tests/auditChainTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

// Isolate the DB BEFORE importing anything that opens it.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-audit-chain-'));
process.env.CLAUDESEC_DB = path.join(TMP, 'spans.db');
// Redirect HOME into the sandbox so the audit HMAC key (minted under
// ~/.claudesec/hooks/audit-key on first hash) lands in the throwaway dir, never
// the real home. os.homedir() reads HOME on macOS/Linux.
process.env.HOME = TMP;

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

async function main(): Promise<void> {
  const { db } = await import('../server/db.js');
  const { makeAuditLogger, verifyAuditChain } = await import('../server/auditLog.js');
  const {
    appendEnforceLog, readEnforceLog, enforceLogCount, verifyEnforceChain,
    ENFORCE_LOG_MAX,
  } = await import('../server/enforceLogStore.js');
  const { computeRowHash, canonicalString } = await import('../server/auditChain.js');

  // A minimal fake request — the audit logger only reads req.socket.remoteAddress.
  const fakeReq = { socket: { remoteAddress: '127.0.0.1' } } as any;
  // No-op scrub options + always-local actor so the test is deterministic.
  const auditLog = makeAuditLogger(() => ({}) as any, () => true);

  // ── Case 1: several audit rows → chain ok ─────────────────────────────────
  for (let i = 0; i < 5; i++) {
    auditLog(fakeReq, 'test.action', `target-${i}`, { i, note: `row ${i}` });
  }
  {
    const v = verifyAuditChain();
    check('case1: audit chain ok after inserts', () => assert.strictEqual(v.ok, true));
    check('case1: audit hashedRows === 5', () => assert.strictEqual(v.hashedRows, 5));
  }

  // ── Case 2: tamper a row's detail → broken at that id ─────────────────────
  {
    const mid = db
      .prepare(`SELECT id FROM operator_audit_log ORDER BY id ASC LIMIT 1 OFFSET 2`)
      .get() as { id: number };
    db.prepare(`UPDATE operator_audit_log SET detail = ? WHERE id = ?`)
      .run('{"tampered":true}', mid.id);
    const v = verifyAuditChain();
    check('case2: audit chain reports broken', () => assert.strictEqual(v.ok, false));
    check('case2: brokenAtId is the tampered row', () => assert.strictEqual(v.brokenAtId, mid.id));
  }

  // ── Case 3: enforce rows persist + chain-verify ───────────────────────────
  for (let i = 0; i < 4; i++) {
    appendEnforceLog({
      ts: Date.now() + i,
      mode: i % 2 === 0 ? 'monitor' : 'enforce',
      label: `rule-${i}`,
      severity: 'high',
      command: `echo step ${i}`,
      wouldBlock: true,
      blocked: i % 2 === 1,
    });
  }
  {
    check('case3: enforce count === 4', () => assert.strictEqual(enforceLogCount(), 4));
    check('case3: read returns newest-first', () => {
      const rows = readEnforceLog(10);
      assert.strictEqual(rows.length, 4);
      assert.strictEqual(rows[0].label, 'rule-3');
    });
    const v = verifyEnforceChain();
    check('case3: enforce chain ok', () => assert.strictEqual(v.ok, true));
    check('case3: enforce hashedRows === 4', () => assert.strictEqual(v.hashedRows, 4));
  }

  // ── Case 4: tamper an enforce row's command → broken at that id ───────────
  {
    const row = db
      .prepare(`SELECT id FROM enforce_log ORDER BY id ASC LIMIT 1 OFFSET 1`)
      .get() as { id: number };
    db.prepare(`UPDATE enforce_log SET command = ? WHERE id = ?`)
      .run('rm -rf / # injected', row.id);
    const v = verifyEnforceChain();
    check('case4: enforce chain reports broken', () => assert.strictEqual(v.ok, false));
    check('case4: brokenAtId is the tampered enforce row', () => assert.strictEqual(v.brokenAtId, row.id));
  }

  // ── Case 5: legacy (unhashed) rows don't break verification ───────────────
  // Use a fresh table-shaped scenario: insert rows with empty hashes (as a
  // pre-upgrade DB would have), then hashed rows after them. The verifier must
  // skip the legacy prefix and validate only the hashed tail.
  {
    db.exec(`
      CREATE TABLE IF NOT EXISTS legacy_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL, actor TEXT, action TEXT, target TEXT,
        detail TEXT, sourceIp TEXT, prevHash TEXT DEFAULT '', rowHash TEXT DEFAULT ''
      );
    `);
    // Two legacy rows with NO hash.
    const ins = db.prepare(
      `INSERT INTO legacy_audit (ts, actor, action, target, detail, sourceIp, prevHash, rowHash)
       VALUES (?, 'local', 'legacy', 't', '{}', '127.0.0.1', '', '')`,
    );
    ins.run(1); ins.run(2);
    // Two hashed rows chained onto an empty prevHash (the chain "starts" here).
    let prev = '';
    for (const ts of [3, 4]) {
      const canon = canonicalString([ts, 'local', 'legacy', 't', '{}', '127.0.0.1']);
      const rowHash = computeRowHash(canon, prev);
      db.prepare(
        `INSERT INTO legacy_audit (ts, actor, action, target, detail, sourceIp, prevHash, rowHash)
         VALUES (?, 'local', 'legacy', 't', '{}', '127.0.0.1', ?, ?)`,
      ).run(ts, prev, rowHash);
      prev = rowHash;
    }
    // Verify directly via the shared verifier (mirrors what verifyAuditChain does).
    const { verifyChain } = await import('../server/auditChain.js');
    const rows = db
      .prepare(`SELECT id, ts, prevHash, rowHash FROM legacy_audit ORDER BY id ASC`)
      .all() as Array<{ id: number; ts: number; prevHash: string; rowHash: string }>;
    const v = verifyChain(
      rows.map(r => ({
        id: r.id,
        prevHash: r.prevHash,
        rowHash: r.rowHash,
        canonical: canonicalString([r.ts, 'local', 'legacy', 't', '{}', '127.0.0.1']),
      })),
    );
    check('case5: legacy prefix does not break verification', () => assert.strictEqual(v.ok, true));
    check('case5: only the 2 hashed rows count', () => assert.strictEqual(v.hashedRows, 2));
    check('case5: total rows scanned === 4', () => assert.strictEqual(v.rows, 4));
  }

  // ── Case 6: crossing the enforce cap fires prune + re-anchor; chain stays ok ─
  // This is the regression test for the prune-breaks-the-chain bug. The store
  // already holds a few rows from case 3/4 (one tampered). Wipe the table first so
  // we start from a clean, verifiable chain, then insert well past the cap so the
  // oldest rows are pruned and the surviving chain must be re-anchored.
  {
    db.exec(`DELETE FROM enforce_log`);
    const overflow = ENFORCE_LOG_MAX + 25;
    for (let i = 0; i < overflow; i++) {
      appendEnforceLog({
        ts: Date.now() + i,
        mode: 'monitor',
        label: `over-${i}`,
        severity: 'high',
        command: `echo overflow ${i}`,
        wouldBlock: true,
        blocked: false,
      });
    }
    check('case6: table pruned to the cap', () =>
      assert.strictEqual(enforceLogCount(), ENFORCE_LOG_MAX));
    const v = verifyEnforceChain();
    check('case6: chain verifies after prune + re-anchor', () =>
      assert.strictEqual(v.ok, true));
    check('case6: every retained row is hashed', () =>
      assert.strictEqual(v.hashedRows, ENFORCE_LOG_MAX));
    // A further insert must still link cleanly onto the re-anchored tail.
    appendEnforceLog({
      ts: Date.now() + overflow,
      mode: 'monitor', label: 'after-prune', severity: 'high',
      command: 'echo after', wouldBlock: true, blocked: false,
    });
    check('case6: insert after prune keeps the chain ok', () =>
      assert.strictEqual(verifyEnforceChain().ok, true));
  }

  // ── Case 7: blanking every rowHash → verify reports broken (reset detection) ─
  {
    const { verifyChain } = await import('../server/auditChain.js');
    // Empty table is fine (no rows to chain).
    check('case7: empty table verifies', () =>
      assert.strictEqual(verifyChain([]).ok, true));
    // Rows present but ALL hashes blanked → broken.
    const wiped = verifyChain([
      { id: 1, prevHash: '', rowHash: '', canonical: canonicalString([1]) },
      { id: 2, prevHash: '', rowHash: '', canonical: canonicalString([2]) },
    ]);
    check('case7: all-blank chain reports broken', () =>
      assert.strictEqual(wiped.ok, false));
    check('case7: all-blank chain has zero hashed rows', () =>
      assert.strictEqual(wiped.hashedRows, 0));
    // And the real audit table, after blanking every rowHash, reports broken too.
    db.exec(`UPDATE operator_audit_log SET rowHash = ''`);
    check('case7: blanked audit table reports broken', () =>
      assert.strictEqual(verifyAuditChain().ok, false));
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  auditChainTest: ${passed}/${total} passed`);
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
    console.error('auditChainTest crashed:', e);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    process.exit(1);
  });
