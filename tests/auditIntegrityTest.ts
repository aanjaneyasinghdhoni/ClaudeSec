/**
 * tests/auditIntegrityTest.ts
 *
 * Gate for the audit record's integrity guarantees. Each case corresponds to a
 * hole that was open before this file existed, so a regression here is a
 * regression in what we are allowed to claim.
 *
 *   1. A valid chain verifies, and says so with a status an auditor can read.
 *   2. Emptying the table from OUTSIDE this process is reported as `wiped`,
 *      not as a clean empty chain.
 *   3. Cutting the newest rows off the tail is reported as `truncated`.
 *      (The chain alone cannot see this — a truncated prefix is a valid chain.)
 *   4. Removing rows from the middle is reported as `truncated` (count regression).
 *   5. A forged row is reported as `row_mismatch`, at its id.
 *   6. A third party holding ONLY the public key can verify the signed anchor and
 *      re-derive every rowHash. No secret changes hands.
 *   7. The spans chain: chained inserts verify; a tampered span is caught at its
 *      position; a deleted span leaves a tombstone that keeps the chain
 *      continuous; destroying the tombstone too is an unaccounted gap.
 *   8. The spans backfill is idempotent and resumable.
 *   9. Per-span ingest cost is measured and printed.
 *
 * "Outside this process" is simulated with a second better-sqlite3 connection to
 * the same file, which is exactly what `sqlite3 ~/.claudesec/spans.db` is: the
 * anchor probe never sees the change, so what it already signed no longer
 * matches what the table holds — and that discrepancy is the detection.
 *
 * Fully sandboxed: CLAUDESEC_DB, CLAUDESEC_HOME and HOME all point into a
 * throwaway directory under os.tmpdir(), set BEFORE any server module is
 * imported (the db module opens the file at import time). The live spans DB and
 * the real ~/.claudesec are never touched.
 *
 * Run via:  npx tsx tests/auditIntegrityTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-audit-integrity-'));
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

/** A second connection to the same file — stands in for an attacker with an
 *  `sqlite3` shell. Nothing it does reaches this process's triggers. */
async function externalConnection(): Promise<import('better-sqlite3').Database> {
  const { default: Database } = await import('better-sqlite3');
  const handle = new Database(process.env.CLAUDESEC_DB!);
  handle.pragma('journal_mode = WAL');
  handle.pragma('busy_timeout = 5000');
  return handle;
}

function sampleSpan(i: number) {
  return {
    spanId:     `span-${i}`,
    traceId:    'trace-integrity',
    parentId:   '',
    name:       `Bash tool call ${i}`,
    protocol:   'HTTPS',
    reason:     'Processing step',
    severity:   i % 7 === 0 ? 'high' : 'none',
    harness:    'claude-code',
    attributes: JSON.stringify({ command: `echo step ${i}`, cwd: '/work', payload: 'x'.repeat(512) }),
    startNano:  String(BigInt(Date.now()) * 1_000_000n + BigInt(i)),
    endNano:    String(BigInt(Date.now()) * 1_000_000n + BigInt(i) + 1000n),
    repo:       'demo',
  };
}

async function main(): Promise<void> {
  const { db, insertChainedSpan, chainSpansBackfill, verifySpanChain } = await import('../server/db.js');
  const { makeAuditLogger, verifyAuditChain } = await import('../server/auditLog.js');
  const {
    canonicalString, computeRowHash, flushChainAnchors, auditPublicKeyPem, auditKeyId,
    verifyChain: verifyChainDirect,
  } = await import('../server/auditChain.js');

  const fakeReq = { socket: { remoteAddress: '127.0.0.1' } } as any;
  const auditLog = makeAuditLogger(() => ({}) as any, () => true);

  // ── Case 1: a valid chain verifies ────────────────────────────────────────
  for (let i = 0; i < 8; i++) auditLog(fakeReq, 'config.set', `key-${i}`, { i });
  {
    const v = verifyAuditChain();
    check('case1: valid audit chain is ok', () => assert.strictEqual(v.ok, true));
    check('case1: status is "ok"', () => assert.strictEqual(v.status, 'ok'));
    check('case1: 8 hashed rows', () => assert.strictEqual(v.hashedRows, 8));
    check('case1: the anchor attests it', () => assert.strictEqual(v.attested, true));
    check('case1: detail refuses to claim completeness', () =>
      assert.ok(/not proof that every event/.test(v.detail), v.detail));
  }

  // ── Case 6 (done early, while the chain is clean): public-key verification ─
  // A third party gets the anchor file and the public key — nothing else — and
  // must be able to (a) check the signature and (b) re-derive every row hash.
  {
    flushChainAnchors();
    const hooks = path.join(process.env.CLAUDESEC_HOME!, 'hooks');
    const anchorRaw = fs.readFileSync(path.join(hooks, 'audit-anchor.json'), 'utf8');
    const pubPem = fs.readFileSync(path.join(hooks, 'audit-key.pub.pem'), 'utf8');
    const anchor = JSON.parse(anchorRaw) as any;

    check('case6: the public key is exported to disk', () =>
      assert.ok(pubPem.includes('BEGIN PUBLIC KEY')));
    check('case6: the API hands out the same public key', () =>
      assert.strictEqual(auditPublicKeyPem().trim(), pubPem.trim()));
    check('case6: the private key is owner-only (0600)', () => {
      const mode = fs.statSync(path.join(hooks, 'audit-key.ed25519.pem')).mode & 0o777;
      assert.strictEqual(mode, 0o600);
    });
    check('case6: keyId is a stable fingerprint of the public key', () => {
      const der = crypto.createPublicKey(pubPem).export({ type: 'spki', format: 'der' });
      assert.strictEqual(auditKeyId(), crypto.createHash('sha256').update(der).digest('hex').slice(0, 32));
    });

    // Signature check using ONLY the public key.
    check('case6: anchor signature verifies with the public key alone', () => {
      const chains: Record<string, unknown> = {};
      for (const k of Object.keys(anchor.chains).sort()) chains[k] = anchor.chains[k];
      const payload = JSON.stringify({
        v: anchor.v, keyId: anchor.keyId, publicKey: anchor.publicKey,
        chains, updatedAt: anchor.updatedAt,
      });
      assert.ok(crypto.verify(null, Buffer.from(payload, 'utf8'), pubPem, Buffer.from(anchor.sig, 'base64')));
    });

    // Row hashes re-derived with plain SHA-256 — no key of any kind.
    check('case6: rows re-derive from plain SHA-256, no secret needed', () => {
      const rows = db.prepare(
        `SELECT id, ts, actor, action, target, detail, sourceIp, prevHash, rowHash
           FROM operator_audit_log ORDER BY id ASC`,
      ).all() as any[];
      let prev = '';
      for (const r of rows) {
        const canon = JSON.stringify([r.ts, r.actor, r.action, r.target, r.detail, r.sourceIp]);
        const expect = crypto.createHash('sha256').update(canon + prev).digest('hex');
        assert.strictEqual(r.rowHash, expect, `row ${r.id}`);
        prev = r.rowHash;
      }
      assert.strictEqual(rows[rows.length - 1].rowHash, anchor.chains.operator_audit_log.lastRowHash);
    });
  }

  // ── Case 5: a forged row is caught at its id ──────────────────────────────
  // Each of the audit cases damages the table from OUTSIDE and then restores it
  // byte-for-byte, so every case starts from the same known-good chain. Restoring
  // rather than re-creating matters: re-creating would need the anchor re-founded,
  // and the point of these cases is what happens when it is NOT.
  const snapshotAudit = async () => {
    const c = await externalConnection();
    const rows = c.prepare(`SELECT * FROM operator_audit_log ORDER BY id ASC`).all() as any[];
    c.close();
    return rows;
  };
  const restoreAudit = async (rows: any[]) => {
    const c = await externalConnection();
    c.exec(`DELETE FROM operator_audit_log`);
    const ins = c.prepare(
      `INSERT INTO operator_audit_log (id, ts, actor, action, target, detail, sourceIp, prevHash, rowHash)
       VALUES (@id, @ts, @actor, @action, @target, @detail, @sourceIp, @prevHash, @rowHash)`,
    );
    for (const r of rows) ins.run(r);
    c.close();
  };

  const pristine = await snapshotAudit();

  {
    const external = await externalConnection();
    const target = external.prepare(`SELECT * FROM operator_audit_log ORDER BY id ASC LIMIT 1 OFFSET 3`)
      .get() as any;
    // Forge the row AND recompute its own hash, the way someone who had read
    // auditChain.ts would. The link to the NEXT row is what gives it away — which
    // is the whole reason a chain beats per-row hashes.
    const canon = JSON.stringify([1, 'local', 'config.set', 'innocent', '{}', '127.0.0.1']);
    const rowHash = crypto.createHash('sha256').update(canon + target.prevHash).digest('hex');
    external.prepare(
      `UPDATE operator_audit_log SET ts=1, actor='local', action='config.set', target='innocent',
              detail='{}', sourceIp='127.0.0.1', rowHash=? WHERE id=?`,
    ).run(rowHash, target.id);
    external.close();

    const v = verifyAuditChain();
    check('case5: a forged row is detected', () => assert.strictEqual(v.ok, false));
    check('case5: status is row_mismatch', () => assert.strictEqual(v.status, 'row_mismatch'));
    check('case5: it names the first row that no longer links', () =>
      assert.strictEqual(v.brokenAtId, target.id + 1));
    await restoreAudit(pristine);
    check('case5: the chain verifies again once restored', () =>
      assert.strictEqual(verifyAuditChain().status, 'ok'));
  }

  // ── Case 3: tail truncation ───────────────────────────────────────────────
  // The chain alone CANNOT see this: lopping rows off the end leaves a valid
  // prefix. Only the anchor knows how far the record was supposed to reach.
  {
    const external = await externalConnection();
    external.prepare(
      `DELETE FROM operator_audit_log WHERE id IN (SELECT id FROM operator_audit_log ORDER BY id DESC LIMIT 4)`,
    ).run();
    external.close();

    const v = verifyAuditChain();
    check('case3: truncating the newest rows is detected', () => assert.strictEqual(v.ok, false));
    check('case3: status is truncated', () => assert.strictEqual(v.status, 'truncated'));
    check('case3: the surviving prefix still hashes correctly', () =>
      assert.strictEqual(v.brokenAtId, undefined));
    check('case3: it reports the expected count', () =>
      assert.strictEqual(v.expectedRows, pristine.length));
    await restoreAudit(pristine);
    check('case3: restored chain verifies', () => assert.strictEqual(verifyAuditChain().status, 'ok'));
  }

  // ── Case 4: count regression (rows removed from the middle) ───────────────
  {
    const external = await externalConnection();
    external.prepare(
      `DELETE FROM operator_audit_log WHERE id IN (SELECT id FROM operator_audit_log ORDER BY id ASC LIMIT 3 OFFSET 3)`,
    ).run();
    external.close();

    const v = verifyAuditChain();
    check('case4: a mid-chain deletion is detected', () => assert.strictEqual(v.ok, false));
    check('case4: the verdict is a deletion or a broken link', () =>
      assert.ok(['truncated', 'row_mismatch'].includes(v.status), v.status));
    check('case4: the anchor still expects the original row count', () =>
      assert.strictEqual(v.expectedRows, pristine.length));
    check('case4: fewer rows remain than the anchor accounts for', () =>
      assert.ok(v.rows < v.expectedRows!, `${v.rows} vs ${v.expectedRows}`));
    await restoreAudit(pristine);
    check('case4: restored chain verifies', () => assert.strictEqual(verifyAuditChain().status, 'ok'));
  }

  // ── Case 2: wiping the table entirely ─────────────────────────────────────
  // The defect this replaces: verifyChain([]) used to answer ok:true, so
  // `DELETE FROM operator_audit_log` verified clean.
  {
    const external = await externalConnection();
    external.exec(`DELETE FROM operator_audit_log`);
    external.close();

    const v = verifyAuditChain();
    check('case2: an emptied table does NOT verify clean', () => assert.strictEqual(v.ok, false));
    check('case2: status is wiped', () => assert.strictEqual(v.status, 'wiped'));
    check('case2: the detail names the missing count', () =>
      assert.ok(new RegExp(`accounts for ${pristine.length} row`).test(v.detail), v.detail));
    check('case2: an unanchored empty chain is NOT reported as wiped', () => {
      // The distinction that makes the verdict useful: nothing recorded and
      // nothing claimed is not the same as "the record was deleted".
      const fresh = verifyChainDirect([]);
      assert.strictEqual(fresh.status, 'unanchored');
    });
    await restoreAudit(pristine);
    check('case2: restored chain verifies', () => assert.strictEqual(verifyAuditChain().status, 'ok'));
  }

  // ── Case 7: the spans chain ───────────────────────────────────────────────
  await checkAsync('case7: chained span inserts verify', async () => {
    for (let i = 0; i < 200; i++) insertChainedSpan(sampleSpan(i));
    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.chainedSpans, 200);
    assert.strictEqual(v.checkedHashes, 200);
  });

  await checkAsync('case7: a duplicate spanId does not consume a chain position', async () => {
    const before = (db.prepare(`SELECT COALESCE(MAX(chainSeq),0) AS m FROM spans`).get() as { m: number }).m;
    const info = insertChainedSpan(sampleSpan(5));   // spanId already present
    assert.strictEqual(info.changes, 0);
    const after = (db.prepare(`SELECT COALESCE(MAX(chainSeq),0) AS m FROM spans`).get() as { m: number }).m;
    assert.strictEqual(after, before);
    assert.strictEqual((await verifySpanChain({ deep: true })).status, 'ok');
  });

  await checkAsync('case7: retention deletion leaves a tombstone and the chain survives', async () => {
    // Delete through OUR handle, the way the retention sweep does.
    db.prepare(`DELETE FROM spans WHERE chainSeq BETWEEN 20 AND 60`).run();
    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.tombstones, 41);
    assert.strictEqual(v.chainedSpans, 159);
    // The payload really is gone — only the link remains.
    const cols = db.prepare(`PRAGMA table_info(span_chain_tombstones)`).all() as Array<{ name: string }>;
    assert.deepStrictEqual(cols.map(c => c.name).sort(), ['chainSeq', 'deletedAt', 'prevHash', 'rowHash']);
  });

  await checkAsync('case7: a tampered span is caught at its chain position', async () => {
    const external = await externalConnection();
    external.prepare(`UPDATE spans SET attributes = ? WHERE chainSeq = ?`)
      .run(JSON.stringify({ command: 'rm -rf /' }), 100);
    external.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'row_mismatch');
    assert.strictEqual(v.brokenAtSeq, 100);
    // Undo so the next case starts clean.
    const back = await externalConnection();
    back.prepare(`UPDATE spans SET attributes = ? WHERE chainSeq = ?`)
      .run(sampleSpan(99).attributes, 100);
    back.close();
    assert.strictEqual((await verifySpanChain({ deep: true })).status, 'ok');
  });

  await checkAsync('case7: an outside deletion is still recorded as a tombstone', async () => {
    // The tombstone trigger lives in the schema, so it fires for ANY connection —
    // including an `sqlite3` shell. Deletion cannot be prevented; it is recorded.
    const external = await externalConnection();
    external.prepare(`DELETE FROM spans WHERE chainSeq = 120`).run();
    external.close();
    const v = await verifySpanChain();
    assert.strictEqual(v.status, 'ok', v.detail);
    const t = db.prepare(`SELECT COUNT(*) AS c FROM span_chain_tombstones WHERE chainSeq = 120`).get() as { c: number };
    assert.strictEqual(t.c, 1);
  });

  await checkAsync('case7: destroying the tombstone too leaves an unaccounted gap', async () => {
    const external = await externalConnection();
    external.prepare(`DELETE FROM span_chain_tombstones WHERE chainSeq = 120`).run();
    external.close();
    const v = await verifySpanChain();
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'unaccounted_gap');
    assert.strictEqual(v.brokenAtSeq, 120);
  });

  // ── Case 8: the backfill is idempotent and resumable ──────────────────────
  await checkAsync('case8: backfill chains pre-existing rows', async () => {
    // Rebuild from scratch with a population that predates the chain entirely.
    db.exec(`DELETE FROM spans`);
    db.exec(`DELETE FROM span_chain_tombstones`);
    const raw = db.prepare(`
      INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness,
                         attributes, startNano, endNano, repo)
      VALUES (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness,
              @attributes, @startNano, @endNano, @repo)
    `);
    const seed = db.transaction(() => { for (let i = 0; i < 500; i++) raw.run(sampleSpan(i)); });
    seed();
    const { ran, rows } = await chainSpansBackfill({ chunkSize: 37, force: true });
    assert.strictEqual(ran, true);
    assert.strictEqual(rows, 500);
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.chainedSpans, 500);
  });

  await checkAsync('case8: a second run is a no-op (idempotent)', async () => {
    const again = await chainSpansBackfill({ chunkSize: 37 });
    assert.deepStrictEqual(again, { ran: false, rows: 0 });
    assert.strictEqual((await verifySpanChain({ deep: true })).status, 'ok');
  });

  await checkAsync('case8: an interrupted backfill resumes instead of restarting', async () => {
    // Simulate a process killed mid-walk: strip the chain from everything past
    // the halfway point and rewind the persisted markers to match, exactly the
    // state a crash after a committed chunk would leave behind.
    const halfway = db.prepare(
      `SELECT rowid AS rid, chainSeq FROM spans WHERE chainSeq = 250`,
    ).get() as { rid: number; chainSeq: number };
    db.prepare(`UPDATE spans SET chainSeq = NULL, prevHash = '', rowHash = '' WHERE chainSeq > 250`).run();
    db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('spans.chain_v1.cursor', ?)`).run(String(halfway.rid));
    db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('spans.chain_v1.seq', '250')`).run();
    db.prepare(`DELETE FROM config WHERE key = 'spans.chain_v1'`).run();
    const ceiling = (db.prepare(`SELECT MAX(rowid) AS m FROM spans`).get() as { m: number }).m;
    db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES ('spans.chain_v1.ceiling', ?)`).run(String(ceiling));

    const resumed = await chainSpansBackfill({ chunkSize: 37 });
    assert.strictEqual(resumed.ran, true);
    // It picked up the remaining 250, not all 500.
    assert.strictEqual(resumed.rows, 250);
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.chainedSpans, 500);
    // Positions are contiguous 1..500 — the resume did not restart the counter.
    const span = db.prepare(`SELECT MIN(chainSeq) AS lo, MAX(chainSeq) AS hi FROM spans`).get() as { lo: number; hi: number };
    assert.deepStrictEqual([span.lo, span.hi], [1, 500]);
  });

  // ── Case 9: measure the per-span cost of chaining ─────────────────────────
  {
    const N = 5_000;
    const plain = db.prepare(`
      INSERT OR IGNORE INTO spans (spanId, traceId, parentId, name, protocol, reason, severity,
                                   harness, attributes, startNano, endNano, repo)
      VALUES (@spanId, @traceId, @parentId, @name, @protocol, @reason, @severity, @harness,
              @attributes, @startNano, @endNano, @repo)
    `);
    const mkPlain = (i: number) => ({ ...sampleSpan(i), spanId: `plain-${i}` });
    const mkChained = (i: number) => ({ ...sampleSpan(i), spanId: `chained-${i}` });

    // Warm both paths so neither pays for first-call JIT.
    for (let i = 0; i < 200; i++) { plain.run(mkPlain(-i - 1)); insertChainedSpan(mkChained(-i - 1)); }

    const t0 = process.hrtime.bigint();
    for (let i = 0; i < N; i++) plain.run(mkPlain(i));
    const t1 = process.hrtime.bigint();
    for (let i = 0; i < N; i++) insertChainedSpan(mkChained(i));
    const t2 = process.hrtime.bigint();

    // Hashing in isolation, to separate it from the extra columns' storage cost.
    const t3 = process.hrtime.bigint();
    let sink = '';
    for (let i = 0; i < N; i++) {
      const s = sampleSpan(i);
      sink = computeRowHash(canonicalString([
        i, s.spanId, s.traceId, s.parentId, s.name, s.protocol, s.reason, s.severity,
        s.harness, s.attributes, s.startNano, s.endNano, s.repo, null, null, null,
      ]), sink);
    }
    const t4 = process.hrtime.bigint();

    const usPlain   = Number(t1 - t0) / 1000 / N;
    const usChained = Number(t2 - t1) / 1000 / N;
    const usHash    = Number(t4 - t3) / 1000 / N;
    console.log(`  ingest cost: plain insert ${usPlain.toFixed(2)} µs/span, chained insert ` +
                `${usChained.toFixed(2)} µs/span (delta ${(usChained - usPlain).toFixed(2)} µs), ` +
                `hashing alone ${usHash.toFixed(2)} µs/span`);

    check('case9: hashing costs well under 100 µs/span', () => assert.ok(usHash < 100, `${usHash} µs`));
    check('case9: chaining does not double the cost of an insert', () =>
      assert.ok(usChained < usPlain * 2 + 10, `plain ${usPlain} vs chained ${usChained}`));
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  auditIntegrityTest: ${passed}/${total} passed`);
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
    console.error('auditIntegrityTest crashed:', e);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    process.exit(1);
  });
