/**
 * tests/auditAnchorForgeTest.ts
 *
 * The keyless forge, and the boundary of what the anchor can promise.
 *
 * ClaudeSec's central claim is that its record is tamper-EVIDENT. The row hashes
 * that back that claim are plain, published SHA-256 — deliberately, so a third
 * party can check them without holding a secret. The only thing standing between
 * that openness and a free rewrite is the signed tail anchor: an attacker can
 * recompute every hash in the table, but they cannot move the pin the anchor
 * signed over the old ones.
 *
 * Unless the pin moves itself. The anchor used to advance onto whatever the table
 * currently said was newest, unconditionally, on a five-second timer. So:
 *
 *      rewrite a row  →  re-thread the rest with public SHA-256  →  append one row
 *      →  the anchor re-pins onto the forged tail  →  verify reports ok, attested
 *
 * That is a total forge of the record with NO access to the private key, on a
 * machine where ingest supplies the appends by itself every few seconds. This
 * file is the gate on that. Case 1 IS the attack; the rest are the variants an
 * attacker would reach for next, and the legitimate operations that must not be
 * mistaken for any of them.
 *
 *    1.  rewrite mid-chain, re-thread, append          → tail_mismatch, not attested
 *    2.  the anchor's pin does not move while forged
 *    3.  rewrite without re-threading                  → link/row mismatch
 *    4.  rewrite, let INGEST append, re-thread over it → detected
 *    5.  truncate the tail                             → truncated
 *    6.  truncate the head (tombstones destroyed too)  → truncated
 *    7.  reorder two positions                         → row_mismatch
 *    8.  delete one row, destroy its tombstone         → unaccounted_gap
 *    9.  an anchor that pins no hash                   → tail_unpinned, not ok
 *   10.  the same attack on the capped operator audit log
 *   11.  RESIDUAL: with the private key, the forge still works. Asserted, not
 *        hand-waved — this is the documented ceiling and it must stay visible.
 *   12.  legitimate paths: ingest, retention with tombstones (including the
 *        pinned position itself), and legacy-scheme rows.
 *   13.  measured cost of the pin check.
 *
 * Fully sandboxed: CLAUDESEC_DB, CLAUDESEC_HOME and HOME point into a throwaway
 * directory, set BEFORE any server module is imported. The live database and the
 * real ~/.claudesec are never touched.
 *
 * Run via:  npx tsx tests/auditAnchorForgeTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-anchor-forge-'));
process.env.CLAUDESEC_DB   = path.join(TMP, 'spans.db');
process.env.CLAUDESEC_HOME = path.join(TMP, '.claudesec');
process.env.HOME           = TMP;
process.env.CLAUDESEC_WATCH = '0';

const HOOKS  = path.join(TMP, '.claudesec', 'hooks');
const ANCHOR = path.join(HOOKS, 'audit-anchor.json');

let passed = 0;
const failures: string[] = [];
async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try { await fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

/** A second connection to the same file — an `sqlite3` shell, in other words.
 *  Nothing it does is seen by this process's caches. */
async function external(): Promise<import('better-sqlite3').Database> {
  const { default: Database } = await import('better-sqlite3');
  const h = new Database(process.env.CLAUDESEC_DB!);
  h.pragma('journal_mode = WAL');
  h.pragma('busy_timeout = 5000');
  return h;
}

// ── The attacker's toolkit: everything below is PUBLIC ──────────────────────
// Neither of these needs a key of any kind. They are transcribed from
// server/db.ts and server/auditChain.ts, which anyone can read.

const sha = (canonical: string, prev: string) =>
  crypto.createHash('sha256').update(canonical + prev).digest('hex');

const canon = (fields: unknown[]) =>
  JSON.stringify(fields.map(f => (f === undefined ? null : f)));

/** server/db.ts spanCanonical — the current scheme. */
const spanCanon = (r: any) => canon([
  r.chainSeq, r.spanId, r.traceId, r.parentId, r.name, r.protocol, r.reason,
  r.severity, r.harness, r.attributes, r.startNano,
  r.principal ?? null, r.agent_identity ?? null, r.delegation_id ?? null,
]);

/** server/db.ts spanCanonicalLegacy — endNano and repo still hashed. */
const spanCanonLegacy = (r: any) => canon([
  r.chainSeq, r.spanId, r.traceId, r.parentId, r.name, r.protocol, r.reason,
  r.severity, r.harness, r.attributes, r.startNano, r.endNano, r.repo,
  r.principal ?? null, r.agent_identity ?? null, r.delegation_id ?? null,
]);

const SPAN_COLS = `chainSeq, spanId, traceId, parentId, name, protocol, reason, severity,
                   harness, attributes, startNano, endNano, repo, principal,
                   agent_identity, delegation_id, prevHash, rowHash`;

/**
 * Re-thread live spans from `fromSeq` upward so every link is self-consistent
 * again — the step that turns a crude edit into a forgery. Returns the new tail.
 */
function rethread(h: import('better-sqlite3').Database, fromSeq: number): { tailSeq: number; tailHash: string } {
  const before = h.prepare(`SELECT rowHash FROM spans WHERE chainSeq = ?`).get(fromSeq - 1) as { rowHash?: string } | undefined;
  let prev = before?.rowHash ?? '';
  const rows = h.prepare(`SELECT ${SPAN_COLS} FROM spans WHERE chainSeq >= ? ORDER BY chainSeq ASC`).all(fromSeq) as any[];
  const upd = h.prepare(`UPDATE spans SET prevHash = ?, rowHash = ? WHERE chainSeq = ?`);
  let tailSeq = fromSeq - 1;
  for (const r of rows) {
    const hash = sha(spanCanon(r), prev);
    upd.run(prev, hash, r.chainSeq);
    prev = hash;
    tailSeq = r.chainSeq;
  }
  return { tailSeq, tailHash: prev };
}

/** Append a span the way an attacker would: straight into the file. */
function appendExternally(h: import('better-sqlite3').Database, seq: number, prevHash: string, tag: string): string {
  const rec = {
    chainSeq: seq, spanId: `ext-${tag}-${seq}`, traceId: 'trace-forge', parentId: '',
    name: 'Bash tool call', protocol: 'HTTPS', reason: 'Processing step',
    severity: 'none', harness: 'claude-code',
    attributes: JSON.stringify({ command: `echo ${seq}` }),
    startNano: String(1_700_000_000_000_000_000n + BigInt(seq)),
    endNano: String(1_700_000_000_000_000_000n + BigInt(seq) + 1000n), repo: 'demo',
    principal: null, agent_identity: null, delegation_id: null,
  };
  const rowHash = sha(spanCanon(rec), prevHash);
  h.prepare(`
    INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness,
                       attributes, startNano, endNano, repo, chainSeq, prevHash, rowHash,
                       principal, agent_identity, delegation_id)
    VALUES (@spanId,@traceId,@parentId,@name,@protocol,@reason,@severity,@harness,
            @attributes,@startNano,@endNano,@repo,@chainSeq,@prevHash,@rowHash,
            @principal,@agent_identity,@delegation_id)`).run({ ...rec, prevHash, rowHash });
  return rowHash;
}

function sampleSpan(i: number) {
  return {
    spanId:     `span-${i}`,
    traceId:    'trace-forge',
    parentId:   '',
    name:       `Bash tool call ${i}`,
    protocol:   'HTTPS',
    reason:     i === 50 ? 'Attempted credential exfiltration' : 'Processing step',
    severity:   i === 50 ? 'critical' : 'none',
    harness:    'claude-code',
    attributes: JSON.stringify({ command: `echo step ${i}`, cwd: '/work' }),
    startNano:  String(1_700_000_000_000_000_000n + BigInt(i)),
    endNano:    String(1_700_000_000_000_000_000n + BigInt(i) + 1000n),
    repo:       'demo',
  };
}

const anchorOnDisk = () => JSON.parse(fs.readFileSync(ANCHOR, 'utf8')) as any;
const spansPin     = () => anchorOnDisk().chains.spans;

async function main(): Promise<void> {
  const { db, insertChainedSpan, verifySpanChain, resetSpanChainTailCacheForTests } =
    await import('../server/db.js');
  const { makeAuditLogger, verifyAuditChain } = await import('../server/auditLog.js');
  const { flushChainAnchors, resetAnchorCacheForTests } = await import('../server/auditChain.js');

  // A clean, honestly-built chain. Position 50 is a CRITICAL finding — the thing
  // an attacker wants to disappear.
  for (let i = 1; i <= 200; i++) insertChainedSpan(sampleSpan(i));
  flushChainAnchors();

  await check('baseline: an honest chain verifies and is attested', async () => {
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.attested, true);
    assert.strictEqual(v.chainedSpans, 200);
  });

  const pin0 = spansPin();
  assert.strictEqual(pin0.lastId, 200, 'fixture: the anchor should pin position 200');

  /** Put the table back exactly as it was so each case starts from the same
   *  known-good chain, and thaw the anchor. Restoring rather than rebuilding is
   *  the point: these cases are about what happens when the anchor is NOT
   *  re-founded. */
  const pristine = (await external()).prepare(`SELECT ${SPAN_COLS} FROM spans ORDER BY chainSeq ASC`).all() as any[];
  const pristineAnchor = fs.readFileSync(ANCHOR);
  const restore = async () => {
    const h = await external();
    h.exec(`DELETE FROM spans; DELETE FROM span_chain_tombstones;`);
    const ins = h.prepare(`
      INSERT INTO spans (${SPAN_COLS})
      VALUES (@chainSeq,@spanId,@traceId,@parentId,@name,@protocol,@reason,@severity,
              @harness,@attributes,@startNano,@endNano,@repo,@principal,
              @agent_identity,@delegation_id,@prevHash,@rowHash)`);
    for (const r of pristine) ins.run(r);
    h.close();
    fs.writeFileSync(ANCHOR, pristineAnchor);
    resetAnchorCacheForTests();
    // This process cannot see a table rewritten through another connection, so
    // its O(1) tail cache has to be dropped too or the next append opens a hole.
    resetSpanChainTailCacheForTests();
  };

  // ── Case 1: THE ATTACK ────────────────────────────────────────────────────
  await check('case1: rewrite + keyless re-thread + one append is NOT reported as ok', async () => {
    const h = await external();
    h.prepare(`UPDATE spans SET severity='info', reason='Processing step' WHERE chainSeq=50`).run();
    const { tailSeq, tailHash } = rethread(h, 50);
    // Nothing so far needed a key: only crypto.createHash('sha256').
    appendExternally(h, tailSeq + 1, tailHash, 'a');
    h.close();

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false, `forged chain reported ok — detail: ${v.detail}`);
    assert.strictEqual(v.status, 'tail_mismatch', v.detail);
    assert.strictEqual(v.brokenAtSeq, 200);
  });

  await check('case1: and it is explicitly NOT attested', async () => {
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.attested, false, 'a forged chain must never claim attestation');
    // The anchor says why, in its own record, over the signature.
    assert.ok(v.pinFrozenAt, 'the pin should be frozen');
    assert.strictEqual(v.pinFrozenSeq, 200);
    assert.strictEqual(v.anchorPinBreaks, 1);
  });

  // ── Case 2: the pin itself must not have moved ────────────────────────────
  await check('case2: the anchor still pins the pre-attack row and hash', () => {
    const pin = spansPin();
    assert.strictEqual(pin.lastId, pin0.lastId, 'the pin advanced onto the forged tail');
    assert.strictEqual(pin.lastRowHash, pin0.lastRowHash, 'the pinned hash was replaced');
  });

  await check('case2: further appends cannot walk the pin forward either', async () => {
    // The attacker's obvious next move: keep appending until the anchor gives in.
    const h = await external();
    let prev = (h.prepare(`SELECT rowHash FROM spans ORDER BY chainSeq DESC LIMIT 1`).get() as any).rowHash;
    let seq  = (h.prepare(`SELECT MAX(chainSeq) AS m FROM spans`).get() as any).m as number;
    for (let i = 0; i < 25; i++) prev = appendExternally(h, ++seq, prev, 'grind');
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'tail_mismatch', v.detail);
    assert.strictEqual(v.attested, false);
    assert.strictEqual(spansPin().lastRowHash, pin0.lastRowHash);
    // The freeze is recorded once, not once per sweep.
    assert.strictEqual(v.anchorPinBreaks, 1);
  });

  await restore();
  await check('case2: the restored chain verifies again', async () => {
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.attested, true);
  });

  // ── Case 3: rewrite without re-threading ──────────────────────────────────
  await check('case3: a rewrite that does not re-thread breaks a link', async () => {
    const h = await external();
    h.prepare(`UPDATE spans SET severity='info' WHERE chainSeq=50`).run();
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'row_mismatch', v.detail);
    assert.strictEqual(v.brokenAtSeq, 50);
  });
  await restore();

  // ── Case 4: rewrite, let real ingest append, then re-thread over it ───────
  // The patient version: do not append anything yourself, let the server's own
  // ingest carry the anchor forward, and re-thread the whole range afterwards.
  await check('case4: rewriting under live ingest is still caught', async () => {
    for (let i = 201; i <= 205; i++) insertChainedSpan(sampleSpan(i));
    flushChainAnchors();
    assert.strictEqual(spansPin().lastId, 205, 'ingest should have advanced the pin');
    const pinBefore = spansPin().lastRowHash;

    const h = await external();
    h.prepare(`UPDATE spans SET severity='info', reason='Processing step' WHERE chainSeq=50`).run();
    rethread(h, 50);   // covers the freshly-ingested rows too
    h.close();

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false, v.detail);
    assert.strictEqual(v.status, 'tail_mismatch', v.detail);
    assert.strictEqual(spansPin().lastRowHash, pinBefore);
  });
  await restore();

  // ── Case 5: tail truncation ───────────────────────────────────────────────
  await check('case5: cutting the newest positions off is truncated', async () => {
    const h = await external();
    h.exec(`DELETE FROM spans WHERE chainSeq > 180; DELETE FROM span_chain_tombstones WHERE chainSeq > 180;`);
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'truncated', v.detail);
  });
  await restore();

  // ── Case 6: head truncation ───────────────────────────────────────────────
  await check('case6: cutting the oldest positions off is truncated', async () => {
    const h = await external();
    h.exec(`DELETE FROM spans WHERE chainSeq <= 10; DELETE FROM span_chain_tombstones WHERE chainSeq <= 10;`);
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'truncated', v.detail);
    assert.ok(/10 were removed outside this server/.test(v.detail), v.detail);
  });
  await restore();

  // ── Case 7: reordering ────────────────────────────────────────────────────
  await check('case7: swapping two positions is row_mismatch', async () => {
    const h = await external();
    const a = h.prepare(`SELECT ${SPAN_COLS} FROM spans WHERE chainSeq = 30`).get() as any;
    const b = h.prepare(`SELECT ${SPAN_COLS} FROM spans WHERE chainSeq = 31`).get() as any;
    // Content swapped, hashes and links left exactly where they were — the chain
    // position is inside the canonical form, so neither row can pass at the
    // other's slot.
    const set = h.prepare(`UPDATE spans SET spanId=?, name=?, attributes=?, startNano=? WHERE chainSeq=?`);
    set.run('__swap__', a.name, a.attributes, a.startNano, 30);   // free the unique spanId
    set.run(a.spanId, a.name, a.attributes, a.startNano, 31);
    set.run(b.spanId, b.name, b.attributes, b.startNano, 30);
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'row_mismatch', v.detail);
    assert.strictEqual(v.brokenAtSeq, 30);
  });
  await restore();

  // ── Case 8: delete a row and destroy its tombstone ────────────────────────
  await check('case8: a deletion with no tombstone is an unaccounted gap', async () => {
    const h = await external();
    h.prepare(`DELETE FROM spans WHERE chainSeq = 77`).run();      // trigger writes a tombstone
    h.prepare(`DELETE FROM span_chain_tombstones WHERE chainSeq = 77`).run();   // …and it is destroyed
    h.close();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.status, 'unaccounted_gap', v.detail);
    assert.strictEqual(v.brokenAtSeq, 77);
  });
  await restore();

  // ── Case 9: an anchor that counts rows but pins no hash ───────────────────
  await check('case9: an anchor with no pinned hash reports tail_unpinned, not ok', async () => {
    const a = anchorOnDisk();
    a.chains.spans.lastRowHash = '';
    fs.writeFileSync(ANCHOR, JSON.stringify(a));
    resetAnchorCacheForTests();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.ok, false, `an unpinnable anchor reported "${v.status}"`);
    assert.strictEqual(v.status, 'tail_unpinned', v.detail);
  });
  await restore();

  // ── Case 10: the same attack on the capped operator audit log ─────────────
  await check('case10: the audit log resists the same forge', async () => {
    const log = makeAuditLogger(() => ({}) as any, () => true);
    const req = { socket: { remoteAddress: '127.0.0.1' } } as any;
    for (let i = 0; i < 20; i++) log(req, 'config.set', `key-${i}`, { i });
    flushChainAnchors();
    assert.strictEqual(verifyAuditChain().status, 'ok');
    const pinned = anchorOnDisk().chains.operator_audit_log;

    const h = await external();
    const target = h.prepare(`SELECT * FROM operator_audit_log ORDER BY id ASC LIMIT 1 OFFSET 5`).get() as any;
    h.prepare(`UPDATE operator_audit_log SET action='config.get', target='innocent' WHERE id=?`).run(target.id);
    // Re-thread everything from the edited row on, with public SHA-256.
    const rows = h.prepare(`SELECT * FROM operator_audit_log WHERE id >= ? ORDER BY id ASC`).all(target.id) as any[];
    let prev = (h.prepare(`SELECT rowHash FROM operator_audit_log WHERE id < ? ORDER BY id DESC LIMIT 1`).get(target.id) as any)?.rowHash ?? '';
    const upd = h.prepare(`UPDATE operator_audit_log SET prevHash=?, rowHash=? WHERE id=?`);
    for (const r of rows) {
      const hash = sha(canon([r.ts, r.actor, r.action, r.target, r.detail, r.sourceIp]), prev);
      upd.run(prev, hash, r.id);
      prev = hash;
    }
    // The append the old anchor would have re-pinned onto — written by the
    // attacker, chained onto the forged tail so every link is consistent.
    const last = h.prepare(`SELECT * FROM operator_audit_log ORDER BY id DESC LIMIT 1`).get() as any;
    const nextTs = last.ts + 1;
    h.prepare(
      `INSERT INTO operator_audit_log (ts, actor, action, target, detail, sourceIp, prevHash, rowHash)
       VALUES (?, 'local', 'config.set', 'after-forge', '{}', '127.0.0.1', ?, ?)`,
    ).run(nextTs, prev, sha(canon([nextTs, 'local', 'config.set', 'after-forge', '{}', '127.0.0.1']), prev));
    h.close();
    flushChainAnchors();

    const v = verifyAuditChain();
    assert.strictEqual(v.ok, false, `forged audit log reported ok — ${v.detail}`);
    assert.strictEqual(v.status, 'tail_mismatch', v.detail);
    assert.strictEqual(v.attested, false);
    assert.strictEqual(anchorOnDisk().chains.operator_audit_log.lastRowHash, pinned.lastRowHash);
  });

  // ── Case 11: THE RESIDUAL — with the private key, the forge still works ───
  // Conceded in server/auditChain.ts and in the docs, and asserted here so it
  // stays a measured fact rather than a footnote. A same-UID attacker who can
  // read audit-key.ed25519.pem can re-sign an anchor over anything they like.
  await restore();
  await check('case11: an attacker WITH the private key can still mint a clean anchor', async () => {
    const h = await external();
    h.prepare(`UPDATE spans SET severity='info', reason='Processing step' WHERE chainSeq=50`).run();
    const { tailSeq, tailHash } = rethread(h, 50);
    h.close();

    const privatePem = fs.readFileSync(path.join(HOOKS, 'audit-key.ed25519.pem'), 'utf8');
    const a = anchorOnDisk();
    a.chains.spans.lastId = tailSeq;
    a.chains.spans.lastRowHash = tailHash;
    a.updatedAt = new Date().toISOString();
    const chains: Record<string, unknown> = {};
    for (const k of Object.keys(a.chains).sort()) chains[k] = a.chains[k];
    const payload = JSON.stringify({ v: a.v, keyId: a.keyId, publicKey: a.publicKey, chains, updatedAt: a.updatedAt });
    a.sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privatePem).toString('base64');
    fs.writeFileSync(ANCHOR, JSON.stringify(a));
    resetAnchorCacheForTests();

    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', `the key-holder forge is expected to succeed: ${v.detail}`);
    assert.strictEqual(v.attested, true);
    assert.strictEqual((db.prepare(`SELECT severity FROM spans WHERE chainSeq=50`).get() as any).severity, 'info');
  });
  await restore();

  // ── Case 12: the legitimate paths must not be collateral damage ───────────
  await check('case12: ordinary ingest keeps advancing the pin', async () => {
    const before = spansPin().lastId;
    for (let i = 300; i < 340; i++) insertChainedSpan(sampleSpan(i));
    flushChainAnchors();
    assert.ok(spansPin().lastId > before, 'the pin must still move over honest appends');
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.attested, true);
  });

  await check('case12: retention pruning through our own handle stays ok', async () => {
    db.prepare(`DELETE FROM spans WHERE chainSeq BETWEEN 20 AND 60`).run();
    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.attested, true);
    assert.strictEqual(v.tombstones, 41);
  });

  await check('case12: pruning the PINNED position itself is still ok', async () => {
    // The tombstone freezes the hash that used to sit there, so the pin can still
    // be checked at its own position and the anchor keeps advancing.
    const pinnedSeq = spansPin().lastId;
    db.prepare(`DELETE FROM spans WHERE chainSeq = ?`).run(pinnedSeq);
    for (let i = 400; i < 405; i++) insertChainedSpan(sampleSpan(i));
    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.strictEqual(v.attested, true);
    assert.ok(spansPin().lastId > pinnedSeq, 'the pin should have moved past the tombstoned row');
  });

  await check('case12: a row hashed under the LEGACY scheme still verifies', async () => {
    const h = await external();
    const tail = h.prepare(`SELECT chainSeq AS seq, rowHash FROM spans ORDER BY chainSeq DESC LIMIT 1`).get() as any;
    const tomb = h.prepare(`SELECT chainSeq AS seq, rowHash FROM span_chain_tombstones ORDER BY chainSeq DESC LIMIT 1`).get() as any;
    const best = (tail?.seq ?? 0) >= (tomb?.seq ?? 0) ? tail : tomb;
    const seq = best.seq + 1;
    const rec = { ...sampleSpan(9001), chainSeq: seq, principal: null, agent_identity: null, delegation_id: null };
    // endNano and repo folded into the hash, exactly as the pre-fix code did.
    const rowHash = sha(spanCanonLegacy(rec), best.rowHash);
    h.prepare(`
      INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness,
                         attributes, startNano, endNano, repo, chainSeq, prevHash, rowHash)
      VALUES (@spanId,@traceId,@parentId,@name,@protocol,@reason,@severity,@harness,
              @attributes,@startNano,@endNano,@repo,@chainSeq,@prevHash,@rowHash)`)
      .run({ ...rec, prevHash: best.rowHash, rowHash });
    h.close();
    flushChainAnchors();
    const v = await verifySpanChain({ deep: true });
    assert.strictEqual(v.status, 'ok', v.detail);
    assert.ok(v.legacyFieldRows >= 1, `expected a legacy-scheme row, saw ${v.legacyFieldRows}`);
  });

  // ── Case 13: what the conditional pin costs ───────────────────────────────
  {
    const { registerChainProbe } = await import('../server/auditChain.js');
    void registerChainProbe;   // imported for the reader; the probe is db.ts's
    const at = db.prepare(`SELECT rowHash FROM spans WHERE chainSeq = ?`);
    const hi = (db.prepare(`SELECT MAX(chainSeq) AS m FROM spans`).get() as { m: number }).m;
    const N = 20_000;
    for (let i = 0; i < 2_000; i++) at.get((i % hi) + 1);          // warm
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < N; i++) at.get((i % hi) + 1);
    const t1 = process.hrtime.bigint();
    const usPin = Number(t1 - t0) / 1000 / N;

    const t2 = process.hrtime.bigint();
    for (let i = 0; i < 200; i++) flushChainAnchors();
    const t3 = process.hrtime.bigint();
    const usSweep = Number(t3 - t2) / 1000 / 200;

    console.log(`  pin check: ${usPin.toFixed(2)} µs per lookup; full anchor sweep ` +
                `(3 chains, probe + pin + sign + fsync) ${usSweep.toFixed(0)} µs, once per ${5}s`);
    await check('case13: a pin lookup is an index seek, not a scan', () =>
      assert.ok(usPin < 50, `${usPin} µs — the chainSeq index is not being used`));
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  auditAnchorForgeTest: ${passed}/${total} passed`);
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
    console.error('auditAnchorForgeTest crashed:', e);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
    process.exit(1);
  });
