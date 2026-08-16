/**
 * tests/auditAnchorTest.ts
 *
 * Gate for server/auditAnchor.ts — the external-witness checkpointing layer
 * that sits on top of the local Ed25519 hash chain (auditChain.ts). Deliberately
 * narrow to the claims the module actually makes:
 *
 *   1. TRUNCATION WINDOW — the pure function an auditor reads first: disabled,
 *      enabled-but-never-countersigned, and countersigned-N-seconds-ago all
 *      report the right number and the right honest caveat text.
 *   2. TOKEN VERIFICATION — a synthetic RFC 3161 TimeStampToken (built with the
 *      exact DER nesting verifyTsaToken walks, constructed independently of
 *      production's own DER encoder so this isn't just verifying itself) is
 *      accepted when its messageImprint matches the checkpoint hash, and
 *      REJECTED when it doesn't — the one thing a third party can mechanically
 *      check without trusting us.
 *   3. OFFLINE QUEUE + RETRY — pointing the TSA at a closed local port gives a
 *      deterministic ECONNREFUSED with no dependency on this machine's actual
 *      internet access. Proves a checkpoint is persisted to disk BEFORE the
 *      network call, survives a failed attempt, and is retried — not dropped —
 *      on the next sweep.
 *   4. LIVE TSA ROUND TRIP — best-effort, network-guarded. A real fetch probe
 *      (not just DNS) decides whether to run it for real and assert success,
 *      or skip cleanly with a note. Never flakes CI for being offline; never
 *      silently hides a real regression while online.
 *
 * Sandboxed per CLAUDE.md: CLAUDESEC_HOME points at a throwaway temp dir, set
 * BEFORE any server-side import, so the Ed25519 audit key this test mints and
 * the checkpoint queue it writes never touch ~/.claudesec. Cleaned up on exit.
 *
 * Run via: npx tsx tests/auditAnchorTest.ts
 *   Exit 0 → every check passed (or cleanly skipped offline). Exit 1 → a failure.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CSEC_TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-auditanchor-home-'));
process.env.CLAUDESEC_HOME = CSEC_TEST_HOME;
const removeTestHome = () => { try { fs.rmSync(CSEC_TEST_HOME, { recursive: true, force: true }); } catch {} };
process.on('exit', removeTestHome);

let passed = 0;
let skipped = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}
function note(msg: string): void { skipped++; console.log(`  note: ${msg}`); }

// ---------------------------------------------------------------------------
// Minimal DER builder — just enough to construct a well-formed synthetic RFC
// 3161 TimeStampToken (ContentInfo → SignedData → encapContentInfo → TSTInfo).
// Written independently of server/auditAnchor.ts's own DER encoder so this
// test exercises the PARSER against a token it did not produce itself — the
// thing a real third-party TSA response looks like from the outside.
// ---------------------------------------------------------------------------
function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
function seq(children: Buffer[]): Buffer { return tlv(0x30, Buffer.concat(children)); }
function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const chunk: number[] = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) { chunk.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
function int(n: number): Buffer { return tlv(0x02, Buffer.from([n])); }
function octets(buf: Buffer): Buffer { return tlv(0x04, buf); }
function explicit0(inner: Buffer): Buffer { return tlv(0xA0, inner); }
function genTime(s: string): Buffer { return tlv(0x18, Buffer.from(s, 'ascii')); }
const NULL_TLV = tlv(0x05, Buffer.alloc(0));
const TSTINFO_CONTENT_OID = '1.2.840.113549.1.9.16.1.4';
const SIGNED_DATA_OID = '1.2.840.113549.1.7.2';
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

/** A synthetic-but-structurally-real TimeStampToken (the ContentInfo DER
 *  verifyTsaToken expects) whose messageImprint is exactly `hashHex`. */
function buildFakeToken(hashHex: string, genTimeStr = '20260101000000Z'): Buffer {
  const messageImprint = seq([seq([oid(SHA256_OID), NULL_TLV]), octets(Buffer.from(hashHex, 'hex'))]);
  const tstInfo = seq([
    int(1),                 // version
    oid('1.2.3.4'),         // policy — arbitrary, unchecked by verifyTsaToken
    messageImprint,
    int(1),                 // serialNumber
    genTime(genTimeStr),
  ]);
  const encapContentInfo = seq([oid(TSTINFO_CONTENT_OID), explicit0(octets(tstInfo))]);
  const signedData = seq([int(3), tlv(0x31, Buffer.alloc(0)), encapContentInfo]);
  return seq([oid(SIGNED_DATA_OID), explicit0(signedData)]);
}

/** Real reachability probe — not just DNS — so a sandbox with working DNS but
 *  no outbound TCP/HTTP doesn't misreport itself as "online" and turn a clean
 *  skip into a flaky failure. Any successful HTTP response (any status) counts
 *  as reachable; any throw (DNS, connect, TLS, abort) counts as offline. */
async function probeNetwork(url: string, timeoutMs: number): Promise<boolean> {
  try {
    await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(timeoutMs) });
    return true;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const {
    computeTruncationWindow, verifyTsaToken, checkpointHash, buildCheckpoint,
    createAndQueueCheckpoint, submitPendingCheckpoints, listCheckpoints, getAnchorStatus,
  } = await import('../server/auditAnchor.js');

  // ── 1. Truncation window — pure function, three cases ──────────────────────
  {
    const disabled = computeTruncationWindow({ enabled: false, lastReceiptedAt: null });
    check('truncation: anchoring disabled reports a null (unbounded) window', () => {
      assert.strictEqual(disabled.windowMs, null);
    });
    check('truncation: disabled detail names the exposure plainly', () => {
      assert.match(disabled.detail, /no bound on the exposure window/i);
    });

    const neverReceipted = computeTruncationWindow({ enabled: true, lastReceiptedAt: null });
    check('truncation: enabled-but-never-countersigned also reports null', () => {
      assert.strictEqual(neverReceipted.windowMs, null);
    });
    check('truncation: never-countersigned detail says everything is exposed', () => {
      assert.match(neverReceipted.detail, /every row written so far/i);
    });

    const now = Date.parse('2026-01-01T00:10:00.000Z');
    const receiptedAt = '2026-01-01T00:00:00.000Z'; // 10 minutes before `now`
    const window = computeTruncationWindow({ enabled: true, lastReceiptedAt: receiptedAt }, now);
    check('truncation: computes the exact elapsed milliseconds', () => {
      assert.strictEqual(window.windowMs, 10 * 60_000);
    });
    check('truncation: detail reports it in seconds', () => {
      assert.match(window.detail, /600s ago/);
    });
    check('truncation: never negative — a receipt that is somehow "in the future" clamps to 0', () => {
      const future = computeTruncationWindow({ enabled: true, lastReceiptedAt: '2026-01-01T01:00:00.000Z' }, now);
      assert.strictEqual(future.windowMs, 0);
    });
  }

  // ── 2. Token verification — accept a matching token, reject a mismatching one
  {
    const cp = buildCheckpoint();
    const hash = checkpointHash(cp);

    const goodToken = buildFakeToken(hash);
    const goodResult = verifyTsaToken(goodToken, hash);
    check('token: matching messageImprint verifies ok', () => assert.strictEqual(goodResult.ok, true));
    check('token: genTime is read back out of the token', () => assert.strictEqual(goodResult.genTime, '20260101000000Z'));

    const otherHash = crypto.createHash('sha256').update('a different checkpoint entirely').digest('hex');
    const wrongToken = buildFakeToken(otherHash);
    const rejected = verifyTsaToken(wrongToken, hash);
    check('token: a token covering a DIFFERENT hash is rejected', () => assert.strictEqual(rejected.ok, false));
    check('token: rejection explains it does not cover this checkpoint', () => {
      assert.match(rejected.detail, /does not cover this checkpoint/);
    });

    const garbage = Buffer.from([0x01, 0x02, 0x03]);
    const unparseable = verifyTsaToken(garbage, hash);
    check('token: unparseable bytes fail closed (ok:false), not throw', () => assert.strictEqual(unparseable.ok, false));
  }

  // ── 3. Offline queue + retry — deterministic, no real network required ─────
  {
    process.env.CLAUDESEC_ANCHOR_METHOD = 'tsa';
    // Nothing listens on 127.0.0.1:1 — ECONNREFUSED is immediate and doesn't
    // depend on whether this machine actually has internet access. Same
    // observable behavior as a genuinely unreachable TSA.
    process.env.CLAUDESEC_ANCHOR_TSA_URL = 'http://127.0.0.1:1';
    process.env.CLAUDESEC_ANCHOR_TIMEOUT_MS = '2000';

    const entry = createAndQueueCheckpoint();
    check('offline: a checkpoint is created and locally signed before any network call', () => {
      assert.ok(entry, 'createAndQueueCheckpoint returned an entry');
      assert.strictEqual(entry!.status, 'pending');
      assert.ok(entry!.cose.length > 0, 'COSE_Sign1 envelope is present at creation time');
    });

    // Durability: it must be ON DISK now, before submitPendingCheckpoints ever
    // runs a network call — see the file header's "durable queue" claim.
    const queuePath = path.join(CSEC_TEST_HOME, 'hooks', 'audit-anchor-checkpoints.json');
    const onDiskBefore = JSON.parse(fs.readFileSync(queuePath, 'utf8')) as { entries: Array<{ id: number; status: string }> };
    check('offline: the queued checkpoint is persisted to disk before the sweep runs', () => {
      assert.ok(onDiskBefore.entries.some((e) => e.id === entry!.id && e.status === 'pending'));
    });

    await submitPendingCheckpoints();
    const afterFirst = listCheckpoints(1)[0];
    check('offline: a failed attempt is recorded, not silently dropped', () => {
      assert.strictEqual(afterFirst.id, entry!.id);
      assert.strictEqual(afterFirst.status, 'error');
      assert.strictEqual(afterFirst.attempts, 1);
      assert.ok(afterFirst.lastError, 'lastError explains why it is not receipted');
    });

    await submitPendingCheckpoints();
    const afterSecond = listCheckpoints(1)[0];
    check('offline: retried on the next sweep — same entry, attempts accumulate, never lost', () => {
      assert.strictEqual(afterSecond.id, entry!.id);
      assert.strictEqual(afterSecond.attempts, 2);
      assert.strictEqual(afterSecond.status, 'error'); // still queued — see pruneQueue in auditAnchor.ts
    });

    const status = getAnchorStatus();
    check('offline: status reports the exposure honestly — no receipted checkpoint yet', () => {
      assert.strictEqual(status.lastReceipted, null);
      assert.strictEqual(status.truncationWindowMs, null);
      assert.match(status.truncationWindowDetail, /every row written so far/i);
      assert.strictEqual(status.errorCount >= 1, true);
    });
  }

  // ── 4. Live TSA round trip — best-effort, network-guarded ──────────────────
  {
    const TSA_URL = 'http://timestamp.digicert.com';
    const online = await probeNetwork(TSA_URL, 3_000);
    if (!online) {
      note(`no outbound reachability to ${TSA_URL} — skipping the live TSA round trip (this is the expected offline path, not a failure)`);
    } else {
      process.env.CLAUDESEC_ANCHOR_METHOD = 'tsa';
      delete process.env.CLAUDESEC_ANCHOR_TSA_URL; // fall back to the real default TSA
      process.env.CLAUDESEC_ANCHOR_TIMEOUT_MS = '10000';

      const entry = createAndQueueCheckpoint();
      await submitPendingCheckpoints();
      const after = listCheckpoints(1)[0];
      check('live TSA: a reachable public TSA actually countersigns the checkpoint', () => {
        assert.ok(entry, 'checkpoint created');
        assert.strictEqual(after.id, entry!.id);
        assert.strictEqual(
          after.status, 'receipted',
          `expected receipted, got ${after.status} (${after.lastError ?? 'no error recorded'})`,
        );
        assert.ok(after.token, 'the raw TSA token is stored');
        assert.strictEqual(after.tokenHashAlgorithm, 'sha256');
        assert.ok(after.tsGenTime, 'the TSA-asserted time is recorded');
      });
      if (after.status === 'receipted' && after.token) {
        const tokenBuf = Buffer.from(after.token, 'base64');
        const reverified = verifyTsaToken(tokenBuf, after.checkpointHash);
        check('live TSA: the stored token independently re-verifies against the checkpoint hash', () => {
          assert.strictEqual(reverified.ok, true);
        });
        const statusAfter = getAnchorStatus();
        check('live TSA: status now reports a bounded, near-zero truncation window', () => {
          assert.ok(statusAfter.truncationWindowMs !== null);
          assert.ok((statusAfter.truncationWindowMs as number) < 60_000, 'just-countersigned window should be well under a minute');
        });
      }
    }
  }

  console.log(`\n${passed} check(s) passed, ${skipped} skipped, ${failures.length} failed.`);
  if (failures.length) {
    console.error('\nFAILURES:');
    for (const f of failures) console.error(`  - ${f}`);
    process.exitCode = 1;
  }
}

void main();
