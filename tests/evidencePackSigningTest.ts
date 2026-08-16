/**
 * tests/evidencePackSigningTest.ts
 *
 * Gate for the signature on GET /api/governance/evidence. The evidence pack is
 * the one artifact this tool hands to a party that does not trust the exporter,
 * so the signature on it is not a nicety — it is the only reason the recipient
 * has to read the file at all.
 *
 *   1. Signing never MINTS a key. A pack requested on an install whose key was
 *      removed exports unsigned; it does not quietly found a new identity and
 *      sign under a keyId no recipient has ever recorded.
 *   2. Probing for a key does not poison the anchor's own signing path — the
 *      chain still mints and signs normally afterwards.
 *   3. A pack from a keyed install reports signed: true, ed25519, and the same
 *      keyId GET /api/audit/public-key serves.
 *   4. The signature verifies with ONLY the public key PEM, following the recipe
 *      the pack itself prints in verification.howToVerify — the canonicalization
 *      is re-implemented here from that description rather than imported, since
 *      a recipe only a recipient can't reproduce is worth nothing.
 *   5. Tampering with any part of the covered payload — the manifest numbers,
 *      the summary prose, or a CSV row — fails verification.
 *   6. The signature is asymmetric: 64 raw Ed25519 bytes, and no secret key
 *      material rides along in the pack.
 *   7. An install where no key can be obtained still gets its pack — HTTP 200,
 *      signed: false, and a reason — rather than an exception. Run in a child
 *      process, since the key resolves once per process and this case needs an
 *      install that never had one.
 *
 * Fully sandboxed: CLAUDESEC_DB, CLAUDESEC_HOME and HOME all point into a
 * throwaway directory under os.tmpdir(), set BEFORE any server module is
 * imported (the db module opens its file at import time). The live spans DB and
 * the real ~/.claudesec are never touched.
 *
 * Run via:  npx tsx tests/evidencePackSigningTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';

const __filename_ = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename_), '..');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

/** Set by the parent when it re-runs this file for the keyless case. */
const KEYLESS_CHILD = process.env.CSEC_EVIDENCE_KEYLESS === '1';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-evidence-sign-'));
// The keyless child arrives with its own sandbox already pointed at a home it
// cannot create, so it must not be overwritten here.
if (!KEYLESS_CHILD) {
  process.env.CLAUDESEC_DB   = path.join(TMP, 'spans.db');
  process.env.CLAUDESEC_HOME = path.join(TMP, '.claudesec');
  process.env.HOME           = TMP;
}
process.env.CLAUDESEC_WATCH = '0';

const HOOKS_DIR = path.join(process.env.CLAUDESEC_HOME!, 'hooks');
const PRIVATE_KEY_PATH = path.join(HOOKS_DIR, 'audit-key.ed25519.pem');
const PUBLIC_KEY_PATH  = path.join(HOOKS_DIR, 'audit-key.pub.pem');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

/**
 * The canonicalization exactly as verification.howToVerify describes it: sort
 * object keys recursively at every level, then JSON.stringify with no extra
 * whitespace. Deliberately a second implementation — importing the server's own
 * canonicalize() would test that the code agrees with itself, not that a
 * recipient following the printed instructions arrives at the same bytes.
 */
function canonicalizeAsRecipient(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) out[k] = sort((v as Record<string, unknown>)[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sort(value));
}

interface EvidencePack {
  manifest: Record<string, unknown>;
  summaryMarkdown: string;
  alertsCsv: string;
  enforceCsv: string;
  auditCsv: string;
  verification: {
    signed: boolean;
    reason?: string;
    algorithm?: string;
    keyId?: string;
    signature?: string;
    publicKeyEndpoint: string;
    howToVerify: string;
  };
}

/** The five fields the signature covers, in the shape the pack documents. */
function coveredPayload(pack: EvidencePack): Record<string, unknown> {
  return {
    manifest: pack.manifest,
    summaryMarkdown: pack.summaryMarkdown,
    alertsCsv: pack.alertsCsv,
    enforceCsv: pack.enforceCsv,
    auditCsv: pack.auditCsv,
  };
}

function verifyAsRecipient(payload: Record<string, unknown>, signatureB64: string, publicKeyPem: string): boolean {
  return crypto.verify(
    null,
    Buffer.from(canonicalizeAsRecipient(payload), 'utf8'),
    publicKeyPem,
    Buffer.from(signatureB64, 'base64'),
  );
}

/** Mount the real governance routes on an ephemeral port and download one pack. */
async function fetchPack(): Promise<{ status: number; pack: EvidencePack }> {
  const { default: express } = await import('express');
  const { registerGovernanceRoutes } = await import('../server/routes/governance.js');

  const app = express();
  registerGovernanceRoutes(app, { appVersion: '0.0.0-test' } as never);
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', () => resolve()));
  const port = (server.address() as AddressInfo).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/governance/evidence`, { signal: AbortSignal.timeout(20_000) });
    return { status: res.status, pack: await res.json() as EvidencePack };
  } finally {
    server.close();
  }
}

/**
 * Case 7, run as its own process: an install where the key directory cannot even
 * be created. The export must degrade to an honest `signed: false`, not 500 and
 * not throw — losing the whole evidence pack because the signature is
 * unavailable would be the audit tool taking away more than it gives.
 */
async function keylessMain(): Promise<void> {
  const { status, pack } = await fetchPack();
  check('case7: an unsignable install still gets its pack', () =>
    assert.strictEqual(status, 200));
  check('case7: it says plainly that it is unsigned', () =>
    assert.strictEqual(pack.verification.signed, false));
  check('case7: it gives the reason rather than a bare false', () =>
    assert.match(pack.verification.reason ?? '', /no Ed25519 signing key/i));
  check('case7: no signature is fabricated', () =>
    assert.strictEqual(pack.verification.signature, undefined));
  check('case7: the evidence itself is still there', () =>
    assert.ok(pack.summaryMarkdown.includes('ClaudeSec evidence pack')));
}

async function main(): Promise<void> {
  if (KEYLESS_CHILD) return keylessMain();

  // ── Case 1: no key on disk → sign, but never mint ─────────────────────────
  // Imported alone, auditChain does no signing of its own (its anchor sweep is
  // a timer that only writes when something is dirty), so this really is a
  // pristine install with no key file.
  const { signWithExistingAuditKey } = await import('../server/auditChain.js');

  check('case1: no signature is produced when the install has no key', () =>
    assert.strictEqual(signWithExistingAuditKey(Buffer.from('anything', 'utf8')), null));
  check('case1: asking for a signature did NOT mint a private key', () =>
    assert.strictEqual(fs.existsSync(PRIVATE_KEY_PATH), false));

  // ── Case 2: the probe did not poison the anchor's own signing path ────────
  const { flushChainAnchors, auditKeyId } = await import('../server/auditChain.js');
  const { db } = await import('../server/db.js');
  const { makeAuditLogger } = await import('../server/auditLog.js');

  const fakeReq = { socket: { remoteAddress: '127.0.0.1' } } as never;
  const auditLog = makeAuditLogger(() => ({}) as never, () => true);
  for (let i = 0; i < 5; i++) auditLog(fakeReq, 'config.set', `key-${i}`, { i });
  flushChainAnchors();

  check('case2: the chain still mints its key after a non-minting probe', () =>
    assert.ok(fs.existsSync(PRIVATE_KEY_PATH), 'no private key was ever created'));
  check('case2: the public half is exported for a third party', () =>
    assert.ok(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8').includes('BEGIN PUBLIC KEY')));

  const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');

  // ── Fetch a real pack off the real route ──────────────────────────────────
  const { status, pack } = await fetchPack();
  assert.strictEqual(status, 200, `evidence route returned ${status}`);

  // ── Case 3: the pack claims a signature, under the install's key ──────────
  check('case3: the pack is signed', () =>
    assert.strictEqual(pack.verification.signed, true, `unsigned: ${pack.verification.reason ?? 'no reason given'}`));
  check('case3: the algorithm is named for the verifier', () =>
    assert.strictEqual(pack.verification.algorithm, 'ed25519'));
  check('case3: the keyId is the one /api/audit/public-key serves', () =>
    assert.strictEqual(pack.verification.keyId, auditKeyId()));
  check('case3: a signed pack carries no "reason" excuse', () =>
    assert.strictEqual(pack.verification.reason, undefined));
  check('case3: the pack points at the public key endpoint', () =>
    assert.strictEqual(pack.verification.publicKeyEndpoint, '/api/audit/public-key'));

  // ── Case 6: asymmetric, and nothing secret rides along ────────────────────
  check('case6: the signature is 64 raw bytes — an Ed25519 signature, not an HMAC digest', () =>
    assert.strictEqual(Buffer.from(pack.verification.signature!, 'base64').length, 64));
  check('case6: no private key material is anywhere in the pack', () =>
    assert.ok(!JSON.stringify(pack).includes('PRIVATE KEY')));

  // ── Case 4: it verifies with the public key alone ─────────────────────────
  check('case4: the signature verifies against the public key alone', () =>
    assert.ok(verifyAsRecipient(coveredPayload(pack), pack.verification.signature!, publicKeyPem),
      'a pristine pack failed verification'));

  // ── Case 5: tampering is caught, wherever it happens ──────────────────────
  check('case5: a doctored manifest fails verification', () => {
    const tampered = coveredPayload(pack);
    tampered.manifest = { ...(pack.manifest as Record<string, unknown>), ruleCount: 999_999 };
    assert.strictEqual(verifyAsRecipient(tampered, pack.verification.signature!, publicKeyPem), false);
  });
  check('case5: a doctored summary fails verification', () => {
    const tampered = coveredPayload(pack);
    tampered.summaryMarkdown = pack.summaryMarkdown.replace('cannot prove', 'proves');
    assert.notStrictEqual(tampered.summaryMarkdown, pack.summaryMarkdown, 'the tamper was a no-op');
    assert.strictEqual(verifyAsRecipient(tampered, pack.verification.signature!, publicKeyPem), false);
  });
  check('case5: a deleted audit-log row fails verification', () => {
    const lines = pack.auditCsv.split('\n');
    assert.ok(lines.length > 2, 'expected seeded audit rows in the pack');
    const tampered = coveredPayload(pack);
    tampered.auditCsv = [lines[0], ...lines.slice(2)].join('\n');
    assert.strictEqual(verifyAsRecipient(tampered, pack.verification.signature!, publicKeyPem), false);
  });
  check('case5: a flipped signature byte fails verification', () => {
    const sig = Buffer.from(pack.verification.signature!, 'base64');
    sig[0] ^= 0xff;
    assert.strictEqual(verifyAsRecipient(coveredPayload(pack), sig.toString('base64'), publicKeyPem), false);
  });
  check('case5: another key cannot verify this pack', () => {
    const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
    assert.strictEqual(verifyAsRecipient(coveredPayload(pack), pack.verification.signature!, other), false);
  });

  try { db.close(); } catch { /* already closed */ }

  // ── Case 7: the keyless install, in its own process ───────────────────────
  // CLAUDESEC_HOME is pointed underneath a regular file, so the hooks directory
  // can never be created and no key can ever be resolved there.
  const blocker = path.join(TMP, 'blocker');
  fs.writeFileSync(blocker, 'not a directory');
  const child = spawnSync(TSX_BIN, [__filename_], {
    encoding: 'utf8',
    timeout: 60_000,
    env: {
      ...process.env,
      CSEC_EVIDENCE_KEYLESS: '1',
      CLAUDESEC_HOME: path.join(blocker, '.claudesec'),
      CLAUDESEC_DB: path.join(TMP, 'keyless.db'),
      HOME: TMP,
    },
  });
  check('case7: the keyless run passed every one of its own assertions', () =>
    assert.strictEqual(child.status, 0, `${child.stdout ?? ''}${child.stderr ?? ''}`));
  passed += Number((/(\d+) assertion/.exec(child.stdout ?? '') ?? [])[1] ?? 0);
}

main()
  .then(() => {
    if (failures.length > 0) {
      console.error(`\nevidencePackSigningTest: ${failures.length} failure(s)`);
      for (const f of failures) console.error(`  ✗ ${f}`);
      process.exit(1);
    }
    console.log(`evidencePackSigningTest: ${passed} assertion(s) passed`);
    process.exit(0);
  })
  .catch(err => {
    console.error(`evidencePackSigningTest: fatal — ${(err as Error).stack ?? err}`);
    process.exit(1);
  })
  .finally(() => {
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* best effort */ }
  });
