/**
 * tests/enforceOverrideTest.ts
 *
 * Gate for the per-rule action-override surface on PUT /api/enforce/config —
 * the backend behind the Rules tab's Block ⇄ Monitor toggle.
 *
 * What this proves (driving the REAL server over loopback):
 *   1. A normal { label: 'block' } / { label: 'alert' } override round-trips:
 *      it persists, is echoed back, and shows up on the subsequent GET.
 *   2. A bad action value ('observe') is a 400 — never silently coerced.
 *   3. SAFETY: demoting a catastrophic-floor label to 'alert' is REJECTED with a
 *      400 and never persisted. This mirrors the rule_overrides disable guard, so
 *      the action-override surface can't be used to silence the catastrophic
 *      events the tool exists to block. Setting the SAME label to 'block' is fine
 *      (a no-op promotion — the floor already blocks it).
 *
 * DB DISCIPLINE: child server uses CLAUDESEC_DB + CLAUDESEC_HOME +
 * CLAUDESEC_ENFORCE_CONFIG under os.tmpdir(), all deleted in a finally block.
 * CLAUDESEC_WATCH=0 keeps it off host transcripts. The real ~/.claudesec DB and
 * the maintainer's installed enforce-config are NEVER touched.
 *
 * Run via:  npx tsx tests/enforceOverrideTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure (or the server failed to boot).
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { CATASTROPHIC_DETECTION_LABELS } from '../server/detection.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'index.ts');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

const PORT = 3207;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(os.tmpdir(), `csec-enfovr-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-enfovr-home-'));
const ENFORCE_CFG = path.join(HOME_DIR, 'enforce-config.json');

// A real catastrophic-floor label (the guard keys off these exact strings).
const CATASTROPHIC_LABEL = [...CATASTROPHIC_DETECTION_LABELS][0];

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try { await fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function waitForServer(timeoutMs: number, earlyExit?: () => string | null): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dead = earlyExit?.();
    if (dead) throw new Error(`server failed to start: ${dead}`);
    try {
      const r = await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(1500) });
      if (r.status >= 200 && r.status < 500) return;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`server did not become ready on ${BASE} within ${timeoutMs}ms`);
}

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch { /* */ }
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch { /* */ }
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group already gone */ }
  try { child.kill('SIGKILL'); } catch { /* already dead */ }
}

const putConfig = (body: unknown) =>
  fetch(`${BASE}/api/enforce/config`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

async function main(): Promise<void> {
  // ── 0. Frontend/backend catastrophic-label parity ─────────────────────────
  // RulesTab.tsx hardcodes the catastrophic-floor labels to LOCK their toggle
  // (the React build can't import server/detection.ts). If a label is renamed
  // server-side, that copy would drift and a catastrophic rule would render an
  // (unblockable, but misleading) toggle. Catch the drift here.
  await check('RulesTab catastrophic-label set matches server detection.ts', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'src', 'RulesTab.tsx'), 'utf8');
    const block = src.slice(
      src.indexOf('CATASTROPHIC_LABELS'),
      src.indexOf('])', src.indexOf('CATASTROPHIC_LABELS')),
    );
    const uiLabels = new Set([...block.matchAll(/'([^']+)'/g)].map(m => m[1]));
    for (const label of CATASTROPHIC_DETECTION_LABELS) {
      assert.ok(uiLabels.has(label), `RulesTab is missing catastrophic label "${label}"`);
    }
    assert.strictEqual(
      uiLabels.size, CATASTROPHIC_DETECTION_LABELS.size,
      'RulesTab lists a different number of catastrophic labels than the server',
    );
  });

  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        CLAUDESEC_HOME: HOME_DIR,
        // Pin the enforce-config path so the test's writes can never reach the
        // maintainer's installed hook config.
        CLAUDESEC_ENFORCE_CONFIG: ENFORCE_CFG,
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_HOST: '127.0.0.1',
        CLAUDESEC_WATCH: '0',
        CLAUDESEC_MODE: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    });

    let serverLog = '';
    let exitInfo: string | null = null;
    child.stdout?.on('data', d => { serverLog += String(d); });
    child.stderr?.on('data', d => { serverLog += String(d); });
    child.on('exit', (code, sig) => { exitInfo = `child exited early (code=${code}, signal=${sig})`; });

    await waitForServer(30_000, () => exitInfo).catch(err => {
      throw new Error(`${err.message}\n--- server output ---\n${serverLog.slice(-2000)}`);
    });

    // ── 1. A normal action override round-trips. ──────────────────────────────
    await check('block override persists and echoes back', async () => {
      const r = await putConfig({ overrides: { 'Some custom rule': 'block' } });
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const body = await r.json();
      assert.strictEqual(body.overrides['Some custom rule'], 'block');
    });

    await check('GET reflects the persisted override', async () => {
      const r = await fetch(`${BASE}/api/enforce/config`);
      const body = await r.json();
      assert.strictEqual(body.overrides['Some custom rule'], 'block');
    });

    await check('alert override (monitor-only) round-trips', async () => {
      const r = await putConfig({ overrides: { 'Some custom rule': 'alert' } });
      assert.strictEqual(r.status, 200);
      const body = await r.json();
      assert.strictEqual(body.overrides['Some custom rule'], 'alert');
    });

    // ── 2. A bad action value is a 400. ───────────────────────────────────────
    await check('invalid action value → 400', async () => {
      const r = await putConfig({ overrides: { 'Some custom rule': 'observe' } });
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
    });

    // ── 3. SAFETY: a catastrophic-floor label can't be demoted to monitor. ────
    await check('demoting a catastrophic-floor label to alert → 400', async () => {
      const r = await putConfig({ overrides: { [CATASTROPHIC_LABEL]: 'alert' } });
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
      const body = await r.json().catch(() => ({}));
      assert.match(String(body.error ?? ''), /catastrophic/i);
    });

    await check('the rejected catastrophic demotion was NOT persisted', async () => {
      const r = await fetch(`${BASE}/api/enforce/config`);
      const body = await r.json();
      assert.strictEqual(
        body.overrides[CATASTROPHIC_LABEL], undefined,
        'a catastrophic-floor demotion must never reach the config',
      );
    });

    await check('promoting a catastrophic-floor label to block is allowed (no-op)', async () => {
      const r = await putConfig({ overrides: { [CATASTROPHIC_LABEL]: 'block' } });
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const body = await r.json();
      assert.strictEqual(body.overrides[CATASTROPHIC_LABEL], 'block');
    });
  } finally {
    if (child) {
      killTree(child);
      await sleep(200);
    }
    cleanup();
  }
}

main()
  .then(() => {
    const total = passed + failed;
    console.log('───────────────────────────────────────────────');
    console.log(`  enforceOverrideTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('enforceOverrideTest crashed:', e);
    process.exit(1);
  });
