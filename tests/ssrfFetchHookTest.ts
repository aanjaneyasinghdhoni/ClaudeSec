/**
 * tests/ssrfFetchHookTest.ts
 *
 * Gate for the PreToolUse hook's SSRF-on-fetch floor — the layer that blocks a
 * WebFetch aimed at a cloud-metadata endpoint (169.254.169.254) or an internal
 * RFC1918 / loopback host before the request leaves the machine. This is the
 * "open-door test": until this floor existed, the enforcement hook intercepted
 * Bash/Edit/Read but NOT WebFetch, so an agent could fetch instance credentials.
 *
 * Black-box: every case spawns the REAL tracked hook
 * (cli/hooks/claudesec-enforce.cjs) as a child, mirroring exfilFloorHookTest /
 * catastrophicFloorHookTest. The best-effort block POST is aimed at a dead port
 * (CLAUDESEC_PORT=9) so nothing reaches the live dashboard.
 *
 * Coverage:
 *   • http://169.254.169.254/latest/meta-data/  → BLOCK even in monitor (floor).
 *   • http://127.0.0.1:8080/                     → BLOCK in enforce; ALLOW with
 *     CLAUDESEC_ALLOW_LOCAL_FETCH=1 (local Ollama / dev server opt-out).
 *   • http://10.0.0.5/admin                      → BLOCK in enforce (RFC1918).
 *   • https://example.com/                       → ALLOW (public host).
 *   • missing / garbage URL                      → fail-open ALLOW (never crash).
 *
 * Run via:  npx tsx tests/ssrfFetchHookTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

// A standalone enforce-config.json (mode: 'enforce') in a temp dir. resolveMode()
// reads the config FILE before CLAUDESEC_MODE, and the repo-root config pins
// 'monitor', so the env var alone would be shadowed — we point
// CLAUDESEC_ENFORCE_CONFIG at this file to actually exercise enforce mode. Cleaned
// up in finally. We never touch the real enforce-config.json.
const ENFORCE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'claudesec-ssrf-'));
const ENFORCE_CONFIG = path.join(ENFORCE_DIR, 'enforce-config.json');
fs.writeFileSync(ENFORCE_CONFIG, JSON.stringify({ mode: 'enforce', overrides: {} }));

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

interface Opts {
  /** 'monitor' (default) | 'enforce' — sets CLAUDESEC_MODE on the child. */
  mode?: 'monitor' | 'enforce';
  /** When true, sets CLAUDESEC_ALLOW_LOCAL_FETCH=1 (local-fetch opt-out). */
  allowLocal?: boolean;
}

/**
 * Run the real hook with a WebFetch tool call on stdin, isolated so the ambient
 * shell can't leak CLAUDESEC_MODE / bypass into the child. `toolInput` is the raw
 * tool_input object (so we can also send a missing/garbage url). Aims the would-be
 * POST at a dead port. Resolves on exit or a ~1s timeout.
 */
function runFetch(toolInput: unknown, opts: Opts = {}): Promise<{ code: number | null }> {
  const stdin = JSON.stringify({ tool_name: 'WebFetch', tool_input: toolInput });
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.CLAUDESEC_MODE;
    delete env.CLAUDESEC_HOOKS_BYPASS;
    delete env.CLAUDESEC_ENFORCE_CONFIG;
    delete env.CLAUDESEC_ENFORCE_RULES;
    delete env.CLAUDESEC_PROTECTED_PATHS;
    delete env.CLAUDESEC_ALLOW_LOCAL_FETCH;
    env.CLAUDESEC_PORT = '9'; // dead port — the block POST goes nowhere
    // Drive enforce mode via the config FILE override (resolveMode reads it before
    // CLAUDESEC_MODE; the repo-root config otherwise pins 'monitor'). Monitor is
    // the hook's safe default when no config/env is set.
    if (opts.mode === 'enforce') env.CLAUDESEC_ENFORCE_CONFIG = ENFORCE_CONFIG;
    else if (opts.mode) env.CLAUDESEC_MODE = opts.mode;
    if (opts.allowLocal) env.CLAUDESEC_ALLOW_LOCAL_FETCH = '1';

    const child = spawn(process.execPath, [HOOK], { cwd: REPO_ROOT, env });
    let settled = false;
    const done = (code: number | null) => {
      if (settled) return;
      settled = true;
      resolve({ code });
    };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } done(null); }, 1000);
    timer.unref?.();
    child.on('exit', (code) => { clearTimeout(timer); done(code); });
    child.on('error', () => { clearTimeout(timer); done(null); });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

async function main(): Promise<void> {
  // ── Cloud-metadata floor: always blocks, even in the default monitor mode. ──
  {
    const { code } = await runFetch({ url: 'http://169.254.169.254/latest/meta-data/' });
    check('FLOOR: metadata 169.254.169.254 blocked in monitor', () =>
      assert.strictEqual(code, 2));
  }
  {
    const { code } = await runFetch({ url: 'http://169.254.169.254/latest/meta-data/' }, { mode: 'enforce' });
    check('FLOOR: metadata 169.254.169.254 blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    // GCP metadata hostname — also an always-on floor target.
    const { code } = await runFetch({ url: 'http://metadata.google.internal/computeMetadata/v1/' });
    check('FLOOR: metadata.google.internal blocked in monitor', () =>
      assert.strictEqual(code, 2));
  }
  {
    // Bare `metadata` — GCP's short hostname; resolves to the same metadata IP
    // inside a GCE instance. Always-block floor, even in monitor.
    const { code } = await runFetch({ url: 'http://metadata/computeMetadata/v1/' });
    check('FLOOR: bare metadata hostname blocked in monitor', () =>
      assert.strictEqual(code, 2));
  }
  {
    // IPv4-mapped IPv6 metadata in the HEX-hextet form the WHATWG URL parser
    // actually produces: http://[::ffff:169.254.169.254]/ → host ::ffff:a9fe:a9fe.
    // Before the unwrap fix this sailed through as a "public" literal.
    const { code } = await runFetch({ url: 'http://[::ffff:169.254.169.254]/latest/meta-data/' });
    check('FLOOR: ::ffff:169.254.169.254 (hex-mapped) blocked in monitor', () =>
      assert.strictEqual(code, 2));
  }
  {
    // IPv4-mapped IPv6 loopback in hex form: http://[::ffff:127.0.0.1]/ → host
    // ::ffff:7f00:1. Loopback → blocked in enforce.
    const { code } = await runFetch({ url: 'http://[::ffff:127.0.0.1]/' }, { mode: 'enforce' });
    check('LOOPBACK: ::ffff:127.0.0.1 (hex-mapped) blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }

  // ── Loopback: blocked in enforce; allowed with the local-fetch opt-out. ──
  {
    const { code } = await runFetch({ url: 'http://127.0.0.1:8080/' }, { mode: 'enforce' });
    check('LOOPBACK: 127.0.0.1 blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    const { code } = await runFetch(
      { url: 'http://127.0.0.1:8080/' },
      { mode: 'enforce', allowLocal: true },
    );
    check('LOOPBACK: 127.0.0.1 allowed with CLAUDESEC_ALLOW_LOCAL_FETCH=1', () =>
      assert.strictEqual(code, 0));
  }
  {
    // In monitor mode loopback is a would-block (logged), not a hard block → allow.
    const { code } = await runFetch({ url: 'http://127.0.0.1:8080/' });
    check('LOOPBACK: 127.0.0.1 allowed (would-block) in monitor', () =>
      assert.strictEqual(code, 0));
  }
  {
    // http://0/ — the WHATWG parser normalizes the bare `0` host to 0.0.0.0, which
    // routes to localhost on Linux. 0.0.0.0/8 is classified loopback → blocked in
    // enforce. (Before the fix the v4 branch had no a===0 case and allowed it.)
    const { code } = await runFetch({ url: 'http://0/' }, { mode: 'enforce' });
    check('LOOPBACK: http://0/ (→0.0.0.0) blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    const { code } = await runFetch({ url: 'http://0.0.0.0:8080/' }, { mode: 'enforce' });
    check('LOOPBACK: 0.0.0.0 blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    // Like any loopback, 0.0.0.0 honors the local-fetch opt-out.
    const { code } = await runFetch(
      { url: 'http://0.0.0.0:8080/' },
      { mode: 'enforce', allowLocal: true },
    );
    check('LOOPBACK: 0.0.0.0 allowed with CLAUDESEC_ALLOW_LOCAL_FETCH=1', () =>
      assert.strictEqual(code, 0));
  }
  {
    // http://[::]/ — IPv6 unspecified, routes to localhost. Loopback → enforce block.
    const { code } = await runFetch({ url: 'http://[::]/' }, { mode: 'enforce' });
    check('LOOPBACK: [::] (IPv6 unspecified) blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }

  // ── RFC1918 internal: blocked in enforce, would-block (allow) in monitor. ──
  {
    const { code } = await runFetch({ url: 'http://10.0.0.5/admin' }, { mode: 'enforce' });
    check('INTERNAL: 10.0.0.5 blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    const { code } = await runFetch({ url: 'http://10.0.0.5/admin' });
    check('INTERNAL: 10.0.0.5 allowed (would-block) in monitor', () =>
      assert.strictEqual(code, 0));
  }
  {
    // 192.168/16 and a *.internal hostname round out the internal set.
    const { code } = await runFetch({ url: 'http://192.168.1.1/' }, { mode: 'enforce' });
    check('INTERNAL: 192.168.1.1 blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }
  {
    const { code } = await runFetch({ url: 'http://db.internal/' }, { mode: 'enforce' });
    check('INTERNAL: *.internal hostname blocked in enforce', () =>
      assert.strictEqual(code, 2));
  }

  // ── Public host: always allowed (we cannot resolve it synchronously). ──
  {
    const { code } = await runFetch({ url: 'https://example.com/' }, { mode: 'enforce' });
    check('PUBLIC: example.com allowed in enforce', () =>
      assert.strictEqual(code, 0));
  }
  {
    const { code } = await runFetch({ url: 'https://example.com/' });
    check('PUBLIC: example.com allowed in monitor', () =>
      assert.strictEqual(code, 0));
  }

  // ── Fail-open: missing / garbage URL never crashes or blocks. ──
  {
    const { code } = await runFetch({}, { mode: 'enforce' });
    check('FAIL-OPEN: missing url allowed', () =>
      assert.strictEqual(code, 0));
  }
  {
    const { code } = await runFetch({ url: 'not a url ::: %%%' }, { mode: 'enforce' });
    check('FAIL-OPEN: garbage url allowed', () =>
      assert.strictEqual(code, 0));
  }
  {
    // A non-http scheme is out of scope for the HTTP-SSRF floor → allow.
    const { code } = await runFetch({ url: 'file:///etc/passwd' }, { mode: 'enforce' });
    check('FAIL-OPEN: non-http scheme allowed', () =>
      assert.strictEqual(code, 0));
  }
}

function cleanup(): void {
  try { fs.rmSync(ENFORCE_DIR, { recursive: true, force: true }); } catch { /* */ }
}

main()
  .then(() => {
    cleanup();
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  ssrfFetchHookTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    cleanup();
    console.error('ssrfFetchHookTest crashed:', e);
    process.exit(1);
  });
