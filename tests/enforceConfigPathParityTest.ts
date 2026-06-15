/**
 * tests/enforceConfigPathParityTest.ts
 *
 * P0 TRUST GATE: the dashboard's reported effective enforcement mode MUST equal
 * what the installed PreToolUse hook actually does. They are two separate code
 * paths — the server status reader (server/enforceStatus.resolveEffectiveMode,
 * which delegates to enforceEval.resolveConfigPath + resolveMode) and the
 * dependency-free hook (cli/hooks/claudesec-enforce.cjs, which mirrors the same
 * logic by hand). A regression that let them resolve DIFFERENT enforce-config.json
 * files is exactly how the dashboard once showed "monitor" while the hook blocked
 * a real command in "enforce". This test makes that divergence impossible to ship.
 *
 * Strategy — drive BOTH sides over the SAME input matrix and assert they agree:
 *   • SERVER side: call resolveEffectiveMode() in-process (the function the
 *     /api/enforce/config route uses to populate the dashboard).
 *   • HOOK side: spawn the REAL tracked hook (cli/hooks/claudesec-enforce.cjs) as a
 *     child against a temp rules snapshot with a single always-block rule, feed it a
 *     Bash command that matches, and read its EFFECTIVE MODE off the exit code:
 *       exit 2 (blocked) ⇒ the hook resolved 'enforce'
 *       exit 0 (allowed) ⇒ the hook resolved 'monitor'
 *     This is the hook's genuine, end-to-end mode decision — not a reimplementation.
 *
 * Input matrix (cwd is varied to prove the per-cwd repo-root file is NOT consulted):
 *   - global control-plane file present with mode enforce / monitor
 *   - global file ABSENT, CLAUDESEC_MODE env enforce / monitor / unset
 *   - global file ABSENT and env unset → 'monitor' default
 *   - a repo-root enforce-config.json present with the OPPOSITE mode (the old bug):
 *     both sides MUST ignore it and agree on the global/env/default result
 *   - explicit CLAUDESEC_ENFORCE_CONFIG override
 *
 * All temp dirs/files — the live ~/.claudesec and the repo-root enforce-config.json
 * are NEVER touched. The would-be block POST is aimed at a dead port.
 *
 * Run via:  npx tsx tests/enforceConfigPathParityTest.ts
 *   Exit 0 → hook and server agree on every case.   Exit 1 → a divergence.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { resolveEffectiveMode } from '../server/enforceStatus.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-cfgparity-'));

// A single always-block rule. The hook blocks ONLY in enforce mode on a rule match
// (the catastrophic floor would block in every mode, which would mask the mode
// decision — so we use a plain rule, not a floor command). 'PARITYMARKER' is a
// benign literal that no real command contains.
const RULES_SNAPSHOT = path.join(SANDBOX, 'rules-enforcement.json');
fs.writeFileSync(
  RULES_SNAPSHOT,
  JSON.stringify([{ source: 'PARITYMARKER', flags: '', label: 'parity probe', severity: 'high', action: 'block' }]),
);
const PROBE_COMMAND = 'echo PARITYMARKER';

type Mode = 'monitor' | 'enforce';

/** Snapshot + restore the env the resolvers read, run `body` with the overrides. */
function withEnv(vars: Record<string, string | undefined>, body: () => void): void {
  const keys = Object.keys(vars);
  const prev = new Map<string, string | undefined>();
  for (const k of keys) prev.set(k, process.env[k]);
  try {
    for (const k of keys) {
      if (vars[k] === undefined) delete process.env[k];
      else process.env[k] = vars[k]!;
    }
    body();
  } finally {
    for (const k of keys) {
      const v = prev.get(k);
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/**
 * Spawn the real hook and infer the EFFECTIVE MODE it resolved from its exit code.
 * The child sees only the env we pass (CLAUDESEC_HOME / CLAUDESEC_MODE /
 * CLAUDESEC_ENFORCE_CONFIG / CLAUDESEC_ENFORCE_RULES), runs in `cwd`, and aims its
 * block POST at a dead port. exit 2 ⇒ enforce, exit 0 ⇒ monitor.
 */
function hookEffectiveMode(env: Record<string, string | undefined>, cwd: string): Promise<Mode> {
  const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: PROBE_COMMAND } });
  return new Promise((resolve, reject) => {
    const childEnv: NodeJS.ProcessEnv = { ...process.env };
    // Start from a clean slate for the vars that steer resolution.
    delete childEnv.CLAUDESEC_MODE;
    delete childEnv.CLAUDESEC_HOOKS_BYPASS;
    delete childEnv.CLAUDESEC_ENFORCE_CONFIG;
    delete childEnv.CLAUDESEC_HOME;
    childEnv.CLAUDESEC_ENFORCE_RULES = RULES_SNAPSHOT;
    childEnv.CLAUDESEC_PORT = '9'; // dead port — block POST goes nowhere
    for (const [k, v] of Object.entries(env)) {
      if (v === undefined) delete childEnv[k];
      else childEnv[k] = v;
    }

    const child = spawn(process.execPath, [HOOK], { cwd, env: childEnv });
    let settled = false;
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } if (!settled) { settled = true; reject(new Error('hook timed out')); } }, 4000);
    timer.unref?.();
    child.on('exit', (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (code === 2) resolve('enforce');
      else if (code === 0) resolve('monitor');
      else reject(new Error(`unexpected hook exit code ${code}`));
    });
    child.on('error', (e) => { clearTimeout(timer); if (!settled) { settled = true; reject(e); } });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/** Write a global control-plane enforce-config.json under a temp CLAUDESEC_HOME. */
function makeHome(mode?: Mode): string {
  const home = fs.mkdtempSync(path.join(SANDBOX, 'home-'));
  const hooksDir = path.join(home, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });
  if (mode) {
    fs.writeFileSync(path.join(hooksDir, 'enforce-config.json'), JSON.stringify({ mode, overrides: {} }));
  }
  return home;
}

/** A throwaway "repo" cwd carrying a repo-root enforce-config.json (the OLD trap). */
function makeRepoWithRootConfig(mode: Mode): string {
  const dir = fs.mkdtempSync(path.join(SANDBOX, 'repo-'));
  fs.writeFileSync(path.join(dir, 'enforce-config.json'), JSON.stringify({ mode, overrides: {} }));
  return dir;
}

interface Case {
  name: string;
  /** env applied to BOTH the server resolver and the hook child. */
  env: Record<string, string | undefined>;
  /** cwd the hook child runs in (defaults to a neutral temp dir). */
  cwd?: string;
  expected: Mode;
}

async function runCases(): Promise<void> {
  const neutralCwd = fs.mkdtempSync(path.join(SANDBOX, 'cwd-'));

  const cases: Case[] = [
    // 1. Global file present, enforce. Both must report enforce.
    { name: 'global file = enforce', env: { CLAUDESEC_HOME: makeHome('enforce') }, expected: 'enforce' },
    // 2. Global file present, monitor. Both must report monitor.
    { name: 'global file = monitor', env: { CLAUDESEC_HOME: makeHome('monitor') }, expected: 'monitor' },
    // 3. Global file ABSENT, env enforce → env wins on both.
    { name: 'no global file, env=enforce', env: { CLAUDESEC_HOME: makeHome(undefined), CLAUDESEC_MODE: 'enforce' }, expected: 'enforce' },
    // 4. Global file ABSENT, env monitor → monitor on both.
    { name: 'no global file, env=monitor', env: { CLAUDESEC_HOME: makeHome(undefined), CLAUDESEC_MODE: 'monitor' }, expected: 'monitor' },
    // 5. Global file ABSENT, env UNSET → 'monitor' default on both.
    { name: 'no global file, env unset → default monitor', env: { CLAUDESEC_HOME: makeHome(undefined) }, expected: 'monitor' },
    // 6. THE OLD BUG: global file = enforce, BUT cwd has a repo-root config = monitor.
    //    Both sides MUST ignore the repo-root file and agree on enforce.
    {
      name: 'global=enforce wins over repo-root=monitor (per-cwd trap)',
      env: { CLAUDESEC_HOME: makeHome('enforce') },
      cwd: makeRepoWithRootConfig('monitor'),
      expected: 'enforce',
    },
    // 7. Inverse trap: global=monitor, repo-root=enforce. Both ignore repo-root.
    {
      name: 'global=monitor wins over repo-root=enforce (per-cwd trap)',
      env: { CLAUDESEC_HOME: makeHome('monitor') },
      cwd: makeRepoWithRootConfig('enforce'),
      expected: 'monitor',
    },
    // 8. No global file, env unset, but repo-root=enforce present in cwd → both
    //    must STILL resolve 'monitor' (repo-root is not in the precedence at all).
    {
      name: 'no global + repo-root=enforce in cwd → still monitor (repo-root ignored)',
      env: { CLAUDESEC_HOME: makeHome(undefined) },
      cwd: makeRepoWithRootConfig('enforce'),
      expected: 'monitor',
    },
    // 9. Explicit CLAUDESEC_ENFORCE_CONFIG override beats everything.
    {
      name: 'explicit CLAUDESEC_ENFORCE_CONFIG override = enforce',
      env: (() => {
        const f = path.join(SANDBOX, `override-${Math.random().toString(36).slice(2)}.json`);
        fs.writeFileSync(f, JSON.stringify({ mode: 'enforce', overrides: {} }));
        return { CLAUDESEC_HOME: makeHome('monitor'), CLAUDESEC_ENFORCE_CONFIG: f };
      })(),
      expected: 'enforce',
    },
  ];

  for (const c of cases) {
    const cwd = c.cwd ?? neutralCwd;
    // Server side: resolve in-process with the same env applied.
    let serverMode: Mode = 'monitor';
    withEnv(c.env, () => { serverMode = resolveEffectiveMode().effectiveMode; });
    // Hook side: spawn the real hook with the same env + cwd.
    const hookMode = await hookEffectiveMode(c.env, cwd);

    check(`${c.name}: server resolves expected`, () => {
      assert.strictEqual(serverMode, c.expected, `server resolved ${serverMode}, expected ${c.expected}`);
    });
    check(`${c.name}: hook resolves expected`, () => {
      assert.strictEqual(hookMode, c.expected, `hook resolved ${hookMode}, expected ${c.expected}`);
    });
    check(`${c.name}: hook === server (PARITY)`, () => {
      assert.strictEqual(hookMode, serverMode, `PARITY BREAK — hook=${hookMode}, server=${serverMode}`);
    });
  }
}

await runCases();

try { fs.rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* best-effort */ }

const total = passed + failures.length;
console.log('───────────────────────────────────────────────');
console.log(`  enforceConfigPathParityTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failures.length) {
  console.error(`\n  ${failures.length} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
