/**
 * tests/protectedPathsHookTest.ts
 *
 * Gate for the PreToolUse hook's "protected paths" floor — a per-user, always-on
 * block list that fires regardless of monitor/enforce mode, like the hardcoded
 * catastrophic floor but user-controlled.
 *
 * Black-box: every case spawns the REAL tracked hook
 * (cli/hooks/claudesec-enforce.cjs) as a child, with CLAUDESEC_PROTECTED_PATHS
 * pointing at a temp file holding [{"path":"/x/.env","label":"env"}]. NO mode is
 * set (so the resolved mode is the safe default 'monitor'), proving the floor is
 * always-on.
 *
 *   1. Read of /x/.env                         → exit 2 (blocked, monitor mode).
 *   2. Bash `cat /x/.env`                       → exit 2.
 *   3. Edit whose file_path is /x/.env          → exit 2.
 *   4. Unrelated Read /x/app.ts                 → exit 0 (allowed).
 *   5. Edit of /x/app.ts whose CONTENT mentions /x/.env → exit 0 (no content match).
 *   6. Empty protected-paths file, unrelated call → exit 0 (fail-open).
 *   7. Stored '~/.ssh/id_rsa', Read of the home-EXPANDED absolute path → exit 2.
 *   8. Stored '/x/.env', Read of '/X/.ENV' (case variation) → exit 2.
 *   9. Stored '~/.ssh/id_rsa', Bash `cat $HOME/.ssh/id_rsa` → exit 2 ($HOME expand).
 *  10. MultiEdit whose edit target file_path is /x/.env → exit 2.
 *  11. Enforce mode, Bash command matching a block rule → exit 2 (rule-engine live).
 *  12. Enforce mode, Read of a non-protected path matching that rule → exit 0
 *      (reads run only the protected-paths floor, never the command rule-engine).
 *
 * Fully sandboxed: temp files live under os.tmpdir() and are removed in finally;
 * the hook's best-effort POST is aimed at a dead port (CLAUDESEC_PORT=9) so it
 * never touches the live dashboard. The real ~/.claude / ~/.claudesec are never
 * read because CLAUDESEC_PROTECTED_PATHS overrides the lookup.
 *
 * Run via:  npx tsx tests/protectedPathsHookTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

/**
 * Run the real hook with the given stdin, isolated so the ambient shell can't
 * leak CLAUDESEC_MODE / bypass into the child. Aims the would-be POST at a dead
 * port so nothing hits the live dashboard. Resolves on exit or a ~1s timeout.
 */
function runHook(
  stdin: string,
  extraEnv: Record<string, string>,
): Promise<{ code: number | null }> {
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.CLAUDESEC_MODE;
    delete env.CLAUDESEC_HOOKS_BYPASS;
    delete env.CLAUDESEC_ENFORCE_CONFIG;
    delete env.CLAUDESEC_ENFORCE_RULES;
    delete env.CLAUDESEC_PROTECTED_PATHS;
    env.CLAUDESEC_PORT = '9'; // dead port — the block POST goes nowhere
    Object.assign(env, extraEnv);

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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-protected-'));
  const protectedFile = path.join(tmp, 'protected-paths.json');
  fs.writeFileSync(protectedFile, JSON.stringify([{ path: '/x/.env', label: 'env' }]), 'utf8');
  const emptyFile = path.join(tmp, 'protected-empty.json');
  fs.writeFileSync(emptyFile, JSON.stringify([]), 'utf8');

  const ENV = { CLAUDESEC_PROTECTED_PATHS: protectedFile };

  try {
    // ── 1: Read of a protected path → blocked even with no mode (monitor) ──────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x/.env' } });
      const { code } = await runHook(stdin, ENV);
      check('case1 Read protected path: exit 2 (blocked in monitor)', () => assert.strictEqual(code, 2));
    }

    // ── 2: Bash that names the protected path → blocked ────────────────────────
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'cat /x/.env' } });
      const { code } = await runHook(stdin, ENV);
      check('case2 Bash cat protected path: exit 2', () => assert.strictEqual(code, 2));
    }

    // ── 3: Edit whose file_path is the protected path → blocked ────────────────
    {
      const stdin = JSON.stringify({
        tool_name: 'Edit',
        tool_input: { file_path: '/x/.env', old_string: 'a', new_string: 'b' },
      });
      const { code } = await runHook(stdin, ENV);
      check('case3 Edit protected file_path: exit 2', () => assert.strictEqual(code, 2));
    }

    // ── 4: Unrelated Read → allowed ────────────────────────────────────────────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x/app.ts' } });
      const { code } = await runHook(stdin, ENV);
      check('case4 unrelated Read: exit 0 (allowed)', () => assert.strictEqual(code, 0));
    }

    // ── 5: Edit of an unrelated file whose CONTENT mentions the protected path ──
    //      → allowed (we never match against edit content, only the target).
    {
      const stdin = JSON.stringify({
        tool_name: 'Edit',
        tool_input: { file_path: '/x/app.ts', old_string: 'x', new_string: 'see /x/.env for config' },
      });
      const { code } = await runHook(stdin, ENV);
      check('case5 Edit content mentions protected path: exit 0 (no content match)', () =>
        assert.strictEqual(code, 0));
    }

    // ── 6: Empty protected-paths file → fail-open, unrelated call allowed ───────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x/app.ts' } });
      const { code } = await runHook(stdin, { CLAUDESEC_PROTECTED_PATHS: emptyFile });
      check('case6 empty protected list: exit 0 (fail-open)', () => assert.strictEqual(code, 0));
    }

    // ── 6b: Missing protected-paths file → fail-open, unrelated call allowed ────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x/app.ts' } });
      const { code } = await runHook(stdin, {
        CLAUDESEC_PROTECTED_PATHS: path.join(tmp, 'does-not-exist.json'),
      });
      check('case6b missing protected file: exit 0 (fail-open)', () => assert.strictEqual(code, 0));
    }

    // A second list using a '~'-prefixed entry, to exercise home expansion.
    const homeFile = path.join(tmp, 'protected-home.json');
    fs.writeFileSync(homeFile, JSON.stringify([{ path: '~/.ssh/id_rsa', label: 'ssh key' }]), 'utf8');
    const HOME_ENV = { CLAUDESEC_PROTECTED_PATHS: homeFile };
    const homeAbs = path.join(os.homedir(), '.ssh', 'id_rsa');

    // ── 7: stored '~'-path blocks a Read of the home-EXPANDED absolute path ─────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: homeAbs } });
      const { code } = await runHook(stdin, HOME_ENV);
      check('case7 Read home-expanded path vs ~ entry: exit 2', () => assert.strictEqual(code, 2));
    }

    // ── 8: case variation — stored /x/.env, Read of /X/.ENV → blocked ──────────
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/X/.ENV' } });
      const { code } = await runHook(stdin, ENV);
      check('case8 case-insensitive Read /X/.ENV vs /x/.env: exit 2', () =>
        assert.strictEqual(code, 2));
    }

    // ── 9: Bash `cat $HOME/.ssh/id_rsa` with stored ~/.ssh/id_rsa → blocked ─────
    {
      const stdin = JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'cat $HOME/.ssh/id_rsa' },
      });
      const { code } = await runHook(stdin, HOME_ENV);
      check('case9 Bash $HOME expansion vs ~ entry: exit 2', () => assert.strictEqual(code, 2));
    }

    // ── 10: MultiEdit whose edit target file_path is a protected path → blocked ─
    {
      const stdin = JSON.stringify({
        tool_name: 'MultiEdit',
        tool_input: {
          file_path: '/x/.env',
          edits: [{ old_string: 'a', new_string: 'b' }],
        },
      });
      const { code } = await runHook(stdin, ENV);
      check('case10 MultiEdit protected file_path: exit 2', () => assert.strictEqual(code, 2));
    }

    // A throwaway enforce-mode rules snapshot whose single rule matches "DANGER".
    // Used to prove that the command rule-engine fires for a Bash command but is
    // deliberately NOT run for a Read (a read is not an execution).
    const rulesFile = path.join(tmp, 'rules-enforcement.json');
    fs.writeFileSync(rulesFile, JSON.stringify([
      { source: 'DANGER', flags: 'i', severity: 'high', label: 'danger marker', action: 'block' },
    ]), 'utf8');
    // Pin enforce mode via an explicit config file. (CLAUDESEC_MODE alone is not
    // enough here: resolveMode reads enforce-config.json first, and an in-repo dev
    // server may have left one at the repo-root fallback path.)
    const enforceConfigFile = path.join(tmp, 'enforce-config.json');
    fs.writeFileSync(enforceConfigFile, JSON.stringify({ mode: 'enforce' }), 'utf8');
    const ENFORCE_ENV = {
      CLAUDESEC_PROTECTED_PATHS: emptyFile, // no protected paths in play here
      CLAUDESEC_ENFORCE_RULES: rulesFile,
      CLAUDESEC_ENFORCE_CONFIG: enforceConfigFile,
    };

    // ── 11: in enforce mode a Bash command matching a block rule → blocked ──────
    //      (control: proves the snapshot rule is actually live).
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'echo DANGER' } });
      const { code } = await runHook(stdin, ENFORCE_ENV);
      check('case11 enforce Bash hits block rule: exit 2', () => assert.strictEqual(code, 2));
    }

    // ── 12: a Read whose PATH matches that same block rule → still allowed ──────
    //      Reads run ONLY the protected-paths floor, never the command rule-engine,
    //      so a non-protected path is never blocked just for matching a command rule.
    {
      const stdin = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x/DANGER.txt' } });
      const { code } = await runHook(stdin, ENFORCE_ENV);
      check('case12 enforce Read of rule-matching non-protected path: exit 0 (reads skip rule-engine)', () =>
        assert.strictEqual(code, 0));
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  protectedPathsHookTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('protectedPathsHookTest crashed:', e);
    process.exit(1);
  });
