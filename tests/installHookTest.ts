/**
 * tests/installHookTest.ts
 *
 * Gate for `claudesec install-hook` / `uninstall-hook`. Proves the installer is
 * safe and well-behaved without ever touching the real home:
 *
 *   1. Fresh install creates the two PreToolUse entries and backs up nothing
 *      (no prior file) — and a re-run DOES back up.
 *   2. Idempotent re-run does not duplicate our entries.
 *   3. Merge preserves an existing, unrelated PreToolUse hook and any other keys.
 *   4. Uninstall removes ONLY our entries, leaving the unrelated hook intact.
 *   5. Without --yes and with a non-interactive (piped, closed) stdin, the
 *      installer ABORTS and writes nothing.
 *
 * Every run is sandboxed: CLAUDESEC_HOME and CLAUDESEC_CLAUDE_SETTINGS point at
 * a fresh temp dir, deleted in finally. The real ~/.claude and ~/.claudesec are
 * NEVER touched. We drive the CLI exactly as a user would — `node cli/init.mjs`
 * — so the dispatch, consent, and settings merge are all covered end-to-end.
 *
 * Run via:  npx tsx tests/installHookTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const CLI = path.join(REPO_ROOT, 'cli', 'init.mjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

/** A throwaway sandbox: a fresh temp dir + the two env overrides. */
interface Sandbox {
  dir: string;
  home: string;        // CLAUDESEC_HOME
  settings: string;    // CLAUDESEC_CLAUDE_SETTINGS
  env: NodeJS.ProcessEnv;
}

function makeSandbox(): Sandbox {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-hook-'));
  const home = path.join(dir, 'claudesec-home');
  // Nest settings one level deep so the installer must create the parent dir.
  const settings = path.join(dir, 'claude', 'settings.json');
  return {
    dir, home, settings,
    env: {
      ...process.env,
      CLAUDESEC_HOME: home,
      CLAUDESEC_CLAUDE_SETTINGS: settings,
      // Force ANSI off-irrelevant; keep output deterministic.
      NO_COLOR: '1',
    },
  };
}

function cleanup(s: Sandbox): void {
  try { fs.rmSync(s.dir, { recursive: true, force: true }); } catch {}
}

/**
 * Run the CLI. `input` is fed to stdin (so a piped, closed stdin exercises the
 * non-interactive abort path). Returns { status, stdout, stderr }.
 */
function runCli(args: string[], env: NodeJS.ProcessEnv, input = ''): {
  status: number; stdout: string; stderr: string;
} {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: REPO_ROOT,
    env,
    input,
    encoding: 'utf-8',
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function readJson(file: string): any {
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

function preToolUse(settings: any): any[] {
  return settings?.hooks?.PreToolUse ?? [];
}

function ourEntries(settings: any): any[] {
  return preToolUse(settings).filter((e: any) =>
    Array.isArray(e.hooks) &&
    e.hooks.some((h: any) => typeof h?.command === 'string' && h.command.includes('claudesec-enforce.cjs')),
  );
}

function listBackups(settingsFile: string): string[] {
  const dir = path.dirname(settingsFile);
  const base = path.basename(settingsFile);
  try {
    return fs.readdirSync(dir).filter(f => f.startsWith(`${base}.bak-`));
  } catch { return []; }
}

// ── Test 1: fresh install creates entries; copies hook + snapshot; logs ───────
{
  const s = makeSandbox();
  try {
    const r = runCli(['install-hook', '--yes'], s.env);
    check('fresh install: exits 0', () => assert.strictEqual(r.status, 0, r.stderr || r.stdout));

    const settings = readJson(s.settings);
    check('fresh install: adds exactly two of our entries', () => {
      assert.strictEqual(ourEntries(settings).length, 2);
    });
    check('fresh install: matchers are Bash and the editing tools', () => {
      const matchers = ourEntries(settings).map((e: any) => e.matcher).sort();
      assert.deepStrictEqual(matchers, ['Bash', 'Edit|Write|MultiEdit|NotebookEdit']);
    });
    check('fresh install: command runs the installed hook via node', () => {
      const cmd = ourEntries(settings)[0].hooks[0].command;
      assert.ok(cmd.startsWith('node '), `command was: ${cmd}`);
      assert.ok(cmd.includes(path.join(s.home, 'hooks', 'claudesec-enforce.cjs')), cmd);
    });
    check('fresh install: copies hook script + rules snapshot next to it', () => {
      assert.ok(fs.existsSync(path.join(s.home, 'hooks', 'claudesec-enforce.cjs')), 'hook missing');
      assert.ok(fs.existsSync(path.join(s.home, 'hooks', 'rules-enforcement.json')), 'snapshot missing');
    });
    check('fresh install: appends an install record to install.log', () => {
      const log = fs.readFileSync(path.join(s.home, 'install.log'), 'utf-8');
      assert.ok(/\tinstall\t/.test(log), `log was: ${log}`);
    });
    check('fresh install: never prints "you are now protected"', () => {
      assert.ok(!/you are now protected/i.test(r.stdout + r.stderr));
    });
    check('fresh install: says fail-open', () => {
      assert.ok(/fail-open/i.test(r.stdout));
    });
  } finally { cleanup(s); }
}

// ── Test 2: idempotent re-run does not duplicate; second run backs up ─────────
{
  const s = makeSandbox();
  try {
    runCli(['install-hook', '--yes'], s.env);
    const r2 = runCli(['install-hook', '--yes'], s.env);
    check('re-run: exits 0', () => assert.strictEqual(r2.status, 0, r2.stderr));

    const settings = readJson(s.settings);
    check('re-run: still exactly two of our entries (no duplicates)', () => {
      assert.strictEqual(ourEntries(settings).length, 2);
      assert.strictEqual(preToolUse(settings).length, 2);
    });
    check('re-run: a settings backup was taken on the second run', () => {
      assert.ok(listBackups(s.settings).length >= 1, 'expected at least one .bak- file');
    });
  } finally { cleanup(s); }
}

// ── Test 3: merge preserves an existing unrelated hook + other keys ───────────
{
  const s = makeSandbox();
  try {
    fs.mkdirSync(path.dirname(s.settings), { recursive: true });
    const existing = {
      $schema: 'https://example.com/schema.json',
      model: 'opus',
      hooks: {
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'hook', command: 'echo my-own-guard' }] },
        ],
        PostToolUse: [
          { matcher: '*', hooks: [{ type: 'hook', command: 'echo after' }] },
        ],
      },
    };
    fs.writeFileSync(s.settings, JSON.stringify(existing, null, 2));

    const r = runCli(['install-hook', '--yes'], s.env);
    check('merge: exits 0', () => assert.strictEqual(r.status, 0, r.stderr));

    const settings = readJson(s.settings);
    check('merge: preserves unrelated top-level keys', () => {
      assert.strictEqual(settings.$schema, 'https://example.com/schema.json');
      assert.strictEqual(settings.model, 'opus');
    });
    check('merge: preserves the unrelated PreToolUse hook', () => {
      const mine = preToolUse(settings).filter((e: any) =>
        e.hooks?.some((h: any) => h.command === 'echo my-own-guard'));
      assert.strictEqual(mine.length, 1, 'unrelated Bash hook was lost');
    });
    check('merge: preserves PostToolUse untouched', () => {
      assert.strictEqual(settings.hooks.PostToolUse.length, 1);
      assert.strictEqual(settings.hooks.PostToolUse[0].hooks[0].command, 'echo after');
    });
    check('merge: adds our two entries alongside (3 PreToolUse total)', () => {
      assert.strictEqual(ourEntries(settings).length, 2);
      assert.strictEqual(preToolUse(settings).length, 3);
    });
    check('merge: backs up the prior settings file', () => {
      assert.ok(listBackups(s.settings).length >= 1);
    });
  } finally { cleanup(s); }
}

// ── Test 4: uninstall removes only ours, leaves the unrelated hook ────────────
{
  const s = makeSandbox();
  try {
    fs.mkdirSync(path.dirname(s.settings), { recursive: true });
    fs.writeFileSync(s.settings, JSON.stringify({
      hooks: {
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'hook', command: 'echo my-own-guard' }] },
        ],
      },
    }, null, 2));

    runCli(['install-hook', '--yes'], s.env);
    const r = runCli(['uninstall-hook', '--yes'], s.env);
    check('uninstall: exits 0', () => assert.strictEqual(r.status, 0, r.stderr));

    const settings = readJson(s.settings);
    check('uninstall: removes all of our entries', () => {
      assert.strictEqual(ourEntries(settings).length, 0);
    });
    check('uninstall: leaves the unrelated hook intact', () => {
      const remaining = preToolUse(settings);
      assert.strictEqual(remaining.length, 1);
      assert.strictEqual(remaining[0].hooks[0].command, 'echo my-own-guard');
    });
    check('uninstall: without --purge, the installed hook files remain', () => {
      assert.ok(fs.existsSync(path.join(s.home, 'hooks', 'claudesec-enforce.cjs')));
    });
    check('uninstall: logs an uninstall record', () => {
      const log = fs.readFileSync(path.join(s.home, 'install.log'), 'utf-8');
      assert.ok(/\tuninstall\t/.test(log), log);
    });
  } finally { cleanup(s); }
}

// ── Test 5: no --yes + non-interactive stdin → abort, write nothing ───────────
{
  const s = makeSandbox();
  try {
    // Piped, immediately-closed stdin (empty input) is non-interactive → abort.
    const r = runCli(['install-hook'], s.env, '');
    check('no-consent: exits non-zero (aborted)', () => {
      assert.notStrictEqual(r.status, 0);
    });
    check('no-consent: did NOT create the settings file', () => {
      assert.ok(!fs.existsSync(s.settings), 'settings.json must not be written without consent');
    });
    check('no-consent: did NOT register any entries', () => {
      // Even if a file somehow existed, there must be zero of our entries.
      const exists = fs.existsSync(s.settings);
      if (exists) assert.strictEqual(ourEntries(readJson(s.settings)).length, 0);
    });
    check('no-consent: prints an abort notice', () => {
      assert.ok(/abort/i.test(r.stdout + r.stderr));
    });
  } finally { cleanup(s); }
}

// ── Report ────────────────────────────────────────────────────────────────────
const total = passed + failures.length;
console.log('───────────────────────────────────────────────');
console.log(`  installHookTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failures.length) {
  console.error(`\n  ${failures.length} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
