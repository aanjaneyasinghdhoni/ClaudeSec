/**
 * tests/enforceStatusTest.ts
 *
 * Gate for server/enforceStatus.ts — the honest-status helper behind the Enforce
 * tab. Proves two things the tab must never get wrong:
 *
 *   1. HOOK DETECTION across the three Claude Code settings scopes (user /
 *      project / project-local): found in each scope individually, found in
 *      several at once, absent everywhere, and malformed JSON counts as absent
 *      (never throws). Honors the CLAUDESEC_CLAUDE_SETTINGS override for the
 *      user-settings path so the suite never reads the real ~/.claude.
 *
 *   2. EFFECTIVE-MODE PRECEDENCE — identical to enforceEval.resolveMode: the
 *      config file's `mode` wins; else CLAUDESEC_MODE env; else the 'monitor'
 *      default. A garbage value at any layer falls through (never 'enforce').
 *      We also assert the reported `modeSource`.
 *
 * Pure unit test: imports the helper directly, drives it with temp dirs/files and
 * env overrides, and restores env between cases. No server, no DB, no network —
 * the real ~/.claude and ~/.claudesec are NEVER touched. Sub-second.
 *
 * Run via:  npx tsx tests/enforceStatusTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

import { resolveEffectiveMode, detectHookStatus, HOOK_FILENAME as STATUS_HOOK_FILENAME } from '../server/enforceStatus.js';
import { HOOK_FILENAME as INSTALL_HOOK_FILENAME } from '../cli/installHook.js';

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// ── HOOK_FILENAME parity ───────────────────────────────────────────────────────
// Both modules declare this constant independently to keep server/ free of any
// runtime dependency on cli/. This assertion is the compile-time safety net:
// renaming the hook file in one place without updating the other would silently
// break detection, so we catch it here at the test level — the same pattern as
// the repo's catastrophic-parity test.
check('HOOK_FILENAME parity: server/enforceStatus matches cli/installHook', () => {
  assert.strictEqual(
    STATUS_HOOK_FILENAME,
    INSTALL_HOOK_FILENAME,
    `HOOK_FILENAME mismatch: server/enforceStatus.ts has '${STATUS_HOOK_FILENAME}', cli/installHook.ts has '${INSTALL_HOOK_FILENAME}'`,
  );
});

// ── Sandbox helpers ───────────────────────────────────────────────────────────
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-enfstatus-'));

/** A settings.json carrying our PreToolUse hook entry (optionally extra noise). */
function withHook(): unknown {
  return {
    hooks: {
      PreToolUse: [
        { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo unrelated' }] },
        { matcher: 'Edit', hooks: [{ type: 'command', command: 'node "/somewhere/.claudesec/hooks/claudesec-enforce.cjs"' }] },
      ],
    },
  };
}

/** A settings.json with hooks, but none of them ours. */
function withoutHook(): unknown {
  return { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo unrelated' }] }] } };
}

let caseN = 0;
/** A fresh project dir + a fresh user-settings path, isolated per case. */
function freshDirs(): { projectDir: string; userSettings: string } {
  const id = `case-${caseN++}`;
  const projectDir = path.join(SANDBOX, id, 'project');
  fs.mkdirSync(path.join(projectDir, '.claude'), { recursive: true });
  const userSettings = path.join(SANDBOX, id, 'user', 'settings.json');
  fs.mkdirSync(path.dirname(userSettings), { recursive: true });
  return { projectDir, userSettings };
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

/** Snapshot + restore the env vars these helpers read. */
function withEnv(
  vars: { settings?: string; config?: string; mode?: string },
  body: () => void,
): void {
  const prev = {
    settings: process.env.CLAUDESEC_CLAUDE_SETTINGS,
    config: process.env.CLAUDESEC_ENFORCE_CONFIG,
    mode: process.env.CLAUDESEC_MODE,
  };
  const set = (k: 'CLAUDESEC_CLAUDE_SETTINGS' | 'CLAUDESEC_ENFORCE_CONFIG' | 'CLAUDESEC_MODE', v: string | undefined) => {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  };
  try {
    set('CLAUDESEC_CLAUDE_SETTINGS', vars.settings);
    set('CLAUDESEC_ENFORCE_CONFIG', vars.config);
    set('CLAUDESEC_MODE', vars.mode);
    body();
  } finally {
    set('CLAUDESEC_CLAUDE_SETTINGS', prev.settings);
    set('CLAUDESEC_ENFORCE_CONFIG', prev.config);
    set('CLAUDESEC_MODE', prev.mode);
  }
}

// ── Hook detection ────────────────────────────────────────────────────────────

// Found in USER scope (via the CLAUDESEC_CLAUDE_SETTINGS override).
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(userSettings, withHook());
  withEnv({ settings: userSettings }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: found in user scope', () => {
      assert.strictEqual(s.installed, 'yes');
      assert.deepStrictEqual(s.scopes, ['user']);
    });
  });
}

// Found in PROJECT scope (./.claude/settings.json).
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(path.join(projectDir, '.claude', 'settings.json'), withHook());
  withEnv({ settings: userSettings /* exists? no — absent user file */ }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: found in project scope', () => {
      assert.strictEqual(s.installed, 'yes');
      assert.deepStrictEqual(s.scopes, ['project']);
    });
  });
}

// Found in PROJECT-LOCAL scope (./.claude/settings.local.json).
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(path.join(projectDir, '.claude', 'settings.local.json'), withHook());
  withEnv({ settings: userSettings }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: found in project-local scope', () => {
      assert.strictEqual(s.installed, 'yes');
      assert.deepStrictEqual(s.scopes, ['project-local']);
    });
  });
}

// Found in MULTIPLE scopes — every matching scope is listed, in fixed order.
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(userSettings, withHook());
  writeJson(path.join(projectDir, '.claude', 'settings.local.json'), withHook());
  withEnv({ settings: userSettings }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: lists every scope where found', () => {
      assert.strictEqual(s.installed, 'yes');
      assert.deepStrictEqual(s.scopes, ['user', 'project-local']);
    });
  });
}

// ABSENT everywhere → 'no', no scopes. (User file present but without our hook;
// no project files at all.)
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(userSettings, withoutHook());
  withEnv({ settings: userSettings }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: absent everywhere → no', () => {
      assert.strictEqual(s.installed, 'no');
      assert.deepStrictEqual(s.scopes, []);
    });
  });
}

// MALFORMED JSON in a scope counts as absent — never throws.
{
  const { projectDir, userSettings } = freshDirs();
  fs.writeFileSync(userSettings, '{ this is not valid json ');
  fs.writeFileSync(path.join(projectDir, '.claude', 'settings.json'), '}]not json[{');
  withEnv({ settings: userSettings }, () => {
    let result: ReturnType<typeof detectHookStatus> | null = null;
    check('hook: malformed JSON does not throw, counts as absent', () => {
      assert.doesNotThrow(() => { result = detectHookStatus(projectDir); });
      assert.strictEqual(result!.installed, 'no');
      assert.deepStrictEqual(result!.scopes, []);
    });
  });
}

// HONESTY: an entry that runs our hook but has an invalid `type` (anything other
// than 'command') does NOT execute in Claude Code, so it must NOT be reported as
// installed — counting it would be a false green that promises blocking which can
// never happen.
{
  const { projectDir, userSettings } = freshDirs();
  writeJson(userSettings, {
    hooks: {
      PreToolUse: [
        { matcher: 'Edit', hooks: [{ type: 'hook', command: 'node "/x/.claudesec/hooks/claudesec-enforce.cjs"' }] },
      ],
    },
  });
  withEnv({ settings: userSettings }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: our command under a non-command type → not installed (no false green)', () => {
      assert.strictEqual(s.installed, 'no');
      assert.deepStrictEqual(s.scopes, []);
    });
  });
}

// CLAUDESEC_CLAUDE_SETTINGS override is honored — point it at a file with our
// hook and the user scope must light up even though the default ~/.claude path
// has nothing of ours.
{
  const { projectDir } = freshDirs();
  const overridePath = path.join(SANDBOX, 'override', 'custom-settings.json');
  writeJson(overridePath, withHook());
  withEnv({ settings: overridePath }, () => {
    const s = detectHookStatus(projectDir);
    check('hook: CLAUDESEC_CLAUDE_SETTINGS override is honored', () => {
      assert.strictEqual(s.installed, 'yes');
      assert.deepStrictEqual(s.scopes, ['user']);
    });
  });
}

// ── Effective-mode precedence ─────────────────────────────────────────────────

/** Write an enforce-config.json with the given mode value (any JSON value). */
function writeConfig(mode: unknown): string {
  const file = path.join(SANDBOX, `enforce-config-${caseN++}.json`);
  fs.writeFileSync(file, JSON.stringify({ mode, overrides: {} }));
  return file;
}

// File wins over env: config=enforce beats env=monitor.
{
  const cfg = writeConfig('enforce');
  withEnv({ config: cfg, mode: 'monitor' }, () => {
    const r = resolveEffectiveMode();
    check('mode: config file wins over env', () => {
      assert.strictEqual(r.effectiveMode, 'enforce');
      assert.strictEqual(r.modeSource, 'config-file');
    });
  });
}

// File wins the other way too: config=monitor beats env=enforce (the trap case).
{
  const cfg = writeConfig('monitor');
  withEnv({ config: cfg, mode: 'enforce' }, () => {
    const r = resolveEffectiveMode();
    check('mode: config monitor beats env enforce (precedence trap)', () => {
      assert.strictEqual(r.effectiveMode, 'monitor');
      assert.strictEqual(r.modeSource, 'config-file');
    });
  });
}

// Env used when no readable file (point config at a path that doesn't exist).
{
  const missing = path.join(SANDBOX, 'does-not-exist.json');
  withEnv({ config: missing, mode: 'enforce' }, () => {
    const r = resolveEffectiveMode();
    check('mode: env used when no config file', () => {
      assert.strictEqual(r.effectiveMode, 'enforce');
      assert.strictEqual(r.modeSource, 'env');
    });
  });
}

// Default 'monitor' when neither file nor env supplies a valid mode.
{
  const missing = path.join(SANDBOX, 'also-missing.json');
  withEnv({ config: missing, mode: undefined }, () => {
    const r = resolveEffectiveMode();
    check('mode: default monitor when neither file nor env', () => {
      assert.strictEqual(r.effectiveMode, 'monitor');
      assert.strictEqual(r.modeSource, 'default');
    });
  });
}

// Garbage config value falls through to env (matches enforceEval semantics).
{
  const cfg = writeConfig('TURBO'); // not 'monitor'|'enforce'
  withEnv({ config: cfg, mode: 'enforce' }, () => {
    const r = resolveEffectiveMode();
    check('mode: garbage config value falls through to env', () => {
      assert.strictEqual(r.effectiveMode, 'enforce');
      assert.strictEqual(r.modeSource, 'env');
    });
  });
}

// Garbage at BOTH layers falls all the way to the monitor default.
{
  const cfg = writeConfig(42); // wrong type entirely
  withEnv({ config: cfg, mode: 'nonsense' }, () => {
    const r = resolveEffectiveMode();
    check('mode: garbage at both layers → monitor default', () => {
      assert.strictEqual(r.effectiveMode, 'monitor');
      assert.strictEqual(r.modeSource, 'default');
    });
  });
}

// Malformed config JSON falls through to env (never throws).
{
  const file = path.join(SANDBOX, `enforce-config-bad-${caseN++}.json`);
  fs.writeFileSync(file, '{ not valid ');
  withEnv({ config: file, mode: 'monitor' }, () => {
    let r: ReturnType<typeof resolveEffectiveMode> | null = null;
    check('mode: malformed config JSON falls through to env, no throw', () => {
      assert.doesNotThrow(() => { r = resolveEffectiveMode(); });
      assert.strictEqual(r!.effectiveMode, 'monitor');
      assert.strictEqual(r!.modeSource, 'env');
    });
  });
}

// ── Report ────────────────────────────────────────────────────────────────────
try { fs.rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* best-effort */ }

const total = passed + failures.length;
console.log('───────────────────────────────────────────────');
console.log(`  enforceStatusTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failures.length) {
  console.error(`\n  ${failures.length} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
