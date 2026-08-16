/**
 * tests/customRuleEnforceTest.ts
 *
 * Gate for "custom regex rules block in enforce mode". Two layers:
 *
 *  A. Unit — the shared snapshot builder (server/enforcementSnapshot.ts):
 *     • built-in rules are always present;
 *     • a high/critical custom rule is appended with action:'block';
 *     • a low/medium custom rule is appended with action:'alert' (detect-only);
 *     • passing no custom rules yields exactly the built-in snapshot.
 *
 *  B. Black-box — the REAL tracked hook (cli/hooks/claudesec-enforce.cjs) reading
 *     a snapshot that contains a custom block rule:
 *     • enforce mode + Bash command matching the custom rule → exit 2 (blocked);
 *     • monitor mode + same command                          → exit 0 (allowed);
 *     • a low-severity (action:'alert') custom rule never blocks, even in enforce.
 *
 * Fully sandboxed: snapshot + config live under os.tmpdir(); the hook's
 * best-effort POST is aimed at a dead port (CLAUDESEC_PORT=9). Mode is pinned via
 * an explicit CLAUDESEC_ENFORCE_CONFIG file so an in-repo dev server's stray
 * enforce-config.json can't steer the result.
 *
 * Run via:  npx tsx tests/customRuleEnforceTest.ts
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildEnforcementSnapshot } from '../server/enforcementSnapshot.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

function runHook(stdin: string, extraEnv: Record<string, string>): Promise<{ code: number | null }> {
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
    const done = (code: number | null) => { if (settled) return; settled = true; resolve({ code }); };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } done(null); }, 1500);
    timer.unref?.();
    child.on('exit', (code) => { clearTimeout(timer); done(code); });
    child.on('error', () => { clearTimeout(timer); done(null); });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

async function main(): Promise<void> {
  // ── A. Unit: the shared builder ────────────────────────────────────────────
  const builtinOnly = buildEnforcementSnapshot();
  check('A1 built-in-only snapshot is non-empty', () => assert.ok(builtinOnly.length > 100));
  check('A2 built-in snapshot has block rules (high/critical)', () =>
    assert.ok(builtinOnly.some(r => r.action === 'block')));

  const withCustom = buildEnforcementSnapshot([
    { pattern: 'zzz_custom_block_marker', severity: 'high', label: 'custom high' },
    { pattern: 'zzz_custom_alert_marker', severity: 'medium', label: 'custom medium' },
  ]);
  check('A3 custom rules are appended after the built-ins', () =>
    assert.strictEqual(withCustom.length, builtinOnly.length + 2));
  check('A4 high custom rule → action:block', () => {
    const r = withCustom.find(x => x.label === 'custom high');
    assert.ok(r && r.action === 'block', 'high custom rule should block');
  });
  check('A5 medium custom rule → action:alert (detect-only)', () => {
    const r = withCustom.find(x => x.label === 'custom medium');
    assert.ok(r && r.action === 'alert', 'medium custom rule should be alert-only');
  });
  check('A6 custom rule defaults to case-insensitive flag', () => {
    const r = withCustom.find(x => x.label === 'custom high');
    assert.ok(r && r.flags.includes('i'));
  });

  // ── B. Black-box: the hook honoring a custom block rule ─────────────────────
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-customrule-'));
  try {
    const snapshot = buildEnforcementSnapshot([
      { pattern: 'zzz_custom_block_marker', severity: 'high', label: 'custom high block' },
      { pattern: 'zzz_custom_alert_marker', severity: 'low', label: 'custom low alert' },
    ]);
    const rulesFile = path.join(tmp, 'rules-enforcement.json');
    fs.writeFileSync(rulesFile, JSON.stringify(snapshot), 'utf8');

    const enforceCfg = path.join(tmp, 'enforce-config.json');
    fs.writeFileSync(enforceCfg, JSON.stringify({ mode: 'enforce' }), 'utf8');
    const monitorCfg = path.join(tmp, 'monitor-config.json');
    fs.writeFileSync(monitorCfg, JSON.stringify({ mode: 'monitor' }), 'utf8');

    const cmd = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'echo zzz_custom_block_marker' } });

    // B1: enforce + matching custom HIGH rule → blocked.
    {
      const { code } = await runHook(cmd, { CLAUDESEC_ENFORCE_RULES: rulesFile, CLAUDESEC_ENFORCE_CONFIG: enforceCfg });
      check('B1 enforce: custom high rule blocks (exit 2)', () => assert.strictEqual(code, 2));
    }
    // B2: monitor + same command → allowed (would-block logged only).
    {
      const { code } = await runHook(cmd, { CLAUDESEC_ENFORCE_RULES: rulesFile, CLAUDESEC_ENFORCE_CONFIG: monitorCfg });
      check('B2 monitor: custom high rule does not block (exit 0)', () => assert.strictEqual(code, 0));
    }
    // B3: enforce + a command matching only the LOW (alert) custom rule → allowed.
    {
      const lowCmd = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'echo zzz_custom_alert_marker' } });
      const { code } = await runHook(lowCmd, { CLAUDESEC_ENFORCE_RULES: rulesFile, CLAUDESEC_ENFORCE_CONFIG: enforceCfg });
      check('B3 enforce: low-severity custom rule never blocks (exit 0)', () => assert.strictEqual(code, 0));
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  customRuleEnforceTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('customRuleEnforceTest crashed:', e);
    process.exit(1);
  });
