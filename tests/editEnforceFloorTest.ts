/**
 * tests/editEnforceFloorTest.ts
 *
 * Gate for "Frictionless enforce: block actions, not edits." The enforcement
 * BLOCK decision for edit-family tools (Edit/Write/MultiEdit/NotebookEdit) gates
 * on PATH + ACTION plus two minimal floors — NEVER on the static content of the
 * code being written. Scanning edit bodies against the ~630 threat rules would
 * false-positive on benign work (editing security code, docs that name attack
 * patterns, fixtures holding secret-shaped strings), so an edit blocks only on:
 *   (1) the protected-path floor (target path),
 *   (2) the minimal live-secret (DLP) floor (an unambiguous credential in content),
 *   (3) the catastrophic / block-rule engine against its PATH.
 * A benign edit whose BODY merely matches a threat rule is allowed.
 *
 * Two layers, so the hook and the server agree on the verdict:
 *   A. Black-box — the REAL tracked hook (cli/hooks/claudesec-enforce.cjs), run in
 *      ENFORCE mode against a snapshot whose one block rule matches a marker string.
 *   B. Unit — server/enforceEval.ts evaluate(), the ESM sibling the MCP proxy uses,
 *      fed the same path/content split the hook builds internally.
 *
 * Cases (each asserted on BOTH layers where applicable):
 *   a. Edit whose CONTENT matches the block rule, benign path → NOT blocked.
 *   b. Edit to a protected path                              → blocked (hook AND proxy/server).
 *   c. Edit writing a live secret (synthetic AKIA…)          → blocked.
 *   c3. Edit writing AWS's doc placeholder AKIAIOSFODNN7EXAMPLE → NOT blocked (allowlist).
 *   f. Edit/Bash targeting the enforcement control plane     → blocked (self-protection).
 *   d. Bash `rm -rf /`                                       → blocked (catastrophic).
 *   e. Hook and server agree on every verdict above.
 *
 * Fully sandboxed: snapshot / config / protected-paths live under os.tmpdir();
 * the hook's best-effort POST is aimed at a dead port (CLAUDESEC_PORT=9). Mode is
 * pinned via an explicit CLAUDESEC_ENFORCE_CONFIG file so an in-repo dev server's
 * stray enforce-config.json can't steer the result.
 *
 * Run via:  npx tsx tests/editEnforceFloorTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { evaluate, type CompiledRule } from '../server/enforceEval.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

// A marker the block rule matches. Used as edit CONTENT (must NOT block) and as a
// path substring (must block) to prove the rule fires on path, never on content.
const MARKER = 'DANGERPATTERN';
// A SYNTHETIC, non-placeholder live AWS access key id (right shape, never a real
// credential and not on the placeholder allowlist) so the DLP floor still fires.
// AKIAIOSFODNN7EXAMPLE — AWS's canonical doc placeholder — is allowlisted and
// tested separately below (must be ALLOWED).
const LIVE_SECRET_BODY = 'const k = "AKIA1234567890ABCDEF"; const s = "wJalrXUtnFEMI";';
const PLACEHOLDER_BODY = 'const example = "AKIAIOSFODNN7EXAMPLE"; // AWS docs placeholder';

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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-editfloor-'));
  try {
    // A snapshot with ONE block rule that matches the marker. If edit content were
    // (wrongly) fed to the rule engine, case (a) would block on this rule.
    const rulesFile = path.join(tmp, 'rules-enforcement.json');
    fs.writeFileSync(rulesFile, JSON.stringify([
      { source: MARKER, flags: '', severity: 'high', label: 'marker rule', action: 'block' },
    ]), 'utf8');
    // The compiled rule set the server-side evaluate() sees (mirror of the snapshot).
    const blockRules: CompiledRule[] = [{ re: new RegExp(MARKER), label: 'marker rule', severity: 'high' }];

    // Pin enforce mode via an explicit config file.
    const enforceConfigFile = path.join(tmp, 'enforce-config.json');
    fs.writeFileSync(enforceConfigFile, JSON.stringify({ mode: 'enforce' }), 'utf8');

    // Protected-paths list holding one entry.
    const protectedFile = path.join(tmp, 'protected-paths.json');
    fs.writeFileSync(protectedFile, JSON.stringify([{ path: '/x/.env', label: 'env' }]), 'utf8');
    // An empty list for cases where protected paths are not in play.
    const emptyProtected = path.join(tmp, 'protected-empty.json');
    fs.writeFileSync(emptyProtected, JSON.stringify([]), 'utf8');

    // Isolate the IN-PROCESS evaluate() calls: point its protected-paths loader at
    // the empty list by default so the real user's ~/.claudesec/hooks list can't
    // steer a verdict. Case (b) overrides this to the populated list and restores.
    process.env.CLAUDESEC_PROTECTED_PATHS = emptyProtected;

    const ENFORCE = {
      CLAUDESEC_ENFORCE_RULES: rulesFile,
      CLAUDESEC_ENFORCE_CONFIG: enforceConfigFile,
      CLAUDESEC_PROTECTED_PATHS: emptyProtected,
    };
    const ENFORCE_PROTECTED = { ...ENFORCE, CLAUDESEC_PROTECTED_PATHS: protectedFile };

    // ── (a) Edit whose CONTENT matches the block rule, benign path → NOT blocked ─
    {
      const stdin = JSON.stringify({
        tool_name: 'Edit',
        tool_input: { file_path: '/x/app.ts', old_string: 'x', new_string: `// see ${MARKER} below` },
      });
      const { code } = await runHook(stdin, ENFORCE);
      check('a hook: edit with threat-pattern CONTENT, benign path → exit 0 (allowed)', () =>
        assert.strictEqual(code, 0));

      // Server parity: matchText is the PATH only (content excluded); the rule
      // matches the marker, but the path does not → not triggered.
      const v = evaluate('/x/app.ts', blockRules, `// see ${MARKER} below`);
      check('a server: edit content not fed to rule engine → not triggered', () =>
        assert.strictEqual(v.triggered, false));
    }

    // ── (b) Edit to a protected path → blocked (BOTH layers) ────────────────────
    {
      const stdin = JSON.stringify({
        tool_name: 'Edit',
        tool_input: { file_path: '/x/.env', old_string: 'a', new_string: 'b' },
      });
      const { code } = await runHook(stdin, ENFORCE_PROTECTED);
      check('b hook: edit to protected path → exit 2 (blocked)', () => assert.strictEqual(code, 2));

      // Server/proxy parity: evaluate() now enforces the SAME protected-path floor
      // (the gap the proxy used to have). Point its loader at the same list via
      // CLAUDESEC_PROTECTED_PATHS, pass the edit's target path, and assert it fires.
      const prevPP = process.env.CLAUDESEC_PROTECTED_PATHS;
      process.env.CLAUDESEC_PROTECTED_PATHS = protectedFile;
      try {
        const v = evaluate('/x/.env', blockRules, 'b', '/x/.env');
        check('b server/proxy: edit to protected path → triggered (protected floor)', () => {
          assert.strictEqual(v.triggered, true);
          assert.ok(v.label && v.label.startsWith('Protected path:'), `label was ${v.label}`);
        });
        // Control: a benign path with the same list loaded → NOT triggered.
        const vOk = evaluate('/x/app.ts', blockRules, 'b', '/x/app.ts');
        check('b server/proxy: edit to benign path with list loaded → not triggered', () =>
          assert.strictEqual(vOk.triggered, false));
      } finally {
        if (prevPP === undefined) delete process.env.CLAUDESEC_PROTECTED_PATHS;
        else process.env.CLAUDESEC_PROTECTED_PATHS = prevPP;
      }
    }

    // ── (c) Edit writing a live secret → blocked (DLP floor) ────────────────────
    {
      const stdin = JSON.stringify({
        tool_name: 'Write',
        tool_input: { file_path: '/x/app.ts', content: LIVE_SECRET_BODY },
      });
      const { code } = await runHook(stdin, ENFORCE);
      check('c hook: write a synthetic live AWS key → exit 2 (blocked, DLP floor)', () =>
        assert.strictEqual(code, 2));

      // Server parity: path benign, but the live-secret floor fires on content.
      const v = evaluate('/x/app.ts', blockRules, LIVE_SECRET_BODY);
      check('c server: live secret in edit content → triggered', () =>
        assert.strictEqual(v.triggered, true));
    }

    // ── (c2) Edit whose content is a benign string that merely looks key-ish →
    //         NOT blocked (the DLP floor is verified-shape, not "looks secret").
    {
      const benign = 'const example = "AKIA_NOT_A_REAL_KEY";'; // wrong shape (underscores)
      const stdin = JSON.stringify({
        tool_name: 'Write',
        tool_input: { file_path: '/x/app.ts', content: benign },
      });
      const { code } = await runHook(stdin, ENFORCE);
      check('c2 hook: benign key-ish content (wrong shape) → exit 0 (allowed)', () =>
        assert.strictEqual(code, 0));
      const v = evaluate('/x/app.ts', blockRules, benign);
      check('c2 server: benign key-ish content → not triggered', () =>
        assert.strictEqual(v.triggered, false));
    }

    // ── (c3) Edit writing AWS's canonical doc PLACEHOLDER → NOT blocked ─────────
    //        AKIAIOSFODNN7EXAMPLE is allowlisted so editing AWS docs/examples works.
    {
      const stdin = JSON.stringify({
        tool_name: 'Write',
        tool_input: { file_path: '/x/aws-docs.md', content: PLACEHOLDER_BODY },
      });
      const { code } = await runHook(stdin, ENFORCE);
      check('c3 hook: write AWS doc placeholder (AKIAIOSFODNN7EXAMPLE) → exit 0 (allowed)', () =>
        assert.strictEqual(code, 0));
      const v = evaluate('/x/aws-docs.md', blockRules, PLACEHOLDER_BODY);
      check('c3 server: AWS doc placeholder → not triggered (allowlisted)', () =>
        assert.strictEqual(v.triggered, false));
    }

    // ── (f) Self-protection: agent cannot edit the enforcement control plane ────
    //        Always-on (mode-independent). Asserted on BOTH layers. Build the
    //        control-plane paths with the SAME CLAUDESEC_HOME logic both layers use
    //        so the targets line up wherever the control plane actually lives.
    {
      const csecHome = process.env.CLAUDESEC_HOME || path.join(os.homedir(), '.claudesec');
      // f1. Edit to <claudesec home>/hooks/enforce-config.json → blocked.
      const cfgTarget = path.join(csecHome, 'hooks', 'enforce-config.json');
      const editStdin = JSON.stringify({
        tool_name: 'Edit',
        tool_input: { file_path: cfgTarget, old_string: 'monitor', new_string: 'enforce' },
      });
      const { code: c1 } = await runHook(editStdin, ENFORCE);
      check('f1 hook: edit ~/.claudesec/hooks/enforce-config.json → exit 2 (blocked)', () =>
        assert.strictEqual(c1, 2));
      const v1 = evaluate(cfgTarget, blockRules, 'enforce', cfgTarget);
      check('f1 server: edit enforce-config.json → triggered (self-protection)', () => {
        assert.strictEqual(v1.triggered, true);
        assert.ok(v1.label && v1.label.startsWith('Self-protection:'), `label was ${v1.label}`);
      });

      // f2. Bash redirect into ~/.claude/settings.json → blocked.
      const settings = path.join(os.homedir(), '.claude', 'settings.json');
      const bashStdin = JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: `echo '{}' > ${settings}` },
      });
      const { code: c2 } = await runHook(bashStdin, ENFORCE);
      check('f2 hook: bash redirect into ~/.claude/settings.json → exit 2 (blocked)', () =>
        assert.strictEqual(c2, 2));
      const v2 = evaluate(`echo '{}' > ${settings}`, blockRules);
      check('f2 server: bash redirect into settings.json → triggered (self-protection)', () => {
        assert.strictEqual(v2.triggered, true);
        assert.ok(v2.label && v2.label.startsWith('Self-protection:'), `label was ${v2.label}`);
      });
    }

    // ── (d) Bash `rm -rf /` → blocked (catastrophic floor, even in monitor) ──────
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
      const { code } = await runHook(stdin, ENFORCE);
      check('d hook: rm -rf / → exit 2 (blocked)', () => assert.strictEqual(code, 2));
      const v = evaluate('rm -rf /', blockRules);
      check('d server: rm -rf / → triggered (catastrophic)', () => {
        assert.strictEqual(v.triggered, true);
        assert.strictEqual(v.kind, 'catastrophic');
      });
    }

    // ── (e) Hook ↔ server agreement: a Bash command matching the block rule ──────
    //      blocks on both layers (control proving the rule is live for commands).
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: `echo ${MARKER}` } });
      const { code } = await runHook(stdin, ENFORCE);
      const v = evaluate(`echo ${MARKER}`, blockRules);
      check('e hook+server: Bash matching block rule → both block', () => {
        assert.strictEqual(code, 2);
        assert.strictEqual(v.triggered, true);
      });
    }

    // ── (g) Symlink guard on the SERVER/proxy path (Phase 5) ────────────────────
    //      evaluate() resolves the target's symlinks too, so reaching a protected
    //      file via a symlink is caught on the MCP-proxy layer exactly as in the
    //      hook. Uses REAL files under tmp so realpath has something to resolve.
    {
      const gReal = path.join(tmp, 'g-secret.env');
      fs.writeFileSync(gReal, 'TOKEN=shh', 'utf8');
      const gLink = path.join(tmp, 'g-innocent.txt');
      const gDir = path.join(tmp, 'g-protdir');
      fs.mkdirSync(gDir, { recursive: true });
      const gLinkDir = path.join(tmp, 'g-linkdir');
      let gSym = true;
      try {
        fs.symlinkSync(gReal, gLink);
        fs.symlinkSync(gDir, gLinkDir);
      } catch {
        gSym = false; // symlinks unsupported here — skip cleanly
      }

      const gProtected = path.join(tmp, 'g-protected.json');
      fs.writeFileSync(gProtected, JSON.stringify([
        { path: gReal, label: 'real secret' },
        { path: gDir, label: 'protected dir' },
      ]), 'utf8');

      const prevPP = process.env.CLAUDESEC_PROTECTED_PATHS;
      process.env.CLAUDESEC_PROTECTED_PATHS = gProtected;
      try {
        if (gSym) {
          // Edit via the symlink → triggered (realpath resolves to the protected file).
          const vLink = evaluate(gLink, blockRules, 'b', gLink);
          check('g server: edit via symlink into protected file → triggered', () => {
            assert.strictEqual(vLink.triggered, true);
            assert.ok(vLink.label && vLink.label.startsWith('Protected path:'), `label was ${vLink.label}`);
          });

          // Write a NEW file under a symlinked protected dir → triggered (ancestor walk).
          const gNew = path.join(gLinkDir, 'brand-new.txt');
          const vNew = evaluate(gNew, blockRules, 'hello', gNew);
          check('g server: new file under symlinked protected dir → triggered (ancestor walk)', () =>
            assert.strictEqual(vNew.triggered, true));

          // A benign non-symlinked path with the same list loaded → NOT triggered.
          const gBenign = path.join(tmp, 'g-fine.txt');
          const vOk = evaluate(gBenign, blockRules, 'b', gBenign);
          check('g server: benign non-symlinked path → not triggered (no regression)', () =>
            assert.strictEqual(vOk.triggered, false));
        } else {
          check('g server: symlink guard skipped (symlinks unsupported here)', () => {});
        }
      } finally {
        if (prevPP === undefined) delete process.env.CLAUDESEC_PROTECTED_PATHS;
        else process.env.CLAUDESEC_PROTECTED_PATHS = prevPP;
      }
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  editEnforceFloorTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('editEnforceFloorTest crashed:', e);
    process.exit(1);
  });
