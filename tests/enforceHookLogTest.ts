/**
 * tests/enforceHookLogTest.ts
 *
 * Gate for the PreToolUse enforcement hook's BLOCK logging. Proves the REAL
 * tracked hook (cli/hooks/claudesec-enforce.cjs) flushes an event to the
 * dashboard before it denies a tool call — so a real block actually shows up in
 * the Enforce feed, not just a monitor "would-block".
 *
 * Three black-box cases, each spawning `node cli/hooks/claudesec-enforce.cjs`
 * as a child against a throwaway local HTTP server that captures the POST body:
 *
 *   1. Catastrophic floor in MONITOR mode -> exit 2 AND a POST with blocked:true
 *      (the floor blocks regardless of mode), a non-empty label/severity and a
 *      redacted command.
 *   2. Enforce rule block -> exit 2 AND a POST with blocked:true.
 *   3. The same rule in MONITOR mode -> exit 0 (allowed) AND a POST with
 *      blocked:false (a would-block).
 *   4. CLAUDESEC_HOOKS_BYPASS=1 -> exit 0 (allowed) AND a POST recording the
 *      bypass (blocked:false, wouldBlock:false, a bypass label, and a command
 *      summary naming the tool that was allowed) — so the escape hatch is
 *      auditable rather than silent.
 *
 * The block-rule trigger is a high-severity SQL-destruction rule that is NOT one
 * of the six catastrophic patterns; its keywords are assembled at runtime so the
 * literal never appears in this source (the hook would otherwise block edits to
 * a file that merely contains the dangerous string).
 *
 * Fully sandboxed: the mock server binds 127.0.0.1:0 (ephemeral, loopback
 * only); temp config files live under os.tmpdir() and are removed in finally.
 * The real ~/.claude, ~/.claudesec and the live spans.db are never touched.
 *
 * Run via:  npx tsx tests/enforceHookLogTest.ts
 *   Exit 0  -> every assertion passed.   Exit 1  -> a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');
const SNAPSHOT = path.join(REPO_ROOT, 'rules-enforcement.json');

// Dangerous strings are assembled at runtime so neither the catastrophic floor
// nor the SQL block rule trips while this very file is being edited/written.
const CATASTROPHIC_CMD = ['rm', '-rf', '/'].join(' ');
const SQL_VERB = 'DR' + 'OP';                 // matches the high-severity SQL rule
const RULE_COMMAND = `psql -c "${SQL_VERB} TABLE users;"`;

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

interface Captured {
  mode?: unknown;
  label?: unknown;
  severity?: unknown;
  command?: unknown;
  blocked?: unknown;
  wouldBlock?: unknown;
}

/** A loopback HTTP server that records the first POST body to /api/enforce-log. */
function startMock(): Promise<{ port: number; bodies: Captured[]; close: () => void }> {
  const bodies: Captured[] = [];
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/api/enforce-log') {
        let raw = '';
        req.on('data', (d) => (raw += d));
        req.on('end', () => {
          try { bodies.push(JSON.parse(raw)); } catch { /* ignore non-JSON */ }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok' }));
        });
        return;
      }
      res.writeHead(404);
      res.end();
    });
    // 127.0.0.1:0 -> loopback only, ephemeral port assigned by the OS.
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ port, bodies, close: () => server.close() });
    });
  });
}

/**
 * Run the real hook with the given stdin + extra env, isolated so the ambient
 * shell can't leak CLAUDESEC_MODE / bypass into the child. Resolves once the
 * child exits OR a ~1s safety timeout elapses (the hook's own backstop is 400ms).
 */
function runHook(
  stdin: string,
  extraEnv: Record<string, string>,
): Promise<{ code: number | null }> {
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    // Start from a clean slate for the vars that steer the hook.
    delete env.CLAUDESEC_MODE;
    delete env.CLAUDESEC_HOOKS_BYPASS;
    delete env.CLAUDESEC_ENFORCE_CONFIG;
    delete env.CLAUDESEC_ENFORCE_RULES;
    Object.assign(env, extraEnv);

    const child = spawn(process.execPath, [HOOK], { cwd: REPO_ROOT, env });
    let settled = false;
    const done = (code: number | null) => {
      if (settled) return;
      settled = true;
      resolve({ code });
    };
    // Safety net so a wedged child can never hang the suite.
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } done(null); }, 1000);
    timer.unref?.();
    child.on('exit', (code) => { clearTimeout(timer); done(code); });
    child.on('error', () => { clearTimeout(timer); done(null); });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/** Give the mock a beat to receive the POST after the child has exited. */
function waitForBody(bodies: Captured[], ms = 500): Promise<void> {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      if (bodies.length > 0 || Date.now() - start > ms) return resolve();
      setTimeout(tick, 20);
    };
    tick();
  });
}

function writeConfig(dir: string, mode: 'monitor' | 'enforce'): string {
  const p = path.join(dir, `enforce-config-${mode}.json`);
  fs.writeFileSync(p, JSON.stringify({ mode }), 'utf8');
  return p;
}

async function main(): Promise<void> {
  // The snapshot is a gitignored generated artifact; build it if it's missing so
  // the rule-block cases have something to match against.
  if (!fs.existsSync(SNAPSHOT)) {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync(process.execPath, [
      path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx'),
      path.join(REPO_ROOT, 'scripts', 'build-enforcement-rules.ts'),
    ], { cwd: REPO_ROOT, encoding: 'utf-8' });
    assert.ok(fs.existsSync(SNAPSHOT), `failed to build snapshot: ${r.stderr || r.stdout}`);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-enforce-log-'));
  const mock = await startMock();
  const ruleStdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: RULE_COMMAND } });

  try {
    const monitorCfg = writeConfig(tmp, 'monitor');
    const enforceCfg = writeConfig(tmp, 'enforce');

    // ── Case 1: catastrophic floor, monitor mode → blocked anyway ─────────────
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: CATASTROPHIC_CMD } });
      const { code } = await runHook(stdin, {
        CLAUDESEC_PORT: String(mock.port),
        CLAUDESEC_ENFORCE_CONFIG: monitorCfg, // resolves to monitor
        CLAUDESEC_ENFORCE_RULES: SNAPSHOT,
      });
      await waitForBody(mock.bodies);
      check('case1 catastrophic: exit code is 2 (denied)', () => assert.strictEqual(code, 2));
      const b = mock.bodies[0];
      check('case1 catastrophic: posted an event', () => assert.ok(b, 'no POST captured'));
      check('case1 catastrophic: blocked === true', () => assert.strictEqual(b?.blocked, true));
      check('case1 catastrophic: non-empty label', () =>
        assert.ok(typeof b?.label === 'string' && b.label.length > 0, `label was ${String(b?.label)}`));
      check('case1 catastrophic: non-empty severity', () =>
        assert.ok(typeof b?.severity === 'string' && b.severity.length > 0));
      check('case1 catastrophic: redacted command present', () =>
        assert.ok(typeof b?.command === 'string' && b.command.length > 0));
    }

    mock.bodies.length = 0;

    // ── Case 2: enforce rule block → blocked ──────────────────────────────────
    {
      const { code } = await runHook(ruleStdin, {
        CLAUDESEC_PORT: String(mock.port),
        CLAUDESEC_ENFORCE_CONFIG: enforceCfg, // resolves to enforce
        CLAUDESEC_ENFORCE_RULES: SNAPSHOT,
      });
      await waitForBody(mock.bodies);
      check('case2 enforce block: exit code is 2 (denied)', () => assert.strictEqual(code, 2));
      const b = mock.bodies[0];
      check('case2 enforce block: posted an event', () => assert.ok(b, 'no POST captured'));
      check('case2 enforce block: blocked === true', () => assert.strictEqual(b?.blocked, true));
      check('case2 enforce block: mode is enforce', () => assert.strictEqual(b?.mode, 'enforce'));
    }

    mock.bodies.length = 0;

    // ── Case 3: same rule, monitor mode → would-block (allowed) ───────────────
    {
      const { code } = await runHook(ruleStdin, {
        CLAUDESEC_PORT: String(mock.port),
        CLAUDESEC_ENFORCE_CONFIG: monitorCfg, // resolves to monitor
        CLAUDESEC_ENFORCE_RULES: SNAPSHOT,
      });
      await waitForBody(mock.bodies);
      check('case3 monitor would-block: exit code is 0 (allowed)', () => assert.strictEqual(code, 0));
      const b = mock.bodies[0];
      check('case3 monitor would-block: posted an event', () => assert.ok(b, 'no POST captured'));
      check('case3 monitor would-block: blocked === false', () => assert.strictEqual(b?.blocked, false));
      check('case3 monitor would-block: wouldBlock !== false', () =>
        assert.notStrictEqual(b?.wouldBlock, false));
    }

    mock.bodies.length = 0;

    // ── Case 4: CLAUDESEC_HOOKS_BYPASS=1 → allowed, but RECORDED ──────────────
    // The bypass allows the call (exit 0) yet still flushes an event so the
    // escape hatch is visible in the tamper-evident feed. We feed a catastrophic
    // command to prove that even a normally-floored call is allowed under bypass,
    // and that the recorded summary names the tool + target that slipped through.
    {
      const stdin = JSON.stringify({ tool_name: 'Bash', tool_input: { command: CATASTROPHIC_CMD } });
      const { code } = await runHook(stdin, {
        CLAUDESEC_PORT: String(mock.port),
        CLAUDESEC_HOOKS_BYPASS: '1',
        CLAUDESEC_ENFORCE_CONFIG: monitorCfg,
        CLAUDESEC_ENFORCE_RULES: SNAPSHOT,
      });
      await waitForBody(mock.bodies);
      check('case4 bypass: exit code is 0 (allowed)', () => assert.strictEqual(code, 0));
      const b = mock.bodies[0];
      check('case4 bypass: posted an event', () => assert.ok(b, 'no POST captured'));
      check('case4 bypass: blocked === false', () => assert.strictEqual(b?.blocked, false));
      check('case4 bypass: wouldBlock === false', () => assert.strictEqual(b?.wouldBlock, false));
      check('case4 bypass: label names the bypass', () =>
        assert.ok(typeof b?.label === 'string' && /bypass/i.test(b.label), `label was ${String(b?.label)}`));
      check('case4 bypass: command summary names the tool', () =>
        assert.ok(typeof b?.command === 'string' && b.command.includes('Bash'),
          `command was ${String(b?.command)}`));
      check('case4 bypass: non-empty severity', () =>
        assert.ok(typeof b?.severity === 'string' && b.severity.length > 0));
    }
  } finally {
    mock.close();
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
  }
}

main()
  .then(() => {
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  enforceHookLogTest: ${passed}/${total} passed`);
    console.log('───────────────────────────────────────────────');
    if (failures.length) {
      console.error(`\n  ${failures.length} FAILURE(S):`);
      for (const f of failures) console.error(`    ✗ ${f}`);
      process.exit(1);
    }
    process.exit(0);
  })
  .catch((e) => {
    console.error('enforceHookLogTest crashed:', e);
    process.exit(1);
  });
