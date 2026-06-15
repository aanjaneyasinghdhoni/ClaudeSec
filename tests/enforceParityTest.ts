/**
 * tests/enforceParityTest.ts
 *
 * BEHAVIORAL cross-layer parity gate. The catastrophic-parity test only compares
 * regex SOURCE strings; it cannot catch a divergence where two layers carry the
 * same patterns but reach DIFFERENT verdicts because of how each one feeds text
 * into those patterns. This test closes that gap: it drives IDENTICAL inputs
 * through BOTH enforcement layers and asserts the BLOCK/ALLOW verdict matches.
 *
 *   • Layer A — the spawned PreToolUse hook (cli/hooks/claudesec-enforce.cjs),
 *     fed a real tool_call on stdin; exit 2 = BLOCK, exit 0 = ALLOW.
 *   • Layer B — the cross-agent MCP enforcement proxy (server/mcpProxy.ts via
 *     server/enforceEval.ts), driven over in-memory streams with a fake downstream
 *     so we observe whether the tools/call is BLOCKED (an isError result is
 *     written back to the agent and the call never reaches downstream) or FORWARDED.
 *
 * The proxy serializes a command-shaped call as `name + JSON.stringify(args)`. The
 * catastrophic floor's command-boundary / end-of-string anchors are destroyed by
 * the JSON wrapper, so before the fix the proxy MISSED `rm -rf /`, `format c:`,
 * `del /f /q`, `rd /s`, and had NO SSRF floor at all — while the hook blocked them.
 * This test FAILS on that drift and PASSES once the proxy extracts the raw command
 * string + URL and applies the SSRF floor (bugs 1 and 2).
 *
 * Mode: enforce is pinned via a temp CLAUDESEC_ENFORCE_CONFIG so the proxy's
 * catastrophic/rule/protected/secret floors are hard blocks (the proxy treats the
 * catastrophic floor as a mode-gated trigger by design — see enforceEval.ts header
 * — so we compare in enforce mode where both layers block). The metadata SSRF tier
 * is mode-independent and is also checked in monitor.
 *
 * Fully sandboxed: temp config/snapshot/protected-paths under os.tmpdir(); every
 * enforce-log POST is aimed at a dead port (CLAUDESEC_PORT=9).
 *
 * Run via:  npx tsx tests/enforceParityTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startProxy } from '../server/mcpProxy.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK = path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// ── Shared sandbox config: one enforce-config, one snapshot, one protected list. ─
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-parity-'));
const ENFORCE_CONFIG = path.join(TMP, 'enforce-config.json');
fs.writeFileSync(ENFORCE_CONFIG, JSON.stringify({ mode: 'enforce', overrides: {} }), 'utf8');
const MONITOR_CONFIG = path.join(TMP, 'monitor-config.json');
fs.writeFileSync(MONITOR_CONFIG, JSON.stringify({ mode: 'monitor', overrides: {} }), 'utf8');
const SNAPSHOT = path.join(TMP, 'rules-enforcement.json');
fs.writeFileSync(SNAPSHOT, JSON.stringify([
  { source: 'DANGERMARKER', flags: 'i', severity: 'high', label: 'danger marker', action: 'block' },
]), 'utf8');
// Empty user protected list — proves the DEFAULT protected set is still applied.
const EMPTY_PROTECTED = path.join(TMP, 'protected-empty.json');
fs.writeFileSync(EMPTY_PROTECTED, JSON.stringify([]), 'utf8');

const HOME = os.homedir();

// ── Layer A — spawn the real hook, return its exit verdict. ──────────────────
function runHook(
  toolName: string,
  toolInput: unknown,
  cfg: string,
  extraEnv: Record<string, string> = {},
): Promise<boolean> {
  const stdin = JSON.stringify({ tool_name: toolName, tool_input: toolInput });
  return new Promise((resolve) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.CLAUDESEC_MODE;
    delete env.CLAUDESEC_HOOKS_BYPASS;
    delete env.CLAUDESEC_ALLOW_LOCAL_FETCH;
    env.CLAUDESEC_PORT = '9'; // dead port
    env.CLAUDESEC_ENFORCE_CONFIG = cfg;
    env.CLAUDESEC_ENFORCE_RULES = SNAPSHOT;
    env.CLAUDESEC_PROTECTED_PATHS = EMPTY_PROTECTED;
    Object.assign(env, extraEnv); // case-specific opt-outs (e.g. allow-local fetch)

    const child = spawn(process.execPath, [HOOK], { cwd: REPO_ROOT, env });
    let settled = false;
    const done = (code: number | null) => {
      if (settled) return;
      settled = true;
      resolve(code === 2); // exit 2 = BLOCK
    };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } done(null); }, 1500);
    timer.unref?.();
    child.on('exit', (code) => { clearTimeout(timer); done(code); });
    child.on('error', () => { clearTimeout(timer); done(null); });
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

/**
 * Layer B — drive the MCP proxy through in-memory streams with a fake downstream,
 * and report whether a tools/call mapping to (toolName, toolInput) was BLOCKED.
 *
 * "Blocked" == the proxy answered the agent itself with an isError result on
 * parentStdout AND never forwarded the line to the (fake) downstream child. We
 * read the proxy's verdict by inspecting which side received the message.
 *
 * The proxy's tools/call name drives shape detection. We map the same logical call
 * the hook receives onto an MCP tool name + arguments so both layers see identical
 * intent:
 *   Bash      → name 'bash',  arguments { command }
 *   WebFetch  → name 'fetch', arguments { url }
 *   Edit/Write→ name 'write', arguments { file_path, content }
 *   Read      → name 'read',  arguments { file_path }   (read-only; the proxy has no
 *               read-only special case, so a read maps to a generic call whose
 *               serialized args still carry the path for the protected floor)
 */
function runProxy(
  mcpName: string,
  args: Record<string, unknown>,
  cfg: string,
  extraEnv: Record<string, string> = {},
): Promise<boolean> {
  return new Promise((resolve) => {
    const prevCfg = process.env.CLAUDESEC_ENFORCE_CONFIG;
    const prevRules = process.env.CLAUDESEC_ENFORCE_RULES;
    const prevPP = process.env.CLAUDESEC_PROTECTED_PATHS;
    const prevPort = process.env.CLAUDESEC_PORT;
    const prevAllow = process.env.CLAUDESEC_ALLOW_LOCAL_FETCH;
    process.env.CLAUDESEC_ENFORCE_CONFIG = cfg;
    process.env.CLAUDESEC_ENFORCE_RULES = SNAPSHOT;
    process.env.CLAUDESEC_PROTECTED_PATHS = EMPTY_PROTECTED;
    process.env.CLAUDESEC_PORT = '9';
    delete process.env.CLAUDESEC_ALLOW_LOCAL_FETCH;
    for (const [k, v] of Object.entries(extraEnv)) process.env[k] = v;

    const restore = () => {
      const set = (k: string, v: string | undefined) => {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      };
      set('CLAUDESEC_ENFORCE_CONFIG', prevCfg);
      set('CLAUDESEC_ENFORCE_RULES', prevRules);
      set('CLAUDESEC_PROTECTED_PATHS', prevPP);
      set('CLAUDESEC_PORT', prevPort);
      set('CLAUDESEC_ALLOW_LOCAL_FETCH', prevAllow);
      for (const k of Object.keys(extraEnv)) {
        if (!(k in { CLAUDESEC_ENFORCE_CONFIG: 0, CLAUDESEC_ENFORCE_RULES: 0, CLAUDESEC_PROTECTED_PATHS: 0, CLAUDESEC_PORT: 0, CLAUDESEC_ALLOW_LOCAL_FETCH: 0 })) {
          delete process.env[k];
        }
      }
    };

    // Fake downstream child: a minimal object with stdin (records forwarded lines),
    // stdout (we never emit), and the EventEmitter surface startProxy uses.
    let forwardedToChild = false;
    const childStdin = { write: () => { forwardedToChild = true; return true; }, end: () => {} };
    const childStdout = new PassThrough();
    const fakeChild = new EventEmitter() as unknown as ReturnType<typeof spawn>;
    (fakeChild as unknown as { stdin: unknown }).stdin = childStdin;
    (fakeChild as unknown as { stdout: unknown }).stdout = childStdout;
    const fakeSpawn = (() => fakeChild) as unknown as typeof spawn;

    const parentStdin = new PassThrough();
    const parentStdout = new PassThrough();
    const parentStderr = new PassThrough();
    parentStderr.resume(); // drain logs

    let blockedToParent = false;
    parentStdout.on('data', (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      if (text.includes('"isError":true') || text.includes('isError')) blockedToParent = true;
    });

    const handle = startProxy({
      command: 'fake',
      args: [],
      parentStdin: parentStdin as unknown as NonNullable<Parameters<typeof startProxy>[0]['parentStdin']>,
      parentStdout: parentStdout as unknown as NodeJS.WritableStream,
      parentStderr: parentStderr as unknown as NodeJS.WritableStream,
      spawnFn: fakeSpawn,
    });

    const req = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: mcpName, arguments: args },
    });
    parentStdin.write(req + '\n');

    // Give the synchronous handler a tick to run, then read the verdict.
    setTimeout(() => {
      void handle.flush().finally(() => {
        try { (fakeChild as unknown as EventEmitter).emit('exit', 0); } catch { /* */ }
        restore();
        // BLOCK == answered the agent with isError AND did not forward downstream.
        resolve(blockedToParent && !forwardedToChild);
      });
    }, 50);
  });
}

// A logical case the parity gate runs through BOTH layers. `hook` describes the
// PreToolUse tool call; `mcp` the equivalent MCP tools/call. `expectBlock` is the
// verdict BOTH layers must agree on (in the given config/mode).
interface ParityCase {
  name: string;
  hookTool: string;
  hookInput: unknown;
  mcpName: string;
  mcpArgs: Record<string, unknown>;
  cfg: string;
  expectBlock: boolean;
  extraEnv?: Record<string, string>;
}

async function main(): Promise<void> {
  const cases: ParityCase[] = [
    // ── Catastrophic floor (bug 1): the JSON wrapper used to hide these from the
    //    proxy. In enforce mode BOTH layers must BLOCK. ──────────────────────────
    {
      name: 'catastrophic: rm -rf /',
      hookTool: 'Bash', hookInput: { command: 'rm -rf /' },
      mcpName: 'bash', mcpArgs: { command: 'rm -rf /' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'catastrophic: rm -rf / --no-preserve-root',
      hookTool: 'Bash', hookInput: { command: 'rm -rf / --no-preserve-root' },
      mcpName: 'bash', mcpArgs: { command: 'rm -rf / --no-preserve-root' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'catastrophic: format c:',
      hookTool: 'Bash', hookInput: { command: 'format c:' },
      mcpName: 'shell', mcpArgs: { command: 'format c:' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'catastrophic: del /f /q',
      hookTool: 'Bash', hookInput: { command: 'del /f /q C:\\Windows' },
      mcpName: 'exec', mcpArgs: { command: 'del /f /q C:\\Windows' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'catastrophic: rd /s',
      hookTool: 'Bash', hookInput: { command: 'rd /s /q C:\\data' },
      mcpName: 'run_command', mcpArgs: { command: 'rd /s /q C:\\data' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'benign command: npm run format (NOT catastrophic)',
      hookTool: 'Bash', hookInput: { command: 'npm run format' },
      mcpName: 'bash', mcpArgs: { command: 'npm run format' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // ── SSRF floor (bug 2): missing from the proxy entirely. ────────────────────
    {
      name: 'ssrf: metadata 169.254.169.254 (mode-independent floor)',
      hookTool: 'WebFetch', hookInput: { url: 'http://169.254.169.254/latest/meta-data/' },
      mcpName: 'fetch', mcpArgs: { url: 'http://169.254.169.254/latest/meta-data/' },
      cfg: MONITOR_CONFIG, expectBlock: true, // floor blocks even in monitor
    },
    {
      name: 'ssrf: loopback 127.0.0.1 in enforce',
      hookTool: 'WebFetch', hookInput: { url: 'http://127.0.0.1:8080/' },
      mcpName: 'web_fetch', mcpArgs: { url: 'http://127.0.0.1:8080/' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'ssrf: RFC1918 10.0.0.5 in enforce',
      hookTool: 'WebFetch', hookInput: { url: 'http://10.0.0.5/admin' },
      mcpName: 'http_get', mcpArgs: { url: 'http://10.0.0.5/admin' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'ssrf: public host example.com → ALLOW',
      hookTool: 'WebFetch', hookInput: { url: 'https://example.com/' },
      mcpName: 'fetch', mcpArgs: { url: 'https://example.com/' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'ssrf: loopback allowed with CLAUDESEC_ALLOW_LOCAL_FETCH=1',
      hookTool: 'WebFetch', hookInput: { url: 'http://127.0.0.1:8080/' },
      mcpName: 'fetch', mcpArgs: { url: 'http://127.0.0.1:8080/' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
      extraEnv: { CLAUDESEC_ALLOW_LOCAL_FETCH: '1' },
    },
    // ── Default protected paths (bug 4): empty user list, defaults still apply. ──
    {
      name: 'default protected: write ~/.ssh/id_rsa',
      hookTool: 'Write', hookInput: { file_path: path.join(HOME, '.ssh', 'id_rsa'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(HOME, '.ssh', 'id_rsa'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'default protected: write ~/.aws/credentials',
      hookTool: 'Write', hookInput: { file_path: path.join(HOME, '.aws', 'credentials'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(HOME, '.aws', 'credentials'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'default protected: write a .env secret',
      hookTool: 'Write', hookInput: { file_path: '/proj/.env', content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: '/proj/.env', content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'default protected carve-out: .env.example → ALLOW',
      hookTool: 'Write', hookInput: { file_path: '/proj/.env.example', content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: '/proj/.env.example', content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'default protected carve-out: ~/.env.example → ALLOW',
      hookTool: 'Write', hookInput: { file_path: path.join(HOME, '.env.example'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(HOME, '.env.example'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // ── Self-protection: project-level Claude settings (bug 5). Both layers
    //    resolve cwd at runtime; the hook is spawned with cwd=REPO_ROOT and the
    //    proxy runs in-process (process.cwd()===REPO_ROOT), so the project settings
    //    files resolve to <REPO_ROOT>/.claude/settings(.local).json on both sides. ─
    {
      name: 'self-protect: project <cwd>/.claude/settings.json',
      hookTool: 'Write', hookInput: { file_path: path.join(REPO_ROOT, '.claude', 'settings.json'), content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: path.join(REPO_ROOT, '.claude', 'settings.json'), content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: project <cwd>/.claude/settings.local.json',
      hookTool: 'Write', hookInput: { file_path: path.join(REPO_ROOT, '.claude', 'settings.local.json'), content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: path.join(REPO_ROOT, '.claude', 'settings.local.json'), content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: Bash redirect into project settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' > ${path.join(REPO_ROOT, '.claude', 'settings.json')}` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' > ${path.join(REPO_ROOT, '.claude', 'settings.json')}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    // ── Block rule parity: a command matching the snapshot rule. ────────────────
    {
      name: 'block rule: command hits DANGERMARKER',
      hookTool: 'Bash', hookInput: { command: 'echo DANGERMARKER' },
      mcpName: 'bash', mcpArgs: { command: 'echo DANGERMARKER' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
  ];

  for (const c of cases) {
    const hookBlock = await runHook(c.hookTool, c.hookInput, c.cfg, c.extraEnv);
    const proxyBlock = await runProxy(c.mcpName, c.mcpArgs, c.cfg, c.extraEnv);
    check(`${c.name}: hook BLOCK == expected(${c.expectBlock})`, () =>
      assert.strictEqual(hookBlock, c.expectBlock));
    check(`${c.name}: proxy BLOCK == expected(${c.expectBlock})`, () =>
      assert.strictEqual(proxyBlock, c.expectBlock));
    check(`${c.name}: hook and proxy AGREE`, () =>
      assert.strictEqual(hookBlock, proxyBlock));
  }
}

function cleanup(): void {
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* */ }
}

main()
  .then(() => {
    cleanup();
    const total = passed + failures.length;
    console.log('───────────────────────────────────────────────');
    console.log(`  enforceParityTest: ${passed}/${total} passed`);
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
    console.error('enforceParityTest crashed:', e);
    process.exit(1);
  });
