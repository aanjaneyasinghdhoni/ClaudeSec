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
 * SELF-PROTECTION COVERAGE. An early version of this gate compared only ABSOLUTE,
 * already-`$HOME`-expanded paths — which is exactly the shape both layers happened
 * to handle — so it passed green while the two sides genuinely disagreed on every
 * other spelling of the same file. The self-protection cases below are therefore
 * written as a matrix of SPELLINGS (tilde, `$HOME`, relative, `../`, a symlinked
 * parent, a shell variable), WRITE VERBS (redirect, `sed -i`, `tee`, `cp`, `mv`,
 * `chmod`, an inline interpreter script), and ARTEFACT SHAPES (control-plane
 * basenames anywhere on disk, `.claude/hooks/`, the launchd plist, a systemd unit,
 * service control by label) — each paired with the benign counterpart that must
 * still be allowed (reads, `sed` without `-i`, a commit message naming
 * settings.json, `.vscode/settings.json`). A regression on either layer flips one
 * of these and fails the gate.
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

/**
 * The hook binary under test (layer A). Defaults to the tracked hook that ships
 * to every clone, which is what CI and `pnpm test` exercise.
 *
 * CLAUDESEC_TEST_HOOK points it at a staged replacement instead. That exists
 * because of the floor this file gates: the live enforcer refuses to let an agent
 * write anything named `claudesec-enforce.cjs`, so a fix TO the hook must be
 * proven from a staged copy before an operator installs it. Pointing this gate at
 * the candidate is how "both layers agree" gets demonstrated rather than asserted.
 */
const HOOK = process.env.CLAUDESEC_TEST_HOOK
  ? path.resolve(process.env.CLAUDESEC_TEST_HOOK)
  : path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs');

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// Relative and `../` spellings are resolved against the process cwd on BOTH
// layers (the hook is spawned with cwd=REPO_ROOT; the proxy runs in-process), so
// pin the cwd rather than inheriting whatever directory the runner was launched
// from. Without this the relative-path cases below would be non-deterministic.
if (process.cwd() !== REPO_ROOT) process.chdir(REPO_ROOT);

// ── Shared sandbox config: one enforce-config, one snapshot, one protected list. ─
// realpath'd: on macOS os.tmpdir() is itself a symlink (/var → /private/var), and
// the symlink-resolution case below compares a resolved path against a prefix
// built from this directory — they must be spelled the same way.
const TMP = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'csec-parity-')));
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

// A sandboxed CLAUDESEC_HOME, pinned for BOTH layers so the control-plane
// directory the floor guards is the same on each side and never depends on
// whether the machine running the tests has a real ~/.claudesec install.
const CSEC_HOME = path.join(TMP, 'csechome');
const CSEC_HOOKS = path.join(CSEC_HOME, 'hooks');
fs.mkdirSync(CSEC_HOOKS, { recursive: true });

// A symlink whose TARGET is the control-plane directory. Writing through it names
// no protected string at all, so it is caught only if the layer resolves the
// symlink chain — the cheapest bypass of a literal-substring floor.
const LINKED_PLANE = path.join(TMP, 'linked-plane');
fs.symlinkSync(CSEC_HOOKS, LINKED_PLANE, 'dir');

const HOME = os.homedir();
const HOME_SETTINGS = path.join(HOME, '.claude', 'settings.json');

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
    env.CLAUDESEC_HOME = CSEC_HOME;
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
    // The proxy runs IN-PROCESS, so every variable it reads has to be pinned to
    // the sandbox and put back afterwards — including whatever the ambient shell
    // had. Remember the previous value the first time each key is touched, then
    // restore exactly that (delete when it was unset).
    const prev = new Map<string, string | undefined>();
    const setEnv = (k: string, v: string | undefined) => {
      if (!prev.has(k)) prev.set(k, process.env[k]);
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    };
    setEnv('CLAUDESEC_ENFORCE_CONFIG', cfg);
    setEnv('CLAUDESEC_ENFORCE_RULES', SNAPSHOT);
    setEnv('CLAUDESEC_PROTECTED_PATHS', EMPTY_PROTECTED);
    setEnv('CLAUDESEC_HOME', CSEC_HOME);
    setEnv('CLAUDESEC_PORT', '9');
    setEnv('CLAUDESEC_MODE', undefined); // the pinned config is the only mode source
    setEnv('CLAUDESEC_ALLOW_LOCAL_FETCH', undefined);
    for (const [k, v] of Object.entries(extraEnv)) setEnv(k, v);

    const restore = () => {
      for (const [k, v] of prev) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
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
    // ── Self-protection floor: PATH NORMALIZATION ───────────────────────────────
    //    The floor used to compare `$HOME`-expanded ABSOLUTE literals only, on both
    //    layers, which meant every other spelling of the same file walked straight
    //    through it. Each case below is a different spelling of ONE path, and each
    //    one must land on the same verdict on both layers.
    {
      name: 'self-protect: tilde redirect into ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' > ~/.claude/settings.json` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' > ~/.claude/settings.json` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: $HOME redirect into ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' > $HOME/.claude/settings.json` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' > $HOME/.claude/settings.json` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: RELATIVE redirect into .claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' > .claude/settings.json` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' > .claude/settings.json` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: ../ traversal back into .claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' > docs/../.claude/settings.json` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' > docs/../.claude/settings.json` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: RELATIVE edit target .claude/settings.json',
      hookTool: 'Write', hookInput: { file_path: '.claude/settings.json', content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: '.claude/settings.json', content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: SYMLINKED parent pointing into the control plane',
      hookTool: 'Write', hookInput: { file_path: path.join(LINKED_PLANE, 'notes.txt'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(LINKED_PLANE, 'notes.txt'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: VAR indirection (P=~/.claude/settings.json; … > $P)',
      hookTool: 'Bash', hookInput: { command: `P=~/.claude/settings.json; echo '{}' > $P` },
      mcpName: 'bash', mcpArgs: { command: `P=~/.claude/settings.json; echo '{}' > $P` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },

    // ── Self-protection floor: CONTROL-PLANE ARTEFACTS BY NAME AND SHAPE ────────
    {
      name: 'self-protect: enforce-config.json written anywhere on disk',
      hookTool: 'Write', hookInput: { file_path: path.join(TMP, 'stash', 'enforce-config.json'), content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: path.join(TMP, 'stash', 'enforce-config.json'), content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: user-level .claude/hooks/ (competing PreToolUse hook)',
      hookTool: 'Write', hookInput: { file_path: path.join(HOME, '.claude', 'hooks', 'rogue.cjs'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(HOME, '.claude', 'hooks', 'rogue.cjs'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: project <cwd>/.claude/hooks/',
      hookTool: 'Write', hookInput: { file_path: path.join(REPO_ROOT, '.claude', 'hooks', 'rogue.cjs'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(REPO_ROOT, '.claude', 'hooks', 'rogue.cjs'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: launchd plist for the ClaudeSec service',
      hookTool: 'Write', hookInput: { file_path: path.join(HOME, 'Library', 'LaunchAgents', 'com.claudesec.agent.plist'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(HOME, 'Library', 'LaunchAgents', 'com.claudesec.agent.plist'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: systemd unit for the ClaudeSec service',
      hookTool: 'Write', hookInput: { file_path: path.join(TMP, 'systemd', 'user', 'claudesec.service'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(TMP, 'systemd', 'user', 'claudesec.service'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: launchctl bootout by LABEL (names no file)',
      hookTool: 'Bash', hookInput: { command: 'launchctl bootout gui/501/com.claudesec.agent' },
      mcpName: 'bash', mcpArgs: { command: 'launchctl bootout gui/501/com.claudesec.agent' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: systemctl --user disable claudesec',
      hookTool: 'Bash', hookInput: { command: 'systemctl --user disable claudesec' },
      mcpName: 'bash', mcpArgs: { command: 'systemctl --user disable claudesec' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },

    // ── Self-protection floor: WRITE VERBS ──────────────────────────────────────
    //    The floor is anchored on the ACTION, so each mutating spelling has to be
    //    recognised as a write — a redirect is not the only way to change a file.
    {
      name: 'self-protect: sed -i on ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `sed -i '' -e 's/monitor/enforce/' ${HOME_SETTINGS}` },
      mcpName: 'bash', mcpArgs: { command: `sed -i '' -e 's/monitor/enforce/' ${HOME_SETTINGS}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: tee into ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `echo '{}' | tee ~/.claude/settings.json` },
      mcpName: 'bash', mcpArgs: { command: `echo '{}' | tee ~/.claude/settings.json` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: cp onto ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: 'cp /tmp/rogue.json ~/.claude/settings.json' },
      mcpName: 'bash', mcpArgs: { command: 'cp /tmp/rogue.json ~/.claude/settings.json' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: mv onto a relative .claude/settings.json',
      hookTool: 'Bash', hookInput: { command: 'mv rogue.json .claude/settings.json' },
      mcpName: 'bash', mcpArgs: { command: 'mv rogue.json .claude/settings.json' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    // `cp -t` puts the destination FIRST, so a tokenizer that only looks at the
    // last argument would miss it on one layer and not the other.
    {
      name: 'self-protect: cp -t the control-plane hooks dir',
      hookTool: 'Bash', hookInput: { command: `cp -t ${CSEC_HOOKS} /tmp/rogue.cjs` },
      mcpName: 'bash', mcpArgs: { command: `cp -t ${CSEC_HOOKS} /tmp/rogue.cjs` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    // Our own teardown commands: an agent that can ask the product to remove
    // itself never has to defeat the floor. Both layers must refuse them.
    {
      name: 'self-protect: claudesec uninstall-hook',
      hookTool: 'Bash', hookInput: { command: 'claudesec uninstall-hook' },
      mcpName: 'bash', mcpArgs: { command: 'claudesec uninstall-hook' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: node cli/init.mjs uninstall-hook --purge',
      hookTool: 'Bash', hookInput: { command: 'node cli/init.mjs uninstall-hook --purge' },
      mcpName: 'bash', mcpArgs: { command: 'node cli/init.mjs uninstall-hook --purge' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: chmod 000 on the installed hook',
      hookTool: 'Bash', hookInput: { command: `chmod 000 ${path.join(CSEC_HOOKS, 'claudesec-enforce.cjs')}` },
      mcpName: 'bash', mcpArgs: { command: `chmod 000 ${path.join(CSEC_HOOKS, 'claudesec-enforce.cjs')}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: inline node script writing .claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `node -e "require('fs').writeFileSync('.claude/settings.json','{}')"` },
      mcpName: 'bash', mcpArgs: { command: `node -e "require('fs').writeFileSync('.claude/settings.json','{}')"` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },

    // ── Self-protection floor: THE FALSE-POSITIVE HALF ──────────────────────────
    //    `settings.json` and `enforce-config.json` are named constantly in ordinary
    //    work — read, grepped, quoted in a commit message, listed by a service
    //    query. None of these files hold a secret, so a floor that fires on a LOOK
    //    is pure noise. These must be ALLOWED on both layers.
    {
      name: 'benign: Read ~/.claude/settings.json → ALLOW',
      hookTool: 'Read', hookInput: { file_path: HOME_SETTINGS },
      mcpName: 'read', mcpArgs: { file_path: HOME_SETTINGS },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: cat ~/.claude/settings.json → ALLOW',
      hookTool: 'Bash', hookInput: { command: `cat ${HOME_SETTINGS}` },
      mcpName: 'bash', mcpArgs: { command: `cat ${HOME_SETTINGS}` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // A copy READS its sources and writes only its destination, so backing the
    // control plane up before changing it must not be refused on either layer.
    {
      name: 'benign: cp ~/.claude/settings.json to a backup → ALLOW',
      hookTool: 'Bash', hookInput: { command: `cp ${HOME_SETTINGS} /tmp/settings.backup.json` },
      mcpName: 'bash', mcpArgs: { command: `cp ${HOME_SETTINGS} /tmp/settings.backup.json` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // Refreshing the enforcer stays possible; only removal is refused.
    {
      name: 'benign: claudesec install-hook → ALLOW',
      hookTool: 'Bash', hookInput: { command: 'claudesec install-hook --yes' },
      mcpName: 'bash', mcpArgs: { command: 'claudesec install-hook --yes' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // The container-build cleanup line the catastrophic floor used to refuse.
    {
      name: 'benign: rm -rf /var/lib/apt/lists/* → ALLOW',
      hookTool: 'Bash', hookInput: { command: 'apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*' },
      mcpName: 'bash', mcpArgs: { command: 'apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: grep the control-plane config → ALLOW',
      hookTool: 'Bash', hookInput: { command: `grep -n mode ${path.join(CSEC_HOOKS, 'enforce-config.json')}` },
      mcpName: 'bash', mcpArgs: { command: `grep -n mode ${path.join(CSEC_HOOKS, 'enforce-config.json')}` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: sed WITHOUT -i only reads → ALLOW',
      hookTool: 'Bash', hookInput: { command: `sed -n '1,20p' ${HOME_SETTINGS}` },
      mcpName: 'bash', mcpArgs: { command: `sed -n '1,20p' ${HOME_SETTINGS}` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: commit message naming settings.json → ALLOW',
      hookTool: 'Bash', hookInput: { command: `git commit -m "document $HOME/.claude/settings.json precedence"` },
      mcpName: 'bash', mcpArgs: { command: `git commit -m "document $HOME/.claude/settings.json precedence"` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: launchctl list | grep claudesec → ALLOW',
      hookTool: 'Bash', hookInput: { command: 'launchctl list | grep claudesec' },
      mcpName: 'bash', mcpArgs: { command: 'launchctl list | grep claudesec' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: .vscode/settings.json is not the control plane → ALLOW',
      hookTool: 'Write', hookInput: { file_path: path.join(REPO_ROOT, '.vscode', 'settings.json'), content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: path.join(REPO_ROOT, '.vscode', 'settings.json'), content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: enforce-config.json.bak is a different file → ALLOW',
      hookTool: 'Write', hookInput: { file_path: path.join(TMP, 'stash', 'enforce-config.json.bak'), content: '{}' },
      mcpName: 'write', mcpArgs: { file_path: path.join(TMP, 'stash', 'enforce-config.json.bak'), content: '{}' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },

    // ── Self-protection floor: SHELL WRAPPERS ───────────────────────────────────
    //    A shell handed an inline script performs the write; an argument scanner
    //    that stops at the shell sees one opaque token and lets it through. Every
    //    direct spelling above was already refused on both layers, so a wrapper
    //    that leaks on EITHER layer is the whole floor gone. The payload is held
    //    identical across these so a failure names the wrapper, not the write.
    {
      name: 'self-protect: sh -c redirect into ~/.claude/settings.json',
      hookTool: 'Bash', hookInput: { command: `sh -c "printf '{}' > ${HOME_SETTINGS}"` },
      mcpName: 'bash', mcpArgs: { command: `sh -c "printf '{}' > ${HOME_SETTINGS}"` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: bash -c rm the enforce config',
      hookTool: 'Bash', hookInput: { command: `bash -c "rm -f ${path.join(CSEC_HOOKS, 'enforce-config.json')}"` },
      mcpName: 'bash', mcpArgs: { command: `bash -c "rm -f ${path.join(CSEC_HOOKS, 'enforce-config.json')}"` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: env sh -c (wrapper in front of the shell)',
      hookTool: 'Bash', hookInput: { command: `env sh -c 'rm -f ${HOME_SETTINGS}'` },
      mcpName: 'bash', mcpArgs: { command: `env sh -c 'rm -f ${HOME_SETTINGS}'` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: timeout 5 sh -c (wrapper with its own argument)',
      hookTool: 'Bash', hookInput: { command: `timeout 5 sh -c 'rm -f ${HOME_SETTINGS}'` },
      mcpName: 'bash', mcpArgs: { command: `timeout 5 sh -c 'rm -f ${HOME_SETTINGS}'` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: payload piped into a shell on stdin',
      hookTool: 'Bash', hookInput: { command: `printf 'rm -f ${HOME_SETTINGS}' | sh` },
      mcpName: 'bash', mcpArgs: { command: `printf 'rm -f ${HOME_SETTINGS}' | sh` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'benign: sh -c running an ordinary command → ALLOW',
      hookTool: 'Bash', hookInput: { command: `sh -c 'npm test'` },
      mcpName: 'bash', mcpArgs: { command: `sh -c 'npm test'` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: bash -c reading the control plane → ALLOW',
      hookTool: 'Bash', hookInput: { command: `bash -c "cat ${HOME_SETTINGS}"` },
      mcpName: 'bash', mcpArgs: { command: `bash -c "cat ${HOME_SETTINGS}"` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },

    // ── Self-protection floor: ANCESTORS ────────────────────────────────────────
    //    A recursive delete of a PARENT destroys the protected child. The old
    //    substring compare was true only at or BELOW a prefix, so the shorter,
    //    strictly worse command was the one that got through.
    {
      name: 'self-protect: rm -rf the parent of the control-plane hooks dir',
      hookTool: 'Bash', hookInput: { command: `rm -rf ${CSEC_HOME}` },
      mcpName: 'bash', mcpArgs: { command: `rm -rf ${CSEC_HOME}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: rm -rf ~/.claude (holds settings.json and hooks/)',
      hookTool: 'Bash', hookInput: { command: `rm -rf ${path.join(HOME, '.claude')}` },
      mcpName: 'bash', mcpArgs: { command: `rm -rf ${path.join(HOME, '.claude')}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: rm -rf the whole project directory (cwd)',
      hookTool: 'Bash', hookInput: { command: 'rm -rf .' },
      mcpName: 'bash', mcpArgs: { command: 'rm -rf .' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: mv the control-plane home away',
      hookTool: 'Bash', hookInput: { command: `mv ${CSEC_HOME} /tmp/gone` },
      mcpName: 'bash', mcpArgs: { command: `mv ${CSEC_HOME} /tmp/gone` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: ancestor delete behind a shell wrapper',
      hookTool: 'Bash', hookInput: { command: `sh -c 'rm -rf ${CSEC_HOME}'` },
      mcpName: 'bash', mcpArgs: { command: `sh -c 'rm -rf ${CSEC_HOME}'` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    // Only verbs that DESTROY or DISPLACE a tree read an ancestor as a hit;
    // writing INTO a directory harms nothing beneath it.
    {
      name: 'benign: cp -r into the project root → ALLOW',
      hookTool: 'Bash', hookInput: { command: 'cp -r ../assets .' },
      mcpName: 'bash', mcpArgs: { command: 'cp -r ../assets .' },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: rm -rf an ordinary build directory → ALLOW',
      hookTool: 'Bash', hookInput: { command: `rm -rf ${path.join(TMP, 'build')}` },
      mcpName: 'bash', mcpArgs: { command: `rm -rf ${path.join(TMP, 'build')}` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: rm a file whose name merely starts the same → ALLOW',
      hookTool: 'Bash', hookInput: { command: `rm -f ${CSEC_HOME}-notes.txt` },
      mcpName: 'bash', mcpArgs: { command: `rm -f ${CSEC_HOME}-notes.txt` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },

    // ── Self-protection floor: THE RECORD, ITS ANCHOR AND ITS KEY ───────────────
    //    Unhooking the enforcer and deleting what it already wrote down are the
    //    same attack finished at different ends. Only the first end was guarded.
    {
      name: 'self-protect: rm the spans database',
      hookTool: 'Bash', hookInput: { command: `rm -f ${path.join(CSEC_HOME, 'spans.db')}` },
      mcpName: 'bash', mcpArgs: { command: `rm -f ${path.join(CSEC_HOME, 'spans.db')}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: rm the WAL sidecar (the newest spans)',
      hookTool: 'Bash', hookInput: { command: `rm -f ${path.join(CSEC_HOME, 'spans.db')}-wal` },
      mcpName: 'bash', mcpArgs: { command: `rm -f ${path.join(CSEC_HOME, 'spans.db')}-wal` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: sqlite3 UPDATE rewriting the record in place',
      hookTool: 'Bash', hookInput: { command: `sqlite3 ${path.join(CSEC_HOME, 'spans.db')} 'UPDATE spans SET severity=0'` },
      mcpName: 'bash', mcpArgs: { command: `sqlite3 ${path.join(CSEC_HOME, 'spans.db')} 'UPDATE spans SET severity=0'` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: rm -rf the backups directory',
      hookTool: 'Bash', hookInput: { command: `rm -rf ${path.join(CSEC_HOME, 'backups')}` },
      mcpName: 'bash', mcpArgs: { command: `rm -rf ${path.join(CSEC_HOME, 'backups')}` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: write the Ed25519 signing key wherever it sits',
      hookTool: 'Write', hookInput: { file_path: path.join(TMP, 'audit-key.ed25519.pem'), content: 'x' },
      mcpName: 'write', mcpArgs: { file_path: path.join(TMP, 'audit-key.ed25519.pem'), content: 'x' },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'benign: sqlite3 SELECT only reads the record → ALLOW',
      hookTool: 'Bash', hookInput: { command: `sqlite3 ${path.join(CSEC_HOME, 'spans.db')} 'SELECT count(*) FROM spans'` },
      mcpName: 'bash', mcpArgs: { command: `sqlite3 ${path.join(CSEC_HOME, 'spans.db')} 'SELECT count(*) FROM spans'` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // The floor is mode-INDEPENDENT: a monitor-mode agent must not be able to
    // delete the record either. (The proxy treats the floor as a mode-gated
    // trigger by design, so this pair is compared in enforce; the monitor-mode
    // hook behaviour is asserted in tests/selfProtectionFloorTest.ts.)

    // ── Self-protection floor: SHELL QUOTING ────────────────────────────────────
    //    A backtick span is command substitution in a script and prose in a
    //    document, and the floor could not tell them apart — so writing a doc that
    //    QUOTED a blocked command was itself blocked, including this project's own
    //    PR description. The rule that separates them is the shell's: a quoted
    //    heredoc body and a single-quoted span are literal, a double-quoted one is
    //    not. Both layers have to agree on that, or an MCP agent and a Claude Code
    //    agent get different answers about whether they may write a changelog.
    {
      name: 'benign: quoted heredoc quoting a blocked command → ALLOW',
      hookTool: 'Bash', hookInput: { command: `cat > /tmp/x.md <<'EOF'\nBefore the fix, \`rm -rf ${CSEC_HOME}\` was allowed.\nEOF` },
      mcpName: 'bash', mcpArgs: { command: `cat > /tmp/x.md <<'EOF'\nBefore the fix, \`rm -rf ${CSEC_HOME}\` was allowed.\nEOF` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    {
      name: 'benign: commit message quoting a blocked command → ALLOW',
      hookTool: 'Bash', hookInput: { command: `git commit -m 'fix(enforce): refuse \`rm -rf ${CSEC_HOME}\`'` },
      mcpName: 'bash', mcpArgs: { command: `git commit -m 'fix(enforce): refuse \`rm -rf ${CSEC_HOME}\`'` },
      cfg: ENFORCE_CONFIG, expectBlock: false,
    },
    // The counterweight: everywhere the shell WOULD expand it, both layers block.
    {
      name: 'self-protect: bare $( ) substitution',
      hookTool: 'Bash', hookInput: { command: `$(rm -rf ${CSEC_HOME})` },
      mcpName: 'bash', mcpArgs: { command: `$(rm -rf ${CSEC_HOME})` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: backticks inside DOUBLE quotes',
      hookTool: 'Bash', hookInput: { command: `echo "see \`rm -rf ${CSEC_HOME}\`"` },
      mcpName: 'bash', mcpArgs: { command: `echo "see \`rm -rf ${CSEC_HOME}\`"` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: unquoted heredoc body is live code',
      hookTool: 'Bash', hookInput: { command: `cat > /tmp/x.md <<EOF\n\`rm -rf ${CSEC_HOME}\`\nEOF` },
      mcpName: 'bash', mcpArgs: { command: `cat > /tmp/x.md <<EOF\n\`rm -rf ${CSEC_HOME}\`\nEOF` },
      cfg: ENFORCE_CONFIG, expectBlock: true,
    },
    {
      name: 'self-protect: rm -rf $( ) supplying the target',
      hookTool: 'Bash', hookInput: { command: `rm -rf $(echo ${CSEC_HOOKS})` },
      mcpName: 'bash', mcpArgs: { command: `rm -rf $(echo ${CSEC_HOOKS})` },
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
