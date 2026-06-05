#!/usr/bin/env node
/**
 * cli/mcp-proxy.ts — CLI entry for the ClaudeSec cross-agent MCP enforcement
 * proxy. Spawns a downstream MCP server and gates its tool calls.
 *
 * Usage:
 *   tsx cli/mcp-proxy.ts -- <downstream-cmd> [args...]
 *   claudesec mcp-proxy -- <downstream-cmd> [args...]   (once wired into the bin)
 *
 * Everything after the first `--` is the downstream MCP server command line.
 * (A bare command without `--` is also accepted for convenience.)
 *
 * Env:
 *   CLAUDESEC_MODE=enforce|monitor   resolved per call (config file wins)
 *   CLAUDESEC_HOOKS_BYPASS=1         forward everything (no gating)
 *   CLAUDESEC_PORT / PORT            dashboard port for enforce-log POSTs
 *   CLAUDESEC_ENFORCE_CONFIG / _RULES  override config/snapshot paths
 *
 * stdout carries ONLY MCP messages; all diagnostics go to stderr. Exits with
 * the downstream server's exit code.
 */

import { startProxy } from '../mcpProxy.ts';

function parseArgs(argv: string[]): { command: string; args: string[] } | null {
  // Strip the node/tsx + script path (argv already sliced by caller).
  const dashDash = argv.indexOf('--');
  const rest = dashDash !== -1 ? argv.slice(dashDash + 1) : argv;
  if (rest.length === 0) return null;
  return { command: rest[0], args: rest.slice(1) };
}

function main(): void {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed) {
    process.stderr.write(
      'Usage: claudesec mcp-proxy -- <downstream-cmd> [args...]\n' +
        '\nWraps a downstream stdio MCP server and enforces ClaudeSec rules on\n' +
        'every tools/call. Example:\n' +
        '  claudesec mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /work\n',
    );
    process.exit(2);
  }

  // Make stdin flow (paused streams won't emit 'data').
  if (typeof (process.stdin as NodeJS.ReadStream).resume === 'function') {
    process.stdin.resume();
  }

  const handle = startProxy({ command: parsed.command, args: parsed.args });

  handle.done.then(async (code) => {
    // Flush any in-flight enforce-log POSTs before exiting — a synchronous exit
    // on child-exit would otherwise race (and drop) the best-effort log.
    await handle.flush();
    process.exit(code ?? 0);
  });

  // If we ourselves are killed, take the child with us.
  const killChild = () => {
    try { handle.child.kill('SIGTERM'); } catch { /* noop */ }
  };
  process.on('SIGINT', killChild);
  process.on('SIGTERM', killChild);
}

main();
