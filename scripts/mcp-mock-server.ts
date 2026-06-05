#!/usr/bin/env node
/**
 * scripts/mcp-mock-server.ts — a minimal stdio MCP server for e2e testing the
 * ClaudeSec enforcement proxy. Speaks JSON-RPC 2.0 over newline-delimited
 * stdin/stdout. Implements just enough of MCP to exercise the proxy:
 *   • initialize            → capabilities + serverInfo
 *   • notifications/initialized → (notification, no response)
 *   • ping                  → empty result
 *   • tools/list            → echo (benign) + run_command (dangerous)
 *   • tools/call            → executes the named tool
 *
 * SIDE-EFFECT PROOF: when run_command is ACTUALLY invoked, it appends a unique
 * token (from env MOCK_EXEC_MARKER) to the file at MOCK_EXEC_FILE. The e2e
 * client asserts that token is ABSENT after an enforce-mode block — proving the
 * downstream tool was never reached.
 */

import fs from 'node:fs';

const MARKER = process.env.MOCK_EXEC_MARKER ?? 'EXECUTED';
const EXEC_FILE = process.env.MOCK_EXEC_FILE ?? '';

function send(msg: unknown): void {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function recordExecution(tool: string, detail: string): void {
  if (!EXEC_FILE) return;
  try {
    fs.appendFileSync(EXEC_FILE, `${MARKER} ${tool} ${detail}\n`);
  } catch {
    /* ignore */
  }
}

const TOOLS = [
  {
    name: 'echo',
    description: 'Echo back the provided text (benign).',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to echo.' } },
      required: ['text'],
    },
  },
  {
    name: 'run_command',
    description: 'Run a shell command (dangerous — gated by ClaudeSec).',
    inputSchema: {
      type: 'object',
      properties: { command: { type: 'string', description: 'Command to run.' } },
      required: ['command'],
    },
  },
];

interface Req {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

function handle(req: Req): void {
  const { id, method, params } = req;

  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'mcp-mock-server', version: '0.0.1' },
        },
      });
      return;

    case 'notifications/initialized':
      return; // notification — no response

    case 'ping':
      send({ jsonrpc: '2.0', id, result: {} });
      return;

    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      return;

    case 'tools/call': {
      const name = String(params?.name ?? '');
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      if (name === 'echo') {
        const text = String(args.text ?? '');
        recordExecution('echo', text);
        send({
          jsonrpc: '2.0',
          id,
          result: { content: [{ type: 'text', text: `echo: ${text}` }], isError: false },
        });
        return;
      }
      if (name === 'run_command') {
        const command = String(args.command ?? '');
        // This is the side-effect the enforce test must prove NEVER happens.
        recordExecution('run_command', command);
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `ran: ${command}` }],
            isError: false,
          },
        });
        return;
      }
      send({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${name}` } });
      return;
    }

    default:
      // Unknown request with an id → method-not-found; notifications → ignore.
      if (id !== undefined && id !== null) {
        send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
      }
      return;
  }
}

let buf = '';
process.stdin.on('data', (chunk: Buffer) => {
  buf += chunk.toString('utf8');
  let nl: number;
  while ((nl = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    if (line.trim() === '') continue;
    try {
      handle(JSON.parse(line) as Req);
    } catch {
      /* ignore malformed line */
    }
  }
});
process.stdin.on('end', () => process.exit(0));
process.stdin.resume();
