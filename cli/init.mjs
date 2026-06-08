#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');

// Subcommand routing. `mcp-proxy` is the cross-agent MCP enforcement proxy: it
// speaks raw JSON-RPC over stdio, so it runs as its own entry (stdin/stdout are
// the MCP wire — they must reach the proxy untouched). Everything else goes to
// the standard CLI (init.ts).
const argv = process.argv.slice(2);
const entry =
  argv[0] === 'mcp-proxy'
    ? path.join(__dirname, 'mcp-proxy.ts')
    : path.join(__dirname, 'init.ts');
// Strip the `mcp-proxy` token so mcp-proxy.ts sees only `-- <downstream...>`.
const forwarded = argv[0] === 'mcp-proxy' ? argv.slice(1) : argv;

const child = spawnSync(process.execPath, [tsxCli, entry, ...forwarded], {
  stdio: 'inherit',
  env: process.env,
});

if (child.error) {
  console.error(child.error.message);
  process.exit(1);
}

process.exit(child.status ?? 1);
