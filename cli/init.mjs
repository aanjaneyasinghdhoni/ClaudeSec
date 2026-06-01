#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');
const entry = path.join(__dirname, 'init.ts');

const child = spawnSync(process.execPath, [tsxCli, entry, ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: process.env,
});

if (child.error) {
  console.error(child.error.message);
  process.exit(1);
}

process.exit(child.status ?? 1);
