#!/usr/bin/env node
/**
 * npx claudesec init
 * Interactive wizard that prints the exact env-var exports needed to
 * connect any supported AI agent harness to ClaudeSec.
 */
import { createInterface } from 'readline';
import { HARNESSES, type HarnessConfig } from '../src/harnesses.js';

const PORT = process.env.CLAUDESEC_PORT ?? '3000';
const ENDPOINT = `http://localhost:${PORT}/v1/traces`;

function prompt(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, resolve));
}

function printExports(harness: HarnessConfig) {
  console.log(`\n\x1b[1m\x1b[36m# ${harness.name} — copy and paste into your terminal:\x1b[0m\n`);
  for (const env of harness.envVars) {
    const val = env.value.replace('{{ENDPOINT}}', ENDPOINT);
    console.log(`\x1b[32mexport ${env.key}="${val}"\x1b[0m   # ${env.description}`);
  }
  console.log(`\n\x1b[90mThen restart ${harness.name} and open http://localhost:${PORT}\x1b[0m\n`);
  if (harness.docsUrl) {
    console.log(`\x1b[90mDocs: ${harness.docsUrl}\x1b[0m\n`);
  }
}

async function main() {
  console.log('\n\x1b[1m\x1b[35mClaudeSec — Agent Setup Wizard\x1b[0m');
  console.log('\x1b[90mConnects any AI agent harness to the local observatory.\x1b[0m\n');

  const rl = createInterface({ input: process.stdin, output: process.stdout });

  // List harnesses (skip 'unknown')
  const choices = HARNESSES.filter(h => h.id !== 'unknown');
  choices.forEach((h, i) => {
    console.log(`  \x1b[33m${i + 1}.\x1b[0m ${h.name.padEnd(20)} \x1b[90m${h.description}\x1b[0m`);
  });
  console.log(`  \x1b[33m${choices.length + 1}.\x1b[0m Show all (generic OTLP)\n`);

  const raw = await prompt(rl, '\x1b[1mSelect your harness (number): \x1b[0m');
  const idx = parseInt(raw.trim(), 10) - 1;

  if (idx === choices.length) {
    // Show all
    for (const h of choices) printExports(h);
  } else if (idx >= 0 && idx < choices.length) {
    printExports(choices[idx]);
  } else {
    console.error('\x1b[31mInvalid selection.\x1b[0m');
    rl.close();
    process.exit(1);
  }

  rl.close();
}

main().catch(err => { console.error(err); process.exit(1); });
