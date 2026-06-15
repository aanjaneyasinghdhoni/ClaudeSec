#!/usr/bin/env tsx
/**
 * scripts/build-enforcement-rules.ts
 *
 * Snapshot generator for the ClaudeSec PreToolUse enforcement hook.
 *
 * Run:  tsx scripts/build-enforcement-rules.ts
 *
 * Produces  rules-enforcement.json  (a GITIGNORED generated artifact) — a flat
 * array of { source, flags, severity, label, action } objects, where:
 *   action = 'block'  for severity 'high' or 'critical'  (the hook blocks the
 *                                                          two top tiers: high
 *                                                          threats + active exfil)
 *   action = 'alert'  for everything else                (monitor / alert only)
 *
 * Rule source: the shared builder in server/enforcementSnapshot.ts, which reads
 * SEVERITY_RULES from server/detection.ts. detection.ts is side-effect-free (no
 * DB, no server setup), so importing it here is safe. Sharing the builder means
 * this install-time generator and the live server can never disagree on the
 * built-in portion of the snapshot.
 *
 * This generator emits the BUILT-IN rules only. The running server later mirrors
 * the same built-ins PLUS any user-added custom rules to the locations the hook
 * and MCP proxy read (see writeEnforcementSnapshot in server/index.ts).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildEnforcementSnapshot } from '../server/enforcementSnapshot.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const OUT_PATH = path.join(REPO_ROOT, 'rules-enforcement.json');

function main(): void {
  const all = buildEnforcementSnapshot();
  const blockCount = all.filter((r) => r.action === 'block').length;

  fs.writeFileSync(OUT_PATH, JSON.stringify(all, null, 2) + '\n', 'utf8');

  console.log('ClaudeSec — build-enforcement-rules');
  console.log('-----------------------------------');
  console.log(`  total rules        : ${all.length}`);
  console.log(`  block (high+crit)  : ${blockCount}`);
  console.log(`  alert (other)      : ${all.length - blockCount}`);
  console.log(`  written to         : ${OUT_PATH}`);
}

main();
