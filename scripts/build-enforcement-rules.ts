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
 *   action = 'block'  for severity === 'high'   (P0: the hook only blocks HIGH)
 *   action = 'alert'  for everything else       (monitor / alert only)
 *
 * Rule source: SEVERITY_RULES imported directly from server/detection.ts.
 * detection.ts is side-effect-free (no DB, no server setup), so importing it
 * here is safe and avoids the brittle text-parsing of server/index.ts that
 * the previous .cjs generator used.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SEVERITY_RULES } from '../server/detection.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const OUT_PATH = path.join(REPO_ROOT, 'rules-enforcement.json');

interface EnforcementRule {
  source: string;
  flags: string;
  severity: string;
  label: string;
  action: 'block' | 'alert';
}

function toEnforcementRule(r: { pattern: RegExp; severity: string; label: string }): EnforcementRule {
  const action = r.severity === 'high' ? 'block' : 'alert';
  return {
    source: r.pattern.source,
    flags: r.pattern.flags,
    severity: r.severity,
    label: r.label,
    action,
  };
}

function main(): void {
  const all: EnforcementRule[] = SEVERITY_RULES.map(toEnforcementRule);
  const blockCount = all.filter((r) => r.action === 'block').length;

  fs.writeFileSync(OUT_PATH, JSON.stringify(all, null, 2) + '\n', 'utf8');

  console.log('ClaudeSec — build-enforcement-rules');
  console.log('-----------------------------------');
  console.log(`  total rules    : ${all.length}`);
  console.log(`  block (high)   : ${blockCount}`);
  console.log(`  alert (other)  : ${all.length - blockCount}`);
  console.log(`  written to     : ${OUT_PATH}`);
}

main();
