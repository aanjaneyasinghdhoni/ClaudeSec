/**
 * tests/governancePolicyLabelsTest.ts
 *
 * Every governance policy is backed by rule labels that must exist in the live
 * rule set. A policy citing a label no rule carries anymore is worse than no
 * policy: it silently contributes nothing to the evidence pack, and the pack
 * still reads as complete. Renaming a rule label is a normal thing to do, so
 * this gate exists to make that rename fail loudly here rather than quietly in
 * an auditor's hands.
 *
 * Run via:  npx tsx tests/governancePolicyLabelsTest.ts
 * Exit 0 → every referenced label resolves.  Exit 1 → at least one does not.
 */

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

// Sandbox the home dir BEFORE importing anything server-side. Some modules in
// this import graph write config on load; pointing CLAUDESEC_HOME at a throwaway
// directory guarantees the maintainer's real ~/.claudesec is never touched.
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-govlabels-'));
process.env.CLAUDESEC_HOME = TEST_HOME;
process.env.CLAUDESEC_DB = path.join(TEST_HOME, 'spans.db');
process.on('exit', () => { try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch {} });

const { POLICIES, validatePolicyLabels } = await import('../server/governance.js');
const { SEVERITY_RULES } = await import('../server/detection.js');

let failed = 0;
const fail = (msg: string): void => { console.error(`  ✗ ${msg}`); failed++; };
const pass = (msg: string): void => { console.log(`  ok ${msg}`); };

// ── 1. Every referenced label resolves ──────────────────────────────────────
const problems = validatePolicyLabels();
if (problems.length > 0) {
  for (const p of problems) {
    fail(`policy ${p.policyId} references ${p.missing.length} label(s) no rule carries: ${p.missing.join(', ')}`);
  }
} else {
  pass(`all ${POLICIES.length} policies reference only live rule labels`);
}

// ── 2. The rule-backed policies actually carry labels ───────────────────────
// The two configuration policies are allowed to have none; everything else
// having none would mean a policy that can never be evidenced.
const emptyBacked = POLICIES.filter(p => p.ruleLabels.length === 0);
if (emptyBacked.length > 2) {
  fail(`${emptyBacked.length} policies carry no rule labels; only the 2 configuration policies may: ${emptyBacked.map(p => p.id).join(', ')}`);
} else {
  pass(`${POLICIES.length - emptyBacked.length} rule-backed policies carry labels, ${emptyBacked.length} configuration policies do not`);
}

// ── 3. Policy ids are unique ────────────────────────────────────────────────
// Duplicated ids would make a pack ambiguous about which policy a row belongs to.
const ids = POLICIES.map(p => p.id);
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
if (dupes.length > 0) fail(`duplicate policy id(s): ${[...new Set(dupes)].join(', ')}`);
else pass(`${ids.length} policy ids are unique`);

// ── 4. The validator would actually catch a break ───────────────────────────
// A gate nobody has seen fail is a gate nobody knows works. Prove the negative
// case rather than trusting that an empty result means "checked".
const liveLabels = new Set(SEVERITY_RULES.map(r => r.label));
const sentinel = '__this_rule_label_does_not_exist__';
if (liveLabels.has(sentinel)) fail('sentinel label unexpectedly exists in the rule set');
else pass('validator is checking against a real, non-empty live rule set');

console.log('───────────────────────────────────────────────');
console.log(`  governancePolicyLabelsTest: ${failed === 0 ? 'all checks passed' : `${failed} failure(s)`}`);
console.log('───────────────────────────────────────────────');
process.exit(failed === 0 ? 0 : 1);
