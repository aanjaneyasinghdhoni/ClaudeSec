#!/usr/bin/env node
// Release-fact consistency gate.
//
// Fails CI when facts that must move together drift apart, so no release ships
// with stale documentation. Enforced invariants:
//   1. Version    — package.json === openapi.yaml `info.version`
//   2. Changelog  — CHANGELOG.md has a section for the current version
//   3. Rule count — the ~core / ~extra / ~total figures in README.md match the
//                   real number of rules in the detection source (within 5%)
//
// Pure Node, no dependencies. Run: `node scripts/check-consistency.mjs`

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(root, p), 'utf8');
const errors = [];

// 1. Version: package.json is the single source of truth.
const version = JSON.parse(read('package.json')).version;
const apiVersion = read('openapi.yaml').match(
  /^info:\s*[\s\S]*?^\s{2}version:\s*["']?([0-9][^\s"']*)/m,
)?.[1];
if (apiVersion !== version) {
  errors.push(`version drift: package.json is ${version}, openapi.yaml is ${apiVersion ?? '(not found)'}`);
}

// 2. Changelog: every release needs an entry. Plain substring match (no regex)
// so the version string needs no metacharacter escaping. The in-app docs ship
// their own copy of the changelog, so it must carry the release too — it once
// drifted four releases behind without anything failing.
if (!read('CHANGELOG.md').includes(`## [${version}]`)) {
  errors.push(`CHANGELOG.md has no "## [${version}]" section — add the release notes before tagging`);
}
if (!read('docs/changelog.mdx').includes(`## ${version}`)) {
  errors.push(`docs/changelog.mdx has no "## ${version}" section — sync it with CHANGELOG.md before tagging`);
}

// 3. Rule counts: docs must track the real detection source.
const countRules = (p) => (read(p).match(/^\s*\{\s*pattern:/gm) || []).length;
const core = countRules('server/detection.ts');
const extra = countRules('server/severityRulesExtra.ts');
const total = core + extra;

const readme = read('README.md');
const documented = (re, label) => {
  const m = readme.match(re);
  if (!m) errors.push(`README.md is missing a documented ${label} rule count`);
  return m ? Number(m[1]) : null;
};
const compare = (real, claimed, label) => {
  if (claimed == null) return;
  const tol = Math.max(10, Math.round(real * 0.05));
  if (Math.abs(real - claimed) > tol) {
    errors.push(`${label} rule count drift: source has ${real}, README says ~${claimed} (±${tol}). Update every doc that cites the count.`);
  }
};
compare(core, documented(/~?(\d{3})\s+core/i, 'core'), 'core');
compare(extra, documented(/~?(\d{3})\s+extra/i, 'extra'), 'extra');
compare(total, documented(/~(\d{3})\s+(?:built-in|total)/i, 'total'), 'total');

// COMPLIANCE.md quotes the same total to reviewers. It sat at ~639 for a whole
// release cycle after the rules grew, because nothing checked it — a compliance
// doc is the last place a stale number belongs, so it is gated here too.
const complianceText = read('COMPLIANCE.md');
const complianceCounts = [...complianceText.matchAll(/~(\d{3})\s+(?:deterministic|built-in|threat)/gi)].map((m) => Number(m[1]));
if (!complianceCounts.length) {
  errors.push('COMPLIANCE.md is missing a documented rule count');
} else {
  for (const claimed of complianceCounts) compare(total, claimed, 'COMPLIANCE.md total');
}

if (errors.length) {
  console.error('✖ consistency check failed:');
  for (const e of errors) console.error(`  - ${e}`);
  console.error('\nSee .github/RELEASING.md. Fix the drift before releasing.');
  process.exit(1);
}
console.log(`✓ consistency check passed (version ${version}; rules: ${core} core + ${extra} extra = ${total}).`);
