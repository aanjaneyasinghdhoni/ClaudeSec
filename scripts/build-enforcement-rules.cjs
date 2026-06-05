#!/usr/bin/env node
/**
 * scripts/build-enforcement-rules.cjs
 *
 * Snapshot generator for the ClaudeSec PreToolUse enforcement hook.
 *
 * Run:  node scripts/build-enforcement-rules.cjs
 *
 * Produces  rules-enforcement.json  (a GITIGNORED generated artifact) — a flat
 * array of { source, flags, severity, label, action } objects, where:
 *   action = 'block'  for severity === 'high'   (P0: the hook only blocks HIGH)
 *   action = 'alert'  for everything else       (monitor / alert only)
 *
 * Rule sources:
 *   (1) Built-in SEVERITY_RULES — text-extracted from server.ts. We NEVER import
 *       server.ts (it has listen()/side-effects). We slice the file to the
 *       `const SEVERITY_RULES = [ ... ];` block so strays elsewhere (e.g. the
 *       `pattern: string` interface field) cannot pollute the snapshot.
 *   (2) EXTRA_SEVERITY_RULES — imported exactly via a tiny `tsx` subprocess that
 *       prints them as JSON. severityRulesExtra.ts is a clean, side-effect-free
 *       module (ruleSelfTest.ts already imports it), so this is robust.
 *
 * The generator itself has no third-party deps — it only shells out to the
 * project-local `tsx` to read the EXTRA rules.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_TS = path.join(REPO_ROOT, 'server.ts');
const EXTRA_TS = path.join(REPO_ROOT, 'severityRulesExtra.ts');
const OUT_PATH = path.join(REPO_ROOT, 'rules-enforcement.json');

/**
 * Slice out the body of the `const SEVERITY_RULES: ... = [ ... ];` array from
 * server.ts as raw text, so pattern-extraction only sees the rule block.
 */
function readSeverityRulesBlock() {
  const text = fs.readFileSync(SERVER_TS, 'utf8');
  const startIdx = text.indexOf('const SEVERITY_RULES');
  if (startIdx === -1) {
    throw new Error('Could not find `const SEVERITY_RULES` in server.ts');
  }
  // Find the `=` that assigns the array, then the first `[` after it, then walk
  // bracket depth to its matching `]`. Anchoring on `=` avoids the `[]` that
  // appears in the type annotation (`...; label: string }[] = [`). This stops
  // the spread `...EXTRA_SEVERITY_RULES` and anything after `];` from being
  // scanned.
  const eqIdx = text.indexOf('=', startIdx);
  if (eqIdx === -1) throw new Error('Could not find = of SEVERITY_RULES assignment');
  const openIdx = text.indexOf('[', eqIdx);
  if (openIdx === -1) throw new Error('Could not find opening [ of SEVERITY_RULES');
  let depth = 0;
  let closeIdx = -1;
  for (let i = openIdx; i < text.length; i++) {
    const ch = text[i];
    if (ch === '[') depth++;
    else if (ch === ']') {
      depth--;
      if (depth === 0) {
        closeIdx = i;
        break;
      }
    }
  }
  if (closeIdx === -1) throw new Error('Could not find closing ] of SEVERITY_RULES');
  return text.slice(openIdx, closeIdx + 1);
}

/**
 * Extract built-in rules from the SEVERITY_RULES block text. Each entry is of
 * the shape:  { pattern: /.../flags, severity: '...', label: '...' }
 *
 * We match the regex literal (handling escaped slashes and character classes),
 * capture its flags, then the severity and label from the same object literal.
 */
function extractBuiltinRules(blockText) {
  const rules = [];
  // pattern: /<body>/<flags> ... severity: '<sev>' ... label: '<label>'
  // The body allows: non-slash/backslash/bracket chars, escapes (\.), or
  // bracket-classes ([...] possibly containing \] escapes).
  const re =
    /pattern\s*:\s*\/((?:[^/\\[\n]|\\.|\[(?:[^\]\\]|\\.)*\])*)\/([a-z]*)\s*,\s*severity\s*:\s*['"]([a-z]+)['"]\s*,\s*label\s*:\s*['"]((?:[^'"\\]|\\.)*)['"]/g;
  let m;
  while ((m = re.exec(blockText)) !== null) {
    const source = m[1];
    const flags = m[2] || '';
    const severity = m[3];
    const label = m[4].replace(/\\(['"\\])/g, '$1');
    rules.push({ source, flags, severity, label });
  }
  return rules;
}

/**
 * Import EXTRA_SEVERITY_RULES exactly, via a tsx subprocess that serialises
 * each rule's pattern.source / pattern.flags / severity / label to JSON.
 */
function importExtraRules() {
  if (!fs.existsSync(EXTRA_TS)) return [];
  const evalSrc = [
    "import { EXTRA_SEVERITY_RULES } from './severityRulesExtra.ts';",
    'const out = EXTRA_SEVERITY_RULES.map((r) => ({',
    '  source: r.pattern.source,',
    '  flags: r.pattern.flags,',
    '  severity: r.severity,',
    '  label: r.label,',
    '}));',
    'process.stdout.write(JSON.stringify(out));',
  ].join('\n');

  // Resolve the project-local tsx binary.
  const tsxBin = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
  const runner = fs.existsSync(tsxBin) ? tsxBin : 'npx';
  const args = fs.existsSync(tsxBin)
    ? ['--eval', evalSrc]
    : ['tsx', '--eval', evalSrc];

  const stdout = execFileSync(runner, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

function toEnforcementRule(r) {
  const action = r.severity === 'high' ? 'block' : 'alert';
  return {
    source: r.source,
    flags: r.flags || '',
    severity: r.severity,
    label: r.label,
    action,
  };
}

function main() {
  const blockText = readSeverityRulesBlock();
  const builtin = extractBuiltinRules(blockText);
  const extra = importExtraRules();

  const all = [...builtin, ...extra].map(toEnforcementRule);
  const blockCount = all.filter((r) => r.action === 'block').length;

  fs.writeFileSync(OUT_PATH, JSON.stringify(all, null, 2) + '\n', 'utf8');

  // Summary
  console.log('ClaudeSec — build-enforcement-rules');
  console.log('-----------------------------------');
  console.log(`  built-in rules : ${builtin.length}`);
  console.log(`  extra rules    : ${extra.length}`);
  console.log(`  total rules    : ${all.length}`);
  console.log(`  block (high)   : ${blockCount}`);
  console.log(`  alert (other)  : ${all.length - blockCount}`);
  console.log(`  written to     : ${OUT_PATH}`);
}

main();
