#!/usr/bin/env node
// Deployed-enforcement drift gate.
//
// Every other gate in this repo proves the *source* is self-consistent:
// tests/catastrophic-parity.test.ts checks that server/enforceEval.ts and
// cli/hooks/claudesec-enforce.cjs declare the same floors. None of them look at
// the copy that is actually wired into Claude Code. `install-hook` takes a
// snapshot, so from the moment it runs the two are independent: a machine can
// execute a months-old hook that is missing the live-secret floor, symlink
// resolution and the self-protection floor, while every source-parity gate
// stays green.
//
// This gate closes that hole. It answers one question: **is the enforcement
// artifact Claude Code will execute the same one this repo ships?**
//
//   1. Discover the hook the way the harness does — read every settings file
//      Claude Code merges (managed → user → project → project-local) and pull
//      the PreToolUse commands out of it. Never assume a location: a machine can
//      legitimately have the hook registered several times, from different
//      files, at different paths, and a check hardcoded to
//      `~/.claudesec/hooks/...` would silently ignore the others.
//   2. Compare each registered copy to cli/hooks/claudesec-enforce.cjs by
//      SHA-256. `install-hook` deploys with fs.copyFileSync — a verbatim byte
//      copy, no templating, no rewriting — so a whole-file hash has no
//      legitimate way to differ, and it catches drift a pattern-level check
//      would miss (a deleted helper, an inverted condition, an early return).
//   3. On mismatch, say *what* drifted: the CATASTROPHIC and LIVE_SECRET
//      pattern sets, which security helpers are missing, sizes and mtimes.
//      "Hashes differ" is not an actionable report.
//   4. Verify the rules snapshot sitting next to each deployed hook still
//      contains every built-in rule the current source produces.
//
// Nothing registered  → PASS. A fresh clone, a CI runner and a Docker build
// have no hook installed; there is no deployment, so there is no drift.
// Registered but the file is gone → FAIL. Claude Code fails open on a missing
// hook command, so that is enforcement silently switched off, not a clean slate.
//
// Pure Node, no dependencies (the optional snapshot step shells out to the
// repo's own tsx and degrades to a skip if that is unavailable).
// Run: `node scripts/check-deployed-hook.mjs`

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Kept in step with cli/installHook.ts HOOK_FILENAME. Declared here rather than
// imported so this gate stays dependency-free plain Node and can run before a
// build; installHookTest.ts already pins the installer side of the name.
const HOOK_FILENAME = 'claudesec-enforce.cjs';
const SOURCE_HOOK = path.join(REPO_ROOT, 'cli', 'hooks', HOOK_FILENAME);
const FIX_COMMAND = 'node cli/init.mjs install-hook --yes';

const errors = [];
const notes = [];

// ── settings discovery ──────────────────────────────────────────────────────

/**
 * Every settings file Claude Code merges, in precedence order. Absent files are
 * skipped; the point is to find registrations wherever the user put them, not
 * to reimplement the merge.
 *
 * CLAUDESEC_CLAUDE_SETTINGS overrides the user-level file — the same override
 * cli/installHook.ts honors, so the gate can be pointed at a sandbox without
 * touching the real home.
 */
function settingsCandidates() {
  const home = os.homedir();
  const userDir = process.env.CLAUDE_CONFIG_DIR || path.join(home, '.claude');
  const userSettings =
    process.env.CLAUDESEC_CLAUDE_SETTINGS || path.join(userDir, 'settings.json');

  const managed =
    process.platform === 'darwin'
      ? '/Library/Application Support/ClaudeCode/managed-settings.json'
      : process.platform === 'win32'
        ? 'C:\\ProgramData\\ClaudeCode\\managed-settings.json'
        : '/etc/claude-code/managed-settings.json';

  return [
    { scope: 'managed', file: managed },
    { scope: 'user', file: userSettings },
    { scope: 'user-local', file: path.join(userDir, 'settings.local.json') },
    { scope: 'project', file: path.join(REPO_ROOT, '.claude', 'settings.json') },
    { scope: 'project-local', file: path.join(REPO_ROOT, '.claude', 'settings.local.json') },
  ];
}

/**
 * Split a shell command into tokens, honoring single and double quotes.
 * install-hook writes `node "<path>"` (quoted so a $HOME with a space cannot
 * split the argument and silently disable the hook), but a hand-written entry
 * may be unquoted, so both spellings have to parse.
 */
function tokenize(command) {
  const tokens = [];
  let current = '';
  let quote = null;
  let started = false;

  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (started || current) tokens.push(current);
      current = '';
      started = false;
      continue;
    }
    current += ch;
  }
  if (started || current) tokens.push(current);
  return tokens;
}

/** Expand the variables a hook command realistically carries, then absolutize. */
function resolveHookPath(token) {
  let p = token;
  if (p === '~' || p.startsWith('~/')) p = path.join(os.homedir(), p.slice(1));
  p = p
    .replace(/\$\{?HOME\}?/g, os.homedir())
    .replace(/\$\{?CLAUDE_PROJECT_DIR\}?/g, REPO_ROOT);
  return path.resolve(REPO_ROOT, p);
}

/** Collapse symlinks so two spellings of one file are not reported twice. */
function canonical(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * Walk hooks.PreToolUse in one settings object and return every command entry
 * that runs our hook, with the script path resolved.
 */
function registrationsIn(settings, scope, file) {
  const found = [];
  const pre = settings?.hooks?.PreToolUse;
  if (!Array.isArray(pre)) return found;

  for (const entry of pre) {
    if (!entry || !Array.isArray(entry.hooks)) continue;
    for (const hook of entry.hooks) {
      if (hook?.type !== 'command' || typeof hook.command !== 'string') continue;
      if (!hook.command.includes(HOOK_FILENAME)) continue;

      const token = tokenize(hook.command).find((t) => t.endsWith(HOOK_FILENAME));
      if (!token) {
        // The filename appears but not as a resolvable argument — most likely a
        // wrapper script. Flag it rather than pretend we verified anything.
        errors.push(
          `${scope} (${file}): a PreToolUse command mentions ${HOOK_FILENAME} but no ` +
            `script path could be parsed out of it — cannot verify what runs.\n` +
            `      command: ${hook.command}`,
        );
        continue;
      }
      found.push({
        scope,
        file,
        matcher: typeof entry.matcher === 'string' ? entry.matcher : '(any)',
        hookPath: resolveHookPath(token),
      });
    }
  }
  return found;
}

function discoverRegistrations() {
  const all = [];
  for (const { scope, file } of settingsCandidates()) {
    if (!fs.existsSync(file)) continue;
    let settings;
    try {
      settings = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      // Claude Code cannot read hooks out of malformed JSON either, so an
      // unparseable settings file is enforcement silently off.
      errors.push(`${scope} settings file is not valid JSON: ${file} (${err.message})`);
      continue;
    }
    all.push(...registrationsIn(settings, scope, file));
  }

  // One deployed file can be registered under several matchers; verify each
  // distinct file once but remember every place it was registered from.
  const byPath = new Map();
  for (const reg of all) {
    const key = canonical(reg.hookPath);
    const existing = byPath.get(key);
    if (existing) existing.registrations.push(reg);
    else byPath.set(key, { hookPath: reg.hookPath, registrations: [reg] });
  }
  return [...byPath.values()];
}

// ── comparison ──────────────────────────────────────────────────────────────

const sha256 = (file) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');

/**
 * Extract `{ re: /pattern/flags, why: '...' }` entries from one named table.
 * Same raw-text technique as tests/catastrophic-parity.test.ts: compare the
 * literal source+flags strings, never engine-normalized RegExp objects.
 */
function extractPatterns(text, marker) {
  const start = text.indexOf(marker);
  let region = text;
  if (start !== -1) {
    const tail = text.slice(start);
    const close = tail.search(/\n\s*\];/);
    region = close !== -1 ? tail.slice(0, close) : tail;
  } else {
    return null; // the table is absent entirely — a finding in its own right
  }

  const out = [];
  for (const line of region.split('\n')) {
    const reIdx = line.indexOf('re:');
    if (reIdx === -1) continue;
    const whyIdx = line.indexOf(', why:', reIdx);
    if (whyIdx === -1) continue;
    const open = line.indexOf('/', reIdx);
    if (open === -1 || open >= whyIdx) continue;
    const close = line.lastIndexOf('/', whyIdx - 1);
    if (close <= open) continue;
    const source = line.slice(open + 1, close);
    if (!source) continue;
    out.push(`${source}|${line.slice(close + 1, whyIdx).trim()}`);
  }
  return out;
}

/**
 * Top-level security helpers and pattern tables declared in the source hook.
 * Derived from the source rather than hardcoded, so a helper added later is
 * automatically required of the deployed copy. A hook that predates a hardening
 * change is missing whole functions: the live-secret check, symlink resolution,
 * the self-protection floor. Naming them is what makes a hash mismatch
 * actionable.
 */
function declarations(text) {
  const names = new Set();
  for (const m of text.matchAll(/^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/gm)) {
    names.add(m[1]);
  }
  // Uppercase consts only: the pattern/allowlist tables, not the require()s.
  for (const m of text.matchAll(/^const\s+([A-Z][A-Z0-9_]*)\s*=/gm)) names.add(m[1]);
  return names;
}

/** Render a "source|flags" key back as a regex literal. The pattern itself can
 *  contain `|` (alternations), so split on the LAST one, which is the separator. */
function asLiteral(key) {
  const cut = key.lastIndexOf('|');
  return `/${key.slice(0, cut)}/${key.slice(cut + 1)}`;
}

function setDiff(sourceList, deployedList, label, out) {
  if (deployedList === null) {
    out.push(`${label}: table is ENTIRELY ABSENT from the deployed copy`);
    return;
  }
  const src = new Set(sourceList);
  const dep = new Set(deployedList);
  const missing = [...src].filter((p) => !dep.has(p));
  const extra = [...dep].filter((p) => !src.has(p));
  if (!missing.length && !extra.length) {
    out.push(`${label}: ${sourceList.length} patterns, identical`);
    return;
  }
  out.push(
    `${label}: source has ${sourceList.length}, deployed has ${deployedList.length} — ` +
      `${missing.length} missing, ${extra.length} unknown`,
  );
  for (const p of missing.slice(0, 6)) out.push(`    missing from deployed: ${asLiteral(p)}`);
  if (missing.length > 6) out.push(`    ... and ${missing.length - 6} more missing`);
  for (const p of extra.slice(0, 3)) out.push(`    only in deployed:       ${asLiteral(p)}`);
  if (extra.length > 3) out.push(`    ... and ${extra.length - 3} more unknown`);
}

/** Explain a hash mismatch in security terms. */
function diagnose(sourceText, deployedFile) {
  const out = [];
  let deployedText;
  try {
    deployedText = fs.readFileSync(deployedFile, 'utf8');
  } catch (err) {
    return [`could not read the deployed file to diagnose: ${err.message}`];
  }

  const srcLines = sourceText.split('\n').length;
  const depLines = deployedText.split('\n').length;
  const depStat = fs.statSync(deployedFile);
  const srcStat = fs.statSync(SOURCE_HOOK);
  out.push(
    `size: source ${srcLines} lines / ${srcStat.size} B (${srcStat.mtime.toISOString().slice(0, 10)}) ` +
      `vs deployed ${depLines} lines / ${depStat.size} B (${depStat.mtime.toISOString().slice(0, 10)})`,
  );

  setDiff(
    extractPatterns(sourceText, 'CATASTROPHIC'),
    extractPatterns(deployedText, 'CATASTROPHIC'),
    'CATASTROPHIC floor',
    out,
  );
  setDiff(
    extractPatterns(sourceText, 'LIVE_SECRET'),
    extractPatterns(deployedText, 'LIVE_SECRET'),
    'LIVE_SECRET floor',
    out,
  );

  const srcDecls = declarations(sourceText);
  const depDecls = declarations(deployedText);
  const missingDecls = [...srcDecls].filter((n) => !depDecls.has(n));
  if (missingDecls.length) {
    out.push(
      `security helpers missing from the deployed copy (${missingDecls.length}): ` +
        missingDecls.join(', '),
    );
  } else {
    out.push('security helpers: all present (the difference is inside a function body)');
  }
  return out;
}

// ── deployed rules snapshot ─────────────────────────────────────────────────

let builtinRules; // null once we have decided we cannot build them

/**
 * Build the built-in enforcement rules from the current source, via the repo's
 * own tsx. Returns null (and records a skip note) if that is not possible —
 * a snapshot check that cannot run reliably must not fail the gate.
 */
function loadBuiltinRules() {
  if (builtinRules !== undefined) return builtinRules;
  try {
    const stdout = execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '-e',
        "import('./server/enforcementSnapshot.ts')" +
          '.then(m => process.stdout.write(JSON.stringify(m.buildEnforcementSnapshot())))',
      ],
      { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 },
    );
    builtinRules = JSON.parse(stdout);
    if (!Array.isArray(builtinRules) || !builtinRules.length) {
      throw new Error('the builder returned no rules');
    }
  } catch (err) {
    notes.push(
      `rules snapshot check SKIPPED — could not build the built-in rules from source ` +
        `(${String(err.message).split('\n')[0]}). The hook comparison above is unaffected.`,
    );
    builtinRules = null;
  }
  return builtinRules;
}

/** Resolve the snapshot exactly the way resolveSnapshotPath() in the hook does. */
function snapshotPathFor(deployedHook) {
  if (process.env.CLAUDESEC_ENFORCE_RULES) return path.resolve(process.env.CLAUDESEC_ENFORCE_RULES);
  const dir = path.dirname(deployedHook);
  const beside = path.join(dir, 'rules-enforcement.json');
  if (fs.existsSync(beside)) return beside;
  return path.resolve(dir, '..', '..', 'rules-enforcement.json');
}

/**
 * The deployed snapshot must CONTAIN every built-in rule; it may hold more.
 * The running server rewrites this file with the built-ins plus any user-added
 * custom rules, so an exact match would fail the moment a custom rule exists —
 * a subset check is the strongest assertion that is not flaky. Rules are keyed
 * on pattern + flags + action: the pattern that matches and what it does.
 */
function checkSnapshot(deployedHook, label) {
  const builtins = loadBuiltinRules();
  if (!builtins) return;

  const snapshot = snapshotPathFor(deployedHook);
  if (!fs.existsSync(snapshot)) {
    errors.push(
      `${label}: the hook is registered but its rules snapshot is missing.\n` +
        `      expected at: ${snapshot}\n` +
        `      The hook fails open on an unreadable snapshot, so rule-based blocking is OFF.\n` +
        `      Fix: ${FIX_COMMAND}`,
    );
    return;
  }

  let deployed;
  try {
    deployed = JSON.parse(fs.readFileSync(snapshot, 'utf8'));
    if (!Array.isArray(deployed)) throw new Error('not a JSON array');
  } catch (err) {
    errors.push(
      `${label}: the deployed rules snapshot is unreadable (${err.message}): ${snapshot}\n` +
        `      Rule-based blocking is silently OFF. Fix: ${FIX_COMMAND}`,
    );
    return;
  }

  const key = (r) => `${r.source}|${r.flags}|${r.action}`;
  const have = new Set(deployed.map(key));
  const missing = builtins.filter((r) => !have.has(key(r)));
  const extra = deployed.length - (builtins.length - missing.length);

  if (missing.length) {
    const sample = missing
      .slice(0, 5)
      .map((r) => `        [${r.action}/${r.severity}] ${r.label}: /${r.source}/${r.flags}`);
    errors.push(
      `${label}: the deployed rules snapshot is STALE — ${missing.length} of ` +
        `${builtins.length} built-in rules are not in it.\n` +
        `      snapshot: ${snapshot}\n` +
        sample.join('\n') +
        (missing.length > 5 ? `\n        ... and ${missing.length - 5} more` : '') +
        `\n      Fix: ${FIX_COMMAND}`,
    );
    return;
  }
  notes.push(
    `snapshot OK (${builtins.length} built-in rules present` +
      `${extra > 0 ? `, +${extra} custom` : ''}): ${snapshot}`,
  );
}

// ── run ─────────────────────────────────────────────────────────────────────

if (!fs.existsSync(SOURCE_HOOK)) {
  console.error(`✖ deployed-hook check failed:\n  - source hook not found at ${SOURCE_HOOK}`);
  process.exit(1);
}
const sourceText = fs.readFileSync(SOURCE_HOOK, 'utf8');
const sourceHash = sha256(SOURCE_HOOK);

const deployments = discoverRegistrations();

if (!deployments.length && !errors.length) {
  console.log('✓ deployed-hook check passed: no ClaudeSec PreToolUse hook is registered.');
  console.log('  Nothing is deployed, so nothing can have drifted (clean clone / CI / Docker).');
  console.log(`  Source hook sha256: ${sourceHash.slice(0, 16)}…`);

  // A hook sitting on disk but wired to nothing is not a live security gap, so
  // it is not a failure. It is still worth a note: re-registering that copy
  // would deploy stale logic.
  const orphan = path.join(
    process.env.CLAUDESEC_HOME || path.join(os.homedir(), '.claudesec'),
    'hooks',
    HOOK_FILENAME,
  );
  if (fs.existsSync(orphan) && sha256(orphan) !== sourceHash) {
    console.log(
      `\n  note: an UNREGISTERED copy at ${orphan} differs from source.\n` +
        `        It is not running, but re-registering it would deploy stale logic.\n` +
        `        Refresh it with: ${FIX_COMMAND}`,
    );
  }
  process.exit(0);
}

for (const { hookPath, registrations } of deployments) {
  const where = registrations
    .map((r) => `${r.scope}:${path.basename(r.file)} [${r.matcher}]`)
    .join(', ');
  const label = `${hookPath}\n      registered by: ${where}`;

  if (!fs.existsSync(hookPath)) {
    errors.push(
      `${label}\n` +
        `      REGISTERED BUT MISSING — the file does not exist. Claude Code fails open on a\n` +
        `      missing hook command, so enforcement is silently disabled entirely.\n` +
        `      Fix: ${FIX_COMMAND}`,
    );
    continue;
  }

  if (sha256(hookPath) === sourceHash) {
    notes.push(`hook OK (sha256 ${sourceHash.slice(0, 16)}…): ${hookPath}\n      via ${where}`);
    checkSnapshot(hookPath, hookPath);
    continue;
  }

  errors.push(
    `${label}\n` +
      `      DRIFTED from cli/hooks/${HOOK_FILENAME}\n` +
      `        source   sha256: ${sourceHash}\n` +
      `        deployed sha256: ${sha256(hookPath)}\n` +
      diagnose(sourceText, hookPath)
        .map((l) => `      ${l}`)
        .join('\n') +
      `\n      Fix: ${FIX_COMMAND}`,
  );
}

if (errors.length) {
  console.error('✖ deployed-hook check failed — the enforcement artifact Claude Code runs');
  console.error('  is not the one this repo ships:\n');
  for (const e of errors) console.error(`  - ${e}\n`);
  // A machine can have several deployments; show the healthy ones too, so a
  // mixed result is not read as "everything is broken".
  for (const n of notes) console.error(`  ${n}`);
  if (notes.length) console.error('');
  console.error(
    `  Every source-parity gate can pass while this fails: they compare tracked files\n` +
      `  to each other and never look at what is deployed. Re-run after fixing.`,
  );
  process.exit(1);
}

console.log(
  `✓ deployed-hook check passed: ${deployments.length} registered enforcement ` +
    `hook(s) match cli/hooks/${HOOK_FILENAME}.`,
);
for (const n of notes) console.log(`  ${n}`);
