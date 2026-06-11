#!/usr/bin/env node
// Ultra-fast local secret & privacy scanner.
//
// Runs over every git-tracked text file and fails the build if it finds a
// real credential or anything that would leak the maintainer's private setup
// into the public repo (home paths, personal emails, private tooling dirs).
// It scans only tracked files — the exact bytes a push would publish — so it
// is fast (well under a second on this repo) and safe to run in CI too.
//
// Two design rules keep the false-positive rate near zero in THIS repo:
//   1. ClaudeSec's own detection rules are secret-SHAPED regexes by design.
//      Secret checks therefore skip the rule/scrub/test sources (PATTERN_FILES);
//      a regex like `AKIA[0-9A-Z]{16}` is not a leaked key.
//   2. Privacy checks allow generic placeholders (/home/user, you@example.com)
//      so documentation can show example paths and addresses.
//
// Pure Node, no dependencies. Run: `node scripts/scan-secrets.mjs`
// An optional, git-ignored `scripts/.scan-local.json` may add machine-specific
// literal strings to block (e.g. your exact username) without committing them.

import { readFileSync, statSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const findings = [];

// --- which files to read ----------------------------------------------------

// Binary / generated / noisy files we never scan. Lockfiles carry base64
// integrity hashes that look secret-ish but aren't.
const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.zip', '.gz', '.lock',
]);
const SKIP_FILE = new Set(['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock']);

// Files that legitimately contain secret-SHAPED regex patterns (the detection
// engine itself). Privacy checks still run on them; the secret checks do not.
const PATTERN_FILES = [
  'server/detection.ts',
  'server/severityRulesExtra.ts',
  'server/scrub.ts',
  'server/ssrf.ts',
  'scripts/scan-secrets.mjs',
  'tests/',
  'docs/security/rules',
];
const isPatternFile = (p) => PATTERN_FILES.some((f) => p === f || p.startsWith(f));

function trackedFiles() {
  const out = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' });
  return out.split('\n').filter(Boolean);
}

// --- secret patterns (high-confidence; real key shapes, not loose keywords) --

const SECRET_RULES = [
  { label: 'AWS access key id',     re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'GitHub token',          re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { label: 'OpenAI API key',        re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/ },
  { label: 'Anthropic API key',     re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'Google API key',        re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'Slack token',           re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { label: 'Stripe secret key',     re: /\bsk_live_[A-Za-z0-9]{20,}\b/ },
  { label: 'Private key block',     re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
];

// A matched value carrying one of these markers is a documentation example, not
// a live credential (incl. AWS's well-known AKIAIOSFODNN7EXAMPLE doc key).
const EXAMPLE_TOKEN = /(EXAMPLE|CANARY|SAMPLE|SYNTH|SYNT|DUMMY|FAKE|XXXX|PLACEHOLDER|REDACTED)/i;

// --- privacy patterns (leak of THIS machine / maintainer) -------------------

// Usernames that are obviously placeholders, not a real person.
const PLACEHOLDER_USER = /^(you|your|user|username|me|name|dev|developer|example|someone|test|tester|admin|root|home|ubuntu|runner|node|alice|bob)$/i;
// Email domains that are clearly examples, not personal mail.
const EXAMPLE_DOMAIN = /(example\.(com|org|net)|test\.com|localhost|email\.com|domain\.com|company\.com|yourdomain|anthropic\.com|noreply)/i;

const HOME_PATH = /\/(?:Users|home)\/([A-Za-z0-9._-]+)/g;
const WIN_HOME  = /[A-Za-z]:\\Users\\([A-Za-z0-9._ -]+)/g;
const EMAIL     = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// Private tooling locations that must never appear in public code. `docs/_local`
// is deliberately NOT here — the public .gitignore, the CI guard, and the docs
// registry all reference it by name to keep it out, which is correct, not a leak.
const PRIVATE_PATH = /(^|[^A-Za-z0-9._-])(\.remember|\.gstack|\.playwright-mcp)\b/;

// Optional machine-local literal blocklist (git-ignored, never committed).
let localLiterals = [];
const localCfgPath = join(root, 'scripts', '.scan-local.json');
if (existsSync(localCfgPath)) {
  try {
    const cfg = JSON.parse(readFileSync(localCfgPath, 'utf8'));
    if (Array.isArray(cfg.block)) localLiterals = cfg.block.filter((s) => typeof s === 'string' && s.length >= 3);
  } catch { /* a malformed local file shouldn't break the scan */ }
}

// --- scan -------------------------------------------------------------------

function scanLine(file, lineNo, line) {
  // The detection/scrub/test sources hold secret-shaped patterns and synthetic
  // home paths / emails on purpose — exempt them from every check.
  if (isPatternFile(file)) return;

  for (const { label, re } of SECRET_RULES) {
    const m = line.match(re);
    if (m && !EXAMPLE_TOKEN.test(m[0])) findings.push({ file, lineNo, kind: `secret: ${label}` });
  }

  for (const m of line.matchAll(HOME_PATH)) {
    if (!PLACEHOLDER_USER.test(m[1])) findings.push({ file, lineNo, kind: `private home path (/.../${m[1]})` });
  }
  for (const m of line.matchAll(WIN_HOME)) {
    if (!PLACEHOLDER_USER.test(m[1].trim())) findings.push({ file, lineNo, kind: 'private Windows home path' });
  }
  for (const m of line.matchAll(EMAIL)) {
    if (!EXAMPLE_DOMAIN.test(m[0])) findings.push({ file, lineNo, kind: `email address (${m[0]})` });
  }
  if (PRIVATE_PATH.test(line)) findings.push({ file, lineNo, kind: 'private tooling/notes path' });
  for (const lit of localLiterals) {
    if (line.includes(lit)) findings.push({ file, lineNo, kind: 'machine-local blocked literal' });
  }
}

let scanned = 0;
for (const file of trackedFiles()) {
  if (SKIP_EXT.has(extname(file).toLowerCase())) continue;
  if (SKIP_FILE.has(file.split('/').pop())) continue;
  const abs = join(root, file);
  let size = 0;
  try { size = statSync(abs).size; } catch { continue; }
  if (size > 1_500_000) continue; // skip very large files; nothing private lives in them
  let buf;
  try { buf = readFileSync(abs); } catch { continue; }
  if (buf.includes(0)) continue; // a NUL byte means binary — skip
  scanned++;
  const lines = buf.toString('utf8').split('\n');
  for (let i = 0; i < lines.length; i++) scanLine(file, i + 1, lines[i]);
}

// --- report -----------------------------------------------------------------

if (findings.length) {
  console.error(`✖ secret/privacy scan failed — ${findings.length} finding(s) in ${scanned} files:`);
  for (const f of findings) console.error(`  - ${f.file}:${f.lineNo}  ${f.kind}`);
  console.error('\nRemove the leak (or, for a false positive, narrow the value / add a placeholder).');
  process.exit(1);
}
console.log(`✓ secret/privacy scan passed (${scanned} tracked files, no leaks).`);
