#!/usr/bin/env node
// Ultra-fast local secret & privacy scanner.
//
// Fails the build if it finds a real credential or anything that would leak the
// maintainer's private setup into the public repo (home paths, personal emails,
// private tooling dirs).
//
// WHAT IT SCANS — the set of bytes that could reach the public repo next, which
// is deliberately wider than "files that are already tracked":
//   1. Tracked files          (`git ls-files`)              — read from the worktree.
//   2. Untracked, NOT ignored (`git ls-files --others --exclude-standard`)
//      — a plain `git add -A` publishes these, so a leak sitting in a brand-new
//      file is caught BEFORE it is ever staged. Scanning only tracked files was
//      the original gap: `pnpm scan` reported clean while a new file holding
//      private data sat one `git add -A` away from publication.
//   3. Staged content that differs from the worktree — a commit writes the INDEX,
//      not your working copy, so where the two disagree the index blob is scanned
//      too (reported as `path (staged)`). This also covers a file staged for
//      addition and then deleted from disk, which has no worktree bytes at all.
// Ignored files are excluded, which is what `--exclude-standard` buys us: it is
// the difference between 64 files and 40,029, and it keeps node_modules/, dist/
// and the maintainer's private directories out of the scan — both correct and fast.
//
// Two design rules keep the false-positive rate near zero in THIS repo:
//   1. ClaudeSec's own detection rules are secret-SHAPED regexes by design, so
//      the rule/scrub/test sources (PATTERN_FILES) are exempted; a regex like
//      `AKIA[0-9A-Z]{16}` is not a leaked key. NOTE: that exemption is currently
//      a blanket one — privacy checks do not run on those paths either, so a real
//      home path or personal email inside tests/ would NOT be caught. Narrowing it
//      to secret checks alone requires widening the placeholder allowlists below
//      for ~10 existing synthetic fixtures first.
//   2. Privacy checks allow generic placeholders (/home/user, you@example.com)
//      so documentation can show example paths and addresses.
//
// LIMIT: these are pattern checks. A bare personal project or client NAME matches
// none of them — use the git-ignored `scripts/.scan-local.json` blocklist below to
// pin machine- or person-specific literals that no regex can infer.
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
  // The live-secret enforcement floor and its shipped hook twin carry a
  // credential pattern for every provider they block, plus the placeholder
  // spellings they must deliberately let through. Both are secret-shaped by
  // definition, exactly like the rule sources above.
  'server/enforceEval.ts',
  'cli/hooks/claudesec-enforce.cjs',
  'scripts/scan-secrets.mjs',
  'tests/',
  'docs/security/rules',
];
const isPatternFile = (p) => PATTERN_FILES.some((f) => p === f || p.startsWith(f));

// -z everywhere: git otherwise C-quotes any path with a space or non-ASCII byte
// ("src/\303\251.ts"), which would then fail to resolve on disk and be skipped.
function gitPaths(args) {
  const out = execFileSync('git', [...args, '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 });
  return out.split('\0').filter(Boolean);
}

/** Everything a `git add -A && git commit` could publish next, worktree copies. */
function publishableFiles() {
  const tracked = gitPaths(['ls-files']);
  const untracked = gitPaths(['ls-files', '--others', '--exclude-standard']);
  return { tracked, untracked, all: [...new Set([...tracked, ...untracked])] };
}

/**
 * Paths whose staged bytes differ from the worktree bytes. A commit writes the
 * index, so for these the worktree copy is the wrong thing to scan — the index
 * blob is read separately. Normally empty, so this costs one extra git call.
 */
function stagedDivergentFiles() {
  const staged = new Set(gitPaths(['diff', '--cached', '--name-only']));
  if (!staged.size) return [];
  const dirty = gitPaths(['diff', '--name-only']); // worktree vs index
  return dirty.filter((p) => staged.has(p));
}

/** The staged blob for a path, or null if it isn't in the index. */
function stagedBlob(path) {
  try {
    return execFileSync('git', ['show', `:${path}`], { cwd: root, maxBuffer: 1 << 28 });
  } catch {
    return null; // staged deletion — nothing to publish, nothing to scan
  }
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

// `file` is what a finding reports (may carry a "(staged)" suffix); `path` is the
// real repo path the exemption list is matched against.
function scanLine(file, lineNo, line, path = file) {
  // The detection/scrub/test sources hold secret-shaped patterns and synthetic
  // home paths / emails on purpose — exempt them from every check.
  if (isPatternFile(path)) return;

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

/** Run every line check over one file's bytes. `label` is what a finding reports. */
function scanBuffer(path, label, buf) {
  if (buf.length > 1_500_000) return false; // nothing private lives in huge files
  if (buf.includes(0)) return false;        // a NUL byte means binary — skip
  const lines = buf.toString('utf8').split('\n');
  for (let i = 0; i < lines.length; i++) scanLine(label, i + 1, lines[i], path);
  return true;
}

const skipByName = (file) =>
  SKIP_EXT.has(extname(file).toLowerCase()) || SKIP_FILE.has(file.split('/').pop());

const { tracked, untracked, all } = publishableFiles();

// A database file is never source. It holds recorded agent activity, which is the
// one thing that must never leave the machine, and it is large enough that nobody
// reviews the diff. CI already refuses a tracked one; checking here too means the
// local gate and the remote gate agree, so a mistake is caught before the push
// rather than after it. Extension match only: the content check below skips
// binaries, so a database would otherwise pass silently.
const DATA_FILE = /\.(?:db|sqlite|sqlite3)(?:-shm|-wal|-journal)?$/i;
for (const file of all) {
  if (DATA_FILE.test(file)) {
    findings.push({ file, lineNo: 0, kind: 'database file staged for publication' });
  }
}

let scanned = 0;
for (const file of all) {
  if (skipByName(file)) continue;
  const abs = join(root, file);
  let buf;
  try {
    if (statSync(abs).size > 1_500_000) continue;
    buf = readFileSync(abs);
  } catch { continue; } // e.g. staged-then-deleted; the index blob is scanned below
  if (scanBuffer(file, file, buf)) scanned++;
}

// Staged bytes win over worktree bytes wherever the two disagree.
let stagedScanned = 0;
for (const file of stagedDivergentFiles()) {
  if (skipByName(file)) continue;
  const buf = stagedBlob(file);
  if (buf && scanBuffer(file, `${file} (staged)`, buf)) stagedScanned++;
}

// --- report -----------------------------------------------------------------

// Spell out the scope so a passing run cannot be mistaken for a narrower guarantee.
const scope = `${scanned} files (${tracked.length} tracked, ${untracked.length} untracked & not ignored)`
  + (stagedScanned ? `, ${stagedScanned} staged blob(s)` : '');

if (findings.length) {
  console.error(`✖ secret/privacy scan failed — ${findings.length} finding(s) across ${scope}:`);
  for (const f of findings) console.error(`  - ${f.file}:${f.lineNo}  ${f.kind}`);
  console.error('\nRemove the leak (or, for a false positive, narrow the value / add a placeholder).');
  process.exit(1);
}
console.log(`✓ secret/privacy scan passed — ${scope}, no leaks.`);
