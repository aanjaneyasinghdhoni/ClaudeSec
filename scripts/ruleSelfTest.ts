/**
 * scripts/ruleSelfTest.ts
 *
 * Quality-gate for EXTRA_SEVERITY_RULES (from severityRulesExtra.ts).
 * Run via:  npx tsx scripts/ruleSelfTest.ts
 *
 * Exit 0  → all rules pass (or no extra rules to check).
 * Exit 1  → one or more rules fail at least one check.
 *
 * Checks performed per rule:
 *   (a) VALID      — pattern is a RegExp, severity ∈ {low|medium|high}, label non-empty.
 *   (b) REDOS      — heuristic detection of catastrophic-backtracking shapes.
 *   (c) DUPLICATE  — same normalised .source as another EXTRA rule or a built-in rule.
 *   (d) FP         — matches one or more strings in the benign corpus.
 *
 * Never imports server.ts; reads it only as raw text to extract existing patterns.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EXTRA_SEVERITY_RULES } from '../severityRulesExtra.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_TS_PATH = path.join(REPO_ROOT, 'server.ts');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = 'low' | 'medium' | 'high';

interface Rule {
  pattern: RegExp;
  severity: Severity;
  label: string;
}

interface Failure {
  ruleIndex: number;
  label: string;
  reasons: FailureReason[];
}

type FailureReason =
  | { kind: 'invalid'; detail: string }
  | { kind: 'redos'; detail: string }
  | { kind: 'duplicate'; detail: string }
  | { kind: 'false-positive'; offendingString: string };

// ---------------------------------------------------------------------------
// (b) ReDoS heuristic
// ---------------------------------------------------------------------------
// Detects common catastrophic-backtracking shapes in a regex source string.
// Conservative: may flag some benign patterns, but that is acceptable for a
// quality gate — authors can tighten the pattern and re-submit.

/** Returns a human-readable description of the ReDoS risk, or null if clean. */
export function detectReDoS(source: string): string | null {
  // Patterns that represent known catastrophic forms:
  const catastrophicPatterns: Array<{ re: RegExp; desc: string }> = [
    // (x+)+  or  (x*)* — repeated quantifier over a group with a quantifier
    { re: /\([^)]*[+*][^)]*\)[+*]/,               desc: 'nested quantifier: (…+)+ or (…*)* shape' },
    // (x*)+  or  (x+)*
    { re: /\([^)]*\*[^)]*\)[+]/,                  desc: 'nested quantifier: (…*)+ shape' },
    { re: /\([^)]*\+[^)]*\)[*]/,                  desc: 'nested quantifier: (…+)* shape' },
    // (.*)+  or  (.+)*  — dot under outer quantifier
    { re: /\(\.\*\)[+*]|\(\.\+\)[+*]/,            desc: 'nested quantifier: (.*)+  or  (.+)* shape' },
    // (a|a)*  — alternation with overlapping branches under a quantifier
    { re: /\(([^|)]+)\|(\1)\)[+*?]/,              desc: 'overlapping alternation branches under quantifier' },
    // (a|ab)*  — prefix ambiguity under quantifier (simplified: same char leading both branches)
    { re: /\(([A-Za-z0-9\\])\|(\1[^)]+)\)[+*]/,  desc: 'prefix-ambiguous alternation under quantifier' },
    // Alternation with .*  inside a quantified group: (.*|.+)+
    { re: /\(\.\*\|[^)]*\)[+*]|\([^)]*\|\.\*\)[+*]/, desc: 'alternation with .* inside quantified group' },
    // {n,}  with large upper bound combined with + or * — exponential compound
    { re: /\{[0-9]+,\s*\}[+*]/,                   desc: 'unbounded quantifier on an already-quantified group' },
  ];

  for (const { re, desc } of catastrophicPatterns) {
    if (re.test(source)) {
      return desc;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Extract existing patterns from server.ts (text-only — never executed)
// ---------------------------------------------------------------------------

/**
 * Reads server.ts as raw text and extracts the .source strings of every
 * inline { pattern: /…/ } literal so we can dedup EXTRA rules against them.
 *
 * The heuristic regex handles:
 *   /literal/flags
 *   /with escaped \/ slashes/flags
 * It is not a full JS parser — edge cases such as character classes containing
 * "/" are handled by allowing `\/` or `[^/]` style content.  Good enough for
 * the structured, machine-readable rule block in server.ts.
 */
export function extractServerPatternSources(): Set<string> {
  const sources = new Set<string>();
  let text: string;
  try {
    text = fs.readFileSync(SERVER_TS_PATH, 'utf8');
  } catch (err) {
    console.warn(`[ruleSelfTest] Warning: could not read server.ts — skipping dedup vs built-ins. (${err})`);
    return sources;
  }

  // Match: pattern: /...regex body.../flags
  // The regex body may contain escaped slashes (\/), bracket expressions
  // ([abc/]), or plain chars — we approximate by matching up to the first
  // unescaped "/" that is not inside [ ].
  //
  // Strategy: find "pattern:" followed by "/" and capture until the closing
  // unescaped "/", allowing for \/ and character-class content.
  //
  // We iterate via matchAll on a global regex.
  const ruleEntryRe = /pattern\s*:\s*\/((?:[^/\\[]|\\.|\[(?:[^\]\\]|\\.)*\])*)\//g;
  for (const match of text.matchAll(ruleEntryRe)) {
    const src = match[1];
    if (src) {
      sources.add(normaliseSource(src));
    }
  }
  return sources;
}

/** Normalise a regex source string for dedup comparison. */
export function normaliseSource(source: string): string {
  // Lower-case and strip flags from consideration (flags live on the RegExp
  // object, not in source); collapse whitespace runs.
  return source.toLowerCase().replace(/\s+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// (d) Benign corpus
// ---------------------------------------------------------------------------
// ~100 realistic, harmless strings that should NOT trigger any well-written
// threat rule.  Covers:
//   • Normal shell commands and flags
//   • Source-code snippets that merely *mention* dangerous keywords in comments
//     or in safe contexts (e.g. "avoid eval()" in a code comment)
//   • Benign rm usages (rm -rf node_modules is routine CI cleanup)
//   • Normal file paths, git/SSH operations, dev-tool commands
//   • Benign reduce/map/filter code that uses arrow functions

const BENIGN: string[] = [
  // ── Routine shell commands ──────────────────────────────────────────────
  'git status',
  'git diff HEAD~1',
  'git add -p',
  'git commit -m "chore: bump version"',
  'git log --oneline -10',
  'git checkout main',
  'git pull --rebase origin main',
  'git stash pop',
  'git merge --no-ff feature/my-branch',
  'git fetch --all --prune',
  'npm install',
  'npm install --save-dev eslint',
  'npm run build',
  'npm run dev',
  'npm run lint',
  'npm test',
  'npm ci',
  'npm audit fix',
  'cd src && npm run build',
  'ls -la',
  'ls -lh /var/log',
  'pwd',
  'mkdir -p dist/assets',
  'cp -r src/assets dist/assets',
  'mv old-name.ts new-name.ts',
  'cat package.json',
  'cat README.md',
  'cat tsconfig.json',
  'less /var/log/syslog',
  'touch .gitignore',
  'rm -rf node_modules',
  'rm -rf dist',
  'rm -rf .next',
  'rm -rf .turbo',
  'rm -f tmp.log',
  'docker compose up',
  'docker compose down',
  'docker compose build',
  'docker ps',
  'docker images',
  'make test',
  'make build',
  'python3 -m pytest tests/',
  'python3 -m venv .venv',
  'source .venv/bin/activate',
  'pip install -r requirements.txt',
  'pip install black flake8',
  'pip install pytest',
  'cargo build --release',
  'cargo test',
  'go build ./...',
  'go test ./...',
  'npx tsc --noEmit',
  'npx eslint src/ --fix',
  'npx prettier --write .',

  // ── SSH / git remote operations (benign) ───────────────────────────────
  'ssh-keygen -t ed25519 -C "me@example.com"',
  'ssh-add ~/.ssh/id_ed25519',
  'git remote add origin git@github.com:org/repo.git',
  'git push origin main',
  'scp -r ./dist user@deploy.example.com:/var/www/',
  'rsync -az ./dist/ user@server.example.com:/var/www/html/',

  // ── Source-code snippets that MENTION dangerous words in safe contexts ──
  '// avoid eval() for performance and security reasons',
  '// never use exec() with untrusted input',
  '// design note: system architecture overview',
  '// system design notes for the caching layer',
  '# system requirements document',
  '# this script does NOT use rm -rf /',
  'const result = array.reduce((acc, b) => acc + b, 0)',
  'arr.map(x => x * 2).filter(x => x > 5)',
  'const fn = (a, b) => a + b',
  'console.log("process.env.NODE_ENV:", process.env.NODE_ENV)',
  'const port = parseInt(process.env.PORT ?? "3000", 10)',
  '// Note: process.env variables must be set before running tests',
  'fs.readFileSync(".env.example", "utf8")',
  'loadDotenv({ path: ".env.example" })',
  '# .env.example — copy to .env and fill in values',
  'const schema = z.object({ DATABASE_URL: z.string() })',
  '// TODO: add password validation before storing',
  'label: "Enter your password:"',
  'placeholder="Password"',
  '// base64 encode for URL safety, not encryption',
  'const encoded = btoa(JSON.stringify(payload))',
  '// run: chmod +x scripts/deploy.sh',
  'chmod 755 scripts/deploy.sh',
  'chmod 644 README.md',

  // ── Normal file paths ───────────────────────────────────────────────────
  '/usr/local/bin/node',
  '/home/user/projects/myapp',
  '/tmp/build-cache',
  'C:\\Users\\user\\Documents\\project',
  './src/components/Button.tsx',
  '../shared/utils/format.ts',
  '~/.config/nvim/init.vim',
  '~/.zshrc',

  // ── Benign Docker / infra ───────────────────────────────────────────────
  'docker run --rm -it node:20 bash',
  'docker run -p 3000:3000 myapp:latest',
  'docker pull node:20-alpine',
  'docker build -t myapp:dev .',

  // ── Normal package-manager installs ────────────────────────────────────
  'npm install express react react-dom',
  'brew install jq',
  'brew install node',
  'gem install bundler',
  'apt-get update && apt-get install -y curl',

  // ── Test / CI pipeline commands ─────────────────────────────────────────
  'npx jest --coverage',
  'npx vitest run',
  'npx playwright test',
  'npx cypress run',
  'npx tsx scripts/seed.ts',

  // ── Miscellaneous safe strings ───────────────────────────────────────────
  'Hello, world!',
  'The quick brown fox jumps over the lazy dog.',
  'SELECT * FROM users WHERE id = ?',
  'SELECT name, email FROM customers LIMIT 100',
  'UPDATE users SET last_login = NOW() WHERE id = $1',
  'INSERT INTO events (type, payload) VALUES ($1, $2)',
  'openssl genrsa -out server.key 2048',
  'openssl req -new -x509 -key server.key -out server.crt -days 365',
  'gpg --import my-public-key.asc',
  'tar -czf backup.tar.gz ./data',
  'tar -xzf archive.tar.gz',
  'zip -r release.zip dist/',
  'git reset --hard HEAD~1',
  'kill -9 12345',
  'pkill -f "node server"',
];

// ---------------------------------------------------------------------------
// Check runner
// ---------------------------------------------------------------------------

function checkRule(
  rule: unknown,
  ruleIndex: number,
  extraSources: Map<number, string>,
  builtinSources: Set<string>,
): Failure | null {
  const reasons: FailureReason[] = [];

  // ── (a) Structural validity ────────────────────────────────────────────
  if (
    rule === null ||
    typeof rule !== 'object' ||
    !(rule instanceof Object)
  ) {
    return {
      ruleIndex,
      label: `(rule #${ruleIndex} — not an object)`,
      reasons: [{ kind: 'invalid', detail: 'rule is not an object' }],
    };
  }

  const r = rule as Record<string, unknown>;
  const label =
    typeof r.label === 'string' && r.label.trim().length > 0
      ? r.label.trim()
      : `(rule #${ruleIndex} — missing label)`;

  if (!(r.pattern instanceof RegExp)) {
    reasons.push({ kind: 'invalid', detail: 'pattern is not a RegExp' });
  }
  if (!['low', 'medium', 'high'].includes(r.severity as string)) {
    reasons.push({
      kind: 'invalid',
      detail: `severity "${r.severity}" is not one of: low, medium, high`,
    });
  }
  if (typeof r.label !== 'string' || r.label.trim().length === 0) {
    reasons.push({ kind: 'invalid', detail: 'label is missing or empty' });
  }

  // If the pattern itself is broken, skip further checks that depend on it
  if (!(r.pattern instanceof RegExp)) {
    return reasons.length > 0 ? { ruleIndex, label, reasons } : null;
  }

  const re = r.pattern as RegExp;
  const src = re.source;

  // ── (b) ReDoS heuristic ────────────────────────────────────────────────
  const redosDesc = detectReDoS(src);
  if (redosDesc !== null) {
    reasons.push({ kind: 'redos', detail: redosDesc });
  }

  // ── (c) Deduplication ─────────────────────────────────────────────────
  const normSrc = normaliseSource(src);

  // Check against other EXTRA rules (lower index only, to report once)
  for (const [otherIndex, otherNorm] of extraSources) {
    if (otherIndex !== ruleIndex && otherNorm === normSrc) {
      reasons.push({
        kind: 'duplicate',
        detail: `same source as EXTRA rule #${otherIndex}`,
      });
      break; // one report is enough
    }
  }

  // Check against built-in server.ts patterns
  if (builtinSources.has(normSrc)) {
    reasons.push({
      kind: 'duplicate',
      detail: 'same source as a built-in rule in server.ts',
    });
  }

  // ── (d) False-positive check ──────────────────────────────────────────
  for (const benignStr of BENIGN) {
    if (re.test(benignStr)) {
      reasons.push({ kind: 'false-positive', offendingString: benignStr });
      // Report the first match only — the author will iterate
      break;
    }
  }

  return reasons.length > 0 ? { ruleIndex, label, reasons } : null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  ClaudeSec — ruleSelfTest.ts  (EXTRA_SEVERITY_RULES gate)');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log();

  const rules = EXTRA_SEVERITY_RULES as unknown[];
  const totalRules = rules.length;

  if (totalRules === 0) {
    console.log('EXTRA_SEVERITY_RULES is empty — nothing to check.');
    console.log();
    console.log('Result: 0 rules checked, 0 passed, 0 failed.');
    console.log('Exit: 0 (pass)');
    process.exit(0);
  }

  console.log(`Checking ${totalRules} EXTRA rule(s)…`);
  console.log();

  // Pre-compute normalised sources for all extra rules (for dedup)
  const extraSources = new Map<number, string>();
  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    if (r !== null && typeof r === 'object' && (r as Record<string, unknown>).pattern instanceof RegExp) {
      extraSources.set(i, normaliseSource(((r as Record<string, unknown>).pattern as RegExp).source));
    }
  }

  // Extract built-in patterns from server.ts (text read only)
  console.log(`Reading server.ts for built-in pattern dedup…`);
  const builtinSources = extractServerPatternSources();
  console.log(`  → found ${builtinSources.size} built-in pattern(s).`);
  console.log();

  // Run all checks
  const failures: Failure[] = [];
  for (let i = 0; i < rules.length; i++) {
    const failure = checkRule(rules[i], i, extraSources, builtinSources);
    if (failure !== null) {
      failures.push(failure);
    }
  }

  const passed = totalRules - failures.length;

  // ── Summary ──────────────────────────────────────────────────────────────
  console.log('───────────────────────────────────────────────────────────────');
  console.log(`  Total rules : ${totalRules}`);
  console.log(`  Passed      : ${passed}`);
  console.log(`  Failed      : ${failures.length}`);
  console.log('───────────────────────────────────────────────────────────────');

  if (failures.length === 0) {
    console.log();
    console.log('All rules passed.');
    console.log('Exit: 0 (pass)');
    process.exit(0);
  }

  // ── Per-failure detail ────────────────────────────────────────────────────
  console.log();
  console.log('FAILURES:');
  console.log();

  for (const failure of failures) {
    console.log(`  Rule #${failure.ruleIndex}  "${failure.label}"`);
    for (const reason of failure.reasons) {
      switch (reason.kind) {
        case 'invalid':
          console.log(`    [INVALID]        ${reason.detail}`);
          break;
        case 'redos':
          console.log(`    [REDOS]          ${reason.detail}`);
          break;
        case 'duplicate':
          console.log(`    [DUPLICATE]      ${reason.detail}`);
          break;
        case 'false-positive':
          console.log(`    [FALSE-POSITIVE] matched benign string:`);
          console.log(`                     ${JSON.stringify(reason.offendingString)}`);
          break;
      }
    }
    console.log();
  }

  console.log('Exit: 1 (fail)');
  process.exit(1);
}

// Only run when invoked directly (npx tsx scripts/ruleSelfTest.ts).
// When the module is imported for unit-testing its exported helpers,
// main() is NOT called automatically.
const _argv1 = process.argv[1] ?? '';
const _self  = fileURLToPath(import.meta.url);
const isEntryPoint =
  _argv1 === _self ||
  // tsx sometimes resolves the argv path without the .ts extension
  _argv1.replace(/\.ts$/, '') === _self.replace(/\.ts$/, '');

if (isEntryPoint) {
  main();
}
