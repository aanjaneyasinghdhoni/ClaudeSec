/**
 * tests/ruleSelfTest.ts
 *
 * Quality-gate for EXTRA_SEVERITY_RULES (from severityRulesExtra.ts).
 * Run via:  npx tsx tests/ruleSelfTest.ts
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
 * Built-in dedup uses CORE_SEVERITY_RULES imported from server/detection.ts
 * (side-effect-free module) — no raw text-parsing of server/index.ts.
 */

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

// Sandbox the home dir BEFORE any server-side import. Should this test's import
// graph ever pull in server/index.ts, that module mirrors the enforce mode to
// <CLAUDESEC_HOME>/hooks/enforce-config.json at load time. Pointing
// CLAUDESEC_HOME at a throwaway temp dir guarantees the maintainer's real
// ~/.claudesec/hooks is never written. Cleaned up on exit.
const CSEC_TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-ruleselftest-home-'));
process.env.CLAUDESEC_HOME = CSEC_TEST_HOME;
const removeTestHome = () => { try { fs.rmSync(CSEC_TEST_HOME, { recursive: true, force: true }); } catch {} };
process.on('exit', removeTestHome);

import { EXTRA_SEVERITY_RULES } from '../server/severityRulesExtra.js';
import { CORE_SEVERITY_RULES, SEVERITY_RULES, CATASTROPHIC_DETECTION_LABELS } from '../server/detection.js';
// The always-on enforcement floor. These patterns run SYNCHRONOUSLY on the RAW,
// UNCAPPED bash command in both the PreToolUse hook and the MCP-proxy evaluator,
// with no per-action escape — so a non-linear floor pattern is a worse ReDoS than
// any user rule. Import the live arrays (not a text copy) and run them through the
// same execution gate, so a future floor edit that backtracks fails CI here.
import { CATASTROPHIC, LIVE_SECRET } from '../server/enforceEval.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = 'low' | 'medium' | 'high' | 'critical';

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
// (b2) ReDoS EXECUTION gate — actually run each pattern under a hard timeout
// ---------------------------------------------------------------------------
// The shape heuristic above only inspects the regex *source string*; it misses
// catastrophic forms whose structure it can't parse (e.g. `^(([a-z])+)+$` — the
// nested ')' defeats the heuristic's [^)]* spans). This gate is the real test:
// it EXECUTES every pattern against adversarial "pump" strings inside a worker
// thread the parent can kill. Catastrophic backtracking blocks synchronously,
// so a same-thread Promise.race timeout would never fire — the timer never runs
// while the regex spins. A worker isolates the spin; worker.terminate() kills it.

/** Adversarial inputs that detonate common catastrophic-backtracking shapes. */
const PUMP_STRINGS: string[] = [
  // Exponential blowup for nested-quantifier shapes — detonates around n≈40.
  'a'.repeat(40) + '!',
  'a'.repeat(50) + '!',
  '1'.repeat(48) + '!',
  // Polynomial blowup for adjacent-quantifier / overlapping-alternation shapes.
  'a'.repeat(5000),
  '1'.repeat(5000),
  ('ab').repeat(2500),
  ' '.repeat(5000) + 'X',
  ('a=').repeat(2500),
];

// Per-pattern execution budget. Catastrophic patterns blow far past this on the
// pump strings above; well-formed linear patterns finish in microseconds, so the
// full 600+ rule sweep stays well under a second.
const EXEC_TIMEOUT_MS = 250;

// Worker body (plain JS, run via { eval: true } — NOT a .ts file, so it needs no
// tsx transform). It reconstructs the RegExp from {source, flags}, runs it against
// every pump string, and reports done. If the regex hangs, the parent terminates
// this worker before it ever posts back.
const WORKER_SRC = `
  const { parentPort, workerData } = require('node:worker_threads');
  try {
    const re = new RegExp(workerData.source, workerData.flags);
    for (const s of workerData.inputs) {
      // .test() is enough to trigger backtracking; result is irrelevant.
      re.test(s);
    }
    parentPort.postMessage({ ok: true });
  } catch (err) {
    // A pattern that throws at construction/exec is reported, not treated as a hang.
    parentPort.postMessage({ ok: false, error: String(err && err.message || err) });
  }
`;

/**
 * Execute one pattern against a pump battery inside a killable worker. Defaults to
 * the generic PUMP_STRINGS; callers can pass a tailored battery (e.g. the floor
 * pumps) to detonate shape-specific backtracking. Returns null if it completed
 * within the budget, or a description string if it timed out (catastrophic
 * backtracking) or threw.
 */
function executePatternSafely(re: RegExp, inputs: string[] = PUMP_STRINGS): Promise<string | null> {
  return new Promise<string | null>((resolve) => {
    let settled = false;
    const worker = new Worker(WORKER_SRC, {
      eval: true,
      workerData: { source: re.source, flags: re.flags, inputs },
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      worker.terminate().finally(() => {
        resolve(`pattern exceeded ${EXEC_TIMEOUT_MS}ms on adversarial input (catastrophic backtracking)`);
      });
    }, EXEC_TIMEOUT_MS);

    worker.on('message', (msg: { ok: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().finally(() => {
        resolve(msg.ok ? null : `pattern threw at execution: ${msg.error}`);
      });
    });

    worker.on('error', (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(`worker error: ${err.message}`);
    });
  });
}

// ---------------------------------------------------------------------------
// Built-in pattern sources (imported — no raw text-parsing of server/index.ts)
// ---------------------------------------------------------------------------

/**
 * Returns a Set of normalised .source strings for every CORE built-in rule
 * (CORE_SEVERITY_RULES — the hand-authored core set, EXCLUDING the EXTRA
 * spread). Used by the dedup check to detect when an EXTRA rule duplicates a
 * core built-in. (Deduping against the combined set would flag every EXTRA
 * rule as a duplicate of itself.)
 */
export function extractServerPatternSources(): Set<string> {
  const sources = new Set<string>();
  for (const rule of CORE_SEVERITY_RULES) {
    sources.add(normaliseSource(rule.pattern.source));
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
  // .env.example is the conventional non-secret template; copying / committing /
  // even piping it must NEVER trip the critical exfil tier.
  'cat .env.example > .env',
  'git add .env.example',
  'git push origin main  # ships .env.example template',
  'cat .env.example | grep DATABASE_URL',
  'curl -sSL https://example.com/install.sh -o setup.sh',
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

async function checkRule(
  rule: unknown,
  ruleIndex: number,
  extraSources: Map<number, string>,
  builtinSources: Set<string>,
): Promise<Failure | null> {
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
  if (!['low', 'medium', 'high', 'critical'].includes(r.severity as string)) {
    reasons.push({
      kind: 'invalid',
      detail: `severity "${r.severity}" is not one of: low, medium, high, critical`,
    });
  }
  // critical is reserved for active EXFILTRATION, never host destruction: a
  // critical rule must NOT reuse a catastrophic-floor label. This keeps the
  // exfil tier and the always-on destruction floor cleanly separated.
  if (
    r.severity === 'critical' &&
    typeof r.label === 'string' &&
    CATASTROPHIC_DETECTION_LABELS.has(r.label.trim())
  ) {
    reasons.push({
      kind: 'invalid',
      detail: `critical severity must not reuse a catastrophic-floor label ("${r.label}")`,
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

  // ── (b) ReDoS heuristic (cheap, source-shape only) ─────────────────────
  const redosDesc = detectReDoS(src);
  if (redosDesc !== null) {
    reasons.push({ kind: 'redos', detail: redosDesc });
  }

  // ── (b2) ReDoS EXECUTION gate (authoritative) ──────────────────────────
  // Actually runs the pattern against adversarial pump strings under a hard
  // timeout in a killable worker. Catches catastrophic patterns the heuristic
  // can't see. Skipped only if the heuristic already flagged it (no need to
  // detonate a pattern we've already rejected).
  if (redosDesc === null) {
    const execFail = await executePatternSafely(re);
    if (execFail !== null) {
      reasons.push({ kind: 'redos', detail: execFail });
    }
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

  // Check against built-in server/index.ts patterns
  if (builtinSources.has(normSrc)) {
    reasons.push({
      kind: 'duplicate',
      detail: 'same source as a built-in rule in server/index.ts',
    });
  }

  // ── (d) False-positive check ──────────────────────────────────────────
  // This runs un-timed on the main thread, so only reach it once the pattern
  // has cleared the execution gate above — otherwise a pattern that backtracks
  // catastrophically on a short BENIGN string could hang the gate it's meant to
  // protect. If a ReDoS reason is already recorded, skip the FP probe entirely.
  if (!reasons.some(r => r.kind === 'redos')) {
    for (const benignStr of BENIGN) {
      if (re.test(benignStr)) {
        reasons.push({ kind: 'false-positive', offendingString: benignStr });
        // Report the first match only — the author will iterate
        break;
      }
    }
  }

  return reasons.length > 0 ? { ruleIndex, label, reasons } : null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  ClaudeSec — ruleSelfTest.ts  (EXTRA_SEVERITY_RULES gate)');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log();

  // ── Catastrophic-floor label parity ───────────────────────────────────────
  // CATASTROPHIC_DETECTION_LABELS names the rules an operator can never disable
  // (the per-rule override route rejects them by exact label). If a rule is ever
  // renamed without updating that set, the protection silently stops matching —
  // the rule could then be disabled. Assert every protected label still maps to
  // a real rule so a rename can't quietly disarm the floor.
  const ruleLabels = new Set(SEVERITY_RULES.map(r => r.label));
  const orphanedLabels = [...CATASTROPHIC_DETECTION_LABELS].filter(label => !ruleLabels.has(label));
  if (orphanedLabels.length > 0) {
    console.error('FAIL  CATASTROPHIC_DETECTION_LABELS references label(s) with no matching rule:');
    for (const label of orphanedLabels) console.error(`         ${JSON.stringify(label)}`);
    console.error('      A protected catastrophic-floor label was renamed or removed from the rule set,');
    console.error('      which would silently disarm the disable-protection. Re-sync detection.ts.');
    console.error('Exit: 1 (fail)');
    process.exit(1);
  }
  console.log(`Catastrophic-floor parity: all ${CATASTROPHIC_DETECTION_LABELS.size} protected label(s) map to a real rule.`);
  console.log();

  // ── Enforcement-floor ReDoS gate (authoritative) ──────────────────────────
  // Run EVERY CATASTROPHIC and LIVE_SECRET floor pattern through the same
  // killable-worker execution gate the user rules face, PLUS floor-shaped pump
  // strings (a flood of flag tokens, a deep path, a long device tail) that target
  // the specific shapes these patterns parse. The floor fires on the raw, uncapped
  // bash command with no per-action escape, so any pattern that backtracks here is
  // a launch-blocking ReDoS — fail CI rather than ship it.
  const FLOOR_PUMPS: string[] = [
    'rm ' + '-x '.repeat(80) + '/etc',          // flag-order / system-dir flood
    'rm ' + '-'.repeat(400) + ' /',             // long single-flag run
    'nc ' + '-x '.repeat(120),                  // netcat flag flood (the P0 shape)
    'nc ' + 'xexcxe'.repeat(2000),              // dense e/c tokens, no boundary
    'netcat ' + 'a'.repeat(8000) + ' -e ',      // long host then dangerous flag
    'rm -rf /var/' + 'a/'.repeat(4000),         // deep system-dir path
    'echo x > /dev/nvme' + '0'.repeat(8000),    // long device tail
    'format ' + '/q '.repeat(2000) + 'c:',      // many switches before drive
    'curl ' + 'a'.repeat(8000) + ' | sh',       // long curl-pipe-sh body
    'a'.repeat(20000),                          // long benign line (must not stall)
  ];
  const floorSets: { name: string; rules: { re: RegExp; why: string }[] }[] = [
    { name: 'CATASTROPHIC', rules: CATASTROPHIC },
    { name: 'LIVE_SECRET', rules: LIVE_SECRET },
  ];
  const floorFailures: string[] = [];
  let floorChecked = 0;
  for (const set of floorSets) {
    for (const rule of set.rules) {
      floorChecked++;
      // The EXECUTION gate is AUTHORITATIVE here — it actually detonates each pattern
      // against the generic pump battery AND the floor-specific pumps under a hard
      // worker timeout. (The source-shape heuristic used for user rules is too coarse
      // for the floor: it flags linear forms like `(?:\/[a-z]\s+)*` whose every
      // iteration consumes a mandatory separator, so it can't decide a shipped floor
      // pattern. Execution proves linearity directly.)
      const generic = await executePatternSafely(rule.re);
      const floorHit = generic === null ? await executePatternSafely(rule.re, FLOOR_PUMPS) : null;
      const verdict = generic ?? floorHit;
      if (verdict !== null) {
        floorFailures.push(`${set.name} /${rule.re.source}/ — ${verdict}`);
      }
    }
  }
  if (floorFailures.length > 0) {
    console.error(`FAIL  enforcement floor has ${floorFailures.length} non-linear pattern(s):`);
    for (const f of floorFailures) console.error(`         ${f}`);
    console.error('      A catastrophic/live-secret floor pattern backtracks on adversarial input.');
    console.error('      The floor runs on the RAW bash command with no escape — rewrite it linear.');
    console.error('Exit: 1 (fail)');
    process.exit(1);
  }
  console.log(`Enforcement-floor ReDoS gate: ${floorChecked} floor pattern(s) are linear / RE2-safe.`);
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

  // Extract built-in patterns from server/index.ts (text read only)
  console.log(`Reading server/index.ts for built-in pattern dedup…`);
  const builtinSources = extractServerPatternSources();
  console.log(`  → found ${builtinSources.size} built-in pattern(s).`);
  console.log();

  // Run all checks. Each rule's execution gate spins up a short-lived worker;
  // run sequentially so a hung pattern is isolated and the timeouts don't pile up.
  const failures: Failure[] = [];
  for (let i = 0; i < rules.length; i++) {
    const failure = await checkRule(rules[i], i, extraSources, builtinSources);
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
  main().catch((err) => {
    console.error('[ruleSelfTest] fatal:', err);
    process.exit(1);
  });
}
