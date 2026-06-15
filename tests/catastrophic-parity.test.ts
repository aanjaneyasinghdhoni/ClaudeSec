/**
 * tests/catastrophic-parity.test.ts
 *
 * Security control: assert that the catastrophic floor patterns are identical
 * across every enforcement source:
 *   1. server/enforceEval.ts                 (CATASTROPHIC export)   — tracked
 *   2. cli/hooks/claudesec-enforce.cjs       (CATASTROPHIC array)    — tracked, ships
 *   3. .claude/hooks/block-catastrophic.cjs  (RULES array)          — local-only
 *   4. .claude/hooks/claudesec-enforce.cjs   (CATASTROPHIC array)   — local-only
 *
 * The two tracked sources are REQUIRED (they ship to every clone). The two
 * .claude/hooks/ copies are OPTIONAL — local-only, gitignored — so a clean
 * clone / CI / Docker build skips them gracefully.
 *
 * Extracts patterns by raw text parsing (no imports) so all three are compared
 * apples-to-apples on source+flags strings, not engine-normalized RegExp objects.
 *
 * Exit 0  → all sources define the identical set of patterns.
 * Exit 1  → any divergence (different count, different source, different flags).
 *
 * Run via:  npx tsx tests/catastrophic-parity.test.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/**
 * Extract `{ re: /pattern/flags, why: '...' }` entries from raw file text.
 * Returns an array of "source|flags" strings (one per entry found).
 *
 * Strategy: scan line by line for `re:` followed by a regex literal.
 *   - Find `re:` in the line.
 *   - The regex literal starts at the next `/` after `re:`.
 *   - The closing `/` is found by locating `, why:` and then finding the last
 *     `/` before that position — this handles escaped slashes inside the pattern.
 *   - Flags (if any) sit between the closing `/` and `, why:`.
 *
 * `marker` scopes the scan to one `{ re, why }` table (e.g. 'CATASTROPHIC' or
 * 'LIVE_SECRET'): slice from the first `<marker>` occurrence to the next line that
 * closes an array literal (`];`). Files without the marker fall back to scanning
 * the whole file (the local-only block-catastrophic.cjs uses a `RULES` array).
 *
 * Asserts count > 0; caller asserts count === expectedCount.
 */
function extractPatterns(filePath: string, marker = 'CATASTROPHIC'): string[] {
  const text = fs.readFileSync(filePath, 'utf8');
  const results: string[] = [];

  // Scope the scan to the marked array so we don't pick up other `{ re, why }`
  // tables in the same file (CATASTROPHIC vs the live-secret DLP floor LIVE_SECRET).
  let region = text;
  const startIdx = text.indexOf(marker);
  if (startIdx !== -1) {
    const tail = text.slice(startIdx);
    const closeMatch = tail.search(/\n\s*\];/);
    region = closeMatch !== -1 ? tail.slice(0, closeMatch) : tail;
  }

  for (const line of region.split('\n')) {
    const reIdx = line.indexOf('re:');
    if (reIdx === -1) continue;

    const whyIdx = line.indexOf(', why:', reIdx);
    if (whyIdx === -1) continue;

    // The opening `/` of the regex literal is the first `/` after `re:`.
    const openSlash = line.indexOf('/', reIdx);
    if (openSlash === -1 || openSlash >= whyIdx) continue;

    // The closing `/` is the last `/` before `, why:`.
    const closeSlash = line.lastIndexOf('/', whyIdx - 1);
    if (closeSlash <= openSlash) continue;

    const source = line.slice(openSlash + 1, closeSlash);
    const flags  = line.slice(closeSlash + 1, whyIdx).trim();

    // Skip if source is empty (shouldn't happen, but be defensive).
    if (!source) continue;

    results.push(`${source}|${flags}`);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** server/enforceEval.ts and cli/hooks/claudesec-enforce.cjs are REQUIRED — both
 *  are tracked and ship to every clone. The two .claude/hooks/ copies are
 *  OPTIONAL — local-only, gitignored. A clean clone / CI / Docker build will
 *  not have them; skip gracefully instead of failing the build. */
const REQUIRED_SOURCES: { name: string; file: string }[] = [
  {
    name: 'server/enforceEval.ts',
    file: path.join(REPO_ROOT, 'server', 'enforceEval.ts'),
  },
  {
    name: 'cli/hooks/claudesec-enforce.cjs',
    file: path.join(REPO_ROOT, 'cli', 'hooks', 'claudesec-enforce.cjs'),
  },
];

const OPTIONAL_SOURCES: { name: string; file: string }[] = [
  {
    name: 'block-catastrophic.cjs',
    file: path.join(REPO_ROOT, '.claude', 'hooks', 'block-catastrophic.cjs'),
  },
  {
    name: 'claudesec-enforce.cjs',
    file: path.join(REPO_ROOT, '.claude', 'hooks', 'claudesec-enforce.cjs'),
  },
];

const EXPECTED_COUNT = 8;

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

let allPassed = true;
const extracted: { name: string; patterns: string[] }[] = [];

// Required sources — hard-fail if missing or count wrong.
for (const src of REQUIRED_SOURCES) {
  if (!fs.existsSync(src.file)) {
    console.error(`FAIL  ${src.name}: file not found at ${src.file}`);
    allPassed = false;
    continue;
  }
  const patterns = extractPatterns(src.file);
  extracted.push({ name: src.name, patterns });

  if (patterns.length !== EXPECTED_COUNT) {
    console.error(
      `FAIL  ${src.name}: expected ${EXPECTED_COUNT} patterns, extracted ${patterns.length}`
    );
    allPassed = false;
  }
}

// Optional sources — skip with a note if missing; fail if present but wrong.
for (const src of OPTIONAL_SOURCES) {
  if (!fs.existsSync(src.file)) {
    console.log(`  note: skipping ${src.name} — not present (local-only hook)`);
    continue;
  }
  const patterns = extractPatterns(src.file);
  extracted.push({ name: src.name, patterns });

  if (patterns.length !== EXPECTED_COUNT) {
    console.error(
      `FAIL  ${src.name}: expected ${EXPECTED_COUNT} patterns, extracted ${patterns.length}`
    );
    allPassed = false;
  }
}

if (!allPassed) {
  console.error('\ncatastrophic parity: FAIL (count mismatch — check extraction above)');
  process.exit(1);
}

// Sort each set so order-independent comparison is correct, then compare.
const sorted = extracted.map(({ name, patterns }) => ({
  name,
  sorted: [...patterns].sort(),
}));

// Reference is always enforceEval.ts (first element of extracted, since required).
const reference = sorted[0];

// Defensive guard: if the reference source was not extracted (shouldn't happen
// since enforceEval.ts is required+tracked, but fail cleanly rather than throw).
if (!reference || reference.sorted.length === 0) {
  console.error(
    '\ncatastrophic parity: FAIL — required reference source (server/enforceEval.ts) ' +
    'was not successfully extracted; cannot run comparison.'
  );
  process.exit(1);
}

for (let i = 1; i < sorted.length; i++) {
  const { name, sorted: s } = sorted[i];
  for (let j = 0; j < EXPECTED_COUNT; j++) {
    if (s[j] !== reference.sorted[j]) {
      console.error(`\nFAIL  ${name} differs from ${reference.name}:`);
      console.error(`  reference[${j}]: ${reference.sorted[j]}`);
      console.error(`  ${name}[${j}]:   ${s[j]}`);
      allPassed = false;
    }
  }
  if (allPassed) {
    // Deep-check the full arrays are the same length too.
    if (s.length !== reference.sorted.length) {
      console.error(
        `\nFAIL  ${name}: ${s.length} patterns vs reference ${reference.sorted.length}`
      );
      allPassed = false;
    }
  }
}

if (!allPassed) {
  console.error('\ncatastrophic parity: FAIL');
  process.exit(1);
}

console.log(
  `catastrophic parity: ${EXPECTED_COUNT}/${EXPECTED_COUNT} identical across ${extracted.length} source(s) checked`
);
console.log(`  sources checked:`);
for (const { name, patterns } of extracted) {
  console.log(`    ${name}: ${patterns.length} patterns`);
}

// ---------------------------------------------------------------------------
// LIVE_SECRET parity — the minimal live-secret (DLP) floor must also stay
// byte-identical across the two TRACKED sources, so the secret lists can't
// silently drift. Same region-slicing technique, scoped to the LIVE_SECRET
// table. Only the two REQUIRED sources carry LIVE_SECRET (the local-only
// block-catastrophic.cjs has no such table).
// ---------------------------------------------------------------------------

const LIVE_SECRET_EXPECTED_COUNT = 9;
let secretPassed = true;
const secretExtracted: { name: string; patterns: string[] }[] = [];

for (const src of REQUIRED_SOURCES) {
  if (!fs.existsSync(src.file)) {
    // Already reported as a hard fail above; nothing to add here.
    secretPassed = false;
    continue;
  }
  const patterns = extractPatterns(src.file, 'LIVE_SECRET');
  secretExtracted.push({ name: src.name, patterns });
  if (patterns.length !== LIVE_SECRET_EXPECTED_COUNT) {
    console.error(
      `FAIL  ${src.name} (LIVE_SECRET): expected ${LIVE_SECRET_EXPECTED_COUNT} patterns, ` +
      `extracted ${patterns.length}`
    );
    secretPassed = false;
  }
}

if (secretPassed && secretExtracted.length >= 2) {
  const sortedSecret = secretExtracted.map(({ name, patterns }) => ({
    name,
    sorted: [...patterns].sort(),
  }));
  const ref = sortedSecret[0];
  for (let i = 1; i < sortedSecret.length; i++) {
    const { name, sorted: s } = sortedSecret[i];
    if (s.length !== ref.sorted.length) {
      console.error(
        `\nFAIL  ${name} (LIVE_SECRET): ${s.length} patterns vs reference ${ref.sorted.length}`
      );
      secretPassed = false;
      continue;
    }
    for (let j = 0; j < ref.sorted.length; j++) {
      if (s[j] !== ref.sorted[j]) {
        console.error(`\nFAIL  ${name} (LIVE_SECRET) differs from ${ref.name}:`);
        console.error(`  reference[${j}]: ${ref.sorted[j]}`);
        console.error(`  ${name}[${j}]:   ${s[j]}`);
        secretPassed = false;
      }
    }
  }
}

if (!secretPassed) {
  console.error('\nlive-secret parity: FAIL');
  process.exit(1);
}

console.log(
  `live-secret parity: ${LIVE_SECRET_EXPECTED_COUNT}/${LIVE_SECRET_EXPECTED_COUNT} identical ` +
  `across ${secretExtracted.length} tracked source(s) checked`
);

process.exit(0);
