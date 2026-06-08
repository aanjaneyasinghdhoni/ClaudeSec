/**
 * tests/catastrophic-parity.test.ts
 *
 * Security control: assert that the catastrophic-6 floor patterns are identical
 * across all three enforcement sources:
 *   1. .claude/hooks/block-catastrophic.cjs  (RULES array)
 *   2. .claude/hooks/claudesec-enforce.cjs   (CATASTROPHIC array)
 *   3. server/enforceEval.ts                 (CATASTROPHIC export)
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
 * Asserts count > 0; caller asserts count === expectedCount.
 */
function extractPatterns(filePath: string): string[] {
  const text = fs.readFileSync(filePath, 'utf8');
  const results: string[] = [];

  for (const line of text.split('\n')) {
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

/** server/enforceEval.ts is REQUIRED (tracked). The two hook files are
 *  OPTIONAL — local-only, gitignored. A clean clone / CI / Docker build
 *  will not have them; skip gracefully instead of failing the build. */
const REQUIRED_SOURCES: { name: string; file: string }[] = [
  {
    name: 'server/enforceEval.ts',
    file: path.join(REPO_ROOT, 'server', 'enforceEval.ts'),
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

const EXPECTED_COUNT = 6;

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

process.exit(0);
