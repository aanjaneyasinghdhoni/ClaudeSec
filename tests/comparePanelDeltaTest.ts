/**
 * tests/comparePanelDeltaTest.ts
 *
 * Unit gate for `computeDelta` in src/ComparePanel.tsx — the pure function
 * behind `<DeltaBadge>` that decides a diff's direction, whether that
 * direction is "good", and how the number is labelled.
 *
 * The concrete regression this guards: `formatTokens` (src/lib/format.ts)
 * scales into billions on long-lived installs ("17.94B" instead of an
 * unreadable dozen-digit number), but the delta badge used to compute its own
 * label from the raw diff with `toLocaleString()`, ignoring the row's
 * `format`. A token-count delta would render as a giant unformatted number
 * next to a compact main value. `computeDelta` takes `format` as an input
 * specifically so the two can never drift apart again — this test pins that.
 *
 * Run via:  npx tsx tests/comparePanelDeltaTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed (details printed).
 *
 * Hermetic: no network, no DB. See tests/webhookDeliveryFormatTest.ts for why
 * a CSS-stub loader is registered before importing a component file.
 */
import assert from 'node:assert';
import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

register('./tests/helpers/cssStubLoader.mjs', pathToFileURL('./'));

const { computeDelta } = await import('../src/ComparePanel.tsx');
const { formatTokens } = await import('../src/lib/format.ts');

// ---------------------------------------------------------------------------
// Tiny assertion harness (matches the house style: plain functions, count
// cases, exit(1) on any failure — no test framework).
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// No difference
// ---------------------------------------------------------------------------

check('equal values have no direction', () => {
  const d = computeDelta(42, 42);
  assert.strictEqual(d.direction, null);
  assert.strictEqual(d.diff, 0);
  assert.strictEqual(d.isGood, true);
});

// ---------------------------------------------------------------------------
// Direction and "goodness" — higher-is-better is the default; lowerIsBetter
// flips which direction reads as good without changing which way the number
// actually moved.
// ---------------------------------------------------------------------------

check('higher-is-better: B > A is up and good', () => {
  const d = computeDelta(10, 15);
  assert.strictEqual(d.direction, 'up');
  assert.strictEqual(d.isGood, true);
  assert.strictEqual(d.diff, 5);
});

check('higher-is-better: B < A is down and bad', () => {
  const d = computeDelta(15, 10);
  assert.strictEqual(d.direction, 'down');
  assert.strictEqual(d.isGood, false);
  assert.strictEqual(d.diff, -5);
});

check('lowerIsBetter: B > A (more alerts) is up but bad', () => {
  const d = computeDelta(3, 8, { lowerIsBetter: true });
  assert.strictEqual(d.direction, 'up');
  assert.strictEqual(d.isGood, false);
});

check('lowerIsBetter: B < A (fewer alerts) is down but good', () => {
  const d = computeDelta(8, 3, { lowerIsBetter: true });
  assert.strictEqual(d.direction, 'down');
  assert.strictEqual(d.isGood, true);
});

// ---------------------------------------------------------------------------
// Labels — the default formatter, and the regression this file exists for.
// ---------------------------------------------------------------------------

check('default format is a signed toLocaleString', () => {
  assert.strictEqual(computeDelta(10, 15).label, '+5');
  assert.strictEqual(computeDelta(15, 10).label, '−5');
});

check('a large default-formatted diff is not compacted on its own', () => {
  // No `format` passed — this is what every non-token metric (spans, alerts,
  // threat counts) gets, and it must stay exact, not compact.
  const d = computeDelta(1_000, 2_500_000);
  assert.strictEqual(d.label, `+${(2_500_000 - 1_000).toLocaleString()}`);
});

check('a billion-scale token delta uses the compact format, not a raw number', () => {
  const a = 140_839_947;
  const b = 17_940_000_000; // crosses into formatTokens' "B" bucket
  const d = computeDelta(a, b, { format: formatTokens });
  assert.strictEqual(d.label, `+${formatTokens(b - a)}`);
  // The whole point: the label must NOT be the raw ~17.8 billion diff spelled
  // out digit by digit.
  assert.ok(!d.label.includes((b - a).toLocaleString()), `label leaked an uncompacted number: ${d.label}`);
  assert.ok(d.label.endsWith('B'), `expected a "B"-scale compact label, got ${d.label}`);
});

check('the exact tooltip value is always the full uncompacted number', () => {
  const a = 140_839_947;
  const b = 17_940_000_000;
  const d = computeDelta(a, b, { format: formatTokens });
  assert.strictEqual(d.exact, `+${(b - a).toLocaleString()}`);
});

check('a token delta below the compact thresholds still round-trips through format', () => {
  const d = computeDelta(100, 2_100, { format: formatTokens });
  assert.strictEqual(d.label, `+${formatTokens(2_000)}`);
});

// ---------------------------------------------------------------------------
// Report + exit
// ---------------------------------------------------------------------------

const total = passed + failed;
console.log('───────────────────────────────────────────────');
console.log(`  comparePanelDeltaTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failed > 0) {
  console.error(`\n  ${failed} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
