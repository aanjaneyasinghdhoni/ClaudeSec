/**
 * tests/webhookDeliveryFormatTest.ts
 *
 * Unit gate for the pure formatter in src/WebhookDeliverySection.tsx —
 * `formatRelativeTime`, which turns a delivery's timestamp into "12s ago" /
 * "4h ago" / a plain date once it falls off the relative scale. It is the one
 * piece of that component with real branching logic (three time buckets plus
 * a malformed-input fallback), so it is the one piece worth a standalone gate.
 *
 * Run via:  npx tsx tests/webhookDeliveryFormatTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed (details printed).
 *
 * Hermetic: no network, no DB. The component file itself imports React and
 * `src/components/data`, which pulls in a `.css` import that plain Node can't
 * resolve outside a bundler — `tests/helpers/cssStubLoader.mjs` stubs that
 * import out so the component module can be loaded here for its one pure
 * export, without a DOM or a build step.
 */
import assert from 'node:assert';
import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

register('./tests/helpers/cssStubLoader.mjs', pathToFileURL('./'));

const { formatRelativeTime } = await import('../src/WebhookDeliverySection.tsx');

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

/** An ISO timestamp `msAgo` milliseconds before now. */
function agoIso(msAgo: number): string {
  return new Date(Date.now() - msAgo).toISOString();
}

// ---------------------------------------------------------------------------
// Buckets — seconds / minutes / hours / calendar date, and the boundaries
// between them, since off-by-one at a bucket edge is exactly where this kind
// of formatter tends to break.
// ---------------------------------------------------------------------------

check('just now reads in seconds', () => {
  assert.strictEqual(formatRelativeTime(agoIso(0)), '0s ago');
});

check('45s reads in seconds', () => {
  assert.strictEqual(formatRelativeTime(agoIso(45_000)), '45s ago');
});

check('just under a minute is still seconds', () => {
  assert.strictEqual(formatRelativeTime(agoIso(59_999)), '60s ago');
});

check('exactly one minute rolls over to minutes', () => {
  assert.strictEqual(formatRelativeTime(agoIso(60_000)), '1m ago');
});

check('30 minutes reads in minutes', () => {
  assert.strictEqual(formatRelativeTime(agoIso(30 * 60_000)), '30m ago');
});

check('exactly one hour rolls over to hours', () => {
  assert.strictEqual(formatRelativeTime(agoIso(3_600_000)), '1h ago');
});

check('12 hours reads in hours', () => {
  assert.strictEqual(formatRelativeTime(agoIso(12 * 3_600_000)), '12h ago');
});

check('a full day falls back to a calendar date', () => {
  const out = formatRelativeTime(agoIso(86_400_000));
  assert.ok(!out.includes('ago'), `expected a calendar date, got ${JSON.stringify(out)}`);
});

check('a week ago falls back to a calendar date', () => {
  const out = formatRelativeTime(agoIso(7 * 86_400_000));
  assert.ok(!out.includes('ago'), `expected a calendar date, got ${JSON.stringify(out)}`);
});

// ---------------------------------------------------------------------------
// Malformed input — a delivery row's timestamp always comes straight off the
// DB, so this is a hypothetical edge, but the one thing that must hold is
// that a bad string never throws and blanks out the settings panel. `Date`
// parses garbage into an "Invalid Date" rather than throwing, and
// `toLocaleDateString()` follows suit — so the function's own `catch` is
// never actually reached by a bad string; this documents that real behaviour
// rather than the more defensive '—' one might expect.
// ---------------------------------------------------------------------------

check('garbage input does not throw', () => {
  assert.strictEqual(formatRelativeTime('not-a-date'), 'Invalid Date');
});

check('empty string does not throw', () => {
  assert.strictEqual(formatRelativeTime(''), 'Invalid Date');
});

// ---------------------------------------------------------------------------
// Report + exit
// ---------------------------------------------------------------------------

const total = passed + failed;
console.log('───────────────────────────────────────────────');
console.log(`  webhookDeliveryFormatTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failed > 0) {
  console.error(`\n  ${failed} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
