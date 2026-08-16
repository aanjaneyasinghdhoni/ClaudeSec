/**
 * tests/governTabStatusTest.ts
 *
 * Unit gate for src/governance/policyVisual.ts — the pure status→visual
 * mapping behind the Govern tab. This is the one place the screen's whole
 * argument lives: "held" must never read as green/safe, "not provable" must
 * never collide with either of the other two outcomes, and a broken hash
 * chain must name which log broke rather than collapsing to a single bit.
 *
 * Deliberately hermetic — it imports only the pure module, never
 * src/GovernTab.tsx itself, which pulls in src/socket.ts and opens a live
 * socket.io connection at import time. No network, no DOM, no React.
 *
 * Run via:  npx tsx tests/governTabStatusTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 */
import assert from 'node:assert';
import {
  policyStatusVisual,
  describeDataHeld,
  summarizeChain,
  isPeriodDays,
  HELD_HONESTY_LINE,
  PERIOD_OPTIONS,
} from '../src/governance/policyVisual.ts';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ── held is always grey, regardless of the policy's own severity floor ─────
check('held on a critical-floor policy still reads none (grey), never the floor colour', () => {
  assert.strictEqual(policyStatusVisual('held', 'critical').severity, 'none');
});
check('held on a high-floor policy still reads none (grey)', () => {
  assert.strictEqual(policyStatusVisual('held', 'high').severity, 'none');
});
check('held on a configuration policy (no floor) still reads none (grey)', () => {
  assert.strictEqual(policyStatusVisual('held', null).severity, 'none');
});
check('held never carries the word "held" without the grey mapping — no green anywhere in this module', () => {
  const v = policyStatusVisual('held', 'critical');
  assert.strictEqual(v.word, 'Held');
  assert.notStrictEqual(v.severity, 'low'); // the only token this codebase could mistake for "safe"
});

// ── not-provable is fixed at medium, not scaled by the policy's own floor ──
check('not-provable on a critical-floor policy still reads medium, not critical', () => {
  assert.strictEqual(policyStatusVisual('not-provable', 'critical').severity, 'medium');
});
check('not-provable on a high-floor policy still reads medium, not high', () => {
  assert.strictEqual(policyStatusVisual('not-provable', 'high').severity, 'medium');
});

// ── violated carries the policy's real floor, with a sane fallback for the
//    two configuration policies that have none ─────────────────────────────
check('violated carries the policy severity floor verbatim', () => {
  assert.strictEqual(policyStatusVisual('violated', 'high').severity, 'high');
  assert.strictEqual(policyStatusVisual('violated', 'critical').severity, 'critical');
});
check('a violated configuration policy (no floor) falls back to high, not something calmer', () => {
  assert.strictEqual(policyStatusVisual('violated', null).severity, 'high');
});

// ── the three statuses can never collide on one screen ─────────────────────
check('held, not-provable, and a violated-high policy never share a spine colour', () => {
  const held = policyStatusVisual('held', 'high').severity;
  const notProvable = policyStatusVisual('not-provable', 'high').severity;
  const violated = policyStatusVisual('violated', 'high').severity;
  const set = new Set([held, notProvable, violated]);
  assert.strictEqual(set.size, 3, `expected 3 distinct severities, got ${[...set].join(', ')}`);
});

// ── coverage strip formatting ───────────────────────────────────────────────
check('describeDataHeld formats the plain case with no warning', () => {
  assert.strictEqual(
    describeDataHeld({ configuredDays: 365, effectiveDays: 76, cappedByMaxSpans: false, warning: null }),
    '365 days configured · 76 days actual',
  );
});
check('describeDataHeld appends the warning when the count cap is biting', () => {
  const out = describeDataHeld({
    configuredDays: 183, effectiveDays: 41, cappedByMaxSpans: true,
    warning: 'capped by MAX_SPANS',
  });
  assert.ok(out.includes('41 days actual'), 'must state the effective (actual) window, not just the configured one');
  assert.ok(out.includes('capped by MAX_SPANS'), 'a silent cap is how a retention claim becomes false — the warning must show');
});
check('describeDataHeld uses the singular for a single day', () => {
  assert.strictEqual(
    describeDataHeld({ configuredDays: 1, effectiveDays: 1, cappedByMaxSpans: false, warning: null }),
    '1 day configured · 1 day actual',
  );
});

// ── chain summary names which log broke ─────────────────────────────────────
check('summarizeChain reports Verified when all three logs are intact', () => {
  const s = summarizeChain({ ok: true, audit: { ok: true }, enforce: { ok: true }, spans: { ok: true } });
  assert.strictEqual(s.ok, true);
  assert.strictEqual(s.label, 'Verified');
});
check('summarizeChain names only the spans table when only it is broken (the real shape seen in production)', () => {
  const s = summarizeChain({ ok: false, audit: { ok: true }, enforce: { ok: true }, spans: { ok: false } });
  assert.strictEqual(s.ok, false);
  assert.strictEqual(s.label, 'Broken — spans');
});
check('summarizeChain names every broken log when more than one fails', () => {
  const s = summarizeChain({ ok: false, audit: { ok: false }, enforce: { ok: true }, spans: { ok: false } });
  assert.strictEqual(s.label, 'Broken — audit log, spans');
});

// ── period validation ────────────────────────────────────────────────────────
check('every documented period option validates', () => {
  for (const d of PERIOD_OPTIONS) assert.ok(isPeriodDays(d), `${d} should be a valid period`);
});
check('an arbitrary number is not a valid period', () => {
  assert.strictEqual(isPeriodDays(91), false);
});

// ── the honesty line actually names all four qualifiers ─────────────────────
check('the on-screen honesty line names all four ways "held" can be hollow', () => {
  const line = HELD_HONESTY_LINE.toLowerCase();
  for (const qualifier of ['unmonitored', 'disabled rule', 'outage', 'pruned']) {
    assert.ok(line.includes(qualifier), `honesty line is missing the "${qualifier}" qualifier`);
  }
});

console.log('───────────────────────────────────────────────');
if (failed > 0) {
  for (const f of failures) console.error(`  ✗ ${f}`);
}
console.log(`  governTabStatusTest: ${passed} passed, ${failed} failed`);
console.log('───────────────────────────────────────────────');
process.exit(failed === 0 ? 0 : 1);
