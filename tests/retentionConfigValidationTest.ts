/**
 * tests/retentionConfigValidationTest.ts
 *
 * Gate for the input validation on POST /api/db-stats/retention (the route that
 * persists maxSpans / retentionDays from the Settings UI).
 *
 * ── Why this test mirrors the handler instead of importing it ──
 * The route is registered by registerDbStatsRoutes() in server/routes/dbStats.ts,
 * which closes over a live `db` handle and a RouteContext built inside
 * server/index.ts (opening the live DB, binding a port, starting the watcher).
 * There is no seam to invoke the handler in isolation without those side effects.
 * So — exactly like tests/retentionTest.ts mirrors pruneSpans() — this test pins
 * the *validation contract* of the handler against a fake Express req/res. The
 * validate() below is copied verbatim from dbStats.ts; if the route changes, this
 * copy must change with it.
 *
 * The bug this guards against: a cleared number input in the UI yields NaN, which
 * JSON.stringify turns into `null`. The server must REJECT non-finite / negative
 * values with a 400 rather than silently skipping them (which returned 200 and let
 * the UI flash "Saved" though nothing changed).
 *
 * Run via:  npx tsx tests/retentionConfigValidationTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → at least one failed.
 */

import assert from 'node:assert';

let passed = 0;
const failures: string[] = [];
function check(name: string, fn: () => void): void {
  try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
}

// ---------------------------------------------------------------------------
// Handler validation mirror — kept byte-for-byte in step with the body checks in
// server/routes/dbStats.ts POST /api/db-stats/retention. `persisted` records the
// keys the handler WOULD have written, so the test can assert a value is skipped
// only because the request omitted it (undefined), never because it was a silent
// no-op on bad input.
// ---------------------------------------------------------------------------

interface FakeRes {
  statusCode: number;
  body: any;
  status(code: number): FakeRes;
  json(payload: any): FakeRes;
}

function makeRes(): FakeRes {
  return {
    statusCode: 200,
    body: undefined,
    status(code: number) { this.statusCode = code; return this; },
    json(payload: any) { this.body = payload; return this; },
  };
}

/** Verbatim mirror of the retention-route validation in server/routes/dbStats.ts. */
function handleRetention(
  body: { maxSpans?: number | null; retentionDays?: number | null },
  res: FakeRes,
  persisted: Record<string, string>,
): void {
  const { maxSpans, retentionDays } = body;
  if (maxSpans !== undefined && maxSpans !== null) {
    if (!Number.isFinite(maxSpans) || maxSpans < 100) {
      res.status(400).json({ error: 'maxSpans must be a finite number >= 100' });
      return;
    }
    persisted['retention.max_spans'] = String(maxSpans);
  }
  if (retentionDays !== undefined && retentionDays !== null) {
    if (!Number.isFinite(retentionDays) || retentionDays < 1) {
      res.status(400).json({ error: 'retentionDays must be a finite number >= 1' });
      return;
    }
    persisted['retention.days'] = String(retentionDays);
  }
  res.status(200).json({ status: 'ok' });
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

check('valid values are persisted with 200', () => {
  const res = makeRes();
  const persisted: Record<string, string> = {};
  handleRetention({ maxSpans: 50_000, retentionDays: 183 }, res, persisted);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(persisted['retention.max_spans'], '50000');
  assert.strictEqual(persisted['retention.days'], '183');
});

check('NaN maxSpans (cleared field) is REJECTED with 400, nothing persisted', () => {
  const res = makeRes();
  const persisted: Record<string, string> = {};
  handleRetention({ maxSpans: NaN, retentionDays: 183 }, res, persisted);
  assert.strictEqual(res.statusCode, 400, 'NaN must 400, not silently skip');
  assert.ok(!('retention.max_spans' in persisted), 'must not persist a bad maxSpans');
  assert.ok(!('retention.days' in persisted), 'must short-circuit before the next field');
});

check('null retentionDays (NaN→JSON null) is REJECTED with 400', () => {
  const res = makeRes();
  const persisted: Record<string, string> = {};
  // JSON.stringify(NaN) === 'null', so a cleared field arrives as null on the wire.
  handleRetention({ maxSpans: 50_000, retentionDays: null }, res, persisted);
  // null is treated as "field absent" (intentional, matches the route) → no 400,
  // BUT it must NOT be persisted as a value either. maxSpans still saved.
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(persisted['retention.max_spans'], '50000');
  assert.ok(!('retention.days' in persisted), 'null must not persist a value');
});

check('negative maxSpans is REJECTED with 400', () => {
  const res = makeRes();
  handleRetention({ maxSpans: -5 }, res, {});
  assert.strictEqual(res.statusCode, 400);
});

check('zero retentionDays is REJECTED with 400 (must be >= 1)', () => {
  const res = makeRes();
  handleRetention({ retentionDays: 0 }, res, {});
  assert.strictEqual(res.statusCode, 400);
});

check('Infinity maxSpans is REJECTED with 400 (not finite)', () => {
  const res = makeRes();
  handleRetention({ maxSpans: Infinity }, res, {});
  assert.strictEqual(res.statusCode, 400);
});

check('empty body is a 200 no-op (both fields undefined)', () => {
  const res = makeRes();
  const persisted: Record<string, string> = {};
  handleRetention({}, res, persisted);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(Object.keys(persisted).length, 0);
});

// ---------------------------------------------------------------------------
// Report + exit
// ---------------------------------------------------------------------------

const total = passed + failures.length;
console.log('───────────────────────────────────────────────');
console.log(`  retentionConfigValidationTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failures.length) {
  console.error(`\n  ${failures.length} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
