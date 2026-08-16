/**
 * tests/anomalySqlParityTest.ts
 *
 * Gate for detectBehavioralAnomalies() in server/index.ts.
 *
 * ── What this pins ──
 * The function used to read a whole trace back into JS (`SELECT * FROM spans
 * WHERE traceId = ?`) and JSON.parse every `attributes` blob, then derive five
 * scalars from all that text. On the largest real session (21,182 spans /
 * 12.5 MB) that cost ~57 ms and ~27 MB of garbage PER CALL, and the sweep
 * re-ran it for every dirty trace every 2.5 s. It is now computed in SQLite.
 *
 * The rewrite has to keep the alerts identical, so the assertions below fix the
 * arithmetic each rule depends on:
 *   • token spike  — average over every positive input-token reading, "latest"
 *     being the newest such reading, and the `> 4× avg && > 2000` trigger.
 *   • threat burst — >= 3 non-`none` spans among the newest TEN, counted in
 *     ARRIVAL order (see the ordering note below).
 *   • tool calls   — a total over the session, counting only truthy tool names.
 *   • every alert  — reports the newest span of the trace.
 *
 * ── The ordering change this locks in ──
 * The old code took the tail of an UNORDERED `SELECT *`. SQLite answers that
 * from idx_spans_traceId_severity, so the rows arrived in severity order and
 * `spans.slice(-10)` was really "the ten highest in severity order" — on real
 * data that is ten `none` rows, which is why the burst rule almost never fired.
 * The rewrite orders by rowid (arrival order), which is what the rule always
 * meant. `burstFiresWhenThreatsAreTheNewestSpans` is the regression that would
 * have caught the old behaviour.
 *
 * Run via:  npx tsx tests/anomalySqlParityTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB and CLAUDESEC_HOME are redirected under
 * os.tmpdir() BEFORE server/index.ts is imported, and removed in a finally
 * block. The real ~/.claudesec database is never opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = path.join(os.tmpdir(), `csec-anomsql-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-anomsql-home-'));

// Must be set before the module graph opens the database or mirrors any config.
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_HOME = HOME_DIR;
process.env.CLAUDESEC_WATCH = '0';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try { fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

// A fixed mid-afternoon local instant. The off-hours rule fires when the local
// hour is < 6, so leaving this to the wall clock made every expectation below
// depend on what time the suite happened to run — green all evening, red after
// midnight. Pinning it keeps the rules under test the only variable.
const FIXED_NOW = new Date(2026, 0, 15, 14, 30, 0).getTime();

async function main(): Promise<void> {
  const { db } = await import('../server/db.js');
  const { detectBehavioralAnomalies: detectRaw } = await import('../server/index.js');
  const detectBehavioralAnomalies = (traceId: string, harness: string): void =>
    detectRaw(traceId, harness, FIXED_NOW);

  const insert = db.prepare(`
    INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason, severity,
                       harness, attributes, startNano, endNano, repo)
    VALUES (?, ?, '', 'span', 'test', '', ?, 'claude', ?, '0', '0', 'unknown')
  `);

  let seq = 0;
  /** Append one span to `traceId`. Insert order IS arrival order. */
  const add = (traceId: string, severity: string, attrs: Record<string, unknown>): string => {
    const spanId = `s${++seq}`;
    insert.run(spanId, traceId, severity, JSON.stringify(attrs));
    return spanId;
  };

  const alertsFor = (traceId: string) =>
    db.prepare(`SELECT ruleLabel, spanId, matchedText FROM alerts WHERE traceId = ? ORDER BY id`)
      .all(traceId) as { ruleLabel: string; spanId: string; matchedText: string }[];
  const labels = (traceId: string) => alertsFor(traceId).map(a => a.ruleLabel).sort();

  // ── Threat burst: the ordering regression ────────────────────────────────
  // Twenty benign spans, then three threats. In ARRIVAL order the newest ten
  // hold three threats and the rule must fire. Reading in severity order
  // instead puts the twenty `none` rows last, sees zero threats, and stays
  // silent — which is exactly what shipped before.
  check('burstFiresWhenThreatsAreTheNewestSpans', () => {
    const t = 'trace-burst';
    for (let i = 0; i < 20; i++) add(t, 'none', { i });
    add(t, 'high', {});
    add(t, 'medium', {});
    const newest = add(t, 'high', {});
    detectBehavioralAnomalies(t, 'claude');
    const a = alertsFor(t);
    assert.deepStrictEqual(a.map(x => x.ruleLabel), ['Threat burst detected']);
    assert.strictEqual(a[0].matchedText, '3 threats in last 10 spans',
      'burst must count only the newest ten and report the window size');
    assert.strictEqual(a[0].spanId, newest, 'alert must point at the newest span of the trace');
  });

  // Two threats among the newest ten is below the >= 3 threshold.
  check('burstStaysSilentBelowThreshold', () => {
    const t = 'trace-burst-quiet';
    for (let i = 0; i < 20; i++) add(t, 'none', { i });
    add(t, 'high', {});
    add(t, 'high', {});
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  // Threats that have scrolled out of the newest-ten window must not fire.
  check('burstIgnoresThreatsOlderThanTheWindow', () => {
    const t = 'trace-burst-stale';
    for (let i = 0; i < 5; i++) add(t, 'high', {});
    for (let i = 0; i < 12; i++) add(t, 'none', { i });
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  // A trace shorter than the window reports its real length, not 10.
  check('burstWindowShrinksToTraceLength', () => {
    const t = 'trace-burst-short';
    add(t, 'high', {}); add(t, 'high', {}); add(t, 'high', {});
    detectBehavioralAnomalies(t, 'claude');
    assert.strictEqual(alertsFor(t)[0].matchedText, '3 threats in last 3 spans');
  });

  // ── Token spike ───────────────────────────────────────────────────────────
  // Three readings of 100 plus a newest reading of 5000: avg over ALL FOUR is
  // 1325, and 5000 > 4 × 1325 = 5300 is false, so nothing fires. This pins that
  // the average includes the spike itself, as the original reduce() did.
  check('tokenSpikeAverageIncludesTheSpike', () => {
    const t = 'trace-tok-avg';
    for (let i = 0; i < 3; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 5000 });
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  check('tokenSpikeFiresAndReportsNewestReading', () => {
    const t = 'trace-tok-spike';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    const spike = add(t, 'none', { 'gen_ai.usage.input_tokens': 9000 });
    detectBehavioralAnomalies(t, 'claude');
    const a = alertsFor(t);
    assert.deepStrictEqual(a.map(x => x.ruleLabel), ['Token spike detected']);
    // 20×100 + 9000 = 11000 over 21 readings = 523.8; 9000 > 2095.2 and > 2000.
    assert.strictEqual(a[0].matchedText, '9000 tokens (avg: 524)');
    assert.strictEqual(a[0].spanId, spike);
  });

  // "Latest" is the newest span carrying a POSITIVE reading, so spans with no
  // token attribute at all must not displace it.
  check('tokenSpikeSkipsSpansWithoutAReading', () => {
    const t = 'trace-tok-gap';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 9000 });
    for (let i = 0; i < 3; i++) add(t, 'none', { note: 'no tokens here' });
    detectBehavioralAnomalies(t, 'claude');
    assert.strictEqual(alertsFor(t)[0].matchedText, '9000 tokens (avg: 524)');
  });

  // The llm.* key is the fallback for the gen_ai.* one, and a numeric STRING
  // counts exactly as Number() made it count.
  check('tokenSpikeHonoursFallbackKeyAndNumericStrings', () => {
    const t = 'trace-tok-alt';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'llm.usage.input_tokens': 100 });
    add(t, 'none', { 'llm.usage.input_tokens': '9000' });
    detectBehavioralAnomalies(t, 'claude');
    assert.strictEqual(alertsFor(t)[0].matchedText, '9000 tokens (avg: 524)');
  });

  // Zero, negative and non-numeric readings are not readings at all.
  check('tokenSpikeIgnoresNonPositiveAndNonNumeric', () => {
    const t = 'trace-tok-junk';
    add(t, 'none', { 'gen_ai.usage.input_tokens': 0 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': -5 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 'abc' });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    detectBehavioralAnomalies(t, 'claude');
    // Only one real reading — below the three needed to average at all.
    assert.deepStrictEqual(labels(t), []);
  });

  // Under 2000 tokens is noise however far above the average it sits.
  check('tokenSpikeNeedsTheAbsoluteFloor', () => {
    const t = 'trace-tok-small';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 1 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 1500 });
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  // ── Excessive tool calls ─────────────────────────────────────────────────
  check('toolCallsFireAboveOneHundred', () => {
    const t = 'trace-tools';
    for (let i = 0; i < 101; i++) add(t, 'none', { 'gen_ai.tool.name': 'Bash' });
    detectBehavioralAnomalies(t, 'claude');
    const a = alertsFor(t);
    assert.deepStrictEqual(a.map(x => x.ruleLabel), ['Excessive tool calls']);
    assert.strictEqual(a[0].matchedText, '101 tool calls in session');
  });

  check('toolCallsStaySilentAtExactlyOneHundred', () => {
    const t = 'trace-tools-edge';
    for (let i = 0; i < 100; i++) add(t, 'none', { 'tool.name': 'Bash' });
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  // A key that is present but FALSY was never a tool call — `if (a || b)`.
  check('toolCallsIgnoreFalsyNames', () => {
    const t = 'trace-tools-falsy';
    for (let i = 0; i < 60; i++) add(t, 'none', { 'gen_ai.tool.name': '' });
    for (let i = 0; i < 60; i++) add(t, 'none', { 'tool.name': 0 });
    for (let i = 0; i < 60; i++) add(t, 'none', { 'gen_ai.tool.name': false });
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), []);
  });

  // ── Robustness ───────────────────────────────────────────────────────────
  // json_extract THROWS on malformed JSON and the sweep swallows throws, so an
  // unguarded query would silently switch detection off for the whole trace.
  // The guarded fallback has to keep the other spans working.
  check('malformedAttributesDoNotDisableDetection', () => {
    const t = 'trace-malformed';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    db.prepare(`INSERT INTO spans (spanId, traceId, parentId, name, protocol, reason,
                                   severity, harness, attributes, startNano, endNano, repo)
                VALUES ('broken', ?, '', 'span', 'test', '', 'none', 'claude', '{not json', '0', '0', 'unknown')`)
      .run(t);
    add(t, 'none', { 'gen_ai.usage.input_tokens': 9000 });
    detectBehavioralAnomalies(t, 'claude');
    const a = alertsFor(t);
    assert.deepStrictEqual(a.map(x => x.ruleLabel), ['Token spike detected'],
      'a single unparseable span must not suppress the whole trace');
    assert.strictEqual(a[0].matchedText, '9000 tokens (avg: 524)');
  });

  check('unknownTraceIsANoOp', () => {
    assert.doesNotThrow(() => detectBehavioralAnomalies('trace-does-not-exist', 'claude'));
    assert.deepStrictEqual(labels('trace-does-not-exist'), []);
  });

  // ── Dedup ────────────────────────────────────────────────────────────────
  // The dedup guards are now read BEFORE the scan. That is only sound if a rule
  // inside its window still produces nothing, so re-running must not add rows.
  check('rulesInsideTheirWindowDoNotFireTwice', () => {
    const t = 'trace-dedup';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    add(t, 'none', { 'gen_ai.usage.input_tokens': 9000 });
    detectBehavioralAnomalies(t, 'claude');
    const first = alertsFor(t);
    assert.strictEqual(first.length, 1);
    for (let i = 0; i < 5; i++) detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(alertsFor(t), first, 'repeat sweeps must be inert inside the window');
  });

  // Each rule has its own label and its own window, so one firing must not
  // suppress another on the same trace.
  check('rulesAreIndependentOfEachOther', () => {
    const t = 'trace-both';
    for (let i = 0; i < 20; i++) add(t, 'none', { 'gen_ai.usage.input_tokens': 100 });
    add(t, 'high', { 'gen_ai.usage.input_tokens': 9000 });
    add(t, 'high', {});
    add(t, 'high', {});
    detectBehavioralAnomalies(t, 'claude');
    assert.deepStrictEqual(labels(t), ['Threat burst detected', 'Token spike detected']);
  });
}

main()
  .catch(err => { failed++; failures.push(`harness: ${(err as Error).message}`); })
  .finally(() => {
    cleanup();
    for (const f of failures) console.error(`  ✗ ${f}`);
    console.log(`anomalySqlParityTest: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
  });
