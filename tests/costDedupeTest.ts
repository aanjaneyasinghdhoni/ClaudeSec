/**
 * tests/costDedupeTest.ts
 *
 * Cost-integrity gate. Proves the two halves of the duplicate-usage fix:
 *
 *   1. INGEST dedupe — Claude Code writes one JSONL line per assistant content
 *      block, every line repeating the SAME message.usage with the same
 *      message.id but a different record.uuid. The watcher now keys the
 *      llm_request span on `${message.id}:llm`, so INSERT OR IGNORE collapses the
 *      repeats to ONE costed row. We reproduce the exact span the watcher emits
 *      (spanId = `${message.id}:llm`, attributes include `gen_ai.response.id`)
 *      and assert that re-inserting the duplicates leaves a single row whose
 *      tokens are NOT summed.
 *
 *   2. QUERY-time dedupe — `dedupedUsageRows()` (server/routes/costs.ts) collapses
 *      rows that share a (traceId, response id) [exact, new data] and, as a
 *      fallback for legacy rows with NO response id, collapses byte-identical
 *      usage tuples within 10s of a kept sibling [heuristic, old data]. Demo
 *      traces (traceId LIKE 'demo-%') are excluded from every aggregate.
 *
 *   3. INPUT ATTRIBUTION — a real production comparison against Claude Code's own
 *      `/stats` found ClaudeSec's reported input tokens at 257% of the all-time
 *      figure despite covering a SHORTER window, while output (39%) and cache-read
 *      (45%) tracked the window correctly. Traced to spans ingested before this
 *      integration's OTLP source split cache tokens out of `input_tokens`: those
 *      rows carry NO `cache_read_input_tokens` key at all (absent, not zero) and
 *      `input_tokens` alone runs into six figures — the full resent context, not a
 *      real per-call input count. `dedupedUsageRows()` flags any such row
 *      `inputUnreliable: true`; every consumer must then treat its `tokensIn` as 0.
 *
 * This runs as its OWN process (spawned by main below) so it can point
 * CLAUDESEC_DB at an isolated temp DB BEFORE importing server/db.ts — the module
 * opens the database at import time. The temp DB is deleted in a finally block.
 * The real ~/.claudesec DB is NEVER touched. No server boot, no network: < 5s.
 *
 * Run via:  npx tsx tests/costDedupeTest.ts
 *   Exit 0  → every assertion passed.   Exit 1  → a failure (or worker crash).
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

// ---------------------------------------------------------------------------
// WORKER: runs with CLAUDESEC_DB already set, seeds the temp DB, runs assertions.
// Everything inside `runWorker` executes in the spawned child only.
// ---------------------------------------------------------------------------
async function runWorker(): Promise<void> {
  // db.ts reads CLAUDESEC_DB at import time, so it must be set in env BEFORE this.
  const { db } = await import('../server/db.js');
  const { dedupedUsageRows, dedupedTokenTotals } = await import('../server/routes/costs.js');

  const insert = db.prepare(`
    INSERT OR IGNORE INTO spans
      (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
    VALUES (@spanId, @traceId, 'root', 'llm_request', 'local', 'step', 'none', @harness, @attributes, @startNano, @endNano)
  `);
  const msToNano = (ms: number) => String(BigInt(ms) * 1_000_000n);

  // ── Scenario A: NEW ingest — one assistant turn, 3 transcript blocks/lines.
  // The watcher keys all three on the SAME message.id, so the same spanId is
  // inserted 3x. INSERT OR IGNORE must keep ONE row of 1000/500 tokens, NOT 3000.
  const msgId = 'msg_01NEWdedupe';
  const newAttrs = JSON.stringify({
    'gen_ai.request.model': 'claude-sonnet-4-6',
    'llm.model': 'claude-sonnet-4-6',
    'gen_ai.usage.input_tokens': 1000,
    'gen_ai.usage.cache_read_input_tokens': 200,
    'gen_ai.usage.cache_creation_input_tokens': 100,
    'gen_ai.usage.output_tokens': 500,
    'gen_ai.response.id': msgId,
  });
  for (let i = 0; i < 3; i++) {
    insert.run({ spanId: `${msgId}:llm`, traceId: 'trace-new', harness: 'claude-code', attributes: newAttrs, startNano: msToNano(1_700_000_000_000 + i * 1000), endNano: msToNano(1_700_000_000_000) });
  }

  // ── Scenario B: LEGACY ingest — same turn, but rows were stored under the OLD
  // per-line uuid key (3 DISTINCT spanIds) with NO response id. They carry
  // byte-identical usage within a few seconds, so the heuristic must collapse
  // them to ONE response worth (800/400) — not 2400/1200.
  const legacyAttrs = JSON.stringify({
    'gen_ai.request.model': 'claude-sonnet-4-6',
    'llm.model': 'claude-sonnet-4-6',
    'gen_ai.usage.input_tokens': 800,
    'gen_ai.usage.output_tokens': 400,
  });
  for (let i = 0; i < 3; i++) {
    insert.run({ spanId: `uuid-legacy-${i}:llm`, traceId: 'trace-legacy', harness: 'claude-code', attributes: legacyAttrs, startNano: msToNano(1_700_000_100_000 + i * 1500), endNano: msToNano(1_700_000_100_000) });
  }
  // A genuinely SEPARATE legacy call in the same trace+model, OUTSIDE the 10s
  // window and with DIFFERENT usage — must survive (not be collapsed).
  insert.run({
    spanId: 'uuid-legacy-distinct:llm', traceId: 'trace-legacy', harness: 'claude-code',
    attributes: JSON.stringify({ 'gen_ai.request.model': 'claude-sonnet-4-6', 'gen_ai.usage.input_tokens': 50, 'gen_ai.usage.output_tokens': 25 }),
    startNano: msToNano(1_700_000_200_000), endNano: msToNano(1_700_000_200_000),
  });

  // ── Scenario C: DEMO data — must be excluded from every aggregate.
  insert.run({
    spanId: 'demo-1:llm', traceId: 'demo-cc-001', harness: 'claude-code',
    attributes: JSON.stringify({ 'gen_ai.request.model': 'claude-sonnet-4-6', 'gen_ai.usage.input_tokens': 999999, 'gen_ai.usage.output_tokens': 999999 }),
    startNano: msToNano(1_700_000_300_000), endNano: msToNano(1_700_000_300_000),
  });

  // ── Scenario D: INPUT ATTRIBUTION — reproduces the real inflated rows found in
  // production: `input_tokens` in the hundreds of thousands with the cache-read
  // KEY entirely absent (this is what an ingest source reports before it starts
  // splitting cache tokens out of input — not a shape any version of this app's
  // own transcriptWatcher.ts has ever written). Paired with a genuinely reliable
  // row in the same trace that DOES carry the cache keys, as explicit zeros, so
  // the fix can't be a blanket "no cache = drop everything" rule.
  insert.run({
    spanId: 'otlp-legacy-1:llm', traceId: 'trace-inputattr', harness: 'claude-code',
    attributes: JSON.stringify({ 'gen_ai.request.model': 'claude-opus-4-8', 'gen_ai.usage.input_tokens': 900000, 'gen_ai.usage.output_tokens': 4000 }),
    startNano: msToNano(1_700_000_400_000), endNano: msToNano(1_700_000_400_000),
  });
  insert.run({
    spanId: 'otlp-reliable-1:llm', traceId: 'trace-inputattr', harness: 'claude-code',
    attributes: JSON.stringify({
      'gen_ai.request.model': 'claude-opus-4-8', 'gen_ai.usage.input_tokens': 300,
      'gen_ai.usage.output_tokens': 150, 'gen_ai.usage.cache_read_input_tokens': 0,
      'gen_ai.usage.cache_creation_input_tokens': 0,
    }),
    startNano: msToNano(1_700_000_450_000), endNano: msToNano(1_700_000_450_000),
  });

  let passed = 0;
  const failures: string[] = [];
  const check = (name: string, fn: () => void) => {
    try { fn(); passed++; } catch (e) { failures.push(`${name}: ${(e as Error).message}`); }
  };

  // 1. INGEST: the 3 identical-id inserts collapsed to one row via PRIMARY KEY.
  check('ingest: duplicate message.id lines store ONE span (not summed)', () => {
    const cnt = (db.prepare(`SELECT COUNT(*) AS c FROM spans WHERE spanId = ?`).get(`${msgId}:llm`) as { c: number }).c;
    assert.strictEqual(cnt, 1, `expected 1 row for ${msgId}:llm, got ${cnt}`);
  });

  const rows = dedupedUsageRows();

  // 2. EXACT dedupe: scenario A contributes exactly its single response's tokens.
  check('query: exact response-id dedupe keeps one row worth of tokens', () => {
    const a = rows.filter(r => r.traceId === 'trace-new');
    assert.strictEqual(a.length, 1, `expected 1 deduped row, got ${a.length}`);
    assert.strictEqual(a[0].tokensIn, 1000, `tokensIn ${a[0].tokensIn}`);
    assert.strictEqual(a[0].tokensOut, 500, `tokensOut ${a[0].tokensOut}`);
    assert.strictEqual(a[0].cacheRead, 200, `cacheRead ${a[0].cacheRead}`);
    assert.strictEqual(a[0].cacheWrite, 100, `cacheWrite ${a[0].cacheWrite}`);
  });

  // 3. FALLBACK heuristic: the 3 identical legacy lines collapse to one; the
  //    distinct call survives → 2 rows totalling 850 in / 425 out.
  check('query: legacy heuristic collapses identical-usage lines, keeps distinct call', () => {
    const b = rows.filter(r => r.traceId === 'trace-legacy');
    assert.strictEqual(b.length, 2, `expected 2 rows (1 collapsed + 1 distinct), got ${b.length}`);
    const sumIn = b.reduce((n, r) => n + r.tokensIn, 0);
    const sumOut = b.reduce((n, r) => n + r.tokensOut, 0);
    assert.strictEqual(sumIn, 850, `expected 800+50=850 in, got ${sumIn}`);
    assert.strictEqual(sumOut, 425, `expected 400+25=425 out, got ${sumOut}`);
  });

  // 4. DEMO exclusion: no demo trace appears in any deduped aggregate.
  check('query: demo traces are excluded from aggregates', () => {
    const demo = rows.filter(r => r.traceId.startsWith('demo-'));
    assert.strictEqual(demo.length, 0, `demo rows leaked into aggregates: ${demo.length}`);
  });

  // 5. INPUT ATTRIBUTION: the cache-key-absent row is flagged unreliable with its
  //    raw tokensIn preserved (nothing is silently rewritten); the row that
  //    carries the cache keys, even as explicit zeros, is trusted as normal.
  check('query: cache-key-absent row is flagged inputUnreliable, raw value kept', () => {
    const bad = rows.find(r => r.traceId === 'trace-inputattr' && r.tokensIn === 900000);
    assert.ok(bad, 'expected the 900000-input row to survive dedupe');
    assert.strictEqual(bad!.inputUnreliable, true, 'cache-key-absent row must be flagged unreliable');
    const good = rows.find(r => r.traceId === 'trace-inputattr' && r.tokensIn === 300);
    assert.ok(good, 'expected the 300-input row to survive dedupe');
    assert.strictEqual(good!.inputUnreliable, false, 'row with explicit-zero cache keys must NOT be flagged');
  });

  // 6. dedupedTokenTotals (the shared basis for /api/costs, harness and session
  //    reports) must exclude the unreliable row's tokensIn from the trace total,
  //    while its tokensOut still counts — only the input dimension was ever wrong.
  //    This is the assertion that would have FAILED before the fix: totals.tokensIn
  //    would have been 900300 instead of 300, a >3000x inflation from one row.
  check('totals: unreliable input is excluded, output is not', () => {
    const totals = dedupedTokenTotals('trace').get('trace-inputattr');
    assert.ok(totals, 'expected a totals entry for trace-inputattr');
    assert.strictEqual(totals!.tokensIn, 300, `expected only the reliable row's 300 in, got ${totals!.tokensIn}`);
    assert.strictEqual(totals!.tokensOut, 4150, `expected 4000+150=4150 out, got ${totals!.tokensOut}`);
  });

  // 7. Grand totals are the hand-computed, deduped RAW figures (dedupedUsageRows
  //    never rewrites tokensIn itself — only downstream consumers apply the
  //    input-attribution correction, checked separately above).
  check('query: grand totals equal the hand-computed deduped figures', () => {
    const totIn = rows.reduce((n, r) => n + r.tokensIn, 0);
    const totOut = rows.reduce((n, r) => n + r.tokensOut, 0);
    // new(1000) + legacy(800+50) + inputattr(900000+300) = 902150 in
    // new(500) + legacy(400+25) + inputattr(4000+150) = 5075 out
    assert.strictEqual(totIn, 902150, `expected 902150 in, got ${totIn}`);
    assert.strictEqual(totOut, 5075, `expected 5075 out, got ${totOut}`);
  });

  const total = passed + failures.length;
  console.log('───────────────────────────────────────────────');
  console.log(`  costDedupeTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failures.length) {
    console.error(`\n  ${failures.length} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// PARENT: set up an isolated temp DB, spawn the worker pointed at it, clean up.
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const DB_PATH = path.join(os.tmpdir(), `csec-costdedupe-${process.pid}-${Date.now()}.db`);
  const cleanup = () => {
    for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
      try { fs.rmSync(f, { force: true }); } catch {}
    }
  };

  const code: number = await new Promise(resolve => {
    const child = spawn(TSX_BIN, [__filename, '--worker'], {
      cwd: REPO_ROOT,
      env: { ...process.env, CLAUDESEC_DB: DB_PATH, CLAUDESEC_WATCH: '0' },
      stdio: 'inherit',
    });
    child.on('exit', c => resolve(c ?? 1));
    child.on('error', () => resolve(1));
  });

  cleanup();
  process.exit(code);
}

if (process.argv.includes('--worker')) {
  runWorker().catch(err => { console.error('[costDedupeTest worker] fatal:', err); process.exit(1); });
} else {
  main().catch(err => { console.error('[costDedupeTest] fatal:', err); process.exit(1); });
}
