/**
 * tests/routeHardeningTest.ts
 *
 * Gate for four input/state defects that all fail SILENTLY — the worst kind for
 * a security tool, because the response still looks like an answer:
 *
 *   1. Copilot assistant messages with no id collapsed into a single span row
 *      (`undefined:llm`) under INSERT OR IGNORE, undercounting tokens.
 *   2. An unparseable ?from / ?to on /api/search dropped the time filter, so a
 *      typo'd date returned the WHOLE table while looking filtered.
 *   3. /api/command-audit accepted a non-string `tool.input` (a JSON object),
 *      risk-scored "[object Object]", and shipped a non-string `command`.
 *   4. The cost aggregates are memoized per state of the spans table; a newly
 *      ingested usage span must be reflected on the very next read.
 *
 * Run via:  npx tsx tests/routeHardeningTest.ts
 *   Exit 0 -> every assertion passed.  Exit 1 -> a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_HOME and CLAUDESEC_DB are pointed at os.tmpdir()
 * BEFORE any server module is imported, so the live ~/.claudesec database is
 * never opened. Both are removed in a finally block.
 */

import assert from 'node:assert';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import express from 'express';
import type { WatcherEvent } from '../server/transcriptWatcher.js';

const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-routehardening-home-'));
const DB_PATH = path.join(TEST_HOME, 'spans.db');
process.env.CLAUDESEC_HOME = TEST_HOME;
process.env.CLAUDESEC_DB = DB_PATH;

const cleanup = () => { try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch {} };
process.on('exit', cleanup);

let passed = 0;
const failures: string[] = [];
const check = async (name: string, fn: () => void | Promise<void>): Promise<void> => {
  try { await fn(); passed++; } catch (err) { failures.push(`${name}: ${(err as Error).message}`); }
};

const msToNano = (ms: number): string => String(BigInt(ms) * 1_000_000n);

async function main(): Promise<void> {
  const { db } = await import('../server/db.js');
  const { registerSearchRoutes } = await import('../server/routes/search.js');
  const { registerCommandAuditRoutes } = await import('../server/routes/commandAudit.js');
  const { dedupedTokenTotals } = await import('../server/routes/costs.js');
  const { startTranscriptWatcher } = await import('../server/transcriptWatcher.js');

  const insertSpan = db.prepare(`
    INSERT OR IGNORE INTO spans (spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano)
    VALUES (@spanId, @traceId, '', @name, 'local', '', @severity, @harness, @attributes, @startNano, @endNano)
  `);
  const seed = (spanId: string, name: string, attrs: Record<string, unknown>, ms: number, opts?: { severity?: string; traceId?: string }) => {
    insertSpan.run({
      spanId, traceId: opts?.traceId ?? 'trace-hardening', name, severity: opts?.severity ?? 'none',
      harness: 'claude-code', attributes: JSON.stringify(attrs),
      startNano: msToNano(ms), endNano: msToNano(ms),
    });
  };

  // ── 1. Copilot records with no usable id ───────────────────────────────────
  // Drive the real watcher over a temp `.copilot` session log so the harness is
  // detected exactly as it is in production.
  const copilotDir = path.join(TEST_HOME, '.copilot', 'session-state', 'session-abc');
  fs.mkdirSync(copilotDir, { recursive: true });
  const records = [
    { type: 'assistant.message', timestamp: '2026-01-01T00:00:00.000Z', data: { outputTokens: 100, model: 'gpt-5' } },            // no id at all
    { type: 'assistant.message', timestamp: '2026-01-01T00:00:01.000Z', id: '', data: { outputTokens: 200, model: 'gpt-5' } },    // empty id
    { type: 'assistant.message', timestamp: '2026-01-01T00:00:02.000Z', id: 'msg-1', data: { outputTokens: 300, model: 'gpt-5' } },
    { type: 'assistant.message', timestamp: '2026-01-01T00:00:03.000Z', id: 'msg-2', data: { outputTokens: 400, model: 'gpt-5' } },
    { type: 'assistant.message', timestamp: '2026-01-01T00:00:04.000Z', id: 7, data: { outputTokens: 500, model: 'gpt-5' } },     // numeric id is usable
  ];
  fs.writeFileSync(path.join(copilotDir, 'log.jsonl'), records.map(r => JSON.stringify(r)).join('\n') + '\n');

  const events: WatcherEvent[] = [];
  const offsets = new Map<string, number>();
  const handle = startTranscriptWatcher({
    roots: [path.join(TEST_HOME, '.copilot', 'session-state')],
    offsets: { get: f => offsets.get(f), set: (f, o) => { offsets.set(f, o); } },
    backfill: true,
    onEvent: e => events.push(e),
  });
  handle.stop();

  const spanIds = events.filter(e => e.kind === 'span').map(e => (e as { span: { spanId: string } }).span.spanId);

  await check('copilot: an id-less assistant.message never mints a span', () => {
    assert.ok(!spanIds.some(id => id.startsWith('undefined')), `got a colliding span id: ${spanIds.join(', ')}`);
    assert.strictEqual(spanIds.length, 3, `expected 3 costed spans (msg-1, msg-2, 7), got ${spanIds.length}: ${spanIds.join(', ')}`);
  });

  await check('copilot: usable ids each get their own span id', () => {
    assert.deepStrictEqual([...spanIds].sort(), ['7:llm', 'msg-1:llm', 'msg-2:llm']);
  });

  await check('copilot: the live usage ticker still counts id-less messages', () => {
    const usage = events.filter(e => e.kind === 'usage') as { tokensOut: number }[];
    const total = usage.reduce((n, u) => n + u.tokensOut, 0);
    assert.strictEqual(total, 1500, `expected 100+200+300+400+500=1500 ticked, got ${total}`);
  });

  // ── 2 & 3. Route-level input handling ──────────────────────────────────────
  seed('cmd-string', 'Bash', { tool: 'bash', command: 'sudo rm -rf /tmp/x' }, 1_760_000_000_000, { severity: 'high' });
  seed('cmd-object', 'Bash', { tool: 'bash', 'tool.input': { command: 'ls', cwd: '/tmp' } }, 1_760_000_001_000);
  seed('old-span', 'Read', { tool: 'Read', file_path: '/tmp/a' }, 1_600_000_000_000);

  const app = express();
  const ctx = {} as unknown as Parameters<typeof registerSearchRoutes>[1];
  registerSearchRoutes(app, ctx);
  registerCommandAuditRoutes(app, ctx);
  const server = await new Promise<http.Server>(resolve => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

  try {
    await check('search: an unparseable ?from is rejected, not ignored', async () => {
      const r = await fetch(`${base}/api/search?q=&from=garbage`);
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
      const body = await r.json() as { error?: string };
      assert.match(String(body.error), /from/i, `expected the error to name the field, got ${body.error}`);
    });

    await check('search: an unparseable ?to is rejected, not ignored', async () => {
      const r = await fetch(`${base}/api/search?q=&to=not-a-date`);
      assert.strictEqual(r.status, 400, `expected 400, got ${r.status}`);
    });

    await check('search: a valid ?from still filters (and does not return everything)', async () => {
      const r = await fetch(`${base}/api/search?q=&from=2025-01-01T00:00:00.000Z`);
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const body = await r.json() as { total: number };
      assert.strictEqual(body.total, 2, `expected the 2 recent spans, got ${body.total}`);
    });

    await check('command-audit: a non-string tool.input is skipped, not stringified', async () => {
      const r = await fetch(`${base}/api/command-audit`);
      assert.strictEqual(r.status, 200, `expected 200, got ${r.status}`);
      const body = await r.json() as { commands: { spanId: string; command: unknown; riskScore: number }[] };
      assert.ok(!body.commands.some(c => c.spanId === 'cmd-object'), 'the object-valued tool.input row leaked into the audit');
      assert.ok(body.commands.every(c => typeof c.command === 'string'), 'a non-string command reached the client');
    });

    await check('command-audit: a real command string is still audited and scored', async () => {
      const r = await fetch(`${base}/api/command-audit`);
      const body = await r.json() as { commands: { spanId: string; riskScore: number }[] };
      const row = body.commands.find(c => c.spanId === 'cmd-string');
      assert.ok(row, 'the string command row is missing');
      assert.ok(row!.riskScore >= 20, `expected sudo to score, got ${row!.riskScore}`);
    });
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }

  // ── 4. Cost memo invalidates the moment a usage span lands ─────────────────
  const usageAttrs = (out: number) => ({
    'gen_ai.request.model': 'claude-sonnet-4-6',
    'gen_ai.response.id': `resp-${out}`,
    'gen_ai.usage.input_tokens': 10,
    'gen_ai.usage.output_tokens': out,
  });
  seed('usage-1:llm', 'llm_request', usageAttrs(50), 1_760_000_002_000);
  const first = dedupedTokenTotals('trace').get('trace-hardening');

  await check('costs: the first read reflects the seeded usage span', () => {
    assert.strictEqual(first?.tokensOut, 50, `expected 50 out, got ${first?.tokensOut}`);
  });

  seed('usage-2:llm', 'llm_request', usageAttrs(70), 1_760_000_003_000);

  await check('costs: a newly ingested usage span invalidates the memo immediately', () => {
    const after = dedupedTokenTotals('trace').get('trace-hardening');
    assert.strictEqual(after?.tokensOut, 120, `expected 50+70=120 after ingest, got ${after?.tokensOut}`);
  });

  db.prepare(`DELETE FROM spans WHERE spanId = 'usage-2:llm'`).run();

  await check('costs: a delete invalidates the memo too', () => {
    const after = dedupedTokenTotals('trace').get('trace-hardening');
    assert.strictEqual(after?.tokensOut, 50, `expected 50 after the delete, got ${after?.tokensOut}`);
  });

  const total = passed + failures.length;
  console.log('───────────────────────────────────────────────');
  console.log(`  routeHardeningTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failures.length > 0) {
    console.error(`\n  ${failures.length} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[routeHardeningTest] fatal:', err);
  process.exit(1);
});
