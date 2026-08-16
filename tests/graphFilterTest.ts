/**
 * tests/graphFilterTest.ts
 *
 * Gate for GET /api/graph's server-side filtering.
 *
 * The Timeline used to filter client-side over whatever /api/graph happened to
 * return — the most-recent GRAPH_LIMIT spans, globally, with no filter applied
 * at all. On a database with many repos that "most recent" window can easily
 * never contain a given repo's spans, so filtering to it produced an empty
 * timeline that looked like a bug in the filter rather than what it actually
 * was: data the client never fetched. This test seeds a DB shaped exactly like
 * that — a "noise" repo whose spans are all newer than a small GRAPH_LIMIT, and
 * a "target" repo whose spans are all older — and asserts that filtering by
 * repo (and severity, harness, time range, and free text) reaches the target
 * repo's spans directly, rather than intersecting them with a recency window
 * that never contained them. It also pins the windowed/shown/total honesty
 * contract and proves (via EXPLAIN QUERY PLAN on a second connection) that the
 * filtered queries seek an index instead of scanning the table.
 *
 * Run via:  npx tsx tests/graphFilterTest.ts
 *   Exit 0  -> every assertion passed.   Exit 1  -> a failure (or boot failure).
 *
 * DB DISCIPLINE: the child server uses CLAUDESEC_DB under os.tmpdir(), seeded by
 * this test and removed in a finally block. CLAUDESEC_WATCH=0 keeps it off host
 * transcripts. The real ~/.claudesec DB is NEVER opened or touched.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'index.ts');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

const PORT = 3220;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(os.tmpdir(), `csec-graphfiltertest-${process.pid}-${Date.now()}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-graphfiltertest-home-'));

// Small on purpose: with a real-sized cap (2000) this scenario needs 2000+
// noise spans to reproduce the bug. Five is enough to prove the same defect
// and its fix without a slow seed.
const GRAPH_LIMIT = 5;

const TARGET_REPO = '/Users/***/code/alpha/alpha-service'; // scrubbed-shaped, matched exactly
const NOISE_REPO = '/Users/***/code/beta/noise-repo';
const NOISE_COUNT = 4000; // large enough that SQLite's planner favors an index over a scan (mirrors spansIndexPlanTest.ts)

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${(err as Error).message}`);
  }
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function waitForServer(timeoutMs: number, earlyExit?: () => string | null): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const dead = earlyExit?.();
    if (dead) throw new Error(`server failed to start: ${dead}`);
    try {
      const r = await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(1500) });
      if (r.status >= 200 && r.status < 500) return;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`server did not become ready on ${BASE} within ${timeoutMs}ms`);
}

function cleanupDb(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group gone */ }
  try { child.kill('SIGKILL'); } catch { /* dead */ }
}

async function waitForPortFree(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(`${BASE}/api/spans`, { signal: AbortSignal.timeout(500) });
    } catch { return; }
    await sleep(150);
  }
}

// ---------------------------------------------------------------------------
// Seeding — second connection on the server's own committed schema, mirroring
// tests/reposRouteTest.ts. Every span has a distinctive `name` prefix
// ('target-' vs 'noise-') so assertions can identify provenance straight off
// the graph payload's node.data.label without inspecting internals.
// ---------------------------------------------------------------------------

const INSERT_COLS = 'spanId, traceId, parentId, name, protocol, reason, severity, harness, attributes, startNano, endNano, repo';

interface TargetSpanSpec {
  name: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  harness: 'codex' | 'claude-code';
}

// Ancient on purpose (2023) — well outside any time-range filter under test,
// and always older than the noise spans below, so an unfiltered / recency-
// windowed read never reaches these without the repo filter actually working.
const TARGET_BASE_NANO = 1_700_000_000_000_000_000n;

const TARGET_SPANS: TargetSpanSpec[] = [
  { name: 'tool_call/target-0',                  severity: 'high', harness: 'codex' },
  { name: 'tool_call/target-1',                  severity: 'high', harness: 'claude-code' },
  { name: 'tool_call/target-2',                  severity: 'none', harness: 'codex' },
  { name: 'tool_call/target-3',                  severity: 'none', harness: 'claude-code' },
  { name: 'tool_call/target-4',                  severity: 'low',  harness: 'codex' },
  { name: 'tool_call/target-5',                  severity: 'low',  harness: 'claude-code' },
  { name: 'tool_call/target-6',                  severity: 'none', harness: 'codex' },
  { name: 'tool_call/target-uniquemarker-7',     severity: 'none', harness: 'claude-code' },
];
const TARGET_HIGH_COUNT = TARGET_SPANS.filter(s => s.severity === 'high').length; // 2
const TARGET_CODEX_COUNT = TARGET_SPANS.filter(s => s.harness === 'codex').length; // 4

function seedDb(): void {
  const dbh = new Database(DB_PATH);
  // The server may write its own bootstrap span(s) on startup; start clean so
  // counts below are exact and reproducible.
  dbh.prepare('DELETE FROM spans').run();

  const insert = dbh.prepare(`INSERT INTO ${'spans'} (${INSERT_COLS}) VALUES (?, ?, '', ?, 'otlp', '', ?, ?, '{}', ?, ?, ?)`);

  const seedTarget = dbh.transaction(() => {
    TARGET_SPANS.forEach((s, i) => {
      const start = String(TARGET_BASE_NANO + BigInt(i) * 1_000_000_000n);
      const end = String(TARGET_BASE_NANO + BigInt(i) * 1_000_000_000n + 500_000_000n);
      insert.run(`target-span-${i}`, `target-trace-${i}`, s.name, s.severity, s.harness, start, end, TARGET_REPO);
    });
  });
  seedTarget();

  // Noise: real "now"-based timestamps, always more recent than every target
  // span, all severity 'none' / harness 'claude-code' so they never satisfy
  // the severity=high, harness=codex, or repo=target filters under test.
  const nowNano = BigInt(Date.now()) * 1_000_000n;
  const seedNoise = dbh.transaction((n: number) => {
    for (let i = 0; i < n; i++) {
      const start = String(nowNano - BigInt(i));
      const end = String(nowNano - BigInt(i) + 1_000_000n);
      insert.run(`noise-span-${i}`, `noise-trace-${i % 50}`, `tool_call/noise-${i}`, 'none', 'claude-code', start, end, NOISE_REPO);
    }
  });
  seedNoise(NOISE_COUNT);

  dbh.close();
}

interface GraphNode { id: string; data: { label?: string; severity?: string; harness?: string } }
interface GraphPayload {
  nodes: GraphNode[];
  edges: unknown[];
  windowed?: boolean;
  shown?: number;
  total?: number;
  limit?: number;
}

const nonRoot = (p: GraphPayload) => p.nodes.filter(n => n.id !== 'agent' && n.id !== 'codex' && n.id !== 'claude-code');
const labelsOf = (p: GraphPayload) => nonRoot(p).map(n => String(n.data.label ?? ''));

async function getGraph(qs: string): Promise<GraphPayload> {
  const r = await fetch(`${BASE}/api/graph${qs}`);
  assert.strictEqual(r.status, 200, `${qs}: expected 200, got ${r.status}`);
  return r.json() as Promise<GraphPayload>;
}

async function main(): Promise<void> {
  let child: ChildProcess | null = null;
  try {
    child = spawn(TSX_BIN, [SERVER_ENTRY], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        CLAUDESEC_DB: DB_PATH,
        // Keep the child off the operator's real ~/.claudesec: booting the
        // server mirrors its hook artifacts (enforce-config, protected-paths,
        // the rule snapshot, the control-plane pairing key) into CLAUDESEC_HOME.
        CLAUDESEC_HOME: HOME_DIR,
        CLAUDESEC_PORT: String(PORT),
        PORT: String(PORT),
        CLAUDESEC_HOST: '127.0.0.1',
        CLAUDESEC_WATCH: '0',
        CLAUDESEC_TRUST_LOCAL: '',
        CLAUDESEC_GRAPH_LIMIT: String(GRAPH_LIMIT),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    });

    let serverLog = '';
    let exitInfo: string | null = null;
    child.stdout?.on('data', d => { serverLog += String(d); });
    child.stderr?.on('data', d => { serverLog += String(d); });
    child.on('exit', (code, sig) => { exitInfo = `child exited early (code=${code}, signal=${sig})`; });

    await waitForServer(30_000, () => exitInfo).catch(err => {
      throw new Error(`${err.message}\n--- server output ---\n${serverLog.slice(-2000)}`);
    });

    seedDb();

    // ── The bug, reproduced ──────────────────────────────────────────────
    await check('unfiltered /api/graph is the recency window, not the whole DB (the defect this fixes)', async () => {
      const p = await getGraph('');
      assert.strictEqual(p.shown, GRAPH_LIMIT, `expected shown=${GRAPH_LIMIT}, got ${p.shown}`);
      assert.strictEqual(p.total, NOISE_COUNT + TARGET_SPANS.length, `expected total=${NOISE_COUNT + TARGET_SPANS.length}, got ${p.total}`);
      assert.strictEqual(p.windowed, true, 'expected windowed=true');
      // Every span in the window is noise — the target repo's older spans
      // are unreachable without a filter that reaches past the window.
      assert.ok(labelsOf(p).every(l => l.startsWith('tool_call/noise-')),
        `expected only noise spans in the unfiltered window, got: ${labelsOf(p).join(', ')}`);
    });

    // ── The fix: each filter axis reaches the target repo's own spans ─────
    await check('repo filter returns the target repo\'s own spans, not an intersection with the recency window', async () => {
      const p = await getGraph(`?repo=${encodeURIComponent(TARGET_REPO)}`);
      assert.strictEqual(p.total, TARGET_SPANS.length, `expected total=${TARGET_SPANS.length}, got ${p.total}`);
      assert.strictEqual(p.shown, GRAPH_LIMIT, `expected shown=${GRAPH_LIMIT} (still capped), got ${p.shown}`);
      assert.strictEqual(p.windowed, true, 'expected windowed=true — 8 matches, cap is 5');
      assert.ok(labelsOf(p).every(l => l.startsWith('tool_call/target-')),
        `expected only target spans, got: ${labelsOf(p).join(', ')}`);
      assert.ok(labelsOf(p).length > 0, 'must actually return spans, not an empty timeline');
    });

    await check('severity filter (sev=high) returns only high-severity spans', async () => {
      const p = await getGraph('?sev=high');
      assert.strictEqual(p.total, TARGET_HIGH_COUNT, `expected total=${TARGET_HIGH_COUNT}, got ${p.total}`);
      assert.ok(nonRoot(p).every(n => n.data.severity === 'high'),
        `expected only high-severity nodes, got severities: ${nonRoot(p).map(n => n.data.severity).join(', ')}`);
    });

    await check('harness filter (harness=codex) returns only that harness\'s spans', async () => {
      const p = await getGraph('?harness=codex');
      assert.strictEqual(p.total, TARGET_CODEX_COUNT, `expected total=${TARGET_CODEX_COUNT}, got ${p.total}`);
      assert.ok(nonRoot(p).every(n => n.data.harness === 'codex'),
        `expected only codex nodes, got harnesses: ${nonRoot(p).map(n => n.data.harness).join(', ')}`);
    });

    await check('time-range filter (t=1h) reaches the recent noise spans, excludes the 2023 target spans', async () => {
      const p = await getGraph('?t=1h');
      assert.ok(labelsOf(p).length > 0, 'expected some spans within the last hour');
      assert.ok(labelsOf(p).every(l => l.startsWith('tool_call/noise-')),
        `expected only recent (noise) spans under t=1h, got: ${labelsOf(p).join(', ')}`);
    });

    await check('free-text search (q=uniquemarker) finds the one span with that term', async () => {
      const p = await getGraph('?q=uniquemarker');
      assert.ok(labelsOf(p).includes('tool_call/target-uniquemarker-7'),
        `expected to find the marker span, got: ${labelsOf(p).join(', ')}`);
    });

    await check('combined repo+severity narrows past GRAPH_LIMIT with an accurate total', async () => {
      const p = await getGraph(`?repo=${encodeURIComponent(TARGET_REPO)}&sev=high`);
      assert.strictEqual(p.total, TARGET_HIGH_COUNT, `expected total=${TARGET_HIGH_COUNT}, got ${p.total}`);
      assert.strictEqual(p.windowed, false, `2 matches under a cap of ${GRAPH_LIMIT} should not be windowed`);
      assert.ok(nonRoot(p).every(n => n.data.severity === 'high'), 'expected only high-severity nodes');
    });

    // ── EXPLAIN QUERY PLAN: the filtered queries seek an index ────────────
    await check('repo/severity/harness/time filters each seek an index, none scan the table', () => {
      const dbh = new Database(DB_PATH, { readonly: true });
      try {
        const plan = (sql: string, params: unknown[]): string =>
          (dbh.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as { detail: string }[])
            .map(r => r.detail).join(' | ');

        const cases: { label: string; sql: string; params: unknown[]; expect: RegExp }[] = [
          {
            label: 'repo',
            sql: `SELECT * FROM (SELECT * FROM spans WHERE repo IN (?) ORDER BY startNano DESC LIMIT ?) ORDER BY startNano ASC`,
            params: [TARGET_REPO, GRAPH_LIMIT],
            expect: /SEARCH spans USING INDEX idx_spans_repo_sev_start \(repo=\?\)/,
          },
          {
            label: 'severity',
            sql: `SELECT * FROM (SELECT * FROM spans WHERE severity IN (?) ORDER BY startNano DESC LIMIT ?) ORDER BY startNano ASC`,
            params: ['high', GRAPH_LIMIT],
            expect: /SEARCH spans USING INDEX idx_spans_severity_startNano \(severity=\?\)/,
          },
          {
            label: 'harness',
            sql: `SELECT * FROM (SELECT * FROM spans WHERE harness IN (?) ORDER BY startNano DESC LIMIT ?) ORDER BY startNano ASC`,
            params: ['codex', GRAPH_LIMIT],
            expect: /SEARCH spans USING INDEX idx_spans_harness_start_sev \(harness=\?\)/,
          },
          {
            label: 'time',
            sql: `SELECT * FROM (SELECT * FROM spans WHERE startNano >= ? ORDER BY startNano DESC LIMIT ?) ORDER BY startNano ASC`,
            params: [String(TARGET_BASE_NANO), GRAPH_LIMIT],
            expect: /SEARCH spans USING INDEX idx_spans_startNano \(startNano>\?\)/,
          },
        ];

        for (const c of cases) {
          const p = plan(c.sql, c.params);
          assert.match(p, c.expect, `[${c.label}] expected an index seek, got: ${p}`);
          assert.doesNotMatch(p, /SCAN spans\b/, `[${c.label}] must not scan the base table, got: ${p}`);
        }
      } finally {
        dbh.close();
      }
    });
  } finally {
    if (child) {
      killTree(child);
      await waitForPortFree(8_000);
    }
    cleanupDb();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  graphFilterTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[graphFilterTest] fatal:', err);
  cleanupDb();
  process.exit(1);
});
