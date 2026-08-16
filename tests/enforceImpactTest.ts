/**
 * tests/enforceImpactTest.ts
 *
 * Gate for the enforcement impact preview (server/routes/enforceImpact.ts) —
 * the replay that answers "what would enforce mode actually have blocked?"
 * against recorded history.
 *
 * The preview exists to make a re-baselining decision on evidence, so the ways
 * it could quietly mislead are the things worth pinning:
 *
 *   1. THE SPLIT. A rule-engine match only bites once enforce is on; a
 *      catastrophic / self-protection / protected-path match is blocking today,
 *      in monitor mode, already. Collapsing the two into one "N blocked"
 *      headline would misrepresent both, so the split is asserted directly.
 *   2. PER-TOOL SEMANTICS. The replay must derive matchText/targetPath the way
 *      the hook does or it reports enforcement nobody runs: a Read reaches the
 *      floors but is NEVER run against the rule engine, and an Edit is judged on
 *      its path, never its content.
 *   3. DEDUP HONESTY. Repeats must raise `count` without inflating
 *      `distinctCalls`, and the examples kept must be three DIFFERENT commands —
 *      otherwise a rule that fired 900 times on one repeated command reads like
 *      one that caught 900 different things.
 *   4. RANKING ARITHMETIC. share / cumulativeShare / rulesToReach80 / top10Share
 *      are the numbers the whole "these seven rules are 80% of it" argument
 *      rests on.
 *   5. SCRUBBING. The self-protection floor labels itself with an absolute path
 *      built from the real home directory. Nothing returned may carry it.
 *   6. THE HOME UNSCRUB. Spans are scrubbed at ingest, so a recorded path reads
 *      `/Users/***`. Without mapping that back for matching, every home-anchored
 *      floor would silently report zero — the single most misleading failure
 *      this preview could have.
 *
 * Run via:  npx tsx tests/enforceImpactTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB points under os.tmpdir() BEFORE server/db.ts is
 * imported (the route module opens it at load), and the file is removed in a
 * finally block. The real ~/.claudesec database is never opened. The enforcement
 * control-plane paths are redirected under the same temp dir so the maintainer's
 * own protected-path list cannot change the result.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const TMP_DIR = path.join(os.tmpdir(), `csec-impact-${process.pid}-${Date.now()}`);
const DB_PATH = path.join(TMP_DIR, 'spans.db');
fs.mkdirSync(path.join(TMP_DIR, 'hooks'), { recursive: true });
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_WATCH = '0';
// Isolate the control plane: an empty protected-paths list and a monitor config,
// so only the built-in defaults (~/.ssh, ~/.aws/credentials, …) are in play.
process.env.CLAUDESEC_HOME = TMP_DIR;
process.env.CLAUDESEC_PROTECTED_PATHS = path.join(TMP_DIR, 'hooks', 'protected-paths.json');
process.env.CLAUDESEC_ENFORCE_CONFIG = path.join(TMP_DIR, 'hooks', 'enforce-config.json');
fs.writeFileSync(process.env.CLAUDESEC_PROTECTED_PATHS, '[]');
fs.writeFileSync(process.env.CLAUDESEC_ENFORCE_CONFIG, JSON.stringify({ mode: 'monitor' }));

let passed = 0;
let failed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try { await fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function cleanup(): void {
  try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}
}

const HOME = os.homedir();

/** A candidate row as SQLite would project it. */
function row(
  tool: string,
  fields: { command?: string; target?: string; url?: string; atMs?: number },
) {
  return {
    tool,
    command: fields.command ?? null,
    target: fields.target ?? null,
    url: fields.url ?? null,
    startNano: String(BigInt(fields.atMs ?? Date.parse('2026-07-01T00:00:00Z')) * 1_000_000n),
  };
}

async function main(): Promise<void> {
  try {
    const { replayImpact } = await import('../server/routes/enforceImpact.js');
    type Rules = Parameters<typeof replayImpact>[1];

    // A tiny, unambiguous rule set. `PATH_RULE` matches a path shape so the
    // Read-vs-Edit asymmetry can be tested with one rule; the others are plain
    // command substrings that no catastrophic pattern also claims.
    const PATH_RULE = { re: /\/tmp\/ruletarget\b/, label: 'Rule: ruletarget path', severity: 'high' };
    const rules: Rules = [
      { re: /\bharmless-alpha\b/, label: 'Rule: alpha', severity: 'high' },
      { re: /\bharmless-beta\b/, label: 'Rule: beta', severity: 'medium' },
      PATH_RULE,
    ];

    // ── 1. The split: rule match vs mode-independent floor ────────────────
    await check('a rule match is enforce-only, not counted as blocking today', () => {
      const r = replayImpact([row('Bash', { command: 'harmless-alpha --now' })], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total, 1, 'rule match belongs to the enforce-only group');
      assert.strictEqual(r.blocksTodayAnyMode.total, 0, 'a rule match must not be reported as already blocking');
      assert.strictEqual(r.wouldBlockInEnforce.rules[0].label, 'Rule: alpha');
    });

    await check('a catastrophic match is reported as blocking today, in every mode', () => {
      const r = replayImpact([row('Bash', { command: 'rm -rf --no-preserve-root /' })], rules);
      assert.strictEqual(r.blocksTodayAnyMode.total, 1, 'the catastrophic floor blocks regardless of mode');
      assert.strictEqual(r.wouldBlockInEnforce.total, 0, 'a floor hit is not a forecast');
    });

    await check('the two groups never double-count one call', () => {
      // A command that trips BOTH a rule and the catastrophic floor is a single
      // call with a single verdict — the floor wins, as it does in the hook.
      const r = replayImpact([row('Bash', { command: 'harmless-alpha; rm -rf --no-preserve-root /' })], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total + r.blocksTodayAnyMode.total, 1);
      assert.strictEqual(r.blocksTodayAnyMode.total, 1, 'the floor is evaluated first, as in the hook');
    });

    // ── 2. Per-tool semantics must mirror the hook ─────────────────────────
    await check('a Read is never run against the rule engine', () => {
      const r = replayImpact([row('Read', { target: '/tmp/ruletarget/notes.txt' })], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total, 0,
        'reading a file is not executing it — the hook leaves a read\'s matchText empty');
      assert.strictEqual(r.scanned.evaluated, 1, 'the read is still evaluated (the floors see its target)');
    });

    await check('an Edit is judged on its path, and that path does reach the rule engine', () => {
      const r = replayImpact([row('Edit', { target: '/tmp/ruletarget/notes.txt' })], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total, 1);
      assert.strictEqual(r.wouldBlockInEnforce.rules[0].label, PATH_RULE.label);
    });

    await check('a WebFetch to link-local metadata is a mode-independent floor', () => {
      const r = replayImpact([row('WebFetch', { url: 'http://169.254.169.254/latest/meta-data/' })], rules);
      assert.strictEqual(r.blocksTodayAnyMode.total, 1, 'cloud-metadata is blocked in monitor too');
      assert.match(r.blocksTodayAnyMode.rules[0].label, /metadata/);
    });

    await check('a WebFetch to an RFC1918 host only bites under enforce', () => {
      const r = replayImpact([row('WebFetch', { url: 'http://10.1.2.3/admin' })], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total, 1);
      assert.strictEqual(r.blocksTodayAnyMode.total, 0);
    });

    await check('a public WebFetch and a URL-less WebSearch are not blocks', () => {
      const r = replayImpact([
        row('WebFetch', { url: 'https://example.com/docs' }),
        row('WebSearch', {}),
      ], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total + r.blocksTodayAnyMode.total, 0);
      assert.strictEqual(r.scanned.evaluated, 1, 'a WebSearch with no URL has nothing to evaluate');
    });

    await check('a tool the hook is not registered for is ignored entirely', () => {
      const r = replayImpact([row('Grep', { command: 'harmless-alpha' })], rules);
      assert.strictEqual(r.scanned.evaluated, 0, 'replaying it would invent enforcement nobody runs');
    });

    // ── 3. Dedup honesty ───────────────────────────────────────────────────
    await check('repeats raise count but not distinctCalls, and examples stay distinct', () => {
      const rows = [
        ...Array.from({ length: 5 }, () => row('Bash', { command: 'harmless-alpha one' })),
        row('Bash', { command: 'harmless-alpha two' }),
        row('Bash', { command: 'harmless-alpha three' }),
        row('Bash', { command: 'harmless-alpha four' }),
      ];
      const r = replayImpact(rows, rules);
      const rule = r.wouldBlockInEnforce.rules[0];
      assert.strictEqual(rule.count, 8, 'every occurrence counts');
      assert.strictEqual(rule.distinctCalls, 4, 'five identical commands are one distinct call');
      assert.strictEqual(rule.examples.length, 3, 'examples are capped');
      assert.strictEqual(new Set(rule.examples.map(e => e.text)).size, 3,
        'three different commands, not the same one three times');
      assert.ok(r.scanned.cacheHitRate > 0, 'the repeats were answered from the memo');
    });

    // ── 4. Ranking arithmetic ──────────────────────────────────────────────
    await check('rules rank by count with correct share, cumulative share and 80% depth', () => {
      const rows = [
        ...Array.from({ length: 8 }, (_, i) => row('Bash', { command: `harmless-alpha ${i}` })),
        row('Bash', { command: 'harmless-beta x' }),
        row('Edit', { target: '/tmp/ruletarget/y' }),
      ];
      const r = replayImpact(rows, rules);
      const g = r.wouldBlockInEnforce;
      assert.strictEqual(g.total, 10);
      assert.strictEqual(g.rules[0].label, 'Rule: alpha', 'most frequent first');
      assert.strictEqual(g.rules[0].count, 8);
      assert.ok(Math.abs(g.rules[0].share - 80) < 1e-9, 'share is a percentage of the group');
      assert.ok(Math.abs(g.rules[0].cumulativeShare - 80) < 1e-9);
      assert.ok(Math.abs(g.rules[g.rules.length - 1].cumulativeShare - 100) < 1e-9,
        'the last rule always closes at 100%');
      assert.strictEqual(g.rulesToReach80, 1, 'one rule already accounts for 80%');
      assert.ok(Math.abs(g.top10Share - 100) < 1e-9, 'three rules are all inside the top ten');
      assert.deepStrictEqual(g.bySeverity, { high: 9, medium: 1 },
        'severity counts come from the matching rule, not the span');
    });

    await check('an empty window produces zeroed groups rather than sentinels', () => {
      const r = replayImpact([], rules);
      assert.strictEqual(r.wouldBlockInEnforce.total, 0);
      assert.strictEqual(r.wouldBlockInEnforce.rulesToReach80, 0);
      assert.strictEqual(r.wouldBlockInEnforce.top10Share, 0);
      assert.strictEqual(r.oldestCallMs, null);
      assert.strictEqual(r.newestCallMs, null);
    });

    // ── 5. The home unscrub, and no home leak on the way out ───────────────
    await check('the scrubbed home placeholder still trips a home-anchored floor', () => {
      // This is what a recorded span actually looks like: the home directory has
      // already been replaced by the scrubber. Matching it literally would find
      // nothing, and the protected-path floor would report a false zero.
      const r = replayImpact([row('Read', { target: '/Users/***/.ssh/id_rsa' })], rules);
      assert.strictEqual(r.blocksTodayAnyMode.total, 1,
        'reading an SSH key is blocked today — the placeholder must be mapped back for matching');
      assert.match(r.blocksTodayAnyMode.rules[0].label, /SSH keys/);
    });

    await check('an unscrubbed real home path trips the same floor', () => {
      const r = replayImpact([row('Read', { target: path.join(HOME, '.ssh', 'id_rsa') })], rules);
      assert.strictEqual(r.blocksTodayAnyMode.total, 1);
    });

    await check('a .env.example template is not treated as a dotenv secret', () => {
      const r = replayImpact([row('Read', { target: '/Users/***/proj/.env.example' })], rules);
      assert.strictEqual(r.blocksTodayAnyMode.total, 0, 'committed templates must stay readable');
    });

    await check('nothing returned carries the real home directory', () => {
      const r = replayImpact([
        row('Read', { target: '/Users/***/.ssh/id_rsa' }),
        row('Write', { target: path.join(HOME, '.claude', 'settings.json') }),
      ], rules);
      const emitted = JSON.stringify([r.wouldBlockInEnforce, r.blocksTodayAnyMode]);
      assert.ok(!emitted.includes(HOME),
        `labels and examples must be scrubbed on the way out; found ${HOME} in the response`);
      assert.ok(r.blocksTodayAnyMode.total >= 1, 'the self-protection floor still fired');
    });

    // ── 6. Bookkeeping ─────────────────────────────────────────────────────
    await check('per-tool tallies and the evidence window reflect what was seen', () => {
      const early = Date.parse('2026-06-01T00:00:00Z');
      const late = Date.parse('2026-07-15T00:00:00Z');
      const r = replayImpact([
        row('Bash', { command: 'harmless-alpha', atMs: late }),
        row('Bash', { command: 'nothing to see here', atMs: early }),
        row('Read', { target: '/tmp/plain.txt', atMs: late }),
      ], rules);
      assert.deepStrictEqual(r.scanned.byTool.Bash, { evaluated: 2, blocked: 1 });
      assert.deepStrictEqual(r.scanned.byTool.Read, { evaluated: 1, blocked: 0 });
      assert.strictEqual(r.scanned.candidateRows, 3);
      assert.strictEqual(r.oldestCallMs, early);
      assert.strictEqual(r.newestCallMs, late);
    });

    await check('an empty rule set still reports the mode-independent floors', () => {
      // The floors are not rules and must not disappear when the snapshot does —
      // this is the fail-open case (an unreadable rules-enforcement.json).
      const r = replayImpact([
        row('Bash', { command: 'harmless-alpha' }),
        row('Bash', { command: 'rm -rf --no-preserve-root /' }),
      ], []);
      assert.strictEqual(r.wouldBlockInEnforce.total, 0, 'no rules, no rule matches');
      assert.strictEqual(r.blocksTodayAnyMode.total, 1, 'the floor is independent of the snapshot');
    });
  } finally {
    cleanup();
  }

  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  enforceImpactTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[enforceImpactTest] fatal:', err);
  cleanup();
  process.exit(1);
});
