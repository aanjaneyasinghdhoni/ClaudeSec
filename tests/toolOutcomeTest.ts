/**
 * tests/toolOutcomeTest.ts
 *
 * Guards the tool-outcome capture in server/transcriptWatcher.ts — the step that
 * turns "the agent ran this" into "the agent ran this AND here is what happened".
 *
 * Run via:  npx tsx tests/toolOutcomeTest.ts
 *   Exit 0 → all checks pass.  Exit 1 → at least one failed.
 *
 * The record fixtures below are hand-written reproductions of the shapes real
 * transcripts use — a shell result carries {stdout, stderr, interrupted}, a
 * failed one collapses to a bare "Error: Exit code N…" string, a fetch reports
 * {code, codeText, bytes} — so a harness format change breaks this test rather
 * than silently degrading what we store.
 */

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

// Sandbox the home dir and the database BEFORE any server-side import. The
// watcher itself is side-effect-free, but this test also drives the real
// scrubber, and the enforcement-config mirror in server/index.ts writes under
// CLAUDESEC_HOME at module load. Pointing both at throwaway temp dirs
// guarantees the maintainer's real ~/.claudesec and live spans database are
// never touched. Cleaned up on exit.
const CSEC_TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-outcome-home-'));
process.env.CLAUDESEC_HOME = CSEC_TEST_HOME;
process.env.CLAUDESEC_DB = path.join(CSEC_TEST_HOME, 'spans.db');
const removeTestHome = () => { try { fs.rmSync(CSEC_TEST_HOME, { recursive: true, force: true }); } catch {} };
process.on('exit', removeTestHome);

import { extractToolOutcome, clampOutput, startTranscriptWatcher } from '../server/transcriptWatcher.js';
import type { WatcherEvent, OffsetStore } from '../server/transcriptWatcher.js';
import { scrubAttributes, loadScrubOptions } from '../server/scrub.js';

let failures = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) { console.log(`  ok   ${name}`); return; }
  failures++;
  console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
}

// ---------------------------------------------------------------------------
// Fixtures — the result shapes observed in real transcripts
// ---------------------------------------------------------------------------

const okShell = {
  record: { toolUseResult: { stdout: 'file-a\nfile-b\n', stderr: '', interrupted: false, isImage: false } },
  block:  { type: 'tool_result', tool_use_id: 'toolu_ok', content: 'file-a\nfile-b\n', is_error: false },
};

const failedShell = {
  record: { toolUseResult: 'Error: Exit code 1\n(eval):1: parse error near `>\'' },
  block:  { type: 'tool_result', tool_use_id: 'toolu_bad', content: 'Exit code 1\n(eval):1: parse error near `>\'', is_error: true },
};

const fetchResult = {
  record: { toolUseResult: { bytes: 317120, code: 404, codeText: 'Not Found', durationMs: 5713, url: 'https://example.test/x', result: 'nope' } },
  block:  { type: 'tool_result', tool_use_id: 'toolu_fetch', content: 'nope' },
};

// ---------------------------------------------------------------------------
console.log('\n1. A result is classified, and failure is distinguishable from success');
// ---------------------------------------------------------------------------

const ok = extractToolOutcome(okShell.record, okShell.block);
const bad = extractToolOutcome(failedShell.record, failedShell.block);

check('a successful shell result reads as ok', ok?.status === 'ok', `got ${ok?.status}`);
check('a failed shell result reads as error', bad?.status === 'error', `got ${bad?.status}`);
check('success and failure are not the same value', ok?.status !== bad?.status);
check('the exit code is recovered from the banner', bad?.exitCode === 1, `got ${bad?.exitCode}`);
check('a successful result invents no exit code', ok?.exitCode === undefined, `got ${ok?.exitCode}`);
check('stdout is kept as the output', ok?.output.includes('file-a'), ok?.output);

// `is_error` is absent on roughly half of all real results, and absence always
// means success. Pin that reading down so a future refactor can't invert it.
const noFlag = extractToolOutcome({ toolUseResult: { stdout: 'done' } }, { type: 'tool_result', tool_use_id: 't', content: 'done' });
check('an absent is_error flag reads as success', noFlag?.status === 'ok', `got ${noFlag?.status}`);

// The two real failures (out of ~33k results) that were NOT flagged by is_error
// both opened with an "Error:" string. That fallback must keep working.
const strOnly = extractToolOutcome({ toolUseResult: 'Error: something broke' }, { type: 'tool_result', tool_use_id: 't', content: 'Error: something broke' });
check('an Error string with no is_error flag still reads as error', strOnly?.status === 'error', `got ${strOnly?.status}`);

const fetched = extractToolOutcome(fetchResult.record, fetchResult.block);
check('an HTTP status is recovered from a fetch result', fetched?.httpStatus === 404, `got ${fetched?.httpStatus}`);

// stderr is captured on its own budget, so a failure explanation survives even
// when stdout is the noisy channel.
const withErr = extractToolOutcome(
  { toolUseResult: { stdout: 'partial', stderr: 'permission denied' } },
  { type: 'tool_result', tool_use_id: 't', content: 'partial', is_error: true },
);
check('stderr is captured separately from stdout', withErr?.stderr === 'permission denied', withErr?.stderr);

// A content array (the MCP shape) flattens to its text blocks.
const mcp = extractToolOutcome(
  { toolUseResult: [{ type: 'text', text: '## Pages\n1: about:blank' }] },
  { type: 'tool_result', tool_use_id: 't', content: [{ type: 'text', text: '## Pages\n1: about:blank' }] },
);
check('an MCP content array flattens to text', Boolean(mcp && mcp.output.includes('about:blank')), mcp?.output);

// ---------------------------------------------------------------------------
console.log('\n2. Output is truncated at the cap, and the truncation is declared');
// ---------------------------------------------------------------------------

const huge = 'A'.repeat(50_000) + 'TAIL_MARKER';
const bigOutcome = extractToolOutcome(
  { toolUseResult: { stdout: huge } },
  { type: 'tool_result', tool_use_id: 't', content: huge },
);
check('a 50 KB output is clamped to the 2 KB cap', (bigOutcome?.output.length ?? 0) <= 2048, `len ${bigOutcome?.output.length}`);
check('the clamp is flagged as truncated', bigOutcome?.truncated === true);
check('a truncation marker is present', Boolean(bigOutcome?.output.includes('truncated')), bigOutcome?.output.slice(0, 80));
check('the true pre-clamp size is still recorded', bigOutcome?.outputBytes === huge.length, `got ${bigOutcome?.outputBytes}`);
// The cap is spent on both ends, so the closing lines — where a failure usually
// states itself — are not thrown away.
check('the tail of the output survives the clamp', Boolean(bigOutcome?.output.includes('TAIL_MARKER')));
check('an output under the cap is untouched', extractToolOutcome({ toolUseResult: { stdout: 'short' } }, { type: 'tool_result', tool_use_id: 't', content: 'short' })?.truncated === false);

const clamped = clampOutput('x'.repeat(10_000), 2048);
check('clampOutput never exceeds its cap', clamped.text.length <= 2048, `len ${clamped.text.length}`);
check('clampOutput leaves short text alone', clampOutput('hello', 2048).text === 'hello');

// ---------------------------------------------------------------------------
console.log('\n3. A secret in command OUTPUT is redacted before it is persisted');
// ---------------------------------------------------------------------------

// This is the new egress surface: `env`, `cat ~/.aws/credentials` and `aws sts`
// all take innocuous arguments and return credentials. The outcome attributes
// must survive the same scrub pass as everything else, so build them exactly as
// the watcher does and run the real scrubber over them.
// Deliberately BARE values, not `SECRET=<value>` pairs. The scrubber has a
// generic key=value rule that would redact almost anything on the right of a
// `secret=`, so wrapping them would prove only that the fallback works. Naked
// tokens are what `env` and `aws sts` actually print, and they exercise the
// credential-format catalogue itself.
const SECRETS: Array<[string, string]> = [
  ['AWS access key id', 'AKIAIOSFODNN7EXAMPLE'],
  ['GitHub token', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
  ['Slack token', 'xoxb-EXAMPLE-NOT-A-REAL-TOKEN-000000'],
  ['private key block', '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLI\n-----END RSA PRIVATE KEY-----'],
];
const scrubOpts = loadScrubOptions([]);

for (const [label, secret] of SECRETS) {
  const leaky = extractToolOutcome(
    { toolUseResult: { stdout: `${secret}\n` } },
    { type: 'tool_result', tool_use_id: 't', content: `${secret}\n` },
  );
  const attrs: Record<string, unknown> = {
    tool: 'Bash',
    'claudesec.outcome': leaky?.status,
    'claudesec.outcome.output': leaky?.output,
  };
  const { attrs: scrubbed } = scrubAttributes(attrs, scrubOpts);
  const serialized = JSON.stringify(scrubbed);
  check(`${label} in output is redacted before persistence`, !serialized.includes(secret), serialized.slice(0, 160));
}

// The same must hold for the stderr channel — it is a separate attribute and a
// separate chance to leak.
const STDERR_SECRET = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
const leakyErr = extractToolOutcome(
  { toolUseResult: { stdout: '', stderr: `auth failed for ${STDERR_SECRET}` } },
  { type: 'tool_result', tool_use_id: 't', content: '', is_error: true },
);
const { attrs: scrubbedErr } = scrubAttributes({ 'claudesec.outcome.stderr': leakyErr?.stderr }, scrubOpts);
check('a secret in stderr is redacted', !JSON.stringify(scrubbedErr).includes(STDERR_SECRET), JSON.stringify(scrubbedErr));

// ---------------------------------------------------------------------------
console.log('\n4. A malformed or missing result never costs us the call span');
// ---------------------------------------------------------------------------

const junk: unknown[] = [null, undefined, 42, 'plain string', [], { type: 'tool_result' }];
let threw = '';
for (const j of junk) {
  try { extractToolOutcome({}, j); } catch (err) { threw = String(err); }
}
check('malformed result blocks never throw', threw === '', threw);
check('a result with no payload at all yields no outcome rather than a fabricated one', extractToolOutcome({}, { type: 'tool_result', tool_use_id: 't', content: '' }) === undefined);

// A command that prints nothing still ran. Roughly 3% of real tool calls are
// silent successes — `mv`, a `grep` with no match, a no-op `git add` — and
// dropping them would leave exactly the commands whose effect is invisible as
// the ones with no recorded effect.
const silent = extractToolOutcome(
  { toolUseResult: { stdout: '', stderr: '', interrupted: false, noOutputExpected: true } },
  { type: 'tool_result', tool_use_id: 't', content: '' },
);
check('a silent success is still recorded as an outcome', silent?.status === 'ok', `got ${silent?.status}`);
check('a silent success records zero output bytes honestly', silent?.outputBytes === 0);
check('a result with no toolUseResult still classifies from content', extractToolOutcome({}, { type: 'tool_result', tool_use_id: 't', content: 'output text' })?.status === 'ok');

// ---------------------------------------------------------------------------
console.log('\n5. End to end: a result correlates to its call through the watcher');
// ---------------------------------------------------------------------------

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-outcome-scan-'));
const projDir = path.join(tmpRoot, '.claude', 'projects', 'demo');
fs.mkdirSync(projDir, { recursive: true });
const transcript = path.join(projDir, 'session.jsonl');

const callLine = JSON.stringify({
  timestamp: '2026-01-01T00:00:00.000Z', sessionId: 'sess-1', cwd: '/work', gitBranch: 'main',
  message: { model: 'test-model', content: [{ type: 'tool_use', id: 'toolu_e2e', name: 'Bash', input: { command: 'false' } }] },
});
const resultLine = JSON.stringify({
  timestamp: '2026-01-01T00:00:02.000Z', sessionId: 'sess-1',
  toolUseResult: 'Error: Exit code 3\nboom',
  message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_e2e', content: 'Exit code 3\nboom', is_error: true }] },
});
// An orphan: a result whose call this watcher never saw, which is what a
// mid-file start looks like.
const orphanLine = JSON.stringify({
  timestamp: '2026-01-01T00:00:03.000Z', sessionId: 'sess-1',
  toolUseResult: { stdout: 'orphan output' },
  message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_never_seen', content: 'orphan output' }] },
});
// A call with no result at all — its span must still stand on its own.
const lonelyCall = JSON.stringify({
  timestamp: '2026-01-01T00:00:04.000Z', sessionId: 'sess-1', cwd: '/work',
  message: { content: [{ type: 'tool_use', id: 'toolu_lonely', name: 'Read', input: { file_path: '/etc/hosts' } }] },
});
fs.writeFileSync(transcript, [callLine, resultLine, orphanLine, lonelyCall].join('\n') + '\n');

const events: WatcherEvent[] = [];
const store = new Map<string, number>();
const offsets: OffsetStore = { get: (f) => store.get(f), set: (f, o) => { store.set(f, o); } };
const handle = startTranscriptWatcher({
  roots: [path.join(tmpRoot, '.claude', 'projects')],
  backfill: true,
  pollMs: 1_000_000, rescanMs: 1_000_000,
  offsets,
  onEvent: (e) => events.push(e),
});
handle.stop();

const spans = events.filter((e): e is Extract<WatcherEvent, { kind: 'span' }> => e.kind === 'span');
const call = spans.find(s => s.span.spanId === 'toolu_e2e');
const outcome = spans.find(s => s.span.spanId === 'toolu_e2e:result');
const orphan = spans.find(s => s.span.spanId === 'toolu_never_seen:result');
const lonely = spans.find(s => s.span.spanId === 'toolu_lonely');

check('the call span is still emitted', Boolean(call));
check('an outcome span is emitted for the result', Boolean(outcome));
check('the outcome links to its call via parentId', outcome?.span.parentId === 'toolu_e2e', outcome?.span.parentId);
check('the outcome id derives from the call id (replay is idempotent)', outcome?.span.spanId === 'toolu_e2e:result');
check('the outcome is named after the tool that produced it', outcome?.span.name === 'Bash.result', outcome?.span.name);
check('the outcome records the failure', outcome?.span.rawAttrs['claudesec.outcome'] === 'error');
check('the outcome records the exit code', outcome?.span.rawAttrs['claudesec.outcome.exit_code'] === 3);
check('the outcome shares the call trace', outcome?.span.traceId === 'sess-1');
check('the end event still fires for the call', events.some(e => e.kind === 'end' && e.spanId === 'toolu_e2e'));

check('an orphan result still records an outcome', Boolean(orphan));
check('an orphan outcome falls back to a generic name', orphan?.span.name === 'tool.result', orphan?.span.name);

check('a call with no result still yields a valid span', Boolean(lonely) && lonely?.span.name === 'Read');
check('a call with no result gets no outcome span', !spans.some(s => s.span.spanId === 'toolu_lonely:result'));

// Outcome attributes must stay flat: the scrubber only walks the top level of
// the attribute map, so a nested object would carry output past redaction.
const nested = Object.entries(outcome?.span.rawAttrs ?? {}).filter(([, v]) => v !== null && typeof v === 'object');
check('outcome attributes are flat so the scrubber reaches them', nested.length === 0, nested.map(([k]) => k).join(','));

fs.rmSync(tmpRoot, { recursive: true, force: true });

// ---------------------------------------------------------------------------
console.log('\n6. Ingest cost — the watcher is on a hot path');
// ---------------------------------------------------------------------------

const benchCases = [okShell, failedShell, fetchResult];
const ITER = 20_000;
// Warm the JIT so the measurement reflects steady state, not first-call cost.
for (let i = 0; i < 2000; i++) extractToolOutcome(benchCases[i % 3].record, benchCases[i % 3].block);
const t0 = process.hrtime.bigint();
for (let i = 0; i < ITER; i++) extractToolOutcome(benchCases[i % 3].record, benchCases[i % 3].block);
const perCallUs = Number(process.hrtime.bigint() - t0) / 1000 / ITER;
console.log(`  extractToolOutcome: ${perCallUs.toFixed(2)} µs per result`);
// A generous ceiling: even 100 µs per result would be under 4 ms across a whole
// 2.5 s sweep at the busiest rate these transcripts ever show. This asserts we
// are nowhere near that, and fails loudly if someone drops a pathological
// regex into the extraction path.
check('extraction stays well under the hot-path budget', perCallUs < 100, `${perCallUs.toFixed(2)} µs`);

// ---------------------------------------------------------------------------
console.log(failures === 0 ? '\nAll tool-outcome checks passed.\n' : `\n${failures} tool-outcome check(s) failed.\n`);
process.exit(failures === 0 ? 0 : 1);
