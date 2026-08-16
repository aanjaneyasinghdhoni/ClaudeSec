/**
 * tests/subAgentLineageTest.ts
 *
 * Guards sub-agent lineage capture in server/transcriptWatcher.ts — the step
 * that turns "something ran this command" into "the code-reviewer agent, which
 * the session launched at 14:02, ran this command".
 *
 * Run via:  npx tsx tests/subAgentLineageTest.ts
 *   Exit 0 → all checks pass.  Exit 1 → at least one failed.
 *
 * The fixtures reproduce the shapes real Claude Code transcripts use:
 *   • a delegated agent gets its OWN transcript, `agent-<agentId>.jsonl`, whose
 *     records carry `isSidechain: true` and `agentId` — but reuse the PARENT's
 *     `sessionId`, which is why looking for a cross-trace parent finds nothing;
 *   • the call that launched it reports the id back as `toolUseResult.agentId`,
 *     at LAUNCH time for an async agent and at COMPLETION time for a sync one.
 * The second shape is the ordering hazard the design has to survive, so it gets
 * its own case below rather than being assumed away.
 */

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

// Sandbox the home dir and the database BEFORE any server-side import, so the
// maintainer's real ~/.claudesec and live spans database are never touched.
const CSEC_TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-lineage-home-'));
process.env.CLAUDESEC_HOME = CSEC_TEST_HOME;
process.env.CLAUDESEC_DB = path.join(CSEC_TEST_HOME, 'spans.db');
const removeTestHome = () => { try { fs.rmSync(CSEC_TEST_HOME, { recursive: true, force: true }); } catch {} };
process.on('exit', removeTestHome);

import { startTranscriptWatcher, scanTranscriptLineage } from '../server/transcriptWatcher.js';
import type { WatcherEvent, OffsetStore } from '../server/transcriptWatcher.js';

let failures = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) { console.log(`  ok   ${name}`); return; }
  failures++;
  console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
}

const AGENT_ID    = 'claudesec.agent.id';
const AGENT_TYPE  = 'claudesec.agent.type';
const AGENT_SPAWN = 'claudesec.agent.spawned_id';

const SESSION   = 'sess-lineage-1';
const ASYNC_ID  = 'a1b2c3d4e5f6a7b8c';   // launch reported before the agent runs
const SYNC_ID   = 'b9c8d7e6f5a4b3c2d';   // launch reported only once it finishes
const NESTED_ID = 'c0d1e2f3a4b5c6d7e';   // launched BY the async agent

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'csec-lineage-scan-'));
const projectsRoot = path.join(tmpRoot, '.claude', 'projects');
const projDir = path.join(projectsRoot, 'demo');
fs.mkdirSync(projDir, { recursive: true });

const line = (o: unknown) => JSON.stringify(o) + '\n';

/** An assistant record in the main session (never a sidechain). */
const mainRecord = (ts: string, content: unknown[], extra: Record<string, unknown> = {}) =>
  line({ timestamp: ts, sessionId: SESSION, cwd: '/work', gitBranch: 'main', isSidechain: false, message: { model: 'test-model', content }, ...extra });

/** A record inside a delegated agent's own transcript. */
const agentRecord = (ts: string, agentId: string, content: unknown[], extra: Record<string, unknown> = {}) =>
  line({
    timestamp: ts, sessionId: SESSION, cwd: '/work', gitBranch: 'main',
    isSidechain: true, agentId, attributionAgent: 'code-reviewer',
    message: { model: 'test-model', content }, ...extra,
  });

const events: WatcherEvent[] = [];
const store = new Map<string, number>();
const offsets: OffsetStore = { get: (f) => store.get(f), set: (f, o) => { store.set(f, o); } };

/** Sweep the tree once, exactly as a live rescan does. */
function sweep(): void {
  const handle = startTranscriptWatcher({
    roots: [projectsRoot],
    backfill: true,
    pollMs: 1_000_000, rescanMs: 1_000_000,
    offsets,
    onEvent: (e) => events.push(e),
  });
  handle.stop();
}

const spanFor = (spanId: string) =>
  events.find((e): e is Extract<WatcherEvent, { kind: 'span' }> => e.kind === 'span' && e.span.spanId === spanId)?.span;

// ---------------------------------------------------------------------------
console.log('\n1. An async launch is recorded before the agent runs, so its spans parent directly');
// ---------------------------------------------------------------------------

// Pass one: only the parent session exists. This is the live ordering — the
// launch record is written the moment the agent starts, long before it acts.
const sessionFile = path.join(projDir, `${SESSION}.jsonl`);
fs.writeFileSync(sessionFile, [
  mainRecord('2026-01-01T00:00:00.000Z', [
    { type: 'tool_use', id: 'toolu_launch_async', name: 'Agent', input: { description: 'review the diff', subagent_type: 'code-reviewer', prompt: 'review' } },
  ]),
  line({
    timestamp: '2026-01-01T00:00:01.000Z', sessionId: SESSION, isSidechain: false,
    toolUseResult: { isAsync: true, status: 'async_launched', agentId: ASYNC_ID, description: 'review the diff' },
    message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_launch_async', content: 'launched' }] },
  }),
  // A plain call the OPERATOR made. It must never pick up agent attribution.
  mainRecord('2026-01-01T00:00:02.000Z', [
    { type: 'tool_use', id: 'toolu_operator', name: 'Bash', input: { command: 'git status' } },
  ]),
].join(''));
sweep();

const launchResult = spanFor('toolu_launch_async:result');
check('the launch call span is emitted', Boolean(spanFor('toolu_launch_async')));
check('the launch result names the agent it started', launchResult?.rawAttrs[AGENT_SPAWN] === ASYNC_ID, String(launchResult?.rawAttrs[AGENT_SPAWN]));
check('the launch result hangs off the call, so the spawning call is one hop away', launchResult?.parentId === 'toolu_launch_async', launchResult?.parentId);
check('the requested agent kind is recorded on the call', spanFor('toolu_launch_async')?.rawAttrs['claudesec.agent.spawned_type'] === 'code-reviewer');
check('an operator tool call carries no agent attribution', spanFor('toolu_operator')?.rawAttrs[AGENT_ID] === undefined);
check('an operator tool call is not parented to a sub-agent', spanFor('toolu_operator')?.parentId === '');

// Pass two: the agent's own transcript appears and starts working.
fs.writeFileSync(path.join(projDir, `agent-${ASYNC_ID}.jsonl`), [
  agentRecord('2026-01-01T00:00:03.000Z', ASYNC_ID, [
    { type: 'tool_use', id: 'toolu_child_read', name: 'Read', input: { file_path: '/work/src/a.ts' } },
  ], { message: { model: 'test-model', id: 'msg_child_1', usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: 'tool_use', id: 'toolu_child_read', name: 'Read', input: { file_path: '/work/src/a.ts' } }] } }),
  agentRecord('2026-01-01T00:00:04.000Z', ASYNC_ID, [
    { type: 'tool_result', tool_use_id: 'toolu_child_read', content: 'export const a = 1;' },
  ], { toolUseResult: { file: { filePath: '/work/src/a.ts' } } }),
  // The sub-agent delegates further — lineage has to survive more than one level.
  agentRecord('2026-01-01T00:00:05.000Z', ASYNC_ID, [
    { type: 'tool_use', id: 'toolu_launch_nested', name: 'Agent', input: { description: 'check types', subagent_type: 'type-checker', prompt: 'check' } },
  ]),
  line({
    timestamp: '2026-01-01T00:00:06.000Z', sessionId: SESSION, isSidechain: true, agentId: ASYNC_ID,
    toolUseResult: { isAsync: true, status: 'async_launched', agentId: NESTED_ID, description: 'check types' },
    message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_launch_nested', content: 'launched' }] },
  }),
].join(''));
sweep();

const childCall = spanFor('toolu_child_read');
check('a sub-agent tool call records which agent made it', childCall?.rawAttrs[AGENT_ID] === ASYNC_ID, String(childCall?.rawAttrs[AGENT_ID]));
check('a sub-agent tool call records the agent kind', childCall?.rawAttrs[AGENT_TYPE] === 'code-reviewer', String(childCall?.rawAttrs[AGENT_TYPE]));
check('a sub-agent tool call is parented to the call that launched the agent', childCall?.parentId === 'toolu_launch_async', childCall?.parentId);
check('the sub-agent still shares its parent session, as the harness writes it', childCall?.traceId === SESSION, childCall?.traceId);
check("a sub-agent's model call is attributed to it, so cost follows delegation", spanFor('msg_child_1:llm')?.rawAttrs[AGENT_ID] === ASYNC_ID);
check("a sub-agent's tool result is attributed to it", spanFor('toolu_child_read:result')?.rawAttrs[AGENT_ID] === ASYNC_ID);
check('a nested launch is recorded by the agent that made it', spanFor('toolu_launch_nested:result')?.rawAttrs[AGENT_SPAWN] === NESTED_ID);
check('the nested launch call is itself attributed to the launching agent', spanFor('toolu_launch_nested')?.rawAttrs[AGENT_ID] === ASYNC_ID);

// ---------------------------------------------------------------------------
console.log('\n2. A synchronous agent reports its id only at the end — attribution must not depend on that');
// ---------------------------------------------------------------------------

// The hazard: this agent's spans are written BEFORE anything states which call
// spawned it, so `parentId` cannot be filled in at ingest. The span still has
// to say which agent produced it, or the edge is lost for good.
fs.writeFileSync(path.join(projDir, `agent-${SYNC_ID}.jsonl`), [
  agentRecord('2026-01-01T00:01:00.000Z', SYNC_ID, [
    { type: 'tool_use', id: 'toolu_sync_bash', name: 'Bash', input: { command: 'pnpm lint' } },
  ]),
].join(''));
sweep();

const syncCall = spanFor('toolu_sync_bash');
check('an unlaunched-yet agent still records which agent made the call', syncCall?.rawAttrs[AGENT_ID] === SYNC_ID, String(syncCall?.rawAttrs[AGENT_ID]));
check('no parent is invented when the launch is not yet known', syncCall?.parentId === '', syncCall?.parentId);

// The launch record lands later, when the agent finishes.
fs.appendFileSync(sessionFile, [
  mainRecord('2026-01-01T00:01:10.000Z', [
    { type: 'tool_use', id: 'toolu_launch_sync', name: 'Agent', input: { description: 'lint', subagent_type: 'linter', prompt: 'lint' } },
  ]),
  line({
    timestamp: '2026-01-01T00:01:11.000Z', sessionId: SESSION, isSidechain: false,
    toolUseResult: { agentType: 'linter', status: 'completed', agentId: SYNC_ID, totalDurationMs: 900, content: [{ type: 'text', text: 'clean' }] },
    message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_launch_sync', content: 'clean' }] },
  }),
].join(''));
sweep();

check('the late launch record still names the agent it started', spanFor('toolu_launch_sync:result')?.rawAttrs[AGENT_SPAWN] === SYNC_ID);
// Both halves of the edge are now on disk under keys that join, which is what
// lets the graph place this agent even though its spans were written first.
check(
  'the two halves of the late edge are recoverable by joining on the agent id',
  spanFor('toolu_sync_bash')?.rawAttrs[AGENT_ID] === spanFor('toolu_launch_sync:result')?.rawAttrs[AGENT_SPAWN],
);

// ---------------------------------------------------------------------------
console.log('\n3. Lineage can be rebuilt from the transcripts alone, without touching stored spans');
// ---------------------------------------------------------------------------

const recovered = scanTranscriptLineage([projectsRoot]);
check('the recovery scan reads the transcripts it was pointed at', recovered.filesScanned >= 3, `scanned ${recovered.filesScanned}`);
check('it maps a sub-agent tool call to its agent', recovered.agentBySpanId.get('toolu_child_read') === ASYNC_ID);
check('it maps a sub-agent result span to its agent', recovered.agentBySpanId.get('toolu_child_read:result') === ASYNC_ID);
check('it maps a sub-agent model call to its agent', recovered.agentBySpanId.get('msg_child_1:llm') === ASYNC_ID);
check('it maps an agent to the call that launched it', recovered.spawnCallByAgentId.get(ASYNC_ID) === 'toolu_launch_async');
check('it recovers the late/synchronous edge too', recovered.spawnCallByAgentId.get(SYNC_ID) === 'toolu_launch_sync');
check('it recovers a nested launch', recovered.spawnCallByAgentId.get(NESTED_ID) === 'toolu_launch_nested');
check('it records the agent kind', recovered.typeByAgentId.get(ASYNC_ID) === 'code-reviewer');
check('it never attributes an operator call to an agent', !recovered.agentBySpanId.has('toolu_operator'));
check('it never attributes a launch call to the agent it launched', recovered.agentBySpanId.get('toolu_launch_nested') === ASYNC_ID);

// The span ids the scan produces must be the ones the watcher actually wrote,
// or the join lands on nothing. Assert that against the live watcher output
// rather than against a second copy of the id-building rules.
const emittedIds = new Set(
  events.filter((e): e is Extract<WatcherEvent, { kind: 'span' }> => e.kind === 'span').map(e => e.span.spanId),
);
const unmatched = [...recovered.agentBySpanId.keys()].filter(id => !emittedIds.has(id));
check('every recovered span id matches one the watcher emitted', unmatched.length === 0, unmatched.join(','));

// ---------------------------------------------------------------------------
console.log('\n4. A malformed transcript costs its own lineage and nothing else');
// ---------------------------------------------------------------------------

fs.writeFileSync(path.join(projDir, 'agent-broken.jsonl'), '{"agentId": "trunc' + '\n');
let threw = '';
let afterBreak: ReturnType<typeof scanTranscriptLineage> | undefined;
try { afterBreak = scanTranscriptLineage([projectsRoot]); } catch (err) { threw = String(err); }
check('a truncated transcript never throws', threw === '', threw);
check('lineage from the intact transcripts survives', afterBreak?.spawnCallByAgentId.get(ASYNC_ID) === 'toolu_launch_async');
check('a missing root is not an error', scanTranscriptLineage([path.join(tmpRoot, 'nope')]).filesScanned === 0);

fs.rmSync(tmpRoot, { recursive: true, force: true });

// ---------------------------------------------------------------------------
console.log(failures === 0 ? '\nAll sub-agent lineage checks passed.\n' : `\n${failures} sub-agent lineage check(s) failed.\n`);
process.exit(failures === 0 ? 0 : 1);
