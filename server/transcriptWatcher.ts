import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface IngestInput {
  spanId: string;
  traceId: string;
  parentId: string;
  name: string;
  rawAttrs: Record<string, unknown>;
  harnessId: string;
  harnessName: string;
  startNano: string;
  endNano: string;
}

export type WatcherEvent =
  | { kind: 'span'; span: IngestInput }
  | { kind: 'end'; spanId: string; endNano: string }
  | { kind: 'usage'; tokensIn: number; tokensOut: number };

export interface OffsetStore {
  get(filePath: string): number | undefined;
  set(filePath: string, offset: number): void;
}

export interface WatcherOptions {
  roots?: string[];
  pollMs?: number;
  rescanMs?: number;
  hotWindowMs?: number;
  backfill?: boolean;
  offsets: OffsetStore;
  onEvent: (event: WatcherEvent) => void;
  onError?: (err: Error) => void;
}

export interface WatcherHandle {
  stop(): void;
  roots: string[];
}

interface HarnessKind {
  id: string;
  name: string;
  format: 'claude' | 'codex' | 'copilot';
}

const CLAUDE_HARNESS: HarnessKind = { id: 'claude-code', name: 'Claude Code', format: 'claude' };
const CODEX_HARNESS: HarnessKind = { id: 'codex', name: 'Codex', format: 'codex' };
const COPILOT_HARNESS: HarnessKind = { id: 'copilot', name: 'GitHub Copilot', format: 'copilot' };

export function defaultRoots(home = os.homedir()): string[] {
  return [
    path.join(home, '.claude', 'projects'),
    path.join(home, '.codex', 'sessions'),
    path.join(home, '.copilot', 'session-state'),
  ];
}

function isoToNano(iso: unknown): string {
  if (typeof iso !== 'string') return '0';
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return '0';
  return String(BigInt(ms) * 1_000_000n);
}

function harnessForPath(filePath: string): HarnessKind {
  if (filePath.includes(`${path.sep}.copilot${path.sep}`)) return COPILOT_HARNESS;
  if (filePath.includes(`${path.sep}.codex${path.sep}`)) return CODEX_HARNESS;
  return CLAUDE_HARNESS;
}

// ── Sub-agent lineage ──────────────────────────────────────────────────────
// Who told this agent to do that? Without an answer, every action a delegated
// agent takes is filed under the top-level session, and a tool call made by a
// sub-agent five levels down is indistinguishable from one the operator asked
// for directly. Attribution is the whole point of the orchestration view.
//
// Claude Code writes a delegated agent's turns to their own transcript, named
// `agent-<agentId>.jsonl`, with `isSidechain: true` and `agentId` on every
// record. Crucially it reuses the PARENT's `sessionId`, so the sub-agent's
// spans already land in the parent's trace — which is why looking for a
// cross-*trace* parent finds nothing, no matter how much delegation happened.
// The link to the specific call that spawned the agent lives on the other side:
// the spawning `Agent` tool call's result carries `toolUseResult.agentId`.
//
// So lineage is stamped from BOTH ends, and every span carries the fact it
// knows first-hand:
//   • a sub-agent's spans get `claudesec.agent.id` (+ `.type` where the record
//     states it) — always available, no ordering dependency;
//   • the spawning call's result span gets `claudesec.agent.spawned_id`.
// Joining those two keys reconstructs the tree regardless of which transcript
// the watcher happened to read first. `parentId` is also set directly when the
// mapping is already known, which is the common case: most agents are launched
// asynchronously and their result record (carrying the agentId) is written at
// LAUNCH time, before the agent has run a single tool.
const ATTR_AGENT_ID         = 'claudesec.agent.id';
const ATTR_AGENT_TYPE       = 'claudesec.agent.type';
const ATTR_AGENT_SPAWN      = 'claudesec.agent.spawned_id';
const ATTR_AGENT_SPAWN_TYPE = 'claudesec.agent.spawned_type';

/** `…/agent-a1b2c3.jsonl` → `a1b2c3`; anything else → ''. */
function subAgentIdFromPath(filePath: string): string {
  const base = path.basename(filePath);
  const m = /^agent-(.+)\.jsonl$/.exec(base);
  return m ? m[1] : '';
}

// agentId → the `Agent` tool call that spawned it. Bounded and oldest-first for
// the same reason as `toolNameByCallId`: this process runs for weeks.
const MAX_TRACKED_AGENTS = 2048;
const spawnCallByAgentId = new Map<string, string>();

function rememberAgentSpawn(agentId: string, callId: string): void {
  if (spawnCallByAgentId.has(agentId)) spawnCallByAgentId.delete(agentId);
  spawnCallByAgentId.set(agentId, callId);
  while (spawnCallByAgentId.size > MAX_TRACKED_AGENTS) {
    const oldest = spawnCallByAgentId.keys().next();
    if (oldest.done) break;
    spawnCallByAgentId.delete(oldest.value);
  }
}

/** The agentId a Claude `Agent` tool result reports having launched, if any. */
function spawnedAgentId(record: unknown): string {
  const rec = (record && typeof record === 'object' ? record : {}) as Record<string, unknown>;
  const tur = rec.toolUseResult;
  if (!tur || typeof tur !== 'object' || Array.isArray(tur)) return '';
  const id = (tur as Record<string, unknown>).agentId;
  return typeof id === 'string' ? id : '';
}

function listJsonlFiles(root: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) listJsonlFiles(full, out);
    else if (entry.isFile() && entry.name.endsWith('.jsonl')) out.push(full);
  }
  return out;
}

function readNewLines(filePath: string, offsets: OffsetStore, onLine: (line: string) => void): void {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return;
  }
  let start = offsets.get(filePath) ?? 0;
  if (stat.size < start) start = 0;
  if (stat.size <= start) return;

  const fd = fs.openSync(filePath, 'r');
  try {
    const length = stat.size - start;
    const buf = Buffer.allocUnsafe(length);
    fs.readSync(fd, buf, 0, length, start);
    const text = buf.toString('utf8');
    const lastNewline = text.lastIndexOf('\n');
    if (lastNewline < 0) return;
    const consumed = text.slice(0, lastNewline);
    const consumedBytes = Buffer.byteLength(text.slice(0, lastNewline + 1), 'utf8');
    for (const line of consumed.split('\n')) {
      const trimmed = line.trim();
      if (trimmed) onLine(trimmed);
    }
    offsets.set(filePath, start + consumedBytes);
  } finally {
    fs.closeSync(fd);
  }
}

// ── Tool outcomes ──────────────────────────────────────────────────────────
// A transcript records a tool call and its result as two separate records, and
// until now we threw the result away. That left every Bash command, fetch and
// MCP call stored as an *intention* with no answer to "did it work?" — the one
// question a post-mortem always asks, and the one a sequence rule needs in
// order to tell an attempt apart from an effect.
//
// Caps. Result text is unbounded in principle and fat in practice: across the
// transcripts on this machine the median result is ~460 bytes but the 99th
// percentile is ~28 KB and the largest single result is ~74 KB. Storing all of
// it would add ~71 MB of text to a database that already mirrors every span
// into an FTS index, so it would land twice. Capping the primary output at
// 2 KB keeps ~76% of results byte-for-byte complete while cutting the stored
// volume by ~60%, which is the knee of that curve.
//
// The cap is spent head *and* tail rather than head-only. Diagnostics cluster
// at both ends — the "Exit code N" banner and the first error open the text,
// while the failing assertion or the last stderr line usually closes it — so a
// head-only window would routinely keep the boilerplate and drop the verdict.
const OUTPUT_CAP = 2048;
// stderr gets its own smaller budget so a chatty stdout can never crowd out the
// channel that actually explains a failure.
const STDERR_CAP = 1024;

/**
 * Clamp text to `cap` bytes' worth of characters, keeping both ends and
 * marking what was dropped. The marker is explicit so nothing downstream — a
 * rule, a reader, an export — can mistake a clipped result for a complete one.
 */
export function clampOutput(text: string, cap: number): { text: string; truncated: boolean } {
  if (text.length <= cap) return { text, truncated: false };
  const dropped = text.length - cap;
  const marker = `\n… [truncated ${dropped} chars] …\n`;
  // Split the surviving budget 60/40 in favour of the head: the opening lines
  // carry the exit banner and the first error, which identify the failure,
  // while the tail is usually the final message that explains it.
  const headLen = Math.max(0, Math.floor((cap - marker.length) * 0.6));
  const tailLen = Math.max(0, cap - marker.length - headLen);
  return { text: text.slice(0, headLen) + marker + text.slice(text.length - tailLen), truncated: true };
}

/** Flatten a tool_result `content` field, which is either a string or a block array. */
function resultContentToText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const item of content) {
    if (typeof item === 'string') { parts.push(item); continue; }
    if (!item || typeof item !== 'object') continue;
    const block = item as Record<string, unknown>;
    if (typeof block.text === 'string') parts.push(block.text);
    // An image result has no text to keep; record that it existed so the
    // outcome isn't silently indistinguishable from an empty one.
    else if (block.type === 'image') parts.push('[image]');
  }
  return parts.join('\n');
}

/**
 * The outcome of one tool call, normalised across the shapes the harnesses
 * actually emit. Every field is optional except `status` because no single
 * field is present on every tool: only the success/failure verdict always is.
 */
export interface ToolOutcome {
  status: 'ok' | 'error';
  /** Process exit code, when the transcript states one. */
  exitCode?: number;
  /** HTTP status, for fetch-shaped tools that report one. */
  httpStatus?: number;
  /** Bounded excerpt of the result text. */
  output: string;
  /** Bounded excerpt of stderr, when the tool separates the streams. */
  stderr?: string;
  /** Length of the result text before clamping — the honest "how big was it". */
  outputBytes: number;
  truncated: boolean;
  /** True when the tool was cut short rather than allowed to finish. */
  interrupted?: boolean;
}

/** Pull the leading `Exit code N` banner the harness prefixes to a failed shell result. */
function parseExitCode(text: string): number | undefined {
  const m = /^(?:Error:\s*)?Exit code (\d+)/.exec(text);
  if (!m) return undefined;
  const code = Number(m[1]);
  return Number.isFinite(code) ? code : undefined;
}

/**
 * Derive a tool outcome from a transcript record and one of its `tool_result`
 * blocks.
 *
 * Shapes this reconciles, all observed in real transcripts:
 *   - `block.is_error === true` is the authoritative failure flag. It is
 *     *omitted* on roughly half of all results, and absence always means
 *     success — of ~33k results, only two failures were not flagged by it, and
 *     both opened with an `Error:` string, which is why that fallback exists.
 *   - `record.toolUseResult` is a per-tool payload with no common schema: an
 *     object of `{stdout, stderr, interrupted}` for a shell call, `{code,
 *     codeText, bytes}` for a fetch, `{file}` for a read, a content array for
 *     an MCP call — and, on failure, a bare `Error: …` STRING regardless of
 *     tool. We read the fields we recognise and fall back to `block.content`,
 *     which is present on every result, so an unrecognised or future tool
 *     still yields a status rather than nothing.
 *
 * Returns undefined only when there is genuinely nothing to record, so a
 * malformed result degrades to "no outcome span" and never disturbs the call.
 */
export function extractToolOutcome(record: unknown, block: unknown): ToolOutcome | undefined {
  if (!block || typeof block !== 'object') return undefined;
  const b = block as Record<string, unknown>;
  const rec = (record && typeof record === 'object' ? record : {}) as Record<string, unknown>;
  const tur = rec.toolUseResult;

  let text = resultContentToText(b.content);
  let stderrText = '';
  let httpStatus: number | undefined;
  let interrupted: boolean | undefined;

  // True when the transcript gave us a real result payload, as opposed to us
  // having found nothing at all. A tool that legitimately prints nothing — a
  // silent `mv`, a `grep` with no match — still ran, and "ran, said nothing,
  // succeeded" is a genuine outcome worth recording. Without this flag those
  // results fall through the emptiness check below and get discarded, which
  // measured at ~3% of all tool calls on real transcripts.
  const hasPayload = tur !== undefined && tur !== null;

  if (typeof tur === 'string') {
    // The failure shape: a bare string that usually leads with the exit banner.
    if (!text) text = tur;
  } else if (tur && typeof tur === 'object' && !Array.isArray(tur)) {
    const r = tur as Record<string, unknown>;
    if (typeof r.stdout === 'string') text = r.stdout;
    if (typeof r.stderr === 'string') stderrText = r.stderr;
    if (typeof r.interrupted === 'boolean') interrupted = r.interrupted;
    // A fetch-shaped result reports the HTTP status as `code`. Guard the range
    // so an unrelated tool that happens to use the same key can't mint a
    // nonsense status.
    if (typeof r.code === 'number' && r.code >= 100 && r.code <= 599) httpStatus = r.code;
  }

  const isError =
    b.is_error === true || (typeof tur === 'string' && /^Error\b/.test(tur)) || /^Error: Exit code \d+/.test(text);

  // The exit code is never its own field — it is only ever stated in the leading
  // text banner, so parse every channel rather than assuming which one carries
  // it. A failure that never states a code still failed; inventing a non-zero
  // placeholder would be fabricating data, so leave it unset and let `status`
  // carry the verdict on its own.
  const exitCode =
    parseExitCode(text) ?? parseExitCode(stderrText) ?? (typeof tur === 'string' ? parseExitCode(tur) : undefined);

  // Bail out only when there is genuinely nothing to say: no payload, no text,
  // no error, no status. Anything less than that is a fact we can record.
  if (!hasPayload && !text && !stderrText && !isError && httpStatus === undefined) return undefined;

  const clamped = clampOutput(text, OUTPUT_CAP);
  const clampedErr = stderrText ? clampOutput(stderrText, STDERR_CAP) : undefined;

  const outcome: ToolOutcome = {
    status: isError ? 'error' : 'ok',
    output: clamped.text,
    outputBytes: text.length,
    truncated: clamped.truncated || Boolean(clampedErr?.truncated),
  };
  if (exitCode !== undefined) outcome.exitCode = exitCode;
  if (httpStatus !== undefined) outcome.httpStatus = httpStatus;
  if (clampedErr && clampedErr.text) outcome.stderr = clampedErr.text;
  if (interrupted) outcome.interrupted = true;
  return outcome;
}

// Remember which tool a call id belonged to, so the outcome span can be named
// after it. Results arrive on a later line than their call — usually the very
// next one, but up to ~2800 lines later in the worst case observed — so the map
// has to outlive the immediate record. It is bounded and evicts oldest-first:
// an unbounded map here would be a slow leak in a process that runs for weeks.
const MAX_TRACKED_CALLS = 4096;
const toolNameByCallId = new Map<string, string>();

function rememberToolName(callId: string, toolName: string): void {
  // Re-inserting moves the entry to the end of the Map's insertion order, which
  // is what makes the oldest-first eviction below correct.
  if (toolNameByCallId.has(callId)) toolNameByCallId.delete(callId);
  toolNameByCallId.set(callId, toolName);
  while (toolNameByCallId.size > MAX_TRACKED_CALLS) {
    const oldest = toolNameByCallId.keys().next();
    if (oldest.done) break;
    toolNameByCallId.delete(oldest.value);
  }
}

/**
 * Build the span that records an outcome, linked to the call it belongs to.
 *
 * WHY a linked child span rather than an in-place UPDATE of the call span.
 * The call span is already written, scrubbed, classified and — if a rule fired
 * — referenced by an alert row, so rewriting its attributes would mutate
 * evidence after the fact. More importantly, detection runs on ingest and only
 * on ingest: an UPDATE would push command output into the database without any
 * rule ever reading it, whereas a span goes through the same ingest path as
 * everything else and gets the full rule set applied to the OUTPUT. That
 * matters, because output is its own exfiltration surface — `env`, `cat
 * ~/.aws/credentials` and `aws sts` all take harmless-looking arguments and
 * return secrets — and it means scrubbing is inherited rather than reimplemented
 * here. The span id is derived from the call id, so the primary key makes a
 * replayed transcript idempotent, and `parentId` is the call id, so the join
 * back to the attempt is a plain lookup.
 */
function outcomeSpan(
  callId: string,
  outcome: ToolOutcome,
  toolName: string,
  base: {
    traceId: string;
    startNano: string;
    harness: HarnessKind;
    cwd?: unknown;
    branch?: unknown;
    /** The sub-agent that produced this result, when the call was made by one. */
    agentId?: string;
    agentType?: string;
    /** Set when this result IS the launch record of a delegated agent. */
    spawnedAgentId?: string;
  },
): WatcherEvent {
  const label = toolName || 'tool';
  const verdict =
    outcome.status === 'error'
      ? `${label} failed${outcome.exitCode !== undefined ? ` (exit ${outcome.exitCode})` : ''}`
      : `${label} succeeded${outcome.httpStatus !== undefined ? ` (HTTP ${outcome.httpStatus})` : ''}`;

  // Flat string/number values only: the scrubber walks the top level of the
  // attribute map, so nesting the output inside an object would carry it past
  // the redaction pass.
  const rawAttrs: Record<string, unknown> = {
    tool: label,
    protocol: 'local',
    reason: verdict,
    'claudesec.outcome': outcome.status,
    'claudesec.outcome.tool_use_id': callId,
    'claudesec.outcome.output': outcome.output,
    'claudesec.outcome.output_bytes': outcome.outputBytes,
    'claudesec.outcome.truncated': outcome.truncated,
  };
  if (outcome.exitCode !== undefined) rawAttrs['claudesec.outcome.exit_code'] = outcome.exitCode;
  if (outcome.httpStatus !== undefined) rawAttrs['claudesec.outcome.http_status'] = outcome.httpStatus;
  if (outcome.stderr) rawAttrs['claudesec.outcome.stderr'] = outcome.stderr;
  if (outcome.interrupted) rawAttrs['claudesec.outcome.interrupted'] = true;
  if (typeof base.cwd === 'string' && base.cwd) rawAttrs['cwd'] = base.cwd;
  if (typeof base.branch === 'string' && base.branch) rawAttrs['git.branch'] = base.branch;
  if (base.agentId) rawAttrs[ATTR_AGENT_ID] = base.agentId;
  if (base.agentType) rawAttrs[ATTR_AGENT_TYPE] = base.agentType;
  if (base.spawnedAgentId) rawAttrs[ATTR_AGENT_SPAWN] = base.spawnedAgentId;

  return {
    kind: 'span',
    span: {
      spanId: `${callId}:result`,
      traceId: base.traceId,
      parentId: callId,
      name: `${label}.result`,
      rawAttrs,
      harnessId: base.harness.id,
      harnessName: base.harness.name,
      startNano: base.startNano,
      endNano: base.startNano,
    },
  };
}

function summarizeToolInput(input: unknown): string {
  if (!input || typeof input !== 'object') return '';
  const fields = input as Record<string, unknown>;
  for (const key of ['command', 'file_path', 'path', 'pattern', 'query', 'url', 'description', 'prompt']) {
    const value = fields[key];
    if (typeof value === 'string' && value.trim()) {
      const collapsed = value.replace(/\s+/g, ' ').trim();
      return collapsed.length > 80 ? collapsed.slice(0, 80) + '…' : collapsed;
    }
  }
  return '';
}

function mapClaudeRecord(
  record: any,
  harness: HarnessKind,
  emit: (event: WatcherEvent) => void,
  filePathAgentId = '',
): void {
  const message = record?.message;
  const startNano = isoToNano(record?.timestamp);
  const traceId = String(record?.sessionId ?? 'unknown');

  // Two independent signals that this record belongs to a delegated agent: the
  // record's own flag, and the transcript's filename. Either alone is enough —
  // across every transcript on disk the two agree exactly, so accepting both
  // keeps capture working if a future version stops writing one of them.
  const agentId =
    record?.isSidechain === true || filePathAgentId
      ? (typeof record?.agentId === 'string' && record.agentId ? String(record.agentId) : filePathAgentId)
      : '';
  // Stated only on the agent's assistant turns (~61% of its records), so it is
  // recorded where present and left off where not, rather than guessed.
  const agentType = typeof record?.attributionAgent === 'string' ? record.attributionAgent : '';
  // A sub-agent's own tool calls hang off the call that spawned it, when that
  // call is already known. When it isn't — a synchronous agent reports its
  // agentId only once it FINISHES, so its spans are written first — the span
  // still carries `claudesec.agent.id`, and the join on that key recovers the
  // same edge at query time.
  const agentParentCall = agentId ? spawnCallByAgentId.get(agentId) ?? '' : '';

  if (message && Array.isArray(message.content)) {
    for (const block of message.content) {
      if (!block || typeof block !== 'object') continue;
      if (block.type === 'tool_use' && block.id && block.name) {
        rememberToolName(String(block.id), String(block.name));
        const rawAttrs: Record<string, unknown> = { ...(block.input ?? {}) };
        rawAttrs['tool'] = block.name;
        rawAttrs['protocol'] = 'local';
        const summary = summarizeToolInput(block.input);
        if (summary) rawAttrs['reason'] = summary;
        if (record.cwd) rawAttrs['cwd'] = record.cwd;
        if (record.gitBranch) rawAttrs['git.branch'] = record.gitBranch;
        if (message.model) rawAttrs['llm.model'] = message.model;
        if (agentId) rawAttrs[ATTR_AGENT_ID] = agentId;
        if (agentType) rawAttrs[ATTR_AGENT_TYPE] = agentType;
        // A delegation request names the kind of agent it wants. Kept under its
        // own key rather than `claudesec.agent.type`, which means "the agent
        // that PRODUCED this span" — a sub-agent delegating further would
        // otherwise label its own span with its child's type.
        const requestedType = (block.input as Record<string, unknown> | undefined)?.subagent_type;
        if (typeof requestedType === 'string' && requestedType) rawAttrs[ATTR_AGENT_SPAWN_TYPE] = requestedType;
        emit({
          kind: 'span',
          span: {
            spanId: String(block.id),
            traceId,
            parentId: agentParentCall,
            name: String(block.name),
            rawAttrs,
            harnessId: harness.id,
            harnessName: harness.name,
            startNano,
            endNano: startNano,
          },
        });
      } else if (block.type === 'tool_result' && block.tool_use_id) {
        const callId = String(block.tool_use_id);
        // Close the call span first, exactly as before. The outcome is strictly
        // additive: if anything below fails, the timing update has already
        // landed and the call span is untouched.
        emit({ kind: 'end', spanId: callId, endNano: startNano });
        // A launch result names the agent it started. Remember it before the
        // outcome span is built so the very next record from that agent can be
        // parented directly.
        const spawned = spawnedAgentId(record);
        if (spawned) rememberAgentSpawn(spawned, callId);
        try {
          const outcome = extractToolOutcome(record, block);
          if (outcome) {
            // A result whose call we never saw — the watcher started mid-file,
            // or the call scrolled out of the bounded map — still records a real
            // outcome, so emit it under a generic name rather than dropping it.
            emit(outcomeSpan(callId, outcome, toolNameByCallId.get(callId) ?? '', {
              traceId,
              startNano,
              harness,
              cwd: record?.cwd,
              branch: record?.gitBranch,
              agentId,
              agentType,
              spawnedAgentId: spawned,
            }));
          }
        } catch {
          // Fail open. An outcome is a bonus fact; never let a strange result
          // shape cost us the call span that is already recorded.
        }
      }
    }
  }

  const usage = message?.usage;
  if (usage && typeof usage === 'object') {
    const inputTokens = Number(usage.input_tokens ?? 0);
    const cacheCreate = Number(usage.cache_creation_input_tokens ?? 0);
    const cacheRead = Number(usage.cache_read_input_tokens ?? 0);
    const outputTokens = Number(usage.output_tokens ?? 0);
    const rawInput = inputTokens + cacheCreate + cacheRead;
    if (rawInput > 0 || outputTokens > 0) {
      const model = typeof message.model === 'string' ? message.model : '';
      // Claude Code writes ONE JSONL line per assistant content block, and every
      // line for the same assistant turn repeats the SAME message.usage verbatim
      // (verified: byte-identical usage across all lines that share a message.id).
      // Each line has its own record.uuid, so keying the llm_request span on the
      // transcript-line uuid lets INSERT OR IGNORE store a duplicate cost row per
      // block — inflating token totals (~45-60% extra output tokens measured).
      //
      // Fix: key the span on the API RESPONSE identity (message.id), so all the
      // repeated lines collapse to a single row via the PRIMARY KEY conflict.
      // message.id is always present on real Claude assistant records; fall back
      // to record.uuid only if it is somehow absent (keeps old behaviour, never
      // crashes). We also persist message.id as `gen_ai.response.id` so query-time
      // dedupe can group on the response even for older/other ingest paths.
      const responseId = typeof message.id === 'string' && message.id ? message.id : '';
      const dedupeKey = responseId || (record?.uuid ? String(record.uuid) : '');
      if (model && dedupeKey) {
        const rawAttrs: Record<string, unknown> = {
          'gen_ai.request.model': model,
          'llm.model': model,
          'gen_ai.usage.input_tokens': inputTokens,
          'gen_ai.usage.cache_read_input_tokens': cacheRead,
          'gen_ai.usage.cache_creation_input_tokens': cacheCreate,
          'gen_ai.usage.output_tokens': outputTokens,
        };
        if (responseId) rawAttrs['gen_ai.response.id'] = responseId;
        // Delegated work is where the tokens go. Attributing the model call to
        // the agent that made it is what turns the cost view from one number
        // per session into a per-agent breakdown.
        if (agentId) rawAttrs[ATTR_AGENT_ID] = agentId;
        if (agentType) rawAttrs[ATTR_AGENT_TYPE] = agentType;
        emit({
          kind: 'span',
          span: {
            spanId: `${dedupeKey}:llm`,
            traceId,
            parentId: agentParentCall,
            name: 'llm_request',
            rawAttrs,
            harnessId: harness.id,
            harnessName: harness.name,
            startNano,
            endNano: startNano,
          },
        });
      }
      // NOTE: the `usage` event is a live running counter for the dashboard ticker
      // and is intentionally left as-is here — the persisted spans (deduped by
      // message.id above) are the source of truth for the cost aggregates.
      emit({ kind: 'usage', tokensIn: rawInput, tokensOut: outputTokens });
    }
  }
}

function mapCodexRecord(record: any, harness: HarnessKind, emit: (event: WatcherEvent) => void): void {
  const payload = record?.payload ?? record;
  const type = String(payload?.type ?? record?.type ?? '');
  const startNano = isoToNano(record?.timestamp ?? payload?.timestamp);
  const traceId = String(record?.session_id ?? record?.sessionId ?? payload?.session_id ?? 'codex-session');

  if (type === 'function_call' || type === 'tool_call' || type === 'local_shell_call') {
    const callId = String(payload.call_id ?? payload.id ?? '');
    if (!callId) return;
    const name = String(payload.name ?? payload.tool_name ?? 'function_call');
    const rawAttrs: Record<string, unknown> = { tool: name };
    if (payload.arguments) rawAttrs['arguments'] = payload.arguments;
    if (payload.command) rawAttrs['command'] = payload.command;
    // Stamp the working directory when the Codex record carries one, so the span
    // can be grouped per git repository. Codex rollout files don't reliably
    // record a cwd today; we read the known candidate fields and only stamp when
    // one is actually present (never fabricated).
    const codexCwd = payload.cwd ?? payload.cwd_path ?? record?.cwd;
    if (typeof codexCwd === 'string' && codexCwd) rawAttrs['cwd'] = codexCwd;
    emit({
      kind: 'span',
      span: {
        spanId: callId,
        traceId,
        parentId: '',
        name,
        rawAttrs,
        harnessId: harness.id,
        harnessName: harness.name,
        startNano,
        endNano: startNano,
      },
    });
  } else if (type === 'function_call_output' || type === 'tool_result' || type === 'local_shell_call_output') {
    const callId = String(payload.call_id ?? payload.id ?? '');
    if (callId) emit({ kind: 'end', spanId: callId, endNano: startNano });
  }
}

function mapCopilotRecord(record: any, harness: HarnessKind, emit: (event: WatcherEvent) => void, sessionId: string): void {
  const type = String(record?.type ?? '');
  const data = record?.data;
  const traceId = sessionId || String(data?.sessionId ?? 'copilot-session');
  const startNano = isoToNano(record?.timestamp);

  if (type === 'tool.execution_start' && data && data.toolCallId && data.toolName) {
    const args = data.arguments && typeof data.arguments === 'object' ? data.arguments : {};
    const rawAttrs: Record<string, unknown> = { ...args, tool: data.toolName, protocol: 'local' };
    const summary = summarizeToolInput(data.arguments);
    if (summary) rawAttrs['reason'] = summary;
    // Stamp the working directory when the Copilot record carries one. Copilot
    // session logs don't include a per-event cwd today, so this almost always
    // no-ops; we still read the candidate fields and stamp only when one is
    // genuinely present (never fabricated), so it lights up automatically if a
    // future log format adds it.
    const copilotCwd = data.cwd ?? data.workingDirectory ?? data.workspaceRoot;
    if (typeof copilotCwd === 'string' && copilotCwd) rawAttrs['cwd'] = copilotCwd;
    emit({
      kind: 'span',
      span: {
        spanId: String(data.toolCallId),
        traceId,
        parentId: '',
        name: String(data.toolName),
        rawAttrs,
        harnessId: harness.id,
        harnessName: harness.name,
        startNano,
        endNano: startNano,
      },
    });
  } else if (type === 'tool.execution_complete' && data && data.toolCallId) {
    emit({ kind: 'end', spanId: String(data.toolCallId), endNano: startNano });
  } else if (type === 'assistant.message' && data) {
    const outputTokens = Number(data.outputTokens ?? 0);
    // The span id must identify THIS message. A Copilot assistant.message with no
    // usable id used to stringify to `undefined:llm`, so every such record
    // collapsed into the SAME row under INSERT OR IGNORE and its tokens were
    // silently dropped from the cost totals. Same guard the Claude path applies to
    // its dedupe key: no id, no costed span (the live usage ticker below still
    // counts it — only persistence needs an identity).
    const messageId = stableRecordId(record?.id ?? data.messageId);
    if (messageId && (outputTokens > 0 || data.model)) {
      const model = typeof data.model === 'string' && data.model ? data.model : 'gpt-4o';
      emit({
        kind: 'span',
        span: {
          spanId: `${messageId}:llm`,
          traceId,
          parentId: '',
          name: 'llm_request',
          rawAttrs: {
            'gen_ai.request.model': model,
            'llm.model': model,
            'gen_ai.usage.input_tokens': 0,
            'gen_ai.usage.output_tokens': outputTokens,
          },
          harnessId: harness.id,
          harnessName: harness.name,
          startNano,
          endNano: startNano,
        },
      });
    }
    if (outputTokens > 0) emit({ kind: 'usage', tokensIn: 0, tokensOut: outputTokens });
  }
}

/**
 * A record id we can safely build a span id from: a non-empty string, or a finite
 * number stringified. Anything else (missing, null, object) returns '' so the
 * caller skips the record rather than minting a colliding `undefined:...` id.
 */
function stableRecordId(id: unknown): string {
  if (typeof id === 'string') return id.trim();
  if (typeof id === 'number' && Number.isFinite(id)) return String(id);
  return '';
}

/**
 * Sub-agent lineage recovered from the transcripts still on disk, keyed the same
 * way the watcher keys its spans so callers can join it straight onto stored
 * rows.
 */
export interface TranscriptLineage {
  /** spanId → the delegated agent that produced it. */
  agentBySpanId: Map<string, string>;
  /** agentId → the spanId of the `Agent` call that launched it. */
  spawnCallByAgentId: Map<string, string>;
  /** agentId → its declared type, where a transcript states one. */
  typeByAgentId: Map<string, string>;
  filesScanned: number;
}

/**
 * Rebuild sub-agent lineage for spans recorded BEFORE the watcher started
 * stamping it.
 *
 * WHY THIS READS, AND NEVER WRITES. `parentId` is one of the fields covered by
 * the spans audit chain (see `spanCanonical` in server/db.ts), so rewriting it
 * on an existing row invalidates that row's signature and, with it, every
 * verification that walks past it. Recovered history is therefore an OVERLAY —
 * derived on demand from files the agent wrote itself, joined at query time,
 * and discarded — not a migration. The stored spans keep the exact bytes they
 * were signed with.
 *
 * Opt-in because it is a full pass over the transcript tree: ~1 GB and ~2.5 s
 * on the corpus this was measured against, versus ~0 for the live path, which
 * needs none of this. Callers cache the result; nothing calls it per request.
 *
 * Only Claude transcripts carry delegated-agent records today, so only they are
 * read. Files are opened read-only and parse failures are skipped — a truncated
 * or half-written transcript costs its own lineage and nothing else.
 */
export function scanTranscriptLineage(roots?: string[]): TranscriptLineage {
  const out: TranscriptLineage = {
    agentBySpanId:      new Map(),
    spawnCallByAgentId: new Map(),
    typeByAgentId:      new Map(),
    filesScanned:       0,
  };
  const searchRoots = (roots ?? defaultRoots()).filter(r => harnessForPath(path.join(r, 'x.jsonl')).format === 'claude');

  for (const root of searchRoots) {
    for (const file of listJsonlFiles(root)) {
      let text: string;
      try {
        text = fs.readFileSync(file, 'utf8');
      } catch {
        continue;
      }
      out.filesScanned++;
      const pathAgentId = subAgentIdFromPath(file);
      for (const line of text.split('\n')) {
        // Every record this needs names an agent. Skipping the rest before
        // parsing is what keeps a multi-gigabyte tree to a couple of seconds.
        if (!line.includes('"agentId"')) continue;
        let record: any;
        try {
          record = JSON.parse(line);
        } catch {
          continue;
        }

        const spawned = spawnedAgentId(record);
        if (spawned) {
          const content = record?.message?.content;
          if (Array.isArray(content)) {
            for (const block of content) {
              if (block?.type === 'tool_result' && block.tool_use_id) {
                out.spawnCallByAgentId.set(spawned, String(block.tool_use_id));
              }
            }
          }
        }

        const agentId =
          record?.isSidechain === true || pathAgentId
            ? (typeof record?.agentId === 'string' && record.agentId ? String(record.agentId) : pathAgentId)
            : '';
        if (!agentId) continue;
        if (typeof record?.attributionAgent === 'string' && record.attributionAgent) {
          out.typeByAgentId.set(agentId, record.attributionAgent);
        }

        const message = record?.message;
        if (!message || typeof message !== 'object') continue;
        // Mirror the span ids mapClaudeRecord mints, so the join is exact.
        if (Array.isArray(message.content)) {
          for (const block of message.content) {
            if (block?.type === 'tool_use' && block.id) out.agentBySpanId.set(String(block.id), agentId);
            else if (block?.type === 'tool_result' && block.tool_use_id) {
              out.agentBySpanId.set(`${block.tool_use_id}:result`, agentId);
            }
          }
        }
        if (typeof message.id === 'string' && message.id && message.usage) {
          out.agentBySpanId.set(`${message.id}:llm`, agentId);
        }
      }
    }
  }
  return out;
}

export function startTranscriptWatcher(opts: WatcherOptions): WatcherHandle {
  const roots = opts.roots ?? defaultRoots();
  const pollMs = opts.pollMs ?? 1000;
  const rescanMs = opts.rescanMs ?? 5000;
  const hotWindowMs = opts.hotWindowMs ?? 120_000;
  const known = new Set<string>();
  const hot = new Set<string>();
  let stopped = false;

  const consume = (file: string): void => {
    const harness = harnessForPath(file);
    const sessionId = harness.format === 'copilot' ? path.basename(path.dirname(file)) : '';
    const subAgentId = harness.format === 'claude' ? subAgentIdFromPath(file) : '';
    try {
      readNewLines(file, opts.offsets, (line) => {
        let record: unknown;
        try {
          record = JSON.parse(line);
        } catch {
          return;
        }
        try {
          if (harness.format === 'copilot') mapCopilotRecord(record, harness, opts.onEvent, sessionId);
          else if (harness.format === 'codex') mapCodexRecord(record, harness, opts.onEvent);
          else mapClaudeRecord(record, harness, opts.onEvent, subAgentId);
        } catch (err) {
          opts.onError?.(err as Error);
        }
      });
    } catch (err) {
      opts.onError?.(err as Error);
    }
  };

  const rescan = (): void => {
    if (stopped) return;
    const now = Date.now();
    for (const root of roots) {
      for (const file of listJsonlFiles(root)) {
        if (!known.has(file)) {
          known.add(file);
          const seenBefore = opts.offsets.get(file) !== undefined;
          if (!opts.backfill && !seenBefore) {
            try {
              opts.offsets.set(file, fs.statSync(file).size);
            } catch {
              opts.offsets.set(file, 0);
            }
          }
        }
        let mtimeMs = 0;
        try {
          mtimeMs = fs.statSync(file).mtimeMs;
        } catch {
          continue;
        }
        if (now - mtimeMs <= hotWindowMs) {
          hot.add(file);
          consume(file);
        } else {
          hot.delete(file);
        }
      }
    }
  };

  const poll = (): void => {
    if (stopped) return;
    for (const file of hot) consume(file);
  };

  rescan();
  const pollTimer = setInterval(poll, pollMs);
  const rescanTimer = setInterval(rescan, rescanMs);
  if (typeof pollTimer.unref === 'function') pollTimer.unref();
  if (typeof rescanTimer.unref === 'function') rescanTimer.unref();

  return {
    roots,
    stop(): void {
      stopped = true;
      clearInterval(pollTimer);
      clearInterval(rescanTimer);
    },
  };
}
