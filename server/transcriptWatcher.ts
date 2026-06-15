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

function mapClaudeRecord(record: any, harness: HarnessKind, emit: (event: WatcherEvent) => void): void {
  const message = record?.message;
  const startNano = isoToNano(record?.timestamp);
  const traceId = String(record?.sessionId ?? 'unknown');

  if (message && Array.isArray(message.content)) {
    for (const block of message.content) {
      if (!block || typeof block !== 'object') continue;
      if (block.type === 'tool_use' && block.id && block.name) {
        const rawAttrs: Record<string, unknown> = { ...(block.input ?? {}) };
        rawAttrs['tool'] = block.name;
        rawAttrs['protocol'] = 'local';
        const summary = summarizeToolInput(block.input);
        if (summary) rawAttrs['reason'] = summary;
        if (record.cwd) rawAttrs['cwd'] = record.cwd;
        if (record.gitBranch) rawAttrs['git.branch'] = record.gitBranch;
        if (message.model) rawAttrs['llm.model'] = message.model;
        emit({
          kind: 'span',
          span: {
            spanId: String(block.id),
            traceId,
            parentId: '',
            name: String(block.name),
            rawAttrs,
            harnessId: harness.id,
            harnessName: harness.name,
            startNano,
            endNano: startNano,
          },
        });
      } else if (block.type === 'tool_result' && block.tool_use_id) {
        emit({ kind: 'end', spanId: String(block.tool_use_id), endNano: startNano });
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
        emit({
          kind: 'span',
          span: {
            spanId: `${dedupeKey}:llm`,
            traceId,
            parentId: '',
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
    if (outputTokens > 0 || data.model) {
      const model = typeof data.model === 'string' && data.model ? data.model : 'gpt-4o';
      emit({
        kind: 'span',
        span: {
          spanId: `${String(record.id)}:llm`,
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
      emit({ kind: 'usage', tokensIn: 0, tokensOut: outputTokens });
    }
  }
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
          else mapClaudeRecord(record, harness, opts.onEvent);
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
