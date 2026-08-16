/**
 * mcpProxy.ts — cross-agent MCP enforcement proxy.
 *
 * A stdio MCP gateway that wraps a downstream MCP server and gates every
 * `tools/call` against ClaudeSec's enforcement rules. Because it speaks the raw
 * MCP wire protocol (JSON-RPC 2.0 over newline-delimited stdio), enforcement
 * reaches ANY MCP-speaking agent — Codex, Copilot, Claude Desktop, Claude Code —
 * not just Claude Code's PreToolUse hook.
 *
 * Wire protocol (modelcontextprotocol.io/specification/2025-06-18):
 *   • Transport: stdio. Each JSON-RPC message is one line of UTF-8, delimited by
 *     '\n', and MUST NOT contain embedded newlines. stderr is for logging only;
 *     stdout carries ONLY MCP messages.
 *   • The proxy is a transparent pipe for initialize, notifications/initialized,
 *     tools/list, resources/*, prompts/*, ping, and ALL responses — forwarded
 *     byte-for-byte. It intercepts only `tools/call`.
 *   • tools/call request: { method:'tools/call', params:{ name, arguments } }.
 *   • A blocked call is answered with a tools/call RESULT carrying isError:true +
 *     explanatory content (NOT a JSON-RPC protocol error) so the agent sees a
 *     clean, model-readable refusal rather than a transport failure.
 *
 * Enforcement model (gated by mode, re-resolved per tools/call so dashboard
 * toggles take effect live):
 *   • enforce + (catastrophic-floor OR effective-block rule) matches → DO NOT
 *     forward; return blocked result; POST a would-block to /api/enforce-log.
 *   • monitor (default) + match → POST a would-block, then forward normally.
 *   • no match → forward.
 *
 * Safety: fail-OPEN. Any parse/eval/proxy error forwards the original message
 * (never break the agent). CLAUDESEC_HOOKS_BYPASS=1 forwards everything.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import {
  loadBlockRules,
  resolveMode,
  evaluate,
  evaluateFetch,
  redact,
  postEnforceLog,
  type CompiledRule,
} from './enforceEval.ts';

/** A line-delimited JSON reader: accumulates chunks, emits complete lines. */
function createLineReader(onLine: (line: string) => void): (chunk: Buffer | string) => void {
  let buf = '';
  return (chunk: Buffer | string) => {
    buf += chunk.toString('utf8');
    let nl: number;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      onLine(line);
    }
  };
}

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: { name?: unknown; arguments?: unknown } & Record<string, unknown>;
}

// Edit-shaped tool names and the arg keys that carry file content vs the target
// path. Mirrors the hook's EDIT_TOOLS split: for an edit call we gate on PATH +
// ACTION (never the static content of the code being written), and check the
// content ONLY against the minimal live-secret floor. Names are matched
// case-insensitively so a downstream MCP server's `edit_file`/`write_file`/etc.
// is treated the same as Claude Code's Edit/Write.
const EDIT_TOOL_NAMES = /(?:^|[._-])(?:edit|write|multiedit|notebook_?edit|str_replace|create_file|write_file|edit_file|apply_patch)(?:$|[._-])/i;
const EDIT_CONTENT_KEYS = ['content', 'new_string', 'new_str', 'new_source', 'text', 'body', 'patch'];
const EDIT_PATH_KEYS = ['file_path', 'path', 'notebook_path', 'filename', 'file'];

// Command-shaped tool names (a shell-exec MCP tool) and the arg keys that carry
// the RAW command string. The catastrophic floor patterns are anchored to a
// command boundary (`(?:^|[\n;&|...]|&&)`) or end-of-string — wrapping the command
// in a JSON blob (`{"command":"rm -rf /"}`) destroys those anchors, so a serialized
// match would silently MISS `rm -rf /`, `format c:`, `del /f /q`, `rd /s`. We
// therefore extract the raw command VALUE and run the floor against it, exactly as
// the hook sees the Bash `command` string.
const COMMAND_TOOL_NAMES = /(?:^|[._-])(?:bash|sh|shell|exec|run|command|cmd|terminal|run_command|execute_command|run_shell|shell_exec|process)(?:$|[._-])/i;
const COMMAND_KEYS = ['command', 'cmd', 'script', 'shell', 'code', 'input'];

// Fetch-shaped calls carry a URL under one of these arg keys (a cross-agent
// fetch / web_fetch / http tool). They bypass the SSRF floor unless we extract
// the URL and classify it — see evaluateFetch. Any tools/call carrying a url-style
// arg is treated as fetch-shaped: the classifier only fires on internal/metadata
// hosts (never a public URL), so there is no false-positive cost to the breadth.
const FETCH_URL_KEYS = ['url', 'uri', 'href', 'link', 'endpoint'];

/** Pull the first string value found under any of `keys` from an args object. */
function firstStringArg(obj: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    if (typeof obj[k] === 'string') return obj[k] as string;
  }
  return '';
}

interface BuiltCall {
  /** Text fed to the rule engine + catastrophic floor. */
  matchText: string;
  /** Edit body, gated ONLY by the live-secret floor — never the rule engine. */
  editContent: string;
  /** The file an edit targets — feeds the self-protection + protected-paths floors. */
  targetPath: string;
  /** A fetch URL when the call is fetch-shaped; '' otherwise. Feeds the SSRF floor. */
  fetchUrl: string;
}

/**
 * Build the matchable text + edit content + target path (+ fetch URL) for a
 * tools/call, mirroring the hook.
 *   • matchText   → for an edit-shaped call, name + PATH only; for a command-shaped
 *     call, the RAW command string (NOT the JSON blob — the catastrophic floor's
 *     boundary/end-of-string anchors only fire against the real command text);
 *     otherwise the full serialized args.
 *   • editContent → the file body an edit would write, gated ONLY by the
 *     live-secret floor — never fed to the rule engine.
 *   • targetPath  → ONLY the file an edit targets (path keys), so evaluate()'s
 *     self-protection + protected-paths floors get the path. Empty otherwise.
 *   • fetchUrl    → the URL of a fetch-shaped call (fetch/web_fetch/http/…); the
 *     caller runs the SSRF floor against it. '' otherwise.
 * Shape detection mirrors the hook's tool families: edit-shaped (EDIT_TOOL_NAMES),
 * command-shaped (COMMAND_TOOL_NAMES + a command-carrying key), fetch-shaped
 * (FETCH_TOOL_NAMES or a `url`-style key).
 */
function buildMatchText(name: string, args: unknown): BuiltCall {
  const obj = args && typeof args === 'object' ? (args as Record<string, unknown>) : null;

  if (obj && EDIT_TOOL_NAMES.test(name)) {
    const pathParts: string[] = [];
    for (const k of EDIT_PATH_KEYS) {
      if (typeof obj[k] === 'string') pathParts.push(obj[k] as string);
    }
    const contentParts: string[] = [];
    for (const k of EDIT_CONTENT_KEYS) {
      if (typeof obj[k] === 'string') contentParts.push(obj[k] as string);
    }
    // MultiEdit-style nested edits: collect each edit's new content.
    if (Array.isArray(obj.edits)) {
      for (const e of obj.edits) {
        if (e && typeof e === 'object') {
          const ev = (e as Record<string, unknown>).new_string ?? (e as Record<string, unknown>).new_str;
          if (typeof ev === 'string') contentParts.push(ev);
        }
      }
    }
    const targetPath = pathParts.join(' ');
    return {
      matchText: `${name} ${targetPath}`.trim(),
      editContent: contentParts.join('\n'),
      targetPath,
      fetchUrl: '',
    };
  }

  // Fetch-shaped: ANY tool carrying a `url`-style arg. Pull the URL out so the
  // SSRF floor sees the raw target the hook sees.
  if (obj) {
    const url = firstStringArg(obj, FETCH_URL_KEYS);
    if (url) {
      return { matchText: `${name} ${url}`, editContent: '', targetPath: '', fetchUrl: url };
    }
  }

  // Command-shaped: a shell-exec tool with a command-carrying key. Run the floor
  // against the RAW command string so boundary/end-anchored catastrophic patterns
  // fire exactly as they do on the hook's Bash `command`.
  if (obj && COMMAND_TOOL_NAMES.test(name)) {
    const cmd = firstStringArg(obj, COMMAND_KEYS);
    if (cmd) {
      return { matchText: cmd, editContent: '', targetPath: '', fetchUrl: '' };
    }
  }

  // Unknown call: serialize all args as before. No edit target — the floors treat
  // matchText as the command form.
  let argStr: string;
  try {
    argStr = JSON.stringify(args ?? {});
  } catch {
    argStr = String(args ?? '');
  }
  return { matchText: `${name} ${argStr}`, editContent: '', targetPath: '', fetchUrl: '' };
}

/** A blocked tools/call result (isError:true + content). id echoed verbatim. */
function blockedResult(id: string | number | null | undefined, label: string): string {
  const text =
    `⛔ ClaudeSec [enforce] blocked this MCP tool call: ${label}.\n` +
    `The call was NOT forwarded to the downstream MCP server.\n` +
    `If this is truly intentional, set CLAUDESEC_HOOKS_BYPASS=1 in the proxy's ` +
    `environment (or switch ClaudeSec to monitor mode) and retry.`;
  return JSON.stringify({
    jsonrpc: '2.0',
    id: id ?? null,
    result: { content: [{ type: 'text', text }], isError: true },
  });
}

export interface ProxyOptions {
  command: string;
  args: string[];
  /**
   * Streams (overridable for tests). Default: real process std streams.
   * Readable side is the minimal EventEmitter-ish surface we use, so both
   * `process.stdin` (a tty.ReadStream) and a plain PassThrough satisfy it.
   */
  parentStdin?: {
    on(event: 'data', listener: (chunk: Buffer | string) => void): unknown;
    on(event: 'end', listener: () => void): unknown;
    on(event: 'error', listener: (err: Error) => void): unknown;
  };
  parentStdout?: NodeJS.WritableStream;
  parentStderr?: NodeJS.WritableStream;
  /** Spawn injection point for tests. Default: node:child_process spawn. */
  spawnFn?: typeof spawn;
  /** Log line sink (defaults to parentStderr). */
  log?: (msg: string) => void;
}

export interface ProxyHandle {
  child: ChildProcessWithoutNullStreams;
  /** Resolves when the child process exits; value is its exit code. */
  done: Promise<number | null>;
  /**
   * Await all in-flight enforce-log POSTs. The CLI calls this before exiting so
   * a block/would-block log actually flushes (a synchronous process.exit on
   * child-exit would otherwise race the best-effort POST and drop it).
   */
  flush: () => Promise<void>;
}

/**
 * Start the enforcement proxy. Spawns the downstream MCP server and pipes
 * JSON-RPC both ways, intercepting tools/call. Returns a handle; the caller is
 * responsible for process lifecycle if it wants to wait on `done`.
 */
export function startProxy(opts: ProxyOptions): ProxyHandle {
  const parentStdin = opts.parentStdin ?? process.stdin;
  const parentStdout = opts.parentStdout ?? process.stdout;
  const parentStderr = opts.parentStderr ?? process.stderr;
  const spawnFn = opts.spawnFn ?? spawn;
  const log = opts.log ?? ((m: string) => parentStderr.write(`[claudesec mcp-proxy] ${m}\n`));

  const bypass = process.env.CLAUDESEC_HOOKS_BYPASS === '1';

  // Track in-flight enforce-log POSTs so the CLI can flush them before exiting.
  const pending = new Set<Promise<void>>();
  const track = (p: Promise<void>) => {
    pending.add(p);
    p.finally(() => pending.delete(p));
  };
  const flush = async (): Promise<void> => { await Promise.allSettled([...pending]); };

  // Compile the block-rule set ONCE at startup (mode + a rule re-eval happen per
  // call). Fail-open → [] so a missing snapshot never breaks the pipe.
  let blockRules: CompiledRule[] = [];
  try {
    blockRules = loadBlockRules();
  } catch {
    blockRules = [];
  }
  log(
    bypass
      ? 'BYPASS active (CLAUDESEC_HOOKS_BYPASS=1) — forwarding all tool calls.'
      : `enforcement active — ${blockRules.length} block rules + catastrophic floor.`,
  );

  // Spawn downstream: stdin/stdout piped (we mediate), stderr → our stderr.
  const child = spawnFn(opts.command, opts.args, {
    stdio: ['pipe', 'pipe', 'inherit'],
  }) as ChildProcessWithoutNullStreams;

  /** Forward a raw line (+ newline) to the child's stdin. Fail-open: log only. */
  const toChild = (line: string) => {
    try {
      child.stdin.write(line + '\n');
    } catch (e) {
      log(`forward-to-child failed (dropping): ${(e as Error).message}`);
    }
  };
  /** Forward a raw line (+ newline) to the parent's stdout (the agent). */
  const toParent = (line: string) => {
    try {
      parentStdout.write(line + '\n');
    } catch (e) {
      log(`forward-to-parent failed: ${(e as Error).message}`);
    }
  };

  // ── Parent → child (the agent's requests). Intercept tools/call only. ──────
  const onParentLine = (line: string) => {
    if (line.trim() === '') return; // ignore keep-alive blank lines

    // BYPASS → forward verbatim, no parsing.
    if (bypass) return toChild(line);

    let msg: JsonRpcMessage | null = null;
    try {
      msg = JSON.parse(line) as JsonRpcMessage;
    } catch {
      // Unparseable → fail-open, forward raw (preserve exact bytes).
      return toChild(line);
    }

    // Only tools/call is gated; everything else is transparent.
    if (!msg || msg.method !== 'tools/call') return toChild(line);

    try {
      const name = typeof msg.params?.name === 'string' ? msg.params.name : '';
      const args = msg.params?.arguments;
      const { matchText, editContent, targetPath, fetchUrl } = buildMatchText(name, args);

      const mode = resolveMode(); // re-resolved per call → live dashboard toggles

      // ── SSRF-on-fetch floor (fetch-shaped calls only) ──────────────────────
      // Classify the URL host synchronously (no DNS — see classifyFetchHost). The
      // metadata/link-local tier is a mode-independent floor; loopback honors the
      // CLAUDESEC_ALLOW_LOCAL_FETCH opt-out; internal blocks only in enforce. This
      // is the SAME decision the hook makes, so a cross-agent fetch tool can no
      // longer bypass the SSRF guard the hook applies to WebFetch.
      if (fetchUrl) {
        const fv = evaluateFetch(fetchUrl, mode);
        if (fv.triggered) {
          const ssrfLabel = `SSRF: fetch to ${fv.klass} address ${fv.host}`;
          if (fv.block) {
            toParent(blockedResult(msg.id, ssrfLabel));
            log(`BLOCKED tools/call "${name}" — ${ssrfLabel}`);
            track(postEnforceLog({
              mode,
              label: ssrfLabel,
              severity: 'high',
              command: redact(fetchUrl),
              wouldBlock: true,
            }));
            return;
          }
          // Triggered but not blocked in this mode (e.g. internal in monitor): log a
          // would-block, then forward.
          log(`WOULD-BLOCK (${mode}) tools/call "${name}" — ${ssrfLabel}`);
          track(postEnforceLog({
            mode,
            label: ssrfLabel,
            severity: 'high',
            command: redact(fetchUrl),
            wouldBlock: true,
          }));
          return toChild(line);
        }
        // Public / unresolvable / opted-out loopback → forward (no rule engine for a
        // fetch, mirroring the hook which short-circuits on the SSRF branch).
        return toChild(line);
      }

      const verdict = evaluate(matchText, blockRules, editContent, targetPath);

      if (!verdict.triggered) return toChild(line); // clean → forward

      const label = verdict.label ?? '(unlabeled)';

      if (mode === 'enforce') {
        // BLOCK: answer the agent ourselves; never reach the downstream server.
        toParent(blockedResult(msg.id, label));
        log(`BLOCKED tools/call "${name}" — ${label} [${verdict.severity}] (${verdict.kind})`);
        track(postEnforceLog({
          mode: 'enforce',
          label,
          severity: verdict.severity,
          command: redact(matchText),
          wouldBlock: true,
        }));
        return;
      }

      // MONITOR (default): log a would-block, then forward normally.
      log(`WOULD-BLOCK (monitor) tools/call "${name}" — ${label} [${verdict.severity}]`);
      track(postEnforceLog({
        mode: 'monitor',
        label,
        severity: verdict.severity,
        command: redact(matchText),
        wouldBlock: true,
      }));
      return toChild(line);
    } catch (e) {
      // Any enforcement error → fail-open, forward the original message.
      log(`enforcement error (failing open): ${(e as Error).message}`);
      return toChild(line);
    }
  };

  // ── Child → parent (downstream responses/notifications). Pure pass-through. ─
  const onChildLine = (line: string) => {
    if (line === '') return;
    toParent(line);
  };

  parentStdin.on('data', createLineReader(onParentLine));
  child.stdout.on('data', createLineReader(onChildLine));

  // Lifecycle: when the agent closes stdin, end the child's stdin too.
  parentStdin.on('end', () => {
    try { child.stdin.end(); } catch { /* noop */ }
  });
  parentStdin.on('error', () => {
    try { child.stdin.end(); } catch { /* noop */ }
  });
  child.on('error', (e) => log(`downstream spawn error: ${e.message}`));

  const done = new Promise<number | null>((resolve) => {
    child.on('exit', (code) => {
      log(`downstream exited (code ${code}).`);
      resolve(code);
    });
  });

  return { child, done, flush };
}
