#!/usr/bin/env node
/* ClaudeSec PreToolUse enforcement hook — opt-in blocker built from the
 * detection rules. Keeps the 6 catastrophic Bash patterns as an ALWAYS-ON floor.
 *
 * SAFETY CONTRACT (a buggy enforcement hook can lock the user out):
 *   • Monitor-by-default: unless CLAUDESEC_MODE === 'enforce', the hook NEVER
 *     blocks on rule matches — it logs "would-block" and exits 0 (allow). The
 *     catastrophic-6 floor is the ONLY thing that blocks in monitor mode.
 *   • Fail-OPEN: any error / unparseable input / missing snapshot → exit 0.
 *   • Bypass: CLAUDESEC_HOOKS_BYPASS=1 → allow everything, exit 0.
 *   • Blocks are logged before exit: every deny (catastrophic floor or enforce
 *     rule) flushes the event to the dashboard, then exits 2. Logging is
 *     best-effort and can NEVER turn a block into an allow — the exit is
 *     guaranteed even if the POST fails (see blockAndLog / postMonitorLog).
 *
 * Claude Code PreToolUse protocol: reads JSON on stdin; exit 2 + stderr = DENY;
 * exit 0 = ALLOW. Dependency-free (Node built-ins only).
 *
 * Snapshot lookup: `rules-enforcement.json` is expected to sit NEXT TO this hook
 * (that is how `claudesec install-hook` copies them — both land in
 * ~/.claudesec/hooks/). The lookup resolves relative to this file's own
 * directory so an installed copy is fully self-contained. Set
 * CLAUDESEC_ENFORCE_RULES / CLAUDESEC_ENFORCE_CONFIG to override either path.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

// ── Catastrophic-6 floor ─────────────────────────────────────────────────────
// ALWAYS blocks, regardless of CLAUDESEC_MODE. Bash commands only — running
// these against Edit/Write content would block editing any file that merely
// *contains* these strings (e.g. server detection sources hold them as regex
// source). Kept byte-identical with server/enforceEval.ts (catastrophic parity).
const CATASTROPHIC = [
  { re: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:--no-preserve-root\s+)?\/\s*(?:$|\*|[;&|>])/m, why: 'rm -rf on the filesystem root (/)' },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:/, why: 'fork bomb' },
  { re: /\b(?:curl|wget)\b[^|>\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i, why: 'piping a remote download straight into a shell' },
  { re: /\b(?:ba)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/tcp\//i, why: 'reverse shell via /dev/tcp' },
  { re: /\bmkfs\.[a-z0-9]+\b/i, why: 'formatting a filesystem (mkfs)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|disk|hd|mmcblk)/i, why: 'overwriting a raw disk device (dd of=/dev/...)' },
];

/**
 * Block the tool call: show `reason` to Claude, flush a log event to the
 * dashboard, then exit 2 (deny). Logging is best-effort and must NEVER turn a
 * block into an allow, so the exit is guaranteed three ways:
 *   1. postMonitorLog calls its callback exactly once (on response / error /
 *      timeout, with a ~400ms backstop) → exit 2 via the callback.
 *   2. postMonitorLog itself swallows every error internally.
 *   3. If anything here throws synchronously before the callback is armed, the
 *      catch still exits 2.
 * The catastrophic floor therefore always blocks even if the POST never lands.
 */
function blockAndLog(reason, payload) {
  try {
    process.stderr.write(reason.endsWith('\n') ? reason : reason + '\n');
    postMonitorLog(payload, () => process.exit(2));
  } catch (_) {
    process.exit(2); // a logging failure can never become an allow
  }
}

/** Resolve the rules-enforcement.json snapshot path. */
function resolveSnapshotPath() {
  // 1. Explicit override (absolute or relative).
  if (process.env.CLAUDESEC_ENFORCE_RULES) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_RULES);
  }
  // 2. The snapshot sits next to this hook (installed layout: ~/.claudesec/hooks/).
  const beside = path.join(__dirname, 'rules-enforcement.json');
  if (fs.existsSync(beside)) return beside;
  // 3. Fallback: running in-repo from cli/hooks/<file> → <repo>/rules-enforcement.json.
  return path.resolve(__dirname, '..', '..', 'rules-enforcement.json');
}

/** Resolve the enforce-config.json path (server-written effective mode). */
function resolveConfigPath() {
  // 1. Explicit override (absolute or relative) — used by tests / isolated server.
  if (process.env.CLAUDESEC_ENFORCE_CONFIG) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_CONFIG);
  }
  // 2. Next to this hook (installed layout), if present.
  const beside = path.join(__dirname, 'enforce-config.json');
  if (fs.existsSync(beside)) return beside;
  // 3. Fallback: running in-repo → <repo>/enforce-config.json.
  return path.resolve(__dirname, '..', '..', 'enforce-config.json');
}

/**
 * Resolve the effective enforcement mode — ALWAYS fail-OPEN / monitor-by-default.
 *   1. enforce-config.json `mode` (server-controlled), accepted ONLY if it is
 *      exactly 'monitor' | 'enforce'. Any read/parse error or unknown value is
 *      ignored (falls through), never throws.
 *   2. CLAUDESEC_MODE env, same strict accept.
 *   3. 'monitor' (the safe default) for everything else.
 * A garbage value at any layer therefore resolves to 'monitor', never 'enforce'.
 */
function resolveMode() {
  // 1. Local config file (no per-call network).
  try {
    const raw = fs.readFileSync(resolveConfigPath(), 'utf8');
    const cfg = JSON.parse(raw);
    if (cfg && (cfg.mode === 'enforce' || cfg.mode === 'monitor')) {
      return cfg.mode;
    }
  } catch (_) {
    // missing / unreadable / malformed config → fall through (fail-open)
  }
  // 2. Env var fallback.
  const env = process.env.CLAUDESEC_MODE;
  if (env === 'enforce' || env === 'monitor') return env;
  // 3. Safe default.
  return 'monitor';
}

/**
 * Read per-rule action overrides from enforce-config.json. Shape:
 * { label: 'alert' | 'block' }. ALWAYS fail-open → {} (never throws). An
 * override lets the operator promote an 'alert' rule to 'block' or demote a
 * 'block' rule to 'alert' without rebuilding the snapshot.
 */
function loadOverrides() {
  try {
    const cfg = JSON.parse(fs.readFileSync(resolveConfigPath(), 'utf8'));
    const ov = cfg && cfg.overrides;
    if (!ov || typeof ov !== 'object') return {};
    const out = {};
    for (const k of Object.keys(ov)) {
      const v = ov[k];
      if (v === 'alert' || v === 'block') out[k] = v;
    }
    return out;
  } catch (_) {
    return {}; // missing / unreadable / malformed → no overrides
  }
}

/**
 * Load + compile the effective-block rules. Fail-open → [].
 * Effective action = overrides[label] ?? snapshot action. A rule is compiled
 * into the block-set iff its effective action is 'block'. Override lookup is
 * itself fail-open: a bad/absent override simply keeps the baked-in action.
 */
function loadBlockRules() {
  try {
    const p = resolveSnapshotPath();
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!Array.isArray(raw)) return [];
    const overrides = loadOverrides();
    const compiled = [];
    for (const r of raw) {
      if (!r || typeof r.source !== 'string') continue;
      const label = typeof r.label === 'string' ? r.label : '(unlabeled)';
      const baked = r.action === 'block' ? 'block' : 'alert';
      const ov = overrides[label];
      const effective = ov === 'block' || ov === 'alert' ? ov : baked;
      if (effective !== 'block') continue;
      try {
        compiled.push({
          re: new RegExp(r.source, typeof r.flags === 'string' ? r.flags : ''),
          label,
          severity: typeof r.severity === 'string' ? r.severity : 'high',
        });
      } catch (_) {
        // skip a single bad pattern, never throw
      }
    }
    return compiled;
  } catch (_) {
    return []; // missing/unreadable snapshot → fail-open
  }
}

/**
 * Best-effort POST to the dashboard. Calls `done` exactly once — on response
 * end / error / timeout — so the caller can exit AFTER the request has had a
 * chance to flush. Exiting synchronously after http.request() would tear the
 * process down before the socket sends a single byte (the request never lands).
 * A hard backstop timer guarantees `done` always fires, so we can never hang.
 */
function postMonitorLog(payload, done) {
  let finished = false;
  const finish = () => {
    if (!finished) { finished = true; done(); }
  };
  try {
    const body = JSON.stringify(payload);
    // Dashboard port: CLAUDESEC_PORT overrides, else the server's own PORT, else 3000.
    const portRaw = Number(process.env.CLAUDESEC_PORT ?? process.env.PORT);
    const port = Number.isFinite(portRaw) && portRaw > 0 ? portRaw : 3000;
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '/api/enforce-log',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: 300,
      },
      (res) => { res.resume(); res.on('end', finish); res.on('error', finish); }, // drain & discard
    );
    req.on('error', finish);
    req.on('timeout', () => { try { req.destroy(); } catch (_) {} finish(); });
    req.write(body);
    req.end();
  } catch (_) {
    finish(); // swallow everything — logging must never gate the exit
  }
  // Hard backstop: even if no socket event ever fires, exit within ~400ms.
  const guard = setTimeout(finish, 400);
  if (guard.unref) guard.unref();
}

/** Redact + truncate a command/text for safe logging. */
function redact(text) {
  let t = String(text || '').replace(/\s+/g, ' ').trim();
  if (t.length > 300) t = t.slice(0, 300) + '…';
  return t;
}

function run(input) {
  // 1. Bypass.
  if (process.env.CLAUDESEC_HOOKS_BYPASS === '1') return process.exit(0);

  let data;
  try {
    data = JSON.parse(input || '{}');
  } catch (_) {
    return process.exit(0); // malformed stdin → fail-open
  }

  const toolName = String((data && data.tool_name) || '');
  const ti = (data && data.tool_input) || {};

  // 2. Build the matchable text.
  let bashCmd = '';
  let matchText = '';
  if (toolName === 'Bash') {
    bashCmd = String(ti.command || '');
    matchText = bashCmd;
  } else if (
    toolName === 'Edit' ||
    toolName === 'Write' ||
    toolName === 'MultiEdit' ||
    toolName === 'NotebookEdit'
  ) {
    const parts = [];
    if (ti.file_path) parts.push(String(ti.file_path));
    if (ti.path) parts.push(String(ti.path));
    if (ti.content) parts.push(String(ti.content));
    if (ti.new_string) parts.push(String(ti.new_string));
    // NotebookEdit names its target/content differently from the text editors:
    // the new cell source is `new_source` and the file is `notebook_path`.
    if (ti.notebook_path) parts.push(String(ti.notebook_path));
    if (ti.new_source) parts.push(String(ti.new_source));
    if (Array.isArray(ti.edits)) {
      for (const e of ti.edits) {
        if (e && e.new_string) parts.push(String(e.new_string));
      }
    }
    matchText = parts.join('\n');
  } else {
    // Unknown tool / nothing to match.
    matchText = String(ti.command || ti.file_path || ti.path || '');
    bashCmd = String(ti.command || '');
  }

  if (!matchText) return process.exit(0);

  // 3. Catastrophic-6 floor — Bash command only, ALWAYS blocks.
  if (bashCmd) {
    for (const r of CATASTROPHIC) {
      if (r.re.test(bashCmd)) {
        // It WAS blocked (blocked: true), in whatever the resolved mode is — the
        // floor fires even in monitor. Catastrophic entries carry only { re, why },
        // so synthesize a label/severity for the feed.
        return blockAndLog(
          `⛔ ClaudeSec guard BLOCKED this command: ${r.why}.\n` +
          `If this is truly intentional, re-run with CLAUDESEC_HOOKS_BYPASS=1 set.`,
          {
            mode: resolveMode(),
            label: 'Catastrophic: ' + r.why,
            severity: 'high',
            command: redact(bashCmd),
            blocked: true,
            wouldBlock: true,
          },
        );
      }
    }
  }

  // 4. Load high-severity block rules from the snapshot (fail-open if missing).
  const blockRules = loadBlockRules();

  // 5. Evaluate block rules against the matchable text.
  let hit = null;
  for (const r of blockRules) {
    if (r.re.test(matchText)) { hit = r; break; }
  }

  if (hit) {
    const enforce = resolveMode() === 'enforce';
    if (enforce) {
      // Blocked → log it (blocked: true), then exit 2 after the POST settles.
      return blockAndLog(
        `ClaudeSec [enforce] blocked: ${hit.label}. ` +
        `Bypass: CLAUDESEC_HOOKS_BYPASS=1`,
        {
          mode: 'enforce',
          label: hit.label,
          severity: hit.severity,
          command: redact(matchText),
          blocked: true,
          wouldBlock: true,
        },
      );
    }
    // Monitor (DEFAULT): log "would-block", then ALLOW. Never block here.
    // Exit only AFTER the best-effort POST settles (or its backstop fires), so
    // the event actually flushes to the dashboard.
    return postMonitorLog(
      {
        mode: 'monitor',
        label: hit.label,
        severity: hit.severity,
        command: redact(matchText),
        blocked: false,
        wouldBlock: true,
      },
      () => process.exit(0),
    );
  }

  // 6. No match → allow.
  return process.exit(0);
}

// 7. Read stdin, then run — wrap EVERYTHING so any exception → exit 0.
let input = '';
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  try {
    run(input);
  } catch (_) {
    process.exit(0); // fail-open
  }
});
process.stdin.on('error', () => process.exit(0));
