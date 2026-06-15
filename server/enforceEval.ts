/**
 * enforceEval.ts — shared enforcement-evaluation core.
 *
 * Faithfully reproduces the evaluation semantics of the ClaudeSec PreToolUse
 * hook (`.claude/hooks/claudesec-enforce.cjs`) so the same rules + config drive
 * BOTH the Claude-Code-specific hook AND the cross-agent MCP enforcement proxy
 * (`mcpProxy.ts`). The hook is intentionally left untouched (it is a live,
 * dependency-free `.cjs` blocker for Claude Code's PreToolUse protocol); this
 * module is the ESM/TypeScript sibling that the proxy imports.
 *
 * Parity with the hook:
 *   • Catastrophic floor patterns (copied verbatim).
 *   • Effective-block rule compilation from rules-enforcement.json, with per-rule
 *     action overrides from enforce-config.json (alert↔block), fail-open.
 *   • resolveMode(): enforce-config.json `mode` → CLAUDESEC_MODE env → 'monitor'.
 *   • Fail-OPEN everywhere: any read/parse/compile error degrades to "allow".
 *
 * DELIBERATE DIVERGENCE (per the MCP-proxy spec): the hook's catastrophic
 * floor blocks ALWAYS (even in monitor mode). For the proxy, catastrophic is a
 * TRIGGER that is still gated by MODE — block only in `enforce`; in `monitor`
 * it is logged as a would-block and forwarded. `evaluate()` therefore returns a
 * mode-independent "triggered?" verdict; the CALLER decides block-vs-log based
 * on mode. This keeps a single high-severity arg BLOCKED under enforce yet
 * FORWARDED+logged under monitor, exactly as the proxy contract requires.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..'); // file lives in server/, root is one level up

export type EnforceMode = 'monitor' | 'enforce';

export interface CompiledRule {
  re: RegExp;
  label: string;
  severity: string;
}

export interface EvalResult {
  /** true if the text matched the catastrophic floor or an effective-block rule. */
  triggered: boolean;
  /** Why it triggered (rule label, or a catastrophic-floor reason). null if not triggered. */
  label: string | null;
  /** Severity of the matching rule; catastrophic floor reports 'high'. */
  severity: string;
  /** 'catastrophic' | 'rule' | null — provenance of the match (diagnostic). */
  kind: 'catastrophic' | 'rule' | null;
}

// ── Catastrophic floor (copied verbatim from block-catastrophic.cjs /
//    claudesec-enforce.cjs). These are Bash-shaped patterns; for MCP tool calls
//    we test them against the full matchable text. ──────────────────────────
export const CATASTROPHIC: { re: RegExp; why: string }[] = [
  { re: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:--no-preserve-root\s+)?\/\s*(?:$|\*|[;&|>])/m, why: 'rm -rf on the filesystem root (/)' },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:/, why: 'fork bomb' },
  { re: /\b(?:curl|wget)\b[^|>\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i, why: 'piping a remote download straight into a shell' },
  { re: /\b(?:ba)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/tcp\//i, why: 'reverse shell via /dev/tcp' },
  { re: /\bmkfs\.[a-z0-9]+\b/i, why: 'formatting a filesystem (mkfs)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|disk|hd|mmcblk)/i, why: 'overwriting a raw disk device (dd of=/dev/...)' },
  { re: /(?:cat|base64|tac|xxd|od|head|tail|gpg)\b[^\n|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))[^\n|]*\|[^\n;&]*\b(?:curl|wget|nc|ncat|telnet)\b/i, why: 'reading a secret and piping it into a network tool' },
  { re: /\b(?:curl|wget)\b[^\n;&|]*(?:-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)[ =]@?[^\n;&|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))/i, why: 'uploading a secret file over the network (curl/wget)' },
];

// ── Minimal live-secret (DLP) floor for edit content ─────────────────────────
// Mirrors LIVE_SECRET in cli/hooks/claudesec-enforce.cjs. The ONLY content-based
// block on an edit-shaped tool call: refuse to write an UNAMBIGUOUS live credential.
// Intentionally tiny + verified-shape (very low false positive) — NOT the ~630
// threat rules. The static body of code being written is gated on PATH + ACTION,
// never scanned against the rule set (editing security code / attack-pattern docs
// / secret-shaped fixtures must not be blocked). Phase 7 replaces this with a real
// secret detector; keep this set small and high-confidence until then.
export const LIVE_SECRET: { re: RegExp; why: string }[] = [
  { re: /\bAKIA[0-9A-Z]{16}\b/, why: 'AWS access key id' },
  { re: /\bASIA[0-9A-Z]{16}\b/, why: 'AWS temporary access key id' },
  { re: /\bghp_[0-9A-Za-z]{36}\b/, why: 'GitHub personal access token' },
  { re: /\bgh[oprs]_[0-9A-Za-z]{36}\b/, why: 'GitHub OAuth/server/refresh token' },
  { re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/, why: 'GitHub fine-grained token' },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, why: 'Slack token' },
  { re: /\bsk_live_[0-9A-Za-z]{20,}\b/, why: 'Stripe live secret key' },
  { re: /\bAIza[0-9A-Za-z_\-]{35}\b/, why: 'Google API key' },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, why: 'private key block' },
];

// Known documentation/placeholder credentials that are NOT live secrets. AWS
// ships `AKIAIOSFODNN7EXAMPLE` in its canonical docs; blocking it would refuse a
// benign edit to AWS docs/examples. Allowlisted by exact (case-sensitive) value
// before the live-secret floor fires. Mirrors SECRET_PLACEHOLDERS in
// cli/hooks/claudesec-enforce.cjs.
export const SECRET_PLACEHOLDERS = new Set<string>([
  'AKIAIOSFODNN7EXAMPLE',
]);

/**
 * Does the edit CONTENT carry an unambiguous live credential? Returns the matching
 * entry or null. This is the minimal DLP floor — the only reason an edit's content
 * (not its path) can be blocked. A match whose entire value is a known placeholder
 * (SECRET_PLACEHOLDERS) is ignored. See LIVE_SECRET.
 */
export function liveSecretHit(content: string): { re: RegExp; why: string } | null {
  if (!content) return null;
  for (const r of LIVE_SECRET) {
    const m = content.match(r.re);
    if (m && !SECRET_PLACEHOLDERS.has(m[0])) return r;
  }
  return null;
}

// ── Protected-paths floor (user-defined, always-on) ──────────────────────────
// A per-user mirror of the catastrophic floor: any tool call that targets a
// user-protected path is blocked in EVERY mode. The hook reads
// protected-paths.json from beside itself (~/.claudesec/hooks/); the proxy reads
// the SAME mirrored artifact so both enforcement layers share one source of
// truth. Fail-OPEN everywhere (a missing/unreadable list never blocks).

export interface ProtectedEntry {
  label: string;
  /** Raw + home-expanded spellings of the protected path (both matchable). */
  forms: string[];
}

/**
 * Resolve ~/.claudesec/hooks — where the installed hook + its protected-paths
 * mirror live. Mirrors server/index.ts hookArtifactsDir() and the installer:
 * honors CLAUDESEC_HOME, else ~/.claudesec. Kept by hand (the server must not
 * import from cli/); keep in sync if the layout changes.
 */
function hookArtifactsDir(): string {
  const homeDir = process.env.CLAUDESEC_HOME ?? path.join(os.homedir(), '.claudesec');
  return path.join(homeDir, 'hooks');
}

/** Resolve the protected-paths.json mirror path (override-aware, parity with the hook). */
export function resolveProtectedPathsPath(): string {
  if (process.env.CLAUDESEC_PROTECTED_PATHS) {
    return path.resolve(process.env.CLAUDESEC_PROTECTED_PATHS);
  }
  return path.join(hookArtifactsDir(), 'protected-paths.json');
}

/**
 * Load the user's protected-path entries from the mirrored artifact the hook
 * reads. Fail-OPEN → [] (never throws). Shape: [{ path, label }]. Each entry is
 * normalized so a leading '~' expands to the home dir; both the raw and expanded
 * forms are carried so a target matches whichever spelling the agent used.
 * Mirrors loadProtectedPaths() in cli/hooks/claudesec-enforce.cjs.
 */
export function loadProtectedPaths(): ProtectedEntry[] {
  try {
    const raw = JSON.parse(fs.readFileSync(resolveProtectedPathsPath(), 'utf8')) as unknown;
    if (!Array.isArray(raw)) return [];
    const home = os.homedir();
    const out: ProtectedEntry[] = [];
    for (const e of raw as { path?: unknown; label?: unknown }[]) {
      if (!e || typeof e.path !== 'string' || e.path.length === 0) continue;
      const p = e.path;
      const expanded =
        p === '~' ? home
        : p.startsWith('~/') ? path.join(home, p.slice(2))
        : p;
      const label = typeof e.label === 'string' && e.label.length > 0 ? e.label : p;
      const forms = expanded === p ? [p] : [p, expanded];
      out.push({ label, forms });
    }
    return out;
  } catch {
    return []; // missing / unreadable / malformed → fail-open
  }
}

/**
 * Expand a standalone `$HOME` / `${HOME}` token to the home dir (parity with the
 * hook's expandHomeVar). Only HOME is expanded — arbitrary shell variable / glob
 * / command substitution is an inherent limitation of static enforcement.
 */
function expandHomeVar(cmd: string): string {
  if (!cmd) return cmd;
  const home = os.homedir();
  return cmd.replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home);
}

/**
 * Does a protected entry match the call's file TARGET or Bash command? Matches
 * case-INSENSITIVE substring (case-insensitive filesystems make a case-sensitive
 * compare a trivial bypass) against the target path or the (HOME-expanded) Bash
 * command — NEVER edit content. Returns the matching entry or null. Parity with
 * protectedHit() in cli/hooks/claudesec-enforce.cjs.
 */
export function protectedHit(
  entries: ProtectedEntry[],
  target: string,
  bashCmd: string,
): ProtectedEntry | null {
  const t = target ? target.toLowerCase() : '';
  const c = bashCmd ? expandHomeVar(bashCmd).toLowerCase() : '';
  for (const e of entries) {
    for (const form of e.forms) {
      const f = form.toLowerCase();
      if ((t && t.includes(f)) || (c && c.includes(f))) return e;
    }
  }
  return null;
}

// ── Self-protection floor (control plane, always-on) ─────────────────────────
// An agent must never be able to edit (or shell-redirect into) the enforcement
// control plane and unhook the enforcer. ALWAYS blocks, regardless of mode.
// Guards the whole ~/.claudesec/hooks/ dir plus the Claude settings files that
// register the PreToolUse hook. Guards AGENT tool calls only; the ClaudeSec
// SERVER writes these from a different process, not subject to this check.
// Mirrors selfProtectionHit() in cli/hooks/claudesec-enforce.cjs.
function selfProtectedPrefixes(): string[] {
  const home = os.homedir();
  const csecHome = process.env.CLAUDESEC_HOME || path.join(home, '.claudesec');
  return [
    path.join(csecHome, 'hooks'),
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
  ];
}

/**
 * Does the call's file TARGET or Bash command touch the enforcement control
 * plane? Case-insensitive substring on the target path or (HOME-expanded) Bash
 * command — never edit content. Returns the matching prefix or null.
 */
export function selfProtectionHit(target: string, bashCmd: string): string | null {
  const prefixes = selfProtectedPrefixes();
  const t = target ? target.toLowerCase() : '';
  const c = bashCmd ? expandHomeVar(bashCmd).toLowerCase() : '';
  for (const p of prefixes) {
    const f = p.toLowerCase();
    if ((t && t.includes(f)) || (c && c.includes(f))) return p;
  }
  return null;
}

/** Resolve the rules-enforcement.json snapshot path (override-aware). */
export function resolveSnapshotPath(): string {
  if (process.env.CLAUDESEC_ENFORCE_RULES) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_RULES);
  }
  return path.join(REPO_ROOT, 'rules-enforcement.json');
}

/** Resolve the enforce-config.json path (override-aware). */
export function resolveConfigPath(): string {
  if (process.env.CLAUDESEC_ENFORCE_CONFIG) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_CONFIG);
  }
  return path.join(REPO_ROOT, 'enforce-config.json');
}

/**
 * Resolve the effective enforcement mode — fail-OPEN / monitor-by-default.
 *   1. enforce-config.json `mode` (accepted only if exactly 'monitor'|'enforce')
 *   2. CLAUDESEC_MODE env (same strict accept)
 *   3. 'monitor'
 * Any read/parse error or unknown value falls through; a garbage value at any
 * layer resolves to 'monitor', never 'enforce'.
 */
export function resolveMode(): EnforceMode {
  try {
    const cfg = JSON.parse(fs.readFileSync(resolveConfigPath(), 'utf8'));
    if (cfg && (cfg.mode === 'enforce' || cfg.mode === 'monitor')) return cfg.mode;
  } catch {
    /* missing / unreadable / malformed → fall through */
  }
  const env = process.env.CLAUDESEC_MODE;
  if (env === 'enforce' || env === 'monitor') return env;
  return 'monitor';
}

/**
 * Read per-rule action overrides from enforce-config.json: { label: 'alert'|'block' }.
 * Fail-open → {}. Lets an operator promote/demote a rule's action without
 * rebuilding the snapshot.
 */
export function loadOverrides(): Record<string, 'alert' | 'block'> {
  try {
    const cfg = JSON.parse(fs.readFileSync(resolveConfigPath(), 'utf8'));
    const ov = cfg && cfg.overrides;
    if (!ov || typeof ov !== 'object') return {};
    const out: Record<string, 'alert' | 'block'> = {};
    for (const k of Object.keys(ov)) {
      const v = ov[k];
      if (v === 'alert' || v === 'block') out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

interface RawRule {
  source?: unknown;
  flags?: unknown;
  severity?: unknown;
  label?: unknown;
  action?: unknown;
}

/**
 * Compile the effective-block rule set from the snapshot, honoring per-rule
 * overrides. A rule is included iff its effective action ('block') wins.
 * Effective action = overrides[label] ?? baked action. Fail-open → [].
 * Each bad pattern is skipped individually (never throws).
 *
 * Compile this ONCE at proxy startup; overrides/mode are re-resolved per call.
 * (Overrides are baked here for simplicity/parity with the hook — operators
 * changing overrides restart the proxy, same as re-invoking the hook.)
 */
export function loadBlockRules(): CompiledRule[] {
  try {
    const raw = JSON.parse(fs.readFileSync(resolveSnapshotPath(), 'utf8')) as unknown;
    if (!Array.isArray(raw)) return [];
    const overrides = loadOverrides();
    const compiled: CompiledRule[] = [];
    for (const r of raw as RawRule[]) {
      if (!r || typeof r.source !== 'string') continue;
      const label = typeof r.label === 'string' ? r.label : '(unlabeled)';
      const baked: 'alert' | 'block' = r.action === 'block' ? 'block' : 'alert';
      const ov = overrides[label];
      const effective = ov === 'block' || ov === 'alert' ? ov : baked;
      if (effective !== 'block') continue;
      try {
        compiled.push({
          re: new RegExp(r.source, typeof r.flags === 'string' ? r.flags : ''),
          label,
          severity: typeof r.severity === 'string' ? r.severity : 'high',
        });
      } catch {
        /* skip a single bad pattern */
      }
    }
    return compiled;
  } catch {
    return [];
  }
}

/**
 * Evaluate a tool call against the enforcement floors. Mode-INDEPENDENT: returns
 * whether the call "triggered"; the caller gates block-vs-log on the resolved mode.
 *
 * `matchText` is the PATH + ACTION text for the call (the Bash command, or an edit
 * tool's target path) — NEVER the static content of code being written. `editContent`
 * (optional) is the new body an edit would write; it is checked ONLY by the minimal
 * live-secret (DLP) floor, never against the ~630 threat rules. `targetPath`
 * (optional) is the file the call targets (an edit tool's path); the self-protection
 * and protected-paths floors match it (or the Bash command) against the control
 * plane / the user's protected list, exactly as the hook does — so an MCP caller
 * (Codex/Copilot/Claude Desktop via the proxy) hits the SAME floors as the hook.
 *
 * Order mirrors the hook: catastrophic floor, self-protection floor, protected-paths
 * floor, live-secret floor, then block rules.
 */
export function evaluate(
  matchText: string,
  blockRules: CompiledRule[],
  editContent = '',
  targetPath = '',
): EvalResult {
  // For Bash, matchText IS the command; for an edit tool it is the path. The
  // floors below want the Bash command and the file target separately — derive
  // the command form (matchText only carries a command when there is no edit target).
  const bashCmd = targetPath ? '' : matchText;

  for (const r of CATASTROPHIC) {
    if (r.re.test(matchText)) {
      return { triggered: true, label: r.why, severity: 'high', kind: 'catastrophic' };
    }
  }
  // Self-protection floor — agent must not edit the enforcement control plane.
  const self = selfProtectionHit(targetPath, bashCmd);
  if (self) {
    return { triggered: true, label: 'Self-protection: ' + self, severity: 'high', kind: 'catastrophic' };
  }
  // Protected-paths floor — user-defined, mirrored from the hook's artifact.
  const prot = protectedHit(loadProtectedPaths(), targetPath, bashCmd);
  if (prot) {
    return { triggered: true, label: 'Protected path: ' + prot.label, severity: 'high', kind: 'catastrophic' };
  }
  // Minimal live-secret (DLP) floor — edit content only. The sole content-based block.
  const secret = liveSecretHit(editContent);
  if (secret) {
    return { triggered: true, label: 'Live secret in edit: ' + secret.why, severity: 'high', kind: 'catastrophic' };
  }
  for (const r of blockRules) {
    if (r.re.test(matchText)) {
      return { triggered: true, label: r.label, severity: r.severity, kind: 'rule' };
    }
  }
  return { triggered: false, label: null, severity: 'high', kind: null };
}

/** Redact + truncate text for safe logging (parity with the hook's redact). */
export function redact(text: string): string {
  let t = String(text || '').replace(/\s+/g, ' ').trim();
  if (t.length > 300) t = t.slice(0, 300) + '…';
  return t;
}

/**
 * Best-effort POST of an enforce-log event to the dashboard. Mirrors the hook:
 * resolves the port from CLAUDESEC_PORT → PORT → 3000, never throws, never
 * gates the caller. Resolves when the request settles or a backstop fires.
 */
export function postEnforceLog(payload: {
  mode: string;
  label: string;
  severity: string;
  command: string;
  wouldBlock: boolean;
}): Promise<void> {
  // Uses the global fetch (Node ≥18) so this works identically under tsx ESM,
  // a Vite/Node build, or plain node — no require()/import-interop pitfalls.
  // Port: CLAUDESEC_PORT → PORT → 3000 (parity with the hook).
  const portRaw = Number(process.env.CLAUDESEC_PORT ?? process.env.PORT);
  const port = Number.isFinite(portRaw) && portRaw > 0 ? portRaw : 3000;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 400);
  if (timer.unref) timer.unref();

  return fetch(`http://127.0.0.1:${port}/api/enforce-log`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: ac.signal,
  })
    .then((res) => { void res.text().catch(() => undefined); }) // drain & discard
    .catch(() => undefined) // swallow everything — logging must never gate the caller
    .finally(() => clearTimeout(timer));
}
