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
// KNOWN LIMITATIONS (accepted residual evasions, documented not silently missed):
//   • Double-slash targets (`rm -rf //etc`, redirect `>//dev/sda`) — the `/`-anchored
//     patterns expect a single leading slash; a doubled slash is a rare hand-typed form.
//   • `rm -- /etc` — the POSIX end-of-options `--` separator before the path.
//   • Long-flag spellings (`rm --recursive --force /etc`) — only the short `-rf`/`-fr`
//     bundle is matched; the verbose flags are uncommon in practice.
//   • Brace/var expansion in the target (`rm -rf ${SYSROOT}`, `$DIR`) — only a literal
//     `~`/`$HOME` is expanded; arbitrary shell variables are out of scope for a static
//     pre-exec floor (the server-side detection layer is the backstop for those).
// The `-[a-zA-Z]*(?:r…f|f…r)…` flag fragment below is order-independent (catches both
// `-rf` and `-fr`, plus combined long-ish bundles like `-rvf`/`-fvr`).
export const CATASTROPHIC: { re: RegExp; why: string }[] = [
  { re: /\brm\s+-[a-zA-Z]*(?:r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*\s+(?:--no-preserve-root\s+)?\/\s*(?:$|\*|[;&|>])/m, why: 'rm -rf on the filesystem root (/)' },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:/, why: 'fork bomb' },
  { re: /\b(?:curl|wget)\b[^|>\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i, why: 'piping a remote download straight into a shell' },
  { re: /\b(?:ba)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/tcp\//i, why: 'reverse shell via /dev/tcp' },
  { re: /\bmkfs\.[a-z0-9]+\b/i, why: 'formatting a filesystem (mkfs)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|disk|hd|mmcblk)/i, why: 'overwriting a raw disk device (dd of=/dev/...)' },
  { re: /(?:cat|base64|tac|xxd|od|head|tail|gpg)\b[^\n|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))[^\n|]*\|[^\n;&]*\b(?:curl|wget|nc|ncat|telnet)\b/i, why: 'reading a secret and piping it into a network tool' },
  { re: /\b(?:curl|wget)\b[^\n;&|]*(?:-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)[ =]@?[^\n;&|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))/i, why: 'uploading a secret file over the network (curl/wget)' },
  // `rm --no-preserve-root` is the single flag that tells GNU rm to delete the
  // filesystem root anyway — match it wherever it sits in an `rm` command line.
  { re: /(?:^|[\n;&|`(]|&&|\bsudo\s+)\s*rm\b[^\n]*\s--no-preserve-root\b/, why: 'rm --no-preserve-root (defeats the filesystem-root guard)' },
  // Recursive delete of a critical system tree or the whole home. We block the
  // unambiguously catastrophic targets only and CARVE OUT user/temp territory so a
  // routine cleanup is never walled off:
  //   • /etc /boot /System /Library  — whole tree.
  //   • /usr — bare, or /usr/{bin,lib,libexec,sbin,share,include}, but NOT /usr/local
  //     (Homebrew / npm-global live there and get wiped constantly).
  //   • /var — bare, or /var/{lib,log,db,spool,run,cache,mail,backups}, but NOT
  //     /var/folders or /var/tmp (the macOS $TMPDIR — build/test tools wipe these all
  //     day). /private/var/… is likewise left alone.
  //   • ~ / $HOME — the whole home, not a sub-path.
  // Each target ends at a path separator / whitespace / shell separator so /var.bak,
  // /etcd, /usrlocal (user paths) and ~/project, $HOME/dist stay allowed. The flag
  // fragment is order-independent (-rf and -fr both match).
  { re: /\brm\s+-[a-zA-Z]*(?:r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:etc|boot|System|Library)(?:\/|\s|$|[;&|])|\/usr(?:\/(?:bin|lib|lib64|libexec|sbin|share|include)(?:\/|\s|$|[;&|])|\s|$|[;&|])|\/var(?:\/(?:lib|log|db|spool|run|cache|mail|backups)(?:\/|\s|$|[;&|])|\s|$|[;&|])|~(?:\/?\s|\/?$)|\$HOME(?:\/?\s|\/?$))/m, why: 'recursive delete of a critical system directory or the whole home' },
  // netcat reverse shell: -e / -c hands the connecting peer a program (a shell). The
  // dangerous flag is matched as a standalone token ANYWHERE after the nc command
  // (before or after the host), via a single linear pass — no overlapping `(A|B)*`
  // quantifier, so a long flag list can never trigger catastrophic backtracking.
  { re: /\b(?:nc|ncat|netcat)\b[^\n]*?\s-[a-zA-Z]*[ec][a-zA-Z]*(?:\s|$)/i, why: 'reverse shell via netcat (nc -e / -c)' },
  // Reverse shell over /dev/udp (the UDP twin of the /dev/tcp pattern above).
  { re: /\b(?:ba)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/udp\//i, why: 'reverse shell via /dev/udp' },
  // Windows whole-disk / boot destroyers at command position. `format` is required to
  // carry a drive-letter argument (`format c:`, `format /q d:`) so the bare Unix word
  // — `make format`, `npm run format`, a `format` alias, `--format=` — is never walled
  // off. diskpart/bcdedit are destructive by name; the boundary keeps `bcdedit_log`,
  // `formatter`, `diskpartition` from matching.
  { re: /(?:^|[\n;&|`(]|&&)\s*(?:format\s+(?:\/[a-z:]+\s+)*[a-z]:|diskpart|bcdedit)(?:\s|$|[\\/:])/i, why: 'Windows destructive command (format <drive:>/diskpart/bcdedit)' },
  // Windows forced/recursive delete: del/erase with a /f, /q or /s switch.
  { re: /(?:^|[\n;&|`(]|&&)\s*(?:del|erase)\s+(?:\/[a-z]\s+)*\/[qsf]\b/i, why: 'Windows forced/recursive delete (del /f /q /s)' },
  // Windows recursive directory removal: rd /s or rmdir /s.
  { re: /(?:^|[\n;&|`(]|&&)\s*(?:rd|rmdir)\s+(?:\/[a-z]\s+)*\/s\b/i, why: 'Windows recursive directory removal (rd /s)' },
  // Deleting volume shadow copies — the anti-recovery step in ransomware playbooks.
  { re: /\bvssadmin\s+delete\s+shadows\b/i, why: 'deleting volume shadow copies (vssadmin delete shadows)' },
  // Secure-wiping free disk space (cipher /w) — destroys recoverable data.
  { re: /\bcipher\s+\/w\b/i, why: 'secure-wiping free disk space (cipher /w)' },
  // Wiping the Windows event log (wevtutil cl) — destroys the audit trail.
  { re: /\bwevtutil\s+(?:cl|clear-log)\b/i, why: 'wiping the Windows event log (wevtutil cl)' },
  // Redirecting output straight onto a raw disk device clobbers the partition table.
  // An optional partition / NVMe-namespace suffix is matched too, so a redirect onto
  // a single partition (/dev/sda1, /dev/nvme0n1, /dev/nvme0n1p2, /dev/mmcblk0p1) is
  // caught alongside the whole-device form.
  { re: />\s*\/dev\/(?:sd[a-z]\d*|disk\d+|nvme\d+(?:n\d+(?:p\d+)?)?|hd[a-z]\d*|mmcblk\d+(?:p\d+)?|vd[a-z]\d*)\b/i, why: 'redirecting output onto a raw disk device' },
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
    for (const e of raw as { path?: unknown; label?: unknown; forms?: unknown }[]) {
      if (!e || typeof e.path !== 'string' || e.path.length === 0) continue;
      const p = e.path;
      const expanded =
        p === '~' ? home
        : p.startsWith('~/') ? path.join(home, p.slice(2))
        : p;
      const label = typeof e.label === 'string' && e.label.length > 0 ? e.label : p;
      const forms = expanded === p ? [p] : [p, expanded];
      // Fold in any add-time resolved symlink forms the server stored (e.g. the
      // realpath of a symlinked entry), so both the symlink and its target match.
      if (Array.isArray(e.forms)) {
        for (const f of e.forms) {
          if (typeof f === 'string' && f.length > 0 && !forms.includes(f)) forms.push(f);
        }
      }
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
 * Resolve a path's symlinks to its real on-disk location so a symlink pointing
 * INTO a protected tree can't launder the target string past the substring match.
 * Returns the realpath, or '' when it can't be resolved. Parity with
 * resolveRealpath() in cli/hooks/claudesec-enforce.cjs.
 *
 * fs.realpathSync THROWS when the path doesn't exist yet (e.g. a Write/Edit that
 * CREATES a new file), so we degrade gracefully: walk up to the nearest EXISTING
 * ancestor directory, realpath THAT, then re-append the not-yet-existing tail (so
 * a write to `/tmp/linkdir/newfile` is still caught when `/tmp/linkdir` is a
 * symlink into a protected tree). If even that fails we return '' (the caller
 * still has the literal substring match). Never throws.
 */
export function resolveRealpath(p: string): string {
  if (!p) return '';
  try {
    return fs.realpathSync(p);
  } catch {
    // Path (or some ancestor) doesn't exist — resolve the nearest existing parent.
  }
  try {
    let dir = path.dirname(p);
    const tail = [path.basename(p)];
    while (dir && dir !== path.dirname(dir)) {
      try {
        const realDir = fs.realpathSync(dir);
        return path.join(realDir, ...tail.reverse());
      } catch {
        tail.push(path.basename(dir));
        dir = path.dirname(dir);
      }
    }
  } catch {
    // Any unexpected failure → give up on realpath; caller keeps the literal match.
  }
  return '';
}

/**
 * Does a protected entry match the call's file TARGET or Bash command? Matches
 * case-INSENSITIVE substring (case-insensitive filesystems make a case-sensitive
 * compare a trivial bypass) against the target path or the (HOME-expanded) Bash
 * command — NEVER edit content. Returns the matching entry or null. Parity with
 * protectedHit() in cli/hooks/claudesec-enforce.cjs.
 *
 * SYMLINK GUARD: the literal substring alone is bypassable —
 * `ln -s /protected/secret.env /tmp/innocent` then editing `/tmp/innocent` never
 * names the protected string. So for the file TARGET we ALSO resolve the symlink
 * chain (resolveRealpath, with an existing-ancestor fallback for not-yet-created
 * files) and match the entry forms against the REAL path too — keeping the literal
 * match so nothing regresses. The Bash command is matched literally only.
 */
export function protectedHit(
  entries: ProtectedEntry[],
  target: string,
  bashCmd: string,
): ProtectedEntry | null {
  const tLit = target ? target.toLowerCase() : '';
  const real = target ? resolveRealpath(target) : '';
  const tReal = real ? real.toLowerCase() : '';
  const c = bashCmd ? expandHomeVar(bashCmd).toLowerCase() : '';
  for (const e of entries) {
    for (const form of e.forms) {
      const f = form.toLowerCase();
      if ((tLit && tLit.includes(f)) || (tReal && tReal.includes(f)) || (c && c.includes(f))) {
        return e;
      }
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
