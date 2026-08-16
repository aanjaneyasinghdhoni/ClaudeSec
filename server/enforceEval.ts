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
  // The shell on the receiving end of the pipe is any POSIX-ish shell, not just
  // `sh`/`bash` — `zsh`/`ksh`/`dash`/`ash`/`fish` execute the payload just the same.
  // The trailing \b is what keeps the common hash/inspection pipelines out:
  // `| shasum`, `| sha256sum` have no word boundary after `sh`.
  { re: /\b(?:curl|wget)\b[^|>\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da|fi|a)?sh\b/i, why: 'piping a remote download straight into a shell' },
  { re: /\b(?:ba|z|k|da|a)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/tcp\//i, why: 'reverse shell via /dev/tcp' },
  // `mkfs` is only destructive at COMMAND POSITION (line start, after a shell
  // separator, or handed to sudo/xargs) or when it names a /dev/ target. Matching
  // the bare word anywhere walled off ordinary work — grepping the threat docs,
  // committing a message that mentions `mkfs.ext4`, a `sed` script rewriting the
  // string — none of which formats anything. The second alternative also catches
  // the sub-command spellings the old word-match missed, e.g. `mkfs -t ext4 /dev/sda`.
  { re: /(?:^|[\n;&|`(]|&&|\bsudo\s+|\bxargs\s+)\s*mkfs(?:\.[a-z0-9]+)?\b|\bmkfs(?:\.[a-z0-9]+)?\s+(?:-\S+\s+)*\/dev\//i, why: 'formatting a filesystem (mkfs)' },
  { re: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|disk|hd|mmcblk)/i, why: 'overwriting a raw disk device (dd of=/dev/...)' },
  { re: /(?:cat|base64|tac|xxd|od|head|tail|gpg)\b[^\n|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))[^\n|]*\|[^\n;&]*\b(?:curl|wget|nc|ncat|telnet)\b/i, why: 'reading a secret and piping it into a network tool' },
  { re: /\b(?:curl|wget)\b[^\n;&|]*(?:-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)[ =]@?[^\n;&|]*(?:id_rsa|id_ed25519|id_ecdsa|\.env(?!\.?(?:example|sample|template|dist|tpl)\b)\b|\.aws\/credentials|\.ssh\/[^\s|]*key|secrets?\.(?:json|ya?ml|env))/i, why: 'uploading a secret file over the network (curl/wget)' },
  // `rm --no-preserve-root` is the single flag that tells GNU rm to delete the
  // filesystem root anyway — match it wherever it sits in an `rm` command line.
  { re: /(?:^|[\n;&|`(]|&&|\bsudo\s+)\s*rm\b[^\n]*\s--no-preserve-root\b/, why: 'rm --no-preserve-root (defeats the filesystem-root guard)' },
  // Recursive delete of a critical system tree or the whole home. The system roots
  // split into two kinds, because a deep path under them means opposite things:
  //   • Fatal at ANY depth — /etc /boot /sys /bin /sbin, plus the macOS /System and
  //     /Library. These hold config and executables; deleting any subtree of them
  //     breaks the machine.
  //   • Fatal only as the WHOLE target — /var /usr /lib /opt /srv, plus the
  //     second-level trees that are as fatal as the root itself when named whole
  //     (/usr/{bin,sbin,lib,lib64,libexec,local,include}, /var/{lib,log,db,spool}).
  //     Their deep paths are where routine cleanup lives: `rm -rf /var/lib/apt/lists/*`
  //     and `rm -rf /var/cache/apk/*` end almost every Debian and Alpine image build,
  //     `rm -rf /usr/share/doc` is the standard slimming line, and `rm -rf /var/log/*.gz`
  //     is log rotation. The floor used to end each root at the following slash, so all
  //     four were refused — in monitor mode too, with no per-action escape.
  //   • ~ / $HOME — the whole home, not a sub-path.
  // This mirrors the high-severity twin ('rm -rf on critical system directory') in
  // server/severityRulesExtra.ts exactly: a floor stricter than the rule it backstops
  // is a floor nobody can reason about. Each whole-target arm ends at whitespace, a
  // shell separator or a quote, so /var.bak, /etcd, /usrlocal (user paths) and
  // ~/project, $HOME/dist stay allowed; an optional quote on the left means
  // `rm -rf "/var"` no longer slips past. The flag fragment is order-independent
  // (-rf and -fr both match).
  { re: /\brm\s+-[a-zA-Z]*(?:r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*\s+(?:--no-preserve-root\s+)?['"]?(?:\/(?:etc|boot|sys|bin|sbin|System|Library)(?=$|[\/\s;&|>)'"])|\/(?:usr|var)(?:\/(?:bin|sbin|lib|lib64|libexec|local|include|log|db|spool))?\/?(?=$|[\s;&|>)'"])|\/(?:lib|opt|srv)\/?(?=$|[\s;&|>)'"])|~(?:\/?\s|\/?$)|\$HOME(?:\/?\s|\/?$))/m, why: 'recursive delete of a critical system directory or the whole home' },
  // netcat reverse shell: -e / -c hands the connecting peer a program (a shell). The
  // dangerous flag is matched as a standalone token ANYWHERE after the nc command
  // (before or after the host), via a single linear pass — no overlapping `(A|B)*`
  // quantifier, so a long flag list can never trigger catastrophic backtracking.
  // The second branch covers ncat's LONG spellings of the same handoff
  // (--exec / --sh-exec / --lua-exec), which the short-flag branch cannot reach
  // because `--exec` has no single-dash bundle. Named exactly, so the other long
  // flags (`--ssl`, `--crlf`, `--send-only`, `--listen`) stay allowed.
  { re: /\b(?:nc|ncat|netcat)\b[^\n]*?\s(?:-[a-zA-Z]*[ec][a-zA-Z]*(?:\s|$)|--(?:exec|sh-exec|lua-exec)\b)/i, why: 'reverse shell via netcat (nc -e / -c / --exec)' },
  // Reverse shell over /dev/udp (the UDP twin of the /dev/tcp pattern above); both
  // accept any POSIX-ish shell name, since `zsh -i`/`ksh -i`/`dash -i` build the
  // same socket. `fish` is absent by design — it has no /dev/tcp redirect.
  { re: /\b(?:ba|z|k|da|a)?sh\b[^\n]*-i\b[^\n]*>&?\s*\/dev\/udp\//i, why: 'reverse shell via /dev/udp' },
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
  // AKIA (long-term) and ASIA (STS/temporary) share one key-id shape; kept as a
  // single entry so the two spellings can never drift apart.
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, why: 'AWS access key id (long-term or temporary)' },
  { re: /\bghp_[0-9A-Za-z]{36}\b/, why: 'GitHub personal access token' },
  { re: /\bgh[oprsu]_[0-9A-Za-z]{36}\b/, why: 'GitHub OAuth/server/refresh/user token' },
  { re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/, why: 'GitHub fine-grained token' },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, why: 'Slack token' },
  // Stripe ships two live server-side keys: the secret key (sk_) and the restricted
  // key (rk_). Both authenticate; the publishable `pk_live_` deliberately does not match.
  { re: /\b[rs]k_live_[0-9A-Za-z]{20,}\b/, why: 'Stripe live secret/restricted key' },
  { re: /\bAIza[0-9A-Za-z_\-]{35}\b/, why: 'Google API key' },
  { re: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/, why: 'OpenAI project API key' },
  { re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/, why: 'Anthropic API key' },
  { re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/, why: 'GitLab personal access token' },
  { re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, why: 'SendGrid API key' },
  { re: /\bSK[0-9a-fA-F]{32}\b/, why: 'Twilio API key SID' },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/, why: 'npm access token' },
  // HuggingFace user access token: `hf_` + exactly 34 LETTERS. The all-alpha,
  // fixed-length body is what keeps the ubiquitous `hf_token` / `hf_home` /
  // `hf_hub_download` identifiers out.
  { re: /\bhf_[A-Za-z]{34}\b/, why: 'HuggingFace user access token' },
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

// An exact-value allowlist cannot scale: every project writes a `.env.example`, and
// each one spells its fill-me-in differently (`sk-ant-api03-REPLACE-ME-WITH-YOUR-KEY`,
// `xoxb-YOUR-SLACK-TOKEN-HERE`, `glpat-XXXXXXXXXXXXXXXXXXXX`). Those are the exact
// SHAPE of a live key, so the floor refused to let anyone author a template.
//
// So a match is also released when the MATCHED TOKEN ITSELF carries an obvious
// fill-me-in marker. Scoped deliberately narrow:
//   • Only the matched credential is tested — never the surrounding text, so a real
//     key sitting in a file that happens to say "example" is still blocked.
//   • Every marker is a word a credential generator cannot emit: runs of x/X/* (no
//     issuer pads a key that way), or an English fill-me-in word. Real tokens are
//     base62/hex and carry no such substring.
const SECRET_PLACEHOLDER_MARKERS =
  /(?:x{4,}|X{4,}|\*{4,}|your[_\-]?|replace|example|placeholder|changeme|change[_\-]?me|dummy|redacted|<[a-z_]+>|\.{3,})/i;

/**
 * Does the edit CONTENT carry an unambiguous live credential? Returns the matching
 * entry or null. This is the minimal DLP floor — the only reason an edit's content
 * (not its path) can be blocked. A match is ignored when its value is a known
 * placeholder (SECRET_PLACEHOLDERS) or the matched token itself carries a
 * fill-me-in marker (SECRET_PLACEHOLDER_MARKERS). See LIVE_SECRET.
 */
export function liveSecretHit(content: string): { re: RegExp; why: string } | null {
  if (!content) return null;
  for (const r of LIVE_SECRET) {
    const m = content.match(r.re);
    if (!m) continue;
    if (SECRET_PLACEHOLDERS.has(m[0])) continue;
    if (SECRET_PLACEHOLDER_MARKERS.test(m[0])) continue;
    return r;
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
  /** A dotenv-secret SHAPE default (matched by secretEnvHit, not a literal form). */
  secretEnv?: boolean;
}

// ── Default protected paths (always merged in) ───────────────────────────────
// The user's protected-paths list is EMPTY on a fresh install, so without these
// defaults the floor would protect nothing out of the box. We merge in a small,
// conservative, HIGH-VALUE set of credential stores that an agent should never
// read or overwrite. Kept minimal to avoid over-blocking ordinary work; the user
// can still remove any of these (they are not pinned). Kept in sync with
// defaultProtectedEntries() in cli/hooks/claudesec-enforce.cjs (parity test).
export function defaultProtectedEntries(): ProtectedEntry[] {
  const home = os.homedir();
  const mk = (rel: string, label: string): ProtectedEntry => ({
    label,
    forms: ['~/' + rel, path.join(home, rel)],
  });
  return [
    mk('.ssh', 'SSH keys (~/.ssh)'),
    mk('.aws/credentials', 'AWS credentials (~/.aws/credentials)'),
    mk('.config/gcloud', 'gcloud config (~/.config/gcloud)'),
    mk('.kube/config', 'Kubernetes config (~/.kube/config)'),
    mk('.npmrc', 'npm credentials (~/.npmrc)'),
    // Dotenv secrets — matched by shape, not a literal path (see secretEnvHit).
    { label: 'dotenv secret (*.env)', forms: [], secretEnv: true },
  ];
}

/**
 * A path "looks like" a dotenv SECRET file when its final component is exactly
 * `.env` or starts with `.env.` BUT is not one of the well-known non-secret
 * template variants (`.env.example`/`.sample`/`.template`/`.dist`/`.tpl`). So
 * `.env`/`.env.local`/`.env.production` are protected; the committed templates are
 * not. Mirrors secretEnvHit() in cli/hooks/claudesec-enforce.cjs. `targetLower`
 * must already be lowercased.
 */
export function secretEnvHit(targetLower: string): boolean {
  if (!targetLower) return false;
  const base = targetLower.split(/[\\/]/).pop() || '';
  if (base === '.env') return true;
  if (!base.startsWith('.env.')) return false;
  const suffix = base.slice('.env.'.length);
  return !/^(?:example|sample|template|dist|tpl)$/.test(suffix);
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
  // ALWAYS start with the conservative built-in defaults so a fresh install
  // (empty/missing user list) still protects the high-value credential stores.
  // The user's entries are merged on top; a user entry never removes a default.
  const out: ProtectedEntry[] = defaultProtectedEntries();
  try {
    const raw = JSON.parse(fs.readFileSync(resolveProtectedPathsPath(), 'utf8')) as unknown;
    if (!Array.isArray(raw)) return out;
    const home = os.homedir();
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
    return out; // missing / unreadable / malformed → still apply the defaults
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
    // The dotenv-secret default matches by SHAPE rather than a literal form, and
    // ONLY against the file TARGET (literal or symlink-resolved) — never the Bash
    // command (a path-shape match on a free-form command would block a plain
    // `cat .env` read; the always-on EXFIL catastrophic floor already covers the
    // dangerous `.env`-read-piped-to-network case). Parity with protectedHit() in
    // cli/hooks/claudesec-enforce.cjs.
    if (e.secretEnv) {
      if (secretEnvHit(tLit) || secretEnvHit(tReal)) return e;
      continue;
    }
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
// An agent must never be able to switch off the thing that is watching it, so a
// tool call that could CHANGE the enforcement control plane is refused in every
// mode. This is the ESM sibling of selfProtectionHit() in
// cli/hooks/claudesec-enforce.cjs, and the two must reach the same verdict: a
// cross-agent MCP caller goes through the proxy, a Claude Code call goes through
// the hook, and a floor that only holds on one of those paths is not a floor.
// tests/enforceParityTest.ts drives identical inputs through both layers.
//
// Two things separate a real floor from theatre, and both are mirrored here:
//   • It is anchored on the WRITE, never on the filename. Reading, grepping or
//     naming `settings.json` in a commit message is ordinary developer work every
//     hour of the day; only an action that could CHANGE the file is denied. None
//     of these files hold a secret, so denying a look at them bought nothing.
//   • Every candidate path is normalized before it is compared: `~` and `$HOME`
//     expanded, relative and `../` spellings resolved, and the symlink chain
//     followed. A floor a `../` walks around protects nothing.
//
// Guards AGENT tool calls only; the ClaudeSec SERVER writes these files from its
// own process, which never passes through this evaluator.
//
// READS are exempt on both layers, by different mechanisms — the hook knows the
// tool NAME and skips the file target for Read/NotebookRead, while this evaluator
// only ever sees a `targetPath` (which mcpProxy populates for EDIT-shaped calls
// only) and the WRITE targets extracted from a command. A read-shaped call
// therefore reaches no comparison here either.

/**
 * Control-plane FILENAMES. These four names are ClaudeSec's own artefacts and
 * mean the same thing wherever they sit — the installed copies under
 * ~/.claudesec/hooks, a Docker-bundled copy beside the hook, or the generated
 * copies in a checkout. Matching the basename covers every layout without having
 * to enumerate them. Mirrors SELF_BASENAMES in cli/hooks/claudesec-enforce.cjs.
 */
const SELF_BASENAMES = new Set<string>([
  'enforce-config.json',
  'rules-enforcement.json',
  'protected-paths.json',
  'claudesec-enforce.cjs',
]);

/**
 * Shell commands that WRITE. Anything in this set mutates whatever path it is
 * handed, so naming a control-plane file anywhere in its arguments is a block.
 * Mirrors MUTATING_COMMANDS in cli/hooks/claudesec-enforce.cjs.
 */
const MUTATING_COMMANDS = new Set<string>([
  'rm', 'unlink', 'truncate', 'shred', 'srm', 'mv', 'cp', 'install', 'ln', 'dd',
  'tee', 'chmod', 'chown', 'chgrp', 'chattr', 'chflags', 'touch', 'mkdir',
  'rmdir', 'rsync', 'ditto', 'patch', 'sponge', 'plutil', 'defaults',
  'launchctl', 'systemctl',
]);

/**
 * Words that sit in front of the real verb and must be skipped when working out
 * what a command actually runs (`sudo tee …`, `FOO=1 rm …`, `xargs rm …`).
 */
const COMMAND_PREFIXES = /^(?:sudo|doas|env|nohup|command|exec|time|nice|xargs|then|do|else)$/;

/**
 * Directories and files that, if written, can switch enforcement off. Resolved
 * fresh on every call so the floor tracks CLAUDESEC_HOME, the process cwd, and
 * whichever artefacts this evaluator is actually reading. Parity with
 * selfProtectedPrefixes() in cli/hooks/claudesec-enforce.cjs.
 */
function selfProtectedPrefixes(): string[] {
  const home = os.homedir();
  // Honor CLAUDESEC_HOME exactly as the installer/hook do, so the guard tracks
  // wherever the control plane actually lives.
  const csecHome = process.env.CLAUDESEC_HOME || path.join(home, '.claudesec');
  // Project-level Claude settings (<cwd>/.claude/…) are ALSO honored by Claude
  // Code, so an agent could write those to register a competing PreToolUse hook
  // and unhook the enforcer. Guard them alongside the user-level files. cwd is
  // resolved at call time so the floor tracks whichever project is in play.
  const cwd = process.cwd();
  const out = [
    path.join(csecHome, 'hooks'),           // whole enforcement control-plane dir
    path.join(csecHome, 'audit-key'),       // prefix: audit-key + its .pem siblings
    path.join(csecHome, 'audit-anchor.json'),
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
    path.join(home, '.claude', 'hooks'),
    path.join(cwd, '.claude', 'settings.json'),
    path.join(cwd, '.claude', 'settings.local.json'),
    path.join(cwd, '.claude', 'hooks'),
    // The hook protects its own `__dirname` — the directory the running copy and
    // its artefacts live in. This module's __dirname is `server/`, which is
    // ordinary source code an agent legitimately edits, so the enforcer's own
    // directory is named explicitly instead of self-referenced.
    path.join(REPO_ROOT, 'cli', 'hooks'),
    // The three artefacts this evaluator actually reads. Going through the same
    // resolvers means an explicit CLAUDESEC_ENFORCE_* override is protected too,
    // instead of only the default location.
    resolveConfigPath(),
    resolveSnapshotPath(),
    resolveProtectedPathsPath(),
  ];
  const seen = new Set<string>();
  const uniq: string[] = [];
  for (const p of out) {
    if (!p) continue;
    const k = p.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    uniq.push(p);
  }
  return uniq;
}

/**
 * Is this path the launchd plist / systemd unit that keeps ClaudeSec running?
 * Matched by SHAPE rather than a literal path because the file name carries the
 * bundle id and the directory differs per platform and per install (user agent,
 * system daemon, user systemd unit). `pathLower` must already be lowercased.
 * Mirrors serviceUnitHit() in cli/hooks/claudesec-enforce.cjs.
 */
function serviceUnitHit(pathLower: string): boolean {
  if (!pathLower) return false;
  return (
    /(?:^|\/)(?:launchagents|launchdaemons)\/[^/]{0,80}claudesec[^/]{0,40}\.plist/.test(pathLower) ||
    /(?:^|\/)systemd\/[^/]{0,40}\/[^/]{0,40}claudesec[^/]{0,40}\.(?:service|timer)/.test(pathLower)
  );
}

/**
 * Expand a leading `~` in every argument position of a command. `$HOME` is
 * already expanded (expandHomeVar); a tilde is the far more common spelling and,
 * left literal, let `echo x > ~/.claudesec/hooks/enforce-config.json` sail
 * straight past an absolute-prefix compare. Mirrors expandTilde() in the hook.
 */
function expandTilde(text: string): string {
  if (!text) return text;
  const home = os.homedir();
  return text.replace(/(^|[\s"'=:(])~(?=[/\s"')]|$)/g, (_m, lead: string) => lead + home);
}

/**
 * Substitute variables assigned EARLIER IN THE SAME command string, so
 * `P=~/.claude/settings.json; echo x > $P` still resolves onto a real path
 * instead of hiding behind one letter of indirection.
 *
 * Only literal, same-command assignments are followed. A variable exported by the
 * parent shell, set in an earlier command, or built by command substitution is out
 * of reach of static enforcement — the server-side detection layer remains the
 * backstop for those. Mirrors expandLocalVars() in the hook.
 */
function expandLocalVars(cmd: string): string {
  if (!cmd || cmd.indexOf('$') === -1) return cmd;
  const assigned = new Map<string, string>();
  const rx = /(?:^|[\n;&|(`]|\bexport\s+)\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(cmd)) !== null) {
    const value = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
    if (value) assigned.set(m[1], value);
  }
  if (!assigned.size) return cmd;
  return cmd.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (whole: string, braced: string | undefined, bare: string | undefined) => {
      const v = assigned.get(braced || bare || '');
      return v === undefined ? whole : v;
    },
  );
}

/**
 * Every spelling of `p` that should be compared against the protected prefixes:
 * the literal, the `~`/`$HOME`-expanded form, that form resolved against the cwd
 * (which also collapses `..`), and finally its realpath. The last two are what
 * stop the two cheapest bypasses — a relative or `../`-laundered path, and a
 * symlink planted to point into the control plane. resolveRealpath already falls
 * back to the nearest existing ancestor, so a file that does not exist yet (the
 * usual case for a write) still resolves through a symlinked parent directory.
 *
 * CAVEAT vs the hook: `path.resolve` uses THIS process's cwd. The hook runs inside
 * the agent's session, so its cwd is the agent's project; the MCP proxy is spawned
 * by the agent's MCP client and inherits the same working directory, which is also
 * the cwd the downstream MCP server resolves relative paths against. The two agree
 * in the normal deployment; a proxy deliberately started from another directory
 * would resolve a relative path differently, and the absolute/tilde/realpath forms
 * are what carry the floor in that case.
 * Mirrors selfPathForms() in cli/hooks/claudesec-enforce.cjs.
 */
function selfPathForms(p: string): string[] {
  if (!p) return [];
  const home = os.homedir();
  const forms: string[] = [];
  const push = (v: string): void => { if (v && !forms.includes(v)) forms.push(v); };
  push(p.toLowerCase());
  const expanded = expandHomeVar(
    p === '~' ? home : p.startsWith('~/') ? path.join(home, p.slice(2)) : p,
  );
  push(expanded.toLowerCase());
  let abs = '';
  try {
    abs = path.resolve(process.cwd(), expanded);
    push(abs.toLowerCase());
  } catch {
    // An unresolvable path keeps the literal forms above; never throw.
  }
  const real = resolveRealpath(abs || expanded);
  if (real) push(real.toLowerCase());
  return forms;
}

/** Does any spelling of `p` land on the control plane? Returns a reason or null. */
function selfPathHit(p: string): string | null {
  const forms = selfPathForms(p);
  if (!forms.length) return null;
  const prefixes = selfProtectedPrefixes();
  for (const form of forms) {
    for (const prefix of prefixes) {
      if (form.includes(prefix.toLowerCase())) return prefix;
    }
    if (SELF_BASENAMES.has(form.split(/[\\/]/).pop() || '')) return 'the ClaudeSec enforcement control plane';
    if (serviceUnitHit(form)) return 'the ClaudeSec service definition';
  }
  return null;
}

/**
 * Copy-shaped commands: the DESTINATION is the write, the earlier path arguments
 * are reads. Treating every argument of a `cp` as a write refused
 * `cp ~/.claude/settings.json /tmp/backup.json` — an ordinary backup, and a READ
 * of the control plane, which the floor is explicitly not meant to police.
 *
 * `mv` is deliberately absent: it REMOVES its source, so both ends of an `mv` are
 * writes. So are `rm`, `truncate`, `shred`, `chmod`, `chown` and `ln` — all of
 * them keep the every-argument reading.
 * Mirrors COPY_COMMANDS in cli/hooks/claudesec-enforce.cjs.
 */
const COPY_COMMANDS = new Set<string>(['cp', 'rsync', 'ditto', 'install']);

/**
 * Work out which arguments of a copy-shaped command are WRITE targets.
 *
 *   • Normally the destination is the final path argument (`cp a b c dir/`).
 *   • GNU `cp`/`install` accept `-t DIR` / `--target-directory=DIR`, which puts the
 *     destination FIRST and the sources last. Only those two verbs get that
 *     reading: rsync's `-t` means "preserve times", so honouring it there would let
 *     `rsync -t evil ~/.claudesec/hooks/x` walk straight past the floor.
 *   • An `-o` / `--output` style flag names an output path; its value is added as an
 *     EXTRA target and never suppresses the trailing one, so `install -o root src dst`
 *     (where `-o` is really the owner) still reports `dst`. The cost is one harmless
 *     extra candidate.
 *   • `install -d` creates every directory it is handed, so all of them are writes.
 *
 * Flags whose value sits in the next token are not modelled beyond those cases; an
 * unrecognised flag value simply becomes a positional candidate, which at worst adds
 * a target. Erring toward MORE targets keeps the floor from being talked around.
 * Mirrors copyWriteTargets() in cli/hooks/claudesec-enforce.cjs.
 */
function copyWriteTargets(verb: string, args: string[]): string[] {
  const targets: string[] = [];
  const positional: string[] = [];
  const honorsTargetDir = verb === 'cp' || verb === 'install';
  let explicitDir = false;
  let makeDirs = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // POSIX end-of-options: everything after it is a path.
    if (a === '--') { for (const rest of args.slice(i + 1)) positional.push(rest); break; }
    const eq = a.startsWith('--') ? a.indexOf('=') : -1;
    const name = eq > 0 ? a.slice(0, eq) : a;
    const inline = eq > 0 ? a.slice(eq + 1) : null;
    if (honorsTargetDir && (name === '-t' || name === '--target-directory')) {
      const v = inline !== null ? inline : args[i + 1];
      if (v) { targets.push(v); explicitDir = true; if (inline === null) i++; }
      continue;
    }
    if (name === '-o' || name === '--output' || name === '--output-file') {
      const v = inline !== null ? inline : args[i + 1];
      if (v && !v.startsWith('-')) { targets.push(v); if (inline === null) i++; }
      continue;
    }
    if (a.length > 1 && a.startsWith('-')) {
      if (verb === 'install' && /^-[a-zA-Z]*d/.test(name)) makeDirs = true;
      continue;
    }
    positional.push(a);
  }
  if (makeDirs) return targets.concat(positional);
  if (explicitDir) return targets;
  if (positional.length) targets.push(positional[positional.length - 1]);
  return targets;
}

/**
 * Pull the paths a command would WRITE to out of the command line. This is
 * deliberately a heuristic and not a shell parser — it only has to tell "reads
 * this path" from "writes this path", which is what keeps `cat …/settings.json`
 * allowed while `cat foo > …/settings.json` is denied.
 *
 * Two things count as a write target:
 *   • a token immediately after a `>` / `>>` redirect, whatever produced the
 *     stream; and
 *   • every argument of a mutating command (MUTATING_COMMANDS), plus the
 *     conditional writers — `sed`/`perl` given `-i`, and an interpreter given an
 *     inline `-c`/`-e` script (the script body is returned whole AND split, so a
 *     path buried inside it is still compared). The copy-shaped verbs are the one
 *     exception: only their destination counts (see copyWriteTargets).
 * Mirrors bashWriteTargets() in cli/hooks/claudesec-enforce.cjs.
 */
function bashWriteTargets(cmd: string): string[] {
  const out: string[] = [];
  if (!cmd) return out;
  // Resolve indirection before tokenizing: same-command variables first, then
  // $HOME, then `~`. Each layer feeds the next, so `P=~/x; … > $P` ends up as an
  // absolute path the prefix compare can actually see.
  const expanded = expandTilde(expandHomeVar(expandLocalVars(cmd)));
  // Rough split into simple commands: a shell separator or a command substitution
  // starts a new command, and a verb only governs the arguments in its own
  // segment. Parentheses are deliberately NOT split on — an inline
  // `python -c "open(...)"` script is one argument and must stay intact.
  for (const seg of expanded.split(/[\n;|&`]+|\$\(/)) {
    const tokens: { val: string; redirect: boolean }[] = [];
    const rx = /(>>?|<|"([^"]*)"|'([^']*)'|[^\s"'<>|;&]+)/g;
    let m: RegExpExecArray | null;
    let redirect = false;
    while ((m = rx.exec(seg)) !== null) {
      if (m[0] === '>' || m[0] === '>>') { redirect = true; continue; }
      if (m[0] === '<') { redirect = false; continue; }
      const val = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[0];
      tokens.push({ val, redirect });
      redirect = false;
    }
    if (!tokens.length) continue;
    // A redirect target is a write no matter which command produced the stream.
    for (const t of tokens) if (t.redirect) out.push(t.val);
    // Command position: step over env assignments and the usual wrappers.
    let i = 0;
    while (i < tokens.length &&
           (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i].val) || COMMAND_PREFIXES.test(tokens[i].val))) {
      i++;
    }
    if (i >= tokens.length) continue;
    const verb = tokens[i].val.replace(/^.*[\\/]/, '');
    const args = tokens.slice(i + 1).map((t) => t.val);
    const writes =
      MUTATING_COMMANDS.has(verb) ||
      // `sed -i` / `perl -pi -e` edit in place; without -i they only read.
      (/^(?:sed|perl|ruby|gawk|awk)$/.test(verb) &&
        args.some((a) => a === '--in-place' || /^-[a-z]*i/.test(a))) ||
      // An inline script can open anything for writing. A script FILE cannot be
      // inspected here, so only the `-c`/`-e` forms are covered.
      (/^(?:python[0-9.]*|node|deno|bun|ruby|perl|php|osascript)$/.test(verb) &&
        args.some((a) => /^-(?:c|e|p|-eval)$/.test(a)));
    if (!writes) continue;
    // A copy reads its sources and writes only its destination; everything else
    // mutates every path it is handed.
    for (const a of COPY_COMMANDS.has(verb) ? copyWriteTargets(verb, args) : args) {
      out.push(a);
      // An inline script arrives as one argument with the path buried inside it
      // (`node -e "fs.writeFileSync('.claude/settings.json', …)"`). Break such an
      // argument on the punctuation a script uses around its string literals so
      // the path itself is compared too.
      if (/['"(),=]/.test(a)) {
        for (const frag of a.split(/['"(),=;\s]+/)) if (frag) out.push(frag);
      }
    }
  }
  return out;
}

/**
 * Does the call's file TARGET or command WRITE to the enforcement control plane?
 * Returns a short description of what was hit, or null.
 *
 * Never matches edit CONTENT — only the target path or the command — so editing a
 * file that merely *mentions* the control plane is not blocked. Comparison is
 * case-INSENSITIVE because on macOS and Windows `/X/.CLAUDESEC` and `/x/.claudesec`
 * are the same file, which would make a case-sensitive compare a one-character
 * bypass. Mirrors selfProtectionHit() in cli/hooks/claudesec-enforce.cjs.
 */
export function selfProtectionHit(target: string, bashCmd: string): string | null {
  const hitTarget = selfPathHit(target);
  if (hitTarget) return hitTarget;
  if (!bashCmd) return null;
  for (const candidate of bashWriteTargets(bashCmd)) {
    const hit = selfPathHit(candidate);
    if (hit) return hit;
  }
  // Service control by LABEL rather than by path: `launchctl bootout
  // gui/501/com.claudesec.agent` and `systemctl --user disable claudesec` never
  // name the unit file, but stop the supervisor just as dead.
  if (/\b(?:launchctl|systemctl)\b[^\n;&|]{0,40}\b(?:unload|bootout|disable|remove|stop|mask|kill)\b[^\n;&|]{0,120}claudesec/i.test(bashCmd)) {
    return 'the ClaudeSec service definition';
  }
  // ClaudeSec's OWN removal path. The floor guards the control-plane files and the
  // service label, but our CLI takes the enforcer apart through neither: an agent
  // never had to defeat the floor, it could just ask the product to remove itself.
  // `uninstall-hook` unregisters the PreToolUse hook; `uninstall`/`stop` are aliases
  // for the same teardown that removes the launchd/systemd unit. `install-hook` is
  // deliberately NOT matched — refreshing the enforcer must stay possible.
  //
  // Matched by SHAPE, like serviceUnitHit(): the binary is `claudesec` on PATH or
  // the entrypoint invoked directly (`node cli/init.mjs …`, `tsx ./cli/init.ts …`),
  // it must sit at COMMAND POSITION (line start, after a shell separator, inside a
  // quoted `-c` payload, or handed to a runner), and only flag tokens may sit
  // between it and the subcommand. Those two anchors are what keep ordinary work
  // out: `git commit -m "docs: explain claudesec uninstall-hook"` names the command
  // without a command position, `npm uninstall lodash` never names ours, and
  // `~/.claudesec/hooks/…` has no whitespace after the binary name.
  //
  // An operator uninstalls from a shell OUTSIDE the agent, which no hook sees.
  if (/(?:^|[\n;&|`("']|&&|\b(?:sudo|doas|env|npx|pnpm|npm|yarn|bunx|bun|node|tsx|exec|command|xargs)\s+)\s*(?:[^\s;&|]{0,60}\/)?(?:claudesec|init\.(?:mjs|ts|cjs|js))\s+(?:-{1,2}[a-z0-9-]{1,20}\s+){0,3}(?:uninstall-hook|uninstall|stop)\b/i.test(bashCmd)) {
    return 'the ClaudeSec uninstall command';
  }
  return null;
}

// ── SSRF-on-fetch floor (WebFetch / fetch-shaped MCP tools) ──────────────────
// A fetch aimed at a cloud-metadata endpoint (169.254.169.254) or an internal
// RFC1918 / loopback host is the classic agent-SSRF. The hook classifies the
// URL synchronously before the request leaves the machine; this is the BYTE-
// IDENTICAL sibling so a cross-agent MCP `fetch`/`web_fetch` tool through the
// proxy hits the SAME floor. Mirrors the classifier in
// cli/hooks/claudesec-enforce.cjs (parseIPv4 / classifyFetchHost / classifyFetchUrl).
//
// KNOWN LIMITATION — DNS rebinding: a PUBLIC hostname that *resolves* to an
// internal IP is NOT caught here (this layer is synchronous and must never block
// on a DNS lookup). The server-side ASYNC assertSafeFetchUrl() in server/ssrf.ts
// is the resolving backstop. This is the fast, literal, in-band layer.

export type FetchClass = 'metadata' | 'loopback' | 'internal' | null;

/** Parse a dotted-quad IPv4 literal into four octets, or null if not one. */
function parseIPv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  for (const x of o) if (!Number.isInteger(x) || x < 0 || x > 255) return null;
  return o;
}

/**
 * Classify a URL host into 'metadata' | 'loopback' | 'internal' | null. Tiers:
 *   • 'metadata'  → ALWAYS block (mode-independent): cloud-metadata + the whole
 *     link-local range (169.254/16, fe80::/10) + GCP metadata hostnames.
 *   • 'loopback'  → block unless CLAUDESEC_ALLOW_LOCAL_FETCH: 127/8, 0/8, ::1, ::,
 *     and bare 'localhost'.
 *   • 'internal'  → block in enforce mode: RFC1918, CGNAT 100.64/10, ULA fc00::/7,
 *     *.internal / *.local.
 *   • null        → ALLOW (public literal, or any unresolvable hostname).
 * `host` must already be lowercased with IPv6 brackets stripped. Byte-identical
 * to classifyFetchHost() in cli/hooks/claudesec-enforce.cjs.
 */
export function classifyFetchHost(host: string): FetchClass {
  if (!host) return null;

  const v4 = parseIPv4(host);
  if (v4) {
    const [a, b] = v4;
    if (a === 169 && b === 254) return 'metadata';
    if (a === 0) return 'loopback';
    if (a === 127) return 'loopback';
    if (a === 10) return 'internal';
    if (a === 172 && b >= 16 && b <= 31) return 'internal';
    if (a === 192 && b === 168) return 'internal';
    if (a === 100 && b >= 64 && b <= 127) return 'internal';
    return null;
  }

  if (host.includes(':')) {
    if (host === '::1' || /^(?:0:){1,7}1$/.test(host)) return 'loopback';
    if (host === '::' || /^(?:0:){7}0$/.test(host)) return 'loopback';
    const mappedQuad = /::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
    if (mappedQuad) return classifyFetchHost(mappedQuad[1]);
    const mappedHex = /^(?:::|(?:0:){1,4}:|(?:0:){5})ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16);
      const lo = parseInt(mappedHex[2], 16);
      const quad = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      return classifyFetchHost(quad);
    }
    if (/^fe[89ab][0-9a-f]?:/i.test(host)) return 'metadata';
    if (/^f[cd][0-9a-f]{0,2}:/i.test(host)) return 'internal';
    return null;
  }

  if (host === 'metadata' || host === 'metadata.google.internal' || host === 'metadata.goog') return 'metadata';
  if (host === 'localhost') return 'loopback';
  if (/\.(?:internal|local)$/.test(host)) return 'internal';
  return null;
}

/**
 * Extract + classify a fetch URL's host. Returns { host, klass }. Fail-OPEN on any
 * parse error (klass null). Only http/https are classified. Byte-identical to
 * classifyFetchUrl() in cli/hooks/claudesec-enforce.cjs.
 */
export function classifyFetchUrl(rawUrl: string): { host: string; klass: FetchClass } {
  if (!rawUrl || typeof rawUrl !== 'string') return { host: '', klass: null };
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { host: '', klass: null };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { host: '', klass: null };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return { host, klass: classifyFetchHost(host) };
}

export interface FetchVerdict {
  /** The classified host (empty when unparseable / non-http). */
  host: string;
  klass: FetchClass;
  /** true if this fetch should be blocked given the mode + allow-local opt-out. */
  block: boolean;
  /** true if it triggered the floor at all (block OR would-block-in-monitor). */
  triggered: boolean;
}

/**
 * Decide whether a fetch URL should be blocked, mirroring the hook's SSRF branch:
 *   • 'metadata'  → ALWAYS block (mode-independent floor).
 *   • 'loopback'  → block unless CLAUDESEC_ALLOW_LOCAL_FETCH=1; otherwise honors mode.
 *   • 'internal'  → block in enforce mode only.
 * `block` is the hard decision; `triggered` is true whenever the floor fired (so
 * a monitor-mode internal/loopback is logged as a would-block but forwarded).
 * Parity with the SSRF decision in cli/hooks/claudesec-enforce.cjs.
 */
export function evaluateFetch(rawUrl: string, mode: EnforceMode): FetchVerdict {
  const { host, klass } = classifyFetchUrl(rawUrl);
  if (!klass) return { host, klass, block: false, triggered: false };
  const allowLocal = process.env.CLAUDESEC_ALLOW_LOCAL_FETCH === '1';
  const loopbackAllowed = klass === 'loopback' && allowLocal;
  const isFloor = klass === 'metadata'; // always-block, mode-independent
  const block = !loopbackAllowed && (isFloor || mode === 'enforce');
  // Triggered (for logging) whenever the floor fired and wasn't explicitly opted out.
  const triggered = !loopbackAllowed;
  return { host, klass, block, triggered };
}

/** Resolve the rules-enforcement.json snapshot path (override-aware). */
export function resolveSnapshotPath(): string {
  if (process.env.CLAUDESEC_ENFORCE_RULES) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_RULES);
  }
  return path.join(REPO_ROOT, 'rules-enforcement.json');
}

/**
 * CANONICAL enforce-config.json resolution — the SINGLE source of truth for the
 * effective-mode file, shared by the server status reader (enforceStatus.ts
 * re-exports this) AND mirrored byte-for-byte by the PreToolUse hooks
 * (.claude/hooks + cli/hooks claudesec-enforce.cjs). A parity test
 * (tests/enforceConfigPathParityTest.ts) asserts the hook and the server resolve
 * the IDENTICAL file + mode for the same environment, so the dashboard can never
 * report a mode the installed hook does not actually run.
 *
 * Precedence (fail-OPEN / monitor-by-default; documented once, here):
 *   1. CLAUDESEC_ENFORCE_CONFIG — explicit path override (tests / isolated server).
 *   2. <CLAUDESEC_HOME or ~/.claudesec>/hooks/enforce-config.json — the USER-GLOBAL
 *      control plane the installed hook reads. This is the primary, machine-wide
 *      source of truth. It is intentionally NOT per-cwd: a previous bug made the
 *      mode depend on which directory you were in (a repo-root enforce-config.json
 *      shadowed the global one), so the dashboard could show 'monitor' while the
 *      installed hook ran 'enforce'. The repo-root file is no longer in the
 *      precedence on EITHER side.
 *   3. Docker/portable fallback — beside the resolver (hookFallbackDir): the hook
 *      passes its own __dirname; the server (no global file, no install) passes
 *      its hooks dir, which is the same global path, so this only matters for a
 *      hook running self-contained where the global dir doesn't exist (Docker).
 * `hookFallbackDir` lets the hook supply its installed location; the server omits
 * it (its primary IS the global path, so a separate fallback is redundant).
 */
export function resolveConfigPath(hookFallbackDir?: string): string {
  // 1. Explicit override.
  if (process.env.CLAUDESEC_ENFORCE_CONFIG) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_CONFIG);
  }
  // 2. User-global control plane (primary).
  const global = path.join(hookArtifactsDir(), 'enforce-config.json');
  if (fs.existsSync(global)) return global;
  // 3. Docker/portable fallback — only when a caller supplied one AND the global
  //    file is absent (e.g. a hook shipped inside a container, no ~/.claudesec).
  if (hookFallbackDir) {
    const beside = path.join(hookFallbackDir, 'enforce-config.json');
    if (fs.existsSync(beside)) return beside;
  }
  // No readable file → return the global path so the (absent) file read fails
  // cleanly and resolveMode falls through to CLAUDESEC_MODE → 'monitor'.
  return global;
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
