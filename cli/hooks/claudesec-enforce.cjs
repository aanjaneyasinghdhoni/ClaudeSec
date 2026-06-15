#!/usr/bin/env node
/* ClaudeSec PreToolUse enforcement hook — opt-in blocker built from the
 * detection rules. Keeps the catastrophic Bash patterns as an ALWAYS-ON floor.
 *
 * SAFETY CONTRACT (a buggy enforcement hook can lock the user out):
 *   • Monitor-by-default: unless CLAUDESEC_MODE === 'enforce', the hook NEVER
 *     blocks on rule matches — it logs "would-block" and exits 0 (allow). The
 *     catastrophic floor is the ONLY thing that blocks in monitor mode.
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
const os = require('node:os');
const http = require('node:http');

// ── Catastrophic floor ───────────────────────────────────────────────────────
// ALWAYS blocks, regardless of CLAUDESEC_MODE. Bash commands only — running
// these against Edit/Write content would block editing any file that merely
// *contains* these strings (e.g. server detection sources hold them as regex
// source). Kept byte-identical with server/enforceEval.ts (catastrophic parity).
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
const CATASTROPHIC = [
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

// Read-only tools carry a file target but no command or content. We match them
// so the protected-paths floor can deny a *read* of a protected secret before it
// happens — but a read is never run against the command rule-engine (reading a
// file is not executing it). Bash `cat`/edits are handled by their own branches.
const READ_TOOLS = new Set(['Read', 'NotebookRead']);

// Fetch tools carry a URL (WebFetch) — or, for WebSearch, no URL at all. We match
// them so the SSRF floor can deny a WebFetch to a cloud-metadata / internal host
// before the request leaves the machine. WebSearch is included for matcher
// symmetry with the installer; it has no URL so it never trips the floor.
const FETCH_TOOLS = new Set(['WebFetch', 'WebSearch']);

// Edit-family tools write file CONTENT. We gate them on PATH + ACTION, never on
// the static content of the code being written — scanning edit bodies against the
// ~630 threat rules false-positives on benign work (editing security code, docs
// that name attack patterns, fixtures holding secret-shaped strings). The block
// decision for these tools is: protected-path floor OR live-secret floor below.
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);

// ── Minimal live-secret (DLP) floor for edit content ─────────────────────────
// The ONLY content-based block on an edit: refuse to write an UNAMBIGUOUS live
// credential to disk. Intentionally tiny + verified-shape (very low false
// positive) — NOT the ~630 threat rules. Phase 7 will replace this with a real
// secret detector; until then keep this set small and high-confidence. Kept in
// sync with server/enforceEval.ts (LIVE_SECRET).
const LIVE_SECRET = [
  { re: /\bAKIA[0-9A-Z]{16}\b/, why: 'AWS access key id' },
  { re: /\bASIA[0-9A-Z]{16}\b/, why: 'AWS temporary access key id' },
  { re: /\bghp_[0-9A-Za-z]{36}\b/, why: 'GitHub personal access token' },
  { re: /\bgh[oprs]_[0-9A-Za-z]{36}\b/, why: 'GitHub OAuth/server/refresh token' },
  { re: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/, why: 'GitHub fine-grained token' },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, why: 'Slack token' },
  { re: /\bsk_live_[0-9A-Za-z]{20,}\b/, why: 'Stripe live secret key' },
  { re: /\bAIza[0-9A-Za-z_\-]{35}\b/, why: 'Google API key' },
  { re: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/, why: 'OpenAI project API key' },
  { re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/, why: 'Anthropic API key' },
  { re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/, why: 'GitLab personal access token' },
  { re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, why: 'SendGrid API key' },
  { re: /\bSK[0-9a-fA-F]{32}\b/, why: 'Twilio API key SID' },
  { re: /\bnpm_[A-Za-z0-9]{36}\b/, why: 'npm access token' },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, why: 'private key block' },
];

// Known documentation/placeholder credentials that are NOT live secrets. AWS
// ships `AKIAIOSFODNN7EXAMPLE` in its canonical docs; blocking it would refuse a
// benign edit to AWS docs/examples. Allowlisted by exact (case-sensitive) value
// before the live-secret floor fires. Kept in sync with server/enforceEval.ts.
const SECRET_PLACEHOLDERS = new Set([
  'AKIAIOSFODNN7EXAMPLE',
]);

/**
 * Does the edit CONTENT carry an unambiguous live credential? Returns the matching
 * entry ({ re, why }) or null. This is the minimal DLP floor — the only reason an
 * edit's content (not its path) can be blocked. A match whose entire value is a
 * known placeholder (SECRET_PLACEHOLDERS) is ignored. See LIVE_SECRET above.
 */
function liveSecretHit(content) {
  if (!content) return null;
  for (const r of LIVE_SECRET) {
    const m = content.match(r.re);
    if (m && !SECRET_PLACEHOLDERS.has(m[0])) return r;
  }
  return null;
}

// ── Self-protection floor (control plane) ────────────────────────────────────
// ALWAYS blocks, regardless of CLAUDESEC_MODE — an agent must never be able to
// edit (or shell-redirect into) the enforcement control plane and unhook the
// enforcer. Guards the whole ~/.claudesec/hooks/ dir (enforce-config.json, the
// hook itself, the enforcement snapshot, protected-paths.json, rules.json) plus
// the Claude settings files that register the PreToolUse hook. This guards AGENT
// tool calls only; the ClaudeSec SERVER process legitimately writes these files
// on boot — a different process, not subject to this hook. Kept in sync with
// server/enforceEval.ts (selfProtectionHit).
function selfProtectedPrefixes() {
  const home = os.homedir();
  // Honor CLAUDESEC_HOME exactly as the installer/server do, so the guard tracks
  // wherever the control plane actually lives.
  const csecHome = process.env.CLAUDESEC_HOME || path.join(home, '.claudesec');
  return [
    path.join(csecHome, 'hooks'),          // whole enforcement control-plane dir
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
  ];
}

/**
 * Does the call's file TARGET or Bash command touch the enforcement control
 * plane? Matches case-insensitively on the normalized path (case-insensitive
 * filesystems make a case-sensitive compare a trivial bypass). Returns the
 * matching prefix or null. Never matches edit CONTENT — only the target path or
 * the (HOME-expanded) Bash command, so editing a file that merely *mentions* the
 * control plane is not blocked.
 */
function selfProtectionHit(target, bashCmd) {
  const prefixes = selfProtectedPrefixes();
  const t = target ? target.toLowerCase() : '';
  const c = bashCmd ? expandHomeVar(bashCmd).toLowerCase() : '';
  for (const p of prefixes) {
    const f = p.toLowerCase();
    if ((t && t.includes(f)) || (c && c.includes(f))) return p;
  }
  return null;
}

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

/** Resolve the protected-paths.json path (server-written user block list). */
function resolveProtectedPathsPath() {
  // 1. Explicit override (absolute or relative) — used by tests / isolated server.
  if (process.env.CLAUDESEC_PROTECTED_PATHS) {
    return path.resolve(process.env.CLAUDESEC_PROTECTED_PATHS);
  }
  // 2. Next to this hook (installed layout: ~/.claudesec/hooks/), if present.
  const beside = path.join(__dirname, 'protected-paths.json');
  if (fs.existsSync(beside)) return beside;
  // 3. Fallback: running in-repo → <repo>/protected-paths.json.
  return path.resolve(__dirname, '..', '..', 'protected-paths.json');
}

/**
 * Load the user's protected-path entries. Fail-OPEN → [] (never throws). Shape:
 * [{ path: '<literal path>', label: '<label>' }]. Each entry is normalized so a
 * leading '~' expands to the home dir; both the raw and home-expanded forms are
 * carried so a target can match whichever spelling the agent used.
 */
function loadProtectedPaths() {
  try {
    const raw = JSON.parse(fs.readFileSync(resolveProtectedPathsPath(), 'utf8'));
    if (!Array.isArray(raw)) return [];
    const home = os.homedir();
    const out = [];
    for (const e of raw) {
      if (!e || typeof e.path !== 'string' || e.path.length === 0) continue;
      const p = e.path;
      // Expand a leading '~' / '~/' to the home dir (the only ~ form we honor).
      const expanded =
        p === '~' ? home
        : p.startsWith('~/') ? path.join(home, p.slice(2))
        : p;
      const label = typeof e.label === 'string' && e.label.length > 0 ? e.label : p;
      // Dedupe the raw/expanded forms when '~' was not used.
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
  } catch (_) {
    return []; // missing / unreadable / malformed → fail-open
  }
}

/**
 * Expand a standalone `$HOME` / `${HOME}` token to the home dir so a command like
 * `cat $HOME/.ssh/id_rsa` matches a `~/.ssh/id_rsa` (home-expanded) protected
 * entry. We only expand HOME — arbitrary shell variable / glob / command
 * substitution (e.g. `$OTHERVAR`, `$(...)`, `*`) is an inherent limitation of a
 * static hook and is NOT resolved here; the server-side detection layer remains
 * the backstop for those.
 */
function expandHomeVar(cmd) {
  if (!cmd) return cmd;
  const home = os.homedir();
  // ${HOME} or $HOME when NOT followed by another identifier char (so $HOMEBREW
  // is left intact). Replace every occurrence.
  return cmd.replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home);
}

/**
 * Resolve a path's symlinks to its real on-disk location so a symlink pointing
 * INTO a protected tree can't launder the target string past the substring match.
 * Returns the realpath, or '' when it can't be resolved.
 *
 * fs.realpathSync THROWS when the path doesn't exist yet (e.g. a Write/Edit that
 * CREATES a new file), so we degrade gracefully: walk up to the nearest EXISTING
 * ancestor directory, realpath THAT, then re-append the not-yet-existing tail. So
 * a write to `/tmp/linkdir/newfile` is still caught when `/tmp/linkdir` is a
 * symlink into a protected tree. If even the ancestor walk fails we return ''
 * (the caller still has the literal substring match) — this never throws.
 */
function resolveRealpath(p) {
  if (!p) return '';
  try {
    return fs.realpathSync(p);
  } catch (_) {
    // Path (or some ancestor) doesn't exist — resolve the nearest existing parent.
  }
  try {
    let dir = path.dirname(p);
    const tail = [path.basename(p)];
    // Walk up until an existing ancestor is found, or we hit the filesystem root.
    while (dir && dir !== path.dirname(dir)) {
      try {
        const realDir = fs.realpathSync(dir);
        return path.join(realDir, ...tail.reverse());
      } catch (_) {
        tail.push(path.basename(dir));
        dir = path.dirname(dir);
      }
    }
  } catch (_) {
    // Any unexpected failure → give up on realpath; caller keeps the literal match.
  }
  return '';
}

/**
 * Does a protected entry match the call's file TARGET or Bash command? We match
 * only against the target path (file_path / path / notebook_path) and the Bash
 * command — NEVER against edit content — so editing a file that merely *mentions*
 * a protected path is not blocked.
 *
 * Case-INSENSITIVE substring: on case-insensitive filesystems (macOS, Windows)
 * `/X/.ENV` and `/x/.env` are the same file, so a case-sensitive compare would
 * be a trivial bypass. Conservative by design — a false positive (over-block) is
 * far cheaper than a missed block on a path the user explicitly protected. We
 * also expand `$HOME`/`${HOME}` in the Bash command first (see expandHomeVar).
 *
 * SYMLINK GUARD: the literal substring match alone is bypassable —
 * `ln -s /protected/secret.env /tmp/innocent` then Edit/Read `/tmp/innocent`
 * never names the protected string. So for the file TARGET we ALSO resolve the
 * symlink chain (resolveRealpath, which falls back to the nearest existing
 * ancestor for not-yet-created files) and match the entry forms against the
 * REAL path too. We keep matching the literal as well, so nothing regresses.
 * (TOCTOU note below.) The Bash command is matched literally only — a shell
 * command string is not a single resolvable path.
 */
function protectedHit(entries, target, bashCmd) {
  const tLit = target ? target.toLowerCase() : '';
  // Resolve the target's symlinks; lowercase for the case-insensitive compare.
  // Only run realpath when it would actually add something (a resolved path that
  // differs from the literal), so a non-symlinked path costs nothing extra.
  const real = target ? resolveRealpath(target) : '';
  const tReal = real ? real.toLowerCase() : '';
  const c = bashCmd ? expandHomeVar(bashCmd).toLowerCase() : '';
  for (const e of entries) {
    for (const form of e.forms) {
      const f = form.toLowerCase();
      if (
        (tLit && tLit.includes(f)) ||
        (tReal && tReal.includes(f)) ||
        (c && c.includes(f))
      ) {
        return e;
      }
    }
  }
  return null;
}

// ── SSRF-on-fetch floor (WebFetch) ───────────────────────────────────────────
// A WebFetch aimed at a cloud-metadata endpoint (169.254.169.254) or an internal
// RFC1918 / loopback host is the classic agent-SSRF: the model is talked into
// fetching http://169.254.169.254/latest/meta-data/iam/... and exfiltrating the
// instance credentials, or probing internal services. The PreToolUse hook is the
// pre-execution chokepoint, so we classify the URL's host HERE, synchronously,
// before the fetch leaves the machine.
//
// This MIRRORS server/ssrf.ts isPublicAddress() — but it cannot import it (the
// hook is dependency-free, Node built-ins only, and never reaches into server/).
// We therefore inline a small literal-IP classifier. It is deliberately
// CONSERVATIVE: it only acts on what it can see synchronously.
//
// KNOWN LIMITATION — DNS rebinding: a PUBLIC hostname that *resolves* to an
// internal IP (e.g. an attacker-controlled name pointing at 169.254.169.254) is
// NOT caught here, because this hook is synchronous and must never block to do a
// DNS lookup (a hung resolver would stall every tool call). Such a hostname is
// ALLOWED through by this floor. The deeper guard is the server-side ASYNC
// assertSafeFetchUrl() in server/ssrf.ts, which DNS-resolves every host at fetch
// time and rejects anything that points inward. This floor is the fast, literal,
// in-band layer; the server guard is the resolving backstop. We surface the gap
// honestly rather than pretend a synchronous hook can resolve names.

/** Parse a dotted-quad IPv4 literal into four octets, or null if not one. */
function parseIPv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  for (const x of o) if (!Number.isInteger(x) || x < 0 || x > 255) return null;
  return o;
}

/**
 * Classify a URL host into one of:
 *   'metadata'   → ALWAYS block (mode-independent floor): cloud-metadata and the
 *                  whole link-local range — 169.254.0.0/16 (v4) and fe80::/10
 *                  (v6), plus the GCP metadata hostnames. These are unambiguous
 *                  SSRF targets with no legitimate WebFetch use.
 *   'loopback'   → block in enforce (or always unless CLAUDESEC_ALLOW_LOCAL_FETCH):
 *                  127.0.0.0/8, 0.0.0.0/8 (the "this host" range — 0.0.0.0 routes
 *                  to localhost on Linux), ::1, :: (unspecified), and the bare name
 *                  'localhost'.
 *   'internal'   → block in enforce mode (like a normal rule): RFC1918
 *                  (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10, ULA fc00::/7,
 *                  and *.internal / *.local hostnames.
 *   null         → ALLOW (public IP literal, or any other hostname — we cannot
 *                  resolve it synchronously; see the DNS-rebinding note above).
 *
 * `host` must already be lowercased and have IPv6 brackets stripped.
 */
function classifyFetchHost(host) {
  if (!host) return null;

  // ── IPv4 literal ──
  const v4 = parseIPv4(host);
  if (v4) {
    const [a, b] = v4;
    // 169.254.0.0/16 — link-local, includes the 169.254.169.254 metadata IP.
    if (a === 169 && b === 254) return 'metadata';
    // 0.0.0.0/8 — the "this host" range. `0.0.0.0` (and bare `http://0/`, which
    // Node normalizes to `0.0.0.0`) routes to localhost on Linux, so treat the
    // whole /8 as loopback rather than letting it through as a "public" literal.
    if (a === 0) return 'loopback';
    // 127.0.0.0/8 — loopback.
    if (a === 127) return 'loopback';
    // 10.0.0.0/8 — private.
    if (a === 10) return 'internal';
    // 172.16.0.0/12 — private.
    if (a === 172 && b >= 16 && b <= 31) return 'internal';
    // 192.168.0.0/16 — private.
    if (a === 192 && b === 168) return 'internal';
    // 100.64.0.0/10 — CGNAT (carrier-grade NAT shared address space).
    if (a === 100 && b >= 64 && b <= 127) return 'internal';
    // Any other IPv4 literal is treated as public → allow.
    return null;
  }

  // ── IPv6 literal ── (heuristic on the textual form; the hook has no ipaddr.js)
  if (host.includes(':')) {
    // ::1 — IPv6 loopback (also the compressed 0:0:...:1 spelling).
    if (host === '::1' || /^(?:0:){1,7}1$/.test(host)) return 'loopback';
    // :: — IPv6 unspecified (and the fully-expanded 0:0:0:0:0:0:0:0). Binding /
    // routing to it lands on localhost, so classify it like loopback.
    if (host === '::' || /^(?:0:){7}0$/.test(host)) return 'loopback';
    // IPv4-mapped — TWO textual forms reach us, both must unwrap to the embedded
    // IPv4 so a wrapped internal/metadata address is still caught:
    //   1. Dotted-quad tail: ::ffff:127.0.0.1 (rare from the WHATWG parser, but a
    //      hand-written URL can carry it).
    //   2. Hex-hextet tail: ::ffff:7f00:1 / ::ffff:a9fe:a9fe — the form Node's URL
    //      parser actually PRODUCES (it compresses the embedded v4 to two hextets).
    //      Without this branch, http://[::ffff:169.254.169.254]/ and
    //      http://[::ffff:127.0.0.1]/ sailed through as "public".
    // Each hextet is two octets; reassemble (hi>>8, hi&0xff, lo>>8, lo&0xff) and
    // re-run the IPv4 classifier on the dotted quad.
    const mappedQuad = /::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
    if (mappedQuad) return classifyFetchHost(mappedQuad[1]);
    // Hex form: the compressed ::ffff:H:H spelling (what the parser emits), the
    // partially-compressed 0:0::ffff:H:H, and the long 0:0:0:0:0:ffff:H:H. Linear
    // (bounded {1,4}/{5} counts, no nested quantifier).
    const mappedHex = /^(?:::|(?:0:){1,4}:|(?:0:){5})ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16);
      const lo = parseInt(mappedHex[2], 16);
      const quad = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      return classifyFetchHost(quad);
    }
    // fe80::/10 — link-local (fe80–febf at the start of the first hextet).
    if (/^fe[89ab][0-9a-f]?:/i.test(host)) return 'metadata';
    // fc00::/7 — unique-local (ULA): first byte fc or fd.
    if (/^f[cd][0-9a-f]{0,2}:/i.test(host)) return 'internal';
    // Any other IPv6 literal → treat as public → allow.
    return null;
  }

  // ── Hostname (not a literal IP) ──
  // Cloud-metadata hostnames are unambiguous SSRF targets → always-block floor.
  // `metadata` (bare) is GCP's short form — http://metadata/computeMetadata/v1/
  // resolves to the same 169.254.169.254 endpoint inside a GCE instance.
  if (host === 'metadata' || host === 'metadata.google.internal' || host === 'metadata.goog') return 'metadata';
  // The bare loopback name.
  if (host === 'localhost') return 'loopback';
  // Internal naming conventions — *.internal / *.local resolve to internal infra.
  // (metadata.google.internal is handled above before this broader check.)
  if (/\.(?:internal|local)$/.test(host)) return 'internal';
  // Any other hostname: we cannot resolve it synchronously → ALLOW here. The
  // server-side resolving guard (assertSafeFetchUrl) is the DNS-rebinding backstop.
  return null;
}

/**
 * Extract + classify a WebFetch URL's host. Returns { host, klass } where klass is
 * one of 'metadata' | 'loopback' | 'internal' | null. Fail-OPEN on any parse
 * error (klass null) — a garbage URL must never crash or block the pipeline. Only
 * http/https URLs are classified; any other scheme is left to the agent (a
 * non-http fetch is not an HTTP SSRF and is out of scope for this floor).
 */
function classifyFetchUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return { host: '', klass: null };
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_) {
    return { host: '', klass: null }; // unparseable → fail-open
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { host: '', klass: null };
  }
  // new URL() keeps the brackets on IPv6 hosts ("[::1]"); strip them before
  // classifying, and lowercase so the literal/name comparisons are stable.
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return { host, klass: classifyFetchHost(host) };
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
  //   • matchText   → fed to the rule regexes. For Bash this is the full command
  //     (the execution boundary). For EDIT tools it is the PATH ONLY — never the
  //     content (see EDIT_TOOLS): the block decision for an edit gates on
  //     path/action + the minimal live-secret floor, NOT the ~630 threat rules.
  //   • editContent → the new content an edit would write, checked ONLY by the
  //     live-secret (DLP) floor below. Never fed to the rule engine.
  //   • fileTarget  → ONLY the file the call targets (path, never content); used
  //     by the protected-paths floor so editing a file that merely *mentions* a
  //     protected path is not blocked.
  let bashCmd = '';
  let matchText = '';
  let editContent = '';
  let fetchUrl = '';
  const fileTarget = String(ti.file_path || ti.path || ti.notebook_path || '');
  if (toolName === 'Bash') {
    bashCmd = String(ti.command || '');
    matchText = bashCmd;
  } else if (EDIT_TOOLS.has(toolName)) {
    // Path/action only into the rule engine — editing a file whose body happens
    // to match a threat rule (security code, attack-pattern docs, secret-shaped
    // fixtures) must NOT be blocked. The content is gated solely by the
    // live-secret floor (collected into editContent).
    matchText = fileTarget;
    const body = [];
    if (ti.content) body.push(String(ti.content));
    if (ti.new_string) body.push(String(ti.new_string));
    // NotebookEdit names its content differently: the new cell source is `new_source`.
    if (ti.new_source) body.push(String(ti.new_source));
    if (Array.isArray(ti.edits)) {
      for (const e of ti.edits) {
        if (e && e.new_string) body.push(String(e.new_string));
      }
    }
    editContent = body.join('\n');
  } else if (READ_TOOLS.has(toolName)) {
    // Read-only: fileTarget (set above) is all that matters. Leave matchText
    // empty so the command rule-engine never fires on a mere read — only the
    // always-on protected-paths floor below can deny it.
    matchText = '';
  } else if (FETCH_TOOLS.has(toolName)) {
    // WebFetch carries the target URL in `url`; WebSearch has no URL (and so never
    // trips the SSRF floor). Leave matchText empty so the command rule-engine never
    // fires on a fetch — only the SSRF floor below inspects the URL.
    fetchUrl = String(ti.url || '');
    matchText = '';
  } else {
    // Unknown tool / nothing to match.
    matchText = String(ti.command || ti.file_path || ti.path || '');
    bashCmd = String(ti.command || '');
  }

  // Nothing to evaluate at all (no command/content, no file target, no fetch URL)
  // → allow. A read tool reaches here with an empty matchText but a real
  // fileTarget, so it still flows into the protected-paths floor; an edit with only
  // content (no path) still flows into the live-secret floor via editContent; a
  // WebFetch reaches here with a fetchUrl and flows into the SSRF floor below.
  if (!matchText && !fileTarget && !editContent && !fetchUrl) return process.exit(0);

  // 2a. SSRF-on-fetch floor — WebFetch URL only. Classify the host synchronously
  // (no DNS — see classifyFetchHost). Decision:
  //   • 'metadata'  → ALWAYS block (mode-independent floor): cloud-metadata and the
  //     whole link-local range. No legitimate WebFetch use; blocked even in monitor.
  //   • 'loopback'  → block, UNLESS CLAUDESEC_ALLOW_LOCAL_FETCH=1 (a user pointing the
  //     agent at a local Ollama / dev server). Otherwise mode-respecting (enforce).
  //   • 'internal'  → block IN ENFORCE MODE only (RFC1918 / CGNAT / ULA / *.internal).
  // A public IP literal or any unresolvable hostname classifies null → allow here
  // (the server-side async assertSafeFetchUrl is the DNS-rebinding backstop).
  if (fetchUrl) {
    const { host, klass } = classifyFetchUrl(fetchUrl);
    if (klass) {
      const allowLocal = process.env.CLAUDESEC_ALLOW_LOCAL_FETCH === '1';
      const mode = resolveMode();
      // Loopback may be opted out for local-model dev; metadata/link-local never is.
      const loopbackAllowed = klass === 'loopback' && allowLocal;
      const isFloor = klass === 'metadata'; // always-block, mode-independent
      const shouldBlock =
        !loopbackAllowed && (isFloor || mode === 'enforce');
      if (shouldBlock) {
        return blockAndLog(
          `⛔ Blocked SSRF: WebFetch to internal/metadata address ${host}. ` +
          (klass === 'loopback'
            ? `If this is a local dev server you trust, set CLAUDESEC_ALLOW_LOCAL_FETCH=1. `
            : '') +
          `Bypass: CLAUDESEC_HOOKS_BYPASS=1`,
          {
            mode,
            label: 'SSRF: WebFetch to ' + klass + ' address ' + host,
            severity: 'high',
            command: redact(fetchUrl),
            blocked: true,
            wouldBlock: true,
          },
        );
      }
      // Not blocked in this mode (e.g. 'internal' in monitor): log a would-block so
      // the dashboard still surfaces the attempt, then ALLOW. Skip when the user
      // explicitly opted local fetches in (no would-block noise for a trusted host).
      if (!loopbackAllowed) {
        return postMonitorLog(
          {
            mode,
            label: 'SSRF: WebFetch to ' + klass + ' address ' + host,
            severity: 'high',
            command: redact(fetchUrl),
            blocked: false,
            wouldBlock: true,
          },
          () => process.exit(0),
        );
      }
    }
    // No classification (public / unresolvable host) or opted-out loopback → allow.
    return process.exit(0);
  }

  // 3. Catastrophic floor — Bash command only, ALWAYS blocks.
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

  // 3a2. Self-protection floor — ALWAYS blocks regardless of mode. An agent must
  // not be able to edit the enforcement control plane (~/.claudesec/hooks/) or the
  // Claude settings that register this hook, which would let it disable the
  // enforcer. Matches the file TARGET or the Bash command only, never edit
  // content. (The ClaudeSec server writes these files from a different process,
  // which is not subject to this hook.)
  {
    const hitSelf = selfProtectionHit(fileTarget, bashCmd);
    if (hitSelf) {
      return blockAndLog(
        `⛔ ClaudeSec: '${hitSelf}' is part of the enforcement control plane and ` +
        `cannot be modified by an agent. Blocked.`,
        {
          mode: resolveMode(),
          label: 'Self-protection: ' + hitSelf,
          severity: 'high',
          command: redact(bashCmd || fileTarget),
          blocked: true,
          wouldBlock: true,
        },
      );
    }
  }

  // 3b. Protected-paths floor — user-defined, ALWAYS blocks regardless of mode
  // (a per-user mirror of the catastrophic floor). Matches the file TARGET or the
  // Bash command only, never edit content. Fail-open if the list is missing.
  {
    const entries = loadProtectedPaths();
    if (entries.length) {
      const hitP = protectedHit(entries, fileTarget, bashCmd);
      if (hitP) {
        return blockAndLog(
          `⛔ ClaudeSec: '${hitP.label}' is a protected path. Blocked. ` +
          `Bypass: CLAUDESEC_HOOKS_BYPASS=1`,
          {
            mode: resolveMode(),
            label: 'Protected path: ' + hitP.label,
            severity: 'high',
            command: redact(bashCmd || fileTarget),
            blocked: true,
            wouldBlock: true,
          },
        );
      }
    }
  }

  // 3c. Live-secret (DLP) floor — edit content only, ALWAYS blocks regardless of
  // mode. The ONLY reason an edit's CONTENT (not its path) is blocked: it would
  // write an unambiguous live credential to disk. Tiny, high-confidence set (see
  // liveSecretHit) — NOT the ~630 threat rules; a benign edit whose body merely
  // resembles a threat pattern is never blocked here.
  if (editContent) {
    const hitS = liveSecretHit(editContent);
    if (hitS) {
      return blockAndLog(
        `⛔ ClaudeSec: this edit would write a live ${hitS.why} to disk. Blocked. ` +
        `Bypass: CLAUDESEC_HOOKS_BYPASS=1`,
        {
          mode: resolveMode(),
          label: 'Live secret in edit: ' + hitS.why,
          severity: 'high',
          command: redact(fileTarget || '(edit)'),
          blocked: true,
          wouldBlock: true,
        },
      );
    }
  }

  // 4. Command rule-engine — only when there is command/content to inspect. A
  // read tool reaches here with an empty matchText (handled solely by the floor
  // above), so it never trips a command rule. For an EDIT tool matchText is the
  // PATH only (content is excluded — see step 2), so an edit never trips a
  // command rule on its body; only its path can match. Load rules from the
  // snapshot (fail-open if missing) and evaluate against the matchable text.
  const blockRules = matchText ? loadBlockRules() : [];

  // Bound the text we run user-supplied regexes over. Custom rules are validated
  // with RE2 (linear-time) at the API, but this dependency-free hook compiles
  // them with the native engine, which CAN backtrack catastrophically on a hostile
  // pattern. Edit/Write matchText carries full file content, which would amplify
  // any such stall. Capping the input bounds the worst case; a real command or
  // path that matters is far shorter than this. (Built-in patterns are linear.)
  const ruleText = matchText.length > 65536 ? matchText.slice(0, 65536) : matchText;

  // 5. Evaluate block rules against the matchable text.
  let hit = null;
  for (const r of blockRules) {
    if (r.re.test(ruleText)) { hit = r; break; }
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
