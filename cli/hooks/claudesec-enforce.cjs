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
// before the live-secret floor fires. Kept in sync with server/enforceEval.ts.
const SECRET_PLACEHOLDERS = new Set([
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
 * entry ({ re, why }) or null. This is the minimal DLP floor — the only reason an
 * edit's content (not its path) can be blocked. A match is ignored when its value is
 * a known placeholder (SECRET_PLACEHOLDERS) or the matched token itself carries a
 * fill-me-in marker (SECRET_PLACEHOLDER_MARKERS). See LIVE_SECRET above.
 */
function liveSecretHit(content) {
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

// ── Self-protection floor (control plane) ────────────────────────────────────
// ALWAYS blocks, regardless of CLAUDESEC_MODE — an agent must never be able to
// overwrite the enforcement control plane and unhook the enforcer. A security
// tool that cannot notice being switched off has a hole under everything else it
// claims, so this floor is mode-independent like the catastrophic one.
//
// Two things make the difference between a real floor and theatre:
//   • It is anchored on the WRITE, never on the filename. Reading, grepping or
//     merely naming `settings.json` in a commit message is ordinary developer
//     work every hour of the day; only an action that could CHANGE the file is
//     denied. (Reads used to be denied too, which walled off the agent looking at
//     its own settings for no security gain.) Be precise about what that costs:
//     one entry here IS secret material — the Ed25519 audit signing key — so
//     "reads are exempt" must not be read as "nothing here is worth reading".
//     This floor exists to stop the supervisor being switched off, not to stop
//     exfiltration; the config and settings files it covers leak nothing, and an
//     operator who also wants the signing key unreadable adds it to
//     protected-paths.json, which does gate reads.
//   • Every candidate path is normalized before it is compared: `~` and `$HOME`
//     expanded, relative and `../` spellings resolved against the cwd, the symlink
//     chain followed, and the comparison itself made on path COMPONENTS rather
//     than raw substrings (see pathRelated). A floor a `../` walks around protects
//     nothing, and one that misses the PARENT of what it guards protects nothing
//     either.
//
// This guards AGENT tool calls only; the ClaudeSec SERVER writes these files from
// its own process, which is not subject to this hook. The escape hatch is the
// existing CLAUDESEC_HOOKS_BYPASS=1 (which is itself recorded in the enforce feed).

// Control-plane FILENAMES. These four names are ClaudeSec's own artefacts and
// mean the same thing wherever they sit — the installed copies under
// ~/.claudesec/hooks, a Docker-bundled copy beside the hook, or the generated
// copies in a checkout. Matching the basename covers every layout without having
// to enumerate them, and the names are specific enough that nothing else on a
// developer's disk is called this.
const SELF_BASENAMES = new Set([
  'enforce-config.json',
  'rules-enforcement.json',
  'protected-paths.json',
  'claudesec-enforce.cjs',
]);

// The audit chain's signing material, matched by BASENAME SHAPE rather than by
// location. The key ships under four names — `audit-key` (the legacy HMAC file),
// `audit-key.ed25519.pem`, `audit-key.pub.pem` and `audit-key.store.json` — and
// `claudesec audit-key to-file` will put it back wherever CLAUDESEC_HOME points,
// so enumerating paths would always trail the product. Losing the private half
// means the audit chain can no longer be signed; losing the public half means it
// can no longer be verified. Both ends of "the record is trustworthy" are the
// supervisor's own integrity, so both belong on this floor.
const AUDIT_KEY_BASENAME = /^audit-key(?:\.[a-z0-9]{1,16}){0,3}$/;

// Shell commands that WRITE. Anything in this set mutates whatever path it is
// handed, so naming a control-plane file anywhere in its arguments is a block.
const MUTATING_COMMANDS = new Set([
  'rm', 'unlink', 'truncate', 'shred', 'srm', 'mv', 'cp', 'install', 'ln', 'dd',
  'tee', 'chmod', 'chown', 'chgrp', 'chattr', 'chflags', 'touch', 'mkdir',
  'rmdir', 'rsync', 'ditto', 'patch', 'sponge', 'plutil', 'defaults',
  'launchctl', 'systemctl',
]);

// Verbs that destroy or displace a whole TREE rather than the single file they
// name. These are the only ones for which an ANCESTOR of a protected path counts
// as a hit: `rm -rf ~/.claudesec` deletes the protected hooks directory
// underneath it, `mv` carries it away, and `chmod 000` / `chown someone-else`
// deny it just as finally. Writing INTO a directory — `cp`, `tee`, `mkdir`, a
// redirect — harms nothing beneath it, so every other verb keeps the
// descendant-only reading and `cp -r ../assets .` stays ordinary work.
const DESTRUCTIVE_COMMANDS = new Set([
  'rm', 'unlink', 'shred', 'srm', 'mv', 'rmdir',
  'chmod', 'chown', 'chgrp', 'chattr', 'chflags',
]);

// Words that sit in front of the real verb and must be skipped when working out
// what a command actually runs (`sudo tee …`, `FOO=1 rm …`, `xargs rm …`).
const COMMAND_PREFIXES = /^(?:sudo|doas|env|nohup|command|exec|time|nice|xargs|then|do|else)$/;

// ── Shell wrappers ───────────────────────────────────────────────────────────
// A shell handed a script is not a leaf command. `sh -c "printf '{}' > …"` runs
// the redirect just as surely as typing it, but to an argument scanner the whole
// script is one opaque string, so the floor saw a `sh` it did not recognise and
// allowed everything. The payload is therefore RE-ANALYSED as a command.
//
// WHERE THIS STOPS, stated plainly rather than implied: a regex cannot parse a
// shell, and pretending otherwise is how a floor gets trusted past its evidence.
// Followed (up to MAX_SHELL_DEPTH levels of nesting):
//   • an inline script in an argument — `sh -c`, `bash -c`, `zsh -c`, `-lc`,
//     `--command=`, and the same for `script`/`flock`, under ANY wrapper
//     (`env`, `sudo`, `nohup`, `timeout 5`, `xargs`, `nice -n 5`, an absolute
//     path to the shell), because the host is looked for at any token position
//     instead of enumerating wrappers and their argument grammars;
//   • a pipeline that ENDS in a bare shell — `printf '…' | sh` (see
//     PIPE_INTO_SHELL); and
//   • backticks and `$( )`, which the segment splitter already treats as fresh
//     commands.
// NOT followed, and no attempt is made to pretend otherwise:
//   • a script FILE — `sh ./setup.sh` — whose contents this layer cannot read;
//   • a heredoc fed to a shell (`sh <<'EOF' … EOF`) or `sh < script`;
//   • anything decoded at runtime — `eval "$(base64 -d …)"`, a payload assembled
//     from string fragments, a variable inherited from the parent shell;
//   • a command sent to ANOTHER machine — `ssh host '…'` — which this floor has
//     no business adjudicating.
// For all of those the server-side detection layer and the post-hoc
// self-protection rules in server/severityRulesExtra.ts remain the backstop,
// exactly as the catastrophic floor's own limitations section documents.

// Shells (plus the two wrappers that take an inline command string) whose `-c`
// payload is re-analysed. `ssh` is deliberately absent — it is not a local shell.
const INLINE_SCRIPT_HOSTS = /^(?:(?:ba|z|k|da|a|fi|tc|c)?sh|busybox|script|flock)$/;

// Flags that introduce an inline script: `-c`, `-lc`, `-ic`, `--command`.
const INLINE_SCRIPT_FLAG = /^(?:-[a-zA-Z]*c|--command)$/;

// A pipeline whose LAST stage is a bare shell (`printf '…' | sh`, `… | sudo bash`).
// The script arrives on stdin, where no argument scan can reach it, so when this
// matches, the quoted strings feeding the pipeline are re-analysed as scripts.
// One optional wrapper and one optional flag group, no nested quantifier — the
// pattern stays linear.
const PIPE_INTO_SHELL =
  /\|\s*(?:(?:sudo|doas|env|command|exec|nohup|xargs)\s+)?(?:[^\s|;&<>]*\/)?(?:ba|z|k|da|a|fi|tc|c)?sh\b\s*(?:-[a-zA-Z]+\s*)?(?:$|[;&|\n])/i;

// How many levels of `sh -c "sh -c …"` nesting are followed before giving up.
const MAX_SHELL_DEPTH = 3;

// SQL that REWRITES the database, as opposed to a query that reads it. `sqlite3`
// is a writer only when its arguments carry one of these, so
// `sqlite3 spans.db "SELECT count(*) FROM spans"` stays allowed while
// `sqlite3 spans.db "UPDATE spans SET severity=0"` — a silent edit of the record
// the supervisor keeps — does not.
const SQLITE_MUTATION =
  /\b(?:insert|update|delete|drop|alter|replace|vacuum|reindex|attach)\b|\.(?:import|restore|clone|recover)\b/i;

/**
 * Directories and files that, if written, can switch enforcement off. Resolved
 * fresh on every call so the floor tracks CLAUDESEC_HOME, the agent's cwd, and
 * whichever artefacts this hook is actually reading.
 */
function selfProtectedPrefixes() {
  const home = os.homedir();
  // Honor CLAUDESEC_HOME exactly as the installer/server do, so the guard tracks
  // wherever the control plane actually lives.
  const csecHome = process.env.CLAUDESEC_HOME || path.join(home, '.claudesec');
  // Project-level Claude settings (<cwd>/.claude/…) are ALSO honored by Claude
  // Code, so an agent could write those to register a competing PreToolUse hook
  // and unhook the enforcer. Guard them alongside the user-level files. cwd is
  // resolved at call time so the floor tracks whichever project the agent is in.
  const cwd = process.cwd();
  // The record the supervisor keeps. Resolved exactly as server/db.ts does
  // (CLAUDESEC_DB → <CLAUDESEC_HOME>/spans.db) so the floor follows an operator
  // who moved the database rather than guarding an empty default path.
  const dbPath = process.env.CLAUDESEC_DB || path.join(csecHome, 'spans.db');
  const out = [
    path.join(csecHome, 'hooks'),           // whole enforcement control-plane dir
    path.join(csecHome, 'audit-key'),       // the legacy HMAC file (see AUDIT_KEY_BASENAME)
    path.join(csecHome, 'audit-anchor.json'),
    // The evidence itself. Unhooking the enforcer and deleting what it already
    // recorded are the same attack finished at different ends, and the second one
    // was free: `rm`, `truncate` and `sqlite3 … UPDATE` all sailed through. The
    // WAL and SHM sidecars are named separately because they are distinct paths —
    // removing spans.db-wal alone discards the most recent, most interesting spans.
    dbPath,
    dbPath + '-wal',
    dbPath + '-shm',
    dbPath + '-journal',
    // Online binary snapshots (server/db.ts writes them beside the database).
    // A record you can restore is the whole reason a backup is worth taking.
    path.join(path.dirname(dbPath), 'backups'),
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
    path.join(home, '.claude', 'hooks'),
    path.join(cwd, '.claude', 'settings.json'),
    path.join(cwd, '.claude', 'settings.local.json'),
    path.join(cwd, '.claude', 'hooks'),
    // The hook that is running RIGHT NOW, and the directory it loads its
    // artefacts from. Self-reference rather than a hardcoded layout, so an
    // installed copy, a Docker copy and an in-repo copy each protect themselves.
    path.resolve(__dirname),
    // The three files this hook actually reads. Going through the same resolvers
    // the hook uses means an explicit CLAUDESEC_ENFORCE_* override is protected
    // too, instead of only the default location.
    resolveConfigPath(),
    resolveSnapshotPath(),
    resolveProtectedPathsPath(),
  ];
  const seen = new Set();
  const uniq = [];
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
 */
function serviceUnitHit(pathLower) {
  if (!pathLower) return false;
  return (
    /(?:^|\/)(?:launchagents|launchdaemons)\/[^/]{0,80}claudesec[^/]{0,40}\.plist/.test(pathLower) ||
    /(?:^|\/)systemd\/[^/]{0,40}\/[^/]{0,40}claudesec[^/]{0,40}\.(?:service|timer)/.test(pathLower)
  );
}

/**
 * Expand a leading `~` in every argument position of a shell command. The hook
 * already expands `$HOME` (expandHomeVar); a tilde is the far more common
 * spelling and, left literal, let `echo x > ~/.claudesec/hooks/enforce-config.json`
 * sail straight past an absolute-prefix compare.
 */
function expandTilde(text) {
  if (!text) return text;
  const home = os.homedir();
  return text.replace(/(^|[\s"'=:(])~(?=[/\s"')]|$)/g, (_m, lead) => lead + home);
}

/**
 * Substitute variables assigned EARLIER IN THE SAME command string, so
 * `P=~/.claude/settings.json; echo x > $P` still resolves onto a real path
 * instead of hiding behind one letter of indirection.
 *
 * Only literal, same-command assignments are followed. A variable exported by
 * the parent shell, set in an earlier command, or built by command substitution
 * is out of reach of a static pre-exec hook — the server-side detection layer
 * remains the backstop for those, exactly as the catastrophic floor documents.
 */
function expandLocalVars(cmd) {
  if (!cmd || cmd.indexOf('$') === -1) return cmd;
  const assigned = new Map();
  const rx = /(?:^|[\n;&|(`]|\bexport\s+)\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))/g;
  let m;
  while ((m = rx.exec(cmd)) !== null) {
    const value = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
    if (value) assigned.set(m[1], value);
  }
  if (!assigned.size) return cmd;
  return cmd.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (whole, braced, bare) => {
      const v = assigned.get(braced || bare);
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
 * usual case for a Write) still resolves through a symlinked parent directory.
 */
function selfPathForms(p) {
  if (!p) return [];
  const home = os.homedir();
  const forms = [];
  const push = (v) => { if (v && !forms.includes(v)) forms.push(v); };
  push(p.toLowerCase());
  const expanded = expandHomeVar(
    p === '~' ? home : p.startsWith('~/') ? path.join(home, p.slice(2)) : p,
  );
  push(expanded.toLowerCase());
  let abs = '';
  try {
    abs = path.resolve(process.cwd(), expanded);
    push(abs.toLowerCase());
  } catch (_) {
    // An unresolvable path keeps the literal forms above; never throw.
  }
  const real = resolveRealpath(abs || expanded);
  if (real) push(real.toLowerCase());
  return forms;
}

/**
 * How a candidate path relates to a protected prefix. Both arguments must
 * already be lowercased.
 *
 * The floor used to ask `candidate.includes(prefix)`, which answers neither of
 * the two questions that matter. Raw substring containment says YES to
 * `~/.claude/settings.json.bak` — a different file, an ordinary backup — and NO
 * to `~/.claudesec`, which is the PARENT of the protected hooks directory. So it
 * over-blocked a copy and under-blocked `rm -rf ~/.claudesec`, the single command
 * that takes the whole control plane with it. That is a correctness bug in the
 * comparison, not a missing entry in the list.
 *
 * The relation is therefore computed on path COMPONENTS:
 *   • the same path, or the candidate sitting INSIDE the prefix → always a hit;
 *   • the candidate being an ANCESTOR of the prefix → a hit only when the verb
 *     destroys or displaces a whole tree (`allowAncestor`; see
 *     DESTRUCTIVE_COMMANDS). `rm -rf ~/.claudesec` destroys the protected child;
 *     `cp -r ../assets .` does not, and must stay allowed.
 */
function pathRelated(candidate, prefix, allowAncestor) {
  if (!candidate || !prefix) return false;
  // A trailing separator is the same directory (`rm -rf ~/.claudesec/`), but the
  // filesystem root is one separator and must not be trimmed away to nothing.
  const trim = (s) => (s.length > 1 ? s.replace(/[\\/]+$/, '') : s);
  const c = trim(candidate);
  const p = trim(prefix);
  if (c === p) return true;
  const dir = (s) => (s.endsWith('/') || s.endsWith('\\') ? s : s + '/');
  if (c.startsWith(dir(p))) return true;             // candidate is inside the prefix
  return allowAncestor && p.startsWith(dir(c));      // candidate contains the prefix
}

/**
 * Does any spelling of `p` land on the control plane? Returns a reason or null.
 * `destructive` says whether the verb that produced this candidate removes or
 * displaces a whole directory tree, which is what makes an ANCESTOR of a
 * protected path count (see pathRelated).
 */
function selfPathHit(p, destructive) {
  const forms = selfPathForms(p);
  if (!forms.length) return null;
  const prefixes = selfProtectedPrefixes();
  for (const form of forms) {
    for (const prefix of prefixes) {
      if (pathRelated(form, prefix.toLowerCase(), destructive)) return prefix;
    }
    const base = form.split(/[\\/]/).pop() || '';
    if (SELF_BASENAMES.has(base)) return 'the ClaudeSec enforcement control plane';
    if (AUDIT_KEY_BASENAME.test(base)) return 'the ClaudeSec audit signing key';
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
 */
const COPY_COMMANDS = new Set(['cp', 'rsync', 'ditto', 'install']);

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
 */
function copyWriteTargets(verb, args) {
  const targets = [];
  const positional = [];
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

// ── Shell quoting ────────────────────────────────────────────────────────────
// The tokenizer used to treat every backtick and every `$(` as command
// substitution wherever it appeared. That is right in a script and wrong in
// prose, and this repo writes prose about shell commands on nearly every page:
//
//     cat > CHANGELOG.md <<'EOF'
//     - fix(enforce): `rm -rf ~/.claudesec` is now refused
//     EOF
//
// was refused, because the backtick span was followed as a substitution, the `rm`
// inside it was read as a mutating verb, and its "arguments" ran on into the
// surrounding sentence until they reached a protected path. Documenting a fix was
// blocked by the fix. The same bug refused `git commit -m 'refuse `rm -rf …`'` and
// every `gh pr create --body '…'` that quoted a command.
//
// The fix is not a guess about which files look like documentation — it is the
// shell's own rule, applied in the two places the tokenizer was not applying it:
//
//   • A QUOTED heredoc (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) is not expanded at all.
//     No parameter expansion, no substitution, no backticks — the body is data on
//     its way to a file. The floor's stated contract is that it never matches
//     CONTENT, only the target path and the command, so scanning that body was
//     always inconsistent with the rest of this hook. An UNQUOTED `<<EOF` body
//     IS expanded, and is still scanned.
//   • A SINGLE-QUOTED span is literal. Backticks and `$(` inside `'…'` are
//     characters, not syntax. Inside DOUBLE quotes they ARE syntax, and are still
//     followed — the shell really would run them.
//
// Applying the same rule properly also closed an under-block in the other
// direction: because `$(` was a plain split delimiter, the closing `)` stayed
// glued to the last argument, so `$(rm -rf ~/.claudesec)` compared
// `…/.claudesec)` against the prefixes and matched nothing. Substitutions are now
// extracted with their delimiters, so a real one is refused and a quoted one is
// not — see extractSubstitutions.

/**
 * Remove the BODY of every QUOTED heredoc (`<<'EOF'`, `<<"EOF"`, `<<\EOF`, and
 * the `<<-` tab-stripping forms). The introducing line is KEPT, because that is
 * where the redirect lives — `cat > ~/.claude/settings.json <<'EOF'` must still
 * be refused on its target.
 *
 * The terminator is matched on the trimmed line, which is deliberately more
 * permissive than POSIX for the non-`<<-` form. Erring that way ends the body
 * EARLY, which means more text is scanned as commands, not less — the safe
 * direction for a floor.
 */
function stripQuotedHeredocBodies(cmd) {
  if (!cmd || cmd.indexOf('<<') === -1) return cmd;
  const rx = /<<-?[ \t]*(?:'([^'\n]{1,64})'|"([^"\n]{1,64})"|\\([A-Za-z_][A-Za-z0-9_]{0,63}))/g;
  let out = '';
  let cursor = 0;
  let m;
  while ((m = rx.exec(cmd)) !== null) {
    const delim = m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3];
    // The rest of the INTRODUCING line is real command text; the body starts
    // after its newline. A `<<'EOF'` with no newline after it has no body here.
    const lineEnd = cmd.indexOf('\n', rx.lastIndex);
    if (lineEnd === -1) break;
    out += cmd.slice(cursor, lineEnd + 1);
    // Walk forward line by line for the terminator. Monotonic, so the whole
    // function stays a single linear pass over the command.
    let i = lineEnd + 1;
    let end = cmd.length;
    while (i <= cmd.length) {
      const nl = cmd.indexOf('\n', i);
      const line = cmd.slice(i, nl === -1 ? cmd.length : nl);
      if (line.trim() === delim) { end = nl === -1 ? cmd.length : nl; break; }
      if (nl === -1) break;
      i = nl + 1;
    }
    cursor = end;
    rx.lastIndex = end;
  }
  return out + cmd.slice(cursor);
}

/**
 * Find the `)` that closes the `(` at `open`, honoring quotes. Returns -1 when
 * the substitution is unterminated, which the caller reads as "runs to the end of
 * the command" — again the safe direction, since it scans MORE text.
 */
function matchCloseParen(s, open) {
  let depth = 0;
  let sq = false;
  let dq = false;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (!sq && c === '\\') { i++; continue; }
    if (!dq && c === "'") { sq = !sq; continue; }
    if (!sq && c === '"') { dq = !dq; continue; }
    if (sq || dq) continue;
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/**
 * Pull command substitutions out of a command, honoring shell quoting.
 *
 * Returns the command with every ACTIVE substitution flattened in place, plus the
 * list of substituted commands to analyse in their own right. Both halves matter,
 * and they catch different attacks:
 *   • the NESTED list catches `$(rm -rf ~/.claudesec)` — the dangerous verb is
 *     inside the substitution;
 *   • the FLATTENED text catches `rm -rf $(echo ~/.claudesec/hooks)` — the
 *     dangerous verb is outside and the substitution only supplies its argument.
 *
 * A substitution inside `'…'` is not active and is left as literal text, which is
 * what lets a document quote a command in backticks. Inside `"…"` it IS active,
 * because the shell would run it.
 */
function extractSubstitutions(cmd) {
  const nested = [];
  if (!cmd || (cmd.indexOf('`') === -1 && cmd.indexOf('$(') === -1)) {
    return { text: cmd, nested };
  }
  let text = '';
  let i = 0;
  let sq = false; // inside '…' — nothing is syntax
  let dq = false; // inside "…" — substitutions still are
  while (i < cmd.length) {
    const ch = cmd[i];
    if (!sq && ch === '\\' && i + 1 < cmd.length) {
      text += ch + cmd[i + 1]; // an escaped backtick is a character, not syntax
      i += 2;
      continue;
    }
    if (!dq && ch === "'") { sq = !sq; text += ch; i++; continue; }
    if (!sq && ch === '"') { dq = !dq; text += ch; i++; continue; }
    if (!sq && (ch === '`' || (ch === '$' && cmd[i + 1] === '('))) {
      const isTick = ch === '`';
      const close = isTick ? cmd.indexOf('`', i + 1) : matchCloseParen(cmd, i + 1);
      const stop = close === -1 ? cmd.length : close;
      const inner = cmd.slice(i + (isTick ? 1 : 2), stop);
      nested.push(inner);
      // Spaces keep the flattened text from fusing the substitution onto its
      // neighbours (`a$(b)c` must not become one token `abc`).
      text += ' ' + inner + ' ';
      i = close === -1 ? cmd.length : close + 1;
      continue;
    }
    text += ch;
    i++;
  }
  return { text, nested };
}

/**
 * Pull the paths a Bash command would WRITE to out of the command line. This is
 * deliberately a heuristic and not a shell parser — it only has to tell "reads
 * this path" from "writes this path", which is what keeps `cat …/settings.json`
 * allowed while `cat foo > …/settings.json` is denied.
 *
 * Three things count as a write target:
 *   • a token immediately after a `>` / `>>` redirect, whatever produced the
 *     stream;
 *   • every argument of a mutating command (MUTATING_COMMANDS), plus the
 *     conditional writers — `sed`/`perl` given `-i`, `sqlite3` given mutating SQL,
 *     and an interpreter given an inline `-c`/`-e` script (the script body is
 *     returned whole, so a path buried inside it is still compared). The
 *     copy-shaped verbs are the one exception: only their destination counts (see
 *     copyWriteTargets); and
 *   • everything a nested shell would write — see the "Shell wrappers" section
 *     above for exactly how far that goes and where it stops.
 *
 * Returns `{ value, destructive }` entries; `destructive` says whether the verb
 * removes or displaces a whole tree (DESTRUCTIVE_COMMANDS), which is what lets an
 * ANCESTOR of a protected path count as a hit. `depth` bounds the shell
 * recursion; callers leave it at 0.
 */
function bashWriteTargets(cmd, depth = 0) {
  const out = [];
  if (!cmd) return out;
  // Drop what the shell will not expand, then lift out what it will. A quoted
  // heredoc body is data on its way to a file; a substitution inside `'…'` is
  // literal text. Everything the shell WOULD run survives both steps.
  const stripped = stripQuotedHeredocBodies(cmd);
  const { text: flattened, nested } = extractSubstitutions(stripped);
  // Each substitution is a command in its own right — `$(rm -rf ~/.claudesec)`
  // hides the verb inside the parentheses, where no argument scan would reach it.
  if (depth < MAX_SHELL_DEPTH) {
    for (const sub of nested) {
      for (const t of bashWriteTargets(sub, depth + 1)) out.push(t);
    }
  }
  // Resolve indirection before tokenizing: same-command variables first, then
  // $HOME, then `~`. Each layer feeds the next, so `P=~/x; … > $P` ends up as an
  // absolute path the prefix compare can actually see.
  const expanded = expandTilde(expandHomeVar(expandLocalVars(flattened)));
  // `printf '…' | sh` hands the shell its script on stdin, where no argument scan
  // can see it. When a pipeline ENDS in a bare shell, every quoted string feeding
  // it is re-analysed as a script.
  if (depth < MAX_SHELL_DEPTH && PIPE_INTO_SHELL.test(expanded)) {
    for (const quoted of expanded.match(/"[^"]*"|'[^']*'/g) || []) {
      for (const t of bashWriteTargets(quoted.slice(1, -1), depth + 1)) out.push(t);
    }
  }
  // Rough split into simple commands: a shell separator starts a new command, and
  // a verb only governs the arguments in its own segment. Backticks and `$(` are
  // NO LONGER split delimiters — extractSubstitutions has already lifted the real
  // ones out (and left the quoted ones as prose), which is what stopped a
  // backticked command in a document from being read as a command. Parentheses
  // are deliberately not split on either: an inline `python -c "open(...)"` script
  // is one argument and must stay intact.
  for (const seg of expanded.split(/[\n;|&]+/)) {
    const tokens = [];
    const rx = /(>>?|<|"([^"]*)"|'([^']*)'|[^\s"'<>|;&]+)/g;
    let m;
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
    // A redirect truncates a FILE; aimed at a directory the shell simply errors,
    // so it never counts as destroying a tree.
    for (const t of tokens) if (t.redirect) out.push({ value: t.val, destructive: false });
    // A shell (or `script`/`flock`) handed an inline `-c` payload is a WRAPPER,
    // not a leaf command: re-analyse the payload. The host is looked for at ANY
    // token position rather than only at command position, which is what covers
    // `env sh -c`, `sudo sh -c`, `timeout 5 sh -c`, `xargs sh -c`, `nice -n 5 sh -c`
    // and `script -q /dev/null sh -c` without enumerating a wrapper grammar each.
    if (depth < MAX_SHELL_DEPTH) {
      for (let h = 0; h < tokens.length; h++) {
        if (!INLINE_SCRIPT_HOSTS.test(tokens[h].val.replace(/^.*[\\/]/, ''))) continue;
        for (let j = h + 1; j < tokens.length; j++) {
          const a = tokens[j].val;
          const eq = a.startsWith('--') ? a.indexOf('=') : -1;
          // Skip past the shell's other flags and `flock`'s lock-file argument;
          // the payload is whatever follows the inline-script flag.
          if (!INLINE_SCRIPT_FLAG.test(eq > 0 ? a.slice(0, eq) : a)) continue;
          // `--command=…` carries the script inline. An EMPTY inline value means
          // the tokenizer split the argument at its opening quote
          // (`--command='rm …'` → `--command=` + `rm …`), so the payload is the
          // next token — which is also where every other spelling puts it.
          const inline = eq > 0 ? a.slice(eq + 1) : '';
          const payload = inline || (j + 1 < tokens.length ? tokens[j + 1].val : '');
          if (payload) for (const t of bashWriteTargets(payload, depth + 1)) out.push(t);
          break;
        }
      }
    }
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
        args.some((a) => /^-(?:c|e|p|-eval)$/.test(a))) ||
      // `sqlite3 db "UPDATE …"` rewrites the database in place; a SELECT reads it.
      (verb === 'sqlite3' && args.some((a) => SQLITE_MUTATION.test(a)));
    if (!writes) continue;
    const destructive =
      DESTRUCTIVE_COMMANDS.has(verb) ||
      // `rsync --delete` removes whatever the source tree does not contain, so it
      // empties its destination the way `rm -r` does.
      (verb === 'rsync' && args.some((a) => a.startsWith('--delete')));
    // A copy reads its sources and writes only its destination; everything else
    // mutates every path it is handed.
    for (const a of COPY_COMMANDS.has(verb) ? copyWriteTargets(verb, args) : args) {
      out.push({ value: a, destructive });
      // An inline script arrives as one argument with the path buried inside it
      // (`node -e "fs.writeFileSync('.claude/settings.json', …)"`). Break such an
      // argument on the punctuation a script uses around its string literals so
      // the path itself is compared too. A fragment carries no verb of its own, so
      // it never claims to destroy a tree.
      if (/['"(),=]/.test(a)) {
        for (const frag of a.split(/['"(),=;\s]+/)) if (frag) out.push({ value: frag, destructive: false });
      }
    }
  }
  return out;
}

/**
 * Does the call's file TARGET or Bash command WRITE to the enforcement control
 * plane? Returns a short description of what was hit, or null.
 *
 * Never matches edit CONTENT — only the target path or the command — so editing
 * a file that merely *mentions* the control plane is not blocked. Comparison is
 * case-INSENSITIVE because on macOS and Windows `/X/.CLAUDESEC` and
 * `/x/.claudesec` are the same file, which would make a case-sensitive compare a
 * one-character bypass.
 */
function selfProtectionHit(target, bashCmd) {
  // An edit tool's target is a single FILE: it can be overwritten, never
  // recursively removed, so the ancestor reading does not apply to it.
  const hitTarget = selfPathHit(target, false);
  if (hitTarget) return hitTarget;
  if (!bashCmd) return null;
  for (const candidate of bashWriteTargets(bashCmd)) {
    const hit = selfPathHit(candidate.value, candidate.destructive);
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

/**
 * Resolve ~/.claudesec/hooks — the USER-GLOBAL enforcement control plane.
 * Honors CLAUDESEC_HOME exactly as the installer/server do. Mirrors
 * hookArtifactsDir() in server/enforceEval.ts (parity test).
 */
function hookArtifactsDir() {
  const homeDir = process.env.CLAUDESEC_HOME || path.join(os.homedir(), '.claudesec');
  return path.join(homeDir, 'hooks');
}

/**
 * CANONICAL enforce-config.json resolution — kept byte-for-byte in step with
 * server/enforceEval.ts resolveConfigPath() so the dashboard's reported effective
 * mode is EXACTLY what this hook runs. A parity test
 * (tests/enforceConfigPathParityTest.ts) enforces the agreement.
 *
 * Precedence (fail-OPEN / monitor-by-default):
 *   1. CLAUDESEC_ENFORCE_CONFIG — explicit path override (tests / isolated server).
 *   2. <CLAUDESEC_HOME or ~/.claudesec>/hooks/enforce-config.json — the USER-GLOBAL
 *      control plane (primary, machine-wide). NOT per-cwd: a repo-root config file
 *      is deliberately NO LONGER consulted — it once made the mode depend on which
 *      directory the agent ran in, so the dashboard could read 'monitor' while the
 *      installed hook ran 'enforce'. The global file is the one source of truth.
 *   3. Beside THIS hook (__dirname) — Docker/portable fallback, only when the
 *      global file is absent AND this hook is not the global install
 *      (__dirname !== the global hooks dir). The installed hook lives in the
 *      global dir, so there the beside-file IS the global file; gating on the
 *      mismatch keeps a custom/Docker copy in parity with the server (which has
 *      no beside-fallback) while still letting a self-contained Docker hook with
 *      no ~/.claudesec read its bundled config.
 * When nothing readable exists, return the global path so the absent-file read
 * fails cleanly and resolveMode falls through to CLAUDESEC_MODE → 'monitor'.
 */
function resolveConfigPath() {
  // 1. Explicit override.
  if (process.env.CLAUDESEC_ENFORCE_CONFIG) {
    return path.resolve(process.env.CLAUDESEC_ENFORCE_CONFIG);
  }
  // 2. User-global control plane (primary).
  const globalDir = hookArtifactsDir();
  const global = path.join(globalDir, 'enforce-config.json');
  if (fs.existsSync(global)) return global;
  // 3. Docker/portable fallback — beside this hook, only when the global is absent
  //    AND this hook is NOT the global install. The installed hook lives IN the
  //    global hooks dir, so __dirname === globalDir there and a beside-file is the
  //    same global file (no divergence). But a custom/Docker copy or a hook run
  //    straight from cli/hooks/ has a different __dirname — gating on the mismatch
  //    keeps the server (which has no beside-fallback) and the hook resolving the
  //    SAME file, while preserving Docker behavior (no global dir → mismatch → use
  //    the bundled beside-file).
  const here = path.resolve(__dirname);
  if (here !== path.resolve(globalDir)) {
    const beside = path.join(here, 'enforce-config.json');
    if (fs.existsSync(beside)) return beside;
  }
  return global;
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

// ── Default protected paths (always merged in) ───────────────────────────────
// The user's protected-paths list is EMPTY on a fresh install, so without these
// defaults the floor would protect nothing out of the box. We merge in a small,
// conservative, HIGH-VALUE set of credential stores that an agent should never
// read or overwrite. Kept deliberately minimal to avoid over-blocking ordinary
// work. The user can still remove any of these (they are not pinned). Kept in
// sync with DEFAULT_PROTECTED in server/enforceEval.ts (parity test).
//
// Two kinds of default:
//   • path defaults — a literal home-relative path, matched by the same
//     case-insensitive substring + realpath logic as a user entry.
//   • the `secretEnv` default — a SHAPE rule for dotenv secrets: any path whose
//     final component is `.env` or `.env.<something>` EXCEPT the well-known
//     non-secret variants (`.env.example`/`.sample`/`.template`/`.dist`/`.tpl`).
//     This protects real secret files without walling off committed templates.
function defaultProtectedEntries() {
  const home = os.homedir();
  const mk = (rel, label) => {
    const expanded = path.join(home, rel);
    return { label, forms: ['~/' + rel, expanded] };
  };
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

// A path "looks like" a dotenv SECRET file when its final path component is
// exactly `.env` or starts with `.env.` BUT is not one of the well-known
// non-secret template variants. So `.env`, `.env.local`, `.env.production` are
// protected; `.env.example`/`.env.sample`/`.env.template`/`.env.dist`/`.env.tpl`
// are NOT (they are committed scaffolding that holds no real credentials).
// Mirrors secretEnvHit() in server/enforceEval.ts.
function secretEnvHit(targetLower) {
  if (!targetLower) return false;
  // Final path component (handle both / and \ separators, case already lowered).
  const base = targetLower.split(/[\\/]/).pop() || '';
  if (base === '.env') return true;
  if (!base.startsWith('.env.')) return false;
  const suffix = base.slice('.env.'.length);
  // Non-secret template variants — never protected.
  return !/^(?:example|sample|template|dist|tpl)$/.test(suffix);
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
 * Load the protected-path entries. ALWAYS includes the conservative built-in
 * defaults (defaultProtectedEntries) so a fresh install still protects the
 * high-value credential stores; the user's entries are merged on top. Fail-OPEN
 * → the defaults alone (never throws). User shape: [{ path, label }]. Each entry
 * is normalized so a leading '~' expands to the home dir; both the raw and
 * home-expanded forms are carried so a target matches whichever spelling the
 * agent used.
 */
function loadProtectedPaths() {
  // ALWAYS start with the conservative built-in defaults so a fresh install
  // (empty/missing user list) still protects the high-value credential stores.
  // The user's entries are appended; a user entry never removes a default here.
  const out = defaultProtectedEntries();
  try {
    const raw = JSON.parse(fs.readFileSync(resolveProtectedPathsPath(), 'utf8'));
    if (!Array.isArray(raw)) return out;
    const home = os.homedir();
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
    return out; // missing / unreadable / malformed → still apply the defaults
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
    // The dotenv-secret default matches by SHAPE rather than a literal form, and
    // ONLY against the file TARGET (literal or symlink-resolved) — never the Bash
    // command. A path-shape match on a free-form command string would block a plain
    // `cat .env` read; the always-on EXFIL catastrophic floor already covers a
    // `.env` read piped to the network, which is the dangerous case. Keeping this
    // default to file targets protects Read/Edit/Write of a real `.env` secret
    // without re-litigating the exfil floor's "secret + network sink" contract.
    if (e.secretEnv) {
      if (secretEnvHit(tLit) || secretEnvHit(tReal)) return e;
      continue;
    }
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

/**
 * Best-effort extract of a tool name + a short target summary from the raw hook
 * stdin, WITHOUT running the rule engine. Used only by the bypass path, which
 * runs before the main parse. Fail-OPEN on anything malformed: a bad payload
 * yields empty strings, never an exception — the bypass must allow regardless.
 */
function summarizeForBypass(input) {
  let toolName = '';
  let target = '';
  try {
    const data = JSON.parse(input || '{}');
    toolName = String((data && data.tool_name) || '');
    const ti = (data && data.tool_input) || {};
    // Whatever best identifies WHAT was allowed: a Bash command, a fetch URL,
    // or the file the call targets. First non-empty wins.
    target = String(
      ti.command || ti.url || ti.file_path || ti.path || ti.notebook_path || '',
    );
  } catch (_) {
    // malformed stdin → leave both empty (fail-open), the bypass still logs+allows
  }
  return { toolName, target };
}

function run(input) {
  // 1. Bypass. An explicit escape hatch (CLAUDESEC_HOOKS_BYPASS=1) allows every
  // tool call — but I record it FIRST so the bypass leaves a trace in the
  // tamper-evident enforce feed. An investigator must be able to see that
  // enforcement was disabled and WHAT was allowed under it. Best-effort and
  // fail-open: postMonitorLog guarantees the callback fires exactly once (on
  // response/error/timeout), so a down dashboard can never make the bypass hang
  // or crash the tool pipeline — we still exit 0.
  if (process.env.CLAUDESEC_HOOKS_BYPASS === '1') {
    const { toolName, target } = summarizeForBypass(input);
    // Mirror the shape of every other enforce-feed event; the server adds `ts`,
    // scrubs, and persists with the hash chain. Embed the tool name in the
    // command summary (the feed has no dedicated tool field) so the entry reads
    // as "<Tool>: <what was allowed>".
    const summary = redact([toolName, target].filter(Boolean).join(': ')) || '(no tool input)';
    return postMonitorLog(
      {
        mode: resolveMode(),
        label: 'Enforcement bypassed (CLAUDESEC_HOOKS_BYPASS=1)',
        severity: 'high',
        command: summary,
        blocked: false,
        wouldBlock: false,
      },
      () => process.exit(0), // exit only AFTER the POST flushes (or its backstop fires)
    );
  }

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
  // not be able to edit the enforcement control plane (the ~/.claudesec/hooks/
  // artefacts, this hook, the service definition) or the Claude settings that
  // register this hook, which would let it disable the enforcer. Matches the file
  // TARGET or the WRITE targets of the Bash command only, never edit content.
  // (The ClaudeSec server writes these files from a different process, which is
  // not subject to this hook.)
  {
    // Reads are exempt: none of these files hold a secret, so denying a look at
    // them bought nothing and walled off the agent inspecting its own settings.
    // Every other tool carrying a file target is treated as a potential writer.
    const selfTarget = READ_TOOLS.has(toolName) ? '' : fileTarget;
    const hitSelf = selfProtectionHit(selfTarget, bashCmd);
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
