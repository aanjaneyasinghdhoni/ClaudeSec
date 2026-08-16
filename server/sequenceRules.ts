// server/sequenceRules.ts
//
// Stateful, sequence-aware detection.
//
// WHY this module exists at all: every built-in rule is a stateless regex over
// a single span's text. That catches an action that is
// dangerous *in isolation* — `rm -rf /`, a hard-coded key, a reverse shell.
// It cannot see the shape that actually matters for an agent: two or three
// individually-ordinary actions in a particular ORDER. Reading `.env` is
// ordinary. Running `curl -X POST` is ordinary. Reading `.env` and then POSTing
// off-box ninety seconds later is the Nx "s1ngularity" attack, and no
// single-string rule can express it.
//
// DESIGN CONSTRAINTS — this runs on the span-ingest hot path:
//   • Bounded memory. State is a FIFO map of at most MAX_TRACES traces, each
//     holding at most MAX_FACTS recent facts. Same bounded-FIFO shape as
//     traceRepoCache in repoIdentity.ts, and for the same reason: a traceId on
//     an OTLP span is attacker-controlled, so an unbounded map is a memory leak
//     handed out for free.
//   • Cheap. The overwhelming majority of spans (llm_request is over half the
//     corpus) carry no command, path or URL and are rejected by a Set lookup
//     before a single regex runs.
//   • Never throws. A classifier fault must never stop a span being ingested.
//
// NOISE BUDGET — the binding constraint here is not coverage, it is volume. An
// analyzer that cries wolf gets ignored, so every rule below was measured
// against the full local span history before it was allowed to ship, and any
// candidate that fired more than a handful of times over that history was
// tightened or cut. The tightening levers that did the work:
//   • Templates are not secrets. `.env.example` is documentation.
//   • A GET is not an upload. The egress step must CARRY a payload
//     (`-d`, `-F`, `--data`, `-T`, `scp`, `nc`) — fetching a doc page after
//     reading a config file is what an agent does all day.
//   • Loopback and RFC1918 are not "off-box". Half the credential-shaped
//     traffic on a developer box is talking to a local dev server.
//   • A heredoc body is a FILE, not a command. `cat > script.mjs <<'EOF' … EOF`
//     is how an agent authors a file, and the bytes in between are data. Reading
//     them as shell was by far the largest source of phantom chains.
//   • A sequence needs two SPANS. Two facts from one command are a stateless
//     match wearing a costume, and the stateless rule set already owns it.
//
// Findings carry the CHAIN — the actual spans, in order, with timestamps — not
// just a label. That is the whole advantage over a regex: the alert can be
// judged without re-reading the session.

import type { Severity } from '../src/shared/types.js';

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

/** One span, normalised to the few fields the sequence rules actually read. */
export interface SequenceInput {
  spanId: string;
  traceId: string;
  /** Tool name — `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, … */
  name: string;
  /** Wall-clock milliseconds for this span. */
  tsMs: number;
  /** Raw (pre-scrub) attributes. Scrubbing happens on the way out, not here. */
  attrs: Record<string, unknown>;
}

/** One link in the evidence chain a finding renders. */
export interface ChainStep {
  /** Human-readable role of this step, e.g. "credential read". */
  step: string;
  spanId: string;
  /** ISO-8601, so the chain reads as a timeline. */
  ts: string;
  /** The span name (`Bash`, `Read`, …). */
  span: string;
  /** Short excerpt of what the step actually did. Scrubbed by the caller. */
  detail: string;
}

/**
 * Severity ordering, so a caller can decide whether a chain outranks whatever
 * the stateless rules already said about the closing span.
 */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  none: 0, low: 1, medium: 2, high: 3, critical: 4,
};

export interface SequenceFinding {
  label: string;
  severity: Severity;
  /** Seconds between the first and last step. */
  elapsedSec: number;
  chain: ChainStep[];
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/** Traces held in memory. A busy operator runs a handful of agents at once. */
const MAX_TRACES = 2_000;
/** Facts retained per trace. Facts are rare — most spans produce none. */
const MAX_FACTS = 48;
/** A fact older than this can satisfy no rule, so it is dropped on sight. */
const MAX_FACT_AGE_MS = 30 * 60 * 1000;
/**
 * Per-trace, per-label cooldown. `insertOrDedupeAlert` already collapses
 * repeats over 15 minutes, but the engine should not even manufacture the
 * duplicate: a session that reads three secrets and then uploads should produce
 * ONE finding, not three.
 */
const RULE_COOLDOWN_MS = 30 * 60 * 1000;
/** Excerpt length stored per chain step. Long enough to judge, short enough to read. */
const DETAIL_MAX = 160;

// ---------------------------------------------------------------------------
// Fast reject
// ---------------------------------------------------------------------------

// Only these tools can ever produce a fact. Everything else — llm_request
// (over half of all spans), StructuredOutput, TaskUpdate, the browser MCP
// tools — leaves the engine after one Set lookup.
const CARRIER_TOOLS: ReadonlySet<string> = new Set([
  'Bash', 'Read', 'Write', 'Edit', 'NotebookEdit', 'MultiEdit',
]);

// ---------------------------------------------------------------------------
// Step predicates
// ---------------------------------------------------------------------------

// A template is documentation, not a credential. `.env.example` is checked into
// thousands of repos precisely so it can be read.
const TEMPLATE_PATH =
  /\.(?:example|sample|template|dist|md|mdx|txt|lock)$|\.env\.(?:example|sample|template|test|ci|local\.example)\b/i;

// Files that hold live credentials on a developer machine.
const SECRET_PATH =
  /(?:^|\/)(?:\.env(?:\.[\w-]+)?|\.npmrc|\.netrc|\.pgpass|id_rsa|id_ed25519|id_ecdsa|credentials)$|\/\.aws\/|\/\.ssh\/id_|\/\.config\/gh\/hosts\.yml|\/\.docker\/config\.json|\/\.kube\/config|\/\.claude\.json$|\.(?:pem|p12|pfx|jks|keystore)$/i;

// Reading a secret THROUGH the shell rather than through the Read tool. Bounded
// to a single command segment so a later `; cat README` cannot drag an earlier
// `.env` token into the match.
const SHELL_READ_SEGMENT = /\b(?:cat|bat|less|more|head|tail|strings|xxd|od|base64|source|\.)\s+[^\n;&|]{0,160}/gi;
const KEYCHAIN_READ = /\bsecurity\s+find-(?:generic|internet)-password\b|\bsecret-tool\s+lookup\b/i;

// An `env | grep TOKEN` sweep: enumerating the process environment and filtering
// it down to the credential-shaped names. Nobody does this to read one variable.
const CRED_ENV_SWEEP =
  /\b(?:env|printenv|set|export)\b\s*(?:\|\s*(?:grep|rg|ag|egrep)\b[^\n]{0,80}(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY))/i;

// Egress that CARRIES a payload. This is the line between exfiltration and the
// ordinary API call an agent makes to do its job: a GET fetches, a body sends.
const PAYLOAD_EGRESS =
  /\bcurl\b[^\n]{0,400}?(?:-X\s*(?:POST|PUT|PATCH)\b|--data(?:-raw|-binary|-urlencode|-ascii)?\b|--upload-file\b|(?:^|\s)-[dFT](?:\s|=))|\bwget\b[^\n]{0,300}?--post-(?:data|file)\b|\b(?:scp|rsync)\b[^\n]{0,200}?\s[\w.-]+@[\w.-]+:|\b(?:nc|ncat|netcat)\b\s+(?!-l\b)[^\n]{0,100}?\s\d{2,5}\b|\bgh\s+gist\s+create\b/i;

// Where that payload is going. A URL, an scp/rsync target, or an nc host.
const EGRESS_HOST =
  /https?:\/\/([^\s/'"$:]+)|(?:scp|rsync)\b[^\n]{0,200}?\s[\w.-]+@([\w.-]+):|\b(?:nc|ncat|netcat)\b\s+(?:-\w+\s+)*([\w.-]+)\s+\d{2,5}\b/i;

// Loopback and RFC1918. Talking to your own dev server is not exfiltration, and
// on a developer box that is most of the credential-shaped POST traffic there is.
const LOCAL_HOST =
  /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[\w-]+\.local|host\.docker\.internal)$/i;

// A git hook is code the repo runs for you on commit/merge/checkout. Writing one
// is how you get execution without ever asking for it. `.sample` files are the
// inert stubs git ships.
const GIT_HOOK_PATH = /\/\.git\/hooks\/(?!.*\.sample$)[\w.-]+$/;

// Persistence: things the machine re-executes without the agent being present.
const PERSISTENCE_PATH =
  /\/\.(?:zshrc|bashrc|bash_profile|zshenv|zprofile|profile)$|\/\.config\/fish\/config\.fish$|\/Library\/LaunchAgents\/|\/Library\/LaunchDaemons\/|\/etc\/(?:cron|systemd)|\/\.config\/systemd\/user\/|\/\.ssh\/(?:authorized_keys|config)$/;

// Agent-config poisoning: the hooks and MCP wiring the coding agent itself obeys.
// Rewriting these turns the developer's own agent into the payload.
const AGENT_CONFIG_PATH =
  /\/\.(?:claude|codex|cursor|continue|aider|windsurf)\/(?:settings(?:\.local)?\.json|hooks\/|mcp[_.]?\w*\.json|config\.toml)|\/\.mcp\.json$/;

const PACKAGE_JSON = /(?:^|\/)package\.json$/;
// The npm lifecycle hooks that execute on `install` — the supply-chain foothold.
const LIFECYCLE_SCRIPT = /"(?:preinstall|install|postinstall|prepare|prepublish(?:Only)?)"\s*:/;
const INSTALL_OR_PUBLISH = /\b(?:npm|pnpm|yarn|bun)\s+(?:i\b|install\b|add\b|ci\b|publish\b)/;

const GIT_RUNS_HOOKS = /\bgit\s+(?:commit|merge|rebase|checkout|push|pull|am)\b/;
const GIT_REMOTE_REPOINT = /\bgit\s+remote\s+(?:add|set-url)\b[^\n]{0,200}?(https?:\/\/|[\w.-]+@[\w.-]+:)/i;
const GIT_PUSH = /\bgit\s+push\b/;

// curl|sh — fetching code and executing it in one breath.
const REMOTE_EXEC = /\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da)?sh|python\d*|perl|ruby|node)\b/i;

// Downloading a file to a named path on disk. The path is captured so a later
// chmod/exec can be correlated against THAT file rather than any file.
const DOWNLOAD_TO_PATH =
  /\bcurl\b[^\n]{0,300}?(?:-o|--output)\s+(['"]?)([^\s'"]+)\1|\bwget\b[^\n]{0,200}?-O\s+(['"]?)([^\s'"]+)\3/i;

// Anti-forensics: erasing the record of what just happened.
const HISTORY_WIPE =
  /\bhistory\s+-c\b|\brm\s+[^\n]{0,80}\.(?:bash|zsh)_history\b|>\s*~?\/?\.(?:bash|zsh)_history\b|\bunset\s+HISTFILE\b|\bHISTFILE=\/dev\/null\b|\brm\s+[^\n]{0,80}\.claude\/(?:history|projects)\b/;

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

type FactKind =
  | 'secret-read'
  | 'cred-env-sweep'
  | 'payload-egress'
  | 'archive-create'
  | 'git-hook-write'
  | 'lifecycle-write'
  | 'install-run'
  | 'git-runs-hooks'
  | 'persistence-write'
  | 'agent-config-write'
  | 'remote-exec'
  | 'download'
  | 'chmod-exec'
  | 'git-remote-repoint'
  | 'git-push'
  | 'history-wipe';

interface Fact {
  kind: FactKind;
  spanId: string;
  /** Tool name of the span this fact came from, carried into the chain. */
  span: string;
  tsMs: number;
  /** Excerpt shown in the chain. */
  detail: string;
  /**
   * Optional correlation key. Used where the identity of the *thing* matters
   * and not merely the kind — a downloaded path that must match the path later
   * executed, or a distinct secret file for the sweep rule.
   */
  key?: string;
}

/** Human-facing name for each step, used when the chain is rendered. */
const STEP_LABEL: Record<FactKind, string> = {
  'secret-read':        'credential read',
  'cred-env-sweep':     'environment credential sweep',
  'payload-egress':     'outbound upload',
  'archive-create':     'archive created',
  'git-hook-write':     'git hook written',
  'lifecycle-write':    'npm lifecycle script written',
  'install-run':        'package install/publish',
  'git-runs-hooks':     'git operation (runs hooks)',
  'persistence-write':  'startup/persistence file written',
  'agent-config-write': 'agent config written',
  'remote-exec':        'remote script piped to interpreter',
  'download':           'file downloaded',
  'chmod-exec':         'downloaded file made executable / run',
  'git-remote-repoint': 'git remote repointed',
  'git-push':           'git push',
  'history-wipe':       'shell/agent history erased',
};

function excerpt(s: string): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > DETAIL_MAX ? flat.slice(0, DETAIL_MAX) + '…' : flat;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

// Heredoc opener: `<<EOF`, `<<-'EOF'`, `<< "PY"`. The body that follows, up to a
// line holding only the delimiter, is stdin DATA — a file being authored, a
// commit message, a test fixture — and must not be read as shell.
const HEREDOC_OPEN = /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/g;
/** Commands longer than this are truncated before scanning, to bound the work. */
const CMD_SCAN_MAX = 8_000;

/**
 * Strip heredoc bodies from a shell command so only the shell itself is
 * classified.
 *
 * WHY this matters more than it looks: agents write files by heredoc constantly,
 * and those files are frequently detection tests, fixtures and scripts full of
 * exactly the strings these rules look for. Before this, a session that authored
 * a test corpus produced a chain claiming an SSH key had been read and uploaded.
 */
export function stripHeredocs(cmd: string): string {
  const src = cmd.length > CMD_SCAN_MAX ? cmd.slice(0, CMD_SCAN_MAX) : cmd;
  if (!src.includes('<<')) return src;

  let out = '';
  let cursor = 0;
  HEREDOC_OPEN.lastIndex = 0;
  let open: RegExpExecArray | null;
  while ((open = HEREDOC_OPEN.exec(src)) !== null) {
    if (open.index < cursor) continue; // opener sat inside a body we already ate
    const bodyStart = src.indexOf('\n', HEREDOC_OPEN.lastIndex);
    if (bodyStart === -1) break;
    const bodyEnd = findTerminator(src, bodyStart + 1, open[2]);
    out += src.slice(cursor, HEREDOC_OPEN.lastIndex);
    cursor = bodyEnd;
    HEREDOC_OPEN.lastIndex = bodyEnd;
  }
  return cursor === 0 ? src : out + src.slice(cursor);
}

/**
 * Index of the newline that ends the line closing a heredoc opened with
 * `delim`, or `src.length` when the heredoc is never terminated (an
 * unterminated heredoc runs to the end of the command, so the rest is dropped).
 *
 * WHY this is a string comparison and not a regex. The delimiter is read out of
 * the command being analysed, which is untrusted input — this module exists to
 * inspect exactly the commands an attacker gets to write. Building
 * `new RegExp('^\\s*' + delim + '\\s*$', 'm')` put that untrusted text into
 * regex SOURCE, and the only thing standing between it and a metacharacter was
 * the character class inside HEREDOC_OPEN thirty lines away, where nothing said
 * so. Widen that opener to accept the terminators bash actually allows
 * (`<<'EOF-1'`, `<<\EOF`, `<<'E O F'` — all of which it currently misses) and
 * the hole opens with it; the enforcement hook's equivalent opener already
 * accepts an arbitrary quoted delimiter.
 *
 * The pattern was never anything but an anchored literal, so a per-line
 * comparison is the same test with no source to inject into, and it drops a
 * regex compile per heredoc opener off the ingest hot path. This is also the
 * shape the hook's stripQuotedHeredocBodies already uses, so the two now reason
 * the same way.
 *
 * Matching on the trimmed line is deliberately more permissive than POSIX, for
 * the same reason the hook gives: erring that way ends the body EARLY, so more
 * text is classified as shell rather than less.
 */
export function findTerminator(src: string, from: number, delim: string): number {
  let i = from;
  while (i <= src.length) {
    const nl = src.indexOf('\n', i);
    const lineEnd = nl === -1 ? src.length : nl;
    if (src.slice(i, lineEnd).trim() === delim) return lineEnd;
    if (nl === -1) break;
    i = nl + 1; // strictly increasing, so this stays one linear pass
  }
  return src.length;
}

/** Is the destination of this egress command off this machine and off the LAN? */
function egressIsExternal(cmd: string): boolean {
  const m = EGRESS_HOST.exec(cmd);
  if (!m) return false; // no resolvable destination — do not guess, stay quiet
  const host = m[1] ?? m[2] ?? m[3] ?? '';
  if (!host) return false;
  // A shell variable as the host (`$ENDPOINT`) is unknowable here; treat it as
  // external, because that is exactly how a real exfil line is written.
  if (host.startsWith('$')) return true;
  return !LOCAL_HOST.test(host);
}

/**
 * Classify one span into zero or more facts.
 *
 * Kept allocation-light: the common case returns the shared empty array.
 */
const NO_FACTS: readonly Fact[] = [];

export function classify(input: SequenceInput): readonly Fact[] {
  if (!CARRIER_TOOLS.has(input.name)) return NO_FACTS;

  const facts: Fact[] = [];
  const add = (kind: FactKind, detail: string, key?: string) =>
    facts.push({ kind, spanId: input.spanId, span: input.name, tsMs: input.tsMs, detail: excerpt(detail), key });

  const filePath = str(input.attrs['file_path']);
  const rawCmd   = str(input.attrs['command']);
  const cmd      = rawCmd ? stripHeredocs(rawCmd) : '';

  // ── file-tool facts ──────────────────────────────────────────────────────
  if (filePath) {
    if (input.name === 'Read') {
      if (SECRET_PATH.test(filePath) && !TEMPLATE_PATH.test(filePath)) {
        add('secret-read', filePath, filePath);
      }
    } else {
      // Write / Edit / MultiEdit / NotebookEdit
      if (GIT_HOOK_PATH.test(filePath))     add('git-hook-write', filePath, filePath);
      if (PERSISTENCE_PATH.test(filePath))  add('persistence-write', filePath, filePath);
      if (AGENT_CONFIG_PATH.test(filePath)) add('agent-config-write', filePath, filePath);
      if (PACKAGE_JSON.test(filePath)) {
        const body = str(input.attrs['content']) || str(input.attrs['new_string']);
        if (LIFECYCLE_SCRIPT.test(body)) add('lifecycle-write', filePath, filePath);
      }
    }
    if (!cmd) return facts.length ? facts : NO_FACTS;
  }

  if (!cmd) return facts.length ? facts : NO_FACTS;

  // ── shell facts ──────────────────────────────────────────────────────────
  if (KEYCHAIN_READ.test(cmd)) {
    add('secret-read', cmd, 'keychain');
  } else {
    // Scan command segments so the secret path and the reader must belong to
    // the same command, not merely the same line.
    SHELL_READ_SEGMENT.lastIndex = 0;
    let seg: RegExpExecArray | null;
    while ((seg = SHELL_READ_SEGMENT.exec(cmd)) !== null) {
      const text = seg[0];
      if (SECRET_PATH.test(text) && !TEMPLATE_PATH.test(text)) {
        add('secret-read', text, text);
        break;
      }
    }
  }

  if (CRED_ENV_SWEEP.test(cmd)) add('cred-env-sweep', cmd);

  if (PAYLOAD_EGRESS.test(cmd) && egressIsExternal(cmd)) add('payload-egress', cmd);

  // Staging a bundle. Only CREATION can precede an upload — `tar -x` (extract)
  // and a bare `.tar.gz` filename are not it, so the create flag must be the
  // first token after the verb.
  if (/\btar\s+(?:--create\b|-{0,2}[a-zA-Z]{0,4}c[a-zA-Z]{0,4}\s)|\bzip\s+-\w*r\b|\b7z\s+a\b/i.test(cmd)) {
    add('archive-create', cmd);
  }

  if (INSTALL_OR_PUBLISH.test(cmd))  add('install-run', cmd);
  if (GIT_RUNS_HOOKS.test(cmd))      add('git-runs-hooks', cmd);
  if (GIT_REMOTE_REPOINT.test(cmd))  add('git-remote-repoint', cmd);
  if (GIT_PUSH.test(cmd))            add('git-push', cmd);
  if (REMOTE_EXEC.test(cmd))         add('remote-exec', cmd);
  if (HISTORY_WIPE.test(cmd))        add('history-wipe', cmd);

  const dl = DOWNLOAD_TO_PATH.exec(cmd);
  if (dl) {
    const target = dl[2] ?? dl[4] ?? '';
    if (target) add('download', cmd, basename(target));
  }
  // Making something executable, or invoking it as a program in its own right.
  // The key is the file NAME, so this only ever pairs with a download of that
  // same name.
  //
  // `node foo.mjs` / `python foo.py` are deliberately NOT here. Running a script
  // through its interpreter is what an agent does thousands of times a session,
  // and including it produced 6,200 facts that could only ever pair with a
  // download of an identically-named file. `chmod +x` and a bare `./thing` are
  // the forms that actually characterise "fetched, then run".
  const chm = /\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2})\s+(['"]?)([^\s'"]+)\1/.exec(cmd);
  if (chm) add('chmod-exec', cmd, basename(chm[2]));
  const run = /(?:^|[\s;&|(])\.\/([^\s'"]+)/.exec(cmd);
  if (run) add('chmod-exec', cmd, basename(run[1]));

  return facts.length ? facts : NO_FACTS;
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

interface SequenceRule {
  label: string;
  severity: Severity;
  /** Kinds that can open the chain. Any one of them satisfies the antecedent. */
  from: readonly FactKind[];
  /** The kind that closes the chain and fires the rule. */
  to: FactKind;
  /** Maximum seconds between the opening step and the closing one. */
  windowSec: number;
  /**
   * When set, the opening and closing facts must share a correlation key. Used
   * where the identity of the artefact matters (download → run THAT file).
   */
  sameKey?: boolean;
  /** Distinct opening facts required before the rule may fire. */
  minDistinct?: number;
  /** Plain-language statement, carried into the finding for the operator. */
  statement: string;
}

export const SEQUENCE_RULES: readonly SequenceRule[] = [
  // 1 ── The Nx "s1ngularity" shape, stated exactly.
  //
  // FALSE POSITIVES: an agent reading `.env` and then calling an API is
  // everyday work. Three things keep this quiet. Templates (`.env.example`)
  // are excluded, because reading documentation is not reading a credential.
  // The egress must carry a BODY — the overwhelmingly common follow-up to a
  // config read is a GET (docs, a health check, a WebFetch), which never
  // matches. And the destination must be off-box: a developer POSTing to their
  // own `127.0.0.1:3000` or a `.local` service is doing local integration work.
  {
    label: 'Credential read then off-box upload',
    severity: 'high',
    from: ['secret-read'],
    to: 'payload-egress',
    windowSec: 300,
    statement: 'A live credential file or keychain entry was read, then a request carrying a body was sent to an external host within five minutes.',
  },

  // 2 ── Same shape, harvested from the environment instead of the filesystem.
  //
  // FALSE POSITIVES: `env | grep` alone is a legitimate debugging move and is
  // NOT enough — the sweep must be followed by an off-box upload. Listing
  // variable NAMES (`vercel env ls`) does not match, because the sweep pattern
  // requires piping the environment itself through a credential-name filter.
  {
    label: 'Environment credential sweep then off-box upload',
    severity: 'high',
    from: ['cred-env-sweep'],
    to: 'payload-egress',
    windowSec: 300,
    statement: 'The process environment was filtered for credential-shaped variable names, then a request carrying a body was sent to an external host.',
  },

  // 3 ── Stage-then-ship: bundle the working tree, then upload the bundle.
  //
  // FALSE POSITIVES: building a release artefact and uploading it is a real
  // workflow. It stays quiet because publishing goes through `npm publish` /
  // `gh release` / CI, not a hand-rolled `curl --data-binary`; and because the
  // destination must be external, so pushing a tarball to a local registry or
  // dev server does not match.
  {
    label: 'Archive staged then uploaded off-box',
    severity: 'high',
    from: ['archive-create'],
    to: 'payload-egress',
    windowSec: 600,
    statement: 'A tar/zip archive was created, then a request carrying a body was sent to an external host within ten minutes.',
  },

  // 4 ── Execution smuggled into the repository itself.
  //
  // FALSE POSITIVES: hook managers (husky, lefthook, pre-commit) write to
  // `.husky/` or `.pre-commit-config.yaml`, not to `.git/hooks/` directly, and
  // git's own `.sample` stubs are excluded. Over the entire local history this
  // antecedent occurred once.
  {
    label: 'Git hook installed then triggered',
    severity: 'high',
    from: ['git-hook-write'],
    to: 'git-runs-hooks',
    windowSec: 900,
    statement: 'A git hook script was written, then a git operation that executes hooks ran within fifteen minutes.',
  },

  // 5 ── The supply-chain foothold: code that runs on `npm install`.
  //
  // FALSE POSITIVES: editing `package.json` and re-installing is constant, so
  // the write must specifically introduce a LIFECYCLE key (preinstall /
  // install / postinstall / prepare / prepublish). Adding a dependency or a
  // normal `scripts.test` entry does not match. Over the local history
  // lifecycle keys were written six times and never once followed by an
  // install inside the window.
  {
    label: 'npm lifecycle script added then executed',
    severity: 'high',
    from: ['lifecycle-write'],
    to: 'install-run',
    windowSec: 600,
    statement: 'An install-time lifecycle script was added to package.json, then an install or publish that executes it ran within ten minutes.',
  },

  // 6 ── Download, make runnable, run — correlated on the FILE, not the kind.
  //
  // FALSE POSITIVES: agents download and run things all day (installers, test
  // fixtures, CLIs). Requiring the executed basename to equal the downloaded
  // basename is what makes this precise; without that key the same pattern
  // fired 177 times over the local history, with it, it collapses to the cases
  // where the very file just fetched is the file being executed.
  {
    label: 'Downloaded file made executable and run',
    severity: 'high',
    from: ['download'],
    to: 'chmod-exec',
    windowSec: 600,
    sameKey: true,
    statement: 'A file was downloaded to disk, then that same file was made executable or invoked within ten minutes.',
  },

  // 7 ── Fetch-and-run followed by a foothold that survives the session.
  //
  // FALSE POSITIVES: `curl | sh` on its own is already a stateless rule and is
  // not this rule's business. What this adds is the SECOND step — a shell rc,
  // LaunchAgent, cron entry or authorized_keys written afterwards. Installing a
  // toolchain (`brew`, `rustup`) can append to a shell rc, which is why the
  // severity is high but the window is tight and the antecedent must be a
  // piped-to-interpreter fetch rather than any install.
  {
    label: 'Remote script executed then persistence installed',
    severity: 'high',
    from: ['remote-exec'],
    to: 'persistence-write',
    windowSec: 900,
    statement: 'A remotely-fetched script was piped into an interpreter, then a startup, cron, LaunchAgent or authorized_keys file was written within fifteen minutes.',
  },

  // 8 ── Harvest, then make sure you keep harvesting.
  //
  // FALSE POSITIVES: writing `~/.zshenv` is something a developer does
  // occasionally, and reading `.env` is something an agent does constantly —
  // but the two inside fifteen minutes of each other is not a workflow anyone
  // has. Agent-config writes are included as a target because rewriting
  // `~/.claude/settings.json` hooks or `.mcp.json` turns the developer's own
  // agent into the delivery mechanism.
  {
    label: 'Credential access then persistence installed',
    severity: 'high',
    from: ['secret-read', 'cred-env-sweep'],
    to: 'persistence-write',
    windowSec: 900,
    statement: 'A live credential was read, then a startup, cron, LaunchAgent or authorized_keys file was written within fifteen minutes.',
  },

  // 9 ── Source exfiltration by repointing the remote.
  //
  // FALSE POSITIVES: repointing a remote is a real, if uncommon, operation —
  // renaming a GitHub repo, moving an org. Over the local history it happened
  // three times. Requiring the push to follow inside fifteen minutes keeps it
  // to the case where the new destination is immediately fed the history.
  // Medium, not high: this is worth a look, not worth an interrupt.
  {
    label: 'Git remote repointed then pushed',
    severity: 'medium',
    from: ['git-remote-repoint'],
    to: 'git-push',
    windowSec: 900,
    statement: 'A git remote was added or repointed at a new URL, then a push to it followed within fifteen minutes.',
  },

  // 10 ── Anti-forensics. Erasing the trail right after doing something worth
  // erasing.
  //
  // FALSE POSITIVES: clearing shell history is a privacy habit, and on its own
  // it says nothing. This rule needs it to arrive within half an hour of a
  // credential read, an off-box upload or a fetch-and-run. Over the local
  // history a history wipe occurred once, and not in that company.
  {
    label: 'History erased after credential or egress activity',
    severity: 'high',
    from: ['secret-read', 'payload-egress', 'remote-exec'],
    to: 'history-wipe',
    windowSec: 1800,
    statement: 'Shell or agent history was erased within thirty minutes of a credential read, an off-box upload or a remotely-fetched script being executed.',
  },
];

/** Plain-language statement for a label, for anything that wants to explain a finding. */
export const RULE_STATEMENTS: ReadonlyMap<string, string> = new Map(
  SEQUENCE_RULES.map((r) => [r.label, r.statement]),
);

// Kinds that only ever CLOSE a chain and never open one. They are evaluated on
// arrival and then thrown away instead of being retained, which is what keeps
// the per-trace fact ring small: `git commit`, `npm install` and `./script` are
// common, and storing every one of them would evict the rare opening facts that
// are the whole point of the ring.
const OPENING_KINDS: ReadonlySet<FactKind> = new Set(SEQUENCE_RULES.flatMap((r) => r.from));

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

interface TraceState {
  facts: Fact[];
  /** label → last fire time, so one session does not emit the same chain twice. */
  fired: Map<string, number>;
}

export class SequenceEngine {
  private readonly traces = new Map<string, TraceState>();
  private readonly maxTraces: number;

  constructor(maxTraces: number = MAX_TRACES) {
    this.maxTraces = Math.max(1, maxTraces);
  }

  /** Traces currently held. Exposed so a test can assert the bound. */
  get size(): number {
    return this.traces.size;
  }

  /** Total facts retained across all traces. Exposed for the memory-bound test. */
  get factCount(): number {
    let n = 0;
    for (const t of this.traces.values()) n += t.facts.length;
    return n;
  }

  reset(): void {
    this.traces.clear();
  }

  /**
   * Feed one span. Returns any findings it completes — usually none.
   *
   * Never throws: a malformed span must not be able to stop ingestion.
   */
  observe(input: SequenceInput): SequenceFinding[] {
    let facts: readonly Fact[];
    try {
      facts = classify(input);
    } catch {
      return [];
    }
    if (facts.length === 0) return [];

    const state = this.touch(input.traceId);

    // Drop facts that can no longer satisfy any rule. Doing this on arrival
    // keeps a long-running session from carrying an hour of dead history.
    const cutoff = input.tsMs - MAX_FACT_AGE_MS;
    if (state.facts.length > 0 && state.facts[0].tsMs < cutoff) {
      state.facts = state.facts.filter((f) => f.tsMs >= cutoff);
    }

    const findings: SequenceFinding[] = [];
    for (const fact of facts) {
      for (const rule of SEQUENCE_RULES) {
        if (rule.to !== fact.kind) continue;
        const last = state.fired.get(rule.label);
        if (last !== undefined && input.tsMs - last < RULE_COOLDOWN_MS) continue;

        const finding = this.match(rule, state, fact);
        if (finding) {
          state.fired.set(rule.label, input.tsMs);
          findings.push(finding);
        }
      }
      if (OPENING_KINDS.has(fact.kind)) state.facts.push(fact);
    }

    // Bounded per trace: keep the most recent MAX_FACTS.
    if (state.facts.length > MAX_FACTS) {
      state.facts.splice(0, state.facts.length - MAX_FACTS);
    }

    return findings;
  }

  private match(rule: SequenceRule, state: TraceState, closing: Fact): SequenceFinding | null {
    const windowMs = rule.windowSec * 1000;
    const opening: Fact[] = [];
    const seenKeys = new Set<string>();

    for (const f of state.facts) {
      if (!rule.from.includes(f.kind)) continue;
      // A sequence needs two SPANS. Two facts extracted from one command are a
      // single-string match, which the stateless rule set already owns — and
      // treating them as a chain manufactured findings out of long one-liners.
      if (f.spanId === closing.spanId) continue;
      const dt = closing.tsMs - f.tsMs;
      if (dt < 0 || dt > windowMs) continue;
      if (rule.sameKey && (!f.key || !closing.key || f.key !== closing.key)) continue;
      opening.push(f);
      seenKeys.add(f.key ?? f.detail);
    }

    if (opening.length === 0) return null;
    if (rule.minDistinct !== undefined && seenKeys.size < rule.minDistinct) return null;

    // The chain is the point of this engine: show the actual spans, in order,
    // with timestamps, so the finding can be judged without opening the session.
    // Keep only the FIRST opening step when several matched — the earliest is
    // the one that establishes intent, and a five-line chain reads worse than a
    // two-line one.
    const first = opening[0];
    const chain: ChainStep[] = [first, closing].map((f) => ({
      step: STEP_LABEL[f.kind],
      spanId: f.spanId,
      ts: new Date(f.tsMs).toISOString(),
      span: f.span,
      detail: f.detail,
    }));

    return {
      label: rule.label,
      severity: rule.severity,
      elapsedSec: Math.round((closing.tsMs - first.tsMs) / 1000),
      chain,
    };
  }

  /** Fetch (or create) trace state, enforcing the FIFO bound. */
  private touch(traceId: string): TraceState {
    const existing = this.traces.get(traceId);
    if (existing) return existing;

    const created: TraceState = { facts: [], fired: new Map() };
    this.traces.set(traceId, created);
    // Same bounded-FIFO eviction as traceRepoCache: a traceId on an inbound
    // OTLP span is attacker-controlled, so the map must have a ceiling.
    while (this.traces.size > this.maxTraces) {
      const oldest = this.traces.keys().next().value;
      if (oldest === undefined) break;
      this.traces.delete(oldest);
    }
    return created;
  }
}

/**
 * Render a finding as the one-line-per-step chain an operator reads.
 *
 * This is what a sequence alert has that a regex alert does not: the alert text
 * IS the evidence. `matchedText` on the alert row carries this string, so the
 * existing alert UI shows the whole chain with no changes of its own.
 */
export function renderChain(finding: SequenceFinding): string {
  const steps = finding.chain
    .map((s, i) => `${i + 1}. ${s.ts}  [${s.span} ${s.spanId.slice(0, 12)}]  ${s.step}: ${s.detail}`)
    .join('\n');
  return `${steps}\n(${finding.chain.length} steps over ${finding.elapsedSec}s)`;
}
