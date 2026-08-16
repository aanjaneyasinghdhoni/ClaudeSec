// scrub.ts
//
// Redacts personal / machine-specific information from OpenTelemetry span
// attributes before they are persisted, broadcast, or exported.  Preserves
// the attribute shape (keys, types, ordering) so that downstream dashboards,
// FTS search, and any OTLP forwarding target keep working unchanged.
//
// Enabled by default.  Set CLAUDESEC_DISABLE_SCRUB=1 to forward raw data.

import os from 'os';

export interface ScrubOptions {
  enabled:        boolean;
  homeDir:        string;
  osUsername:     string;
  honeytokens:    string[];
}

export interface ScrubHit {
  honeytoken: string;
  key:        string;
}

// Words that name a credential.  Shared by the two name-based checks below so
// the pair cannot drift apart: SENSITIVE_KEY_RE matches a *whole* attribute
// key, while isSensitiveEnvName() matches a word *inside* a compound shell
// variable name (MT5_PASSWORD, PGPASSWORD, SUPABASE_SECRET_KEY).
//
// `token` is deliberately not in here — it needs a "not TOKENS" guard in the
// compound case (MAX_TOKENS is a budget, not a credential) that would be
// pointless noise in the exact-key case.
const CREDENTIAL_WORDS =
  'password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|secret[_-]?key|' +
  'private[_-]?key|signing[_-]?key|encryption[_-]?key|access[_-]?token|' +
  'refresh[_-]?token|id[_-]?token|client[_-]?secret|credentials?';

const SENSITIVE_KEY_RE = new RegExp(
  `^(?:${CREDENTIAL_WORDS}|token|authorization|cookie|set-cookie|x-api-key|pwd|bearer|session|csrf)$`,
  'i',
);

// The compound form.  Deliberately NARROWER than SENSITIVE_KEY_RE, because a
// word that is safe to match as an entire key is not safe to match as a
// substring of one:
//   • no bare KEY      — SORT_KEY / CACHE_KEY / PARTITION_KEY are not secrets
//   • no SESSION, AUTH — SESSION_TIMEOUT and NEXTAUTH_URL are ordinary config,
//                        and the credential-carrying spellings (SESSION_SECRET,
//                        AUTH_TOKEN) are already covered by SECRET / TOKEN
//   • TOKEN but not TOKENS — MAX_TOKENS is a token budget
const SENSITIVE_ENV_NAME_RE = new RegExp(`(?:${CREDENTIAL_WORDS}|token(?![a-z0-9]))`, 'i');

function isSensitiveEnvName(name: string): boolean {
  // MYSQL_PWD and friends hold a password; a bare PWD is the working directory.
  if (name !== 'PWD' && /(?:^|_)PWD(?:_|$)/.test(name)) return true;
  return SENSITIVE_ENV_NAME_RE.test(name);
}

// The leading lookbehind is a performance guard, not a filter. Without it the
// local-part `+` can start at every offset, so a long run of local-part
// characters that never reaches an `@` — a base64 blob, a minified bundle, a
// stack trace — costs O(n²). Requiring a boundary leaves exactly one viable
// start per run and makes the scan linear. It changes no result: the greedy
// leftmost match already began at that boundary.
const EMAIL_RE =
  /(?<![A-Za-z0-9_.+-])([A-Za-z0-9_.+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;

type SecretPattern = {
  re:          RegExp;
  replacement: string | ((...args: string[]) => string);
};

// ── Inline environment assignments ─────────────────────────────────────────
//
// `docker run -e MT5_PASSWORD='…'`, `export GH_TOKEN=…`, `--env API_KEY=…`,
// `PGPASSWORD=… psql …`.  All of those are the same shape once you stop caring
// about the flag in front: NAME=value at a token boundary.
//
// A password has no format to match on, so this redacts on the strength of the
// NAME instead.  The name is preserved — `-e MT5_PASSWORD=‹redacted›` tells an
// operator which credential was passed, which "the argument vanished" does not,
// and it keeps the stored text matching the rule that flagged the span in the
// first place so the match-highlight endpoint still resolves.
//
// The name must be UPPER_SNAKE.  That is the shell and Docker convention every
// real form uses, and it keeps the rule away from camelCase source code
// (`<Form apiKey={apiKey} />`), where the "value" is an identifier and
// redacting it would destroy context while protecting nothing.
const ENV_ASSIGNMENT_RE =
  /(?<![A-Za-z0-9_$])([A-Z][A-Z0-9_]{1,63})=('[^'\n]{0,512}'|"[^"\n]{0,512}"|[^\s'"\n;&|]{1,512}|'[^'\n]{0,512}|"[^"\n]{0,512})/g;

/**
 * Values that are not worth redacting.  A variable *reference* holds no secret
 * and blanking it only destroys context; a placeholder is what documentation
 * and `.env.example` files are made of, and redacting those would bury the real
 * hits in noise.  Already-redacted values are skipped too, so the scrubber
 * stays idempotent and the more specific vendor placeholder produced earlier in
 * the pass (`GH_TOKEN=[redacted:github-token]`, which says *which kind* of
 * credential it was) survives this rule.
 *
 * Each test is anchored on the whole value, so a password that merely *starts*
 * with `$` or `<` is still redacted.
 */
function isPlaceholderValue(v: string): boolean {
  if (v.length === 0) return true;
  if (v.includes('‹redacted›') || v.includes('[redacted:') || v.includes('***')) return true;

  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]{0,64}\}?$/.test(v)) return true;  // $VAR, ${VAR}
  if (/^\$\([^)\n]{0,128}\)$/.test(v))                 return true;  // $(cmd)
  if (/^`[^`\n]{0,128}`$/.test(v))                     return true;  // `cmd`
  if (/^%[A-Za-z_][A-Za-z0-9_]{0,64}%$/.test(v))       return true;  // %VAR% (cmd.exe)
  if (/^\{[^}\n]{0,128}\}$/.test(v))                   return true;  // {expr}
  if (/^<[^>\n]{0,128}>?$/.test(v))                    return true;  // <your-token-here>
  if (/^[^A-Za-z0-9]{1,64}$/.test(v))                  return true;  // ***, ---, …

  return /^(?:changeme|change[_-]?me|change[_-]?this|replace[_-]?me|placeholder|redacted|todo|tbd|none|null|undefined|x{3,}|your[_-]?[a-z0-9_-]{0,32}|true|false|yes|no|on|off|enabled|disabled)$/i
    .test(v);
}

function redactEnvAssignment(_m: string, name: string, rawValue: string): string {
  const original = `${name}=${rawValue}`;
  if (!isSensitiveEnvName(name)) return original;

  // Keep the quoting so the result still reads as a runnable command.
  const first  = rawValue[0];
  const quote  = rawValue.length >= 2 && (first === "'" || first === '"')
                 && rawValue[rawValue.length - 1] === first ? first : '';
  const value  = quote ? rawValue.slice(1, -1) : rawValue;

  if (isPlaceholderValue(value)) return original;
  return `${name}=${quote}‹redacted›${quote}`;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[redacted:private-key]' },
  // Fallback for a key block the rule above cannot close: agent output is
  // routinely truncated mid-key, and a 4096-bit RSA body can also overrun the
  // bound. Either way the header alone is enough for the detector to report a
  // finding, so the scrubber must be able to act on the header alone too.
  //
  // The body is consumed with a single base64+whitespace class — one flat
  // quantifier, no nesting, so it stays linear. It deliberately runs to the end
  // of the base64 run rather than to a length cap: the tail of an RSA key holds
  // the prime factors, so a partial redaction is not a redaction. The cost is
  // that unpunctuated prose immediately following a bare BEGIN header is eaten
  // too, which is the right way round to be wrong.
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]*/g, replacement: '[redacted:private-key]' },

  { re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, replacement: '[redacted:jwt]' },

  { re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{16,}/g, replacement: 'https://hooks.slack.com/services/[redacted:slack-webhook]' },
  { re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]{6,}\/[A-Za-z0-9_-]{16,}/g, replacement: 'https://discord.com/api/webhooks/[redacted:discord-webhook]' },
  // The scheme is optional: the bot token is the credential, and it travels on
  // its own in config files and `-d` payloads as often as it does inside a URL.
  // Must stay in step with the `telegram-token` detect pattern below.
  { re: /(?:https:\/\/)?(?:api\.telegram\.org\/)?bot[0-9]{6,}:[A-Za-z0-9_-]{30,}/g, replacement: '[redacted:telegram-webhook]' },

  { re: /sk-ant-[A-Za-z0-9_-]{20,}/g, replacement: 'sk-ant-‹redacted›' },
  // `proj-` is spelled out because the tail class has no hyphen, so a project
  // key would otherwise fall four characters short of the 20-char floor.
  { re: /(?<![A-Za-z0-9_])sk-(?:proj-)?[A-Za-z0-9]{20,}/g, replacement: 'sk-‹redacted›' },

  { re: /A(?:KIA|SIA|GPA|IDA|ROA)[0-9A-Z]{16}/g, replacement: '[redacted:aws-akia]' },
  { re: /(aws_secret_access_key)\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}['"]?/gi, replacement: (_m, k) => `${k}=‹redacted›` },

  { re: /gh[posru]_[A-Za-z0-9]{36,}/g, replacement: '[redacted:github-token]' },
  { re: /glpat-[A-Za-z0-9_-]{20,}/g, replacement: 'glpat-‹redacted›' },

  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, replacement: 'xox-‹redacted›' },

  { re: /AIza[0-9A-Za-z_-]{35}/g, replacement: '[redacted:google-api]' },
  { re: /ya29\.[0-9A-Za-z_-]+/g, replacement: 'ya29.‹redacted›' },

  { re: /(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{20,}/g, replacement: '[redacted:stripe]' },

  { re: /SK[0-9a-fA-F]{32}/g, replacement: '[redacted:twilio-key]' },
  { re: /AC[0-9a-fA-F]{32}/g, replacement: '[redacted:twilio-sid]' },
  { re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, replacement: '[redacted:sendgrid]' },

  { re: /npm_[A-Za-z0-9]{36}/g, replacement: '[redacted:npm-token]' },
  { re: /pypi-[A-Za-z0-9_-]{16,}/g, replacement: 'pypi-‹redacted›' },
  { re: /dop_v1_[a-f0-9]{64}/g, replacement: '[redacted:digitalocean]' },
  { re: /key-[0-9a-f]{32}/g, replacement: '[redacted:mailgun]' },

  // Database connection strings with inline credentials — redact the
  // `user:password@` portion so a dumped .env never persists live DB creds.
  // Bounded character classes (no `.*`) keep these linear-time / non-backtracking.
  { re: /(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqp|amqps):\/\/[^\s:/@]{1,128}:[^\s:/@]{1,256}@/gi, replacement: (_m, scheme) => `${scheme}://‹redacted›:‹redacted›@` },

  { re: /(authorization)(\s*[:=]\s*['"]?)((?:bearer|basic|token|digest)\s+)?\S+/gi, replacement: (_m, k, sep, scheme) => `${k}${sep}${scheme ? scheme : ''}‹redacted›` },
  { re: /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, replacement: 'Bearer ‹redacted›' },

  // Runs before the generic assignment rule below so the key-aware, quote-
  // preserving form wins; anything it redacts is then skipped by that rule,
  // whose 12-character floor the placeholder sits under.
  { re: ENV_ASSIGNMENT_RE, replacement: redactEnvAssignment },

  { re: /(api[_-]?key|access[_-]?token|client[_-]?secret|secret|password|passwd)(\s*[=:]\s*)['"]?[^\s'"]{12,}['"]?/gi, replacement: (_m, k, sep) => `${k}${sep}‹redacted›` },
];

// Inline value redactors.  Each runs in order; order matters because earlier
// rules make the string easier to reason about for later ones.
function redactString(s: string, opts: ScrubOptions): string {
  if (typeof s !== 'string' || s.length === 0) return s;
  let out = s;

  // Platform-specific home directories
  out = out.replace(/\/Users\/[^\/\\\s"':]+/g, '/Users/***');
  out = out.replace(/\/home\/[^\/\\\s"':]+/g, '/home/***');
  out = out.replace(/C:\\\\Users\\\\[^\\\\\s"':]+/gi, 'C:\\Users\\***');
  out = out.replace(/C:\\Users\\[^\\\s"':]+/gi, 'C:\\Users\\***');

  // Current process $HOME (covers shells like /var/root, /Users/realname, /root)
  if (opts.homeDir && opts.homeDir !== '/' && opts.homeDir.length > 2) {
    const re = new RegExp(escapeRegex(opts.homeDir), 'g');
    out = out.replace(re, '~');
  }

  // Host OS username
  if (opts.osUsername && opts.osUsername.length > 2) {
    const re = new RegExp(`\\b${escapeRegex(opts.osUsername)}\\b`, 'g');
    out = out.replace(re, '***');
  }

  // Email addresses — keep domain for debugging, mask local part
  out = out.replace(EMAIL_RE, (_m, _local, domain) => `***@${domain}`);

  for (const { re, replacement } of SECRET_PATTERNS) {
    out = out.replace(re, replacement as (substring: string, ...args: unknown[]) => string);
  }

  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function redactValue(key: string, value: unknown, opts: ScrubOptions): unknown {
  // Sensitive keys — completely mask regardless of value type
  if (SENSITIVE_KEY_RE.test(key)) return '***';

  if (typeof value === 'string') return redactString(value, opts);
  if (Array.isArray(value))      return value.map(v => redactValue(key, v, opts));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(k, v, opts);
    }
    return out;
  }
  return value;
}

/**
 * Scrub a flat attributes map in place of re-building.  Keys are preserved so
 * OTLP semantic conventions (service.name, gen_ai.*) remain queryable.
 */
export function scrubAttributes(
  attrs: Record<string, unknown>,
  opts: ScrubOptions,
): { attrs: Record<string, unknown>; honeytokenHits: ScrubHit[] } {
  if (!opts.enabled) {
    return { attrs, honeytokenHits: detectHoneytokens(attrs, opts.honeytokens) };
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(attrs)) {
    out[k] = redactValue(k, v, opts);
  }

  const honeytokenHits = detectHoneytokens(attrs, opts.honeytokens);
  return { attrs: out, honeytokenHits };
}

/**
 * Detect honeytokens in the *original* (un-scrubbed) values — they are unique
 * strings planted by the operator that should never legitimately appear in
 * span attributes, so any match is an exfiltration signal.
 */
function detectHoneytokens(
  attrs: Record<string, unknown>,
  tokens: string[],
): ScrubHit[] {
  if (tokens.length === 0) return [];
  const hits: ScrubHit[] = [];
  const walk = (key: string, v: unknown) => {
    if (typeof v === 'string') {
      for (const t of tokens) {
        if (t.length >= 6 && v.includes(t)) hits.push({ honeytoken: t, key });
      }
    } else if (Array.isArray(v)) {
      v.forEach(item => walk(key, item));
    } else if (v && typeof v === 'object') {
      for (const [nk, nv] of Object.entries(v as Record<string, unknown>)) walk(nk, nv);
    }
  };
  for (const [k, v] of Object.entries(attrs)) walk(k, v);
  return hits;
}

/**
 * Build a scrub options object from the current environment.  Safe to call
 * once at server boot — options are read-only after construction.
 */
export function loadScrubOptions(honeytokens: string[] = []): ScrubOptions {
  const disabled = process.env.CLAUDESEC_DISABLE_SCRUB === '1';
  let homeDir = '';
  let osUsername = '';
  try { homeDir = os.homedir() || ''; } catch {}
  try { osUsername = os.userInfo().username || ''; } catch {}
  return { enabled: !disabled, homeDir, osUsername, honeytokens };
}

/**
 * Apply the same rules to a free-form string — used for span.name and any
 * other raw text the ingest path writes.
 */
export function scrubText(s: string, opts: ScrubOptions): string {
  if (!opts.enabled) return s;
  return redactString(s, opts);
}

// ───────────────────────────────────────────────────────────────────────────
// Secret detection (read-only) — used by the MCP/skill static scanner.
//
// scrubAttributes/redactString REPLACE secrets with placeholders, which is the
// wrong primitive for a scanner that needs to *report* a finding (kind +
// masked excerpt). This exposes the same credential-format catalogue used by
// the scrubber as a detection-only pass so the two never drift apart.
// ───────────────────────────────────────────────────────────────────────────

export interface SecretFinding {
  kind:   string;  // e.g. 'github-token', 'aws-akia', 'private-key'
  match:  string;  // the raw matched substring
  masked: string;  // safe-to-display excerpt (most of the secret elided)
  index:  number;  // offset of the match within the scanned string
}

// Credential formats with a human-readable kind.
//
// This list and SECRET_PATTERNS describe the same credentials but answer
// different questions, so they are kept as two lists rather than derived from
// one another:
//
//   • the scrubber needs the WIDEST span it can safely delete (the whole PEM
//     block, the `user:pass@` of a URI) and a replacement that is sometimes a
//     function of the capture groups;
//   • the scanner needs the NARROWEST span that still identifies the secret,
//     because maskSecret() shows an excerpt of it to a human, plus a stable
//     `kind` string that mcpScan surfaces in findings.
//
// What must hold between them is not that the patterns look alike, but that
// **anything the scanner can name is something the scrubber removes**. That
// property is asserted directly, over the union of all scrub rules, by the
// scrub/detect parity section of tests/scrubTest.ts — which also fails if a
// kind is added here without a sample, so the two lists cannot drift silently.
//
// Deliberate, reviewed asymmetries (scrub broader than detect — no leak, only
// a missing alert):
//   • twilio-sid `AC…`, mailgun `key-…`  — scrubbed, not reported.
//   • google-oauth — the scrubber accepts any tail length, the scanner wants
//     20+ so it does not report a bare `ya29.` appearing in prose.
//   • the contextual rules (aws_secret_access_key=…, DB connection strings,
//     `Authorization:` / `Bearer`, UPPER_SNAKE env assignments, the generic
//     `api_key=` form) have no vendor format at all. They redact on the
//     strength of a NAME, which yields no `kind` worth reporting, so they
//     intentionally have no counterpart here.
const SECRET_DETECT_PATTERNS: { kind: string; re: RegExp }[] = [
  { kind: 'private-key',      re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'jwt',             re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { kind: 'slack-webhook',   re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{16,}/g },
  { kind: 'discord-webhook', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]{6,}\/[A-Za-z0-9_-]{16,}/g },
  { kind: 'telegram-token',  re: /(?:api\.telegram\.org\/)?bot[0-9]{6,}:[A-Za-z0-9_-]{30,}/g },
  { kind: 'anthropic-key',   re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'openai-key',      re: /(?<![A-Za-z0-9_])sk-(?:proj-)?[A-Za-z0-9]{20,}/g },
  { kind: 'aws-akia',        re: /A(?:KIA|SIA|GPA|IDA|ROA)[0-9A-Z]{16}/g },
  { kind: 'github-token',    re: /gh[posru]_[A-Za-z0-9]{36,}/g },
  { kind: 'gitlab-token',    re: /glpat-[A-Za-z0-9_-]{20,}/g },
  { kind: 'slack-token',     re: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'google-api-key',  re: /AIza[0-9A-Za-z_-]{35}/g },
  { kind: 'google-oauth',    re: /ya29\.[0-9A-Za-z_-]{20,}/g },
  { kind: 'stripe-key',      re: /(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{20,}/g },
  { kind: 'twilio-key',      re: /SK[0-9a-fA-F]{32}/g },
  { kind: 'sendgrid-key',    re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { kind: 'npm-token',       re: /npm_[A-Za-z0-9]{36}/g },
  { kind: 'pypi-token',      re: /pypi-[A-Za-z0-9_-]{16,}/g },
  { kind: 'digitalocean',    re: /dop_v1_[a-f0-9]{64}/g },
];

/**
 * The credential kinds this scanner can name, in declaration order.
 *
 * Exported so the parity gate can assert that every one of them has at least
 * one sample proving the scrubber removes it. Adding a pattern above without
 * adding a sample fails the test — that is the whole point of exporting it.
 */
export const SECRET_DETECT_KINDS: readonly string[] =
  SECRET_DETECT_PATTERNS.map(p => p.kind);

/** Mask a secret for display: keep a short visible prefix, elide the rest. */
export function maskSecret(s: string): string {
  if (s.length <= 8) return s.slice(0, 2) + '…';
  const head = s.slice(0, 6);
  return `${head}…[${s.length} chars]`;
}

/**
 * Find hardcoded credentials in a free-form string. Read-only — never mutates.
 * Returns every distinct match (so a config with three secrets yields three
 * findings, unlike detectSeverity which returns first-match only).
 */
export function detectSecrets(text: string): SecretFinding[] {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out: SecretFinding[] = [];
  const seen = new Set<string>();
  for (const { kind, re } of SECRET_DETECT_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 50) {
      const match = m[0];
      const dedupe = `${kind}:${match}`;
      if (!seen.has(dedupe)) {
        seen.add(dedupe);
        out.push({ kind, match, masked: maskSecret(match), index: m.index });
      }
      if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loop
    }
  }
  return out;
}
