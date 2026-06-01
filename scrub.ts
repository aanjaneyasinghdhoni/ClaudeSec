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

const SENSITIVE_KEY_RE =
  /^(authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|passwd|pwd|bearer|private[_-]?key|client[_-]?secret|session|csrf)$/i;

const EMAIL_RE =
  /([A-Za-z0-9_.+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;

type SecretPattern = {
  re:          RegExp;
  replacement: string | ((...args: string[]) => string);
};

const SECRET_PATTERNS: SecretPattern[] = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[redacted:private-key]' },

  { re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, replacement: '[redacted:jwt]' },

  { re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{16,}/g, replacement: 'https://hooks.slack.com/services/[redacted:slack-webhook]' },
  { re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]{6,}\/[A-Za-z0-9_-]{16,}/g, replacement: 'https://discord.com/api/webhooks/[redacted:discord-webhook]' },
  { re: /https:\/\/(?:api\.telegram\.org\/)?bot[0-9]{6,}:[A-Za-z0-9_-]{30,}/g, replacement: '[redacted:telegram-webhook]' },

  { re: /sk-ant-[A-Za-z0-9_-]{20,}/g, replacement: 'sk-ant-‹redacted›' },
  { re: /(?<![A-Za-z0-9_])sk-[A-Za-z0-9]{20,}/g, replacement: 'sk-‹redacted›' },

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

  { re: /(authorization)(\s*[:=]\s*['"]?)((?:bearer|basic|token|digest)\s+)?\S+/gi, replacement: (_m, k, sep, scheme) => `${k}${sep}${scheme ? scheme : ''}‹redacted›` },
  { re: /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, replacement: 'Bearer ‹redacted›' },

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
