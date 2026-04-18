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
