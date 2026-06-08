// ---------------------------------------------------------------------------
// Shared SSRF guard + address classification helpers.
//
// Extracted from server.ts so that every outbound-fetch sink (webhook sender,
// webhook retry, OTLP forward, and the optional LLM-as-judge) uses ONE copy of
// the guard. A divergent copy of a security control is worse than the feature
// it protects — keep this the single source of truth.
//
// IMPORTANT: this module has NO top-level side effects (no DB, no server, no
// timers) so it can be imported by both server.ts and standalone modules
// (llmJudge.ts) without booting a second server.
// ---------------------------------------------------------------------------

import dns from 'node:dns';
import ipaddr from 'ipaddr.js';

/** Strip the IPv4-mapped IPv6 prefix (`::ffff:127.0.0.1` → `127.0.0.1`). */
export function normalizeAddr(addr: string | undefined | null): string {
  let a = String(addr ?? '').trim();
  if (a.startsWith('::ffff:')) a = a.slice('::ffff:'.length);
  return a;
}

/** True for loopback addresses (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`). */
export function isLoopbackAddr(addr: string | undefined | null): boolean {
  const a = normalizeAddr(addr);
  return a === '127.0.0.1' || a === '::1';
}

// ---------------------------------------------------------------------------
// SSRF guard — shared by every outbound-fetch sink.  A string/regex hostname
// check is trivially bypassable (http://2130706433/ == 127.0.0.1, hex/octal
// forms, DNS rebinding where a public name resolves to a private IP, IPv6 forms
// like [::ffff:127.0.0.1]).
//
// Instead we (1) require http/https, (2) actually DNS-resolve the host — which
// also normalises decimal/hex/octal integer literals to dotted-quad — and
// (3) classify EVERY resolved address with ipaddr.js, allowing only globally
// routable `unicast` addresses.  That single allowlist transparently rejects
// loopback / private / link-local (incl. 169.254.169.254 metadata) / CGNAT /
// unique-local / multicast / reserved without enumerating each range.
//
// Because resolution happens at call time (not just at config time), this also
// defeats DNS rebinding: a host that was public when configured is re-resolved
// on every delivery and blocked the moment it points inward.
// ---------------------------------------------------------------------------

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

const dnsLookupAll = (host: string): Promise<{ address: string; family: number }[]> =>
  new Promise((resolve, reject) => {
    dns.lookup(host, { all: true }, (err, addresses) => {
      if (err) reject(err);
      else resolve(addresses as { address: string; family: number }[]);
    });
  });

/**
 * Classify a single resolved IP literal. Returns true only for globally
 * routable unicast addresses. IPv4-mapped IPv6 (::ffff:127.0.0.1) is unwrapped
 * to its embedded IPv4 before classification so a wrapped loopback is caught.
 */
export function isPublicAddress(addr: string): boolean {
  let parsed;
  try {
    parsed = ipaddr.parse(addr);
  } catch {
    return false; // unparseable → treat as unsafe
  }
  // Unwrap IPv4-mapped IPv6 so ::ffff:10.0.0.1 is classified as the v4 range.
  if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
    parsed = (parsed as ipaddr.IPv6).toIPv4Address();
  }
  return parsed.range() === 'unicast';
}

/**
 * Validate that a URL is safe to fetch (no SSRF to internal/metadata hosts).
 * Throws SsrfBlockedError on any violation. Resolves the host every call so it
 * must be invoked at fetch time to defeat DNS rebinding.
 */
export async function assertSafeFetchUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError('invalid URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfBlockedError('URL must use http or https');
  }
  // new URL() keeps the brackets on IPv6 hosts ("[::1]"); dns.lookup rejects
  // that form, so strip them before resolving / direct-parsing.
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host) throw new SsrfBlockedError('URL has no host');

  // If the host is already an IP literal, classify it directly — no DNS needed
  // (and dns.lookup on some literals can behave inconsistently).
  if (ipaddr.isValid(host)) {
    if (!isPublicAddress(host)) {
      throw new SsrfBlockedError('URL resolves to a private/internal/reserved address');
    }
    return;
  }

  // Otherwise resolve the hostname. dns.lookup also normalises integer literals
  // (decimal 2130706433, hex 0x7f000001) to dotted-quad, so those are classified
  // correctly here even though ipaddr.isValid() rejected them above.
  let addresses: { address: string; family: number }[];
  try {
    addresses = await dnsLookupAll(host);
  } catch {
    throw new SsrfBlockedError('could not resolve host');
  }
  if (addresses.length === 0) {
    throw new SsrfBlockedError('host did not resolve to any address');
  }
  for (const { address } of addresses) {
    if (!isPublicAddress(address)) {
      throw new SsrfBlockedError('URL resolves to a private/internal/reserved address');
    }
  }
}

/**
 * True if the URL's host is a loopback literal (so it can skip the public-only
 * SSRF guard). Used by the LLM-judge path: a LOCAL Ollama at
 * http://127.0.0.1:11434 is always allowed (no-egress), while any non-loopback
 * URL is forced through assertSafeFetchUrl so it can't be aimed at internal
 * infra. The bare hostname "localhost" IS treated as loopback here (it resolves
 * to 127.0.0.1, so the public-only guard would otherwise reject the recommended
 * local-Ollama path). Any OTHER hostname (e.g. "myhost.local") is NOT treated as
 * loopback — it goes through the resolving guard, which correctly rejects
 * anything that resolves inward.
 */
export function isLoopbackUrlHost(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost') return true;
  if (ipaddr.isValid(host) && isLoopbackAddr(host)) return true;
  return false;
}
