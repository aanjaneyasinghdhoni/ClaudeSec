/**
 * tests/ssrfTest.ts
 *
 * Unit gate for server/ssrf.ts — the SSRF guard shared by every outbound-fetch
 * sink (webhook sender + retry, OTLP forward, LLM-as-judge). A regression that
 * lets a private/metadata address through turns ClaudeSec into an SSRF pivot,
 * so this is a security-critical control.
 *
 * Run via:  npx tsx tests/ssrfTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 *
 * HERMETIC: every URL here uses an IP *literal*, which assertSafeFetchUrl
 * classifies directly via ipaddr.js WITHOUT any DNS lookup (see the
 * `ipaddr.isValid(host)` fast-path in ssrf.ts). So no real network/DNS call is
 * ever made — important both for determinism and for the no-egress rule. We do
 * NOT exercise the hostname-resolution branch (would require DNS); that branch
 * is noted in the returned coverage summary.
 */

import assert from 'node:assert';
import {
  assertSafeFetchUrl,
  isPublicAddress,
  isLoopbackAddr,
  isLoopbackUrlHost,
  normalizeAddr,
  SsrfBlockedError,
} from '../server/ssrf.js';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  return (async () => {
    try {
      await fn();
      passed++;
    } catch (err) {
      failed++;
      failures.push(`${name}: ${(err as Error).message}`);
    }
  })();
}

/** Assert assertSafeFetchUrl REJECTS the URL with an SsrfBlockedError. */
async function assertBlocked(name: string, url: string): Promise<void> {
  await check(name, async () => {
    await assert.rejects(
      () => assertSafeFetchUrl(url),
      (e: unknown) => e instanceof SsrfBlockedError,
      `expected SsrfBlockedError for ${url}`,
    );
  });
}

/** Assert assertSafeFetchUrl ALLOWS the URL (resolves without throwing). */
async function assertAllowed(name: string, url: string): Promise<void> {
  await check(name, async () => {
    await assert.doesNotReject(
      () => assertSafeFetchUrl(url),
      `expected ${url} to be allowed`,
    );
  });
}

async function main(): Promise<void> {
  // ─────────────────────────────────────────────────────────────────────────
  // 1. normalizeAddr / isLoopbackAddr — IPv4-mapped IPv6 unwrapping.
  // ─────────────────────────────────────────────────────────────────────────
  await check('normalizeAddr strips ::ffff: prefix', () => {
    assert.strictEqual(normalizeAddr('::ffff:127.0.0.1'), '127.0.0.1');
    assert.strictEqual(normalizeAddr('10.0.0.5'), '10.0.0.5');
  });
  await check('isLoopbackAddr true for 127.0.0.1 / ::1 / mapped', () => {
    assert.ok(isLoopbackAddr('127.0.0.1'));
    assert.ok(isLoopbackAddr('::1'));
    assert.ok(isLoopbackAddr('::ffff:127.0.0.1'));
  });
  await check('isLoopbackAddr false for public / private non-loopback', () => {
    assert.ok(!isLoopbackAddr('8.8.8.8'));
    assert.ok(!isLoopbackAddr('10.0.0.1'));
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 2. isPublicAddress — the core range classifier.
  // ─────────────────────────────────────────────────────────────────────────
  await check('isPublicAddress true for routable public IPs', () => {
    assert.ok(isPublicAddress('8.8.8.8'));
    assert.ok(isPublicAddress('1.1.1.1'));
    assert.ok(isPublicAddress('93.184.216.34')); // example.com historical
    assert.ok(isPublicAddress('2606:4700:4700::1111')); // public IPv6 (cloudflare)
  });
  await check('isPublicAddress false for RFC1918 10.0.0.0/8', () => {
    assert.ok(!isPublicAddress('10.0.0.1'));
    assert.ok(!isPublicAddress('10.255.255.255'));
  });
  await check('isPublicAddress false for 172.16.0.0/12', () => {
    assert.ok(!isPublicAddress('172.16.0.1'));
    assert.ok(!isPublicAddress('172.31.255.254'));
  });
  await check('isPublicAddress true at 172.16/12 boundaries (172.15 / 172.32 are public)', () => {
    assert.ok(isPublicAddress('172.15.0.1'));
    assert.ok(isPublicAddress('172.32.0.1'));
  });
  await check('isPublicAddress false for 192.168.0.0/16', () => {
    assert.ok(!isPublicAddress('192.168.0.1'));
    assert.ok(!isPublicAddress('192.168.255.255'));
  });
  await check('isPublicAddress false for loopback 127/8', () => {
    assert.ok(!isPublicAddress('127.0.0.1'));
    assert.ok(!isPublicAddress('127.255.255.255'));
  });
  await check('isPublicAddress false for link-local + cloud metadata 169.254.x', () => {
    assert.ok(!isPublicAddress('169.254.0.1'));
    assert.ok(!isPublicAddress('169.254.169.254')); // AWS/GCP metadata endpoint
  });
  await check('isPublicAddress false for CGNAT 100.64.0.0/10', () => {
    assert.ok(!isPublicAddress('100.64.0.1'));
  });
  await check('isPublicAddress false for IPv6 loopback / link-local / ULA', () => {
    assert.ok(!isPublicAddress('::1'));
    assert.ok(!isPublicAddress('fe80::1'));     // link-local
    assert.ok(!isPublicAddress('fc00::1'));     // unique-local
    assert.ok(!isPublicAddress('fd00::1'));     // unique-local
  });
  await check('isPublicAddress false for IPv4-mapped private IPv6', () => {
    assert.ok(!isPublicAddress('::ffff:10.0.0.1'));
    assert.ok(!isPublicAddress('::ffff:169.254.169.254'));
  });
  await check('isPublicAddress false for unparseable garbage', () => {
    assert.ok(!isPublicAddress('not-an-ip'));
    assert.ok(!isPublicAddress(''));
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 3. assertSafeFetchUrl — scheme validation.
  // ─────────────────────────────────────────────────────────────────────────
  await assertBlocked('reject file:// scheme', 'file:///etc/passwd');
  await assertBlocked('reject ftp:// scheme', 'ftp://8.8.8.8/x');
  await assertBlocked('reject gopher:// scheme', 'gopher://8.8.8.8:70/x');
  await assertBlocked('reject empty / invalid URL', 'http://');
  await assertBlocked('reject non-url junk', 'not a url at all');

  // ─────────────────────────────────────────────────────────────────────────
  // 4. assertSafeFetchUrl — private/metadata IP literals are blocked.
  //    (IP literal → no DNS; classified directly.)
  // ─────────────────────────────────────────────────────────────────────────
  await assertBlocked('block 127.0.0.1', 'http://127.0.0.1/');
  await assertBlocked('block 127.0.0.1 with port', 'http://127.0.0.1:8080/path');
  await assertBlocked('block 10.x', 'http://10.0.0.5/internal');
  await assertBlocked('block 172.16.x', 'https://172.16.0.1/');
  await assertBlocked('block 172.31.x', 'https://172.31.255.1/');
  await assertBlocked('block 192.168.x', 'http://192.168.1.1/admin');
  await assertBlocked('block 169.254.169.254 metadata', 'http://169.254.169.254/latest/meta-data/');
  await assertBlocked('block IPv6 ::1', 'http://[::1]:3000/');
  await assertBlocked('block IPv6 link-local fe80::1', 'http://[fe80::1]/');
  await assertBlocked('block IPv4-mapped loopback [::ffff:127.0.0.1]', 'http://[::ffff:127.0.0.1]/');

  // ─────────────────────────────────────────────────────────────────────────
  // 5. assertSafeFetchUrl — public IP literals are allowed (still no DNS).
  // ─────────────────────────────────────────────────────────────────────────
  await assertAllowed('allow public 8.8.8.8', 'http://8.8.8.8/collector');
  await assertAllowed('allow public 1.1.1.1 https', 'https://1.1.1.1/v1/traces');
  await assertAllowed('allow public IPv6 literal', 'https://[2606:4700:4700::1111]/');

  // ─────────────────────────────────────────────────────────────────────────
  // 6. isLoopbackUrlHost — the LLM-judge local-Ollama exemption.
  // ─────────────────────────────────────────────────────────────────────────
  await check('isLoopbackUrlHost true for localhost + 127.0.0.1 + [::1]', () => {
    assert.ok(isLoopbackUrlHost('http://localhost:11434/api'));
    assert.ok(isLoopbackUrlHost('http://127.0.0.1:11434/api'));
    assert.ok(isLoopbackUrlHost('http://[::1]:11434/api'));
  });
  await check('isLoopbackUrlHost false for public + private-non-loopback + custom host', () => {
    assert.ok(!isLoopbackUrlHost('http://8.8.8.8/'));
    assert.ok(!isLoopbackUrlHost('http://10.0.0.1/'));
    assert.ok(!isLoopbackUrlHost('http://myhost.local/'));
    assert.ok(!isLoopbackUrlHost('not a url'));
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Report + exit
  // ─────────────────────────────────────────────────────────────────────────
  const total = passed + failed;
  console.log('───────────────────────────────────────────────');
  console.log(`  ssrfTest: ${passed}/${total} passed`);
  console.log('───────────────────────────────────────────────');
  if (failed > 0) {
    console.error(`\n  ${failed} FAILURE(S):`);
    for (const f of failures) console.error(`    ✗ ${f}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch(err => {
  console.error('[ssrfTest] fatal:', err);
  process.exit(1);
});
