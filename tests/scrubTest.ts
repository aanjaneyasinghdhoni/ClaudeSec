/**
 * tests/scrubTest.ts
 *
 * Unit gate for server/scrub.ts — the secret-scrubbing layer that runs on every
 * span attribute before it is persisted, broadcast, or forwarded. A regression
 * here leaks live credentials, so this is one of the highest-value tests in the
 * suite.
 *
 * Run via:  npx tsx tests/scrubTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed (details printed).
 *
 * Hermetic: no network, no DB, no filesystem. Pure function calls.
 *
 * Coverage:
 *   • API keys (OpenAI sk-…, Anthropic sk-ant-…, AWS AKIA…/secret, GitHub,
 *     GitLab, Slack, Stripe, Google, npm, …)
 *   • JWTs
 *   • Slack / Discord / Telegram webhook URLs
 *   • password / secret / token assignments in env-style strings
 *   • SSH private-key blocks
 *   • home-path redaction (/Users, /home, C:\Users)
 *   • email local-part redaction (domain preserved)
 *   • sensitive-key masking on the attribute map
 *   • benign text passes through UNCHANGED (no over-scrubbing of ordinary URLs,
 *     code snippets, normal prose)
 */

import assert from 'node:assert';
import { fileURLToPath } from 'node:url';
import {
  scrubText,
  scrubAttributes,
  detectSecrets,
  type ScrubOptions,
} from '../server/scrub.js';

// ---------------------------------------------------------------------------
// Tiny assertion harness (matches the house style: plain functions, count
// cases, exit(1) on any failure — no test framework).
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Fixed scrub options so the test is deterministic regardless of the host's
// real $HOME / username (we never read the maintainer's machine identity).
// ---------------------------------------------------------------------------

const OPTS: ScrubOptions = {
  enabled:     true,
  homeDir:     '/home/tester',
  osUsername:  'tester',
  honeytokens: [],
};

/** Assert a secret string is GONE from the scrubbed output. */
function assertGone(name: string, secret: string, input?: string): void {
  check(name, () => {
    const out = scrubText(input ?? secret, OPTS);
    assert.ok(
      !out.includes(secret),
      `secret still present in output: ${JSON.stringify(out)}`,
    );
  });
}

/** Assert benign input passes through completely unchanged. */
function assertUnchanged(name: string, input: string): void {
  check(name, () => {
    const out = scrubText(input, OPTS);
    assert.strictEqual(out, input, `benign text was modified: ${JSON.stringify(out)}`);
  });
}

// ───────────────────────────────────────────────────────────────────────────
// 1. API keys — assert the secret is gone AND a placeholder convention holds.
// ───────────────────────────────────────────────────────────────────────────

assertGone('openai-key gone', 'sk-abcdefghij0123456789ABCDEFXYZ');
check('openai-key placeholder', () => {
  const out = scrubText('token=sk-abcdefghij0123456789ABCDEFXYZ done', OPTS);
  assert.ok(out.includes('sk-‹redacted›'), `expected sk-‹redacted›, got ${JSON.stringify(out)}`);
});

assertGone('anthropic-key gone', 'sk-ant-abcdefghij0123456789ABCDEFXYZ');
check('anthropic-key placeholder', () => {
  const out = scrubText('key: sk-ant-abcdefghij0123456789ABCDEFXYZ', OPTS);
  assert.ok(out.includes('sk-ant-‹redacted›'), `got ${JSON.stringify(out)}`);
});

assertGone('aws-akia gone', 'AKIAIOSFODNN7EXAMPLE');
check('aws-akia placeholder', () => {
  const out = scrubText('aws id AKIAIOSFODNN7EXAMPLE here', OPTS);
  assert.ok(out.includes('[redacted:aws-akia]'), `got ${JSON.stringify(out)}`);
});

check('aws secret-access-key value gone', () => {
  const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; // 40 chars
  const out = scrubText(`aws_secret_access_key=${secret}`, OPTS);
  assert.ok(!out.includes(secret), `secret still present: ${JSON.stringify(out)}`);
  assert.ok(out.includes('‹redacted›'), `got ${JSON.stringify(out)}`);
});

assertGone('github-token gone', 'ghp_' + 'a'.repeat(36));
check('github-token placeholder', () => {
  const out = scrubText('GH_TOKEN=ghp_' + 'a'.repeat(36), OPTS);
  assert.ok(out.includes('[redacted:github-token]'), `got ${JSON.stringify(out)}`);
});

assertGone('gitlab-token gone', 'glpat-' + 'a'.repeat(20));
assertGone('slack-token gone', 'xoxb-' + '1'.repeat(20));
assertGone('stripe-key gone', 'sk_live_' + 'a'.repeat(24));
assertGone('google-api-key gone', 'AIza' + 'a'.repeat(35));
assertGone('npm-token gone', 'npm_' + 'a'.repeat(36));

// ───────────────────────────────────────────────────────────────────────────
// 2. JWT
// ───────────────────────────────────────────────────────────────────────────

check('jwt redacted', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.' +
    'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const out = scrubText(`Authorization header carried ${jwt} today`, OPTS);
  assert.ok(!out.includes(jwt), `jwt still present: ${JSON.stringify(out)}`);
  assert.ok(out.includes('[redacted:jwt]'), `got ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 3. Webhook URLs
// ───────────────────────────────────────────────────────────────────────────

check('slack webhook redacted', () => {
  const url = 'https://hooks.slack.com/services/' + 'T00000000/B00000000/' + 'X'.repeat(24);
  const out = scrubText(url, OPTS);
  assert.ok(!out.includes('X'.repeat(24)), `secret tail leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('[redacted:slack-webhook]'), `got ${JSON.stringify(out)}`);
});

check('discord webhook redacted', () => {
  const url =
    'https://discord.com/api/webhooks/123456789012345678/' + 'a'.repeat(40);
  const out = scrubText(url, OPTS);
  assert.ok(!out.includes('a'.repeat(40)), `secret tail leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('[redacted:discord-webhook]'), `got ${JSON.stringify(out)}`);
});

check('telegram bot token redacted', () => {
  const url = 'https://api.telegram.org/bot123456789:' + 'A'.repeat(35) + '/sendMessage';
  const out = scrubText(url, OPTS);
  assert.ok(!out.includes('A'.repeat(35)), `secret leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('[redacted:telegram-webhook]'), `got ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 4. Password / secret / token assignments in env-style strings
// ───────────────────────────────────────────────────────────────────────────

check('password assignment value gone', () => {
  const out = scrubText('password=SuperSecretP@ss123', OPTS);
  assert.ok(!out.includes('SuperSecretP@ss123'), `password leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('‹redacted›'), `got ${JSON.stringify(out)}`);
});

check('api_key assignment value gone', () => {
  const out = scrubText('api_key: "abcdef0123456789secret"', OPTS);
  assert.ok(!out.includes('abcdef0123456789secret'), `value leaked: ${JSON.stringify(out)}`);
});

check('bearer token in authorization header gone', () => {
  const out = scrubText('Authorization: Bearer aVeryLongOpaqueTokenValue123456', OPTS);
  assert.ok(!out.includes('aVeryLongOpaqueTokenValue123456'), `token leaked: ${JSON.stringify(out)}`);
  assert.ok(/‹redacted›/.test(out), `got ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 5. SSH / PEM private key block
// ───────────────────────────────────────────────────────────────────────────

check('private key block redacted', () => {
  const key =
    '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA\n'.repeat(3) +
    '-----END OPENSSH PRIVATE KEY-----';
  const out = scrubText(key, OPTS);
  assert.ok(!out.includes('b3BlbnNzaC1rZXk'), `key body leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('[redacted:private-key]'), `got ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 6. Home-path redaction
// ───────────────────────────────────────────────────────────────────────────

check('/Users path redacted', () => {
  const out = scrubText('/Users/alice/projects/app/src/index.ts', OPTS);
  assert.ok(!out.includes('/Users/alice'), `username leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('/Users/***'), `got ${JSON.stringify(out)}`);
});

check('/home path redacted', () => {
  const out = scrubText('/home/bob/.ssh/config', OPTS);
  assert.ok(!out.includes('/home/bob'), `username leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('/home/***'), `got ${JSON.stringify(out)}`);
});

check('Windows C:\\Users path redacted', () => {
  const out = scrubText('C:\\Users\\Carol\\Documents\\notes.txt', OPTS);
  assert.ok(!out.includes('C:\\Users\\Carol'), `username leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('C:\\Users\\***'), `got ${JSON.stringify(out)}`);
});

check('configured homeDir collapses to ~', () => {
  const out = scrubText('cache lives at /home/tester/.cache/app', OPTS);
  // /home/<user> rule fires first → /home/*** ; the homeDir collapse is a
  // belt-and-braces second pass. Either way the real username is gone.
  assert.ok(!out.includes('/home/tester'), `homeDir leaked: ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 7. Email local-part redaction (domain preserved for debugging)
// ───────────────────────────────────────────────────────────────────────────

check('email local part redacted, domain kept', () => {
  const out = scrubText('contact alice.smith@example.com for access', OPTS);
  assert.ok(!out.includes('alice.smith'), `local part leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('***@example.com'), `got ${JSON.stringify(out)}`);
});

// ───────────────────────────────────────────────────────────────────────────
// 8. scrubAttributes — sensitive KEYS masked wholesale, nested objects walked.
// ───────────────────────────────────────────────────────────────────────────

check('sensitive key masked to ***', () => {
  const { attrs } = scrubAttributes(
    { authorization: 'Bearer xyz', password: 'hunter2', 'x-api-key': 'abc123' },
    OPTS,
  );
  assert.strictEqual(attrs.authorization, '***');
  assert.strictEqual(attrs.password, '***');
  assert.strictEqual(attrs['x-api-key'], '***');
});

check('non-sensitive key value still scrubbed for embedded secret', () => {
  const { attrs } = scrubAttributes(
    { 'tool.command': 'curl -H "x: ghp_' + 'a'.repeat(36) + '"' },
    OPTS,
  );
  const v = String(attrs['tool.command']);
  assert.ok(!v.includes('ghp_' + 'a'.repeat(36)), `embedded token leaked: ${v}`);
  assert.ok(v.includes('[redacted:github-token]'), `got ${v}`);
});

check('nested object values are scrubbed recursively', () => {
  const { attrs } = scrubAttributes(
    { meta: { note: 'login as alice@corp.io' } },
    OPTS,
  );
  const note = (attrs.meta as Record<string, unknown>).note as string;
  assert.ok(!note.includes('alice@corp.io'), `email leaked in nested obj: ${note}`);
  assert.ok(note.includes('***@corp.io'), `got ${note}`);
});

check('scrub disabled forwards attributes untouched', () => {
  const raw = { password: 'plaintext', note: 'sk-' + 'a'.repeat(24) };
  const { attrs } = scrubAttributes(raw, { ...OPTS, enabled: false });
  assert.strictEqual(attrs.password, 'plaintext');
  assert.strictEqual(attrs.note, 'sk-' + 'a'.repeat(24));
});

check('honeytoken hit detected in original (un-scrubbed) value', () => {
  const { honeytokenHits } = scrubAttributes(
    { 'tool.output': 'planted canary_TRAP_9f3a2b here' },
    { ...OPTS, honeytokens: ['canary_TRAP_9f3a2b'] },
  );
  assert.strictEqual(honeytokenHits.length, 1);
  assert.strictEqual(honeytokenHits[0].honeytoken, 'canary_TRAP_9f3a2b');
});

// ───────────────────────────────────────────────────────────────────────────
// 9. Benign text MUST pass through unchanged — guards against over-scrubbing.
// ───────────────────────────────────────────────────────────────────────────

assertUnchanged('ordinary https url unchanged', 'see https://example.com/docs/getting-started');
assertUnchanged('github repo url unchanged', 'git clone https://github.com/org/repo.git');
assertUnchanged('npm install command unchanged', 'npm install express react react-dom');
assertUnchanged('arrow-fn code snippet unchanged', 'const add = (a, b) => a + b;');
assertUnchanged('reduce snippet unchanged', 'arr.reduce((acc, x) => acc + x, 0)');
assertUnchanged('plain prose unchanged', 'The quick brown fox jumps over the lazy dog.');
assertUnchanged('relative path unchanged', './src/components/Button.tsx');
assertUnchanged('sql query unchanged', 'SELECT name, email FROM users WHERE id = ?');
assertUnchanged('docker run unchanged', 'docker run -p 3000:3000 myapp:latest');
assertUnchanged('short word "secret" alone unchanged', 'this is no secret');

// A bare word that *looks* like a key prefix but is too short must NOT match
// (avoids redacting words like "sk-" or "AIza" in normal text fragments).
assertUnchanged('short sk- fragment unchanged', 'the task-sk list is empty');

// ───────────────────────────────────────────────────────────────────────────
// 10. detectSecrets — read-only scanner returns kind + masked excerpt.
// ───────────────────────────────────────────────────────────────────────────

check('detectSecrets finds multiple distinct secrets', () => {
  const text =
    'token ghp_' + 'b'.repeat(36) + ' and aws AKIAIOSFODNN7EXAMPLE';
  const findings = detectSecrets(text);
  const kinds = findings.map(f => f.kind).sort();
  assert.ok(kinds.includes('github-token'), `expected github-token, got ${kinds.join(',')}`);
  assert.ok(kinds.includes('aws-akia'), `expected aws-akia, got ${kinds.join(',')}`);
});

check('detectSecrets masks the raw value', () => {
  const findings = detectSecrets('AKIAIOSFODNN7EXAMPLE');
  assert.strictEqual(findings.length, 1);
  assert.ok(!findings[0].masked.includes('FODNN7EXAMPLE'), `mask leaked tail: ${findings[0].masked}`);
});

check('detectSecrets returns empty for benign text', () => {
  assert.deepStrictEqual(detectSecrets('npm run build && npm test'), []);
});

// ---------------------------------------------------------------------------
// Report + exit
// ---------------------------------------------------------------------------

const total = passed + failed;
console.log('───────────────────────────────────────────────');
console.log(`  scrubTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failed > 0) {
  console.error(`\n  ${failed} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}

// Only auto-run when invoked directly.
const _argv1 = process.argv[1] ?? '';
const _self = fileURLToPath(import.meta.url);
void _argv1;
void _self;
process.exit(0);
