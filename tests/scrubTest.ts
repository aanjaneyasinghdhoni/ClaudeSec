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
 *   • scrub/detect parity — nothing detectSecrets() can name survives scrubText()
 */

import assert from 'node:assert';
import { fileURLToPath } from 'node:url';
import {
  scrubText,
  scrubAttributes,
  detectSecrets,
  SECRET_DETECT_KINDS,
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

// ───────────────────────────────────────────────────────────────────────────
// 11. Database connection strings — inline user:password@ credentials must be
//     redacted (a dumped .env routinely carries these).
// ───────────────────────────────────────────────────────────────────────────

check('mongodb connection-string credentials gone', () => {
  const out = scrubText('mongodb://dbuser:S3cretP%40ss@cluster0.mongodb.net/app', OPTS);
  assert.ok(!out.includes('S3cretP%40ss'), `password leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('mongodb://‹redacted›:‹redacted›@'), `got ${JSON.stringify(out)}`);
});

check('postgres connection-string credentials gone', () => {
  const out = scrubText('postgres://admin:hunter2longpass@db.internal:5432/prod', OPTS);
  assert.ok(!out.includes('hunter2longpass'), `password leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('postgres://‹redacted›:‹redacted›@'), `got ${JSON.stringify(out)}`);
});

check('postgresql connection-string credentials gone', () => {
  const out = scrubText('postgresql://svc:p4ssw0rdValue@10.0.0.5/db', OPTS);
  assert.ok(!out.includes('p4ssw0rdValue'), `password leaked: ${JSON.stringify(out)}`);
});

check('mysql connection-string credentials gone', () => {
  const out = scrubText('mysql://root:tooManySecrets@127.0.0.1:3306/shop', OPTS);
  assert.ok(!out.includes('tooManySecrets'), `password leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('mysql://‹redacted›:‹redacted›@'), `got ${JSON.stringify(out)}`);
});

check('redis connection-string credentials gone', () => {
  const out = scrubText('redis://default:R3disPassWord@redis.example.com:6379', OPTS);
  assert.ok(!out.includes('R3disPassWord'), `password leaked: ${JSON.stringify(out)}`);
});

// A connection string WITHOUT inline credentials must pass through untouched —
// the host alone is not a secret and over-scrubbing would corrupt config dumps.
assertUnchanged('credential-less mongodb url unchanged', 'mongodb://cluster0.example.net:27017/app');
assertUnchanged('credential-less redis url unchanged', 'redis://cache.internal:6379');

// ───────────────────────────────────────────────────────────────────────────
// 12. Inline environment assignments — `-e NAME=value`, `export NAME=value`,
//     `NAME=value cmd`. A password has no format to match on, so these are
//     redacted on the strength of the NAME. Both directions matter: every
//     credential-named assignment must lose its value, and every ordinary one
//     must survive byte-for-byte.
//
//     Secrets below are invented for this file. Never paste a real one here.
// ───────────────────────────────────────────────────────────────────────────

/** Assert an assignment lost its value but kept its name. */
function assertRedacted(name: string, input: string, secret: string, expectKey: string): void {
  check(name, () => {
    const out = scrubText(input, OPTS);
    assert.ok(!out.includes(secret), `value leaked: ${JSON.stringify(out)}`);
    assert.ok(out.includes(expectKey), `key not preserved, got ${JSON.stringify(out)}`);
    assert.ok(out.includes('‹redacted›'), `no placeholder, got ${JSON.stringify(out)}`);
  });
}

// -- docker -e, all three quoting styles ------------------------------------

assertRedacted(
  "-e NAME='value' (single-quoted) redacted",
  "docker run -e MT5_PASSWORD='Zq7!tradeRig' -p 80:80 img:latest",
  'Zq7!tradeRig',
  "MT5_PASSWORD='‹redacted›'",
);

assertRedacted(
  '-e NAME="value" (double-quoted, contains a space) redacted',
  'docker run -e DB_PASSWORD="two word phrase" img',
  'two word phrase',
  'DB_PASSWORD="‹redacted›"',
);

assertRedacted(
  '-e NAME=value (unquoted) redacted',
  'docker run -e GH_TOKEN=r4nd0mOpaqueValue img',
  'r4nd0mOpaqueValue',
  'GH_TOKEN=‹redacted›',
);

// The reported gap was short values: the generic assignment rule has a
// 12-character floor, so anything under it used to persist in the clear.
assertRedacted(
  'short value below the 12-char floor still redacted',
  'PGPASSWORD=sh0rt psql -h db.internal -U app',
  'sh0rt',
  'PGPASSWORD=‹redacted›',
);

assertRedacted(
  'very short value redacted',
  'docker run -e QA_PASSWORD=ab3 img',
  'ab3',
  'QA_PASSWORD=‹redacted›',
);

// -- the other syntactic forms ----------------------------------------------

assertRedacted(
  '--env NAME=value redacted',
  'docker run --env SUPABASE_ACCESS_TOKEN=sbp_shorty img',
  'sbp_shorty',
  'SUPABASE_ACCESS_TOKEN=‹redacted›',
);

assertRedacted(
  '--env=NAME=value redacted',
  'docker run --env=SECRET_KEY=abc123def img',
  'abc123def',
  'SECRET_KEY=‹redacted›',
);

assertRedacted(
  'export NAME=value redacted',
  'export CRON_SECRET=w3eklyRun && node job.js',
  'w3eklyRun',
  'CRON_SECRET=‹redacted›',
);

assertRedacted(
  'bare NAME=value command prefix redacted',
  'MYSQL_PWD=r00tpass mysql -u root shop',
  'r00tpass',
  'MYSQL_PWD=‹redacted›',
);

assertRedacted(
  'Windows set NAME=value redacted',
  'set ADMIN_SIGNING_SECRET=w1nSecret',
  'w1nSecret',
  'ADMIN_SIGNING_SECRET=‹redacted›',
);

assertRedacted(
  'glued name (PGPASSWORD, no underscore) redacted',
  'PGPASSWORD=Gl0edName pg_dump app',
  'Gl0edName',
  'PGPASSWORD=‹redacted›',
);

assertRedacted(
  'PASSPHRASE redacted',
  'export SSH_PASSPHRASE=unlockMe42',
  'unlockMe42',
  'SSH_PASSPHRASE=‹redacted›',
);

assertRedacted(
  'CREDENTIALS redacted',
  'docker run -e AWS_CREDENTIALS=blobOfStuff img',
  'blobOfStuff',
  'AWS_CREDENTIALS=‹redacted›',
);

// A truncated command must not become a bypass: an unterminated quote still
// loses its value even though the closing quote never arrives.
check('unterminated quote still redacted', () => {
  const out = scrubText("docker run -e MT5_PASSWORD='Zq7truncated", OPTS);
  assert.ok(!out.includes('Zq7truncated'), `value leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('MT5_PASSWORD='), `key not preserved: ${JSON.stringify(out)}`);
});

// Several assignments on one line: only the credential-named one changes.
check('mixed line redacts only the sensitive assignment', () => {
  const out = scrubText(
    'docker run -e NODE_ENV=production -e API_KEY=liveValue99 -e PORT=8080 img',
    OPTS,
  );
  assert.ok(!out.includes('liveValue99'), `value leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('-e NODE_ENV=production'), `benign arg mangled: ${JSON.stringify(out)}`);
  assert.ok(out.includes('-e PORT=8080'), `benign arg mangled: ${JSON.stringify(out)}`);
});

// Scrubbing must be idempotent — spans are re-scrubbed on export paths.
check('env-assignment redaction is idempotent', () => {
  const once  = scrubText("docker run -e MT5_PASSWORD='Zq7!tradeRig' img", OPTS);
  const twice = scrubText(once, OPTS);
  assert.strictEqual(twice, once, `second pass changed the output: ${JSON.stringify(twice)}`);
});

// A vendor-format value keeps its more informative placeholder rather than
// being flattened by the name-based rule — the earlier pattern already said
// *which kind* of credential this was, and that is worth keeping.
check('vendor placeholder survives the name-based rule', () => {
  const out = scrubText('export GH_TOKEN=ghp_' + 'a'.repeat(36), OPTS);
  assert.ok(out.includes('[redacted:github-token]'), `vendor placeholder lost: ${JSON.stringify(out)}`);
});

// The whole attributes map, not just free text.
check('env assignment inside an attribute value is redacted', () => {
  const { attrs } = scrubAttributes(
    { 'tool.command': "docker run -e MT5_PASSWORD='Zq7!tradeRig' img" },
    OPTS,
  );
  const v = String(attrs['tool.command']);
  assert.ok(!v.includes('Zq7!tradeRig'), `value leaked into attributes: ${v}`);
  assert.ok(v.includes('MT5_PASSWORD='), `key not preserved: ${v}`);
});

// -- must NOT redact: ordinary configuration --------------------------------

assertUnchanged('NODE_ENV unchanged',        'docker run -e NODE_ENV=production myapp');
assertUnchanged('POSTGRES_USER unchanged',   'docker run -e POSTGRES_USER=postgres postgres:16');
assertUnchanged('DEBUG flag unchanged',      'docker run -e DEBUG=1 myapp');
assertUnchanged('CI flag unchanged',         'docker run --env CI=true node:22 pnpm test');
assertUnchanged('LOG_LEVEL unchanged',       'export LOG_LEVEL=debug');
assertUnchanged('SORT_KEY unchanged',        'docker run -e SORT_KEY=created_at myapp');
assertUnchanged('MAX_TOKENS unchanged',      'docker run -e MAX_TOKENS=4096 myapp');
assertUnchanged('SESSION_TIMEOUT unchanged', 'docker run -e SESSION_TIMEOUT=3600 myapp');
assertUnchanged('NEXTAUTH_URL unchanged',    'export NEXTAUTH_URL=https://app.example.net');
assertUnchanged('bare PWD unchanged',        'docker run -e PWD=/srv/app myapp');

// Variable references and placeholders carry no secret; redacting them only
// destroys context.
assertUnchanged('$VAR reference unchanged',    'docker run -e MY_TOKEN=$MY_TOKEN myapp');
assertUnchanged('${VAR} reference unchanged',  'docker run -e API_SECRET=${SECRET} myapp');
assertUnchanged('%VAR% reference unchanged',   'set API_KEY=%API_KEY%');
assertUnchanged('$(cmd) reference unchanged',  'docker run -e API_KEY="$(cat key.txt)" myapp');
assertUnchanged('changeme placeholder unchanged', 'docker run -e DB_PASSWORD=changeme postgres:16');
assertUnchanged('xxx placeholder unchanged',      'docker run -e DB_PASSWORD=xxxx myapp');
assertUnchanged('asterisk placeholder unchanged', 'docker run -e DB_PASSWORD=*** myapp');
assertUnchanged('angle placeholder unchanged',    'export GH_TOKEN=<your-token-here>');
assertUnchanged('empty value unchanged',          'docker run -e DB_PASSWORD= myapp');
assertUnchanged('boolean value unchanged',        'docker run -e TOKEN_REQUIRED=true myapp');

// `-e NAME` with no `=` is Docker's host-passthrough form: it names a variable
// to inherit and carries no value at all. Nothing to redact, and blanking the
// name would hide the one pattern operators should be using.
assertUnchanged(
  'docker -e host-passthrough (no value) unchanged',
  'docker run -e MT5_PASSWORD -e MT5_LOGIN mt5:latest',
);

// camelCase is source code, not an environment assignment. The "value" there is
// an identifier, so redacting it would destroy context and protect nothing.
assertUnchanged('camelCase JSX prop unchanged', '<Form apiKey={apiKey} onSubmit={save} />');
assertUnchanged('lowercase local var unchanged', 'const token = await getToken();');

// -- linearity: the pattern must stay cheap on adversarial input ------------
// scrubAttributes runs on every attribute of every ingested span, so a
// quadratic blow-up here is a denial of service, not a slow test.

check('env-assignment scan stays linear on adversarial input', () => {
  const pumps = [
    'A_PASSWORD=' + "'".repeat(4000),
    'A_PASSWORD=' + 'a'.repeat(4000),
    "A_PASSWORD='" + 'a'.repeat(4000),
    'SECRET=x '.repeat(2000),
    ('A'.repeat(64) + '=' + 'b'.repeat(64) + ' ').repeat(500),
  ];
  for (const pump of pumps) {
    const t0 = Date.now();
    scrubText(pump, OPTS);
    const ms = Date.now() - t0;
    assert.ok(ms < 500, `scrubText took ${ms}ms on a ${pump.length}-char pump string`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// 13. Scrub / detect parity.
//
// server/scrub.ts maintains two hand-written pattern lists: SECRET_PATTERNS
// (redact) and SECRET_DETECT_PATTERNS (report). They are separate on purpose —
// see the comment above SECRET_DETECT_PATTERNS — but a credential the scanner
// can NAME and the scrubber does not REMOVE is a leak: the alert fires while
// the value is persisted and broadcast in the clear. That is exactly how the
// Telegram bot-token gap survived; the scrub pattern required an `https://`
// prefix the detect pattern did not.
//
// So this asserts the property directly, over the union of every scrub rule
// rather than pattern-against-pattern, because the scrubber is allowed to cover
// a detect pattern by some other rule. The kind-coverage check at the end makes
// the gate fail when a pattern is added to one side only.
//
// Every credential below is invented for this file and assembled at runtime, so
// no credential-shaped literal is ever written to disk. Never paste a real one.
// ───────────────────────────────────────────────────────────────────────────

const SK        = 'sk' + '-';
const PEM_BEGIN = (t: string) => '-----BEGIN ' + t + ' PRIVATE ' + 'KEY-----';
const PEM_END   = (t: string) => '-----END ' + t + ' PRIVATE ' + 'KEY-----';
const PEM_BODY  = 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA\n';
const HEX32     = 'a1b2c3d4'.repeat(4);

/** kind → samples that MUST be both detected and scrubbed. */
const PARITY_CORPUS: { kind: string; label: string; sample: string }[] = [
  { kind: 'private-key', label: 'terminated block', sample: PEM_BEGIN('OPENSSH') + '\n' + PEM_BODY.repeat(3) + PEM_END('OPENSSH') },
  // Truncated agent output and oversized RSA bodies both leave the block
  // unterminated. The header alone is enough to detect, so it must be enough
  // to scrub.
  { kind: 'private-key', label: 'truncated, no END marker', sample: PEM_BEGIN('OPENSSH') + '\n' + PEM_BODY.repeat(3) },
  { kind: 'private-key', label: 'body over the 4096 bound', sample: PEM_BEGIN('RSA') + '\n' + PEM_BODY.repeat(200) + PEM_END('RSA') },

  { kind: 'jwt', label: 'three-segment', sample: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV' },

  { kind: 'slack-webhook', label: 'services url', sample: 'https://hooks.slack.com/services/T00000000/B00000000/' + 'X'.repeat(24) },

  { kind: 'discord-webhook', label: 'discord.com',    sample: 'https://discord.com/api/webhooks/123456789012345678/' + 'd'.repeat(40) },
  { kind: 'discord-webhook', label: 'discordapp.com', sample: 'https://discordapp.com/api/webhooks/123456789012345678/' + 'd'.repeat(40) },
  { kind: 'discord-webhook', label: 'canary subdomain', sample: 'https://canary.discord.com/api/webhooks/123456789012345678/' + 'd'.repeat(40) },

  // The reported gap: a bot token is the credential whether or not it is
  // wrapped in a URL, and it travels bare in config files and `curl -d` bodies.
  { kind: 'telegram-token', label: 'bare token',        sample: 'bot777000111:' + 'T'.repeat(35) },
  { kind: 'telegram-token', label: 'host, no scheme',   sample: 'api.telegram.org/bot777000111:' + 'T'.repeat(35) },
  { kind: 'telegram-token', label: 'full https url',    sample: 'https://api.telegram.org/bot777000111:' + 'T'.repeat(35) + '/sendMessage' },

  { kind: 'anthropic-key', label: 'api03', sample: SK + 'ant-api03-' + 'n'.repeat(28) },

  { kind: 'openai-key', label: 'classic',      sample: SK + 'o'.repeat(32) },
  // Project keys carry a hyphen the tail class does not accept, so the scrub
  // side has to spell `proj-` out or it falls short of the length floor.
  { kind: 'openai-key', label: 'project form', sample: SK + 'proj-' + 'o'.repeat(32) },

  { kind: 'aws-akia', label: 'AKIA', sample: 'AKIAIOSFODNN7EXAMPLE' },
  { kind: 'aws-akia', label: 'ASIA', sample: 'ASIAIOSFODNN7EXAMPLE' },
  { kind: 'aws-akia', label: 'AROA', sample: 'AROAIOSFODNN7EXAMPLE' },

  { kind: 'github-token', label: 'ghp_',           sample: 'ghp_' + 'g'.repeat(36) },
  { kind: 'github-token', label: 'ghs_',           sample: 'ghs_' + 'g'.repeat(36) },
  { kind: 'github-token', label: 'ghu_ 76-char',   sample: 'ghu_' + 'g'.repeat(76) },

  { kind: 'gitlab-token', label: 'plain',            sample: 'glpat-' + 'l'.repeat(20) },
  { kind: 'gitlab-token', label: 'dashes and score', sample: 'glpat-Ab_c-Def' + 'l'.repeat(12) },

  { kind: 'slack-token', label: 'xoxb', sample: 'xoxb-' + '1'.repeat(12) + '-abcdEFGH' },
  { kind: 'slack-token', label: 'xoxs', sample: 'xoxs-' + '1'.repeat(12) + '-abcdEFGH' },

  { kind: 'google-api-key', label: 'AIza', sample: 'AIza' + 'D'.repeat(35) },
  { kind: 'google-oauth',   label: 'ya29', sample: 'ya29.' + 'E'.repeat(40) },

  { kind: 'stripe-key', label: 'sk_live', sample: 'sk_live_' + 'f'.repeat(24) },
  { kind: 'stripe-key', label: 'rk_test', sample: 'rk_test_' + 'f'.repeat(24) },
  { kind: 'stripe-key', label: 'pk_live', sample: 'pk_live_' + 'f'.repeat(24) },

  { kind: 'twilio-key',   label: 'SK + 32 hex', sample: 'SK' + HEX32 },
  { kind: 'sendgrid-key', label: 'SG.',         sample: 'SG.' + 'g'.repeat(22) + '.' + 'h'.repeat(43) },
  { kind: 'npm-token',    label: 'npm_',        sample: 'npm_' + 'i'.repeat(36) },
  { kind: 'pypi-token',   label: 'pypi-',       sample: 'pypi-AgEIcHlwaS5vcmcSYNTH' },
  { kind: 'digitalocean', label: 'dop_v1_',     sample: 'dop_v1_' + 'a1b2c3d4'.repeat(8) },
];

// A secret rarely arrives alone on a line. Anchoring and lookbehind differences
// between the two sides only surface in one of these framings, so each sample
// is run through all of them.
const PARITY_CONTEXTS: { name: string; wrap: (s: string) => string }[] = [
  { name: 'bare',     wrap: s => s },
  { name: 'in-prose', wrap: s => `the value is ${s} ok` },
  { name: 'in-json',  wrap: s => `{"note":"${s}"}` },
];

for (const { kind, label, sample } of PARITY_CORPUS) {
  check(`parity: ${kind} (${label}) is detected and scrubbed`, () => {
    for (const { name, wrap } of PARITY_CONTEXTS) {
      const input = wrap(sample);
      const findings = detectSecrets(input);
      const kinds = findings.map(f => f.kind);
      assert.ok(
        kinds.includes(kind),
        `[${name}] detectSecrets did not report ${kind}; got [${kinds.join(',') || 'none'}]`,
      );

      // The property that matters: nothing the scanner named survives.
      const out = scrubText(input, OPTS);
      for (const f of findings) {
        assert.ok(
          !out.includes(f.match),
          `[${name}] ${f.kind} was detected but NOT redacted — value persisted in the clear`,
        );
      }
      assert.ok(!out.includes(sample), `[${name}] sample survived scrubbing: ${JSON.stringify(out)}`);
    }
  });
}

// The gate that stops the drift recurring: a new detect pattern with no sample
// is a pattern nobody has proved the scrubber removes.
check('parity: every detect kind has a corpus sample', () => {
  const covered = new Set(PARITY_CORPUS.map(c => c.kind));
  const missing = SECRET_DETECT_KINDS.filter(k => !covered.has(k));
  assert.deepStrictEqual(
    missing, [],
    `detect kinds with no parity sample: ${missing.join(', ')} — add one to PARITY_CORPUS ` +
    `and confirm the scrubber removes it`,
  );
});

// And the reverse bookkeeping check, so a sample cannot silently outlive the
// pattern it was written for (a typo'd kind would otherwise pass vacuously).
check('parity: every corpus sample names a real detect kind', () => {
  const known = new Set(SECRET_DETECT_KINDS);
  const unknown = [...new Set(PARITY_CORPUS.map(c => c.kind))].filter(k => !known.has(k));
  assert.deepStrictEqual(unknown, [], `corpus names unknown kinds: ${unknown.join(', ')}`);
});

// The unterminated-private-key fallback consumes its body with an unbounded
// character class, so it gets the same linearity bar as everything else that
// runs on every attribute of every span.
check('unterminated private-key fallback stays linear', () => {
  const pumps = [
    PEM_BEGIN('RSA') + '\n' + 'A'.repeat(40000),
    PEM_BEGIN('RSA') + '\n' + ('A'.repeat(64) + '\n').repeat(1000),
    PEM_BEGIN('RSA') + '\n' + ('A'.repeat(64) + '\n').repeat(1000) + '-'.repeat(2000),
    (PEM_BEGIN('EC') + '\nQUJD\n').repeat(500),
  ];
  for (const pump of pumps) {
    const t0 = Date.now();
    scrubText(pump, OPTS);
    const ms = Date.now() - t0;
    assert.ok(ms < 500, `scrubText took ${ms}ms on a ${pump.length}-char private-key pump`);
  }
});

// Email scanning is the other rule that sees every byte of every attribute.
// A long run of local-part characters that never reaches an `@` — a base64
// blob, a minified bundle — used to cost O(n²): 160 KB took over twelve
// seconds of CPU, per attribute, on the ingest path.
check('email scan stays linear on long non-email runs', () => {
  const pumps = [
    'A'.repeat(160000),
    '.a'.repeat(80000),
    'a@'.repeat(80000),
    '@' + 'a'.repeat(160000),
    'a'.repeat(160000) + '@',
  ];
  for (const pump of pumps) {
    const t0 = Date.now();
    scrubText(pump, OPTS);
    const ms = Date.now() - t0;
    assert.ok(ms < 500, `scrubText took ${ms}ms on a ${pump.length}-char email pump`);
  }
});

// …and still redacts an address that is genuinely there, including a local
// part longer than the RFC limit (the guard is a boundary, not a length cap).
check('email redaction survives the linearity guard', () => {
  const out = scrubText('ping ' + 'x'.repeat(80) + '@example.com now', OPTS);
  assert.ok(!out.includes('x'.repeat(80)), `local part leaked: ${JSON.stringify(out)}`);
  assert.ok(out.includes('***@example.com'), `got ${JSON.stringify(out)}`);
});

// A terminated block must keep using the precise whole-block rule — the
// fallback is a safety net, not a replacement, and ordering is what keeps the
// trailing text after `-----END …-----` intact.
check('terminated private key does not over-consume trailing text', () => {
  const block = PEM_BEGIN('OPENSSH') + '\n' + PEM_BODY.repeat(2) + PEM_END('OPENSSH');
  const out = scrubText(`${block}\nand then some following notes`, OPTS);
  assert.ok(out.includes('[redacted:private-key]'), `got ${JSON.stringify(out)}`);
  assert.ok(out.includes('and then some following notes'), `trailing text eaten: ${JSON.stringify(out)}`);
});

// Scrubbing stays idempotent with the fallback in place — spans are re-scrubbed
// on the export paths.
check('private-key redaction is idempotent', () => {
  const once  = scrubText(PEM_BEGIN('RSA') + '\n' + PEM_BODY.repeat(3), OPTS);
  const twice = scrubText(once, OPTS);
  assert.strictEqual(twice, once, `second pass changed the output: ${JSON.stringify(twice)}`);
});

// Prose that merely mentions a key must not trip the fallback.
assertUnchanged('private-key prose unchanged', 'I stored the private key in the vault, not in git.');

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
