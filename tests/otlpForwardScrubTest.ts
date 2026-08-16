/**
 * tests/otlpForwardScrubTest.ts
 *
 * Gate for the OTEL_FORWARD_URL leak: the OTLP proxy used to POST the raw
 * request body upstream, so a collector received the live credentials the
 * scrubber strips from everything we persist and broadcast. The forwarded batch
 * is now scrubbed with the same rules as the stored one.
 *
 * Coverage:
 *   • No planted secret (Anthropic key, AWS access key, GitHub token, bearer
 *     header, home path, OS username, a secret nested in an arrayValue, one in a
 *     span event) survives anywhere in the serialized forward payload.
 *   • The forwarded document is still valid OTLP — resourceSpans / scopeSpans /
 *     spans survive, every attribute is a {key, value:<AnyValue>} pair, and a
 *     non-sensitive intValue stays an intValue so numeric telemetry keeps its
 *     type upstream.
 *   • Forwarded values match what ingest stores, so the two copies cannot drift.
 *   • The caller's body is NOT mutated — detection runs on the raw attributes.
 *   • CLAUDESEC_DISABLE_SCRUB (opts.enabled === false) forwards untouched.
 *
 * Run via:  npx tsx tests/otlpForwardScrubTest.ts
 *   Exit 0 → every assertion passed.   Exit 1 → a failure.
 *
 * DB DISCIPLINE: CLAUDESEC_DB and CLAUDESEC_HOME point under os.tmpdir() BEFORE
 * server/index.ts is imported (importing it is inert — no listener — but it does
 * open a database), and both are removed in a finally block. The real
 * ~/.claudesec database is never opened.
 */

import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const STAMP = `${process.pid}-${Date.now()}`;
const DB_PATH = path.join(os.tmpdir(), `csec-fwdscrub-${STAMP}.db`);
const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), `csec-fwdscrub-home-${STAMP}-`));
process.env.CLAUDESEC_DB = DB_PATH;
process.env.CLAUDESEC_HOME = HOME_DIR;
process.env.CLAUDESEC_WATCH = '0';
delete process.env.CLAUDESEC_DISABLE_SCRUB;

const { scrubTraceDataForForward } = await import('../server/index.js');
const { loadScrubOptions, scrubAttributes } = await import('../server/scrub.js');

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try { fn(); passed++; }
  catch (err) { failed++; failures.push(`${name}: ${(err as Error).message}`); }
}

function cleanup(): void {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
  try { fs.rmSync(HOME_DIR, { recursive: true, force: true }); } catch {}
}

// ---------------------------------------------------------------------------
// Planted secrets. All synthetic — shaped to match the scrubber's patterns, of
// no value to anyone. Every one of these must be absent from the forward body.
// ---------------------------------------------------------------------------

const ANTHROPIC_KEY = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const AWS_KEY       = 'AKIAQQQQWWWWEEEERRRR';
const GITHUB_TOKEN  = 'ghp_' + 'a'.repeat(36);
const BEARER_TOKEN  = 'Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const NESTED_KEY    = 'glpat-ZZZZZZZZZZZZZZZZZZZZ';
const EVENT_KEY     = 'AIza' + 'B'.repeat(35);
const HOME_PATH     = '/Users/someoperator/work/.env';

const SECRETS = [ANTHROPIC_KEY, AWS_KEY, GITHUB_TOKEN, NESTED_KEY, EVENT_KEY, '/Users/someoperator'];

const TRACE_ID = 'fwdscrub000000000000000000000001';

/** A realistic OTLP/JSON batch carrying a secret at every nesting level. */
function batchWithSecrets(): any {
  return {
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: 'claude-code' } },
            { key: 'host.workdir', value: { stringValue: HOME_PATH } },
          ],
        },
        scopeSpans: [
          {
            scope: { name: 'claudesec', attributes: [{ key: 'api_key', value: { stringValue: ANTHROPIC_KEY } }] },
            spans: [
              {
                spanId: 'fwdscrubspan001',
                traceId: TRACE_ID,
                parentSpanId: '',
                name: `tool_call/Bash ${HOME_PATH}`,
                startTimeUnixNano: '1700000000000000000',
                endTimeUnixNano: '1700000000500000000',
                status: { code: 2, message: `failed reading ${HOME_PATH}` },
                attributes: [
                  { key: 'tool.name', value: { stringValue: 'Bash' } },
                  { key: 'tool.command', value: { stringValue: `export ANTHROPIC_API_KEY=${ANTHROPIC_KEY} && aws configure set ${AWS_KEY}` } },
                  { key: 'authorization', value: { stringValue: BEARER_TOKEN } },
                  // A sensitive KEY holding a non-string value: masked by name.
                  { key: 'session', value: { intValue: '4815162342' } },
                  // Ordinary numeric telemetry: must survive with its type.
                  { key: 'gen_ai.usage.input_tokens', value: { intValue: '1234' } },
                  { key: 'tool.succeeded', value: { boolValue: true } },
                  // Structured value: the secret hides two levels down.
                  {
                    key: 'tool.args',
                    value: {
                      arrayValue: {
                        values: [
                          { stringValue: 'git' },
                          { stringValue: `push https://oauth2:${NESTED_KEY}@gitlab.com/x.git` },
                          { kvlistValue: { values: [{ key: 'ci.token', value: { stringValue: GITHUB_TOKEN } }] } },
                        ],
                      },
                    },
                  },
                ],
                events: [
                  {
                    name: 'tool.result',
                    timeUnixNano: '1700000000400000000',
                    attributes: [{ key: 'result.body', value: { stringValue: `key=${EVENT_KEY}` } }],
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// A structural OTLP conformance check — what a downstream collector requires.
// ---------------------------------------------------------------------------

const ANY_VALUE_FIELDS = ['stringValue', 'boolValue', 'intValue', 'doubleValue', 'arrayValue', 'kvlistValue', 'bytesValue'];

function assertValidOtlp(doc: any, where = 'root'): void {
  assert.ok(doc && typeof doc === 'object', `${where}: not an object`);
  assert.ok(Array.isArray(doc.resourceSpans), `${where}: resourceSpans must be an array`);
  for (const [i, rs] of doc.resourceSpans.entries()) {
    if (rs.resource) assertValidAttributes(rs.resource.attributes, `resourceSpans[${i}].resource`);
    assert.ok(Array.isArray(rs.scopeSpans), `resourceSpans[${i}]: scopeSpans must be an array`);
    for (const [j, ss] of rs.scopeSpans.entries()) {
      if (ss.scope) assertValidAttributes(ss.scope.attributes, `scopeSpans[${j}].scope`);
      assert.ok(Array.isArray(ss.spans), `scopeSpans[${j}]: spans must be an array`);
      for (const [k, span] of ss.spans.entries()) {
        const at = `spans[${k}]`;
        assert.strictEqual(typeof span.spanId, 'string', `${at}: spanId must be a string`);
        assert.strictEqual(typeof span.traceId, 'string', `${at}: traceId must be a string`);
        assert.strictEqual(typeof span.name, 'string', `${at}: name must be a string`);
        assertValidAttributes(span.attributes, at);
        for (const [e, ev] of (span.events ?? []).entries()) assertValidAttributes(ev.attributes, `${at}.events[${e}]`);
        for (const [l, ln] of (span.links ?? []).entries()) assertValidAttributes(ln.attributes, `${at}.links[${l}]`);
      }
    }
  }
}

function assertValidAttributes(attributes: any, where: string): void {
  if (attributes === undefined) return;
  assert.ok(Array.isArray(attributes), `${where}: attributes must be an array`);
  for (const attr of attributes) {
    assert.strictEqual(typeof attr?.key, 'string', `${where}: attribute key must be a string`);
    assert.ok(attr.value && typeof attr.value === 'object' && !Array.isArray(attr.value),
      `${where}.${attr.key}: value must be an AnyValue object, got ${JSON.stringify(attr.value)}`);
    const fields = Object.keys(attr.value).filter(f => ANY_VALUE_FIELDS.includes(f));
    assert.strictEqual(fields.length, 1, `${where}.${attr.key}: AnyValue must carry exactly one field, got ${JSON.stringify(Object.keys(attr.value))}`);
  }
}

function attrOf(doc: any, key: string): any {
  return doc.resourceSpans[0].scopeSpans[0].spans[0].attributes.find((a: any) => a.key === key);
}

// ---------------------------------------------------------------------------

try {
  const opts = loadScrubOptions([]);
  const input = batchWithSecrets();
  const pristine = JSON.stringify(input);
  const forwarded = scrubTraceDataForForward(input, opts) as any;
  const wire = JSON.stringify(forwarded);

  // ── 1. No secret leaves the machine. ─────────────────────────────────────
  for (const secret of SECRETS) {
    check(`forward payload does not contain ${secret.slice(0, 10)}…`, () => {
      assert.ok(!wire.includes(secret), `secret survived scrubbing: ${secret.slice(0, 10)}…`);
    });
  }

  check('the bearer credential is redacted', () => {
    assert.ok(!wire.includes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'bearer token survived scrubbing');
  });

  check('the sensitive-key attribute is masked whatever its type', () => {
    assert.deepStrictEqual(attrOf(forwarded, 'session').value, { stringValue: '***' });
    assert.deepStrictEqual(attrOf(forwarded, 'authorization').value, { stringValue: '***' });
  });

  check('span name and status message are scrubbed', () => {
    const span = forwarded.resourceSpans[0].scopeSpans[0].spans[0];
    assert.ok(!span.name.includes('someoperator'), `span name leaked a home path: ${span.name}`);
    assert.ok(!span.status.message.includes('someoperator'), `status message leaked a home path: ${span.status.message}`);
  });

  // ── 2. The result is still valid OTLP. ───────────────────────────────────
  check('the forwarded payload round-trips as JSON', () => {
    assert.doesNotThrow(() => JSON.parse(wire));
  });

  check('the forwarded payload is structurally valid OTLP', () => {
    assertValidOtlp(JSON.parse(wire));
  });

  check('the OTLP envelope keeps its shape and span count', () => {
    assert.strictEqual(forwarded.resourceSpans.length, 1);
    assert.strictEqual(forwarded.resourceSpans[0].scopeSpans.length, 1);
    assert.strictEqual(forwarded.resourceSpans[0].scopeSpans[0].spans.length, 1);
    assert.strictEqual(forwarded.resourceSpans[0].scopeSpans[0].spans[0].spanId, 'fwdscrubspan001');
    assert.strictEqual(forwarded.resourceSpans[0].scopeSpans[0].spans[0].traceId, TRACE_ID);
  });

  check('non-sensitive numeric and boolean attributes keep their OTLP type', () => {
    assert.deepStrictEqual(attrOf(forwarded, 'gen_ai.usage.input_tokens').value, { intValue: '1234' });
    assert.deepStrictEqual(attrOf(forwarded, 'tool.succeeded').value, { boolValue: true });
  });

  check('a structured attribute keeps its arrayValue / kvlistValue shape', () => {
    const args = attrOf(forwarded, 'tool.args').value;
    assert.ok(Array.isArray(args?.arrayValue?.values), 'arrayValue.values was flattened away');
    assert.strictEqual(args.arrayValue.values.length, 3);
    assert.strictEqual(args.arrayValue.values[0].stringValue, 'git');
    const kv = args.arrayValue.values[2].kvlistValue;
    assert.ok(Array.isArray(kv?.values), 'kvlistValue.values was flattened away');
    assert.strictEqual(kv.values[0].key, 'ci.token');
    assert.ok(!String(kv.values[0].value.stringValue).includes(GITHUB_TOKEN), 'nested token survived');
  });

  check('event attributes are scrubbed and keep their shape', () => {
    const ev = forwarded.resourceSpans[0].scopeSpans[0].spans[0].events[0];
    assert.strictEqual(ev.name, 'tool.result');
    assert.ok(!ev.attributes[0].value.stringValue.includes(EVENT_KEY), 'event attribute leaked a key');
  });

  // ── 3. Forwarded and stored copies agree. ────────────────────────────────
  check('forwarded values match what the ingest path scrubs into the database', () => {
    // ingestSpan() flattens each attribute to key → primitive and hands that map
    // to scrubAttributes(). Re-run exactly that on the raw batch and compare.
    const rawSpan = batchWithSecrets().resourceSpans[0].scopeSpans[0].spans[0];
    const flat: Record<string, unknown> = {};
    for (const attr of rawSpan.attributes) {
      flat[attr.key] = attr.value?.stringValue ?? attr.value?.intValue ?? attr.value?.boolValue ?? JSON.stringify(attr.value);
    }
    const stored = scrubAttributes(flat, opts).attrs;
    for (const key of ['tool.name', 'tool.command', 'authorization', 'session']) {
      assert.strictEqual(
        attrOf(forwarded, key).value.stringValue, String(stored[key]),
        `forwarded and stored values diverged for ${key}`,
      );
    }
  });

  // ── 4. The caller's body is untouched (detection reads the raw one). ─────
  check('the input batch is not mutated', () => {
    assert.strictEqual(JSON.stringify(input), pristine, 'scrubTraceDataForForward mutated its input');
  });

  // ── 5. CLAUDESEC_DISABLE_SCRUB opt-out still forwards raw. ───────────────
  check('a disabled scrubber forwards the body untouched', () => {
    const raw = batchWithSecrets();
    const out = scrubTraceDataForForward(raw, { ...opts, enabled: false });
    assert.strictEqual(out, raw, 'expected the original object back when scrubbing is disabled');
  });

  // ── 6. Degenerate batches do not throw on the ingest path. ───────────────
  check('an empty or malformed batch is passed through without throwing', () => {
    assert.doesNotThrow(() => scrubTraceDataForForward({ resourceSpans: [] } as any, opts));
    assert.doesNotThrow(() => scrubTraceDataForForward({} as any, opts));
    assert.doesNotThrow(() => scrubTraceDataForForward({ resourceSpans: [{}] } as any, opts));
    assert.doesNotThrow(() => scrubTraceDataForForward(
      { resourceSpans: [{ scopeSpans: [{ spans: [{ attributes: 'nope' }] }] }] } as any, opts));
  });
} finally {
  cleanup();
}

const total = passed + failed;
console.log('───────────────────────────────────────────────');
console.log(`  otlpForwardScrubTest: ${passed}/${total} passed`);
console.log('───────────────────────────────────────────────');
if (failed > 0) {
  console.error(`\n  ${failed} FAILURE(S):`);
  for (const f of failures) console.error(`    ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
