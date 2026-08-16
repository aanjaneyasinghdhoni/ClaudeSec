/**
 * tests/sessionLabelTest.ts
 *
 * Unit gate for sessionDisplayLabel() in src/dashboardTypes.ts — the function
 * that turns "Claude Code · 11:17:10 AM" into "ClaudeSec · 11:17 AM" so
 * 6,500 sessions in the same harness stop reading as identical rows.
 *
 * The bug this guards against: a naive "always compose from repo" version
 * would stomp a user's own rename the instant they gave a session a real
 * name, because the derivation has no way to tell "chosen" apart from
 * "default" without a rule. isAutoSessionName() is that rule, and this file
 * is what proves it holds for every shape server/index.ts actually writes,
 * plus the data-quality edges (no repo, several repos) the live migration
 * exposed.
 *
 * Deliberately hermetic — imports only the pure module, never
 * src/shell/SessionList.tsx, which pulls in React and shadcn UI components.
 * No DOM, no React, no network.
 *
 * Run via:  npx tsx tests/sessionLabelTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 */
import assert from 'node:assert';
import {
  isAutoSessionName, sessionDisplayLabel, sessionRepos, type Session,
} from '../src/dashboardTypes.ts';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    failures.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

const CREATED_AT = '2026-08-15T18:17:10.000Z';
// toLocaleTimeString() renders in the machine's local timezone, so the exact
// clock string it produces depends on where this test runs — computed here
// with the same call sessionDisplayLabel() makes internally, rather than a
// hardcoded string, so the assertions hold in CI regardless of TZ.
const EXPECTED_TIME = new Date(CREATED_AT).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

// Minimal fixture — sessionDisplayLabel only reads name/repo/createdAt.
function session(over: Partial<Pick<Session, 'name' | 'repo' | 'createdAt'>>): Pick<Session, 'name' | 'repo' | 'createdAt'> {
  return {
    name: 'Claude Code · 11:17:10 AM',
    repo: null,
    createdAt: CREATED_AT,
    ...over,
  };
}

// ── isAutoSessionName: the gate that decides whether a rename survives ──────
check('recognizes the "<harness> · <time>" default', () => {
  assert.strictEqual(isAutoSessionName('Claude Code · 11:17:10 AM'), true);
  assert.strictEqual(isAutoSessionName('Codex · 7:38:57 AM'), true);
  assert.strictEqual(isAutoSessionName('GitHub Copilot CLI · 10:02:19 PM'), true);
});
check('recognizes the PID auto-detect shape', () => {
  assert.strictEqual(isAutoSessionName('Claude Code · PID 2985 (auto-detected)'), true);
});
check('recognizes the Import shape', () => {
  assert.strictEqual(isAutoSessionName('Import · 11:17:10 AM'), true);
});
check('a genuine user rename never matches', () => {
  assert.strictEqual(isAutoSessionName('Investigating the curl exfil attempt'), false);
  assert.strictEqual(isAutoSessionName('Refactor auth module'), false);
  // Coincidentally contains " · " but not a time or PID shape — still a real name.
  assert.strictEqual(isAutoSessionName('Prod incident · root caused'), false);
});

// ── sessionRepos: splits the newline-joined repo_agg column, drops 'unknown' ─
check('sessionRepos drops the unknown bucket and empty entries', () => {
  assert.deepStrictEqual(sessionRepos('unknown'), []);
  assert.deepStrictEqual(sessionRepos(null), []);
  assert.deepStrictEqual(sessionRepos('/Users/***/ClaudeSec\nunknown'), ['/Users/***/ClaudeSec']);
});

// ── sessionDisplayLabel: repo present ───────────────────────────────────────
check('a single known repo becomes "<repo> · <time>"', () => {
  const s = session({ repo: '/Users/***/code/alpha/alpha-service' });
  assert.strictEqual(sessionDisplayLabel(s), `alpha-service · ${EXPECTED_TIME}`);
});

// ── repo unknown ─────────────────────────────────────────────────────────────
check('no known repo says so honestly instead of guessing', () => {
  const s = session({ repo: 'unknown' });
  assert.strictEqual(sessionDisplayLabel(s), `Unknown repo · ${EXPECTED_TIME}`);
});
check('a null repo (no span data yet) is the same as unknown', () => {
  const s = session({ repo: null });
  assert.strictEqual(sessionDisplayLabel(s), `Unknown repo · ${EXPECTED_TIME}`);
});

// ── multi-repo: counted, never guessed at ───────────────────────────────────
check('several distinct repos are counted, not collapsed into one', () => {
  const repos = Array.from({ length: 26 }, (_, i) => `/Users/***/repo-${i}`).join('\n');
  const s = session({ repo: repos });
  assert.strictEqual(sessionDisplayLabel(s), `26 repos · ${EXPECTED_TIME}`);
});
check('the unknown bucket does not inflate the multi-repo count', () => {
  const s = session({ repo: '/Users/***/a\n/Users/***/b\nunknown' });
  assert.strictEqual(sessionDisplayLabel(s), `2 repos · ${EXPECTED_TIME}`);
});

// ── user-renamed sessions win, unconditionally ──────────────────────────────
check('a user rename is returned verbatim, repo data ignored entirely', () => {
  const s = session({
    name: 'Investigating the curl exfil attempt',
    repo: '/Users/***/ClaudeSec',
  });
  assert.strictEqual(sessionDisplayLabel(s), 'Investigating the curl exfil attempt');
});
check('a rename survives even when the session has no repo data at all', () => {
  const s = session({ name: 'Quarterly audit prep', repo: null });
  assert.strictEqual(sessionDisplayLabel(s), 'Quarterly audit prep');
});

// ── a very long repo path reduces to its basename, not the whole path ──────
check('a very long repo path composes from the basename only', () => {
  const longPath = '/Users/***/some-extremely-long-organization-name/'
    + 'a-second-extremely-long-nested-folder-that-keeps-going-and-going/'
    + 'finally-the-actual-repository-name-lives-here';
  const s = session({ repo: longPath });
  assert.strictEqual(
    sessionDisplayLabel(s),
    `finally-the-actual-repository-name-lives-here · ${EXPECTED_TIME}`,
    'the label should carry only the last path segment, not the full scrubbed path',
  );
});

// ── report ───────────────────────────────────────────────────────────────────
console.log(`\nsessionLabelTest: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error('\nFailures:');
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
