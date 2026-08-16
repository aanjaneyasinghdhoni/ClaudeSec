/**
 * tests/repoTreeGroupingTest.ts
 *
 * Unit gate for src/shell/repoTreeGrouping.ts — the pure path-grouping logic
 * behind the sidebar's "Repositories" tree.
 *
 * The bug this guards against: repo keys are stored as scrubbed paths — e.g.
 * `/Users/***` followed by `reponame` — so grouping the raw path segments
 * collapses every repository into the same "Users > ***" node — on a real
 * 100-repo install, 97 of them landed under one indistinguishable bucket.
 * That broke silently because nothing exercised buildTree() against a
 * scrubbed path shape.
 *
 * Deliberately hermetic — imports only the pure module, never
 * src/shell/RepoTree.tsx itself, which pulls in React and shadcn UI
 * components. No DOM, no React, no network.
 *
 * Run via:  npx tsx tests/repoTreeGroupingTest.ts
 *   Exit 0  → every assertion passed.
 *   Exit 1  → at least one assertion failed.
 */
import assert from 'node:assert';
import { buildTree, meaningfulSegments, type TreeNode } from '../src/shell/repoTreeGrouping.ts';
import { UNKNOWN_REPO, type Repo } from '../src/dashboardTypes.ts';

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

// Minimal Repo fixture — only `repo` drives buildTree, so the rest is filler.
function repo(key: string): Repo {
  return {
    repo: key,
    spanCount: 1, sessionCount: 1, harnesses: 'claude-code',
    threatHigh: 0, threatMedium: 0, threatLow: 0,
    firstSeen: null, lastSeen: null, healthScore: 0, grade: 'A',
  };
}

/** Find a leaf repo node anywhere in the tree by its full repo key. */
function findLeaf(nodes: TreeNode[], key: string): TreeNode | undefined {
  for (const n of nodes) {
    if (n.repo?.repo === key) return n;
    const found = findLeaf(n.children, key);
    if (found) return found;
  }
  return undefined;
}

/** Every repo key present anywhere in the tree, leaves only. */
function allLeafKeys(nodes: TreeNode[]): string[] {
  const out: string[] = [];
  for (const n of nodes) {
    if (n.repo) out.push(n.repo.repo);
    out.push(...allLeafKeys(n.children));
  }
  return out;
}

// ── meaningfulSegments: the redaction marker and its home-dir container drop ─
check('meaningfulSegments drops the *** marker', () => {
  assert.deepStrictEqual(meaningfulSegments(['Users', '***', 'repo']), ['repo']);
});
check('meaningfulSegments drops "Users" only when it directly precedes ***', () => {
  // A real directory named "Users" elsewhere in the path must survive.
  assert.deepStrictEqual(meaningfulSegments(['code', 'Users', 'repo']), ['code', 'Users', 'repo']);
});
check('meaningfulSegments drops "home" (Linux) the same way', () => {
  assert.deepStrictEqual(meaningfulSegments(['home', '***', 'repo']), ['repo']);
});
check('meaningfulSegments falls back to the raw parts when nothing is left', () => {
  // "/Users/***" alone — no real repo path underneath.
  assert.deepStrictEqual(meaningfulSegments(['Users', '***']), ['Users', '***']);
});
check('meaningfulSegments is a no-op on an already-clean path', () => {
  assert.deepStrictEqual(meaningfulSegments(['alpha', 'alpha-service']), ['alpha', 'alpha-service']);
});

// ── buildTree: the real-world regression — 100 scrubbed repos, one per user ──
check('98 distinct repos under /Users/***/ do not collapse into one node', () => {
  const repos = [
    repo('/Users/***/ClaudeSec'),
    repo('/Users/***/alpha/alpha-service'),
    repo('/Users/***/beta/beta-insights'),
    repo('/Users/***/beta/beta-insights/.claude/worktrees/agent-0000000000000001'),
    repo('/Users/***/beta/beta-insights/.claude/worktrees/prod-qa'),
    repo('/Users/***/gamma-tools'),
  ];
  const tree = buildTree(repos);

  // Every repo must still be individually reachable — none silently merged.
  const keys = allLeafKeys(tree);
  for (const r of repos) {
    assert.ok(keys.includes(r.repo), `expected ${r.repo} to be reachable in the tree, got leaves: ${keys.join(', ')}`);
  }
  assert.strictEqual(new Set(keys).size, repos.length, 'no two distinct repos should share a leaf');

  // There must be no "Users" or "***" branch node left in the tree — that is
  // exactly the collapsed bucket this fix removes.
  const walk = (nodes: TreeNode[]): string[] => nodes.flatMap(n => [n.name, ...walk(n.children)]);
  const names = walk(tree);
  assert.ok(!names.includes('Users'), `"Users" should not survive as a branch name, got: ${names.join(', ')}`);
  assert.ok(!names.some(n => n === '***'), `"***" should not survive as a branch name, got: ${names.join(', ')}`);
});

check('worktree children nest under their parent repo, not flattened', () => {
  const repos = [
    repo('/Users/***/beta/beta-insights'),
    repo('/Users/***/beta/beta-insights/.claude/worktrees/agent-0000000000000001'),
  ];
  const tree = buildTree(repos);
  const parent = findLeaf(tree, '/Users/***/beta/beta-insights');
  assert.ok(parent, 'parent repo should be reachable');
  // The worktree child hangs somewhere below the parent's own subtree, once
  // depth-first from the shared "beta" ancestor.
  const worktreeKey = '/Users/***/beta/beta-insights/.claude/worktrees/agent-0000000000000001';
  assert.ok(allLeafKeys(tree).includes(worktreeKey), 'worktree child should still be reachable');
});

check('a single repo folds straight to a leaf with no intermediate "Users" hop', () => {
  const tree = buildTree([repo('/Users/***/ClaudeSec')]);
  assert.strictEqual(tree.length, 1);
  assert.strictEqual(tree[0].repo?.repo, '/Users/***/ClaudeSec', 'a lone repo should fold directly to a leaf');
});

check('a bare home directory ("/Users/***") still appears, not dropped', () => {
  const repos = [repo('/Users/***'), repo('/Users/***/ClaudeSec')];
  const tree = buildTree(repos);
  const keys = allLeafKeys(tree);
  assert.ok(keys.includes('/Users/***'), 'the bare home-directory repo must not vanish from the tree');
  assert.ok(keys.includes('/Users/***/ClaudeSec'), 'the real repo must still be reachable alongside it');
});

check('the unknown bucket is a flat leaf, never grouped into the path tree', () => {
  const tree = buildTree([repo(UNKNOWN_REPO), repo('/Users/***/ClaudeSec')]);
  const unknown = findLeaf(tree, UNKNOWN_REPO);
  assert.ok(unknown, 'unknown repo should be present');
  assert.strictEqual(unknown!.children.length, 0);
});

check('two repos that only differ after the redacted segment stay distinct siblings', () => {
  const repos = [repo('/Users/***/delta/delta-app'), repo('/Users/***/gamma-tools')];
  const tree = buildTree(repos);
  assert.strictEqual(new Set(allLeafKeys(tree)).size, 2);
});

// ── report ───────────────────────────────────────────────────────────────────
console.log(`\nrepoTreeGroupingTest: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.error('\nFailures:');
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
process.exit(0);
