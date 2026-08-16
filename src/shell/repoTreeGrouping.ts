import { UNKNOWN_REPO, type Repo } from '../dashboardTypes';

/**
 * The pure grouping logic behind the sidebar repository tree — split out of
 * RepoTree.tsx so it can be unit-tested against real (scrubbed) path shapes
 * without dragging in React or any UI component.
 */

export interface TreeNode {
  /** Path segment shown on the row. */
  name: string;
  /** Full repo key when this node *is* a repository, else undefined. */
  repo?: Repo;
  children: TreeNode[];
}

/**
 * A repo key is a scrubbed filesystem path, e.g. `/Users/***` followed by
 * `reponame/...` — so the username segment is always the literal string
 * `***`, identical across every user's machine and every repo on it. Grouping
 * on raw path segments therefore collapses every repository into the same
 * "Users > ***" node: on a 100-repo install, 97 of them land under one
 * indistinguishable bucket.
 *
 * This drops the segments that carry no information once scrubbed — the
 * redaction marker itself, and the home-directory container name that sits
 * immediately in front of it (`Users` on macOS, `home` on Linux) — so the tree
 * groups on the part of the path that actually tells repos apart.
 */
export function meaningfulSegments(parts: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === '***') continue;
    if (parts[i + 1] === '***' && /^(users|home)$/i.test(part)) continue;
    out.push(part);
  }
  // A bare home directory ("/Users/***" with nothing after it) has no
  // meaningful segments left once both are dropped. Fall back to the raw path
  // so that rare case still shows up in the tree instead of vanishing.
  return out.length > 0 ? out : parts;
}

/**
 * Ninety-eight repositories do not fit in a flat list, and virtualising them is
 * the wrong answer at this size — the tree is what makes them navigable, because
 * repo keys are filesystem paths and already carry the hierarchy. Directories
 * with a single child are folded into their parent so the tree never turns into
 * a column of one-item folders.
 */
export function buildTree(repos: Repo[]): TreeNode[] {
  const root: TreeNode = { name: '', children: [] };
  for (const repo of repos) {
    if (repo.repo === UNKNOWN_REPO) { root.children.push({ name: repo.repo, repo, children: [] }); continue; }
    const rawParts = repo.repo.replace(/[/\\]+$/, '').split(/[/\\]/).filter(Boolean);
    const parts = meaningfulSegments(rawParts);
    let node = root;
    parts.forEach((part, i) => {
      const leaf = i === parts.length - 1;
      let child = node.children.find(c => c.name === part && (leaf ? !!c.repo : !c.repo));
      if (!child) {
        child = { name: part, children: [] };
        node.children.push(child);
      }
      if (leaf) child.repo = repo;
      node = child;
    });
  }
  const fold = (node: TreeNode): TreeNode => {
    let current = node;
    while (!current.repo && current.children.length === 1) {
      const only = current.children[0];
      current = { name: `${current.name}/${only.name}`, repo: only.repo, children: only.children };
    }
    return { ...current, children: current.children.map(fold) };
  };
  return root.children.map(fold);
}
