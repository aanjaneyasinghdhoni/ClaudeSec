# Releasing ClaudeSec

This is the release runbook. It exists so that every release — even a one-line fix —
ships with everything else updated to match: version, changelog, docs, and the figures
the docs quote. Most of it is automated; the rest is a short checklist.

## Principles

- **Semantic Versioning.** `MAJOR.MINOR.PATCH`. Breaking change → MAJOR, new feature →
  MINOR, fix → PATCH. `package.json` is the single source of truth for the version.
- **Conventional Commits.** Commit messages drive the release. The type/scope decide the
  version bump and the changelog section, so they have to be accurate:

  | Commit type | Changelog section | Version effect |
  |---|---|---|
  | `feat:` | Added | minor |
  | `fix:` | Fixed | patch |
  | `perf:` | Performance | patch |
  | `refactor:` | Changed | patch |
  | `docs:` | Documentation | patch |
  | `security:` | Security | patch |
  | `build:` | Build System | patch |
  | `feat!:` / `fix!:` / `BREAKING CHANGE:` | — | major |
  | `ci:` `test:` `chore:` | hidden | none |

- **No release ships with stale docs.** This is the hard rule. CI enforces the parts it
  can (see [Consistency gate](#consistency-gate)); the [checklist](#pre-release-checklist)
  covers the rest.

## How a release happens (the normal path)

Releases are automated with [release-please](https://github.com/googleapis/release-please).

1. **Land work on `master`** as Conventional Commits (via PRs).
2. release-please keeps an open **"chore: release X.Y.Z"** pull request that accumulates the
   pending changes — it bumps `package.json` and rewrites the top of `CHANGELOG.md` from the
   commit history. Review it as the human-readable preview of the next release.
3. **Merge the release PR.** On merge, release-please creates the git tag (`vX.Y.Z`) and the
   **GitHub Release** page with the generated notes. Tags and the Release page are managed
   only this way — never hand-create or move a tag.

## Pre-release checklist

Before merging the release PR, confirm the things automation can't:

- [ ] `pnpm lint`, `pnpm test`, and `pnpm build` are green; CI is green on `master`.
- [ ] The CHANGELOG entry reads cleanly and is written for users (what changed and why),
      not for maintainers.
- [ ] Every doc that quotes a changed fact is updated **in the same release**:
  - Rule counts (`~630` total / `~183` core / `~447` extra) in `README.md`, `docs/`, and
    `COMPLIANCE.md` if the detection set changed.
  - `openapi.yaml` `info.version` (the consistency gate checks this against `package.json`).
  - Supported harnesses, env vars, and badges if any changed.
  - `COMPLIANCE.md` control mappings if security/data-handling behavior changed.
- [ ] No new secrets, local paths, or generated artifacts are tracked (`git status` clean).

Quick drift scan:

```bash
node scripts/check-consistency.mjs        # the same check CI runs
git grep -nE '~?[0-9]{3}\s+(built-in|core|extra|total)' README.md docs COMPLIANCE.md
```

## Consistency gate

`scripts/check-consistency.mjs` runs in CI (the `consistency` job in
[`ci.yml`](workflows/ci.yml)) and **fails the build** when:

1. `package.json` and `openapi.yaml` disagree on the version.
2. `CHANGELOG.md` has no section for the current version.
3. The `~core` / `~extra` / `~total` rule counts in `README.md` drift more than 5% from the
   real number of rules in `server/detection.ts` + `server/severityRulesExtra.ts`.

This is what makes "update everything" a rule and not a hope.

## Manual / hotfix release

If you need to cut a release without the bot (e.g. an urgent fix), do it by hand and keep
everything in sync:

```bash
# 1. Bump the version (updates package.json)
npm version patch --no-git-tag-version    # or: minor / major

# 2. Update CHANGELOG.md (move [Unreleased] entries under the new version + date)
#    and openapi.yaml info.version to match. Run the gate:
node scripts/check-consistency.mjs

# 3. Commit, tag, push
git commit -am "chore: release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push && git push --tags

# 4. Publish the GitHub Release page from the tag + changelog
gh release create vX.Y.Z --title "vX.Y.Z" --notes-from-tag
```

After a manual release, update `.release-please-manifest.json` to the new version so the bot
picks up cleanly next time.
