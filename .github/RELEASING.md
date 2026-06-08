# Releasing ClaudeSec

This is the release runbook. It exists so that every release — even a one-line fix —
ships with everything else updated to match: version, changelog, docs, and the figures
the docs quote. The whole flow is one command; the rest is a short checklist.

## Principles

- **Semantic Versioning.** `MAJOR.MINOR.PATCH`. Breaking change → MAJOR, new feature →
  MINOR, fix → PATCH. `package.json` is the single source of truth for the version.
- **Conventional Commits.** Commit messages describe the release. The type/scope tell you
  which version bump to choose and which changelog section the change belongs under, so
  keep them accurate:

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

## How a release happens

Releases are cut locally, from the maintainer's machine, with a single command:

```bash
./scripts/release.sh <patch|minor|major>
```

Choose the bump from the highest-impact change since the last release (`major` for a
breaking change, `minor` for a new feature, `patch` for fixes only).

The script does the whole release in order, and stops to ask before anything is pushed:

1. **Safety checks.** Aborts unless you are on `master`, the working tree is clean, and
   your branch is in sync with `origin/master` (it fetches first).
2. **Computes the next version** from the bump argument and the current `package.json`.
3. **Runs `pnpm preflight`** (the full local CI: lint, test, build, consistency gate, and
   dependency audit). A failure here stops the release before any file is touched.
4. **Bumps the version** in `package.json` and `openapi.yaml` (`info.version`).
5. **Updates `CHANGELOG.md`:** renames the `## [Unreleased]` heading to
   `## [X.Y.Z] - <date>`, opens a fresh empty `## [Unreleased]` above it, and refreshes the
   compare/tag links at the bottom.
6. **Re-runs the consistency gate** to confirm everything agrees on the new version.
7. **Shows a `git diff --stat` and prompts for confirmation.** Only on an explicit `yes`
   does it commit (`chore: release vX.Y.Z`), create an annotated tag `vX.Y.Z`, push
   `master` and the tag, and publish the GitHub Release with the new changelog section as
   the notes. It never force-pushes.
8. **Prints a summary and the release URL.**

Tags and the GitHub Release page are created only by this script — never hand-create or
move a tag.

## Pre-release checklist

The script enforces version/changelog/rule-count consistency for you. Before you run it,
confirm the things automation can't:

- [ ] CI is green on `master`.
- [ ] The `## [Unreleased]` section of `CHANGELOG.md` reads cleanly and is written for
      users (what changed and why), not for maintainers — this becomes the release notes
      verbatim.
- [ ] Every doc that quotes a changed fact is updated **in the same release**:
  - Rule counts (`~630` total / `~183` core / `~447` extra) in `README.md`, `docs/`, and
    `COMPLIANCE.md` if the detection set changed.
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
[`ci.yml`](workflows/ci.yml)) and again inside `release.sh`, and **fails the build** when:

1. `package.json` and `openapi.yaml` disagree on the version.
2. `CHANGELOG.md` has no section for the current version.
3. The `~core` / `~extra` / `~total` rule counts in `README.md` drift more than 5% from the
   real number of rules in `server/detection.ts` + `server/severityRulesExtra.ts`.

This is what makes "update everything" a rule and not a hope.
