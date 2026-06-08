#!/usr/bin/env bash
#
# One-command local release for ClaudeSec.
#
#   ./scripts/release.sh <patch|minor|major>
#
# Releases are cut from a maintainer's own machine rather than a CI bot, so the
# whole flow lives here: it runs the full local CI (`pnpm preflight`), bumps the
# version everywhere it is recorded, writes the changelog, re-runs the
# consistency gate, and — only after you confirm — commits, tags, pushes, and
# publishes the GitHub Release.
#
# Why a script instead of automation: every fact that describes a release
# (package.json version, openapi.yaml version, CHANGELOG entry, git tag, GitHub
# Release) must move together. Doing them by hand drifts; doing them here keeps
# them in lockstep and stops before anything is pushed so you can review.
#
# Safe by design: it refuses to run unless you are on an up-to-date `master`
# with a clean tree, it never force-pushes, and it asks before the first push.

set -euo pipefail

# --- helpers ----------------------------------------------------------------

# Colourless, prefixed output so the important lines stand out in a plain
# terminal and in CI logs alike.
info()  { printf '  %s\n' "$*"; }
step()  { printf '\n==> %s\n' "$*"; }
fail()  { printf '\nError: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/release.sh <patch|minor|major>

  patch   bug fixes only            (X.Y.Z -> X.Y.Z+1)
  minor   new, backwards-compatible (X.Y.Z -> X.Y+1.0)
  major   breaking changes          (X.Y.Z -> X+1.0.0)
EOF
  exit 2
}

# Run all repo-relative commands from the project root, no matter where the
# script is invoked from.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- 0. validate the bump argument ------------------------------------------

BUMP="${1:-}"
case "$BUMP" in
  patch|minor|major) ;;
  *) usage ;;
esac

# --- 1. safety: branch, clean tree, in sync with origin ---------------------

step "Checking release preconditions"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "master" ] || fail "releases must be cut from 'master' (you are on '$BRANCH')."

# A dirty tree means uncommitted work would silently ride along — or be lost.
if ! git diff-index --quiet HEAD --; then
  fail "working tree is not clean. Commit or stash your changes first."
fi

# Compare against the real remote state, not a stale local ref.
info "Fetching origin..."
git fetch --quiet origin master

LOCAL="$(git rev-parse @)"
REMOTE="$(git rev-parse origin/master)"
BASE="$(git merge-base @ origin/master)"

if [ "$LOCAL" != "$REMOTE" ]; then
  if [ "$LOCAL" = "$BASE" ]; then
    fail "local 'master' is behind origin/master. Run 'git pull' first."
  elif [ "$REMOTE" = "$BASE" ]; then
    fail "local 'master' is ahead of origin/master. Push your commits first."
  else
    fail "local and origin/master have diverged. Reconcile them before releasing."
  fi
fi
info "On master, clean, in sync with origin."

# --- 2. read current version, compute the next one --------------------------

step "Computing next version"

CURRENT="$(node -p "require('./package.json').version")"
[ -n "$CURRENT" ] || fail "could not read version from package.json."

# Split MAJOR.MINOR.PATCH and apply the requested bump. Pure SemVer arithmetic,
# no npm — pnpm is the package manager here and we want no surprises.
IFS='.' read -r MAJOR MINOR PATCH <<EOF
$CURRENT
EOF
case "$BUMP" in
  patch) PATCH=$((PATCH + 1)) ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
esac
NEXT="${MAJOR}.${MINOR}.${PATCH}"
TAG="v${NEXT}"
TODAY="$(date +%F)"

# Derive the canonical repo URL from package.json so links never hardcode a fork.
REPO_URL="$(node -p "require('./package.json').repository.url.replace(/^git\+/, '').replace(/\.git$/, '')")"

info "Current: $CURRENT"
info "Next:    $NEXT  (tag $TAG)"

# Refuse to clobber a tag that already exists locally or on the remote.
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag $TAG already exists locally."
fi
if git ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  fail "tag $TAG already exists on origin."
fi

# --- 3. full local CI -------------------------------------------------------

step "Running pnpm preflight (full local CI)"
# preflight = lint + test + build + consistency + dependency audit. If anything
# is wrong with the code we want to know now, before we touch any version.
pnpm preflight || fail "preflight failed. Fix the issues above before releasing."

# --- 4. bump version in package.json and openapi.yaml -----------------------

step "Bumping version to $NEXT"

# Edit both files in Node (always available; no sed -i portability differences
# between BSD/macOS and GNU/Linux). Targeted replacements only — we never
# reformat the surrounding file.
NEXT="$NEXT" CURRENT="$CURRENT" node <<'NODE'
const fs = require('node:fs');
const next = process.env.NEXT;
const current = process.env.CURRENT;

// package.json: replace only the top-level "version" field value.
const pkg = fs.readFileSync('package.json', 'utf8');
const pkgOut = pkg.replace(
  new RegExp(`("version":\\s*")${current.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(")`),
  `$1${next}$2`,
);
if (pkgOut === pkg) throw new Error('package.json version line not found');
fs.writeFileSync('package.json', pkgOut);

// openapi.yaml: replace the two-space-indented `version:` inside info:. This is
// the exact line the consistency gate reads, so keep the indentation intact.
const api = fs.readFileSync('openapi.yaml', 'utf8');
const apiOut = api.replace(/^( {2}version:\s*).*$/m, `$1${next}`);
if (apiOut === api) throw new Error('openapi.yaml version line not found');
fs.writeFileSync('openapi.yaml', apiOut);
NODE
info "package.json and openapi.yaml set to $NEXT"

# --- 5. update CHANGELOG.md -------------------------------------------------

step "Updating CHANGELOG.md"

# Three coordinated edits, done in Node so dots in version strings are never
# treated as regex wildcards:
#   1. Turn the existing "## [Unreleased]" heading into the dated release
#      heading, and insert a fresh empty "## [Unreleased]" above it. The entries
#      already written under Unreleased thereby become this release's notes.
#   2. Point the [Unreleased] compare link at the new tag.
#   3. Add a [X.Y.Z] link to the release tag.
NEXT="$NEXT" TODAY="$TODAY" REPO_URL="$REPO_URL" node <<'NODE'
const fs = require('node:fs');
const next = process.env.NEXT;
const today = process.env.TODAY;
const repo = process.env.REPO_URL;

let cl = fs.readFileSync('CHANGELOG.md', 'utf8');

// 1. Rename Unreleased -> versioned section, add a new empty Unreleased above.
const unreleased = '## [Unreleased]';
if (!cl.includes(unreleased)) throw new Error('CHANGELOG.md has no "## [Unreleased]" heading');
cl = cl.replace(
  unreleased,
  `## [Unreleased]\n\n## [${next}] - ${today}`,
);

// 2 & 3. Refresh the compare/tag links at the bottom of the file.
const unreleasedLink = new RegExp(`^\\[Unreleased\\]:.*$`, 'm');
if (!unreleasedLink.test(cl)) throw new Error('CHANGELOG.md has no [Unreleased] link line');
cl = cl.replace(
  unreleasedLink,
  `[Unreleased]: ${repo}/compare/v${next}...HEAD\n[${next}]: ${repo}/releases/tag/v${next}`,
);

fs.writeFileSync('CHANGELOG.md', cl);
NODE
info "CHANGELOG.md now has a [$NEXT] section dated $TODAY"

# --- 6. confirm consistency -------------------------------------------------

step "Re-checking release-fact consistency"
# Proves package.json, openapi.yaml, and CHANGELOG.md now agree on $NEXT.
node scripts/check-consistency.mjs || fail "consistency check failed after the bump."

# --- 7. review, confirm, then commit / tag / push / publish -----------------

step "Review the staged release"
git --no-pager diff --stat

# Extract this release's changelog body (between the new "## [X.Y.Z]" heading and
# the next "## [" heading) for the GitHub Release notes. awk with a literal
# index() match avoids treating version dots as regex wildcards.
NOTES_FILE="$(mktemp)"
TRIMMED="$(mktemp)"
trap 'rm -f "$NOTES_FILE" "$TRIMMED"' EXIT
NEXT="$NEXT" awk '
  BEGIN { start = "## [" ENVIRON["NEXT"] "]"; capture = 0 }
  index($0, start) == 1 { capture = 1; next }
  capture && index($0, "## [") == 1 { exit }
  capture { print }
' CHANGELOG.md > "$NOTES_FILE"
# Trim leading and trailing blank lines so the Release page reads cleanly.
awk 'NF { p = 1 } p { print }' "$NOTES_FILE" \
  | awk '{ lines[NR] = $0 } END { last = NR; while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--; for (i = 1; i <= last; i++) print lines[i] }' \
  > "$TRIMMED"
mv "$TRIMMED" "$NOTES_FILE"
# $TRIMMED was moved onto $NOTES_FILE; keep the trap simple and idempotent.
TRIMMED="$NOTES_FILE"

printf '\n'
# Default to "no": pressing Enter (or EOF, e.g. a non-interactive shell) aborts.
# Nothing is pushed without a clear yes. The `|| REPLY=""` keeps an EOF from
# tripping `set -e` so we fall through to the friendly abort message below.
REPLY=""
read -r -p "Commit, tag, push, and publish $TAG? [y/N] " REPLY || REPLY=""
case "$REPLY" in
  [yY]|[yY][eE][sS]) ;;
  *) fail "aborted before any push. The version/changelog edits are left in your working tree for review." ;;
esac

step "Committing and tagging"
git commit -am "chore: release ${TAG}"
# Annotated tag so the release carries a message and shows up in `git describe`.
git tag -a "$TAG" -m "$TAG"

step "Pushing master and $TAG"
# Plain pushes only — never --force. A rejected push means someone else moved
# master; reconcile by hand rather than overwriting their work.
git push origin master
git push origin "$TAG"

step "Publishing GitHub Release"
gh release create "$TAG" --title "$TAG" --notes-file "$NOTES_FILE"

RELEASE_URL="$(gh release view "$TAG" --json url --jq .url 2>/dev/null || echo "${REPO_URL}/releases/tag/${TAG}")"

step "Done"
info "Released $TAG"
info "Tag:     $TAG"
info "Release: $RELEASE_URL"
