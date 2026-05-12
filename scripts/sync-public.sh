#!/bin/sh
# Rebuild the local `public` branch as a SINGLE clean commit reflecting the
# current state of `main`, with private paths stripped, then push to the
# `public` remote as `main`.
#
# Each release should look like one commit on github.com/projectwarden/warden,
# not the messy work history from `main`. We achieve this by always rebuilding
# `public` as an orphan branch with a single "release: ..." commit.
#
# Usage:
#   ./scripts/sync-public.sh                  # rebuild + push to public/main
#   ./scripts/sync-public.sh --no-push        # rebuild only, do not push
#   ./scripts/sync-public.sh -m "release: v1.0.1"   # custom commit message
#
# Run from the repo root. Assumes:
#   - You are currently on `main` with a clean working tree
#   - `public` and `private` remotes exist
#   - The default commit message is "release: warden <version>" pulled from Cargo.toml

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# --------------- arg parsing ---------------
NO_PUSH=0
COMMIT_MSG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-push) NO_PUSH=1; shift ;;
    -m) COMMIT_MSG="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$COMMIT_MSG" ]; then
  VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)"$/\1/')
  COMMIT_MSG="release: warden v$VERSION"
fi

# --------------- safety checks ---------------
if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree has uncommitted changes. Commit or stash first." >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "main" ]; then
  echo "error: must be on main, currently on $CURRENT_BRANCH" >&2
  exit 1
fi

# Capture the main HEAD so we can checkout files from it later.
MAIN_SHA="$(git rev-parse HEAD)"

echo ">>> Rebuilding the local 'public' branch as a single clean commit..."

# Delete the old local public branch entirely. We are going to rebuild it as
# an orphan so the public repo only sees one commit per release, never the
# messy work history from main.
git branch -D public 2>/dev/null || true

# Create a brand new orphan branch (no parent, no history).
git checkout --orphan public

# Stage everything from main, then strip private paths.
git checkout "$MAIN_SHA" -- .
# Files and dirs that must never reach projectwarden/warden. If you add a
# new one, bump the sanity-check regex below too.
git rm -rf --quiet --ignore-unmatch \
  web/ \
  .local/ \
  CLAUDE.md \
  RELEASE.md \
  USER_TODO.md \
  SECURITY-AUDIT-WEB.md \
  docs/internal/ \
  .github/workflows/deploy-web.yml

# Clean any on-disk remnants that git rm missed (e.g. files only in
# nested .gitignore scopes like web/.clerk/). Without this, git add -A
# below would re-add them. git clean -fdx scours untracked files too.
git clean -fdx -- web/ .local/ >/dev/null 2>&1 || true
rm -rf web/ .local/ 2>/dev/null || true

# Stage what's left and commit it as the single release commit.
git add -A
git -c user.email="warden@projectwarden.dev" -c user.name="warden" \
  commit --quiet -m "$COMMIT_MSG"

# Sanity check: make absolutely sure no private paths slipped in.
LEAKED="$(git ls-tree -r HEAD --name-only | grep -E '^(web/|\.local/|CLAUDE\.md|RELEASE\.md|USER_TODO\.md|SECURITY-AUDIT-WEB\.md|docs/internal/|\.github/workflows/deploy-web\.yml)' || true)"
if [ -n "$LEAKED" ]; then
  echo "error: public branch contains private paths after strip:" >&2
  echo "$LEAKED" >&2
  git checkout main
  exit 1
fi

FILE_COUNT=$(git ls-tree -r HEAD --name-only | wc -l)
echo ">>> public branch rebuilt as single commit ($FILE_COUNT files): $COMMIT_MSG"

if [ "$NO_PUSH" -eq 0 ]; then
  echo ">>> Force-pushing public:main to public remote..."
  # --force-with-lease is safer than --force, but on an orphan rebuild the
  # remote ref bears no relation to local history, so we use --force.
  git push public public:main --force
fi

git checkout main
echo ">>> Done. You are back on main."
echo ""
echo "Next steps:"
echo "  1. Watch CI on https://github.com/projectwarden/warden/actions"
echo "  2. Add CARGO_REGISTRY_TOKEN secret in repo Settings -> Secrets -> Actions"
PUBLISHED_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)"$/\1/')
echo "  3. git tag v$PUBLISHED_VERSION public"
echo "  4. git push public v$PUBLISHED_VERSION"
