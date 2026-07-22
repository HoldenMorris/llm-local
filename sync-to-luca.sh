#!/usr/bin/env bash
# Publish this toolkit's committed files into luca-ecosystem/tools/local-llm on a fresh
# branch, ready for a PR. THIS repo stays the source of truth; the luca copy is a
# point-in-time snapshot -- never hand-edit it there, re-run this after committing here.
#
#   ./sync-to-luca.sh                     # branch local-llm-sync-<sha>, push, print PR URL
#   ./sync-to-luca.sh my-branch           # a specific branch name (reuse to update a PR)
#   FORCE=1 ./sync-to-luca.sh my-branch   # overwrite an existing remote branch
#   DRY_RUN=1 ./sync-to-luca.sh           # build + commit locally, don't push (self-check)
set -euo pipefail

REPO="${LUCA_REPO:-git@bitbucket.org:synaq/luca-ecosystem.git}"
SUBPATH="tools/local-llm"
EMAIL="${GIT_EMAIL:-holdenm@synaq.com}"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHA="$(git -C "$SRC" rev-parse --short HEAD)"
BRANCH="${1:-local-llm-sync-$SHA}"

# The snapshot is HEAD (git archive) -- a dirty tree would silently ship stale files.
if ! git -C "$SRC" diff --quiet || ! git -C "$SRC" diff --cached --quiet; then
  echo "error: uncommitted changes in $SRC -- commit first (the snapshot exports HEAD)" >&2
  exit 1
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
echo ">> cloning $REPO (shallow)"
git clone --depth 1 "$REPO" "$WORK/luca" >/dev/null 2>&1
cd "$WORK/luca"
git config user.email "$EMAIL"
git config user.name "$(git -C "$SRC" config user.name || echo 'Holden Morris')"
git checkout -b "$BRANCH" >/dev/null 2>&1

# Replace the whole subtree from this repo's HEAD. archive = tracked files only, so no
# .env / .cache / .git ever leaks; rm first so files deleted here get dropped there too.
rm -rf "$SUBPATH"; mkdir -p "$SUBPATH"
git -C "$SRC" archive HEAD | tar -x -C "$SUBPATH"
git add -A "$SUBPATH"

if git diff --cached --quiet; then
  echo ">> luca already matches local-llm@$SHA -- nothing to sync"; exit 0
fi
git commit -q -m "Sync tools/local-llm from local-llm@$SHA"
echo ">> staged $(git ls-files "$SUBPATH" | wc -l | tr -d ' ') files under $SUBPATH"

if [ -n "${DRY_RUN:-}" ]; then
  echo ">> DRY_RUN: not pushing. Branch $BRANCH is ready in $WORK/luca"; trap - EXIT; exit 0
fi
echo ">> pushing $BRANCH"
git push -u origin "$BRANCH" ${FORCE:+--force}
echo ">> open a PR: https://bitbucket.org/synaq/luca-ecosystem/pull-requests/new?source=$BRANCH"
