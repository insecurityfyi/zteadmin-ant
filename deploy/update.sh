#!/usr/bin/env bash
# Pull the latest code from GitHub and deploy it on this VPS. Run as the deploy
# user (aperrego), from anywhere:
#
#   ~/zteadmin-ant/deploy/update.sh            # update to the latest main
#   ~/zteadmin-ant/deploy/update.sh --force    # rebuild and restart even if nothing changed
#   ~/zteadmin-ant/deploy/update.sh <commit>   # deploy a specific commit (e.g. to go back)
#
# What it does:
#   1. git fetch + fast-forward the checkout to origin/main (or the commit given)
#   2. builds the web image locally with Podman, tagged sha-<commit>
#      (no GitHub Actions, registry login or SSH key from GitHub needed)
#   3. installs the Quadlet unit files from the checkout
#   4. runs deploy.sh: tags the image :current, restarts the app, checks
#      /healthz, and rolls back to the previous image if it doesn't come up
#
# Database tables are created/upgraded by the app itself when it starts, so
# there is no separate migration step.
set -euo pipefail
trap 'echo "!! update.sh stopped at line $LINENO: $BASH_COMMAND" >&2' ERR

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRANCH="${LW_BRANCH:-main}"
IMAGE="ghcr.io/insecurityfyi/linkwatch"
STATE="$HOME/linkwatch/deployed-commit"
FORCE=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) TARGET="$arg" ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as the deploy user (e.g. aperrego), not root or sudo." >&2
  exit 1
fi
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
cd "$REPO"

echo "==> Fetching from GitHub"
git fetch --quiet origin "$BRANCH"
if [ -n "$TARGET" ]; then
  git -c advice.detachedHead=false checkout --quiet "$TARGET"
else
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "!! $REPO has local edits; commit them, or run 'git stash', then try again." >&2
    git status --short --untracked-files=no >&2
    exit 1
  fi
  git checkout --quiet "$BRANCH" 2>/dev/null || git checkout --quiet -b "$BRANCH" "origin/$BRANCH"
  git merge --quiet --ff-only "origin/$BRANCH"
fi

COMMIT="$(git rev-parse HEAD)"
TAG="sha-${COMMIT:0:12}"
DEPLOYED="$(cat "$STATE" 2>/dev/null || true)"
echo "    now at $(git log -1 --format='%h %s (%cr)')"

if [ "$COMMIT" = "$DEPLOYED" ] && [ "$FORCE" -eq 0 ] \
   && systemctl --user is-active --quiet linkwatch-web.service; then
  echo "==> Already running $TAG; nothing to do (use --force to rebuild anyway)"
  exit 0
fi
if [ -n "$DEPLOYED" ] && [ "$COMMIT" != "$DEPLOYED" ]; then
  echo "==> Changes since the last deploy:"
  git log --oneline "${DEPLOYED}..${COMMIT}" 2>/dev/null | sed 's/^/    /' || true
fi

echo "==> Building $IMAGE:$TAG"
podman build --pull=newer -f Dockerfile.linkwatch -t "$IMAGE:$TAG" \
  --label "org.opencontainers.image.revision=$COMMIT" .

echo "==> Copying unit files and deploy script"
mkdir -p "$HOME/linkwatch/quadlet"
cp deploy/quadlet/* "$HOME/linkwatch/quadlet/"
cp deploy/deploy.sh "$HOME/linkwatch/deploy.sh"
chmod +x "$HOME/linkwatch/deploy.sh"

if bash "$HOME/linkwatch/deploy.sh" "$TAG"; then
  echo "$COMMIT" > "$STATE"
  echo "==> Done: $TAG is live at http://127.0.0.1:8080 (and your public URL)"
else
  echo "!! The new version failed its health check. deploy.sh rolled back to the previous image if there was one." >&2
  if [ -n "$DEPLOYED" ]; then
    echo "   The last good commit was ${DEPLOYED:0:12}. To put the code back too: $0 ${DEPLOYED:0:12}" >&2
  fi
  exit 1
fi
