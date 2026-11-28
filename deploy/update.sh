#!/usr/bin/env bash
# Pull the latest code from GitHub and deploy it on this VPS. Run as the deploy
# user (aperrego), from anywhere:
#
#   ~/zteadmin-ant/deploy/update.sh            # update to the latest main
#   ~/zteadmin-ant/deploy/update.sh --force    # rebuild and restart even if nothing changed
#   ~/zteadmin-ant/deploy/update.sh <commit>   # deploy a specific commit (e.g. to go back)
#   update.sh --auto      # what the timer runs (enable-auto-update.sh): quiet when there's nothing new
#   update.sh --skip-ci   # deploy even if GitHub's tests haven't passed on that commit
#
# Safety checks: only fast-forwards of origin/main are deployed (a rewritten
# history stops it), local edits stop it, the commit's "pytest" check on GitHub
# must have passed, and a commit that failed its health check once is not
# retried automatically (run update.sh by hand, or --force, to retry it).
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
GH_REPO="${LW_GITHUB_REPO:-insecurityfyi/zteadmin-ant}"
CI_CHECK="${LW_CI_CHECK:-pytest}"
STATE="$HOME/linkwatch/deployed-commit"
FAILED="$HOME/linkwatch/failed-commit"
FORCE=0
AUTO=0
SKIP_CI=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=1 ;;
    --auto) AUTO=1 ;;
    --skip-ci) SKIP_CI=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) TARGET="$arg" ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as the deploy user (e.g. aperrego), not root or sudo." >&2
  exit 1
fi
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
cd "$REPO"
mkdir -p "$HOME/linkwatch"

say() { [ "$AUTO" -eq 1 ] || echo "$@"; }

# Asks GitHub whether the test job passed on a commit. Prints success, pending or failed.
ci_state() {
  local json
  json="$(curl -fsS --max-time 20 -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$GH_REPO/commits/$1/check-runs?check_name=$CI_CHECK" 2>/dev/null)" || { echo unknown; return; }
  if ! grep -q '"name": *"'"$CI_CHECK"'"' <<<"$json"; then echo pending; return; fi
  if grep -Eq '"conclusion": *"(failure|cancelled|timed_out|action_required|startup_failure)"' <<<"$json"; then echo failed
  elif grep -q '"conclusion": *"success"' <<<"$json"; then echo success
  else echo pending; fi
}

say "==> Fetching from GitHub"
git fetch --quiet origin "$BRANCH"
if [ -z "$TARGET" ] && ! git merge-base --is-ancestor HEAD "origin/$BRANCH"; then
  echo "!! origin/$BRANCH is not a fast-forward of the deployed code (history was rewritten?). Not deploying; check GitHub, then run: $0 origin/$BRANCH" >&2
  exit 1
fi
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
say "    now at $(git log -1 --format='%h %s (%cr)')"

if [ "$COMMIT" = "$DEPLOYED" ] && [ "$FORCE" -eq 0 ] \
   && systemctl --user is-active --quiet linkwatch-web.service; then
  say "==> Already running $TAG; nothing to do (use --force to rebuild anyway)"
  exit 0
fi
if [ "$AUTO" -eq 1 ] && [ "$COMMIT" = "$(cat "$FAILED" 2>/dev/null || true)" ]; then
  exit 0   # failed its health check before; waits for a new commit or a manual run
fi
echo "==> New version: $(git log -1 --format='%h %s')"

if [ "$SKIP_CI" -eq 0 ]; then
  case "$(ci_state "$COMMIT")" in
    success) echo "==> GitHub tests passed on ${COMMIT:0:12}" ;;
    pending) echo "==> GitHub tests haven't finished on ${COMMIT:0:12} yet; not deploying until they pass."
             [ "$AUTO" -eq 1 ] && exit 0
             echo "   Run again in a few minutes, or add --skip-ci." >&2; exit 1 ;;
    failed)  echo "!! GitHub tests FAILED on ${COMMIT:0:12}; not deploying it (override: --skip-ci)." >&2
             [ "$AUTO" -eq 1 ] && echo "$COMMIT" > "$FAILED"
             exit 1 ;;
    *)       echo "!! Couldn't reach the GitHub API to check the tests; not deploying (override: --skip-ci)." >&2
             [ "$AUTO" -eq 1 ] && exit 0
             exit 1 ;;
  esac
fi
if [ -n "$DEPLOYED" ] && [ "$COMMIT" != "$DEPLOYED" ]; then
  echo "==> Changes since the last deploy:"
  git log --oneline "${DEPLOYED}..${COMMIT}" 2>/dev/null | sed 's/^/    /' || true
fi

echo "==> Building $IMAGE:$TAG"
podman build --pull=newer -f Dockerfile.linkwatch -t "$IMAGE:$TAG" \
  --build-arg "LW_BUILD=${COMMIT:0:12}" \
  --label "org.opencontainers.image.revision=$COMMIT" .

echo "==> Copying unit files and deploy script"
mkdir -p "$HOME/linkwatch/quadlet"
cp deploy/quadlet/* "$HOME/linkwatch/quadlet/"
cp deploy/deploy.sh "$HOME/linkwatch/deploy.sh"
chmod +x "$HOME/linkwatch/deploy.sh"

if bash "$HOME/linkwatch/deploy.sh" "$TAG"; then
  echo "$COMMIT" > "$STATE"
  rm -f "$FAILED"
  if systemctl --user is-enabled --quiet linkwatch-update.timer 2>/dev/null; then
    mkdir -p "$HOME/.config/systemd/user"
    cp deploy/systemd/linkwatch-update.service deploy/systemd/linkwatch-update.timer "$HOME/.config/systemd/user/"
    systemctl --user daemon-reload
  fi
  echo "==> Done: $TAG is live at http://127.0.0.1:8080 (and your public URL)"
else
  echo "$COMMIT" > "$FAILED"
  echo "!! The new version failed its health check. deploy.sh rolled back to the previous image if there was one." >&2
  if [ -n "$DEPLOYED" ]; then
    echo "   The last good commit was ${DEPLOYED:0:12}. To put the code back too: $0 ${DEPLOYED:0:12}" >&2
  fi
  exit 1
fi
