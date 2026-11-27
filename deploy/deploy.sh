#!/usr/bin/env bash
# Runs on the VPS as the deploy user (aperrego). Called by update.sh (image
# built locally) or by the manual GitHub Actions deploy:
#   deploy.sh <image-tag>
# Uses ghcr.io/insecurityfyi/linkwatch:<tag> (pulled only if it isn't already
# local), makes it :current, restarts the service, and rolls back to :previous
# if the health check fails.
set -euo pipefail
TAG="${1:?usage: deploy.sh <image-tag>}"
IMAGE="ghcr.io/insecurityfyi/linkwatch"
QUADLET_DIR="$HOME/.config/containers/systemd"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

health() {
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 3 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

echo "==> Installing unit files"
mkdir -p "$QUADLET_DIR"
cp "$HOME/linkwatch/quadlet/"* "$QUADLET_DIR/"
systemctl --user daemon-reload

if podman image exists "$IMAGE:$TAG"; then
  echo "==> Using local image $IMAGE:$TAG"
else
  echo "==> Pulling $IMAGE:$TAG"
  podman pull "$IMAGE:$TAG"
fi
if podman image exists "$IMAGE:current"; then
  podman tag "$IMAGE:current" "$IMAGE:previous"
fi
podman tag "$IMAGE:$TAG" "$IMAGE:current"

echo "==> Starting database and app"
systemctl --user start linkwatch-db.service
systemctl --user start linkwatch-guacd.service || echo "   (guacd did not start; remote desktop will be unavailable)" >&2
systemctl --user restart linkwatch-web.service

if health; then
  echo "==> Healthy on $TAG"
  podman image prune -f >/dev/null || true
  exit 0
fi

echo "!! Health check failed on $TAG; recent logs:" >&2
journalctl --user -u linkwatch-web.service -n 40 --no-pager >&2 || true
if podman image exists "$IMAGE:previous"; then
  echo "==> Rolling back to the previous image" >&2
  podman tag "$IMAGE:previous" "$IMAGE:current"
  systemctl --user restart linkwatch-web.service
  health && echo "==> Rolled back; previous version is running" >&2
fi
exit 1
