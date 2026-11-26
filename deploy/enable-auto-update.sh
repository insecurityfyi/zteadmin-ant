#!/usr/bin/env bash
# Turn on (or off) automatic deploys. Run as the deploy user (aperrego):
#
#   ~/zteadmin-ant/deploy/enable-auto-update.sh         # check every 5 minutes, deploy new commits on main once CI passed
#   ~/zteadmin-ant/deploy/enable-auto-update.sh off     # back to running update.sh by hand
#
# Watch it with: journalctl --user -u linkwatch-update -f
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as the deploy user (e.g. aperrego), not root or sudo." >&2; exit 1
fi
if [ "$REPO" != "$HOME/zteadmin-ant" ]; then
  echo "The timer expects the checkout at ~/zteadmin-ant (this one is $REPO)." >&2; exit 1
fi

if [ "${1:-on}" = "off" ]; then
  systemctl --user disable --now linkwatch-update.timer 2>/dev/null || true
  echo "Automatic deploys are off. Run ~/zteadmin-ant/deploy/update.sh by hand."
  exit 0
fi

loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q yes \
  || echo "!! Linger is off, so the timer stops when you log out. Fix: sudo loginctl enable-linger $USER" >&2
mkdir -p "$UNIT_DIR" "$HOME/linkwatch"
cp "$REPO/deploy/systemd/linkwatch-update.service" "$REPO/deploy/systemd/linkwatch-update.timer" "$UNIT_DIR/"
systemctl --user daemon-reload
systemctl --user enable --now linkwatch-update.timer
echo "Automatic deploys are on. Next check:"
systemctl --user list-timers linkwatch-update.timer --no-pager | sed -n '1,2p'
echo "Logs: journalctl --user -u linkwatch-update -f"
