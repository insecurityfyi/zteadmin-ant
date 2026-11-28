#!/usr/bin/env bash
# Set a new admin password for the VisCon1 web UI. Run as the deploy user (aperrego):
#
#   ~/zteadmin-ant/deploy/reset-password.sh            # generates a random password and prints it
#   ~/zteadmin-ant/deploy/reset-password.sh 'MyPass'   # sets the one you give (at least 12 characters)
#
# The password lives only in ~/.config/linkwatch/linkwatch.env (LW_ADMIN_PASSWORD).
# This rewrites that line and restarts the app; open sessions stay signed in.
set -euo pipefail
ENV_FILE="${LW_ENV_FILE:-$HOME/.config/linkwatch/linkwatch.env}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as the deploy user (e.g. aperrego), not root or sudo." >&2; exit 1
fi
[ -f "$ENV_FILE" ] || { echo "No $ENV_FILE. Run the bootstrap script first." >&2; exit 1; }

NEW="${1:-}"
if [ -z "$NEW" ]; then
  NEW="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
elif [ "${#NEW}" -lt 12 ]; then
  echo "Use at least 12 characters." >&2; exit 1
fi
case "$NEW" in *$'\n'*) echo "The password can't contain a newline." >&2; exit 1;; esac

cp -p "$ENV_FILE" "$ENV_FILE.bak"
tmp="$(mktemp "$ENV_FILE.XXXXXX")"
chmod 600 "$tmp"
grep -v '^LW_ADMIN_PASSWORD=' "$ENV_FILE" > "$tmp" || true
printf 'LW_ADMIN_PASSWORD=%s\n' "$NEW" >> "$tmp"
mv "$tmp" "$ENV_FILE"

if systemctl --user is-enabled --quiet linkwatch-web.service 2>/dev/null || systemctl --user is-active --quiet linkwatch-web.service; then
  systemctl --user restart linkwatch-web.service
  echo "Restarted the app."
fi
echo "New admin password: $NEW"
echo "(Saved in $ENV_FILE; the old file is at $ENV_FILE.bak.)"
