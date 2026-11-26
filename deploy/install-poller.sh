#!/usr/bin/env bash
# Install (or update) a Linkwatch poller on a Linux machine on your LAN: a small
# VM, a Proxmox LXC container, or a Raspberry Pi. Run as root (or with sudo):
#
#   curl -fsSL https://raw.githubusercontent.com/insecurityfyi/zteadmin-ant/main/deploy/install-poller.sh \
#     | sudo bash -s -- --server https://monitor.example.com --token enr_xxx --name poller-hq-01
#
#   install-poller.sh --server URL --token TOKEN [--name NAME]   first install
#   install-poller.sh                                            update to the latest image (keeps its key); the server
#                                                                and name come from the last install or the running container
#   install-poller.sh --uninstall                                remove the container (keeps the key volume)
#
# What it does:
#   1. installs Podman, curl and the SNMP command-line tools (apt, dnf/yum or zypper),
#      or uses Docker if that is already installed and Podman isn't
#   2. checks it can reach the server's /healthz over HTTPS
#   3. pulls the poller image and (re)creates the container with NET_RAW so ping works,
#      a volume for its key, and restart-on-boot
#   4. waits for "Connected" in the logs
#
# The enrollment token is shown once by the server (Pollers > Add poller), works
# once and expires after 24 hours. After the first start the poller keeps its own
# key in the volume, so updates don't need a token. The poller only connects out.
set -euo pipefail

IMAGE="${LW_POLLER_IMAGE:-ghcr.io/insecurityfyi/linkwatch-poller:latest}"
NAME_CT="linkwatch-poller"
VOLUME="linkwatch-poller"
CONF="/etc/linkwatch-poller.env"
SERVER="${LW_SERVER:-}"
TOKEN="${LW_ENROLL_TOKEN:-}"
PNAME="${LW_POLLER_NAME:-}"
UNINSTALL=0

usage() { sed -n '2,23p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; }
die() { echo "!! $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) PNAME="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    enr_*) TOKEN="$1"; shift ;;          # a bare token is accepted too
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root, e.g. with sudo."

# Remember the server and name from the first install so updates need no arguments.
if [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF"
  SERVER="${SERVER:-${LW_SERVER:-}}"; PNAME="${PNAME:-${LW_POLLER_NAME:-}}"
fi

# ------------------------------------------------------------------ packages
pkg_install() {
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null; then dnf install -y -q "$@"
  elif command -v yum >/dev/null; then yum install -y -q "$@"
  elif command -v zypper >/dev/null; then zypper --non-interactive install -y "$@"
  else die "No apt, dnf, yum or zypper found. Install Podman yourself, then run this again."
  fi
}

if command -v podman >/dev/null; then RT=podman
elif command -v docker >/dev/null; then RT=docker
else
  say "Installing Podman"
  pkg_install podman
  RT=podman
fi
command -v curl >/dev/null || { say "Installing curl"; pkg_install curl ca-certificates; }
if ! command -v snmpwalk >/dev/null; then
  say "Installing SNMP tools (snmpwalk/snmpget, for testing devices by hand)"
  if command -v apt-get >/dev/null; then pkg_install snmp || true; else pkg_install net-snmp-utils || true; fi
fi
say "Using $($RT --version | head -1)"

# A poller started by hand (podman run ...) has no $CONF: take the server, name and key volume from its container.
EXISTING=""
if $RT container inspect "$NAME_CT" >/dev/null 2>&1; then
  EXISTING="$NAME_CT"
else
  EXISTING="$($RT ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null | awk '$2 ~ /linkwatch-poller/ {print $1; exit}')"
fi
if [ -n "$EXISTING" ]; then
  ct_env="$($RT container inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$EXISTING" 2>/dev/null || true)"
  [ -n "$SERVER" ] || SERVER="$(sed -n 's/^LW_SERVER=//p' <<<"$ct_env" | head -1)"
  [ -n "$PNAME" ] || PNAME="$(sed -n 's/^LW_POLLER_NAME=//p' <<<"$ct_env" | head -1)"
  ct_vol="$($RT container inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/linkwatch"}}{{if .Name}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$EXISTING" 2>/dev/null || true)"
  if [ -n "$ct_vol" ] && [ "$ct_vol" != "$VOLUME" ]; then
    say "Keeping the key from the existing container's storage ($ct_vol)"
    VOLUME="$ct_vol"
  fi
  [ -n "$SERVER" ] && say "Found the existing poller container '$EXISTING' (server $SERVER)"
fi
PNAME="${PNAME:-$(hostname -s 2>/dev/null || echo poller)}"
SERVER="${SERVER%/}"

if [ "$UNINSTALL" -eq 1 ]; then
  $RT rm -f "$NAME_CT" >/dev/null 2>&1 || true
  say "Removed the $NAME_CT container. Its key is still in the '$VOLUME' volume; '$RT volume rm $VOLUME' deletes it."
  exit 0
fi

# ------------------------------------------------------------------ checks
[ -n "$SERVER" ] || die "Give the server address: --server https://your-linkwatch-host"
case "$SERVER" in https://*|http://*) ;; *) SERVER="https://$SERVER" ;; esac

say "Checking $SERVER/healthz"
if ! curl -fsS --max-time 15 "$SERVER/healthz" >/dev/null; then
  die "Can't reach $SERVER/healthz from here. Check DNS, the firewall, outbound HTTPS and the address."
fi

say "Pulling $IMAGE"
$RT pull -q "$IMAGE" >/dev/null || die "Could not pull $IMAGE"

have_identity=0
if { [ -d "$VOLUME" ] || $RT volume inspect "$VOLUME" >/dev/null 2>&1; } \
   && $RT run --rm -v "$VOLUME:/v:ro" --entrypoint test "$IMAGE" -s /v/identity.json 2>/dev/null; then
  have_identity=1
fi
if [ "$have_identity" -eq 0 ] && [ -z "$TOKEN" ]; then
  die "This machine isn't enrolled yet. In Linkwatch open Pollers > Add poller and pass the token: --token enr_..."
fi

# ------------------------------------------------------------------ run
umask 077
printf 'LW_SERVER=%s\nLW_POLLER_NAME=%s\n' "$SERVER" "$PNAME" > "$CONF"

say "Starting $NAME_CT (name: $PNAME)"
$RT rm -f "$NAME_CT" >/dev/null 2>&1 || true
if [ -n "$EXISTING" ] && [ "$EXISTING" != "$NAME_CT" ]; then
  $RT rm -f "$EXISTING" >/dev/null 2>&1 || true      # one poller per key: replace the hand-started container
fi
args=(run -d --name "$NAME_CT" --restart=always --cap-add=NET_RAW
      -e "LW_SERVER=$SERVER" -e "LW_POLLER_NAME=$PNAME" -v "$VOLUME:/var/lib/linkwatch")
if [ "$have_identity" -eq 0 ]; then args+=(-e "LW_ENROLL_TOKEN=$TOKEN"); fi
if ! $RT "${args[@]}" "$IMAGE" >/dev/null; then
  if grep -qa container=lxc /proc/1/environ 2>/dev/null || [ -d /proc/vz ]; then
    echo "!! The container didn't start. This looks like an LXC container: on the Proxmox host enable" >&2
    echo "   Options > Features > 'Nesting' (and 'keyctl' for an unprivileged container), restart it, and run this again." >&2
  fi
  exit 1
fi

if [ "$RT" = podman ] && command -v systemctl >/dev/null && systemctl list-unit-files podman-restart.service >/dev/null 2>&1; then
  systemctl enable -q podman-restart.service 2>/dev/null || true    # brings --restart=always containers back after a reboot
elif [ "$RT" = docker ] && command -v systemctl >/dev/null; then
  systemctl enable -q docker 2>/dev/null || true
fi

say "Waiting for it to connect"
for _ in $(seq 1 30); do
  logs="$($RT logs "$NAME_CT" 2>&1 || true)"
  if grep -q "Connected to" <<<"$logs"; then
    grep -E "Enrolled|Connected|Config:" <<<"$logs" | tail -3 | sed 's/^/    /'
    say "Done. The poller shows as connected under Pollers. Follow its log with: $RT logs -f $NAME_CT"
    say "To update it later, run this script again with no arguments."
    exit 0
  fi
  if grep -qE "refused|Invalid|expired|ERROR" <<<"$logs"; then break; fi
  sleep 2
done
echo "!! It hasn't connected yet. Last log lines:" >&2
$RT logs --tail 15 "$NAME_CT" 2>&1 | sed 's/^/    /' >&2
echo "   A used or expired token needs a new one from Pollers > Add poller." >&2
exit 1
