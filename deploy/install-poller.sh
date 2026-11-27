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
#   install-poller.sh --network bridge                           use the container runtime's own network instead of
#                                                                the host's (remembered for later updates)
#   install-poller.sh --no-helper                                don't install the update helper (step 5)
#
# What it does:
#   1. installs Podman, curl and the SNMP command-line tools (apt, dnf/yum or zypper),
#      or uses Docker if that is already installed and Podman isn't
#   2. checks it can reach the server's /healthz over HTTPS
#   3. pulls the poller image and (re)creates the container on the host's network (so ping,
#      SNMP and path probes go out from the machine's own address, not the 10.88.0.1 Podman
#      bridge), with NET_RAW so ping and mtr work, a volume for its key, and restart-on-boot
#   4. waits for "Connected" in the logs
#   5. before starting it, installs a small systemd helper (linkwatch-poller-helper.path/.service) that runs this
#      script again when the poller asks, so Pollers > Update in Linkwatch can update it and report the result
#
# The enrollment token is shown once by the server (Pollers > Add poller), works
# once and expires after 24 hours. After the first start the poller keeps its own
# key in the volume, so updates don't need a token. The poller only connects out.
set -euo pipefail

DEFAULT_IMAGE="ghcr.io/insecurityfyi/linkwatch-poller:latest"
IMAGE="${LW_POLLER_IMAGE:-}"
INSTALLER_URL="${LW_INSTALLER_URL:-https://raw.githubusercontent.com/insecurityfyi/zteadmin-ant/main/deploy/install-poller.sh}"
HELPER=1
NAME_CT="linkwatch-poller"
VOLUME="linkwatch-poller"
CONF="/etc/linkwatch-poller.env"
SERVER="${LW_SERVER:-}"
TOKEN="${LW_ENROLL_TOKEN:-}"
PNAME="${LW_POLLER_NAME:-}"
NETWORK="${LW_POLLER_NETWORK:-}"
UNINSTALL=0

usage() { sed -n '2,30p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; }
die() { echo "!! $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) PNAME="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --network) NETWORK="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --no-helper) HELPER=0; shift ;;
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
  NETWORK="${NETWORK:-${LW_POLLER_NETWORK:-}}"; IMAGE="${IMAGE:-${LW_POLLER_IMAGE:-}}"
fi
IMAGE="${IMAGE:-$DEFAULT_IMAGE}"
# Host networking by default: the poller then uses the machine's real address and interfaces,
# so devices, ACLs and path probes see it as itself rather than as the runtime's NAT bridge.
NETWORK="${NETWORK:-host}"
case "$NETWORK" in host|bridge) ;; *) die "--network takes host or bridge" ;; esac

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
  ct_net="$($RT container inspect -f '{{.HostConfig.NetworkMode}}' "$EXISTING" 2>/dev/null || true)"
  if [ "$NETWORK" = host ] && [ -n "$ct_net" ] && [ "$ct_net" != host ]; then
    say "Moving it from the container network ($ct_net) to the host's network"
  fi
fi
PNAME="${PNAME:-$(hostname -s 2>/dev/null || echo poller)}"
SERVER="${SERVER%/}"

if [ "$UNINSTALL" -eq 1 ]; then
  if command -v systemctl >/dev/null; then
    systemctl disable -q --now linkwatch-poller-helper.path 2>/dev/null || true
    rm -f /etc/systemd/system/linkwatch-poller-helper.path /etc/systemd/system/linkwatch-poller-helper.service
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f /usr/local/sbin/linkwatch-poller-helper
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
printf 'LW_SERVER=%q\nLW_POLLER_NAME=%q\nLW_POLLER_NETWORK=%q\nLW_POLLER_IMAGE=%q\n' "$SERVER" "$PNAME" "$NETWORK" "$IMAGE" > "$CONF"

# ------------------------------------------------------------------ update helper
# The poller can't replace its own container, so Pollers > Update asks the host: the poller writes
# control/update.request in its volume, a systemd path unit runs linkwatch-poller-helper, which runs this script
# again and writes control/update.result for the poller to report back. The request file carries only an id;
# the helper never runs anything from the volume.
install_helper() {
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || { say "No systemd here: skipping the update helper (update by running this script)"; return 0; }
  local mp ctl lib=/usr/local/lib/linkwatch-poller tmp
  if [ -d "$VOLUME" ]; then mp="$VOLUME"; else
    $RT volume inspect "$VOLUME" >/dev/null 2>&1 || $RT volume create "$VOLUME" >/dev/null 2>&1 || true
    mp="$($RT volume inspect -f '{{.Mountpoint}}' "$VOLUME" 2>/dev/null || true)"
  fi
  [ -n "$mp" ] && [ -d "$mp" ] || { say "Couldn't find the poller volume on disk: skipping the update helper"; return 0; }
  ctl="$mp/control"
  # Podman and Docker copy the image's folder (owned by the poller's user, uid 10001) into an empty volume only;
  # the helper's files make it non-empty, so give a new volume that owner ourselves.
  [ "$(stat -c %u "$mp")" = 10001 ] || [ -s "$mp/identity.json" ] || chown 10001:10001 "$mp" 2>/dev/null || true
  install -d -m 0755 "$lib"
  # The poller (uid 10001) writes its update requests here. Use mkdir, not install -d: on SELinux hosts install
  # gives the folder the policy's default label for that path (container_var_lib_t), which the container may read
  # but not write. Copy the volume's own label (container_file_t, with its MCS categories) instead, and set the
  # owner every time, so a folder left by an earlier install is fixed too.
  mkdir -p "$ctl"
  chown 10001:10001 "$ctl" 2>/dev/null || true
  chmod 0755 "$ctl"
  if command -v selinuxenabled >/dev/null && selinuxenabled 2>/dev/null; then
    chcon -R --reference="$mp" "$ctl" 2>/dev/null || say "Couldn't copy the volume's SELinux label to $ctl"
  fi
  # a copy of this script for the helper to fall back on when GitHub can't be reached (replaced atomically:
  # the helper may be running the old copy right now)
  tmp="$(mktemp "$lib/.install.XXXXXX")"
  if curl -fsSL --max-time 60 "$INSTALLER_URL" -o "$tmp" && head -1 "$tmp" | grep -q bash; then
    chmod 0755 "$tmp"; mv -f "$tmp" "$lib/install-poller.sh"
  else
    rm -f "$tmp"
  fi
  tmp="$(mktemp /usr/local/sbin/.lwhelper.XXXXXX)"
  {
    echo '#!/usr/bin/env bash'
    echo '# Installed by install-poller.sh. systemd runs this when the Linkwatch poller asks to be updated'
    echo '# (Pollers > Update): it runs the install script again and leaves the result for the poller to report.'
    echo 'set -uo pipefail'
    printf 'CTL=%q\nRT=%q\nURL=%q\nCACHE=%q\nCT=%q\n' "$ctl" "$RT" "$INSTALLER_URL" "$lib/install-poller.sh" "$NAME_CT"
    cat <<'HELPER'
REQ="$CTL/update.request"
[ -f "$REQ" ] || exit 0
id="$(head -c 64 "$REQ" | tr -cd 'A-Za-z0-9_-')"
rm -f "$REQ"
[ -n "$id" ] || exit 0
echo "Update requested by the poller (request $id)"
before="$($RT container inspect -f '{{.Image}}' "$CT" 2>/dev/null || true)"
tmp="$(mktemp "$(dirname "$CACHE")/.install.XXXXXX")"
if curl -fsSL --max-time 60 "$URL" -o "$tmp" && head -1 "$tmp" | grep -q bash; then
  chmod 0755 "$tmp"; mv -f "$tmp" "$CACHE"
else
  rm -f "$tmp"; echo "Couldn't download $URL; using the saved copy"
fi
if [ -f "$CACHE" ]; then out="$(bash "$CACHE" 2>&1)"; rc=$?; else out="No install script: couldn't download $URL"; rc=1; fi
printf '%s\n' "$out"
after="$($RT container inspect -f '{{.Image}}' "$CT" 2>/dev/null || true)"
ok=false; [ "$rc" -eq 0 ] && ok=true
changed=false; [ -n "$after" ] && [ "$after" != "$before" ] && changed=true
err=""
if [ "$rc" -ne 0 ]; then
  err="$(printf '%s\n' "$out" | grep -v '^==>' | tail -4 | tr '\n\t' '  ' | tr -cd '[:print:]' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-600)"
  [ -n "$err" ] || err="install-poller.sh exited with code $rc"
fi
img="${after#sha256:}"
printf '{"id":"%s","ok":%s,"changed":%s,"image":"%s","error":"%s","at":%s}\n' "$id" "$ok" "$changed" "${img:0:19}" "$err" "$(date +%s)" > "$CTL/.update.result.tmp"
chmod 0644 "$CTL/.update.result.tmp"
if command -v selinuxenabled >/dev/null && selinuxenabled 2>/dev/null; then chcon --reference="$CTL" "$CTL/.update.result.tmp" 2>/dev/null || true; fi
mv -f "$CTL/.update.result.tmp" "$CTL/update.result"
echo "Update $id finished: ok=$ok"
HELPER
  } > "$tmp"
  chmod 0755 "$tmp"; mv -f "$tmp" /usr/local/sbin/linkwatch-poller-helper
  cat > /etc/systemd/system/linkwatch-poller-helper.service <<UNIT
[Unit]
Description=Update the Linkwatch poller when it asks (Pollers > Update)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/linkwatch-poller-helper
TimeoutStartSec=20min
UNIT
  cat > /etc/systemd/system/linkwatch-poller-helper.path <<UNIT
[Unit]
Description=Watch for update requests from the Linkwatch poller

[Path]
PathExists=$ctl/update.request
Unit=linkwatch-poller-helper.service

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable -q linkwatch-poller-helper.path 2>/dev/null || true
  systemctl restart linkwatch-poller-helper.path 2>/dev/null || systemctl start linkwatch-poller-helper.path || true
  printf '{"version":1,"runtime":"%s","installed":%s}\n' "$RT" "$(date +%s)" > "$ctl/helper.json"
  chmod 0644 "$ctl/helper.json"
  if command -v selinuxenabled >/dev/null && selinuxenabled 2>/dev/null; then chcon --reference="$mp" "$ctl/helper.json" 2>/dev/null || true; fi
  say "Installed the update helper (Pollers > Update in Linkwatch now works for this poller)"
}

if [ "$HELPER" -eq 1 ]; then install_helper || say "Couldn't install the update helper; update by running this script"; fi

say "Starting $NAME_CT (name: $PNAME, network: $NETWORK)"
$RT rm -f "$NAME_CT" >/dev/null 2>&1 || true
if [ -n "$EXISTING" ] && [ "$EXISTING" != "$NAME_CT" ]; then
  $RT rm -f "$EXISTING" >/dev/null 2>&1 || true      # one poller per key: replace the hand-started container
fi
args=(run -d --name "$NAME_CT" --restart=always --cap-add=NET_RAW
      --network "$NETWORK"
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
