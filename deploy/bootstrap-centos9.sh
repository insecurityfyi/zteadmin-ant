#!/usr/bin/env bash
# One-time setup of a CentOS Stream 9 or 10 (or RHEL/Rocky/Alma 9-10) VPS for Linkwatch. Run as root (or with sudo):
#
#   sudo bash bootstrap-centos9.sh aperrego utilz.perrego.net you@example.com
#
# Safe to run again: every step checks what is already there.
# docs/install-centos9.md walks through the same steps by hand, with explanations.
set -euo pipefail
trap 'echo "!! Stopped at line $LINENO: $BASH_COMMAND  (fix the error above, then run the script again; it is safe to re-run)" >&2' ERR

DEPLOY_USER="${1:-aperrego}"
DOMAIN="${2:-utilz.perrego.net}"
EMAIL="${3:-}"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
id "$DEPLOY_USER" >/dev/null 2>&1 || { echo "User $DEPLOY_USER does not exist." >&2; exit 1; }

echo "==> 1/7 System updates"
dnf -y upgrade --refresh

echo "==> 2/7 Packages"
# Core packages come from the base CentOS repos, so install them first: a problem
# with EPEL below must never leave the box without a firewall.
dnf -y install podman nginx firewalld policycoreutils-python-utils curl git tar openssl

# certbot and fail2ban live in EPEL, which needs the CRB repo turned on.
# Works on CentOS Stream / RHEL / Rocky / Alma 9 and 10 (EL10 has no epel-next).
EL="$(. /etc/os-release; echo "${VERSION_ID%%.*}")"
echo "    Detected EL$EL ($(. /etc/os-release; echo "$PRETTY_NAME"))"
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb 2>/dev/null \
  || dnf config-manager setopt crb.enabled=1 2>/dev/null \
  || echo "    (could not enable CRB; trying EPEL anyway)"
rpm -q epel-release >/dev/null 2>&1 || dnf -y install epel-release \
  || dnf -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$EL.noarch.rpm"
if [[ "$EL" == "9" ]]; then
  dnf -y install epel-next-release >/dev/null 2>&1 || true
fi

if ! dnf -y install certbot python3-certbot-nginx; then
  echo "    certbot is not packaged for EL$EL here; installing it in /opt/certbot with pip"
  dnf -y install python3 python3-pip augeas-libs
  python3 -m venv /opt/certbot
  /opt/certbot/bin/pip install --quiet --upgrade pip certbot certbot-nginx
  ln -sf /opt/certbot/bin/certbot /usr/local/bin/certbot
  cat > /etc/systemd/system/certbot-renew.service <<UNIT
[Unit]
Description=Renew Let's Encrypt certificates
[Service]
Type=oneshot
ExecStart=/usr/local/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
UNIT
  cat > /etc/systemd/system/certbot-renew.timer <<UNIT
[Unit]
Description=Renew Let's Encrypt certificates twice a day
[Timer]
OnCalendar=*-*-* 03,15:17:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
fi
export PATH="$PATH:/usr/local/bin"
HAVE_FAIL2BAN=1
dnf -y install fail2ban || { HAVE_FAIL2BAN=0; echo "    fail2ban not available for EL$EL; skipping it (SSH keys-only login is the stronger fix anyway)"; }

for bin in firewall-cmd podman nginx certbot semanage; do
  command -v "$bin" >/dev/null || { echo "!! $bin is still missing after install; stopping." >&2; exit 1; }
done

echo "==> 3/7 Firewall: SSH, HTTP and HTTPS in; everything else closed"
systemctl unmask firewalld >/dev/null 2>&1 || true   # some VPS images ship it masked
if systemctl is-active --quiet iptables 2>/dev/null; then
  echo "    Stopping the legacy iptables service so firewalld can manage the firewall"
  systemctl disable --now iptables
fi
systemctl enable --now firewalld
firewall-cmd --state
ZONE="$(firewall-cmd --get-default-zone)"
for svc in cockpit dhcpv6-client; do
  firewall-cmd --permanent --zone="$ZONE" --remove-service="$svc" >/dev/null 2>&1 || true
done
for svc in ssh http https; do
  firewall-cmd --permanent --zone="$ZONE" --add-service="$svc" >/dev/null
done
firewall-cmd --reload
firewall-cmd --zone="$ZONE" --list-all

echo "==> 4/7 fail2ban for SSH"
if [[ "$HAVE_FAIL2BAN" == "1" ]]; then
  cat > /etc/fail2ban/jail.d/sshd.local <<JAIL
[sshd]
enabled = true
maxretry = 5
bantime = 1h
JAIL
  systemctl enable --now fail2ban
else
  echo "    skipped"
fi

echo "==> 5/7 nginx reverse proxy"
setsebool -P httpd_can_network_connect 1        # SELinux: let nginx talk to the app on 127.0.0.1:8080
sed "s/utilz\.perrego\.net/$DOMAIN/g" "$REPO_DIR/nginx/utilz.perrego.net.conf" > "/etc/nginx/conf.d/$DOMAIN.conf"
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "==> 6/7 Deploy user: rootless Podman that keeps running after logout"
loginctl enable-linger "$DEPLOY_USER"
HOME_DIR="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
sudo -u "$DEPLOY_USER" mkdir -p "$HOME_DIR/.config/linkwatch" "$HOME_DIR/.config/containers/systemd" "$HOME_DIR/linkwatch/quadlet"
cp "$REPO_DIR/quadlet/"* "$HOME_DIR/linkwatch/quadlet/"
cp "$REPO_DIR/deploy.sh" "$HOME_DIR/linkwatch/deploy.sh"
chown -R "$DEPLOY_USER": "$HOME_DIR/linkwatch"
chmod +x "$HOME_DIR/linkwatch/deploy.sh"

ENV_FILE="$HOME_DIR/.config/linkwatch/linkwatch.env"
DB_FILE="$HOME_DIR/.config/linkwatch/db.env"
if [[ ! -f "$ENV_FILE" ]]; then
  DB_PASS="$(openssl rand -hex 24)"
  SECRET="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_')"
  ADMIN_PASS="$(openssl rand -base64 18)"
  umask 077
  cat > "$DB_FILE" <<DB
POSTGRES_USER=linkwatch
POSTGRES_DB=linkwatch
POSTGRES_PASSWORD=$DB_PASS
DB
  cat > "$ENV_FILE" <<ENV
LW_DATABASE_URL=postgresql+psycopg://linkwatch:$DB_PASS@linkwatch-db:5432/linkwatch
LW_SECRET_KEY=$SECRET
LW_ADMIN_PASSWORD=$ADMIN_PASS
LW_PUBLIC_URL=https://$DOMAIN
LW_POLL_INTERVAL=300
ENV
  chown "$DEPLOY_USER": "$ENV_FILE" "$DB_FILE"
  echo
  echo "    Admin password for the web UI: $ADMIN_PASS"
  echo "    (stored in $ENV_FILE; change it there and restart linkwatch-web)"
  echo "    Back up $ENV_FILE: LW_SECRET_KEY decrypts every stored credential."
  echo
fi

echo "==> 7/7 TLS certificate"
if [[ -n "$EMAIL" ]]; then
  if certbot certificates 2>/dev/null | grep -q "Domains: $DOMAIN"; then
    echo "    Certificate for $DOMAIN already present."
  else
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
  fi
  systemctl enable --now certbot-renew.timer
else
  echo "    Skipped: pass your email as the third argument once DNS for $DOMAIN points here."
fi

echo
echo "Done. Next: add the GitHub secrets (docs/install-centos9.md, step 8) and push to main to deploy."
