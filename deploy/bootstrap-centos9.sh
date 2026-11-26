#!/usr/bin/env bash
# One-time setup of a CentOS Stream 9 VPS for Linkwatch. Run as root (or with sudo):
#
#   sudo bash bootstrap-centos9.sh aperrego utilz.perrego.net you@example.com
#
# Safe to run again: every step checks what is already there.
# docs/install-centos9.md walks through the same steps by hand, with explanations.
set -euo pipefail

DEPLOY_USER="${1:-aperrego}"
DOMAIN="${2:-utilz.perrego.net}"
EMAIL="${3:-}"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
id "$DEPLOY_USER" >/dev/null 2>&1 || { echo "User $DEPLOY_USER does not exist." >&2; exit 1; }

echo "==> 1/7 System updates and repositories"
dnf -y upgrade --refresh
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb
dnf -y install epel-release epel-next-release

echo "==> 2/7 Packages"
dnf -y install podman nginx firewalld policycoreutils-python-utils curl git tar \
  certbot python3-certbot-nginx fail2ban

echo "==> 3/7 Firewall: SSH, HTTP and HTTPS in; everything else closed"
systemctl enable --now firewalld
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
cat > /etc/fail2ban/jail.d/sshd.local <<JAIL
[sshd]
enabled = true
maxretry = 5
bantime = 1h
JAIL
systemctl enable --now fail2ban

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
