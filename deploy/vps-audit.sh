#!/usr/bin/env bash
# VisCon1 VPS read-only security audit. Changes nothing. Run as root:
#   sudo bash vps-audit.sh > vps-audit.txt 2>&1
# then share vps-audit.txt. Review it first: it lists your users, ports and SSH settings (no passwords or keys).
set -u
DEPLOY_USER="${DEPLOY_USER:-aperrego}"
sec() { printf '\n===== %s =====\n' "$*"; }
run() { printf '$ %s\n' "$*"; bash -c "$*" 2>&1 | head -${LINES_MAX:-80}; }

sec "System";        run 'cat /etc/os-release | head -4; uname -r; uptime'
sec "Pending updates"; run 'dnf -q check-update --security 2>/dev/null | tail -n +1 | head -40; echo "exit=$?"'
run 'dnf -q updateinfo list --security 2>/dev/null | head -30'
run 'needs-restarting -r 2>/dev/null || echo "needs-restarting not installed (dnf-utils)"'
sec "Automatic updates"; run 'systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>&1; grep -E "^(upgrade_type|apply_updates)" /etc/dnf/automatic.conf 2>/dev/null'
run 'sudo -u '"$DEPLOY_USER"' XDG_RUNTIME_DIR=/run/user/$(id -u '"$DEPLOY_USER"') systemctl --user list-timers 2>/dev/null | grep -i linkwatch'

sec "Listening sockets (should be 22/80/443 public; 8080 on 127.0.0.1 only)"
run 'ss -tulpnH | sort -k5'
sec "Firewall"
run 'systemctl is-active firewalld; firewall-cmd --get-active-zones; firewall-cmd --list-all'
run 'nft list ruleset 2>/dev/null | grep -cE "accept|drop" | sed "s/^/nft rule lines: /"'

sec "SSH daemon (effective config)"
run 'sshd -T 2>/dev/null | grep -Ei "^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|allowtcpforwarding|allowusers|allowgroups|authenticationmethods|loglevel|clientaliveinterval|ciphers|macs|kexalgorithms)\b"'
run 'ls -la /etc/ssh/sshd_config.d/'
sec "Accounts"
run 'awk -F: "(\$3==0 || \$3>=1000) && \$7 !~ /nologin|false/ {print \$1, \$3, \$7}" /etc/passwd'
run 'getent group wheel sudo 2>/dev/null; ls /etc/sudoers.d/; grep -rhE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null'
run 'for h in /root /home/*; do f=$h/.ssh/authorized_keys; [ -f $f ] && echo "$f: $(grep -cv "^#" $f) key(s); perms $(stat -c %a $f)"; done'
run 'lastlog 2>/dev/null | grep -v "Never logged in" | head -20'
run 'last -n 15 -a 2>/dev/null'

sec "fail2ban"
run 'systemctl is-active fail2ban; fail2ban-client status 2>/dev/null; fail2ban-client status sshd 2>/dev/null'
sec "Failed SSH logins (last 24h, top sources)"
run 'journalctl -u sshd --since "-24h" --no-pager 2>/dev/null | grep -Ei "failed|invalid" | grep -oE "from [0-9a-f.:]+" | sort | uniq -c | sort -rn | head -15'

sec "SELinux"
run 'getenforce; sestatus | head -8; getsebool httpd_can_network_connect'
run 'ausearch -m AVC -ts today 2>/dev/null | grep -c "type=AVC" | sed "s/^/AVC denials today: /"'

sec "nginx"
run 'nginx -v; nginx -T 2>/dev/null | grep -Ei "^\s*(listen|server_name|ssl_protocols|ssl_ciphers|ssl_prefer|add_header|server_tokens|client_max_body_size|proxy_set_header X-Forwarded-For|return 301)"'
run 'certbot certificates 2>/dev/null | grep -E "Domains|Expiry"; systemctl list-timers 2>/dev/null | grep -i certbot'

sec "Containers (rootless, deploy user)"
run 'sudo -u '"$DEPLOY_USER"' XDG_RUNTIME_DIR=/run/user/$(id -u '"$DEPLOY_USER"') podman ps --format "{{.Names}} {{.Image}} {{.Ports}} {{.Status}}"'
run 'sudo -u '"$DEPLOY_USER"' XDG_RUNTIME_DIR=/run/user/$(id -u '"$DEPLOY_USER"') podman inspect linkwatch-web --format "user={{.Config.User}} privileged={{.HostConfig.Privileged}} caps_add={{.HostConfig.CapAdd}} caps_drop={{.HostConfig.CapDrop}} readonly={{.HostConfig.ReadonlyRootfs}} nnp={{.HostConfig.SecurityOpt}}"'
run 'podman ps -a --format "{{.Names}} {{.Image}}" 2>/dev/null | sed "s/^/root container: /"'

sec "Secret file permissions"
run 'H=$(getent passwd '"$DEPLOY_USER"' | cut -d: -f6); ls -la $H/.config/linkwatch/ 2>&1; stat -c "%a %U %n" $H/.config/linkwatch/*.env 2>/dev/null'
run 'H=$(getent passwd '"$DEPLOY_USER"' | cut -d: -f6); cd $H/zteadmin-ant 2>/dev/null && git remote -v | head -2 && git log -1 --format="%h %cd" && git status --short | head'

sec "Kernel / network hardening"
run 'sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.tcp_syncookies kernel.randomize_va_space net.ipv4.conf.all.rp_filter 2>/dev/null'
sec "Done"
