# Installing Linkwatch on the CentOS Stream 10 VPS

This guide sets up `utilz.perrego.net` (VPS `129.121.123.176`, deploy account
`aperrego`) so that after every push to `main` on GitHub, one command on the
VPS (`deploy/update.sh`) pulls and deploys the new version.

When you're done:

```
Internet ──443──▶ firewalld ──▶ nginx (TLS, Let's Encrypt) ──▶ 127.0.0.1:8080 linkwatch-web ──▶ linkwatch-db
                                                                    ▲
Your LAN: poller ──outbound wss://utilz.perrego.net/api/poller/ws ──┘   (nothing ever connects into your LAN)
You on the VPS: update.sh ── git pull from GitHub, build image, restart, health check, roll back on failure
```

There are two ways to do steps 2 to 9:

* **Script:** copy the repo's `deploy/` folder to the VPS and run
  `sudo bash deploy/bootstrap-centos9.sh aperrego utilz.perrego.net you@example.com`.
  It runs the same commands as below and is safe to run more than once.
* **By hand:** follow the steps below. Each one explains what it does, so you
  know what's on the box.

Commands that start with `sudo` need root. Everything else runs as `aperrego`.

The VPS runs CentOS Stream 10 (EL10). The script and the steps below also
work on Stream 9; where the two differ it says so. The file names still say
`centos9` for history, they cover both.

---

## 1. Before you start

1. **DNS.** At your DNS provider for `perrego.net`, add an A record
   `utilz` → `129.121.123.176`. Check it from any machine:
   ```sh
   dig +short utilz.perrego.net        # should print 129.121.123.176
   ```
2. **Provider firewall.** Some VPS hosts have their own firewall in the control
   panel, separate from the one on the server. If yours does, allow inbound TCP
   22, 80 and 443 there too.
3. **Log in as the deploy account** and confirm the OS:
   ```sh
   ssh aperrego@129.121.123.176
   cat /etc/os-release | head -3        # NAME="CentOS Stream", VERSION="10"
   sudo -v                              # confirms aperrego can use sudo
   ```

## 2. Update the system and turn on the extra repositories

```sh
sudo dnf -y upgrade --refresh
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --set-enabled crb   # CodeReady Builder, needed by EPEL
sudo dnf -y install epel-release            # EPEL 10 has certbot and fail2ban
```

If `epel-release` isn't found, install it straight from Fedora:
`sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm`.
If `config-manager --set-enabled` errors (newer dnf), use
`sudo dnf config-manager setopt crb.enabled=1`. On Stream 9 only, also install
`epel-next-release`; there is no EPEL Next for 10.

If the upgrade installed a new kernel (`dnf needs-restarting -r` says a reboot
is required), run `sudo reboot` and log back in.

## 3. Install the dependencies

```sh
sudo dnf -y install podman nginx firewalld policycoreutils-python-utils curl git tar openssl
sudo dnf -y install certbot python3-certbot-nginx fail2ban    # from EPEL
```

EPEL 10 is newer and sometimes lags a package. If certbot isn't available yet,
install it with pip instead (this is what the script does automatically):

```sh
sudo dnf -y install python3 python3-pip augeas-libs
sudo python3 -m venv /opt/certbot
sudo /opt/certbot/bin/pip install certbot certbot-nginx
sudo ln -sf /opt/certbot/bin/certbot /usr/local/bin/certbot
```

and use the renewal timer the script writes (`certbot-renew.timer`), or see
step 7. If fail2ban is missing, skip step 5 for now; key-only SSH matters more.

| Package | Why |
| --- | --- |
| `podman` | Runs the app and PostgreSQL as containers, rootless, under `aperrego`. It's Red Hat's Docker replacement and ships with CentOS. |
| `nginx` | Public web server. Terminates HTTPS and forwards to the app on `127.0.0.1:8080`. |
| `firewalld` | Host firewall (step 4). |
| `policycoreutils-python-utils` | `semanage`, for SELinux port and boolean changes. |
| `certbot`, `python3-certbot-nginx` | Free Let's Encrypt certificate that renews automatically. |
| `fail2ban` | Bans IPs that keep failing SSH logins. |
| `curl`, `git`, `tar` | Health checks and general tooling. |

Python and PostgreSQL don't get installed on the host. They live inside the
containers.

## 4. Install and configure firewalld

firewalld groups rules into **zones**. Each network interface belongs to a
zone, and the default zone on a VPS is normally `public`. Every rule has two
copies: the **runtime** copy, which is live now and gone after a reboot, and
the **permanent** copy, which is saved to disk. You add rules with
`--permanent`, then `--reload` to load them into the runtime.

The goal is simple: only SSH (22), HTTP (80, for the certificate challenge and
the redirect to HTTPS) and HTTPS (443) come in. The app's port 8080 is bound to
`127.0.0.1` only, so it never needs a rule. Pollers connect *out* from your
LAN to 443, so they don't need one either.

### 4a. Turn it on

```sh
sudo systemctl enable --now firewalld
sudo firewall-cmd --state                     # running
sudo firewall-cmd --get-default-zone          # usually: public
sudo firewall-cmd --get-active-zones          # shows which interface (eth0, ens3…) is in which zone
```

> If you're connected over SSH, don't worry: the `public` zone allows `ssh`
> by default, so turning firewalld on won't cut your session.

### 4b. See what's open now

```sh
sudo firewall-cmd --zone=public --list-all
```

A fresh CentOS Stream install usually shows `services: cockpit dhcpv6-client ssh`.

### 4c. Allow only what Linkwatch needs

```sh
# remove services you don't use (cockpit is the web console on port 9090)
sudo firewall-cmd --permanent --zone=public --remove-service=cockpit
sudo firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client

# allow SSH, HTTP and HTTPS
sudo firewall-cmd --permanent --zone=public --add-service=ssh
sudo firewall-cmd --permanent --zone=public --add-service=http
sudo firewall-cmd --permanent --zone=public --add-service=https

# load the permanent rules into the running firewall
sudo firewall-cmd --reload
```

If your VPS has IPv6 configured and you don't use DHCPv6 on it, removing
`dhcpv6-client` is safe. If your provider hands out IPv6 by DHCPv6 (rare),
skip that line.

### 4d. Verify

```sh
sudo firewall-cmd --zone=public --list-all
#   services: http https ssh
#   ports:                       <- should be empty
```

From your own computer (not the VPS):

```sh
nc -vz 129.121.123.176 22      # succeeded
nc -vz 129.121.123.176 443     # succeeded once nginx is running (step 7)
nc -vz 129.121.123.176 8080    # must time out or be refused
```

### 4e. Optional: lock SSH to your own IP

If your home or office has a fixed public IP, you can let only that address
reach SSH. Replace `203.0.113.10` with your IP (`curl -s ifconfig.me` from
home shows it). Keep your current SSH session open while you test in a second
one.

```sh
sudo firewall-cmd --permanent --zone=public --remove-service=ssh
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="203.0.113.10/32" service name="ssh" accept'
sudo firewall-cmd --reload
```

Don't do this yet. GitHub Actions deploys over SSH from addresses that
change, so this rule would break automatic deploys. If you want both, use the
pull-based alternative described at the end of this guide.

### 4f. Useful firewalld commands later

```sh
sudo firewall-cmd --list-all-zones | less     # everything
sudo firewall-cmd --list-rich-rules           # custom rules
sudo firewall-cmd --runtime-to-permanent      # save runtime-only changes you tested
sudo firewall-cmd --panic-on                  # emergency: drop ALL traffic (console access needed to undo!)
```

## 5. Block SSH brute-forcing (fail2ban)

```sh
sudo tee /etc/fail2ban/jail.d/sshd.local >/dev/null <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 1h
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

On CentOS, fail2ban adds its bans through firewalld, so they show up in
`firewall-cmd --list-rich-rules`.

### Recommended: key-only SSH

Once you can log in with an SSH key, turn off password logins and root login:

```sh
sudo tee /etc/ssh/sshd_config.d/50-hardening.conf >/dev/null <<'EOF'
PasswordAuthentication no
PermitRootLogin no
EOF
sudo sshd -t && sudo systemctl reload sshd
```

Test in a **new** terminal (`ssh aperrego@129.121.123.176`) before you close
the old one.

## 6. Allow nginx to reach the app (SELinux)

CentOS runs SELinux in enforcing mode, which blocks nginx from opening network
connections by default. Allow nginx to proxy to the app:

```sh
getenforce                                         # Enforcing (leave it that way)
sudo setsebool -P httpd_can_network_connect 1
```

## 7. nginx and the TLS certificate

Copy the site config from the repo (`deploy/nginx/utilz.perrego.net.conf`):

```sh
git clone https://github.com/insecurityfyi/zteadmin-ant.git ~/zteadmin-ant   # or scp the deploy/ folder
sudo cp ~/zteadmin-ant/deploy/nginx/utilz.perrego.net.conf /etc/nginx/conf.d/
sudo nginx -t
sudo systemctl enable --now nginx
```

(If the repo is private, `git clone` asks for a GitHub token. It's often
easier to `scp -r deploy aperrego@129.121.123.176:~/` from your own checkout.)

Then get the certificate. DNS from step 1 has to resolve first:

```sh
sudo certbot --nginx -d utilz.perrego.net --agree-tos -m you@example.com --redirect
sudo systemctl enable --now certbot-renew.timer
sudo certbot renew --dry-run
```

Certbot edits the nginx file to add the `listen 443 ssl` lines and certificate
paths, and turns on the redirect from HTTP to HTTPS. Until the app is deployed,
`https://utilz.perrego.net` answers with *502 Bad Gateway*. That's expected.

## 8. Prepare `aperrego` to run the containers

### 8a. Rootless Podman that survives logout

```sh
sudo loginctl enable-linger aperrego     # lets aperrego's systemd services run without a login session
grep aperrego /etc/subuid /etc/subgid    # both should print a range, e.g. aperrego:100000:65536
podman info --format '{{.Host.Security.Rootless}}'   # true
```

If the `subuid`/`subgid` lines are missing:
`sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 aperrego`.

### 8b. Folders and the deploy script

```sh
mkdir -p ~/.config/linkwatch ~/.config/containers/systemd ~/linkwatch/quadlet
cp ~/zteadmin-ant/deploy/quadlet/* ~/linkwatch/quadlet/
cp ~/zteadmin-ant/deploy/deploy.sh ~/linkwatch/ && chmod +x ~/linkwatch/deploy.sh
```

`update.sh` copies fresh versions of these files on every update. This
first copy only matters for running things by hand.

### 8c. Secrets

These two files hold the database password, the encryption key for every
stored credential, and the admin password. They never go into git.

```sh
umask 077
DB_PASS=$(openssl rand -hex 24)
cat > ~/.config/linkwatch/db.env <<EOF
POSTGRES_USER=linkwatch
POSTGRES_DB=linkwatch
POSTGRES_PASSWORD=$DB_PASS
EOF
cat > ~/.config/linkwatch/linkwatch.env <<EOF
LW_DATABASE_URL=postgresql+psycopg://linkwatch:$DB_PASS@linkwatch-db:5432/linkwatch
LW_SECRET_KEY=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_')
LW_ADMIN_PASSWORD=$(openssl rand -base64 18)
LW_PUBLIC_URL=https://utilz.perrego.net
LW_POLL_INTERVAL=300
EOF
grep LW_ADMIN_PASSWORD ~/.config/linkwatch/linkwatch.env    # your web login
```

**Back up `linkwatch.env` somewhere safe** (a password manager is ideal). If
`LW_SECRET_KEY` is lost, every saved SNMP and API credential has to be
entered again.

## 9. First deploy and every update: `update.sh`

The VPS pulls new code from GitHub itself. Nothing on GitHub needs an SSH key
to your server. The workflow is: you (or Claude) push to `main`, then on the
VPS you run one command.

```sh
~/zteadmin-ant/deploy/update.sh
```

It fast-forwards `~/zteadmin-ant` to the latest `main`, builds the web image
with Podman (about two minutes the first time, faster after), installs the
unit files, restarts the app, checks `/healthz`, and rolls back to the previous
image if the new one doesn't come up. The database tables are created and
upgraded by the app when it starts, so there's no separate migration step.
If nothing changed since the last run it says so and stops.

Other forms:

| Command | Does |
| --- | --- |
| `update.sh --force` | Rebuild and restart even if the code didn't change |
| `update.sh 1a2b3c4d5e6f` | Deploy that exact commit, e.g. to go back to an older version (run plain `update.sh` later to return to `main`) |
| `update.sh --skip-ci` | Deploy even if GitHub's tests haven't passed on that commit |

### 9a. Automatic deploys

```sh
~/zteadmin-ant/deploy/enable-auto-update.sh        # turn on
~/zteadmin-ant/deploy/enable-auto-update.sh off    # turn off
journalctl --user -u linkwatch-update -f           # watch it
```

A systemd timer runs `update.sh --auto` every 5 minutes. It deploys a new
commit on `main` only when all of these hold:

* the commit is a fast-forward of what's deployed (a force-pushed or rewritten
  `main` stops it until you look),
* the `pytest` check on GitHub passed for that exact commit (it waits while
  the tests are still running),
* nobody has edited files in `~/zteadmin-ant` on the VPS,
* it didn't already fail its health check. A failed commit is rolled back and
  not retried until a newer commit arrives or you run `update.sh` by hand.

### 9b. Protect `main` on GitHub

Automatic deploys trust whatever lands on `main`, so make GitHub enforce how
it gets there. In **zteadmin-ant → Settings → Branches → Add branch ruleset**
(or *Add rule*), target `main` and turn on:

* **Require a pull request before merging**,
* **Require status checks to pass**, and add `pytest`,
* **Block force pushes** and **Restrict deletions**.

Then every change reaches the VPS only through a reviewed pull request whose
tests passed. The repository is public, so the VPS fetches over HTTPS with no
credentials and nothing on the VPS can write to GitHub.

### 9c. Admin password

The password is in `~/.config/linkwatch/linkwatch.env`:

```sh
grep LW_ADMIN_PASSWORD ~/.config/linkwatch/linkwatch.env    # show it
~/zteadmin-ant/deploy/reset-password.sh                     # set a new random one and restart
~/zteadmin-ant/deploy/reset-password.sh 'your-own-password' # or choose it (12+ characters)
```

If you ever make the repository private, `git fetch` needs a credential. Add a
read-only deploy key: on the VPS run
`ssh-keygen -t ed25519 -f ~/.ssh/github_ro -N ""`, paste `~/.ssh/github_ro.pub`
into **GitHub → zteadmin-ant → Settings → Deploy keys** (leave *Allow write
access* off), then
`git -C ~/zteadmin-ant remote set-url origin git@github.com:insecurityfyi/zteadmin-ant.git`
and add to `~/.ssh/config`:

```
Host github.com
  IdentityFile ~/.ssh/github_ro
```

After the first run, check it:

```sh
systemctl --user status linkwatch-db linkwatch-web
curl -s http://127.0.0.1:8080/healthz        # {"ok":true,"version":"0.1.0"}
journalctl --user -u linkwatch-web -f        # live logs
```

Then open **https://utilz.perrego.net** and sign in with `LW_ADMIN_PASSWORD`.

## 10. Install the poller on your LAN

In the web UI, open **Pollers → Add poller**. It shows a one-time command
like the one below. Run it on any always-on Linux box on your network: a
small VM or LXC container on Proxmox works well.

```sh
podman run -d --name linkwatch-poller --restart=always \
  -e LW_SERVER=https://utilz.perrego.net \
  -e LW_ENROLL_TOKEN=enr_xxxxxxxx \
  -e LW_POLLER_NAME=poller-hq-01 \
  -v linkwatch-poller:/var/lib/linkwatch \
  ghcr.io/insecurityfyi/linkwatch-poller:latest
```

The poller needs outbound TCP 443 to `utilz.perrego.net`, plus UDP 161 and
ICMP to your devices. It needs nothing inbound. See `docs/poller.md` for
running it under systemd and for updating it.

Then:

1. **Settings → SNMP credentials:** add your v3 user (or v2c community).
2. **Discovery:** scan your subnets from the poller (ping + SNMP with your saved credentials) and add what it finds in bulk. Or use **Devices → Import CSV** / **Add device**.
3. **Integrations:** add Zscaler (OneAPI), Meraki, PAN-OS, FortiGate, UniFi
   and Proxmox. Cloud APIs run on the server; PAN-OS, FortiGate, UniFi and
   Proxmox run on the poller you choose.
4. **Settings → Where alerts are sent:** add email or Teams and press
   **Send test**.

---

## Day-to-day

| Task | Command (as `aperrego`) |
| --- | --- |
| Logs | `journalctl --user -u linkwatch-web -f` |
| Update to the latest code | `~/zteadmin-ant/deploy/update.sh` |
| Automatic updates on/off | `~/zteadmin-ant/deploy/enable-auto-update.sh` / `... off` |
| Reset admin password | `~/zteadmin-ant/deploy/reset-password.sh` |
| Restart | `systemctl --user restart linkwatch-web` |
| Roll back by hand | `podman tag ghcr.io/insecurityfyi/linkwatch:previous ghcr.io/insecurityfyi/linkwatch:current && systemctl --user restart linkwatch-web` |
| Database backup | `podman exec linkwatch-db pg_dump -U linkwatch linkwatch \| gzip > ~/linkwatch-$(date +%F).sql.gz` |
| Restore | `gunzip -c backup.sql.gz \| podman exec -i linkwatch-db psql -U linkwatch linkwatch` |
| Disk use | `podman system df` and `du -sh ~/.local/share/containers` |

A nightly backup with cron (`crontab -e` as `aperrego`):

```
15 3 * * * podman exec linkwatch-db pg_dump -U linkwatch linkwatch | gzip > ~/backups/linkwatch-$(date +\%a).sql.gz
```

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| 502 Bad Gateway | App not running, or SELinux blocking nginx | `systemctl --user status linkwatch-web`; `getsebool httpd_can_network_connect` must be `on` |
| Deploy job: `Permission denied (publickey)` | Deploy key not in `authorized_keys`, or `VPS_SSH_KEY` copied without its first/last lines | Redo the key steps under *Optional: deploy from GitHub Actions* |
| Deploy job: `Host key verification failed` | `VPS_SSH_KNOWN_HOSTS` missing or for a different key type | Re-run `ssh-keyscan -t ed25519 129.121.123.176` and update the secret |
| `Failed to connect to bus` when running `systemctl --user` over plain `su` | No user session | Log in as `aperrego` over SSH (not `su`), or `export XDG_RUNTIME_DIR=/run/user/$(id -u)` |
| Services gone after reboot | Linger not enabled | `sudo loginctl enable-linger aperrego` |
| Poller log: `HTTP 403` | Poller was revoked, or its key was deleted | Delete the poller volume and enroll again with a new token |
| Poller shows devices down but they're up | Poller can't reach UDP 161 or ICMP, or the SNMP credentials are wrong | From the poller box: `snmpget -v3 -l authPriv -u USER -a SHA -A ... -x AES -X ... DEVICE 1.3.6.1.2.1.1.5.0` |
| Certificate didn't renew | Port 80 closed or DNS changed | `sudo certbot renew --dry-run` shows why |

## Optional: deploy from GitHub Actions instead

Every push to `main` already builds both images on GitHub (the poller image is
needed on your LAN). Deploying to the VPS from GitHub is off unless you start
it yourself: **Actions → deploy → Run workflow**. That needs the SSH key
below; skip all of this if you use `update.sh`.

You need a dedicated SSH key that only GitHub Actions uses.

### Create the deploy key (on your own computer)

```sh
ssh-keygen -t ed25519 -f linkwatch-deploy -C "github-actions deploy" -N ""
```

This makes `linkwatch-deploy` (private) and `linkwatch-deploy.pub` (public).

### Authorize it for `aperrego` (on the VPS)

```sh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
# paste the single line from linkwatch-deploy.pub after the word restrict:
echo 'restrict ssh-ed25519 AAAA...your-key... github-actions deploy' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

`restrict` turns off port forwarding, agent forwarding and terminals for this
key. It can still run the deploy commands and copy files.

### Add the secrets to the repository

In GitHub, open **zteadmin-ant → Settings → Secrets and variables → Actions**
and add:

| Secret | Value |
| --- | --- |
| `VPS_SSH_KEY` | Full contents of the private file `linkwatch-deploy` |
| `VPS_SSH_KNOWN_HOSTS` | Output of `ssh-keyscan -t ed25519 129.121.123.176` |

The host and user default to `129.121.123.176` and `aperrego`. To change them
later, set the repository variables `VPS_HOST` and `VPS_USER` on the same
page, under the Variables tab.

Delete the private key from your computer once it's saved in GitHub, or keep
it in your password manager.

### Container images

The workflow publishes two images to GitHub Container Registry:
`ghcr.io/insecurityfyi/linkwatch` (web) and `ghcr.io/insecurityfyi/linkwatch-poller`.
The VPS logs in with the workflow's own short-lived token on every deploy, so
the web image can stay private.

For the poller on your LAN, either:

* make the poller package public (**GitHub → your profile → Packages →
  linkwatch-poller → Package settings → Change visibility**). It contains no
  secrets. Or:
* log in on the poller machine with a classic personal access token that has
  only `read:packages`: `podman login ghcr.io -u insecurityfyi`.

### What the manual run does

When you press **Run workflow**, it:

1. runs the tests,
2. builds both images and pushes them to GHCR,
3. copies `deploy/quadlet/*` and `deploy/deploy.sh` to the VPS,
4. runs `deploy.sh <tag>`, which pulls the image, tags it `:current`, restarts
   the service, polls `/healthz`, and rolls back to `:previous` if the new
   version doesn't come up.

## Alternative: fully automatic pulls

If you want updates with no command at all, run `podman auto-update` from a systemd timer, with
`AutoUpdate=registry` and `Image=ghcr.io/insecurityfyi/linkwatch:latest` in
`linkwatch-web.container`. Deploys then lag a push by up to the timer's
interval, and you lose the automatic health check and rollback in `deploy.sh`.
