# The VisCon1 poller

The poller runs inside your network and does all of the SNMP, ping and on-prem
API work. It needs:

* **Outbound** TCP 443 to `utilz.perrego.net`. This is the only connection it
  makes to the internet.
* UDP 161 (SNMP) and ICMP to the devices it polls, and HTTPS to the on-prem
  APIs (PAN-OS, FortiGate, UniFi, Proxmox) you assign to it. For Proxmox that is port 8006,
  which also carries VM actions and consoles. Setup: [unifi.md](unifi.md), [proxmox.md](proxmox.md).
* **Nothing inbound.** No port forwards, no VPN.

One poller comfortably handles about 150 devices at a 5-minute interval. Add a
second poller for another site, or if the *Last cycle* time on the Pollers
page gets close to the interval.

## How it connects

1. On first start it posts the one-time enrollment token to
   `/api/poller/enroll` and receives its own random key. The key is saved to
   `/var/lib/linkwatch/identity.json` (mode 0600, in the volume).
2. It opens a WebSocket to `wss://utilz.perrego.net/api/poller/ws` with that
   key and keeps it open. The server sends the device list, SNMP credentials
   and API settings down this connection. Credentials are held in memory
   only, never written to disk on the poller.
3. Every cycle it writes the results to a spool folder in the volume, then
   sends them. The server acknowledges each batch, and acknowledged batches
   are deleted. If the connection is down, polling continues and the spool
   is sent in order once the server is reachable again, so graphs have no
   gaps. Up to 5,000 batches are kept, about 17 days at a 5-minute interval.
4. **Revoke** on the Pollers page cuts it off immediately.

## Install script (quickest)

Pollers > **Add poller** shows a ready-made command with a one-time token. It
runs [`deploy/install-poller.sh`](../deploy/install-poller.sh) as root:

```sh
curl -fsSL https://raw.githubusercontent.com/insecurityfyi/zteadmin-ant/main/deploy/install-poller.sh \
  | sudo bash -s -- --server https://utilz.perrego.net --token enr_... --name poller-hq-01
```

It installs Podman, curl and the SNMP tools (apt, dnf/yum or zypper), checks it
can reach `/healthz`, pulls the image, starts the container on the host's
network with `NET_RAW`, a key volume and restart-on-boot (`podman-restart.service`), and waits for
"Connected". It saves the server and name in `/etc/linkwatch-poller.env`, so
running it again with no arguments updates the poller to the latest image
without a new token, and moves a poller that was on Podman's bridge network
onto the host's network. `--uninstall` removes the container and keeps the key.
`--network bridge` keeps the container on the runtime's own network instead
(remembered for later updates).
In a Proxmox LXC container, turn on *Options > Features > Nesting* (and
*keyctl* if it is unprivileged) before running it.

## Managing pollers from the Pollers page

Admins can push commands to pollers from **Pollers**, one at a time (the
buttons on each poller) or several at once (tick the pollers, or *Select all
connected*, and use the bar at the top). Each poller shows the result of its
last command: who sent it, whether it passed or failed, and why.

* **Reload config** sends the poller its devices, credentials, local APIs and
  path probes again, then asks what it now holds. It passes when the poller
  reports the same numbers it was sent, and fails if the poller is offline,
  doesn't answer within 30 seconds, or holds something else.
* **Update** has the poller's host pull the latest image and recreate the
  container. It passes when the host reports success and the poller reconnects;
  the result shows the version and build it came back with (for example
  *Updated from v0.1.0 (sha-1a2b…) to v0.1.0 (sha-3c4d…)*). A failed pull or
  start shows the installer's error. No result within 10 minutes fails it.

### The update helper

A container can't replace itself, so the install script adds a small helper on
the host (rootful Podman or Docker with systemd):

* `linkwatch-poller-helper.path` watches `control/update.request` in the poller's
  volume. The poller writes that file, containing only a request id, when you
  press Update.
* `linkwatch-poller-helper.service` then runs `/usr/local/sbin/linkwatch-poller-helper`,
  which downloads the current `install-poller.sh` (falling back to the copy in
  `/usr/local/lib/linkwatch-poller/`), runs it exactly as you would by hand,
  and writes `control/update.result`. The new container reads that file and
  reports it to the server.

Nothing from the volume is ever executed on the host, and the container gets no
access to the Podman or Docker socket. The helper's log is in
`journalctl -u linkwatch-poller-helper`. Pollers installed before the helper
existed, or started by hand, need the install script run on them once; pressing
Update on such a poller explains this and shows the command. `--no-helper`
skips it, and `--uninstall` removes it.

If Update fails with *Permission denied* on `control/.update.request.tmp`, the
`control` folder in the volume has the wrong owner or SELinux label (installs
from before this was fixed gave it the label `container_var_lib_t`, which the
container can't write). Run the install script again, or fix it by hand:

```sh
d=$(podman volume inspect -f '{{.Mountpoint}}' linkwatch-poller)/control
sudo chown 10001:10001 "$d" && sudo chcon -R --reference="$(dirname "$d")" "$d"
```

## Poller names

*Settings > Poller names* sets a base name, such as `poller-hq`. Every poller
enrolled after that is named `poller-hq.1`, `poller-hq.2`, `poller-hq.3`… using
the lowest number not already taken, whatever `--name` the install command
passed. Existing pollers keep their names; use *Rename* on the Pollers page to
bring them into the scheme. With no base name, the name given at install is
used (and a duplicate gets `-2`, `-3`…).

## Factory reset

*Factory reset* on a poller (admins only) asks you to type the poller's name,
then tells the poller to delete its key, its spool of unsent results and its
update state. Credentials are only ever held in memory, so nothing else is
left. The poller then sits idle waiting to be enrolled again, without
restarting in a loop, and the server deletes its record; its devices, local
APIs and path probes are left without a poller. The reset is written to the
audit log and the event log.

To use the machine again, press **Add poller** and run the install command
with the new token on it. If the poller is offline, the reset is refused
unless you tick *Remove it from the server even if the poller doesn't answer*;
its key stops working, and you can clean up the host with
`install-poller.sh --uninstall` and `podman volume rm linkwatch-poller`.

## Host networking

The install script runs the poller with `--network host`. The poller then
polls, pings and traces from the machine's own address and interfaces. On
Podman's default bridge network it would instead appear behind NAT, with the
bridge gateway 10.88.0.1 as its first hop in path probes. The poller never
listens on a port, so there are no port mappings to keep, and `NET_RAW` still
lets ping and `mtr` open raw sockets.

This applies to rootful containers (the install script runs as root). In a
rootless container (below), leave out `Network=host`: the host's network
belongs to the host's user namespace, so the container's `NET_RAW` doesn't
count there and ping and path probes stop working.

## Running under systemd as a non-root user

On a Debian/Ubuntu/Rocky VM or LXC container with Podman:

```sh
sudo useradd -m -s /bin/bash lwpoller
sudo loginctl enable-linger lwpoller
sudo -iu lwpoller
mkdir -p ~/.config/containers/systemd
cat > ~/.config/containers/systemd/linkwatch-poller.container <<'EOF'
[Container]
ContainerName=linkwatch-poller
Image=ghcr.io/insecurityfyi/linkwatch-poller:latest
Environment=LW_SERVER=https://utilz.perrego.net
Environment=LW_POLLER_NAME=poller-hq-01
# Only needed for the first start; remove after the poller shows up as connected.
Environment=LW_ENROLL_TOKEN=enr_xxxxxxxx
Volume=linkwatch-poller:/var/lib/linkwatch
AddCapability=NET_RAW
AutoUpdate=registry

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user start linkwatch-poller
journalctl --user -u linkwatch-poller -f
```

To keep it updated automatically, enable Podman's update timer:
`systemctl --user enable --now podman-auto-update.timer`.

With Docker instead of Podman, use the `docker run` command shown on the
Pollers page. `--restart=always` keeps it running across reboots.

## Ping inside a container

The poller runs as an unprivileged user. Give the container the `NET_RAW`
capability so ping can send ICMP: `--cap-add=NET_RAW` on the run command, or
`AddCapability=NET_RAW` in the `.container` file. Podman leaves `NET_RAW` out
by default.

Without it, ping still works if the host allows ICMP datagram sockets
(`net.ipv4.ping_group_range`); otherwise the poller logs
"ping can't open an ICMP socket" once and devices show no ping data. Don't use
`--sysctl net.ipv4.ping_group_range=...` inside an LXC container: it fails with
`crun: write to /proc/sys/net/ipv4/ping_group_range: Invalid argument`.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `LW_SERVER` | (required) | `https://utilz.perrego.net` |
| `LW_ENROLL_TOKEN` | | One-time token from the Pollers page, first start only |
| `LW_POLLER_NAME` | hostname | Name shown in the UI |
| `LW_DATA_DIR` | `/var/lib/linkwatch` | Identity and spool |
| `LW_CONCURRENCY` | `32` | Devices polled at the same time |
| `LW_LOG_LEVEL` | `INFO` | `DEBUG` for troubleshooting |
| `LW_TUNNEL` | `on` | `off` refuses SSH and remote desktop tunnels through this poller (see [ssh.md](ssh.md), [rdp.md](rdp.md)) |
| `LW_TUNNEL_PORTS` | `22,3389` | TCP ports a tunnel may reach, comma separated, or `any` |
| `LW_BUILD` | set by the image build | Build id reported to the server, used to confirm updates |
