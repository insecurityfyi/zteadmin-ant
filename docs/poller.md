# The Linkwatch poller

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
| `LW_TUNNEL` | `on` | `off` refuses SSH console tunnels through this poller (see [ssh.md](ssh.md)) |
| `LW_TUNNEL_PORTS` | `22` | TCP ports a tunnel may reach, comma separated, or `any` |
