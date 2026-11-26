# The Linkwatch poller

The poller runs inside your network and does all of the SNMP, ping and on-prem
API work. It needs:

* **Outbound** TCP 443 to `utilz.perrego.net`. This is the only connection it
  makes to the internet.
* UDP 161 (SNMP) and ICMP to the devices it polls, and HTTPS to the on-prem
  APIs (PAN-OS, FortiGate, UniFi, Proxmox) you assign to it.
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

## Running under systemd (recommended)

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
