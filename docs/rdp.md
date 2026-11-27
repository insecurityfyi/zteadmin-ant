# Remote desktop (RDP) through a poller

Admins can open a remote desktop to any Windows (or xrdp) machine a poller can reach, in a pop-out browser
window, without opening any inbound port at the remote site. It works like the [SSH console](ssh.md).

## Using it

* **From a device:** press **Remote desktop** at the top of the device page.
* **From the Pollers page:** type a host, leave the port empty (3389) and press **Remote desktop**.
* Sign in with a user name, password and optional domain, or leave the user name empty to sign in on the
  computer's own login screen. **Connection options** has the security mode (Negotiate, NLA, TLS, RDP) and
  *Accept the computer's certificate even if it is self-signed*, which is on by default because almost every
  RDP host uses a self-signed certificate.
* Tick **Save this login for this computer** to keep it, encrypted with `LW_SECRET_KEY`.
* The toolbar has **Ctrl+Alt+Del**, **Send clipboard** (puts the text on your clipboard onto the remote
  clipboard; text copied on the remote computer lands on yours when the browser allows it), **Full screen** and
  **Disconnect**. The remote screen follows the window size.
* Sessions close after 30 minutes without keyboard or mouse input, and after 12 hours in any case.

## How it works

```
browser ──wss──▶ linkwatch-web ──tcp──▶ linkwatch-guacd (Apache Guacamole)
                      ▲                       │ RDP, to a one-off port on linkwatch-web
                      └──── relay ◀───────────┘
                      │
                      └──wss /api/poller/ws/tunnel/<id> (the poller dials out)──▶ poller ──tcp──▶ host:3389
```

1. The pop-out posts the login to the server, which keeps it and hands back a one-time token (the login is
   never put in a URL).
2. The server asks the poller for a tunnel to the host, exactly as for SSH. The poller connects to port 3389
   and dials back out with a second WebSocket.
3. The server opens a one-off TCP listener and tells **guacd** to connect to *that* instead of the real host.
   The listener accepts a single connection, only from guacd's address, and relays it over the tunnel.
4. guacd speaks RDP to the computer and the Guacamole protocol to the browser (via the server). The browser
   runs Apache's `guacamole-common-js`, vendored under `static/vendor/guacamole`.

guacd never needs a route to the remote site, nothing connects in to the site, the poller relays the
RDP connection's TLS-encrypted bytes only, and the login goes to guacd and nowhere else.

## Installing guacd

`deploy/quadlet/linkwatch-guacd.container` runs `docker.io/guacamole/guacd:1.6.0` on the `linkwatch` network
with no published port. `deploy/update.sh` (or `deploy.sh`) installs and starts it with the web app; the web
unit `Wants=` it, so the app still starts if guacd doesn't. To start it by hand:

```sh
systemctl --user daemon-reload
systemctl --user start linkwatch-guacd.service
```

Settings on the web container (the defaults fit the Quadlet setup):

| Variable | Default | |
| --- | --- | --- |
| `LW_GUACD` | `linkwatch-guacd:4822` | Where guacd listens |
| `LW_GUACD_CALLBACK_HOST` | `linkwatch-web` | Name guacd uses to reach the web container's one-off listeners |
| `LW_GUACD_CALLBACK_BIND` | `0.0.0.0` | Address those listeners bind to (inside the container; not published) |

For a local run: `guacd -b 127.0.0.1 -l 4822` and set `LW_GUACD=127.0.0.1:4822 LW_GUACD_CALLBACK_HOST=127.0.0.1`.

## Pollers

Pollers allow ports 22 and 3389 by default (`LW_TUNNEL_PORTS`). A poller that advertises remote desktop shows
the button enabled; an older one says to update it. If a host uses another port, add it to `LW_TUNNEL_PORTS`
on that poller and enter the port on the Pollers page or as `&port=` on the `/rdp` link.

## Security

* Admin only, Origin-checked, one-time tokens tied to the admin who asked for them.
* Audit log: `opened RDP session`, `closed RDP session` (length and why it ended) and `RDP session failed`.
* The RDP host's certificate is not pinned (guacd can't); turn off *Accept the computer's certificate* for hosts
  with a proper certificate. The hop from the poller to the host is on that site's LAN.
* Audio, drive and printer redirection are off.

## Troubleshooting

| Message | Meaning |
| --- | --- |
| The remote desktop service (guacd ...) isn't reachable | `linkwatch-guacd` isn't running: `systemctl --user status linkwatch-guacd`. |
| Poller ... doesn't support remote desktop | Update the poller, or add 3389 to its `LW_TUNNEL_PORTS`. |
| Could not connect to ... port 3389 | The poller can't reach the host: firewall, wrong IP or RDP off. |
| Disconnected right after connecting | Usually the security mode or a refused login; try Negotiate, or NLA with a domain. |

## Which button a device offers

Device pages show SSH and Remote desktop according to the operating system the device reports (SNMP
sysDescr and sysObjectID, the platform an integration gives, and the device type):

| Detected | SSH | Remote desktop |
| --- | --- | --- |
| Windows | greyed out | yes |
| Linux, Unix, network equipment | yes | greyed out |
| Not recognised | yes | yes |

Hover a greyed-out button to see why. To change it for one device (a Windows server with OpenSSH, a Linux
box with xrdp), pick **Edit > Remote access**: Automatic, SSH only, Remote desktop only, both, or neither.
The SSH and remote desktop windows follow the same setting for that device. The Pollers page form still
reaches any host.
