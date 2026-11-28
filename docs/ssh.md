# SSH consoles through a poller

Admins can open an SSH session to any device a poller can reach, in a pop-out browser window, without opening
any inbound port at the remote site.

## Using it

* **From a device:** press **SSH** at the top of the device page (offered for Linux, Unix and network
  equipment, and for devices whose OS isn't recognised; see [rdp.md](rdp.md#which-button-a-device-offers)). A window opens; sign in with a user name and
  a password or a pasted private key. Use the port field in the URL (`&port=2222`) for a non-standard port.
* **From the Pollers page:** each connected poller has *SSH through this poller to* with a host and port.
  `127.0.0.1` is the poller host itself when the poller container runs with host networking.
* Tick **Save this login for this host** to keep it for next time. It is encrypted with `LW_SECRET_KEY`
  like every other stored credential; the window then offers *Connect as &lt;user&gt;* and *Forget saved login*.
* **Disconnect** closes the session; closing the window does too. Sessions close after 30 minutes with no
  typing and no output, and after 12 hours in any case.

Only admins see the SSH buttons, and only admins can open the window or its WebSocket.

## How it works

```
browser ──wss──▶ VisCon1 server ──(existing poller WebSocket: "tunnel_open")──▶ poller
                       ▲                                                           │
                       └──────wss /api/poller/ws/tunnel/<id> (poller dials out)───┘──tcp──▶ device:22
```

1. The pop-out talks to the server over a WebSocket (`/api/poller/ws/console`).
2. The server asks the device's poller, over the connection the poller already holds open, for a tunnel to
   the device's address and port.
3. The poller connects to the device, then opens a **second outbound** WebSocket back to the server and
   relays raw TCP bytes over it. Nothing connects in to the poller or the site.
4. The **SSH client runs on the server** (asyncssh), over that tunnel. SSH is end to end between the server and
   the device, so the poller only ever relays encrypted traffic, and the login never reaches the poller.

Both WebSockets live under `/api/poller/ws`, so the nginx site config needs no change.

## Security

* **Admin only.** Read-only users don't get the button, the page answers 403 and the WebSocket refuses them.
  The WebSocket also checks the browser's Origin, so another site can't open a console with your session.
* **Audit log.** Every session start (`opened SSH session`), end (`closed SSH session`, with length, bytes and
  why it ended), failure, and every *forget* is in Administration > Audit log, with the user, address, target
  and poller. Keystrokes are not recorded.
* **Host keys are pinned.** The first connection to a host saves its key and shows the fingerprint. After that,
  a different key is refused *before* any password is sent, with a *HOST KEY CHANGED* warning. If the device was
  reinstalled, press **Forget host key** in the window and connect again.
* **Credentials.** Typed logins are used for that session only and cleared from the form. Saved logins are
  sealed with `LW_SECRET_KEY` in the `ssh_targets` table; only the user name is stored readable.
* **Poller-side limits.** A poller only opens tunnels to ports 22 and 3389 (remote desktop, see
  [rdp.md](rdp.md)) unless you set `LW_TUNNEL_PORTS` (for example `22,2222`, or `any`). Set `LW_TUNNEL=off` on a poller to refuse tunnels altogether; its Pollers
  card then shows SSH as unavailable. At most 8 sessions run through one poller at a time.

## Requirements

* The poller must run an image with SSH support. Older pollers show *Update this poller* on the Open button;
  run the update command from the Pollers page on the poller host (it keeps the poller's key).
* The server image needs `asyncssh` (in `requirements-server.txt`); `deploy/update.sh` rebuilds it.

## Troubleshooting

| Message | Meaning |
| --- | --- |
| Poller ... is not connected | The poller is offline; check it on the Pollers page. |
| This poller only allows tunnels to ports 22, 3389 | Set `LW_TUNNEL_PORTS` on the poller and restart it. |
| Could not connect to ... / No answer from ... | The poller can't reach that address and port: firewall, wrong IP or SSH off on the device. |
| Sign-in refused | Wrong user name, password or key. |
| HOST KEY CHANGED | The device presents a different key than the first time. Check why before forgetting the key. |
