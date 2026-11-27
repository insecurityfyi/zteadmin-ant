"""Reverse tunnels: a TCP connection from the poller to a host on its network, carried back to the server.

The server never connects in. When an admin opens an SSH console, the server sends ``tunnel_open`` down the
poller's existing WebSocket. The poller then opens a *second* outbound WebSocket to
``/api/poller/ws/tunnel/<sid>`` (authenticated with its key), connects to the requested host and port, and
copies bytes both ways until either side closes. SSH itself runs end to end between the server and the device,
so the poller only ever sees encrypted traffic and never the login.

Environment:
    LW_TUNNEL        "on" (default) or "off" to refuse every tunnel request
    LW_TUNNEL_PORTS  TCP ports the server may ask for, comma separated (default "22"); "any" allows every port
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

log = logging.getLogger("linkwatch.poller.tunnel")
CONNECT_TIMEOUT = 10.0
CHUNK = 64 * 1024


def enabled() -> bool:
    return os.environ.get("LW_TUNNEL", "on").strip().lower() not in ("off", "0", "no", "false")


def allowed_ports() -> set[int] | None:
    """None means any port."""
    raw = os.environ.get("LW_TUNNEL_PORTS", "22").strip().lower()
    if raw in ("any", "*", "all"):
        return None
    ports = set()
    for part in raw.replace(" ", "").split(","):
        if part.isdigit() and 0 < int(part) < 65536:
            ports.add(int(part))
    return ports


def refusal(host: str, port: int) -> str | None:
    if not enabled():
        return "SSH through this poller is turned off (LW_TUNNEL=off on the poller host)."
    if not host or len(host) > 255 or any(c.isspace() for c in host):
        return "Invalid host name."
    ports = allowed_ports()
    if ports is not None and port not in ports:
        allowed = ", ".join(str(p) for p in sorted(ports)) or "none"
        return f"This poller only allows tunnels to port {allowed}. Set LW_TUNNEL_PORTS on the poller to allow {port}."
    return None


async def run(ws_base: str, key: str, sid: str, host: str, port: int) -> None:
    """Open one tunnel. Errors are reported to the server on the tunnel socket so the admin sees why."""
    url = f"{ws_base}/api/poller/ws/tunnel/{sid}"
    try:
        async with connect(url, additional_headers={"Authorization": f"Bearer {key}"}, ping_interval=30,
                           ping_timeout=30, max_size=4 * 2**20, open_timeout=20) as ws:
            problem = refusal(host, port)
            if problem:
                await ws.send(json.dumps({"ok": False, "error": problem}))
                return
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                await ws.send(json.dumps({"ok": False, "error": f"No answer from {host} port {port} within {CONNECT_TIMEOUT:.0f} s."}))
                return
            except OSError as exc:
                await ws.send(json.dumps({"ok": False, "error": f"Could not connect to {host} port {port}: {exc.strerror or exc}"}))
                return
            log.info("Tunnel %s… open to %s:%s", sid[:6], host, port)
            await ws.send(json.dumps({"ok": True}))
            sent = received = 0

            async def up() -> None:          # device -> server
                nonlocal sent
                while data := await reader.read(CHUNK):
                    sent += len(data)
                    await ws.send(data)

            async def down() -> None:        # server -> device
                nonlocal received
                async for msg in ws:
                    if isinstance(msg, bytes):
                        received += len(msg)
                        writer.write(msg)
                        await writer.drain()

            tasks = [asyncio.create_task(up()), asyncio.create_task(down())]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            log.info("Tunnel %s… to %s:%s closed (%d bytes up, %d down)", sid[:6], host, port, sent, received)
    except (OSError, ConnectionClosed, asyncio.TimeoutError) as exc:
        log.warning("Tunnel %s… to %s:%s failed: %s", sid[:6], host, port, exc.__class__.__name__)
    except Exception:
        log.exception("Tunnel %s… failed", sid[:6])
