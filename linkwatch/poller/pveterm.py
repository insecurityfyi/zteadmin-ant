"""Proxmox text consoles (LXC console, VM serial port, node shell), relayed to the server.

Unlike SSH, the poller is the console client here: it holds the Proxmox API token, so it asks Proxmox for a
``termproxy`` ticket, opens Proxmox's console WebSocket itself and relays plain terminal bytes over a tunnel
socket to the server (the same ``/api/poller/ws/tunnel/<sid>`` socket SSH uses). Nothing connects in to the
poller's network.

Proxmox's termproxy framing, which this module hides from the server:

* first frame to Proxmox: ``<user>:<ticket>\\n``; Proxmox answers ``OK``;
* keystrokes: ``0:<byte length>:<bytes>``; terminal size: ``1:<cols>:<rows>:``; keepalive: ``2``;
* everything Proxmox sends after ``OK`` is terminal output.

On the tunnel socket, binary frames are terminal bytes and text frames are JSON control messages
(``{"type": "resize", "cols": 120, "rows": 40}``), as in the browser console protocol.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
from urllib.parse import quote

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from ..integrations import IntegrationError, build
from . import tunnel

log = logging.getLogger("linkwatch.poller.pveterm")
KEEPALIVE = 30.0


def frame_input(data: bytes) -> bytes:
    return b"0:" + str(len(data)).encode() + b":" + data


def frame_resize(cols: int, rows: int) -> bytes:
    return f"1:{int(cols)}:{int(rows)}:".encode()


def _ssl(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def run(ws_base: str, key: str, sid: str, integ: dict | None, node: str, vtype: str | None, vmid, cols: int = 80,
              rows: int = 24) -> None:
    url = f"{ws_base}/api/poller/ws/tunnel/{sid}"
    try:
        async with connect(url, additional_headers={"Authorization": f"Bearer {key}"}, ping_interval=30,
                           ping_timeout=30, max_size=4 * 2**20, open_timeout=20) as ws:
            if not tunnel.enabled():
                await ws.send(json.dumps({"ok": False, "error": "Consoles through this poller are turned off (LW_TUNNEL=off on the poller host)."}))
                return
            if not integ or integ.get("kind") != "proxmox":
                await ws.send(json.dumps({"ok": False, "error": "This poller doesn't run that Proxmox integration. Press Sync now and try again."}))
                return
            client = build("proxmox", integ["config"])
            try:
                path, info = await asyncio.to_thread(client.termproxy, node, vtype, vmid)
            except IntegrationError as exc:
                await ws.send(json.dumps({"ok": False, "error": str(exc)}))
                return
            finally:
                client.close()
            base = client.base.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
            pve_url = f"{base}/api2/json{path}?port={int(info['port'])}&vncticket={quote(str(info['ticket']), safe='')}"
            try:
                pve = await connect(pve_url, additional_headers=client.auth, subprotocols=["binary"],
                                    ssl=_ssl(bool(integ["config"].get("verify_tls", True))) if pve_url.startswith("wss") else None,
                                    open_timeout=15, ping_interval=None, max_size=4 * 2**20)
            except Exception as exc:
                await ws.send(json.dumps({"ok": False, "error": f"Could not open the Proxmox console: {exc.__class__.__name__}: {exc}"[:300]}))
                return
            try:
                await pve.send(f"{info.get('user') or integ['config'].get('token_id')}:{info['ticket']}\n".encode())
                first = await asyncio.wait_for(pve.recv(), 15)
                if (first if isinstance(first, bytes) else first.encode())[:2] != b"OK":
                    await ws.send(json.dumps({"ok": False, "error": "Proxmox refused the console ticket."}))
                    return
                await pve.send(frame_resize(cols, rows))
                await ws.send(json.dumps({"ok": True}))
                log.info("Proxmox console %s… open to %s %s %s", sid[:6], node, vtype or "shell", vmid or "")
                await _relay(ws, pve, first[2:] if isinstance(first, bytes) else first[2:].encode())
            except (asyncio.TimeoutError, ConnectionClosed):
                try:
                    await ws.send(json.dumps({"ok": False, "error": "The Proxmox console closed before it was ready."}))
                except ConnectionClosed:
                    pass
            finally:
                await pve.close()
            log.info("Proxmox console %s… closed", sid[:6])
    except (OSError, ConnectionClosed, asyncio.TimeoutError) as exc:
        log.warning("Proxmox console %s… failed: %s", sid[:6], exc.__class__.__name__)
    except Exception:
        log.exception("Proxmox console %s… failed", sid[:6])


async def _relay(ws, pve, leftover: bytes = b"") -> None:
    if leftover:
        await ws.send(leftover)

    async def up() -> None:            # Proxmox -> server
        async for msg in pve:
            await ws.send(msg if isinstance(msg, bytes) else msg.encode())

    async def down() -> None:          # server -> Proxmox
        async for msg in ws:
            if isinstance(msg, bytes):
                await pve.send(frame_input(msg))
                continue
            try:
                ctl = json.loads(msg)
            except ValueError:
                continue
            if ctl.get("type") == "resize":
                try:
                    await pve.send(frame_resize(max(20, min(500, int(ctl.get("cols") or 80))), max(5, min(200, int(ctl.get("rows") or 24)))))
                except (TypeError, ValueError):
                    pass

    async def keepalive() -> None:
        while True:
            await asyncio.sleep(KEEPALIVE)
            await pve.send(b"2")

    tasks = [asyncio.create_task(c) for c in (up(), down(), keepalive())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
