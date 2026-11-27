"""Remote desktop (RDP) through a poller's outbound tunnel, in a pop-out browser window.

Same shape as the SSH console (see ssh.py), with Apache Guacamole doing the RDP part:

    browser (guacamole-common-js) ──wss──▶ Linkwatch server ──tcp──▶ guacd (sidecar container)
                                                 ▲                       │ RDP, to a one-off port on the server
                                                 └── relay ◀─────────────┘
                                                 │
                                                 └──wss (poller dials out)──▶ poller ──tcp──▶ host:3389

guacd is told to connect to a one-off listener on this server instead of the real host; that listener carries
the bytes over the poller's reverse tunnel. So guacd needs no route to the remote site, nothing connects in to
the site, and the RDP login goes to guacd only (never to the browser after it is typed, never to the poller).

Settings (environment of the web container):
    LW_GUACD                 host:port of guacd (default linkwatch-guacd:4822)
    LW_GUACD_CALLBACK_HOST   name guacd uses to reach this server (default linkwatch-web)
    LW_GUACD_CALLBACK_BIND   address the one-off listeners bind to (default 0.0.0.0, only reachable on the
                             container network since the port isn't published)
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import secrets
import socket
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from .gateway import TunnelError, outdated_poller_message
from .guacproto import Parser, ProtocolError, encode
from .models import SshTarget, utcnow
from .ssh import USER_RE, Target, _admin_or_403, _lw, _same_origin, _ws_user, find_saved, resolve_target
from .users import audit

log = logging.getLogger("linkwatch.rdp")
router = APIRouter(include_in_schema=False)

SECURITY = {"any": "Negotiate (recommended)", "nla": "NLA (Network Level Authentication)", "tls": "TLS", "rdp": "Standard RDP"}
TOKEN_TTL = 60
IDLE_TIMEOUT = 30 * 60
MAX_SESSION = 12 * 3600
_pending: dict[str, dict[str, Any]] = {}       # one-time tokens: the login stays on the server, not in a URL


def guacd_addr() -> tuple[str, int]:
    raw = os.environ.get("LW_GUACD", "linkwatch-guacd:4822").strip()
    host, _, port = raw.rpartition(":")
    return (host or raw), int(port or 4822) if port.isdigit() else 4822


def callback_host() -> str:
    return os.environ.get("LW_GUACD_CALLBACK_HOST", "linkwatch-web").strip() or "linkwatch-web"


def callback_bind() -> str:
    return os.environ.get("LW_GUACD_CALLBACK_BIND", "0.0.0.0").strip() or "0.0.0.0"


# ------------------------------------------------------------------ pop-out page
@router.get("/rdp", response_class=HTMLResponse)
def rdp_page(request: Request, device: int | None = None, poller: int | None = None, host: str = "", port: str = ""):
    _admin_or_403(request)
    from .themes import theme_for
    state = _lw(request)
    with state.db.session() as s:
        error, saved, t = None, None, None
        try:
            t = resolve_target(s, device, poller, host, port or 3389, kind="rdp")
            row = find_saved(s, t)
            if row is not None:
                extra = state.vault.open(row.cred_enc) if row.cred_enc else {}
                saved = {"id": row.id, "username": row.username, "has_creds": bool(row.cred_enc),
                         "saved_by": row.cred_saved_by, "saved_at": row.cred_saved_at, "domain": extra.get("domain") or ""}
        except ValueError as exc:
            error = str(exc)
        theme = theme_for(s, request.state.user)
    target = {"device": t.device_id, "poller": t.poller_id, "host": t.host, "port": t.port} if t else None
    return state.templates.TemplateResponse(request, "rdp.html", {
        "t": t, "target": target, "error": error, "saved": saved, "theme": theme, "security": SECURITY,
        "connected": t is not None and t.poller_id in state.hub.conns,
        "supported": t is not None and "rdp" in t.poller_features,
    })


@router.post("/rdp/session")
async def rdp_session(request: Request):
    """Step 1 of connecting: the page posts the login here and gets a one-time token for the WebSocket."""
    user = _admin_or_403(request)
    if not _same_origin(request):
        raise HTTPException(403, "Cross-site request refused.")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Expected JSON.") from None
    state = _lw(request)

    def prepare() -> dict:
        with state.db.session() as s:
            t = resolve_target(s, body.get("device"), body.get("poller"), body.get("host"), body.get("port") or 3389, kind="rdp")
            row = find_saved(s, t)
            if body.get("use_saved"):
                if row is None or not row.cred_enc:
                    raise ValueError("There is no saved login for this host.")
                creds = state.vault.open(row.cred_enc)
                username = row.username or ""
            else:
                username = str(body.get("username") or "").strip()
                creds = {"password": str(body.get("password") or ""), "domain": str(body.get("domain") or "").strip()[:128],
                         "security": body.get("security") if body.get("security") in SECURITY else "any",
                         "ignore_cert": bool(body.get("ignore_cert", True))}
        if username and not USER_RE.match(username.replace("\\", "")):
            raise ValueError("That user name isn't valid.")
        return {"target": t, "username": username, "creds": creds}
    try:
        prep = await asyncio.to_thread(prepare)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    t: Target = prep["target"]
    if t.poller_id not in state.hub.conns:
        return JSONResponse({"error": f"Poller {t.poller_name} is not connected."}, status_code=409)
    if "rdp" not in t.poller_features:
        return JSONResponse({"error": outdated_poller_message(t.poller_name, "remote desktop")}, status_code=409)
    now = time.monotonic()
    for k in [k for k, v in _pending.items() if v["expires"] < now]:
        del _pending[k]
    token = secrets.token_urlsafe(24)
    _pending[token] = {**prep, "user": user.username, "uid": user.id, "expires": now + TOKEN_TTL,
                       "save": bool(body.get("save")) and not body.get("use_saved"),
                       "ip": request.headers.get("x-real-ip") or (request.client.host if request.client else None),
                       "width": _int(body.get("width"), 1024, 640, 7680), "height": _int(body.get("height"), 768, 480, 4320),
                       "dpi": _int(body.get("dpi"), 96, 72, 288)}
    return {"token": token}


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ the Guacamole tunnel WebSocket
@router.websocket("/api/poller/ws/rdp")
async def rdp_ws(ws: WebSocket):
    """Speaks the Guacamole WebSocket tunnel protocol (subprotocol "guacamole") to guacamole-common-js."""
    user = await asyncio.to_thread(_ws_user, ws)
    if user is None or user.role != "admin" or not _same_origin(ws):
        await ws.close(code=1008)
        return
    sess = _pending.pop(ws.query_params.get("token", ""), None)
    if sess is None or sess["uid"] != user.id or sess["expires"] < time.monotonic():
        await ws.close(code=1008)
        return
    await ws.accept(subprotocol="guacamole")
    try:
        await RdpSession(ws, sess).run()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


class _Fail(Exception):
    pass


class RdpSession:
    def __init__(self, ws: WebSocket, sess: dict):
        self.ws, self.sess = ws, sess
        self.state = _lw(ws)
        self.t: Target = sess["target"]
        self.last_input = time.monotonic()
        self.remote_error: str | None = None

    def _audit(self, action: str, detail: str) -> None:
        with self.state.db.session() as s:
            audit(s, self.sess["user"], self.sess["ip"], action, detail)

    def _remember(self) -> None:
        t, creds = self.t, self.sess["creds"]
        with self.state.db.session() as s:
            row = find_saved(s, t)
            if row is None:
                row = SshTarget(poller_id=t.poller_id, host=t.host, port=t.port)
                s.add(row)
            row.device_id = t.device_id or row.device_id
            row.last_used, row.last_user = utcnow(), self.sess["user"]
            if self.sess["save"]:
                row.username = self.sess["username"] or None
                row.cred_enc = self.state.vault.seal({k: v for k, v in creds.items() if v not in ("", None)})
                row.cred_saved_by, row.cred_saved_at = self.sess["user"], utcnow()
            elif row.username is None and self.sess["username"]:
                row.username = self.sess["username"]

    async def _error(self, text: str) -> None:
        try:
            await self.ws.send_text(encode("error", text, "519"))   # 519: upstream error, shown by the page
        except Exception:
            pass

    async def run(self) -> None:
        t = self.t
        who = self.sess["username"] or "(prompted)"
        where = f"{who}@{t.host}:{t.port} via poller {t.poller_name}"
        await self.ws.send_text(encode("", secrets.token_hex(16)))    # tunnel UUID: opens the client side
        started = time.monotonic()
        tws = done = None
        listener = None
        tasks: list[asyncio.Task] = []
        g_writer = None
        opened = False
        reason = "closed"
        try:
            try:
                tws, done = await self.state.hub.open_tunnel(t.poller_id, t.host, t.port)
            except TunnelError as exc:
                raise _Fail(str(exc)) from None
            relay_ready = asyncio.get_running_loop().create_future()
            listener = await self._listen(tws, relay_ready)
            lport = listener.sockets[0].getsockname()[1]
            ghost, gport = guacd_addr()
            try:
                g_reader, g_writer = await asyncio.wait_for(asyncio.open_connection(ghost, gport), 10)
            except (OSError, asyncio.TimeoutError) as exc:
                raise _Fail(f"The remote desktop service (guacd at {ghost}:{gport}) isn't reachable: "
                            f"{getattr(exc, 'strerror', None) or exc.__class__.__name__}. See docs/rdp.md.") from None
            parser = Parser()
            ready_id, leftover = await self._handshake(g_reader, g_writer, parser, lport)
            opened = True
            await asyncio.to_thread(self._remember)
            await asyncio.to_thread(self._audit, "opened RDP session", where)
            log.info("RDP %s ready (guacd connection %s)", where, ready_id)
            if leftover:
                await self.ws.send_text(leftover)
            tasks = [asyncio.create_task(c) for c in (self._from_guacd(g_reader, parser), self._to_guacd(g_writer),
                                                     self._watchdog())]
            finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            try:
                reason = finished.pop().result()
            except (WebSocketDisconnect, RuntimeError):
                reason = "window closed"
            except Exception as exc:
                reason = f"{exc.__class__.__name__}: {exc}"
        except _Fail as exc:
            reason = str(exc)
            await self._error(reason)
        except ProtocolError as exc:
            reason = f"guacd sent something unexpected: {exc}"
            await self._error(reason)
        except Exception as exc:
            log.exception("RDP session to %s failed", where)
            reason = f"{exc.__class__.__name__}: {exc}"
            await self._error(f"Remote desktop failed: {reason}")
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if g_writer is not None:
                g_writer.close()
            if listener is not None:
                listener.close()
            for task in getattr(self, "_relay_tasks", []):
                task.cancel()
            if done is not None:
                done.set()
        if self.remote_error and reason in ("the session ended", "closed"):
            reason = self.remote_error
        mins = (time.monotonic() - started) / 60
        if opened:
            await asyncio.to_thread(self._audit, "closed RDP session", f"{where}, {mins:.0f} min ({reason})")
        else:
            await asyncio.to_thread(self._audit, "RDP session failed", f"{where}: {reason}")

    async def _listen(self, tws: WebSocket, ready: asyncio.Future):
        """A one-off TCP listener that guacd connects to in place of the real host. It accepts one connection,
        only from guacd's address, and relays it over the poller's tunnel."""
        allowed = await _guacd_ips()
        self._relay_tasks: list[asyncio.Task] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = (writer.get_extra_info("peername") or ("",))[0]
            if ready.done() or (allowed and not _ip_in(peer, allowed)):
                log.warning("RDP relay: refused a connection from %s", peer)
                writer.close()
                return
            ready.set_result(True)

            async def up() -> None:            # guacd -> host
                try:
                    while data := await reader.read(65536):
                        await tws.send_bytes(data)
                except (WebSocketDisconnect, RuntimeError, OSError):
                    pass

            async def down() -> None:          # host -> guacd
                try:
                    while True:
                        msg = await tws.receive()
                        if msg["type"] == "websocket.disconnect":
                            break
                        if msg.get("bytes"):
                            writer.write(msg["bytes"])
                            await writer.drain()
                except (WebSocketDisconnect, RuntimeError, OSError):
                    pass
            pair = [asyncio.create_task(up()), asyncio.create_task(down())]
            self._relay_tasks += pair
            try:
                await asyncio.wait(pair, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for p in pair:
                    p.cancel()
                writer.close()
        return await asyncio.start_server(handle, callback_bind(), 0)

    async def _read_instruction(self, reader, parser: Parser, pending: list) -> tuple[str, list[str]]:
        while not pending:
            data = await asyncio.wait_for(reader.read(65536), 20)
            if not data:
                raise _Fail("guacd closed the connection during the handshake.")
            pending.extend(parser.feed(data))
        _, el = pending.pop(0)
        return el[0], el[1:]

    async def _handshake(self, reader, writer, parser: Parser, lport: int) -> tuple[str, str]:
        s, c = self.sess, self.sess["creds"]
        pending: list = []
        writer.write(encode("select", "rdp").encode())
        await writer.drain()
        op, args = await self._read_instruction(reader, parser, pending)
        if op != "args" or not args:
            raise _Fail("guacd did not answer the handshake. Is LW_GUACD pointing at guacd?")
        values = {
            "hostname": callback_host(), "port": str(lport),
            "username": s["username"], "password": c.get("password") or "", "domain": c.get("domain") or "",
            "security": c.get("security") or "any", "ignore-cert": "true" if c.get("ignore_cert", True) else "",
            "resize-method": "display-update", "disable-audio": "true", "enable-font-smoothing": "true",
            "width": str(s["width"]), "height": str(s["height"]), "dpi": str(s["dpi"]),
        }
        reply = [a if a.startswith("VERSION_") else values.get(a, "") for a in args]
        out = encode("size", s["width"], s["height"], s["dpi"]) + encode("audio") + encode("video") \
            + encode("image", "image/png", "image/jpeg", "image/webp")
        if args[0].startswith("VERSION_"):
            out += encode("timezone", os.environ.get("TZ", "UTC"))
        out += encode("connect", *reply)
        writer.write(out.encode())
        await writer.drain()
        op, rargs = await self._read_instruction(reader, parser, pending)
        if op == "error":
            raise _Fail(f"guacd refused the connection: {rargs[0] if rargs else 'unknown error'}")
        if op != "ready":
            raise _Fail(f"guacd answered {op!r} instead of ready.")
        return (rargs[0] if rargs else ""), "".join(raw for raw, _ in pending)

    async def _from_guacd(self, reader, parser: Parser) -> str:
        while True:
            data = await reader.read(65536)
            if not data:
                return "the session ended"
            instrs = parser.feed(data)
            if not instrs:
                continue
            for raw, el in instrs:
                if el and el[0] == "error":
                    self.remote_error = f"remote desktop error: {el[1] if len(el) > 1 else '?'}"
            await self.ws.send_text("".join(raw for raw, _ in instrs))

    async def _to_guacd(self, writer) -> str:
        parser = Parser()
        while True:
            msg = await self.ws.receive()
            if msg["type"] == "websocket.disconnect":
                return "window closed"
            text = msg.get("text")
            if text is None and msg.get("bytes"):
                text = msg["bytes"].decode("utf-8", "replace")
            if not text:
                continue
            out = []
            for raw, el in parser.feed(text):
                if el and el[0] == "":                       # tunnel-internal: answer pings ourselves
                    if len(el) > 1 and el[1] == "ping":
                        await self.ws.send_text(raw)
                    continue
                if el and el[0] in ("key", "mouse"):
                    self.last_input = time.monotonic()
                if el and el[0] == "disconnect":
                    writer.write(raw.encode())
                    await writer.drain()
                    return "closed by the user"
                out.append(raw)
            if out:
                writer.write("".join(out).encode())
                await writer.drain()

    async def _watchdog(self) -> str:
        start = time.monotonic()
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            if now - self.last_input > IDLE_TIMEOUT:
                await self._error(f"Disconnected after {IDLE_TIMEOUT // 60} minutes without keyboard or mouse input.")
                return f"idle for {IDLE_TIMEOUT // 60} minutes"
            if now - start > MAX_SESSION:
                await self._error(f"Disconnected at the {MAX_SESSION // 3600} hour limit.")
                return f"reached the {MAX_SESSION // 3600} hour limit"


async def _guacd_ips() -> list[str]:
    host, _ = guacd_addr()
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []          # can't resolve: don't block (guacd itself would fail to connect anyway)
    return sorted({i[4][0] for i in infos})


def _ip_in(peer: str, allowed: list[str]) -> bool:
    try:
        p = ipaddress.ip_address(peer.split("%")[0])
    except ValueError:
        return False
    for a in allowed:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if p == ip or (p.is_loopback and ip.is_loopback):
            return True
        if getattr(p, "ipv4_mapped", None) == ip:
            return True
    return False
