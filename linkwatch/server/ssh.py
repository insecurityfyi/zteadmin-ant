"""SSH consoles through a poller's outbound tunnel.

An admin presses SSH on a device (or on a poller) and a pop-out window opens with a terminal. The browser talks
to this server over a WebSocket; the server asks the device's poller for a reverse tunnel (Hub.open_tunnel) and
runs the SSH client itself, over that tunnel. So:

* nothing connects in to the remote site: the poller dials out for the tunnel just as it does for polling;
* SSH is end to end between this server and the device: the poller relays encrypted bytes only;
* the login is typed into the pop-out (or saved, sealed with LW_SECRET_KEY) and never sent to the poller;
* the device's host key is pinned on first use and checked every time after;
* only admins can open a console, and each session's start and end is in the audit log.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import asyncssh
from fastapi import APIRouter, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select

from .gateway import TunnelError, outdated_poller_message
from .models import Device, Poller, SshTarget, User, utcnow
from .security import sha256
from .users import audit

log = logging.getLogger("linkwatch.ssh")
logging.getLogger("asyncssh").setLevel(logging.WARNING)
router = APIRouter(include_in_schema=False)

HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]%]{1,255}$")
USER_RE = re.compile(r"^[^\s:@/]{1,128}$")
IDLE_TIMEOUT = 30 * 60          # no keystrokes and no output for this long closes the session
MAX_SESSION = 12 * 3600
CONNECT_TIMEOUT = 25


def _lw(obj):
    return obj.app.state.lw


# ------------------------------------------------------------------ targets
class Target:
    """Where a console goes: a poller, a host and a port, optionally on behalf of a device."""

    def __init__(self, poller: Poller, host: str, port: int, device: Device | None = None):
        self.poller_id, self.poller_name = poller.id, poller.name
        self.poller_features = list(poller.features or [])
        self.host, self.port = host, port
        self.device_id = device.id if device else None
        self.label = (device.hostname if device else host) + (f":{port}" if port not in (22, 3389) else "")


def resolve_target(s, device: Any = None, poller: Any = None, host: Any = None, port: Any = None,
                   kind: str | None = None) -> Target:
    try:
        port_n = int(port or 22)
    except (TypeError, ValueError):
        raise ValueError("The port must be a number.") from None
    if not 0 < port_n < 65536:
        raise ValueError("The port must be between 1 and 65535.")
    if device:
        d = s.get(Device, int(device))
        if d is None:
            raise ValueError("No such device.")
        if not d.poller_id or d.poller is None:
            raise ValueError("This device isn't collected by a poller, so there is no tunnel to reach it through.")
        if not d.ip:
            raise ValueError("This device has no IP address.")
        if kind:
            from .access import access_for
            acc = access_for(d)
            if not getattr(acc, kind):
                raise ValueError(acc.why or "This kind of remote access is turned off for this device.")
        return Target(d.poller, d.ip, port_n, d)
    p = s.get(Poller, int(poller or 0))
    if p is None:
        raise ValueError("No such poller.")
    host = str(host or "").strip()
    if not HOST_RE.match(host):
        raise ValueError("Enter a host name or IP address.")
    return Target(p, host, port_n)


def find_saved(s, t: Target) -> SshTarget | None:
    return s.scalar(select(SshTarget).where(SshTarget.poller_id == t.poller_id, SshTarget.host == t.host,
                                            SshTarget.port == t.port))


# ------------------------------------------------------------------ pop-out page
def _admin_or_403(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None or user.role != "admin":
        raise HTTPException(403, "Only admins can open an SSH console.")
    return user


@router.get("/ssh", response_class=HTMLResponse)
def ssh_page(request: Request, device: int | None = None, poller: int | None = None, host: str = "", port: str = ""):
    _admin_or_403(request)
    from .themes import theme_for
    state = _lw(request)
    with state.db.session() as s:
        error, saved, t = None, None, None
        try:
            t = resolve_target(s, device, poller, host, port or 22, kind="ssh")
            row = find_saved(s, t)
            if row is not None:
                saved = {"id": row.id, "username": row.username, "has_creds": bool(row.cred_enc),
                         "saved_by": row.cred_saved_by, "saved_at": row.cred_saved_at, "fingerprint": row.fingerprint}
        except ValueError as exc:
            error = str(exc)
        theme = theme_for(s, request.state.user)
    target = None
    if t is not None:
        target = {"device": t.device_id, "poller": t.poller_id, "host": t.host, "port": t.port}
    return state.templates.TemplateResponse(request, "ssh.html", {
        "t": t, "target": target, "error": error, "saved": saved, "theme": theme,
        "connected": t is not None and t.poller_id in state.hub.conns,
        "supported": t is not None and "ssh" in t.poller_features,
    })


@router.post("/ssh/forget")
def ssh_forget(request: Request, target_id: int = Form(...), what: str = Form("creds"), back: str = Form("/")):
    user = _admin_or_403(request)
    with _lw(request).db.session() as s:
        row = s.get(SshTarget, target_id)
        if row is not None:
            if what == "key":
                row.host_key = row.fingerprint = None
                audit(s, user.username, request.client.host if request.client else None, "forgot SSH host key",
                      f"{row.host}:{row.port}")
            else:
                row.cred_enc, row.cred_saved_by, row.cred_saved_at = None, None, None
                audit(s, user.username, request.client.host if request.client else None, "forgot saved SSH login",
                      f"{row.username or '?'}@{row.host}:{row.port}")
    return RedirectResponse(back if back.startswith(("/ssh", "/rdp")) else "/", status_code=303)


# ------------------------------------------------------------------ browser WebSocket
def _ws_user(ws: WebSocket) -> User | None:
    """The middleware that guards pages doesn't run for WebSockets, so check the session the same way here."""
    try:
        sess = ws.session
    except AssertionError:
        return None
    uid = sess.get("uid")
    if not uid:
        return None
    with _lw(ws).db.session() as s:
        user = s.get(User, uid)
        if user is None or user.disabled or sha256("pwv:" + user.password_hash)[:20] != sess.get("pwv"):
            return None
        s.expunge(user)
        return user


def _same_origin(conn) -> bool:
    """For a WebSocket or a fetch(): the browser's Origin must be this site."""
    origin = conn.headers.get("origin")
    if not origin:
        return False
    host = conn.headers.get("host", "")
    return urlsplit(origin).netloc.lower() == host.lower()


async def _send(ws: WebSocket, kind: str, **fields) -> None:
    try:
        await ws.send_text(json.dumps({"type": kind, **fields}))
    except Exception:
        pass


@router.websocket("/api/poller/ws/console")
async def console_ws(ws: WebSocket):
    """Browser side of a console. Under /api/poller/ws so the existing nginx WebSocket location covers it.

    Text frames are JSON control messages; binary frames are terminal bytes."""
    user = await asyncio.to_thread(_ws_user, ws)
    if user is None or user.role != "admin" or not _same_origin(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    ip = ws.headers.get("x-real-ip") or (ws.client.host if ws.client else None)
    try:
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), 120))
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect, RuntimeError, KeyError):
        await ws.close()
        return
    try:
        await Console(ws, user.username, ip, hello).run()
    finally:
        try:
            await ws.close()
        except Exception:
            pass


class Console:
    def __init__(self, ws: WebSocket, username: str, ip: str | None, hello: dict):
        self.ws, self.who, self.ip, self.hello = ws, username, ip, hello
        self.state = _lw(ws)
        self.bytes_in = self.bytes_out = 0
        self.last_activity = time.monotonic()

    def _audit(self, action: str, detail: str) -> None:
        with self.state.db.session() as s:
            audit(s, self.who, self.ip, action, detail)

    def _prepare(self) -> tuple[Target, str, dict, str | None, str | None]:
        """Resolve the target and the login to use: typed in, or the saved one."""
        h = self.hello
        with self.state.db.session() as s:
            t = resolve_target(s, h.get("device"), h.get("poller"), h.get("host"), h.get("port"), kind="ssh")
            row = find_saved(s, t)
            stored_key = row.host_key if row else None
            stored_fp = row.fingerprint if row else None
            if h.get("use_saved"):
                if row is None or not row.cred_enc:
                    raise ValueError("There is no saved login for this host.")
                creds = self.state.vault.open(row.cred_enc)
                username = row.username or ""
            else:
                username = str(h.get("username") or "").strip()
                creds = {k: str(h.get(k) or "") for k in ("password", "key", "passphrase")}
        if not USER_RE.match(username):
            raise ValueError("Enter the user name to sign in as.")
        if not creds.get("password") and not creds.get("key"):
            raise ValueError("Enter a password or paste a private key.")
        return t, username, creds, stored_key, stored_fp

    def _remember(self, t: Target, username: str, creds: dict, host_key: str | None, fingerprint: str | None) -> None:
        with self.state.db.session() as s:
            row = find_saved(s, t)
            if row is None:
                row = SshTarget(poller_id=t.poller_id, host=t.host, port=t.port)
                s.add(row)
            row.device_id = t.device_id or row.device_id
            if host_key and not row.host_key:
                row.host_key, row.fingerprint = host_key, fingerprint
            row.last_used, row.last_user = utcnow(), self.who
            if self.hello.get("save") and not self.hello.get("use_saved"):
                row.username = username
                row.cred_enc = self.state.vault.seal({k: v for k, v in creds.items() if v})
                row.cred_saved_by, row.cred_saved_at = self.who, utcnow()
            elif row.username is None:
                row.username = username

    async def run(self) -> None:
        try:
            t, username, creds, stored_key, stored_fp = await asyncio.to_thread(self._prepare)
        except ValueError as exc:
            await _send(self.ws, "error", text=str(exc))
            return
        where = f"{username}@{t.host}:{t.port} via poller {t.poller_name}"
        if t.poller_id not in self.state.hub.conns:
            await _send(self.ws, "error", text=f"Poller {t.poller_name} is not connected.")
            return
        if "ssh" not in t.poller_features:
            await _send(self.ws, "error", text=outdated_poller_message(t.poller_name, "SSH consoles"))
            return
        await _send(self.ws, "status", text=f"Asking poller {t.poller_name} for a tunnel to {t.host} port {t.port}…")
        try:
            tws, done = await self.state.hub.open_tunnel(t.poller_id, t.host, t.port)
        except TunnelError as exc:
            await asyncio.to_thread(self._audit, "SSH session failed", f"{where}: {exc}")
            await _send(self.ws, "error", text=str(exc))
            return
        await _send(self.ws, "status", text="Tunnel open. Starting SSH…")
        started = time.monotonic()
        reason = "closed"
        conn = None
        bridge: list[asyncio.Task] = []
        a, b = socket.socketpair()
        try:
            bridge = await self._bridge(tws, b)
            client = _PinningClient(stored_key)
            pinned = [asyncssh.import_public_key(stored_key)] if stored_key else []
            client_keys = []
            if creds.get("key"):
                try:
                    client_keys = [asyncssh.import_private_key(creds["key"], creds.get("passphrase") or None)]
                except (asyncssh.KeyImportError, ValueError) as exc:
                    raise _Fail(f"The private key could not be read: {exc}") from None
            try:
                conn = await asyncio.wait_for(asyncssh.connect(
                    t.host, t.port, sock=a, username=username, password=creds.get("password") or None,
                    client_keys=client_keys, known_hosts=(pinned, [], []), client_factory=lambda: client,
                    agent_path=None, config=None, preferred_auth=_auth_order(creds), keepalive_interval=30,
                    login_timeout=CONNECT_TIMEOUT), CONNECT_TIMEOUT + 5)
            except asyncssh.HostKeyNotVerifiable:
                offered = client.offered.get_fingerprint() if client.offered else "unknown"
                raise _Fail(f"HOST KEY CHANGED. {t.host} now presents {offered} but {stored_fp} was saved the "
                            "first time. This could be a reinstalled device or someone intercepting the connection. "
                            "If you expected it, forget the saved key in this window and connect again.",
                            hostkey=True) from None
            except asyncssh.PermissionDenied:
                raise _Fail("Sign-in refused: wrong user name, password or key.") from None
            except asyncssh.DisconnectError as exc:
                raise _Fail(f"The device closed the connection: {exc.reason}") from None
            except asyncio.TimeoutError:
                raise _Fail("The device did not finish the SSH handshake in time.") from None
            except (OSError, asyncssh.Error) as exc:
                raise _Fail(f"SSH failed: {exc}") from None
            key = conn.get_server_host_key()
            host_key = key.export_public_key().decode().strip() if key else None
            fingerprint = key.get_fingerprint() if key else None
            await asyncio.to_thread(self._remember, t, username, creds, host_key, fingerprint)
            await asyncio.to_thread(self._audit, "opened SSH session", where)
            await _send(self.ws, "hostkey", fingerprint=fingerprint, new=not stored_key)
            cols, rows = _size(self.hello)
            try:
                proc = await conn.create_process(term_type="xterm-256color", term_size=(cols, rows), encoding=None,
                                                 stderr=asyncssh.STDOUT)
            except (asyncssh.ChannelOpenError, asyncssh.Error) as exc:
                raise _Fail(f"The device refused a terminal session: {exc}") from None
            await _send(self.ws, "ready", text=f"Connected to {t.label} as {username}")
            reason = await self._pump(proc)
        except _Fail as exc:
            reason = str(exc)
            await _send(self.ws, "error", text=str(exc), hostkey=exc.hostkey)
        except Exception as exc:  # never leave a half-open tunnel behind
            log.exception("SSH console to %s failed", where)
            reason = f"{exc.__class__.__name__}: {exc}"
            await _send(self.ws, "error", text=f"SSH failed: {reason}")
        finally:
            if conn is not None:
                conn.close()
            for task in bridge:
                task.cancel()
            await asyncio.gather(*bridge, return_exceptions=True)
            a.close()
            b.close()
            done.set()
        mins = (time.monotonic() - started) / 60
        if conn is not None:
            await asyncio.to_thread(self._audit, "closed SSH session",
                                    f"{where}, {mins:.0f} min, {self.bytes_in} bytes typed, {self.bytes_out} bytes shown ({reason})")
        else:
            await asyncio.to_thread(self._audit, "SSH session failed", f"{where}: {reason}")
        await _send(self.ws, "closed", text=reason)

    async def _bridge(self, tws: WebSocket, sock: socket.socket) -> list[asyncio.Task]:
        """Copy bytes between the poller's tunnel WebSocket and one end of a socket pair; asyncssh gets the other."""
        reader, writer = await asyncio.open_connection(sock=sock)

        async def from_poller() -> None:
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
            finally:
                try:
                    writer.write_eof()
                except OSError:
                    pass

        async def to_poller() -> None:
            try:
                while data := await reader.read(65536):
                    await tws.send_bytes(data)
            except (WebSocketDisconnect, RuntimeError, OSError):
                pass
        return [asyncio.create_task(from_poller()), asyncio.create_task(to_poller())]

    async def _pump(self, proc) -> str:
        async def out() -> str:
            while True:
                data = await proc.stdout.read(65536)
                if not data:
                    return "the session ended"
                self.bytes_out += len(data)
                self.last_activity = time.monotonic()
                await self.ws.send_bytes(data)

        async def inp() -> str:
            while True:
                msg = await self.ws.receive()
                if msg["type"] == "websocket.disconnect":
                    return "window closed"
                if msg.get("bytes"):
                    self.bytes_in += len(msg["bytes"])
                    self.last_activity = time.monotonic()
                    proc.stdin.write(msg["bytes"])
                elif msg.get("text"):
                    try:
                        ctl = json.loads(msg["text"])
                    except ValueError:
                        continue
                    if ctl.get("type") == "resize":
                        cols, rows = _size(ctl)
                        proc.change_terminal_size(cols, rows)
                    elif ctl.get("type") == "close":
                        return "closed by the user"

        async def watchdog() -> str:
            start = time.monotonic()
            while True:
                await asyncio.sleep(15)
                now = time.monotonic()
                if now - self.last_activity > IDLE_TIMEOUT:
                    return f"idle for {IDLE_TIMEOUT // 60} minutes"
                if now - start > MAX_SESSION:
                    return f"reached the {MAX_SESSION // 3600} hour limit"

        tasks = [asyncio.create_task(c) for c in (out(), inp(), watchdog())]
        try:
            finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            task = finished.pop()
            try:
                return task.result()
            except (WebSocketDisconnect, RuntimeError):
                return "window closed"
            except Exception as exc:
                return f"{exc.__class__.__name__}: {exc}"
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


class _Fail(Exception):
    def __init__(self, text: str, hostkey: bool = False):
        super().__init__(text)
        self.hostkey = hostkey


def _size(msg: dict) -> tuple[int, int]:
    try:
        return max(20, min(500, int(msg.get("cols") or 80))), max(5, min(200, int(msg.get("rows") or 24)))
    except (TypeError, ValueError):
        return 80, 24


def _auth_order(creds: dict) -> list[str]:
    order = []
    if creds.get("key"):
        order.append("publickey")
    if creds.get("password"):
        order += ["keyboard-interactive", "password"]
    return order


class _PinningClient(asyncssh.SSHClient):
    """Trust on first use: with no saved key accept what the device offers (it is saved after sign-in);
    with a saved key, asyncssh accepts only that one and asks us about anything else, which we refuse."""

    def __init__(self, stored_key: str | None):
        self.stored = stored_key
        self.offered = None

    def validate_host_public_key(self, host, addr, port, key) -> bool:
        self.offered = key
        return self.stored is None
