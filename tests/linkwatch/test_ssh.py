"""SSH consoles through a poller's reverse tunnel.

The end-to-end test runs the real server (uvicorn on a free port), a real poller, a real SSH server on
127.0.0.1 and a browser-like WebSocket client, and types into the console."""
import asyncio
import json
import re
import socket
import time

import asyncssh
import httpx
import pytest
from sqlalchemy import select
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from linkwatch.poller import tunnel
from linkwatch.server.models import AuditEvent, Device, Poller, SshTarget


# ------------------------------------------------------------------ unit
def test_tunnel_refusal(monkeypatch):
    monkeypatch.delenv("LW_TUNNEL", raising=False)
    monkeypatch.delenv("LW_TUNNEL_PORTS", raising=False)
    assert tunnel.refusal("10.0.0.1", 22) is None
    assert "only allows tunnels to ports 22, 3389" in tunnel.refusal("10.0.0.1", 443)
    assert tunnel.refusal("10.0.0.1", 3389) is None
    assert tunnel.refusal("bad host", 22) == "Invalid host name."
    monkeypatch.setenv("LW_TUNNEL_PORTS", "22, 2222")
    assert tunnel.refusal("10.0.0.1", 2222) is None
    monkeypatch.setenv("LW_TUNNEL_PORTS", "any")
    assert tunnel.refusal("10.0.0.1", 8443) is None
    monkeypatch.setenv("LW_TUNNEL", "off")
    assert "turned off" in tunnel.refusal("10.0.0.1", 22)


def test_poller_advertises_ssh(tmp_path, monkeypatch):
    from linkwatch.poller.main import Poller as LanPoller
    monkeypatch.delenv("LW_TUNNEL", raising=False)
    assert "ssh" in LanPoller("http://x", tmp_path).features()
    monkeypatch.setenv("LW_TUNNEL", "off")
    assert "ssh" not in LanPoller("http://x", tmp_path).features()


def _add_device(app, poller_features=("ssh",), dtype="Firewall"):
    with app.state.lw.db.session() as s:
        p = Poller(name="site-a", key_hash="x" * 64, features=list(poller_features))
        s.add(p)
        s.flush()
        d = Device(hostname="edge-fw", ip="10.9.9.1", type=dtype, poller_id=p.id)
        s.add(d)
        s.flush()
        return p.id, d.id


def test_ssh_page_admin_only(logged_in, app):
    pid, did = _add_device(app)
    page = logged_in.get(f"/devices/{did}").text
    assert f'href="/ssh?device={did}"' in page and "window.open" in page
    r = logged_in.get(f"/ssh?device={did}")
    assert r.status_code == 200 and "Sign in to edge-fw" in r.text and "not connected right now" in r.text
    assert "/static/vendor/xterm/xterm.js" in r.text
    assert 'name="host" value="127.0.0.1"' in logged_in.get("/pollers").text
    assert "Enter a host name" in logged_in.get(f"/ssh?poller={pid}&host=").text

    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    from fastapi.testclient import TestClient
    viewer = TestClient(app)
    viewer.post("/login", data={"username": "noc", "password": "noc-password-123"})
    assert viewer.get(f"/ssh?device={did}").status_code == 403
    assert "/ssh?device=" not in viewer.get(f"/devices/{did}").text


def test_console_ws_rejects_viewers_and_cross_site(logged_in, app):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):          # no Origin header
        with logged_in.websocket_connect("/api/poller/ws/console") as ws:
            ws.receive_text()
    with pytest.raises(WebSocketDisconnect):          # another site
        with logged_in.websocket_connect("/api/poller/ws/console", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_text()
    from fastapi.testclient import TestClient
    anon = TestClient(app)
    with pytest.raises(WebSocketDisconnect):
        with anon.websocket_connect("/api/poller/ws/console", headers={"origin": "http://testserver"}) as ws:
            ws.receive_text()
    # signed-in admin, same origin: accepted, and an unknown target is explained
    with logged_in.websocket_connect("/api/poller/ws/console", headers={"origin": "http://testserver"}) as ws:
        ws.send_text(json.dumps({"device": 999, "username": "root", "password": "x"}))
        assert json.loads(ws.receive_text()) == {"type": "error", "text": "No such device."}


def test_tunnel_socket_needs_a_pending_request(client, app):
    from starlette.websockets import WebSocketDisconnect
    ident = _enroll_direct(app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/poller/ws/tunnel/made-up", headers={"Authorization": f"Bearer {ident}"}) as ws:
            ws.receive_text()


def _enroll_direct(app) -> str:
    from linkwatch.server.security import new_secret, sha256
    key = new_secret("lwp", 32)
    with app.state.lw.db.session() as s:
        s.add(Poller(name=f"p-{key[-6:]}", key_hash=sha256(key)))
    return key


# ------------------------------------------------------------------ end to end
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "netops" and password == "s3cret-pass"


async def _shell(process):
    process.stdout.write(f"welcome {process.get_extra_info('username')} term={process.get_terminal_type()}\r\n")
    try:
        async for line in process.stdin:
            line = line.rstrip("\r\n")
            if line == "exit":
                break
            process.stdout.write(f"you typed: {line}\r\n")
    except asyncssh.BreakReceived:
        pass
    process.exit(0)


def test_ssh_console_end_to_end(app, live_server, tmp_path, monkeypatch):
    monkeypatch.delenv("LW_TUNNEL", raising=False)
    monkeypatch.setenv("LW_TUNNEL_PORTS", "any")
    base = live_server

    async def scenario():
        ssh_port = _free_port()
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        sshd = await asyncssh.create_server(_Server, "127.0.0.1", ssh_port, server_host_keys=[host_key],
                                            process_factory=_shell)
        async with httpx.AsyncClient(base_url=base, follow_redirects=True) as http:
            r = await http.post("/login", data={"username": "admin", "password": "pw-for-tests"})
            assert r.status_code == 200
            page = (await http.post("/pollers/token")).text
            token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", page).group(1)
            cookie = "lw_session=" + http.cookies["lw_session"]

        from linkwatch.poller.main import Poller as LanPoller
        lan = LanPoller(base, tmp_path / "poller", enroll_token=token, name="site-a")
        lan_task = asyncio.create_task(lan.run())
        for _ in range(100):
            if app.state.lw.hub.conns:
                break
            await asyncio.sleep(0.05)
        pid = next(iter(app.state.lw.hub.conns))
        for _ in range(100):     # the hello (with features) lands just after the connection
            with app.state.lw.db.session() as s:
                if "ssh" in (s.get(Poller, pid).features or []):
                    break
            await asyncio.sleep(0.05)
        with app.state.lw.db.session() as s:
            d = Device(hostname="lab-box", ip="127.0.0.1", type="Server", poller_id=pid)
            s.add(d)
            s.flush()
            did = d.id

        ws_url = base.replace("http://", "ws://") + "/api/poller/ws/console"
        headers = {"Cookie": cookie, "Origin": base}

        async def session(hello, lines=()):
            out, msgs = b"", []
            async with connect(ws_url, additional_headers=headers) as ws:
                await ws.send(json.dumps({"device": did, "port": ssh_port, "cols": 100, "rows": 30, **hello}))
                deadline = time.monotonic() + 20
                ready = False
                while time.monotonic() < deadline:
                    try:
                        m = await asyncio.wait_for(ws.recv(), 20)
                    except ConnectionClosed:
                        break
                    if isinstance(m, bytes):
                        out += m
                        if ready and lines and b"welcome" in out:
                            for ln in lines:
                                await ws.send(ln.encode() + b"\r")
                            lines = ()
                        continue
                    m = json.loads(m)
                    msgs.append(m)
                    if m["type"] == "ready":
                        ready = True
                        if b"welcome" in out and lines:
                            for ln in lines:
                                await ws.send(ln.encode() + b"\r")
                            lines = ()
                    if m["type"] in ("closed",):
                        break
            return out, msgs

        # 1. password sign-in, typed in, saved
        out, msgs = await session({"username": "netops", "password": "s3cret-pass", "save": True}, ["hello there", "exit"])
        kinds = [m["type"] for m in msgs]
        assert "ready" in kinds and kinds[-1] == "closed", msgs
        assert b"welcome netops term=xterm-256color" in out
        assert b"you typed: hello there" in out
        hk = next(m for m in msgs if m["type"] == "hostkey")
        assert hk["new"] is True and hk["fingerprint"] == host_key.get_fingerprint()

        with app.state.lw.db.session() as s:
            row = s.scalar(select(SshTarget))
            assert row.fingerprint == host_key.get_fingerprint() and row.username == "netops"
            assert "s3cret-pass" not in (row.cred_enc or "") and app.state.lw.vault.open(row.cred_enc)["password"] == "s3cret-pass"
            actions = [a.action for a in s.scalars(select(AuditEvent).order_by(AuditEvent.id))]
            assert "opened SSH session" in actions and "closed SSH session" in actions
            closed = s.scalar(select(AuditEvent).where(AuditEvent.action == "closed SSH session"))
            assert "netops@127.0.0.1" in closed.detail and "via poller site-a" in closed.detail

        # 2. saved login works; host key now pinned
        out, msgs = await session({"use_saved": True}, ["exit"])
        assert any(m["type"] == "ready" for m in msgs)
        assert next(m for m in msgs if m["type"] == "hostkey")["new"] is False

        # 3. wrong password is explained
        out, msgs = await session({"username": "netops", "password": "nope"})
        err = next(m for m in msgs if m["type"] == "error")
        assert "Sign-in refused" in err["text"]

        # 4. the device's key changes: refused before any password is sent
        sshd.close()
        await sshd.wait_closed()
        other = asyncssh.generate_private_key("ssh-ed25519")
        sshd = await asyncssh.create_server(_Server, "127.0.0.1", ssh_port, server_host_keys=[other], process_factory=_shell)
        out, msgs = await session({"username": "netops", "password": "s3cret-pass"})
        err = next(m for m in msgs if m["type"] == "error")
        assert err["hostkey"] is True and "HOST KEY CHANGED" in err["text"] and other.get_fingerprint() in err["text"]

        # 5. nothing listening: the poller says so
        sshd.close()
        await sshd.wait_closed()
        out, msgs = await session({"username": "netops", "password": "s3cret-pass"})
        err = next(m for m in msgs if m["type"] == "error")
        assert "Could not connect to 127.0.0.1" in err["text"]

        assert app.state.lw.hub.open_tunnels.get(pid, 0) == 0
        lan_task.cancel()

    asyncio.run(scenario())
