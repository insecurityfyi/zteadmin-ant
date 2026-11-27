"""Remote desktop (RDP) through a poller's reverse tunnel, via guacd.

The end-to-end test uses the real server, a real poller and a fake guacd that does the Guacamole handshake and
then connects to the one-off address it was given, the way real guacd connects to an RDP host. Behind the poller
sits a plain TCP echo server standing in for the Windows machine."""
import asyncio
import re

import httpx
import pytest
from sqlalchemy import select
from websockets.asyncio.client import connect

from linkwatch.server.guacproto import Parser, ProtocolError, encode
from linkwatch.server.models import AuditEvent, Device, Poller, SshTarget

from .test_ssh import _add_device


# ------------------------------------------------------------------ protocol
def test_guac_parser_handles_split_and_unicode():
    p = Parser()
    msg = encode("name", "café ☕", "x") + encode("sync", "123")
    raw = msg.encode()
    out = []
    for i in range(0, len(raw), 3):                       # split mid code point and mid instruction
        out += p.feed(raw[i:i + 3])
    assert [el for _, el in out] == [["name", "café ☕", "x"], ["sync", "123"]]
    assert "".join(r for r, _ in out) == msg
    assert encode("", "ping", 5) == "0.,4.ping,1.5;"
    with pytest.raises(ProtocolError):
        Parser().feed("4.sync;ab.c;")


# ------------------------------------------------------------------ pages and access
def test_rdp_page_and_access(logged_in, app):
    pid, did = _add_device(app, poller_features=("ssh", "rdp"), dtype="Server")
    page = logged_in.get(f"/devices/{did}").text
    assert f'href="/rdp?device={did}"' in page
    r = logged_in.get(f"/rdp?device={did}")
    assert r.status_code == 200 and "Remote desktop to edge-fw" in r.text and "guacamole-common.min.js" in r.text
    assert "edge-fw:3389" not in r.text                     # the standard port isn't shown
    assert 'formaction="/rdp"' in logged_in.get("/pollers").text

    # the login is posted (same origin only) and swapped for a one-time token
    body = {"device": did, "username": "admin", "password": "x"}
    assert logged_in.post("/rdp/session", json=body).status_code == 403
    r = logged_in.post("/rdp/session", json=body, headers={"origin": "http://testserver"})
    assert r.status_code == 409 and "not connected" in r.json()["error"]

    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    from fastapi.testclient import TestClient
    viewer = TestClient(app)
    viewer.post("/login", data={"username": "noc", "password": "noc-password-123"})
    assert viewer.get(f"/rdp?device={did}").status_code == 403
    assert "/rdp?device=" not in viewer.get(f"/devices/{did}").text


def test_rdp_ws_needs_a_token(logged_in):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with logged_in.websocket_connect("/api/poller/ws/rdp?token=nope", subprotocols=["guacamole"],
                                         headers={"origin": "http://testserver"}) as ws:
            ws.receive_text()


def test_outdated_poller_is_explained(logged_in, app):
    pid, did = _add_device(app, poller_features=("ssh",), dtype="Server")
    app.state.lw.hub.conns[pid] = object()       # pretend it's connected
    try:
        r = logged_in.post("/rdp/session", json={"device": did, "username": "a", "password": "b"},
                           headers={"origin": "http://testserver"})
    finally:
        del app.state.lw.hub.conns[pid]
    assert r.status_code == 409 and "doesn't support remote desktop" in r.json()["error"]


# ------------------------------------------------------------------ end to end
async def _fake_guacd(reader, writer, seen: dict):
    """Enough of guacd: handshake, then connect to the 'RDP host' it was given and prove bytes flow."""
    p = Parser()
    buf = []

    async def instr():
        while not buf:
            data = await reader.read(65536)
            if not data:
                raise ConnectionError
            buf.extend(el for _, el in p.feed(data))
        return buf.pop(0)
    assert (await instr()) == ["select", "rdp"]
    names = ["VERSION_1_5_0", "hostname", "port", "domain", "username", "password", "security", "ignore-cert",
             "resize-method", "width"]
    writer.write(encode("args", *names).encode())
    while True:
        el = await instr()
        if el[0] == "connect":
            break
        seen.setdefault("before_connect", []).append(el[0])
    seen["connect"] = dict(zip(names, el[1:]))
    host, port = seen["connect"]["hostname"], int(seen["connect"]["port"])
    r2, w2 = await asyncio.open_connection(host, port)          # through the relay and the poller's tunnel
    w2.write(b"RDP-HELLO")
    await w2.drain()
    echoed = await asyncio.wait_for(r2.readexactly(9), 10)
    writer.write((encode("ready", "$conn-1") + encode("name", echoed.decode())).encode())
    await writer.drain()
    while True:
        el = await instr()
        seen.setdefault("from_browser", []).append(el)
        if el[0] == "key":
            writer.write(encode("sync", "42").encode())
            await writer.drain()
        if el[0] == "disconnect":
            break
    w2.close()
    writer.close()


def test_rdp_end_to_end(app, live_server, tmp_path, monkeypatch):
    monkeypatch.delenv("LW_TUNNEL", raising=False)
    monkeypatch.setenv("LW_TUNNEL_PORTS", "any")
    base = live_server

    async def scenario():
        seen: dict = {}
        guacd = await asyncio.start_server(lambda r, w: _fake_guacd(r, w, seen), "127.0.0.1", 0)
        monkeypatch.setenv("LW_GUACD", f"127.0.0.1:{guacd.sockets[0].getsockname()[1]}")
        monkeypatch.setenv("LW_GUACD_CALLBACK_HOST", "127.0.0.1")
        monkeypatch.setenv("LW_GUACD_CALLBACK_BIND", "127.0.0.1")

        async def echo(r, w):
            while data := await r.read(65536):
                w.write(data)
                await w.drain()
            w.close()
        rdp_host = await asyncio.start_server(echo, "127.0.0.1", 0)
        rdp_port = rdp_host.sockets[0].getsockname()[1]

        async with httpx.AsyncClient(base_url=base, follow_redirects=True) as http:
            assert (await http.post("/login", data={"username": "admin", "password": "pw-for-tests"})).status_code == 200
            token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", (await http.post("/pollers/token")).text).group(1)
            from linkwatch.poller.main import Poller as LanPoller
            lan_task = asyncio.create_task(LanPoller(base, tmp_path / "poller", enroll_token=token, name="site-a").run())
            for _ in range(200):
                pid = next(iter(app.state.lw.hub.conns), None)
                if pid:
                    with app.state.lw.db.session() as s:
                        if "rdp" in (s.get(Poller, pid).features or []):
                            break
                await asyncio.sleep(0.05)
            with app.state.lw.db.session() as s:
                d = Device(hostname="lab-win01", ip="127.0.0.1", type="Server", poller_id=pid)
                s.add(d)
                s.flush()
                did = d.id
            r = await http.post("/rdp/session", headers={"origin": base}, json={
                "device": did, "port": rdp_port, "username": "Administrator", "password": "Winpass-1",
                "domain": "LAB", "save": True, "width": 1280, "height": 720})
            assert r.status_code == 200, r.text
            tok = r.json()["token"]
            cookie = "lw_session=" + http.cookies["lw_session"]

        url = base.replace("http://", "ws://") + f"/api/poller/ws/rdp?token={tok}"
        got = []
        async with connect(url, subprotocols=["guacamole"], additional_headers={"Cookie": cookie, "Origin": base}) as ws:
            assert ws.subprotocol == "guacamole"
            p = Parser()

            async def until(op):
                while True:
                    for _, el in p.feed(await asyncio.wait_for(ws.recv(), 20)):
                        got.append(el)
                        if el[0] == op:
                            return el
            assert (await until(""))[0] == ""                                # tunnel UUID first
            assert (await until("name")) == ["name", "RDP-HELLO"]            # bytes made the round trip
            await ws.send(encode("", "ping", "1234"))
            assert (await until("")) == ["", "ping", "1234"]                 # pings answered by the server
            await ws.send(encode("key", "65", "1"))
            assert (await until("sync")) == ["sync", "42"]
            await ws.send(encode("disconnect"))
            try:
                while True:
                    await asyncio.wait_for(ws.recv(), 5)
            except Exception:
                pass

        c = seen["connect"]
        assert c["hostname"] == "127.0.0.1" and int(c["port"]) != rdp_port   # guacd got the relay, not the host
        assert c["username"] == "Administrator" and c["password"] == "Winpass-1" and c["domain"] == "LAB"
        assert c["VERSION_1_5_0"] == "VERSION_1_5_0" and c["ignore-cert"] == "true" and c["width"] == "1280"
        assert seen["before_connect"][:4] == ["size", "audio", "video", "image"]
        assert ["", "ping", "1234"] not in seen["from_browser"]             # never forwarded to guacd

        for _ in range(50):
            with app.state.lw.db.session() as s:
                if s.scalar(select(AuditEvent).where(AuditEvent.action == "closed RDP session")):
                    break
            await asyncio.sleep(0.1)
        with app.state.lw.db.session() as s:
            actions = [a.action for a in s.scalars(select(AuditEvent).order_by(AuditEvent.id))]
            assert "opened RDP session" in actions and "closed RDP session" in actions
            row = s.scalar(select(SshTarget).where(SshTarget.port == rdp_port))
            assert row.username == "Administrator" and "Winpass-1" not in row.cred_enc
            assert app.state.lw.vault.open(row.cred_enc)["domain"] == "LAB"
        assert app.state.lw.hub.open_tunnels.get(pid, 0) == 0
        lan_task.cancel()
        guacd.close()
        rdp_host.close()

    asyncio.run(scenario())
