"""Pollers page commands (reload config, update), the poller naming scheme and factory reset, end to end with a real
poller connected to a live server."""
import asyncio
import json
import re

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from linkwatch.server.models import AuditEvent, Device, Poller, PollerCommand


async def _login(base):
    http = httpx.AsyncClient(base_url=base, follow_redirects=True, timeout=20)
    await http.post("/login", data={"username": "admin", "password": "pw-for-tests"})
    return http


async def _token(http) -> str:
    page = (await http.post("/pollers/token")).text
    return re.search(r"LW_ENROLL_TOKEN=(\S+) ", page).group(1)


async def _connect(base, app, http, data_dir, name="site-a", helper=False):
    from linkwatch.poller.main import Poller as LanPoller
    lan = LanPoller(base, data_dir, enroll_token=await _token(http), name=name)
    lan.result_poll = 0.1
    if helper:
        (lan.control / "helper.json").write_text(json.dumps({"version": 1, "runtime": "podman"}))
    before = set(app.state.lw.hub.conns)
    task = asyncio.create_task(lan.run())
    for _ in range(200):
        new = set(app.state.lw.hub.conns) - before
        if new:
            pid = new.pop()
            with app.state.lw.db.session() as s:
                if "commands" in (s.get(Poller, pid).features or []):
                    return lan, task, pid
        await asyncio.sleep(0.05)
    raise AssertionError("poller did not connect")


async def _wait_cmd(app, pid, timeout=10.0) -> PollerCommand:
    for _ in range(int(timeout / 0.05)):
        with app.state.lw.db.session() as s:
            c = s.scalar(select(PollerCommand).where(PollerCommand.poller_id == pid).order_by(PollerCommand.id.desc()))
            if c is not None and c.state != "pending":
                return c
        await asyncio.sleep(0.05)
    raise AssertionError("command still pending")


def test_naming_scheme(logged_in, app):
    def enroll(name):
        logged_in.post("/pollers/token")
        token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", logged_in.get("/pollers").text)
        assert token is None       # the token is shown once, right after it is made
        r = logged_in.post("/pollers/token", follow_redirects=True)
        token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", r.text).group(1)
        return logged_in.post("/api/poller/enroll", json={"token": token, "name": name}).json()

    assert enroll("hq")["name"] == "hq"
    assert enroll("hq")["name"] == "hq-2"          # no scheme: the old behaviour
    r = logged_in.post("/settings/pollers", data={"base_name": "bad name."}, follow_redirects=True)
    assert "Use up to 60 letters" in r.text
    r = logged_in.post("/settings/pollers", data={"base_name": "lw-poller"}, follow_redirects=True)
    assert "lw-poller.1" in r.text
    names = [enroll(n)["name"] for n in ("anything", "hq", "")]
    assert names == ["lw-poller.1", "lw-poller.2", "lw-poller.3"]
    page = logged_in.post("/pollers/token", follow_redirects=True).text
    assert "lw-poller.4" in page and "--name poller-hq-01" not in page
    with app.state.lw.db.session() as s:
        p = s.scalar(select(Poller).where(Poller.name == "lw-poller.2"))
        p.revoked = True
        pid = p.id
    logged_in.post(f"/pollers/{pid}/delete")
    assert enroll("x")["name"] == "lw-poller.2"     # the lowest free number
    # renaming an existing poller; names stay unique
    with app.state.lw.db.session() as s:
        hq = s.scalar(select(Poller).where(Poller.name == "hq")).id
    r = logged_in.post(f"/pollers/{hq}/rename", data={"name": "lw-poller.1"}, follow_redirects=True)
    assert "already called" in r.text
    logged_in.post(f"/pollers/{hq}/rename", data={"name": "lw-poller.9"})
    with app.state.lw.db.session() as s:
        assert s.get(Poller, hq).name == "lw-poller.9"
    assert enroll("y")["name"] == "lw-poller.4"
    logged_in.post("/settings/pollers", data={"base_name": ""})
    assert enroll("plain")["name"] == "plain"


def test_reload_config_verified(app, live_server, tmp_path):
    async def scenario():
        http = await _login(live_server)
        lan, task, pid = await _connect(live_server, app, http, tmp_path / "p1")
        with app.state.lw.db.session() as s:
            s.add(Device(hostname="sw1", ip="10.0.0.1", type="Switch", poller_id=pid, ping=True, source="ping", extra={}))
        r = await http.post("/pollers/commands", data={"kind": "reload", "poller_ids": [str(pid)]})
        assert "Reload config sent to site-a" in r.text
        c = await _wait_cmd(app, pid)
        assert c.state == "ok", c.detail
        assert c.detail.startswith("Applied: 1 devices") and c.after.startswith("v0.1.0") and c.username == "admin"
        assert [d["hostname"] for d in lan.devices] == ["sw1"]
        status = (await http.get("/ui/pollers/status")).json()
        assert status[str(pid)]["command"]["state"] == "ok"
        assert "Reload config</b> passed" in (await http.get("/pollers")).text
        # nothing ticked
        r = await http.post("/pollers/commands", data={"kind": "reload"})
        assert "Tick at least one poller" in r.text
        task.cancel()
        await http.aclose()
    asyncio.run(scenario())


def test_reload_on_old_poller_fails_with_reason(logged_in, app):
    logged_in.post("/pollers/token")
    token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", logged_in.post("/pollers/token", follow_redirects=True).text).group(1)
    ident = logged_in.post("/api/poller/enroll", json={"token": token, "name": "old"}).json()
    with logged_in.websocket_connect("/api/poller/ws", headers={"Authorization": f"Bearer {ident['key']}"}) as ws:
        ws.receive_text()       # config
        ws.send_text(json.dumps({"type": "hello", "version": "0.0.9", "features": ["rpc"]}))
        ws.send_text(json.dumps({"type": "pong"}))
        for _ in range(100):
            with app.state.lw.db.session() as s:
                if s.get(Poller, ident["poller_id"]).features == ["rpc"]:
                    break
        logged_in.post("/pollers/commands", data={"kind": "update", "poller_ids": [str(ident["poller_id"])]})
        logged_in.post("/pollers/commands", data={"kind": "reload", "poller_ids": [str(ident["poller_id"])]})
        assert json.loads(ws.receive_text())["type"] == "config"      # the reload still sends the config
        asyncio.run(asyncio.sleep(0.3))
    with app.state.lw.db.session() as s:
        cmds = {c.kind: c for c in s.scalars(select(PollerCommand))}
    assert cmds["update"].state == "failed" and "update helper" in cmds["update"].detail and "install-poller.sh" in cmds["update"].detail
    assert cmds["reload"].state == "failed" and "too old to confirm" in cmds["reload"].detail


def test_update_through_host_helper(app, live_server, tmp_path, monkeypatch):
    from linkwatch.poller import main as poller_main

    async def fake_helper(lan, ok=True, error="", new_build=None):
        """What linkwatch-poller-helper does on the host: take the request, and leave a result for the poller."""
        req = lan.control / "update.request"
        for _ in range(200):
            if req.exists():
                break
            await asyncio.sleep(0.05)
        rid = req.read_text().strip()
        req.unlink()
        if new_build:      # the "new container" comes back with a newer build
            monkeypatch.setattr(poller_main, "BUILD", new_build)
            await lan.ws.close()
            await asyncio.sleep(0.5)
        (lan.control / "update.result").write_text(json.dumps(
            {"id": rid, "ok": ok, "changed": bool(new_build), "image": "0123456789ab", "error": error, "at": 1}))
        return rid

    async def scenario():
        monkeypatch.setattr(poller_main, "BUILD", "sha-aaaaaaaaaaaa")
        http = await _login(live_server)
        lan, task, pid = await _connect(live_server, app, http, tmp_path / "p1", helper=True)
        with app.state.lw.db.session() as s:
            assert "self_update" in s.get(Poller, pid).features and s.get(Poller, pid).build == "sha-aaaaaaaaaaaa"
        await http.post("/pollers/commands", data={"kind": "update", "poller_ids": [str(pid)]})
        rid = await fake_helper(lan, new_build="sha-bbbbbbbbbbbb")
        c = await _wait_cmd(app, pid, 20)
        assert c.state == "ok", c.detail
        assert rid.startswith(f"u{c.id}-")
        assert c.before == "v0.1.0 (sha-aaaaaaaaaaaa)" and c.after == "v0.1.0 (sha-bbbbbbbbbbbb)"
        assert "Updated from v0.1.0 (sha-aaaaaaaaaaaa) to v0.1.0 (sha-bbbbbbbbbbbb)" in c.detail
        # a failed pull on the host
        await http.post("/pollers/commands", data={"kind": "update", "poller_ids": [str(pid)]})
        await fake_helper(lan, ok=False, error="!! Could not pull ghcr.io/x")
        c = await _wait_cmd(app, pid, 20)
        assert c.state == "failed" and "Could not pull ghcr.io/x" in c.detail
        # a host without the helper
        (lan.control / "helper.json").unlink()
        with app.state.lw.db.session() as s:
            s.get(Poller, pid).features = [f for f in s.get(Poller, pid).features if f != "self_update"]
        await http.post("/pollers/commands", data={"kind": "update", "poller_ids": [str(pid)]})
        c = await _wait_cmd(app, pid)
        assert c.state == "failed" and "doesn't have the update helper" in c.detail
        task.cancel()
        await http.aclose()
    asyncio.run(scenario())


def test_bulk_commands(app, live_server, tmp_path):
    async def scenario():
        http = await _login(live_server)
        a = await _connect(live_server, app, http, tmp_path / "a", name="a")
        b = await _connect(live_server, app, http, tmp_path / "b", name="b")
        r = await http.post("/pollers/commands", data={"kind": "reload", "poller_ids": [str(a[2]), str(b[2])]})
        assert "Reload config sent to 2 pollers" in r.text
        assert (await _wait_cmd(app, a[2])).state == "ok" and (await _wait_cmd(app, b[2])).state == "ok"
        for x in (a, b):
            x[1].cancel()
        await http.aclose()
    asyncio.run(scenario())


def test_factory_reset(app, live_server, tmp_path):
    async def scenario():
        http = await _login(live_server)
        data = tmp_path / "p1"
        lan, task, pid = await _connect(live_server, app, http, data, name="site-a")
        with app.state.lw.db.session() as s:
            s.add(Device(hostname="sw1", ip="10.0.0.1", type="Switch", poller_id=pid, ping=True, source="ping", extra={}))
        r = await http.post(f"/pollers/{pid}/factory-reset", data={"confirm_name": "site-b"})
        assert "name (site-a) exactly to confirm" in r.text
        assert (data / "identity.json").exists()
        r = await http.post(f"/pollers/{pid}/factory-reset", data={"confirm_name": "site-a"})
        assert "site-a was factory reset" in r.text
        assert not (data / "identity.json").exists() and (data / "factory-reset.json").exists()
        assert lan.reset_done.is_set() and lan.devices == [] and lan.key is None
        await asyncio.sleep(0.2)
        assert not task.done()          # waits for a new enrollment instead of exiting (no restart loop)
        with app.state.lw.db.session() as s:
            assert s.get(Poller, pid) is None
            assert s.scalar(select(Device).where(Device.hostname == "sw1")).poller_id is None
            a = s.scalar(select(AuditEvent).where(AuditEvent.action == "factory reset poller"))
            assert a.username == "admin" and a.detail.startswith("site-a: the poller wiped")
        # a restarted container with the old (used) token stays idle; a new token enrolls it again
        from linkwatch.poller.main import Poller as LanPoller
        assert LanPoller(live_server, data, enroll_token=lan.enroll_token).token_is_stale()
        assert not LanPoller(live_server, data, enroll_token="enr_new").token_is_stale()
        task.cancel()
        # not connected: refused unless forced
        lan2, task2, pid2 = await _connect(live_server, app, http, tmp_path / "p2", name="site-c")
        task2.cancel()
        for _ in range(100):
            if pid2 not in app.state.lw.hub.conns:
                break
            await asyncio.sleep(0.05)
        r = await http.post(f"/pollers/{pid2}/factory-reset", data={"confirm_name": "site-c"})
        assert "Factory reset of site-c failed: The poller is not connected." in r.text
        with app.state.lw.db.session() as s:
            assert s.get(Poller, pid2) is not None
        r = await http.post(f"/pollers/{pid2}/factory-reset", data={"confirm_name": "site-c", "force": "on"})
        assert "removed from this server, but it didn" in r.text
        with app.state.lw.db.session() as s:
            assert s.get(Poller, pid2) is None
        await http.aclose()
    asyncio.run(scenario())


def test_factory_reset_needs_admin(app):
    from linkwatch.server.users import hash_password
    from linkwatch.server.models import User
    with app.state.lw.db.session() as s:
        s.add(User(username="viewer1", full_name="V", role="viewer", password_hash=hash_password("viewer-password-1")))
        s.add(Poller(name="p", key_hash="x" * 64))
    with TestClient(app) as c:
        c.post("/login", data={"username": "viewer1", "password": "viewer-password-1"})
        c.post("/pollers/1/factory-reset", data={"confirm_name": "p"})
        c.post("/pollers/commands", data={"kind": "update", "poller_ids": ["1"]})
    with app.state.lw.db.session() as s:
        assert s.get(Poller, 1) is not None and s.scalar(select(PollerCommand)) is None
