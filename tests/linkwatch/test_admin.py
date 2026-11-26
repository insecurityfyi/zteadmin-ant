import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from linkwatch.server.models import AuditEvent, Device, DiscoveryJob, DiscoveryRule, User
from linkwatch.server.security import hash_password, verify_password

from .test_server import enroll


def sign_in(app, username, password):
    c = TestClient(app)
    r = c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    return c, r.status_code


def test_password_hashing():
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h) and not verify_password("wrong", h) and not verify_password("x", "junk")


def test_users_roles_and_audit(logged_in, app):
    assert "Administration" in logged_in.get("/admin").text
    r = logged_in.post("/admin/users", data={"username": "noc", "password": "short", "role": "viewer"})
    assert "at least 12" in r.text
    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer", "full_name": "NOC"})
    assert "already a user" in logged_in.post("/admin/users", data={"username": "NOC", "password": "noc-password-123"}).text

    viewer, code = sign_in(app, "noc", "noc-password-123")
    assert code == 303
    assert viewer.get("/devices").status_code == 200                       # can look
    r = viewer.post("/devices/new", data={"hostname": "x", "ip": "10.1.1.1", "type": "Switch"})
    assert "read-only" in r.text                                          # can't change
    assert "Only admins" in viewer.get("/admin").text
    assert viewer.get("/ui/metrics/device/1").status_code == 200
    # viewer can change their own password; old password stops working
    r = viewer.post("/account/password", data={"current": "noc-password-123", "password": "noc-password-456", "password2": "noc-password-456"})
    assert "Password changed" in r.text and viewer.get("/devices").status_code == 200
    assert sign_in(app, "noc", "noc-password-123")[1] == 401

    with app.state.lw.db.session() as s:
        noc = s.scalar(select(User).where(User.username == "noc"))
        admin = s.scalar(select(User).where(User.username == "admin"))
    # disabling signs the user out at once
    logged_in.post(f"/admin/users/{noc.id}", data={"role": "viewer", "disabled": "on"})
    assert viewer.get("/devices", follow_redirects=False).status_code == 303
    assert sign_in(app, "noc", "noc-password-456")[1] == 401
    # an admin can't lock themselves out, and the last admin can't be removed
    assert "remove your own admin role" in logged_in.post(f"/admin/users/{admin.id}", data={"role": "viewer"}).text
    assert "delete yourself" in logged_in.post(f"/admin/users/{admin.id}/delete", data={"confirm": "on"}).text
    # reset someone's password, then delete them
    logged_in.post(f"/admin/users/{noc.id}", data={"role": "admin"})
    logged_in.post(f"/admin/users/{noc.id}/password", data={"password": "brand-new-pass-1"})
    assert sign_in(app, "noc", "brand-new-pass-1")[1] == 303
    assert "Deleted noc" in logged_in.post(f"/admin/users/{noc.id}/delete", data={"confirm": "on"}).text

    page = logged_in.get("/admin").text
    for action in ("created user", "signed in", "sign-in failed", "updated user", "reset password", "deleted user"):
        assert action in page, action
    with app.state.lw.db.session() as s:
        assert s.scalar(select(AuditEvent).where(AuditEvent.action == "POST /account/password", AuditEvent.username == "noc")) is None
        assert s.scalar(select(AuditEvent).where(AuditEvent.action == "changed own password"))


def test_env_password_change_resets_admin(lw_config, tmp_path):
    from linkwatch.server.app import create_app
    app = create_app(lw_config)
    with app.state.lw.db.session() as s:
        s.scalar(select(User).where(User.username == "admin")).disabled = True
    import dataclasses
    app2 = create_app(dataclasses.replace(lw_config, admin_password="a-new-recovery-pw"))           # what reset-password.sh's restart does
    assert sign_in(app2, "admin", "a-new-recovery-pw")[1] == 303
    assert sign_in(app2, "admin", "pw-for-tests")[1] == 401


def test_old_database_gets_new_columns(tmp_path):
    import sqlalchemy as sa
    from linkwatch.server.db import Database
    url = f"sqlite:///{tmp_path}/old.db"
    eng = sa.create_engine(url)
    with eng.begin() as c:
        c.execute(sa.text("CREATE TABLE discovery_jobs (id INTEGER PRIMARY KEY, poller_id INTEGER, targets TEXT, profile_ids JSON, "
                          "status VARCHAR(16), total INTEGER, scanned INTEGER, results JSON, error TEXT, created_at DATETIME, finished_at DATETIME)"))
    Database(url).init()
    cols = {c["name"] for c in sa.inspect(sa.create_engine(url)).get_columns("discovery_jobs")}
    assert {"rule_id", "added"} <= cols


def test_saved_scan_runs_and_auto_adds(logged_in, app):
    ident = enroll(logged_in)
    logged_in.post("/settings/snmp", data={"name": "first", "version": "2c", "community": "a"})
    logged_in.post("/settings/snmp", data={"name": "second", "version": "2c", "community": "b"})
    # credential order: move 'second' above 'first'
    logged_in.post("/discovery/order", data={"profile_id": "2", "dir": "up"})
    page = logged_in.get("/discovery").text
    assert page.index("<b>second</b>") < page.index("<b>first</b>")

    assert "not an IPv4" in logged_in.post("/discovery/rules", data={"name": "bad", "targets": "nope", "poller_id": ident["poller_id"]}).text
    logged_in.post("/discovery/rules", data={"name": "Lab", "targets": "10.8.0.0/29", "poller_id": ident["poller_id"],
                                             "profile_id": ["1", "2"], "interval_hours": "24", "auto_add": "snmp",
                                             "site_name": "Lab", "enabled": "on"})
    with app.state.lw.db.session() as s:
        rule = s.scalar(select(DiscoveryRule))
        assert (rule.interval_hours, rule.auto_add, rule.site_name) == (24, "snmp", "Lab")
    assert logged_in.get(f"/discovery/rules/{rule.id}").status_code == 200

    from linkwatch.server.discovery import due_rules
    with app.state.lw.db.session() as s:
        assert due_rules(s, set()) == []                       # poller offline: not due
        assert [r.id for r in due_rules(s, {ident["poller_id"]})] == [rule.id]

    with logged_in.websocket_connect("/api/poller/ws", headers={"Authorization": f"Bearer {ident['key']}"}) as ws:
        json.loads(ws.receive_text())
        logged_in.post(f"/discovery/rules/{rule.id}/run")
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "discover" and [p["id"] for p in msg["profiles"]] == [2, 1]     # credential order kept
        ws.send_text(json.dumps({"type": "discovery_result", "job_id": msg["job_id"], "scanned": 6, "total": 6, "found": [
            {"ip": "10.8.0.1", "rtt_ms": 0.3, "profile_id": 2, "sys_name": "lab-sw", "sys_descr": "Cisco IOS Software"},
            {"ip": "10.8.0.2", "rtt_ms": 0.4}]}))
        cfg = json.loads(ws.receive_text())                    # config pushed after auto-add
        assert cfg["type"] == "config" and [d["ip"] for d in cfg["devices"]] == ["10.8.0.1"]

    with app.state.lw.db.session() as s:
        job = s.get(DiscoveryJob, msg["job_id"])
        assert job.added == 1 and job.rule_id == rule.id
        d = s.scalar(select(Device).where(Device.ip == "10.8.0.1"))
        assert (d.hostname, d.type, d.snmp_profile_id, d.site.name) == ("lab-sw", "Switch", 2, "Lab")
        assert s.scalar(select(Device).where(Device.ip == "10.8.0.2")) is None          # ping-only not auto-added in 'snmp' mode
        assert due_rules(s, {ident["poller_id"]}) == []                                 # ran just now
