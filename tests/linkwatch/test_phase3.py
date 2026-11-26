"""Phase 3: the widget dashboard and the alert rule builder."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from linkwatch.server.alerts import Alerter
from linkwatch.server.dashboard import WIDGETS, clean_layout
from linkwatch.server.db import get_setting
from linkwatch.server.models import Alert, AlertPending, AlertRule, Device, Event, Port, Sensor, Site, User


def seed(app):
    with app.state.lw.db.session() as s:
        site = Site(name="HQ")
        s.add(site)
        s.flush()
        core = Device(hostname="core-sw01", ip="10.0.0.2", type="Switch", site_id=site.id, status="up", cpu=40, mem=60, ping_ms=1.2, uptime_s=300)
        fw = Device(hostname="edge-fw01", ip="10.0.0.1", type="Firewall", site_id=site.id, status="up", cpu=12, mem=30, uptime_s=900000)
        s.add_all([core, fw])
        s.flush()
        s.add_all([Port(device_id=core.id, ifindex=1, name="Te1/1/1", alias="uplink to fw", speed_mbps=10000, admin="up", oper="up", util_pct=91.0, in_bps=9.1e9, out_bps=1e9),
                   Port(device_id=core.id, ifindex=2, name="Gi1/0/2", alias="printer", speed_mbps=1000, admin="up", oper="up", util_pct=95.0),
                   Port(device_id=core.id, ifindex=3, name="Gi1/0/3", alias="", speed_mbps=1000, admin="up", oper="down", util_pct=0.0),
                   Sensor(device_id=core.id, key="t1", kind="temperature", name="Inlet", unit="°C", value=41.0, status="ok"),
                   Sensor(device_id=core.id, key="t2", kind="temperature", name="CPU", unit="°C", value=60.0, status="ok"),
                   Event(kind="device", severity="ok", device_id=core.id, message="Device up")])
        return core.id, fw.id


def make_viewer(logged_in, app):
    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer", "full_name": "NOC"})
    c = TestClient(app)
    assert c.post("/login", data={"username": "noc", "password": "noc-password-123"}, follow_redirects=False).status_code == 303
    return c


def test_default_dashboard_and_every_widget(logged_in, app):
    core_id, _ = seed(app)
    page = logged_in.get("/").text
    assert "Customise" in page and "Traffic on core-sw01 Gi1/0/2" in page and "Devices by site" in page and "Highest CPU" in page
    edit = logged_in.get("/?edit=1").text
    assert 'id="w-add"' in edit and "Make default for everyone" in edit and "/static/dashboard.js" in edit
    with app.state.lw.db.session() as s:
        port_id = s.scalar(select(Port.id).where(Port.name == "Te1/1/1"))
    layout = [{"id": f"w{i:04d}", "type": t, "w": 6, "opts": {}} for i, t in enumerate(WIDGETS)]
    for w in layout:
        if w["type"] == "device_graph":
            w["opts"] = {"device_id": str(core_id), "metric": "traffic"}
        if w["type"] == "traffic":
            w["opts"] = {"port_id": str(port_id)}
        if w["type"] == "top":
            w["opts"] = {"metric": "ping_ms"}
        if w["type"] == "note":
            w["opts"] = {"text": "On call: see https://example.com/rota"}
    r = logged_in.post("/account/dashboard", json={"layout": layout})
    assert r.json() == {"ok": True, "widgets": len(WIDGETS)}
    page = logged_in.get("/").text
    assert "couldn't load" not in page
    for text in ("Traffic on core-sw01 Te1/1/1", "Highest latency", "core-sw01", "Inlet", "On call", 'href="https://example.com/rota"',
                 'id="netmap"', "/static/map.js", "Device up", "Every device is up"):
        assert text in page, text
    assert page.count('class="p c6 widget"') == len(WIDGETS)


def test_layouts_are_cleaned_and_per_user(logged_in, app):
    seed(app)
    assert clean_layout([{"type": "nope"}, "junk", {"type": "alerts", "w": 5}])[0]["w"] == 4
    lay = clean_layout([{"type": "alerts", "id": "abcd1234", "w": 5, "opts": {"limit": "3", "evil": "x"}}])
    assert lay == [{"id": "abcd1234", "type": "alerts", "w": 4, "opts": {"limit": "3"}}]
    assert len(clean_layout([{"type": "note"}] * 100)) == 40

    viewer = make_viewer(logged_in, app)
    assert viewer.post("/account/dashboard", json={"layout": [{"type": "note", "w": 12, "opts": {"text": "viewer note"}}]}).status_code == 200
    assert "viewer note" in viewer.get("/").text and "viewer note" not in logged_in.get("/").text
    assert "Make default for everyone" not in viewer.get("/?edit=1").text

    # an admin's layout becomes the default for people who haven't customised theirs
    logged_in.post("/account/dashboard", json={"layout": [{"type": "events", "w": 12}, {"type": "down", "w": 4}]})
    assert logged_in.post("/admin/dashboard/default", follow_redirects=False).status_code == 303
    with app.state.lw.db.session() as s:
        assert [w["type"] for w in json.loads(get_setting(s, "dashboard_default"))] == ["events", "down"]
    assert viewer.post("/admin/dashboard/default", follow_redirects=False).status_code == 303   # refused, read-only
    viewer.post("/account/dashboard/reset")
    page = viewer.get("/").text
    assert "Event log" in page and "viewer note" not in page and "Devices by site" not in page
    with app.state.lw.db.session() as s:
        assert s.scalar(select(User.dashboard).where(User.username == "noc")) is None


def test_port_picker(logged_in, app):
    seed(app)
    rows = logged_in.get("/ui/dashboard/ports?q=uplink").json()
    assert [r["label"] for r in rows] == ["core-sw01 Te1/1/1 (uplink to fw)"]


def _evaluate(app, hostname):
    with app.state.lw.db.session() as s:
        dev = s.scalar(select(Device).where(Device.hostname == hostname))
        alerter = Alerter(s)
        alerter.evaluate_device(dev)
        return [(e.kind, e.title) for e in alerter.events]


def test_rule_builder_port_rule(logged_in, app):
    seed(app)
    assert "When a" in logged_in.get("/alerts/rules/new").text
    form = {"entity": "port", "metric": "util_pct", "op": ">", "threshold": "80", "polls": "2", "severity": "crit",
            "name": "Uplink saturated", "port": "uplink, Te*", "enabled": "on"}
    pv = logged_in.post("/alerts/rules/preview", data=form).json()
    assert pv["checked"] == 1 and pv["matching"] == 1 and pv["rows"][0]["value"] == "91%"
    assert pv["text"] == 'Port utilisation above 80% for 2 polls; ports matching "uplink, Te*"'
    assert logged_in.post("/alerts/rules/preview", data={**form, "threshold": "abc"}).json()["problems"] == ["The value must be a number."]
    assert logged_in.post("/alerts/rules/new", data={**form, "threshold": ""}).status_code == 400
    assert logged_in.post("/alerts/rules/new", data=form, follow_redirects=False).status_code == 303
    page = logged_in.get("/alerts").text
    assert "Uplink saturated" in page and "Your rules" in page and "Built-in rules" in page

    assert _evaluate(app, "core-sw01") == []                     # first matching poll: pending
    with app.state.lw.db.session() as s:
        assert s.scalar(select(AlertPending.hits)) == 1
    assert _evaluate(app, "core-sw01") == [("opened", "Uplink saturated: core-sw01 Te1/1/1 (uplink to fw)")]
    with app.state.lw.db.session() as s:
        a = s.scalar(select(Alert).where(Alert.state == "open"))
        assert a.severity == "crit" and "Utilisation 91%" in a.detail
        s.scalar(select(Port).where(Port.name == "Te1/1/1")).util_pct = 40.0
    assert _evaluate(app, "core-sw01") == [("resolved", "Uplink saturated: core-sw01 Te1/1/1 (uplink to fw)")]
    with app.state.lw.db.session() as s:
        assert s.scalar(select(AlertPending)) is None


def test_rule_builder_device_sensor_state_rules_and_delete(logged_in, app):
    seed(app)
    # rebooted recently: uptime under 10 minutes, firewalls and switches by name pattern
    logged_in.post("/alerts/rules/new", data={"entity": "device", "metric": "uptime_min", "op": "<", "threshold": "10", "polls": "1",
                                              "severity": "warn", "name": "Rebooted", "name_q": "core-*, *-fw*", "enabled": "on"})
    logged_in.post("/alerts/rules/new", data={"entity": "sensor", "metric": "value", "op": ">=", "threshold": "35", "polls": "1",
                                              "severity": "warn", "name": "Hot inlet", "sensor_kind": "temperature", "sensor_name": "inlet",
                                              "enabled": "on"})
    logged_in.post("/alerts/rules/new", data={"entity": "port", "metric": "oper", "op": "==", "value_text": "down", "polls": "1",
                                              "severity": "info", "name": "Link down", "type": "Switch", "enabled": "on"})
    titles = {t for _, t in _evaluate(app, "core-sw01")}
    assert {"Rebooted: core-sw01", "Hot inlet: core-sw01 Inlet", "Link down: core-sw01 Gi1/0/3"} <= titles
    assert "Hot inlet: core-sw01 CPU" not in titles
    assert _evaluate(app, "edge-fw01") == []                     # uptime is long; it has no ports or sensors

    with app.state.lw.db.session() as s:
        rule = s.scalar(select(AlertRule).where(AlertRule.name == "Hot inlet"))
        rid = rule.id
    assert "Hot inlet" in logged_in.get(f"/alerts/rules/{rid}/edit").text
    assert logged_in.get("/alerts/rules/1/edit").status_code == 404           # built-in rules aren't edited here
    # narrowing the scope resolves the alert on the next poll
    logged_in.post(f"/alerts/rules/{rid}/edit", data={"entity": "sensor", "metric": "value", "op": ">=", "threshold": "35", "polls": "1",
                                                     "severity": "warn", "name": "Hot inlet", "sensor_name": "exhaust", "enabled": "on"})
    assert ("resolved", "Hot inlet: core-sw01 Inlet") in _evaluate(app, "core-sw01")

    with app.state.lw.db.session() as s:
        link = s.scalar(select(AlertRule).where(AlertRule.name == "Link down")).id
    assert logged_in.post(f"/alerts/rules/{link}/delete", follow_redirects=False).status_code == 303
    with app.state.lw.db.session() as s:
        assert s.scalar(select(AlertRule).where(AlertRule.name == "Link down")) is None
        assert s.scalar(select(Alert).where(Alert.rule_key.like("custom_%"), Alert.title.like("Link down%"))).state == "resolved"

    viewer = make_viewer(logged_in, app)
    assert viewer.post("/alerts/rules/new", data={"entity": "device", "metric": "cpu", "threshold": "1"}, follow_redirects=False).status_code == 303
    with app.state.lw.db.session() as s:
        assert s.scalar(select(AlertRule).where(AlertRule.name == "Device cpu")) is None


def test_update_command_names_the_server(app):
    from linkwatch.server.gateway import outdated_poller_message, update_command
    assert update_command("poller 2").endswith("| sudo bash -s -- --server http://testserver --name 'poller 2'")
    assert "--server http://testserver --name poller2 (no token needed" in outdated_poller_message("poller2", "VyOS")
