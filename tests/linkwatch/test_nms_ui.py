"""The LibreNMS-style pages: event log, ports, health, device tabs, themes, ping-only handling, API/SNMP matching."""
import json

from sqlalchemy import select

from linkwatch.server.alerts import Alerter
from linkwatch.server.ingest import ingest_batch, ingest_integration
from linkwatch.server.models import (
    Alert,
    Device,
    DeviceMetric,
    Event,
    Integration,
    Poller,
    Port,
    SnmpProfile,
    User,
)

from .test_ingest import batch, make_db, snmp_item
from .test_server import enroll


def test_events_for_status_and_port_changes(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        ingest_batch(s, 1, batch(snmp_item(1000, 0, 0)))
    item = snmp_item(1300, 10, 10)
    item["ports"][0]["oper"] = "down"
    with db.session() as s:
        ingest_batch(s, 1, batch(item))
    for ts in (1600, 1900):
        with db.session() as s:
            ingest_batch(s, 1, batch(snmp_item(ts, 0, 0, ok=False, ping={"rtt_ms": None, "loss_pct": 100})))
    with db.session() as s:
        msgs = [e.message for e in s.scalars(select(Event).where(Event.device_id == 10).order_by(Event.id))]
    assert msgs[0] == "Device up"
    assert any(m.startswith("Port Gi1 down (was up)") for m in msgs)
    assert any(m.startswith("Device down (was up)") for m in msgs)
    assert any(m.startswith("Alert opened: Device down") for m in msgs)


def test_network_pages_render(logged_in, app):
    ident = enroll(logged_in)
    with app.state.lw.db.session() as s:
        s.add(SnmpProfile(id=9, name="v2", version="2c", config_enc="-"))
        d = Device(hostname="core-sw", ip="10.1.1.1", poller_id=ident["poller_id"], snmp_profile_id=9, cpu=55.0, mem=40.0,
                   ping_ms=2.5, loss_pct=0.0, status="up", extra={})
        s.add(d)
        s.flush()
        s.add(Port(device_id=d.id, ifindex=1, name="Gi1/0/1", alias="uplink", speed_mbps=1000, admin="up", oper="up",
                   in_bps=5e8, out_bps=1e8, util_pct=50.0))
        s.add(Port(device_id=d.id, ifindex=2, name="Gi1/0/2", admin="up", oper="down"))
        s.add(Event(kind="device", severity="ok", device_id=d.id, message="Device up"))
        s.flush()
        did, pid = d.id, s.scalar(select(Port.id).where(Port.ifindex == 1))
    for tab in ("overview", "graphs", "ports", "health", "inventory", "events", "alerts"):
        r = logged_in.get(f"/devices/{did}?tab={tab}")
        assert r.status_code == 200 and "core-sw" in r.text, tab
    assert "Gi1/0/1" in logged_in.get(f"/devices/{did}?tab=ports&view=graphs").text
    page = logged_in.get("/ports").text
    assert "Gi1/0/1" in page and "Gi1/0/2" in page
    page = logged_in.get("/ports?state=down").text
    assert "Gi1/0/2" in page and "Gi1/0/1" not in page
    assert "uplink" in logged_in.get(f"/ports/{pid}").text
    assert logged_in.get("/ports/99999").status_code == 404
    for m in ("cpu", "mem", "ping", "loss", "bogus"):
        assert "core-sw" in logged_in.get(f"/health?metric={m}").text, m
    page = logged_in.get("/eventlog").text
    assert "Device up" in page and "Poller" in page            # the poller enrolled above isn't connected; device event shows
    assert "Device up" in logged_in.get(f"/eventlog?device={did}&kind=device&q=core").text
    assert logged_in.get("/ui/metrics/device/%d/traffic" % did).json() == {"ts": [], "in": [], "out": []}
    assert "util_in" in logged_in.get(f"/ui/metrics/port/{pid}").json()


def test_themes_site_default_and_per_user(logged_in, app):
    assert 'data-theme="auto"' in logged_in.get("/").text
    logged_in.post("/admin/theme", data={"theme": "midnight"})
    assert 'data-theme="midnight"' in logged_in.get("/").text
    logged_in.post("/account/theme", data={"theme": "graphite"})
    assert '<html lang="en" data-theme="graphite" data-layout="top">' in logged_in.get("/").text
    logged_in.post("/account/theme", data={"theme": ""})             # back to the site default
    assert '<html lang="en" data-theme="midnight" data-layout="top">' in logged_in.get("/").text
    logged_in.post("/admin/theme", data={"theme": "nonsense"})
    assert '<html lang="en" data-theme="auto" data-layout="top">' in logged_in.get("/").text
    with app.state.lw.db.session() as s:
        assert s.scalar(select(User.theme).where(User.username == "admin")) is None


def test_navy_console_theme_sidebar_and_dashboard(logged_in, app):
    from datetime import timedelta

    from linkwatch.server.models import (
        Alert,
        Device,
        DeviceMetric,
        Port,
        PortMetric,
        Site,
        utcnow,
    )
    with app.state.lw.db.session() as s:
        site = Site(name="New York")
        s.add(site)
        s.flush()
        core = Device(hostname="core-switch-01", ip="10.0.1.1", status="up", cpu=82, mem=61, ping_ms=1.5, site_id=site.id, last_polled=utcnow())
        rtr = Device(hostname="remote-router-02", ip="192.168.5.10", status="down", type="Router", site_id=site.id)
        s.add_all([core, rtr])
        s.flush()
        p1 = Port(device_id=core.id, ifindex=1, name="Te1/1/1", in_bps=4e8, out_bps=1e8)
        p2 = Port(device_id=rtr.id, ifindex=1, name="ge-0/0/0", in_bps=2e8, out_bps=2e8)
        s.add_all([p1, p2, Alert(rule_key="device_down", ref="x", device_id=rtr.id, severity="crit", title="Device down: remote-router-02", state="open")])
        s.flush()
        now = utcnow()
        for k in range(4):
            ts = now - timedelta(minutes=5 * k + 1)
            s.add_all([PortMetric(port_id=p1.id, ts=ts, in_bps=100.0 + k, out_bps=10.0), PortMetric(port_id=p2.id, ts=ts, in_bps=50.0, out_bps=5.0),
                       DeviceMetric(device_id=core.id, ts=ts, cpu=80.0, mem=60.0, ping_ms=2.0)])

    logged_in.post("/admin/theme", data={"theme": "navy"})
    page = logged_in.get("/").text
    assert '<html lang="en" data-theme="navy" data-layout="sidebar">' in page and "family=Inter" in page
    assert 'class="m side-only' in page and "Administration" in page            # sidebar extras
    for text in ("Total devices", "Offline / critical", "Average latency", "Bandwidth now", "Network traffic", "Overall health",
                 "Highest CPU", "core-switch-01", 'class="pill down"', "Offline", "data-dtable", "data-range-select", "widget tall"):
        assert text in page, text
    assert "1 device down, 1 critical alert" in page and ">45<" in page    # 50% up, less 5 for the critical alert

    series = logged_in.get("/ui/metrics/network?range=6h").json()
    assert len(series["ts"]) >= 2 and max(series["in"]) == 153.0 and series["ping"][0] == 2.0
    assert logged_in.get("/ui/metrics/network?range=6h&ports=edge").json()["in"][0] == 50.0

    # the layout can be chosen per site and per user
    logged_in.post("/admin/theme", data={"theme": "navy", "layout": "top"})
    assert 'data-layout="top"' in logged_in.get("/").text
    logged_in.post("/account/theme", data={"theme": "light", "layout": "sidebar"})
    page = logged_in.get("/account").text
    assert '<html lang="en" data-theme="light" data-layout="sidebar">' in page and "<title>Your account · VisCon1</title>" in page
    # the Navy layout is only the starting point for that theme
    assert "Overall health" not in logged_in.get("/").text


def test_ping_only_hosts_can_be_skipped_and_bulk_disabled(logged_in, app):
    ident = enroll(logged_in)
    logged_in.post("/settings/snmp", data={"name": "lab", "version": "2c", "community": "public"})
    with logged_in.websocket_connect("/api/poller/ws", headers={"Authorization": f"Bearer {ident['key']}"}) as ws:
        json.loads(ws.receive_text())
        logged_in.post("/discovery", data={"targets": "10.8.0.0/29", "poller_id": ident["poller_id"], "profile_id": "1"})
        job = json.loads(ws.receive_text())["job_id"]
        ws.send_text(json.dumps({"type": "discovery_result", "job_id": job, "scanned": 6, "total": 6, "found": [
            {"ip": "10.8.0.1", "rtt_ms": 0.4},
            {"ip": "10.8.0.2", "rtt_ms": 0.6, "profile_id": 1, "sys_name": "sw-a", "sys_descr": "Cisco IOS"}]}))
        ws.send_text(json.dumps({"type": "results", "batch_id": "barrier", "items": []}))
        json.loads(ws.receive_text())
    assert "2 found" in logged_in.get(f"/discovery/{job}").text
    logged_in.post("/discovery/ping-only", data={"mode": "skip"})
    page = logged_in.get(f"/discovery/{job}").text
    assert "1 found" in page and "1 ping-only host skipped" in page and "10.8.0.1" not in page
    r = logged_in.post(f"/discovery/{job}/add", data={"ip": ["10.8.0.1", "10.8.0.2"]})
    assert "Added 1 device" in r.text
    logged_in.post("/discovery/ping-only", data={"mode": "include"})
    logged_in.post(f"/discovery/{job}/add", data={"ip": ["10.8.0.1"]})
    with app.state.lw.db.session() as s:
        ping_id = s.scalar(select(Device.id).where(Device.ip == "10.8.0.1", Device.source == "ping"))
        s.add(Alert(rule_key="device_down", ref=f"device:{ping_id}", device_id=ping_id, severity="crit", title="down"))
    page = logged_in.get("/devices?source=ping").text
    assert "10.8.0.1" in page and "10.8.0.2" not in page
    r = logged_in.post("/devices/bulk", data={"action": "disable", "device_id": [str(ping_id)], "back": "/devices?source=ping"})
    assert "Disabled 1 device" in r.text
    with app.state.lw.db.session() as s:
        d = s.get(Device, ping_id)
        assert d.disabled and d.status == "off"
        assert s.scalar(select(Alert.state).where(Alert.device_id == ping_id)) == "resolved"
    logged_in.post("/devices/bulk", data={"action": "delete", "device_id": [str(ping_id)]})
    with app.state.lw.db.session() as s:
        assert s.get(Device, ping_id) is None
        assert s.scalar(select(Event.message).where(Event.message.like("Device 10.8.0.1 deleted%")))


def _meraki(s, records):
    integ = s.get(Integration, 1) or Integration(id=1, kind="meraki", name="Meraki", config_enc="-", enabled=True)
    s.add(integ)
    s.flush()
    alerter = Alerter(s)
    ingest_integration(s, alerter, integ, {"ok": True, "ts": 1_700_000_000, "records": records})


def test_api_devices_merge_with_snmp_devices(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        s.get(Device, 10).serial = "Q2XX-AAAA-BBBB"
        s.add(Device(id=12, hostname="10.0.0.9", ip="10.0.0.9", poller_id=1, source="ping", extra={}))
        s.add(Device(id=13, hostname="mr-lobby", sys_name="MR-Lobby", ip="10.0.0.20", poller_id=1, snmp_profile_id=1, extra={}))
    recs = [
        {"external_id": "Q2XX-AAAA-BBBB", "hostname": "MS-Core", "ip": "192.0.2.1", "serial": "Q2XX-AAAA-BBBB", "status": "up",
         "type": "Switch", "platform": "Meraki MS250", "extra": {"mac": "aa:bb"}},                      # by serial
        {"external_id": "Q2MX-0001", "hostname": "MX-Edge", "ip": "203.0.113.5", "serial": "Q2MX-0001", "status": "up",
         "type": "Firewall", "extra": {"ips": ["10.0.0.9", "203.0.113.5"]}},                            # by WAN/LAN IP list
        {"external_id": "Q2MR-0002", "hostname": "mr-lobby", "serial": "Q2MR-0002", "status": "up", "type": "Wireless"},   # by name
        {"external_id": "Q2MR-0003", "hostname": "MR-Far", "serial": "Q2MR-0003", "status": "up", "type": "Wireless", "cpu": 5.0},
    ]
    with db.session() as s:
        _meraki(s, recs)
    with db.session() as s:
        by_ext = {d.external_id: d for d in s.scalars(select(Device).where(Device.integration_id == 1))}
        assert by_ext["Q2XX-AAAA-BBBB"].id == 10 and by_ext["Q2XX-AAAA-BBBB"].source == "snmp"
        assert by_ext["Q2XX-AAAA-BBBB"].extra["api"]["integration"] == "Meraki"
        assert by_ext["Q2MX-0001"].id == 12
        assert by_ext["Q2MR-0002"].id == 13
        far = by_ext["Q2MR-0003"]
        assert far.source == "meraki"
        far_id = far.id
        assert s.scalar(select(DeviceMetric.id).where(DeviceMetric.device_id == far_id))
        assert len(s.scalars(select(Device)).all()) == 5
    # now someone adds MR-Far over SNMP: the next sync folds the API-only device into it, keeping its history
    with db.session() as s:
        s.add(Device(id=20, hostname="mr-far.lan", sys_name="MR-Far", ip="10.0.0.30", poller_id=1, snmp_profile_id=1, extra={}))
    with db.session() as s:
        _meraki(s, recs)
    with db.session() as s:
        assert s.get(Device, far_id) is None
        merged = s.get(Device, 20)
        assert merged.integration_id == 1 and merged.external_id == "Q2MR-0003"
        assert s.scalar(select(DeviceMetric.id).where(DeviceMetric.device_id == 20))
        assert s.scalar(select(Event.id).where(Event.device_id == 20, Event.message.like("Matched to Meraki%")))
        assert len(s.scalars(select(Device)).all()) == 5
