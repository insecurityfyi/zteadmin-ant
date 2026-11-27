"""Standard system/disk counters, custom OIDs (poller, config push, ingest, UI) and MIB uploads."""
import asyncio
import json

from sqlalchemy import select

from linkwatch.poller import snmp_extra
from linkwatch.server.alerts import Alerter
from linkwatch.server.ingest import ingest_batch
from linkwatch.server.models import Alert, AlertRule, CustomOid, Device, MibModule, Poller, Port, Sensor, SensorMetric, SnmpProfile

from .test_ingest import batch, make_db, snmp_item
from .test_phase2 import FakeSnmp

DIO = "1.3.6.1.4.1.2021.13.15.1.1"
TABLE = {
    "1.3.6.1.4.1.2021.10.1.5.1": 152, "1.3.6.1.2.1.6.9.0": 42, "1.3.6.1.2.1.6.12.0": 1000, "1.3.6.1.2.1.4.8.0": 7,
    "1.3.6.1.4.1.2021.4.3.0": 1000, "1.3.6.1.4.1.2021.4.4.0": 750,
    f"{DIO}.2.1": "sda", f"{DIO}.12.1": 5000, f"{DIO}.13.1": 9000,
    f"{DIO}.2.2": "loop0", f"{DIO}.12.2": 10, f"{DIO}.13.2": 10,
    f"{DIO}.2.3": "sdb", f"{DIO}.3.3": 0, f"{DIO}.4.3": 0,
    # custom: a scalar, a table column with names, and a Cisco-only OID
    "1.3.6.1.4.1.99999.1.1.0": 37, "1.3.6.1.4.1.99999.1.3.1.3.1": 1, "1.3.6.1.4.1.99999.1.3.1.3.2": 2,
    "1.3.6.1.4.1.99999.1.3.1.2.1": "to-hq", "1.3.6.1.4.1.99999.1.3.1.2.2": "to-dc",
    "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1": 12,
}

ACME = open(__file__.replace("test_custom_oids.py", "acme_mib.txt")).read()


def test_poller_system_disk_and_custom():
    s = FakeSnmp(TABLE)
    sysrows = {r["key"]: r for r in asyncio.run(snmp_extra.system_stats(s))}
    assert sysrows["sys.load1"]["value"] == 1.52 and sysrows["sys.tcp_estab"]["value"] == 42
    assert sysrows["sys.tcp_retrans"]["counter"] and sysrows["sys.tcp_retrans"]["raw"] == 1000
    assert sysrows["sys.swap"]["value"] == 25.0
    dio = asyncio.run(snmp_extra.disk_io(s))
    assert {r["name"] for r in dio} == {"sda read", "sda write"}          # loop devices and idle disks dropped
    defs = [{"id": 1, "oid": "1.3.6.1.4.1.99999.1.1.0", "mode": "get"},
            {"id": 2, "oid": "1.3.6.1.4.1.99999.1.3.1.3", "mode": "walk", "label_oid": "1.3.6.1.4.1.99999.1.3.1.2"},
            {"id": 3, "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "mode": "walk", "sys_object_id": "1.3.6.1.4.1.9"},
            {"id": 4, "oid": "1.3.6.1.4.1.99999.9.0", "mode": "get"}]
    rows = asyncio.run(snmp_extra.custom_oids(s, defs, "1.3.6.1.4.1.99999.2"))
    assert {"id": 1, "index": "", "value": 37, "label": None} in rows
    assert {"id": 2, "index": "1", "value": 1, "label": "to-hq"} in rows
    assert not any(r["id"] in (3, 4) for r in rows)                        # wrong vendor; no such OID
    assert any(r["id"] == 3 for r in asyncio.run(snmp_extra.custom_oids(s, defs, "1.3.6.1.4.1.9.1.1")))
    assert snmp_extra.sys_oid_matches("1.3.6.1.4.1.9", "1.3.6.1.4.1.9.1.5") and not snmp_extra.sys_oid_matches("1.3.6.1.4.1.9", "1.3.6.1.4.1.99.1")


def add_defs(db):
    with db.session() as s:
        s.add_all([
            CustomOid(id=1, name="Acme CPU", oid="1.3.6.1.4.1.99999.1.1.0", mode="get", value_type="gauge", unit="%", enabled=True),
            CustomOid(id=2, name="Tunnel", oid="1.3.6.1.4.1.99999.1.3.1.3", mode="walk", value_type="state",
                      states={"1": "up", "2": "down"}, ok_values="1", category="VPN", enabled=True),
            CustomOid(id=3, name="Sessions", oid="1.3.6.1.4.1.99999.1.2.0", mode="get", value_type="counter", scale=2, enabled=True),
            CustomOid(id=4, name="Version", oid="1.3.6.1.4.1.99999.1.4.0", mode="get", value_type="text", enabled=True),
            CustomOid(id=5, name="Cisco only", oid="1.3.6.1.4.1.9.9.109.1.1.1.1.7", mode="walk", value_type="gauge",
                      match_sys_oid="1.3.6.1.4.1.9", enabled=True),
            CustomOid(id=6, name="Firewalls only", oid="1.3.6.1.4.1.99999.5.0", mode="get", value_type="gauge",
                      match_type="Firewall", enabled=True),
        ])


def test_ingest_custom_system_and_discards(tmp_path):
    db = make_db(tmp_path)
    add_defs(db)
    t0 = 1_700_000_000.0

    def item(ts, sessions, retrans, rd, disc):
        it = snmp_item(ts, 0, 0)
        it["ports"][0].update(in_discards=disc, out_discards=0)
        it["system_stats"] = [{"key": "sys.tcp_retrans", "kind": "system", "name": "TCP retransmits", "unit": "/s",
                               "counter": True, "raw": retrans, "bits": 32, "scale": 1}]
        it["disk_io"] = [{"key": "dio.1.read", "kind": "diskio", "name": "sda read", "unit": "B/s", "counter": True, "raw": rd,
                          "bits": 64, "scale": 1}]
        it["custom"] = [{"id": 1, "index": "", "value": 37, "label": None},
                        {"id": 2, "index": "1", "value": 1, "label": "to-hq"}, {"id": 2, "index": "2", "value": 2, "label": "to-dc"},
                        {"id": 3, "index": "", "value": sessions, "label": None},
                        {"id": 4, "index": "", "value": "v9.1.2", "label": None},
                        {"id": 99, "index": "", "value": 1, "label": None}]       # deleted definition: ignored
        return it

    with db.session() as s:
        ingest_batch(s, 1, batch(item(t0, 100, 2**32 - 100, 0, 5)))
    with db.session() as s:
        ingest_batch(s, 1, batch(item(t0 + 300, 400, 200, 3000, 65)))
        sens = {x.key: x for x in s.scalars(select(Sensor).where(Sensor.device_id == 10))}
        assert sens["oid1"].value == 37 and sens["oid1"].kind == "custom" and sens["oid1"].unit == "%"
        assert sens["oid2.1"].name == "Tunnel to-hq" and sens["oid2.1"].status == "ok" and sens["oid2.1"].extra["state"] == "up"
        assert sens["oid2.2"].status == "crit" and sens["oid2.2"].extra["label"] == "VPN"
        assert sens["oid3"].value == 2.0                       # (400 - 100) / 300 s * 2
        assert sens["oid4"].value is None and sens["oid4"].extra["text"] == "v9.1.2"
        assert "oid99" not in sens
        assert sens["sys.tcp_retrans"].value == 1.0             # 32-bit wrap: 300 retransmits in 300 s
        assert sens["dio.1.read"].value == 10.0
        assert s.scalar(select(SensorMetric.value).where(SensorMetric.sensor_id == sens["oid3"].id)) == 2.0
        port = s.scalar(select(Port).where(Port.device_id == 10))
        assert port.in_disc_rate == 60 and port.out_disc_rate == 0
    with db.session() as s:
        ingest_batch(s, 1, batch(item(t0 + 600, 700, 500, 6000, 65)))
        titles = [a.title for a in s.scalars(select(Alert).where(Alert.state == "open"))]
        assert any("Tunnel to-dc" in t for t in titles)


def test_config_push_scopes_custom_oids(tmp_path, app):
    with app.state.lw.db.session() as s:
        s.add(Poller(id=1, name="p1", key_hash="x"))
        s.add(SnmpProfile(id=1, name="v2", version="2c", config_enc=app.state.lw.vault.seal({"version": "2c", "community": "c"})))
        s.add(Device(id=10, hostname="core-sw", ip="10.0.0.2", poller_id=1, snmp_profile_id=1, type="Switch",
                     sys_object_id="1.3.6.1.4.1.9.1.2694", extra={}))
        s.add(Device(id=11, hostname="edge-fw", ip="10.0.0.1", poller_id=1, snmp_profile_id=1, type="Firewall", extra={}))
        s.add(Device(id=12, hostname="printer", ip="10.0.0.9", poller_id=1, ping=True, extra={}))
    add_defs(app.state.lw.db)
    cfg = app.state.lw.hub.build_config(1)
    devs = {d["id"]: d for d in cfg["devices"]}
    ids = lambda d: sorted(x["id"] for x in devs[d]["oids"])          # noqa: E731
    assert ids(10) == [1, 2, 3, 4, 5]                 # Cisco switch: not the firewall-only one
    assert ids(11) == [1, 2, 3, 4, 5, 6]              # sysObjectID unknown yet: the poller checks the prefix
    assert next(x for x in devs[11]["oids"] if x["id"] == 5)["sys_object_id"] == "1.3.6.1.4.1.9"
    assert "oids" not in devs[12]                     # ping-only
    assert set(devs[10]["oids"][0]) == {"id", "oid", "mode", "label_oid", "sys_object_id"}


def test_custom_oid_pages_and_mib_upload(logged_in, app):
    c = logged_in
    page = c.get("/oids")
    assert page.status_code == 200 and "Custom OIDs and MIBs" in page.text and "Start from a common OID" in page.text
    # standard MIB names resolve without uploading anything; a column defaults to a table walk
    hits = c.get("/ui/mibs/search?q=ifHCInUcast").json()
    assert hits[0]["name"] == "ifHCInUcastPkts" and hits[0]["suggest"]["value_type"] == "counter" and hits[0]["suggest"]["mode"] == "walk"
    r = c.post("/oids/new", data={"oid": "IF-MIB::ifHCInUcastPkts", "label_oid": "IF-MIB::ifName", "value_type": "counter",
                                  "unit": "pkts/s", "enabled": "on"}, follow_redirects=False)
    assert r.status_code == 303
    with app.state.lw.db.session() as s:
        d = s.scalar(select(CustomOid))
        assert (d.oid, d.mode, d.label_oid, d.name, d.mib_name) == ("1.3.6.1.2.1.31.1.1.1.7", "walk", "1.3.6.1.2.1.31.1.1.1.1",
                                                                      "ifHCInUcastPkts", "IF-MIB::ifHCInUcastPkts")
        oid_id = d.id
    # a scalar gets .0; a table is refused; garbage is refused
    c.post("/oids/new", data={"oid": "TCP-MIB::tcpCurrEstab", "name": "TCP", "value_type": "gauge", "enabled": "on"})
    with app.state.lw.db.session() as s:
        assert s.scalar(select(CustomOid.oid).where(CustomOid.name == "TCP")) == "1.3.6.1.2.1.6.9.0"
    bad = c.post("/oids/new", data={"oid": "IF-MIB::ifXTable", "value_type": "gauge"})
    assert bad.status_code == 400 and "whole table" in bad.text
    bad = c.post("/oids/new", data={"oid": "NOPE-MIB::nothing", "value_type": "gauge"})
    assert bad.status_code == 400 and "Upload the MIB" in bad.text

    # upload a vendor MIB, then one that imports something missing
    r = c.post("/mibs/upload", files=[("files", ("ACME-MIB.my", ACME.encode(), "text/plain"))], follow_redirects=True)
    assert "Loaded ACME-MIB" in r.text
    broken = ACME.replace("ACME-MIB", "BROKEN-MIB").replace("FROM SNMPv2-TC", "FROM ACME-TC")
    r = c.post("/mibs/upload", files=[("files", ("broken.mib", broken.encode(), "text/plain"))], follow_redirects=True)
    assert "ACME-TC" in r.text
    r = c.post("/mibs/upload", files=[("files", ("notes.txt", b"hello", "text/plain"))], follow_redirects=True)
    assert "does not look like a MIB" in r.text
    with app.state.lw.db.session() as s:
        acme = s.scalar(select(MibModule).where(MibModule.name == "ACME-MIB"))
        assert acme.error is None and any(o["name"] == "acmeTunnelState" for o in acme.objects)
        acme_id = acme.id
    hit = c.get("/ui/mibs/search?q=acmeTunnelState").json()[0]
    assert hit["module"] == "ACME-MIB" and hit["suggest"]["value_type"] == "state" and hit["suggest"]["states"] == {"1": "up", "2": "down"}
    detail = c.get(f"/mibs/{acme_id}")
    assert "acmeCpuLoad" in detail.text and "Poll this" in detail.text
    form = c.get("/oids/new?oid=ACME-MIB::acmeCpuLoad")
    assert 'value="1.3.6.1.4.1.99999.1.1.0"' in form.text and 'value="%"' in form.text
    assert c.get("/oids/new?preset=0").status_code == 200

    # edit, test (no poller connected), delete removes its sensors
    r = c.post(f"/oids/{oid_id}", data={"oid": "1.3.6.1.2.1.31.1.1.1.7", "name": "Unicast in", "mode": "walk", "value_type": "counter"},
               follow_redirects=False)
    assert r.status_code == 303
    with app.state.lw.db.session() as s:
        assert s.get(CustomOid, oid_id).enabled is False and s.get(CustomOid, oid_id).name == "Unicast in"
        s.add(SnmpProfile(id=1, name="v2", version="2c", config_enc="-"))
        s.add(Poller(id=1, name="p1", key_hash="y"))
        s.add(Device(id=10, hostname="sw1", ip="10.0.0.2", poller_id=1, snmp_profile_id=1, extra={}))
        s.flush()
        s.add(Sensor(device_id=10, key=f"oid{oid_id}.1", kind="custom", name="Unicast in Gi1", status="ok"))
    t = c.post("/ui/oids/test", json={"device_id": 10, "oid": "SNMPv2-MIB::sysUpTime"}).json()
    assert "not connected" in t["error"]
    c.post(f"/oids/{oid_id}/delete")
    with app.state.lw.db.session() as s:
        assert s.get(CustomOid, oid_id) is None and not s.scalars(select(Sensor)).all()
    c.post(f"/mibs/{acme_id}/delete")
    assert c.get("/health?metric=custom").status_code == 200 and c.get("/health?metric=system").status_code == 200


def test_custom_alert_rule_on_custom_oid(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        s.add(Sensor(device_id=10, key="oid1", kind="custom", name="Sessions", value=5000, status="ok"))
        s.add(AlertRule(key="custom_x", name="Too many sessions", description="", severity="warn", polls=1, enabled=True,
                        entity="sensor", metric="value", op=">", threshold=1000,
                        scope={"sensor_kind": "custom", "sensor_name": "sessions"}))
    with db.session() as s:
        dev = s.get(Device, 10)
        dev.status = "up"
        Alerter(s).evaluate_device(dev)
        assert s.scalar(select(Alert.title).where(Alert.rule_key == "custom_x")) == "Too many sessions: sw1 Sessions"


def test_viewer_sees_but_cannot_change(logged_in, app):
    from .test_phase3 import make_viewer
    v = make_viewer(logged_in, app)
    assert v.get("/oids").status_code == 200
    r = v.post("/oids/new", data={"oid": "1.3.6.1.2.1.1.3.0", "name": "x"}, follow_redirects=False)
    assert r.status_code == 303
    with app.state.lw.db.session() as s:
        assert s.scalar(select(CustomOid)) is None
    assert json.loads(v.post("/ui/oids/test", json={}).text)["detail"] == "Your account is read-only"


def test_poller_answers_snmp_test(tmp_path, monkeypatch):
    from linkwatch.poller import main as pm
    p = pm.Poller("https://example.invalid", tmp_path)
    p.devices = [{"id": 10, "ip": "192.0.2.1", "snmp": {"version": "2c", "community": "c"}}]
    sent = []

    class Sess(FakeSnmp):
        def __init__(self, *a, **kw):
            super().__init__(TABLE)

    async def capture(msg, queue=True):
        sent.append(msg)
    monkeypatch.setattr(pm, "SnmpSession", Sess)
    monkeypatch.setattr(p, "send_or_queue", capture)
    asyncio.run(p.snmp_test({"req": "r1", "device_id": 10, "oid": "1.3.6.1.4.1.99999.1.3.1.3", "mode": "walk",
                             "label_oid": "1.3.6.1.4.1.99999.1.3.1.2"}))
    asyncio.run(p.snmp_test({"req": "r2", "device_id": 99, "oid": "1.3.6.1.2.1.1.3.0"}))
    assert sent[0] == {"type": "snmp_test_result", "req": "r1", "rows": [{"index": "1", "value": 1, "label": "to-hq"},
                                                                          {"index": "2", "value": 2, "label": "to-dc"}]}
    assert sent[1]["req"] == "r2" and "no SNMP credentials" in sent[1]["error"]
    assert "custom_oids" in p.features()
