import time

from sqlalchemy import select

from linkwatch.server.alerts import Alerter
from linkwatch.server.db import Database
from linkwatch.server.ingest import counter_delta, ingest_batch, ingest_integration
from linkwatch.server.models import Alert, Device, DeviceMetric, Integration, Poller, PortMetric, SnmpProfile


def make_db(tmp_path):
    db = Database(f"sqlite:///{tmp_path}/t.db")
    db.init()
    with db.session() as s:
        s.add(Poller(id=1, name="p1", key_hash="x"))
        s.add(SnmpProfile(id=1, name="v2", version="2c", config_enc="-"))
        s.add(Device(id=10, hostname="sw1", ip="10.0.0.2", poller_id=1, snmp_profile_id=1, extra={}))
        s.add(Device(id=11, hostname="pve-01", ip="10.10.5.11", poller_id=1, snmp_profile_id=1, extra={}, sys_descr="Linux pve-01 6.8"))
    return db


def snmp_item(ts, in_oct, out_oct, ok=True, cpu=20.0, errors=0, ping=None):
    return {"kind": "device", "device_id": 10, "ts": ts, "ok": ok, "error": None if ok else "SNMP: timeout",
            "system": {"sys_name": "sw1", "uptime_s": 100}, "cpu": cpu, "mem": 40.0, "poll_ms": 300,
            "ping": ping if ping is not None else {"rtt_ms": 1.0, "loss_pct": 0.0},
            "ports": [{"ifindex": 1, "name": "Gi1", "speed_mbps": 1000, "admin": "up", "oper": "up", "in_octets": in_oct,
                       "out_octets": out_oct, "counter_bits": 64, "in_errors": errors, "out_errors": 0}]}


def batch(*items, bid=None):
    return {"type": "results", "batch_id": bid or f"{time.time_ns()}", "items": list(items)}


def test_counter_delta():
    assert counter_delta(150, 100) == 50
    assert counter_delta(10, 2**32 - 10, bits=32) == 20       # 32-bit wrap
    assert counter_delta(10, 500, bits=64) is None              # reset
    assert counter_delta(None, 5) is None


def test_rates_metrics_and_duplicates(tmp_path):
    db = make_db(tmp_path)
    t0 = 1_700_000_000.0
    with db.session() as s:
        assert ingest_batch(s, 1, batch(snmp_item(t0, 0, 0), bid="b1"))
    with db.session() as s:
        ingest_batch(s, 1, batch(snmp_item(t0 + 300, 375_000_000, 37_500_000), bid="b2"))
        assert ingest_batch(s, 1, batch(snmp_item(t0 + 300, 1, 1), bid="b2")) is None   # resent batch ignored
    with db.session() as s:
        d = s.get(Device, 10)
        p = d.ports[0]
        assert d.status == "up" and d.sys_name == "sw1"
        assert p.in_bps == 10_000_000 and p.out_bps == 1_000_000 and p.util_pct == 1.0
        assert s.scalar(select(PortMetric).where(PortMetric.port_id == p.id)) is not None
        assert len(s.scalars(select(DeviceMetric).where(DeviceMetric.device_id == 10)).all()) == 2


def test_down_after_two_failed_polls_and_alert_resolves(tmp_path):
    db = make_db(tmp_path)
    t = 1_700_000_000.0
    dead = {"rtt_ms": None, "loss_pct": 100.0}
    with db.session() as s:
        ingest_batch(s, 1, batch(snmp_item(t, 0, 0)))
    with db.session() as s:
        ingest_batch(s, 1, batch(snmp_item(t + 300, 0, 0, ok=False, ping=dead)))
        assert s.get(Device, 10).status == "up"                # one miss is not an outage
    with db.session() as s:
        al = ingest_batch(s, 1, batch(snmp_item(t + 600, 0, 0, ok=False, ping=dead)))
        assert s.get(Device, 10).status == "down"
        assert [e.kind for e in al.events] == ["opened"]
    with db.session() as s:
        al = ingest_batch(s, 1, batch(snmp_item(t + 900, 0, 0)))
        assert [e.kind for e in al.events] == ["resolved"]
        assert s.scalar(select(Alert)).state == "resolved"


def test_snmp_failing_but_ping_ok_is_warning(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        ingest_batch(s, 1, batch(snmp_item(1_700_000_000.0, 0, 0, ok=False)))
        d = s.get(Device, 10)
        assert d.status == "warn" and "SNMP" in d.status_reason


def test_high_cpu_needs_consecutive_polls(tmp_path):
    db = make_db(tmp_path)
    t = 1_700_000_000.0
    for i in range(3):
        with db.session() as s:
            al = ingest_batch(s, 1, batch(snmp_item(t + i * 300, 0, 0, cpu=97.0)))
    assert [e.title for e in al.events] == ["High cpu: sw1"]


def test_results_for_another_pollers_device_are_ignored(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        ingest_batch(s, 2, batch(snmp_item(1_700_000_000.0, 0, 0)))
        assert s.get(Device, 10).last_polled is None


def test_integration_records_create_and_merge(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        integ = Integration(id=5, kind="proxmox", name="Proxmox", config_enc="-", poller_id=1)
        s.add(integ)
        s.flush()
        item = {"ok": True, "ts": 1_700_000_000.0, "records": [
            {"external_id": "node-pve-01", "hostname": "pve-01", "ip": "10.10.5.11", "type": "Hypervisor",
             "platform": "Proxmox VE", "status": "up", "cpu": 42.0, "mem": 25.0, "detail": "16 vCPU", "extra": {"maxcpu": 16}},
            {"external_id": "qemu-101", "hostname": "web", "type": "VM", "status": "down", "detail": "On node pve-01"}]}
        ingest_integration(s, Alerter(s), integ, item)
    with db.session() as s:
        merged = s.get(Device, 11)
        assert merged.integration_id == 5 and merged.extra["api"]["maxcpu"] == 16
        assert merged.platform == "Proxmox VE" and merged.source == "snmp"
        vm = s.scalar(select(Device).where(Device.external_id == "qemu-101"))
        assert vm.source == "proxmox" and vm.status == "down"
        assert s.scalar(select(Alert).where(Alert.device_id == vm.id)).rule_key == "device_down"
        assert s.get(Integration, 5).object_count == 2


def test_integration_failure_opens_alert(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        integ = Integration(id=6, kind="meraki", name="Meraki", config_enc="-")
        s.add(integ)
        s.flush()
        al = Alerter(s)
        ingest_integration(s, al, integ, {"ok": False, "error": "rejected the credentials"})
        assert integ.status == "error" and al.events[0].title == "Integration failing: Meraki"


def test_unifi_data_ports_and_series(tmp_path):
    import respx
    from linkwatch.integrations import build
    from linkwatch.server.models import IntegrationMetric, Port
    from tests.linkwatch.test_integrations import mock_unifi

    with respx.mock:
        mock_unifi()
        client = build("unifi", {"host": "192.168.1.1", "api_key": "k"})
        records = client.collect()
    db = make_db(tmp_path)
    with db.session() as s:
        s.add(Integration(id=5, kind="unifi", name="UniFi", config_enc="-", poller_id=1))
    t0 = time.time() - 600
    for i, ts in enumerate((t0, t0 + 300)):
        recs = [dict(r, ports=[dict(p, in_octets=(p["in_octets"] or 0) + i * 37_500, out_octets=p["out_octets"]) for p in r.get("ports", [])])
                for r in records]
        with db.session() as s:
            ingest_batch(s, 1, batch({"kind": "integration", "integration_id": 5, "ts": ts, "ok": True, "records": recs,
                                      "data": client.data}))
    with db.session() as s:
        integ = s.get(Integration, 5)
        assert integ.data["summary"]["clients"] == 3 and integ.data["ts"].endswith("Z")
        assert integ.data["clients"][0]["series"] == "client:cc:00:00:00:00:01"
        ap = s.scalar(select(Device).where(Device.external_id == "aa:aa:aa:00:00:01"))
        port = s.scalar(select(Port).where(Port.device_id == ap.id))
        assert port.speed_mbps == 2500 and round(port.in_bps) == 1000          # 37,500 bytes in 300 s
        keys = {m.key for m in s.scalars(select(IntegrationMetric))}
        assert {"clients", "wan:total", "wan:udm/WAN1", "ssid:Office", "ssid:IoT", "ap:aa:aa:aa:00:00:01",
                "client:cc:00:00:00:00:03"} <= keys
        office = s.scalars(select(IntegrationMetric).where(IntegrationMetric.key == "ssid:Office")).all()
        assert len(office) == 2 and office[0].a == 4_000_000 and office[0].c == 1


def test_unifi_rollup(tmp_path):
    from datetime import timedelta
    from types import SimpleNamespace
    from linkwatch.server.jobs import rollup_and_prune
    from linkwatch.server.models import IntegrationMetric, utcnow
    db = make_db(tmp_path)
    hour = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    with db.session() as s:
        s.add(Integration(id=5, kind="unifi", name="UniFi", config_enc="-"))
        s.flush()
        for m, v in ((5, 10.0), (35, 30.0)):
            s.add(IntegrationMetric(integration_id=5, key="ssid:Office", ts=hour + timedelta(minutes=m), a=v, b=v, c=2))
    cfg = SimpleNamespace(raw_days=7, hourly_days=365)
    rollup_and_prune(SimpleNamespace(config=cfg, db=db))
    with db.session() as s:
        hourly = s.scalars(select(IntegrationMetric).where(IntegrationMetric.hourly.is_(True))).all()
        assert [(h.key, h.a, h.c) for h in hourly] == [("ssid:Office", 20.0, 2)]
