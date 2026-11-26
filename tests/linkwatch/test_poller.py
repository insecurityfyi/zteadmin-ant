import asyncio

from linkwatch.poller.main import Poller, new_batch_id
from linkwatch.poller.ping import parse
from linkwatch.poller.spool import Spool


def test_ping_parse():
    out = "3 packets transmitted, 3 received, 0% packet loss, time 402ms\nrtt min/avg/max/mdev = 0.031/0.045/0.061/0.012 ms"
    assert parse(out) == {"loss_pct": 0.0, "rtt_ms": 0.045}
    assert parse("3 packets transmitted, 0 received, 100% packet loss") == {"loss_pct": 100.0, "rtt_ms": None}


def test_spool_roundtrip_and_trim(tmp_path):
    sp = Spool(tmp_path, max_batches=3)
    ids = [new_batch_id() for _ in range(5)]
    for i in ids:
        sp.put({"batch_id": i, "items": []})
    assert [b["batch_id"] for b in sp.pending()] == ids[2:]     # oldest dropped, order kept
    sp.ack(ids[3])
    assert len(sp) == 2


def test_cycle_spools_when_offline(tmp_path, monkeypatch):
    p = Poller("https://example.invalid", tmp_path)
    p.devices = [{"id": 1, "ip": "192.0.2.1", "ping": False, "snmp": None}]

    async def fake_poll(dev):
        return {"kind": "device", "device_id": dev["id"], "ok": True}
    monkeypatch.setattr(p, "poll_one", fake_poll)
    asyncio.run(p.cycle())
    pending = p.spool.pending()
    assert len(pending) == 1 and pending[0]["items"][0]["device_id"] == 1


def test_handle_config_and_ack(tmp_path):
    p = Poller("https://example.invalid", tmp_path)

    async def go():
        await p.handle({"type": "config", "interval": 30, "devices": [{"id": 4}], "integrations": []})
        assert p.interval == 60 and p.devices == [{"id": 4}] and p.configured.is_set()
        p.spool.put({"batch_id": "x1", "items": []})
        await p.handle({"type": "ack", "batch_id": "x1"})
        assert len(p.spool) == 0
    asyncio.run(go())


def test_expand_targets_and_guess_type():
    import pytest
    from linkwatch.common.discovery import TargetError, expand_targets, guess_type
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("10.0.0.5-7\n10.0.0.6, 10.0.1.1") == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.1.1"]
    assert len(expand_targets("10.0.0.0/20")) == 4094
    for bad in ["10.0.0.0/16", "nope", "10.0.0.9-3", ""]:
        with pytest.raises(TargetError):
            expand_targets(bad)
    assert guess_type("Cisco IOS Software, C2960X Software") == "Switch"
    assert guess_type("Linux pve 6.8.12-4-pve") == "Hypervisor"
    assert guess_type(None, "1.3.6.1.4.1.25461.2.3.38") == "Firewall"


def test_scan_reports_ping_or_snmp_hosts():
    from linkwatch.poller.discover import scan

    async def pinger(ip, count=1, timeout_s=1):
        return {"loss_pct": 0.0, "rtt_ms": 0.5} if ip.endswith((".1", ".2")) else {"loss_pct": 100.0, "rtt_ms": None}

    async def prober(ip, profiles, engine):
        return {"profile_id": 7, "sys_name": "sw-" + ip} if ip.endswith((".2", ".3")) else None
    ticks = []

    async def progress(done, total):
        ticks.append((done, total))
    found = asyncio.run(scan([f"10.0.0.{i}" for i in range(1, 7)], [{"id": 7, "creds": {}}], engine=object(),
                             pinger=pinger, prober=prober, progress=progress))
    assert found == [{"ip": "10.0.0.1", "rtt_ms": 0.5}, {"ip": "10.0.0.2", "rtt_ms": 0.5, "profile_id": 7, "sys_name": "sw-10.0.0.2"},
                     {"ip": "10.0.0.3", "rtt_ms": None, "profile_id": 7, "sys_name": "sw-10.0.0.3"}]


def test_discover_message_queues_result_when_offline(tmp_path, monkeypatch):
    import linkwatch.poller.main as pm
    p = Poller("https://example.invalid", tmp_path)

    async def fake_scan(hosts, profiles, engine=None, progress=None, **kw):
        return [{"ip": hosts[0], "rtt_ms": 1.0}]
    monkeypatch.setattr(pm, "scan", fake_scan)

    async def go():
        await p.handle({"type": "discover", "job_id": 5, "targets": "192.0.2.0/30", "profiles": []})
        await asyncio.sleep(0.05)
        await p.handle({"type": "discover", "job_id": 6, "targets": "bad target", "profiles": []})
        await asyncio.sleep(0.05)
    asyncio.run(go())
    assert p.outbox[0] == {"type": "discovery_result", "job_id": 5, "scanned": 2, "total": 2, "found": [{"ip": "192.0.2.1", "rtt_ms": 1.0}]}
    assert p.outbox[1]["job_id"] == 6 and "not an IPv4" in p.outbox[1]["error"]
