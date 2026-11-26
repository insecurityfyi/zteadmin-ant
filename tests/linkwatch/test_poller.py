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
