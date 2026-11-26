"""Path probes: mtr parsing on the poller, ingest, AS lookup cache, route-change detection, alerts and the pages."""
import json
import time

import pytest
from sqlalchemy import select

from linkwatch.poller import mtr
from linkwatch.server import paths
from linkwatch.server.db import Database
from linkwatch.server.ingest import ingest_batch
from linkwatch.server.models import Alert, AsnInfo, Event, PathProbe, PathResult, Poller

MTR_JSON = json.dumps({"report": {"mtr": {"dst": "1.1.1.1", "tests": 10}, "hubs": [
    {"count": 1, "host": "192.168.1.1", "Loss%": 0.0, "Snt": 10, "Last": 0.5, "Avg": 0.6, "Best": 0.4, "Wrst": 1.0, "StDev": 0.1, "Javg": 0.1},
    {"count": 2, "host": "???", "Loss%": 100.0, "Snt": 10, "Last": 0.0, "Avg": 0.0, "Best": 0.0, "Wrst": 0.0, "StDev": 0.0},
    {"count": 3, "host": "62.115.44.9", "Loss%": 30.0, "Snt": 10, "Last": 9.1, "Avg": 9.5, "Best": 8.8, "Wrst": 12.0, "StDev": 0.9, "Javg": 0.7},
    {"count": 4, "host": "1.1.1.1", "Loss%": 0.0, "Snt": 10, "Last": 10.2, "Avg": 10.4, "Best": 9.9, "Wrst": 11.0, "StDev": 0.3, "Javg": 0.4},
]}})


def test_mtr_command_and_parse():
    cmd = mtr.command("example.com", "tcp", 8443, 5)
    assert "--tcp" in cmd and cmd[cmd.index("-P") + 1] == "8443" and cmd[-1] == "example.com" and "--json" in cmd
    assert "--udp" in mtr.command("8.8.8.8", "udp", None, 5)
    with pytest.raises(ValueError):
        mtr.command("-x; rm -rf /")
    hops = mtr.parse(MTR_JSON)
    assert [h["ip"] for h in hops] == ["192.168.1.1", None, "62.115.44.9", "1.1.1.1"]
    assert hops[1]["loss"] == 100 and hops[1]["avg"] is None
    assert hops[3] == {"n": 4, "ip": "1.1.1.1", "loss": 0.0, "sent": 10, "last": 10.2, "avg": 10.4, "best": 9.9, "worst": 11.0,
                       "stdev": 0.3, "jitter": 0.4}


def test_poller_probe_schedule(tmp_path):
    from linkwatch.poller.main import Poller as P
    p = P("http://x", tmp_path)
    p.set_probes([{"id": 1, "target": "1.1.1.1", "protocol": "icmp", "count": 5, "interval": 300}])
    assert 1 in p.probe_due
    due = p.probe_due[1]
    p.set_probes([{"id": 1, "target": "1.1.1.1", "protocol": "icmp", "count": 5, "interval": 300}])
    assert p.probe_due[1] == due                      # unchanged config keeps its schedule
    p.set_probes([])
    assert p.probe_due == {}


def make_db(tmp_path, monkeypatch, lookups=None):
    db = Database(f"sqlite:///{tmp_path}/t.db")
    db.init()
    with db.session() as s:
        s.add(Poller(id=1, name="hq", key_hash="x"))
        s.add(Poller(id=2, name="branch", key_hash="y"))
        s.add(PathProbe(id=5, name="Cloudflare", target="1.1.1.1", protocol="icmp", count=10, interval_s=300, poller_ids=[1]))
    asns = lookups if lookups is not None else {"62.115.44.9": (64500, "TRANSIT-NET - Transit Example Ltd, GB"),
                                                "4.69.0.7": (64511, "OTHER - Other Carrier Inc, US"),
                                                "1.1.1.1": (13335, "CLOUDFLARENET - Cloudflare, Inc., US")}
    calls = []

    def fake(ip, timeout=4.0):
        calls.append(ip)
        asn, holder = asns.get(ip, (None, None))
        return {"asn": asn, "holder": holder, "prefix": "1.1.1.0/24" if asn == 13335 else None}
    monkeypatch.setattr(paths, "fetch_asn", fake)
    monkeypatch.setattr(paths, "_backoff_until", 0.0)
    return db, calls


def item(ts, hops=None, ok=True, probe_id=5):
    return {"kind": "probe", "probe_id": probe_id, "ts": ts, "ok": ok, "error": None if ok else "mtr exploded",
            "hops": mtr.parse(MTR_JSON) if hops is None else hops}


def batch(*items):
    return {"type": "results", "batch_id": f"{time.time_ns()}", "partial": True, "items": list(items)}


def test_ingest_stores_result_and_caches_asns(tmp_path, monkeypatch):
    db, calls = make_db(tmp_path, monkeypatch)
    with db.session() as s:
        ingest_batch(s, 1, batch(item(1_700_000_000.0)))
        ingest_batch(s, 2, batch(item(1_700_000_000.0)))       # poller 2 isn't assigned: ignored
    with db.session() as s:
        rows = s.scalars(select(PathResult)).all()
        assert len(rows) == 1
        r = rows[0]
        assert r.reached and r.loss_pct == 0 and r.avg_ms == 10.4 and r.jitter_ms == 0.4 and r.hop_count == 4
        assert r.asns == ["Private network", "AS64500", "AS13335"]
        assert sorted(calls) == ["1.1.1.1", "62.115.44.9"]     # private and silent hops are never looked up
        assert s.get(AsnInfo, "1.1.1.1").holder.startswith("CLOUDFLARENET")
    with db.session() as s:
        ingest_batch(s, 1, batch(item(1_700_000_300.0)))
    assert len(calls) == 2                                     # cached


def test_route_and_network_changes(tmp_path, monkeypatch):
    db, _ = make_db(tmp_path, monkeypatch)
    hops = mtr.parse(MTR_JSON)
    t = 1_700_000_000.0
    with db.session() as s:
        ingest_batch(s, 1, batch(item(t)))
        moved = [dict(h) for h in hops]
        moved[0]["ip"] = "192.168.1.254"                       # same networks, different router
        ingest_batch(s, 1, batch(item(t + 300, moved)))
        other = [dict(h) for h in hops]
        other[2]["ip"] = "4.69.0.7"                        # a different transit provider
        al = ingest_batch(s, 1, batch(item(t + 600, other)))
        assert [e.title for e in al.events if e.kind == "opened"] == ["Path changed networks: Cloudflare from hq"]
    with db.session() as s:
        assert [r.changed for r in s.scalars(select(PathResult).order_by(PathResult.ts))] == [None, "route", "asn"]
        ev = s.scalar(select(Event).where(Event.kind == "path"))
        assert "AS64511" in ev.message and "was Private network > AS64500 > AS13335" in ev.message
        for i in range(1, 4):                                  # the path holds steady for 3 runs: alert clears
            al = ingest_batch(s, 1, batch(item(t + 600 + i * 300, other)))
        assert [e.kind for e in al.events] == ["resolved"]


def test_loss_and_latency_alerts(tmp_path, monkeypatch):
    db, _ = make_db(tmp_path, monkeypatch)
    lossy = mtr.parse(MTR_JSON)
    lossy[-1] = dict(lossy[-1], loss=40.0)
    t = 1_700_000_000.0
    with db.session() as s:
        al = ingest_batch(s, 1, batch(item(t, lossy)))
        assert not al.events                                   # needs 2 runs in a row
        al = ingest_batch(s, 1, batch(item(t + 300, lossy)))
        assert [e.title for e in al.events] == ["Path loss: Cloudflare from hq"]
        probe = s.get(PathProbe, 5)
        probe.latency_ms = 5                                   # per-probe threshold beats the rule's 150 ms
    with db.session() as s:
        for i in range(2, 5):
            al = ingest_batch(s, 1, batch(item(t + i * 300)))
        titles = {a.title: a.state for a in s.scalars(select(Alert))}
        assert titles == {"Path loss: Cloudflare from hq": "resolved", "Path latency: Cloudflare from hq": "open"}
        al = ingest_batch(s, 1, batch(item(t + 5 * 300, ok=False, hops=[])))   # a failed run doesn't count as loss
        assert s.scalars(select(PathResult).where(PathResult.ok.is_(False))).one().error == "mtr exploded"


def test_offline_lookups_back_off(tmp_path, monkeypatch):
    import httpx
    db, _ = make_db(tmp_path, monkeypatch)
    n = []

    def boom(ip, timeout=4.0):
        n.append(ip)
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(paths, "fetch_asn", boom)
    with db.session() as s:
        ingest_batch(s, 1, batch(item(1_700_000_000.0)))
        r = s.scalar(select(PathResult))
        assert r.asns is None and len(n) == 1                  # stops after the first failure


def test_diagram_bands_and_health(tmp_path, monkeypatch):
    db, _ = make_db(tmp_path, monkeypatch)
    hops = mtr.parse(MTR_JSON)
    with db.session() as s:
        cache = paths.lookup(s, [h["ip"] for h in hops if h["ip"]])
        d = paths.diagram(hops, cache, "hq", "1.1.1.1")
    assert [n["health"] for n in d["nodes"]] == ["ok", "ok", "none", "limited", "ok"]
    assert [(b["title"], b["name"]) for b in d["bands"]] == [("Private network", ""), ("AS64500", "Transit Example Ltd"),
                                                             ("AS13335", "Cloudflare, Inc.")]
    assert paths.provider("CLOUDFLARENET - Cloudflare, Inc., US") == "Cloudflare, Inc."


def test_probe_pages_config_and_metrics(logged_in, app, monkeypatch):
    monkeypatch.setattr(paths, "fetch_asn", lambda ip, timeout=4.0: {"asn": 13335, "holder": "CLOUDFLARENET - Cloudflare, Inc., US",
                                                                      "prefix": "1.1.1.0/24"})
    lw = app.state.lw
    with lw.db.session() as s:
        s.add(Poller(id=1, name="hq", key_hash="x", features=["mtr"]))
        s.add(Poller(id=2, name="old", key_hash="y", features=[], last_seen=paths.utcnow()))
    r = logged_in.get("/probes")
    assert r.status_code == 200 and "No path probes yet" in r.text
    r = logged_in.post("/probes/new", data={"name": "M365", "target": "bad target!", "protocol": "tcp", "poller_id": "1"})
    assert r.status_code == 400 and "host name or IP" in r.text and "Port is required" in r.text
    r = logged_in.post("/probes/new", data={"name": "M365", "target": "outlook.office365.com", "protocol": "tcp", "port": "443",
                                            "count": "10", "interval_s": "300", "poller_id": ["1", "2"], "enabled": "on",
                                            "latency_ms": "80"}, follow_redirects=False)
    assert r.status_code == 303
    pid = int(r.headers["location"].rsplit("/", 1)[1])
    cfg = lw.hub.build_config(1)
    assert cfg["probes"] == [{"id": pid, "target": "outlook.office365.com", "protocol": "tcp", "port": 443, "count": 10,
                              "interval": 300}]
    with lw.db.session() as s:
        ingest_batch(s, 1, batch(item(time.time() - 60, probe_id=pid)))
    r = logged_in.get(f"/probes/{pid}")
    assert r.status_code == 200
    assert "AS13335" in r.text and "Cloudflare, Inc." in r.text and 'class="pathsvg"' in r.text
    assert "rate-limited" in r.text and "old is running an older poller image" in r.text
    r = logged_in.get("/probes")
    assert "M365" in r.text and "outlook.office365.com" in r.text
    data = logged_in.get(f"/ui/metrics/probe/{pid}/1?range=6h").json()
    assert data["avg"] == [10.4] and data["loss"] == [0.0]
    r = logged_in.post(f"/probes/{pid}/edit", data={"name": "M365", "target": "outlook.office365.com", "protocol": "icmp",
                                                    "count": "10", "interval_s": "300", "poller_id": "2"}, follow_redirects=False)
    assert r.status_code == 303
    assert lw.hub.build_config(1)["probes"] == [] and lw.hub.build_config(2)["probes"] == []   # disabled (no "enabled")
    assert logged_in.post(f"/probes/{pid}/delete", follow_redirects=False).status_code == 303
    with lw.db.session() as s:
        assert s.scalar(select(PathResult)) is None


def test_hello_records_features(app):
    with app.state.lw.db.session() as s:
        s.add(Poller(id=3, name="p3", key_hash="z"))
    app.state.lw.hub._set_features(3, ["mtr"])
    with app.state.lw.db.session() as s:
        assert s.get(Poller, 3).features == ["mtr"]
