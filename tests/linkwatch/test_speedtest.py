"""Scheduled speed tests: librespeed-cli on the poller, scheduling and data caps, ingest with ISP labels, pages, widget."""
import asyncio
import json
import time

import pytest
from sqlalchemy import select

from linkwatch.poller import speedtest as pst
from linkwatch.server import isp as ispmod
from linkwatch.server import speedtest
from linkwatch.server.db import Database
from linkwatch.server.ingest import ingest_batch
from linkwatch.server.models import Event, Poller, SpeedTest, utcnow

LIBRESPEED_JSON = json.dumps([{
    "timestamp": "2026-11-28T03:00:00Z", "server": {"name": "Atlanta, United States (Example)", "url": "https://speed.example.net/backend"},
    "client": {"ip": "98.97.10.20", "hostname": "", "city": "", "region": "", "country": "US", "loc": "",
               "org": "AS14593 Space Exploration Technologies Corporation", "postal": "", "timezone": ""},
    "bytes_sent": 40_000_000, "bytes_received": 360_000_000, "ping": 41.2, "jitter": 6.3, "upload": 18.4, "download": 212.75,
    "share": ""}])


# ------------------------------------------------------------------ poller
def test_command_and_parse(monkeypatch):
    monkeypatch.setattr(pst.shutil, "which", lambda b: f"/usr/local/bin/{b}")
    cmd = pst.command({}, {"key": "default", "duration": 10})
    assert cmd[:2] == ["/usr/local/bin/librespeed-cli", "--json"] and "--no-icmp" in cmd and "--share" not in cmd
    assert cmd[cmd.index("--duration") + 1] == "10" and "--source" not in cmd
    cmd = pst.command({"server_ids": [42, "7"], "server_json": "https://speed.example.com/servers.json"},
                      {"source": "192.168.20.5", "duration": 99, "no_upload": True})
    assert cmd[cmd.index("--source") + 1] == "192.168.20.5" and "--ipv4" in cmd and cmd[cmd.index("--duration") + 1] == "30"
    assert cmd.count("--server") == 2 and "--no-upload" in cmd and "--server-json" in cmd
    with pytest.raises(ValueError):
        pst.command({}, {"source": "eth0; rm -rf /"})
    with pytest.raises(ValueError):
        pst.command({"server_json": "file:///etc/passwd"}, {})
    got = pst.parse(LIBRESPEED_JSON)
    assert got["download_mbps"] == 212.75 and got["upload_mbps"] == 18.4 and got["public_ip"] == "98.97.10.20"
    assert got["bytes_sent"] + got["bytes_received"] == 400_000_000 and got["server"]["url"].startswith("https://")


def test_run_uses_icmp_burst_for_latency(monkeypatch):
    monkeypatch.setattr(pst, "available", lambda: True)

    class Proc:
        returncode = 0

        async def communicate(self):
            return LIBRESPEED_JSON.encode(), b""

    async def fake_exec(*cmd, **kw):
        return Proc()

    async def fake_icmp(host, source, count=20):
        assert host == "speed.example.net"
        return {"loss_pct": 5.0, "rtt_ms": 38.0, "jitter_ms": 4.5}
    monkeypatch.setattr(pst.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(pst, "icmp", fake_icmp)
    item = asyncio.run(pst.run({}, {"key": "default"}, "manual"))
    assert item["ok"] and item["kind"] == "speedtest" and item["trigger"] == "manual"
    assert (item["ping_ms"], item["jitter_ms"], item["loss_pct"], item["latency_from"]) == (38.0, 4.5, 5.0, "icmp")

    async def no_icmp(host, source, count=20):
        return None
    monkeypatch.setattr(pst, "icmp", no_icmp)
    item = asyncio.run(pst.run({}, {"key": "default"}))
    assert (item["ping_ms"], item["jitter_ms"], item["loss_pct"], item["latency_from"]) == (41.2, 6.3, None, "http")


def test_schedule_and_caps():
    rnd = lambda a, b: b          # noqa: E731 - always the top of the range
    now = 1_000_000.0
    assert pst.next_due(None, 6, 20, now, rnd) == now + 900           # first run: within 15 minutes
    assert pst.next_due(now - 3600, 6, 20, now, rnd) == now - 3600 + 6 * 3600 + 1200
    assert pst.next_due(now - 10 * 3600, 6, 0, now, rnd) == now + 60  # overdue: soon, not now
    assert pst.runnable({"blocked": True, "blocked_reason": "cap"}, None) == "cap"
    assert pst.runnable({"budget_bytes": 100}, 500).startswith("Skipped")
    assert pst.runnable({"budget_bytes": 1000}, 500) is None and pst.runnable({}, None) is None


def test_poller_runs_lanes_in_turn_and_keeps_schedule(tmp_path, monkeypatch):
    from linkwatch.poller.main import Poller as P
    p = P("http://x", tmp_path)
    ran = []

    async def fake_run(cfg, lane, trigger="schedule"):
        ran.append((lane["key"], trigger))
        return {"kind": "speedtest", "ok": True, "download_mbps": 100.0, "upload_mbps": 10.0, "bytes_sent": 10, "bytes_received": 90,
                "lane": {"key": lane["key"]}, "trigger": trigger}
    monkeypatch.setattr(pst, "run", fake_run)
    cfg = {"enabled": True, "interval_h": 6, "jitter_min": 0, "lanes": [
        {"key": "default"}, {"key": "192.168.30.5", "source": "192.168.30.5", "blocked": True, "blocked_reason": "cap"}]}
    p.set_speedtest(cfg)
    assert p.st_due is not None and p.st_due - time.time() <= 900
    due = p.st_due
    p.set_speedtest(dict(cfg))
    assert p.st_due == due                                    # same schedule: not moved
    asyncio.run(p.run_speedtests("schedule"))
    assert ran == [("default", "schedule")]                   # the capped lane was skipped
    state = json.loads((tmp_path / "speedtest.json").read_text())
    assert state["last_bytes"] == {"default": 100} and abs(state["last_run"] - time.time()) < 5
    assert abs(p.st_due - (state["last_run"] + 6 * 3600)) < 61
    batches = p.spool.pending()
    assert len(batches) == 1 and batches[0]["items"][0]["kind"] == "speedtest"
    asyncio.run(p.run_speedtests("manual", {"192.168.30.5"}))  # Run now on a capped lane reports why
    item = p.spool.pending()[-1]["items"][0]
    assert item["skipped"] and item["error"] == "cap"
    p2 = P("http://x", tmp_path)                               # after a restart, the next run comes from the saved time
    p2.set_speedtest(cfg)
    assert p2.st_due > time.time() + 5 * 3600
    p.set_speedtest({"enabled": False})
    assert p.st_due is None
    assert "speedtest" in P("http://x", tmp_path).features() or not pst.available()


# ------------------------------------------------------------------ server
def make_db(tmp_path):
    db = Database(f"sqlite:///{tmp_path}/t.db")
    db.init()
    with db.session() as s:
        s.add(Poller(id=1, name="hq", key_hash="x", features=["speedtest"]))
    return db


def result(ts, ip="98.97.10.20", org="AS14593 Space Exploration Technologies Corporation", lane="default", down=200.0, used=400_000_000):
    return {"kind": "speedtest", "ts": ts, "ok": True, "trigger": "schedule", "lane": {"key": lane, "source": None},
            "download_mbps": down, "upload_mbps": 20.0, "ping_ms": 35.0, "jitter_ms": 4.0, "loss_pct": 0.0, "latency_from": "icmp",
            "public_ip": ip, "org": org, "server": {"name": "Atlanta", "url": "https://speed.example.net/"},
            "bytes_sent": used // 10, "bytes_received": used - used // 10}


def batch(*items):
    return {"type": "results", "batch_id": f"{time.time_ns()}", "partial": True, "items": list(items)}


def test_read_form():
    cfg, problems = speedtest.read_form({"enabled": "on", "interval_h": "4", "jitter_min": "30", "server_ids": "42, 7",
                                         "lane0_source": "", "lane0_duration": "10", "lane1_source": "192.168.30.5",
                                         "lane1_isp": "Starlink Satellite", "lane1_cap_gb": "50", "lane1_duration": "5",
                                         "lane1_no_upload": "on"})
    assert not problems
    assert cfg["enabled"] and cfg["interval_h"] == 4 and cfg["jitter_min"] == 30 and cfg["server_ids"] == [42, 7]
    assert cfg["lanes"] == [{"source": "", "isp": "", "duration": 10, "cap_gb": None, "no_upload": False},
                            {"source": "192.168.30.5", "isp": "Starlink Satellite", "duration": 5, "cap_gb": 50.0, "no_upload": True}]
    _, problems = speedtest.read_form({"interval_h": "5", "server_ids": "abc", "server_json": "ftp://x", "lane1_source": "eth0",
                                       "lane2_source": "", "lane2_isp": "Spectrum", "lane2_cap_gb": "-1"})
    assert len(problems) == 4      # bad server id, bad URL, bad source, duplicate default route (its cap isn't read)


def test_ingest_labels_by_isp_and_enforces_cap(tmp_path, monkeypatch):
    db = make_db(tmp_path)
    monkeypatch.setattr(speedtest, "map_isps", lambda s: {"24.0.0.9": "Spectrum Business"})
    with db.session() as s:
        s.get(Poller, 1).speedtest = {"enabled": True, "interval_h": 6, "lanes": [
            {"source": "", "isp": ""}, {"source": "192.168.30.5", "isp": "", "cap_gb": 0.5}]}
        ispmod.set_ranges(s, [{"cidr": "203.0.113.0/24", "isp": "Brightspeed Fiber"}])
    now = time.time()
    with db.session() as s:
        ingest_batch(s, 1, batch(result(now - 300, ip="203.0.113.8", org="AS1 Somebody"),          # range wins
                                 result(now - 200, ip="24.0.0.9", org="AS20115 Charter"),            # map
                                 result(now - 100, lane="192.168.30.5")))                            # server's org: Starlink
    with db.session() as s:
        rows = s.scalars(select(SpeedTest).order_by(SpeedTest.ts)).all()
        assert [(r.isp, r.isp_source) for r in rows] == [("Brightspeed Fiber", "range"), ("Spectrum Business", "map"),
                                                         ("Starlink", "speedtest")]
        assert rows[2].bytes_used == 400_000_000 and rows[2].lane == "192.168.30.5"
        cfg = speedtest.poller_config(s, s.get(Poller, 1))
        assert cfg["lanes"][1]["budget_bytes"] == 100_000_000 and not cfg["lanes"][1].get("blocked")
        ingest_batch(s, 1, batch(result(now - 50, lane="192.168.30.5")))
        cfg = speedtest.poller_config(s, s.get(Poller, 1))
        assert cfg["lanes"][1]["blocked"] and cfg["lanes"][1]["budget_bytes"] == 0 and not cfg["lanes"][0].get("blocked")
        assert any("paused until next month" in e.message for e in s.scalars(select(Event)))
        summary = speedtest.isp_summary(s)
        assert [g["isp"] for g in summary] == ["Brightspeed Fiber", "Spectrum Business", "Starlink"]
        assert summary[2]["n"] == 2 and summary[2]["key"] == "isp_starlink"
        data = speedtest.series(s, "download", "7d")
        assert set(data) == {"ts", "isp_brightspeed_fiber", "isp_spectrum_business", "isp_starlink"} and len(data["ts"]) == 4
        assert data["isp_starlink"] == [None, None, 200.0, 200.0]


def test_typed_isp_wins_and_failed_tests_are_kept(tmp_path):
    db = make_db(tmp_path)
    with db.session() as s:
        s.get(Poller, 1).speedtest = {"lanes": [{"source": "", "isp": "Brightspeed Fiber"}]}
        ingest_batch(s, 1, batch(result(time.time()), {"kind": "speedtest", "ts": time.time(), "ok": False,
                                                       "error": "no servers answered", "lane": {"key": "default"}}))
        rows = s.scalars(select(SpeedTest).order_by(SpeedTest.id)).all()
        assert rows[0].isp == "Brightspeed Fiber" and rows[0].isp_source == "manual"
        assert not rows[1].ok and rows[1].error == "no servers answered"


# ------------------------------------------------------------------ pages and widget
def test_pages_settings_run_now_and_widget(logged_in, app, monkeypatch):
    lw = app.state.lw
    monkeypatch.setattr(speedtest, "map_isps", lambda s: {})
    with lw.db.session() as s:
        s.add(Poller(id=1, name="hq", key_hash="x", features=["speedtest"]))
        s.add(Poller(id=2, name="old", key_hash="y", features=["mtr"], last_seen=utcnow()))
    r = logged_in.get("/speedtests")
    assert r.status_code == 200 and "No speed test results yet" in r.text and "can't run speed tests yet" in r.text
    assert lw.hub.build_config(1)["speedtest"]["enabled"] is False
    r = logged_in.post("/speedtests/1/settings", data={"enabled": "on", "interval_h": "6", "jitter_min": "20",
                                                       "lane0_source": "", "lane1_source": "192.168.30.5",
                                                       "lane1_isp": "Starlink Satellite", "lane1_cap_gb": "50"},
                       follow_redirects=False)
    assert r.status_code == 303
    cfg = lw.hub.build_config(1)["speedtest"]
    assert cfg["enabled"] and [ln["key"] for ln in cfg["lanes"]] == ["default", "192.168.30.5"]
    assert cfg["lanes"][1]["budget_bytes"] == 50_000_000_000
    logged_in.get("/speedtests")                                # shows (and clears) the "saved" message
    r = logged_in.post("/speedtests/1/settings", data={"lane0_source": "not-an-ip"}, follow_redirects=True)
    assert "source must be an IP address" in r.text
    r = logged_in.post("/speedtests/run", data={"next": "https://evil.example/"}, follow_redirects=False)
    assert r.headers["location"] == "/speedtests"
    logged_in.get("/speedtests")
    r = logged_in.post("/speedtests/run", data={}, follow_redirects=True)
    assert "hq is not connected right now" in r.text and "old can&#39;t run speed tests yet" in r.text
    sent = []
    monkeypatch.setattr(lw.hub, "send_soon", lambda pid, msg: sent.append((pid, msg)) or True)
    r = logged_in.post("/speedtests/run", data={"poller_id": "1", "lane": "192.168.30.5", "next": "/"}, follow_redirects=False)
    assert r.headers["location"] == "/" and sent == [(1, {"type": "speedtest_now", "lane": "192.168.30.5"})]

    with lw.db.session() as s:
        ingest_batch(s, 1, batch(result(time.time() - 3600, lane="192.168.30.5"), result(time.time() - 60, ip="203.0.113.8",
                                                                                          org="AS1234 Brightspeed")))
    r = logged_in.get("/speedtests")
    assert r.status_code == 200 and "Starlink Satellite" in r.text and "Brightspeed" in r.text
    assert "of 50.0 GB" in r.text and "~400 MB a test" in r.text
    data = logged_in.get("/ui/metrics/speedtest?metric=upload&range=30d").json()
    assert data["isp_starlink_satellite"] == [20.0, None] and data["isp_brightspeed"] == [None, 20.0]

    layout = [{"type": "speedtest", "w": 6, "opts": {"metric": "latency"}}]
    assert logged_in.post("/account/dashboard", json={"layout": layout}).json()["widgets"] == 1
    r = logged_in.get("/")
    assert r.status_code == 200 and "Speed tests by ISP" in r.text and "Starlink Satellite" in r.text
    assert "/ui/metrics/speedtest?metric=latency" in r.text and "This widget couldn" not in r.text
    r = logged_in.get("/?edit=1")
    assert r.status_code == 200 and 'name="poller_id"' in r.text
