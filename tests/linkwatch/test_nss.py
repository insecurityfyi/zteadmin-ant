"""Zscaler Cloud NSS ingest: auth, parsing, the size cap with oldest-first roll-off, and the activity pages."""
import gzip
import json
import time

import pytest

from linkwatch.server import nss


def web(user="alice@corp.example", app="ChatGPT", action="Allowed", ts=None, **kw):
    ev = {"datetime": "2026-11-28 01:00:00", "epochtime": str(ts or int(time.time())), "user": user, "department": "Sales",
          "location": "HQ", "appname": app, "urlcategory": "Generative AI", "hostname": "chat.openai.com",
          "url": "chat.openai.com/c/1", "action": action, "transactionsize": "1500", "ClientIP": "10.0.0.5",
          "serverip": "104.18.1.1", "threatname": "None", **kw}
    return {"sourcetype": "zscalernss-web", "event": ev}


FW = {"sourcetype": "zscalernss-fw", "event": {"epochtime": "0", "datetime": "Fri Nov 27 10:00:00 2020", "user": "bob",
      "csip": "10.0.0.9", "cdip": "8.8.8.8", "cdport": "443", "nwapp": "dns-over-https", "action": "Drop",
      "inbytes": "100", "outbytes": "50"}}
DNS = {"sourcetype": "zscalernss-dns", "event": {"user": "carol", "dns_req": "bad.example", "reqaction": "REQ_BLOCK",
       "resaction": "None", "category": "Malicious Sites"}}


def test_parse_shapes():
    one = json.dumps(web())
    assert len(nss.parse_records(one.encode())) == 1
    assert len(nss.parse_records(("\n".join([one, one, one]) + "\n").encode())) == 3
    assert len(nss.parse_records((one + one).encode())) == 2
    assert len(nss.parse_records(json.dumps([web(), web()]).encode())) == 2
    assert nss.parse_records(b"  ") == []
    rec = nss.parse_records(one.encode())[0]
    assert rec["sourcetype"] == "zscalernss-web" and rec["user"] == "alice@corp.example"
    with pytest.raises(ValueError):
        nss.parse_records(b'{"a": 1} not json')


def test_normalize_feeds():
    w = nss.normalize(nss.parse_records(json.dumps(web(action="Blocked", threatname="EICAR")).encode())[0])
    assert (w["feed"], w["blocked"], w["threat"], w["host"], w["bytes"], w["app"]) == ("web", 1, "EICAR", "chat.openai.com", 1500, "ChatGPT")
    f = nss.normalize(nss.parse_records(json.dumps(FW).encode())[0])
    assert (f["feed"], f["blocked"], f["host"], f["bytes"], f["app"], f["user"]) == ("fw", 1, "8.8.8.8:443", 150, "dns-over-https", "bob")
    assert f["ts"] == 1606471200     # epochtime "0" ignored, datetime string used
    d = nss.normalize(nss.parse_records(json.dumps(DNS).encode())[0])
    assert (d["feed"], d["blocked"], d["host"], d["action"]) == ("dns", 1, "bad.example", "REQ_BLOCK")
    # raw NSS variable names, no sourcetype
    raw = nss.normalize({"login": "dave", "eurl": "https://x.example/a", "urlcat": "News", "action": "Allowed"})
    assert (raw["feed"], raw["user"], raw["host"], raw["blocked"]) == ("web", "dave", "x.example", 0)


def test_size_cap_rolls_off_oldest(tmp_path):
    cap = 600 * 1024
    store = nss.NssStore(tmp_path / "nss", max_bytes=cap, min_free=0)
    pad = "x" * 600
    first_ts = None
    for batch in range(60):
        body = "\n".join(json.dumps(web(user=f"u{batch}-{i}", ts=1_790_000_000 + batch * 60 + i, ua=pad + str(batch * 1000 + i)))
                         for i in range(40))
        store.ingest(body.encode())
        if first_ts is None:
            first_ts = store.oldest_ts()
        assert store.used_bytes() <= cap, f"batch {batch}: {store.used_bytes()} > {cap}"
    assert store.stats.pruned_segments > 0
    assert store.oldest_ts() > first_ts                 # the oldest data went first
    assert store.newest_ts() == 1_790_000_000 + 59 * 60 + 39
    names = [s.name for s in store.segments]
    assert names == sorted(names) and len(names) >= 2
    # a fresh store on the same folder picks the segments up again
    again = nss.NssStore(tmp_path / "nss", max_bytes=cap, min_free=0)
    assert again.oldest_ts() == store.oldest_ts() and len(again.segments) == len(store.segments)


def test_summary_and_events(tmp_path):
    store = nss.NssStore(tmp_path / "nss", min_free=0)
    now = int(time.time())
    recs = [web(ts=now - 10), web(ts=now - 20), web(user="bob", app="Dropbox", action="Blocked", ts=now - 30),
            web(ts=now - 40 * 86400)]
    store.ingest("\n".join(json.dumps(r) for r in recs).encode())
    s = store.summary(now - 86400)
    assert s["events"] == 3 and s["blocked"] == 1 and s["users"] == 2
    assert s["top_users"][0][0] == "alice@corp.example" and s["top_users"][0][1] == 2
    assert s["top_blocked_apps"][0][0] == "Dropbox"
    assert store.summary(None)["events"] == 4
    ev = store.events(user="bob")
    assert len(ev) == 1 and ev[0]["blocked"] == 1
    assert [e["ts"] for e in store.events(limit=2)] == [now - 10, now - 20]
    assert len(store.events(q="dropbox")) == 1
    full = store.event(ev[0]["seg"], ev[0]["id"])
    assert full["raw"]["appname"] == "Dropbox"
    assert store.event("../etc/passwd", 1) is None


def _token(logged_in):
    r = logged_in.post("/admin/nss/tokens", data={"name": "ZIA web"})
    assert r.status_code == 200
    tok = r.text.split('<div class="secret">Bearer ', 1)[1].split("<", 1)[0]
    assert tok.startswith("vcnss_")
    return tok


def test_ingest_endpoint_and_pages(logged_in, app):
    assert logged_in.post("/api/nss/ingest", content=json.dumps(web())).status_code == 401
    assert logged_in.post("/api/nss/ingest", content=json.dumps(web()), headers={"Authorization": "Bearer nope"}).status_code == 401
    tok = _token(logged_in)
    h = {"Authorization": f"Bearer {tok}"}
    body = "\n".join(json.dumps(r) for r in (web(), web(user="bob", action="Blocked")))
    r = logged_in.post("/api/nss/ingest", content=body, headers=h)
    assert r.status_code == 200 and r.json() == {"ok": True, "accepted": 2}
    r = logged_in.post("/api/nss/ingest/fw", content=gzip.compress(json.dumps([FW, FW]).encode()),
                       headers={**h, "Content-Encoding": "gzip"})
    assert r.json()["accepted"] == 2
    assert logged_in.post("/api/nss/ingest", content=b"", headers=h).json()["accepted"] == 0   # Validate with an empty body
    assert logged_in.post("/api/nss/ingest", content=b"{oops", headers=h).status_code == 400
    assert logged_in.post("/api/nss/ingest/bogus", content=b"{}", headers=h).status_code == 404

    page = logged_in.get("/logs")
    assert page.status_code == 200 and "alice@corp.example" in page.text and "Most blocked users" in page.text
    u = logged_in.get("/logs/user", params={"u": "bob"})
    assert u.status_code == 200 and "Recently blocked" in u.text and "ChatGPT" in u.text
    ev = logged_in.get("/logs/events", params={"blocked": "1", "range": "all"})
    assert ev.status_code == 200 and "bob" in ev.text
    link = ev.text.split('href="/logs/events/seg-', 1)[1].split('"', 1)[0]
    assert logged_in.get("/logs/events/seg-" + link).status_code == 200
    series = logged_in.get("/ui/logs/series", params={"range": "24h"}).json()
    assert sum(series["a"]) == 2 and sum(series["b"]) == 1      # the two firewall records are from 2020
    admin = logged_in.get("/admin/nss")
    assert admin.status_code == 200 and "/api/nss/ingest" in admin.text and "ZIA web" in admin.text


def test_storage_settings_and_clear(logged_in, app):
    tok = _token(logged_in)
    logged_in.post("/api/nss/ingest", content=json.dumps(web()), headers={"Authorization": f"Bearer {tok}"})
    r = logged_in.post("/admin/nss/storage", data={"max_gb": "120", "min_free_gb": "10"}, follow_redirects=False)
    assert r.status_code == 303
    assert app.state.nss.max_bytes == 120 * nss.GB
    assert logged_in.post("/admin/nss/storage", data={"max_gb": "0", "min_free_gb": "1"}, follow_redirects=False).status_code == 303
    assert app.state.nss.max_bytes == 120 * nss.GB
    logged_in.post("/admin/nss/clear", data={"confirm": "nope"})
    assert app.state.nss.newest_ts() is not None
    logged_in.post("/admin/nss/clear", data={"confirm": "DELETE"})
    assert app.state.nss.newest_ts() is None and app.state.nss.segments == []


def test_viewers_cannot_manage_feeds(client, app):
    from linkwatch.server.models import User
    from linkwatch.server.security import hash_password
    with app.state.lw.db.session() as s:
        s.add(User(username="viewer", password_hash=hash_password("viewer-password-1"), role="viewer"))
    client.post("/login", data={"username": "viewer", "password": "viewer-password-1", "next": "/"})
    assert client.get("/logs").status_code == 200
    r = client.get("/admin/nss", follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/admin/nss/tokens", data={"name": "x"}, follow_redirects=False)
    assert r.status_code == 303
