"""Adding SNMP polling to devices an API integration found: attach, merge into an existing SNMP device, bulk, undo."""
from sqlalchemy import select

from linkwatch.server.alerts import Alerter
from linkwatch.server.ingest import ingest_integration
from linkwatch.server.models import Device, DeviceMetric, Event, Integration, Poller, Port, SnmpProfile

UNIFI = [
    {"external_id": "aa:01", "hostname": "USW-Core", "ip": "10.0.0.40", "serial": "SW-1", "status": "up", "type": "Switch",
     "platform": "USW Pro 24", "cpu": 7.0, "extra": {"mac": "aa:01", "clients": 12},
     "ports": [{"ifindex": 1, "name": "Port 1", "admin": "up", "oper": "up", "in_octets": 1, "out_octets": 1}]},
    {"external_id": "aa:02", "hostname": "U6-Lobby", "ip": "10.0.0.41", "serial": "AP-2", "status": "up", "type": "Wireless",
     "extra": {"mac": "aa:02", "clients": 4}},
    {"external_id": "aa:03", "hostname": "USW-Lab", "ip": "10.0.0.42", "status": "up", "type": "Switch", "extra": {"mac": "aa:03"}},
]


def _setup(app):
    lw = app.state.lw
    with lw.db.session() as s:
        s.add(Poller(id=1, name="lan-poller", key_hash="x", features=["snmp_probe"]))
        s.add(SnmpProfile(id=1, name="campus", version="2c", config_enc=lw.vault.seal({"version": "2c", "community": "c"})))
        s.add(Integration(id=1, kind="unifi", name="UniFi", config_enc="-", enabled=True, poller_id=1))
        # USW-Lab is already polled over SNMP at its address, but the automatic match missed it (different name)
        s.add(Device(id=50, hostname="lab-sw.example", ip="10.0.0.42", poller_id=1, snmp_profile_id=1, extra={}))


def _sync(app, records=UNIFI):
    with app.state.lw.db.session() as s:
        ingest_integration(s, Alerter(s), s.get(Integration, 1), {"ok": True, "ts": 1_700_000_000, "records": records})


def _dev(app, ext):
    with app.state.lw.db.session() as s:
        d = s.scalar(select(Device).where(Device.integration_id == 1, Device.external_id == ext))
        d.ports                 # loaded before the session closes
        s.expunge(d)
        return d


def test_add_snmp_to_one_api_device(logged_in, app):
    _setup(app)
    # first sync: USW-Lab was matched to the SNMP device automatically (by IP), the others are API only
    _sync(app)
    core = _dev(app, "aa:01")
    assert core.source == "unifi" and core.ports
    page = logged_in.get(f"/devices/{core.id}").text
    assert f'href="/devices/add-snmp?ids={core.id}"' in page

    page = logged_in.get(f"/devices/add-snmp?ids={core.id}").text
    assert "Add SNMP to USW-Core" in page and 'value="10.0.0.40"' in page and "Merge into" not in page
    r = logged_in.post("/devices/add-snmp", data={"ids": str(core.id), f"ip_{core.id}": "10.0.0.40",
                                                  f"action_{core.id}": "attach", "poller_id": "1", "profile": "1", "ping": "on"},
                       follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/devices/{core.id}"

    d = _dev(app, "aa:01")
    assert d.id == core.id and d.source == "snmp" and d.snmp_profile_id == 1 and d.poller_id == 1 and d.ping
    assert d.extra["mac"] == "aa:01" and d.extra["api"]["integration"] == "UniFi" and d.extra["api"]["clients"] == 12
    cfg = app.state.lw.hub.build_config(1)
    polled = {x["id"]: x for x in cfg["devices"]}
    assert polled[core.id]["snmp"]["community"] == "c" and polled[core.id]["ip"] == "10.0.0.40"

    # the next sync keeps it one device; API data goes under extra.api and no longer drives status or ports
    recs = [dict(UNIFI[0], status="down", extra={"mac": "aa:01", "clients": 30}), *UNIFI[1:]]
    _sync(app, recs)
    with app.state.lw.db.session() as s:
        d = s.get(Device, core.id)
        assert d.source == "snmp" and d.status != "down" and d.extra["api"]["clients"] == 30
        assert len(s.scalars(select(Device).where(Device.external_id == "aa:01")).all()) == 1
        assert s.scalar(select(Event.id).where(Event.device_id == core.id, Event.message.like("SNMP polling added by admin%")))

    # and back again: API data only, SNMP ports gone, not polled
    page = logged_in.get(f"/devices/{core.id}/edit").text
    assert f'action="/devices/{core.id}/snmp/remove"' in page
    logged_in.post(f"/devices/{core.id}/snmp/remove", data={"confirm": "on"})
    with app.state.lw.db.session() as s:
        d = s.get(Device, core.id)
        assert d.source == "unifi" and d.snmp_profile_id is None and d.poller_id is None
        assert d.extra.get("clients") == 30 and "api" not in d.extra
        assert not s.scalars(select(Port).where(Port.device_id == core.id)).all()
    assert core.id not in {x["id"] for x in app.state.lw.hub.build_config(1)["devices"]}


def test_merge_into_existing_snmp_device(logged_in, app):
    _setup(app)
    with app.state.lw.db.session() as s:
        s.get(Device, 50).ip = "10.9.9.9"     # so the sync can't match it on its own
    _sync(app)
    lab = _dev(app, "aa:03")
    assert lab.source == "unifi"
    with app.state.lw.db.session() as s:
        s.add(DeviceMetric(device_id=lab.id, ts=lab.created_at, cpu=3.0))
    # the person types the address the SNMP device is polled on: the page offers to merge instead of a duplicate
    r = logged_in.post("/devices/add-snmp", data={"ids": str(lab.id), f"ip_{lab.id}": "10.9.9.9", f"action_{lab.id}": "attach",
                                                  "poller_id": "1", "profile": "1"})
    assert r.status_code == 400 and "lab-sw.example already polls 10.9.9.9" in r.text
    r = logged_in.post("/devices/add-snmp", data={"ids": str(lab.id), f"ip_{lab.id}": "10.9.9.9", f"action_{lab.id}": "merge",
                                                  "poller_id": "1"}, follow_redirects=False)
    assert r.headers["location"] == "/devices/50"
    with app.state.lw.db.session() as s:
        assert s.get(Device, lab.id) is None
        twin = s.get(Device, 50)
        assert twin.integration_id == 1 and twin.external_id == "aa:03" and twin.source == "snmp"
        assert twin.extra["api"]["integration"] == "UniFi" and twin.extra["mac"] == "aa:03"
        assert s.scalar(select(DeviceMetric.id).where(DeviceMetric.device_id == 50))
    _sync(app)
    with app.state.lw.db.session() as s:
        assert len(s.scalars(select(Device).where(Device.integration_id == 1)).all()) == 3


def test_bulk_add_snmp_with_new_credentials(logged_in, app):
    _setup(app)
    with app.state.lw.db.session() as s:
        s.get(Device, 50).ip = "10.9.9.9"
        s.get(Device, 50).serial = "AP-2"      # the AP is already an SNMP device, found by serial
    _sync(app)
    ids = [_dev(app, e).id for e in ("aa:01", "aa:02", "aa:03")]
    assert _dev(app, "aa:02").id == 50          # matched on sync already, so it's skipped below
    r = logged_in.post("/devices/bulk", data={"action": "add_snmp", "device_id": [str(i) for i in ids]}, follow_redirects=False)
    assert r.headers["location"] == "/devices/add-snmp?ids=" + ",".join(map(str, ids))
    page = logged_in.get(r.headers["location"]).text
    assert "Add SNMP to 2 devices" in page and "Skipped 1 device" in page
    assert 'name="ip_50"' not in page

    form = {"ids": ",".join(map(str, ids)), "poller_id": "1", "profile": "new", "name": "unifi-v3", "version": "3",
            "username": "lw", "level": "authPriv", "auth_protocol": "SHA", "auth_key": "short", "priv_protocol": "AES",
            "priv_key": "privpass1"}
    for i in ids:
        form[f"ip_{i}"] = ""
    form[f"ip_{ids[0]}"], form[f"ip_{ids[2]}"] = "10.0.0.40", "10.0.0.42"
    r = logged_in.post("/devices/add-snmp", data=form)
    assert r.status_code == 400 and "passphrases of at least 8" in r.text
    form["auth_key"] = "authpass1"
    r = logged_in.post("/devices/add-snmp", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/devices"
    with app.state.lw.db.session() as s:
        prof = s.scalar(select(SnmpProfile).where(SnmpProfile.name == "unifi-v3"))
        assert prof.version == "3" and app.state.lw.vault.open(prof.config_enc)["priv_key"] == "privpass1"
        for i in (ids[0], ids[2]):
            d = s.get(Device, i)
            assert d.source == "snmp" and d.snmp_profile_id == prof.id and not d.ping


def test_credential_test_goes_through_the_poller(logged_in, app):
    _setup(app)
    sent = {}

    async def fake_test(poller_id, message, timeout=30.0):
        sent.update(message, poller_id=poller_id)
        return {"rows": [{"index": "1.3.6.1.2.1.1.5.0", "value": "usw-core", "label": "sysName"},
                         {"index": "1.3.6.1.2.1.1.1.0", "value": "USW-Pro-24, 7.1.66\nmore", "label": "sysDescr"}]}
    app.state.lw.hub.snmp_test = fake_test
    r = logged_in.post("/ui/devices/snmp-test", json={"poller_id": 1, "ip": "10.0.0.40", "profile": "new", "version": "2c",
                                                      "community": "public"})
    assert r.json() == {"ok": True, "poller": "lan-poller", "ip": "10.0.0.40", "sys_name": "usw-core",
                        "sys_descr": "USW-Pro-24, 7.1.66", "sys_object_id": None}
    assert sent["snmp"] == {"version": "2c", "community": "public"} and sent["mode"] == "system" and sent["poller_id"] == 1
    r = logged_in.post("/ui/devices/snmp-test", json={"poller_id": 1, "ip": "10.0.0.40", "profile": "1"})
    assert sent["snmp"]["community"] == "c"
    with app.state.lw.db.session() as s:
        s.get(Poller, 1).features = ["rpc"]
    assert "too old" in logged_in.post("/ui/devices/snmp-test", json={"poller_id": 1, "ip": "10.0.0.40", "profile": "1"}).json()["error"]


def test_poller_tries_credentials_it_was_sent(tmp_path, monkeypatch):
    import asyncio

    from linkwatch.poller import main as pm

    from .test_phase2 import FakeSnmp
    p = pm.Poller("https://example.invalid", tmp_path)
    seen, sent = [], []

    class Sess(FakeSnmp):
        def __init__(self, host, creds, **kw):
            seen.append((host, creds))
            super().__init__({"1.3.6.1.2.1.1.5.0": "usw-core", "1.3.6.1.2.1.1.1.0": "USW-Pro-24"}
                             if creds.get("community") == "good" else {})

    async def capture(msg, queue=True):
        sent.append(msg)
    monkeypatch.setattr(pm, "SnmpSession", Sess)
    monkeypatch.setattr(p, "send_or_queue", capture)
    asyncio.run(p.snmp_test({"req": "a", "ip": "10.0.0.40", "snmp": {"version": "2c", "community": "good"}, "mode": "system"}))
    asyncio.run(p.snmp_test({"req": "b", "ip": "10.0.0.40", "snmp": {"version": "2c", "community": "bad"}, "mode": "system"}))
    assert seen[0] == ("10.0.0.40", {"version": "2c", "community": "good"})
    assert sent[0]["rows"] == [{"index": "1.3.6.1.2.1.1.5.0", "value": "usw-core", "label": "sysName"},
                               {"index": "1.3.6.1.2.1.1.1.0", "value": "USW-Pro-24", "label": "sysDescr"}]
    assert "no system information" in sent[1]["error"]
    assert "snmp_probe" in p.features()
