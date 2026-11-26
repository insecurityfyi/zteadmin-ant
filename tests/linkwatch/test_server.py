import json
import re

from sqlalchemy import select

from linkwatch.server.models import Device, Poller


def test_pages_need_login(client):
    r = client.get("/devices", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert client.get("/ui/metrics/device/1").status_code == 401
    assert client.get("/healthz").json()["ok"] is True


def test_wrong_password_and_lockout(client):
    for _ in range(8):
        assert client.post("/login", data={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/login", data={"username": "admin", "password": "pw-for-tests"}).status_code == 429


def test_every_page_renders(logged_in):
    for path in ["/", "/devices", "/alerts", "/pollers", "/integrations", "/settings", "/devices/new", "/devices/import",
                 "/integrations/new?kind=zscaler", "/integrations/new?kind=proxmox", "/discovery", "/admin", "/account"]:
        r = logged_in.get(path)
        assert r.status_code == 200, path


def enroll(client):
    page = client.post("/pollers/token").text
    token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", page).group(1)
    assert f"install-poller.sh \\\n  | sudo bash -s -- --server http://testserver --token {token} --name" in page
    r = client.post("/api/poller/enroll", json={"token": token, "name": "poller-hq-01", "hostname": "lan-box"})
    assert r.status_code == 200
    assert client.post("/api/poller/enroll", json={"token": token}).status_code == 403   # single use
    return r.json()


def test_poller_end_to_end(logged_in, app):
    ident = enroll(logged_in)
    logged_in.post("/settings/snmp", data={"name": "lab", "version": "2c", "community": "public"})
    r = logged_in.post("/devices/new", data={"hostname": "core-sw01", "ip": "10.10.0.2", "type": "Switch", "site": "HQ",
                                             "poller_id": str(ident["poller_id"]), "snmp_profile_id": "1", "ping": "on"})
    assert r.status_code == 200 and "core-sw01" in r.text

    with logged_in.websocket_connect("/api/poller/ws", headers={"Authorization": f"Bearer {ident['key']}"}) as ws:
        cfg = json.loads(ws.receive_text())
        assert cfg["type"] == "config" and cfg["interval"] == 300
        assert cfg["devices"][0]["snmp"] == {"version": "2c", "community": "public"}
        ws.send_text(json.dumps({"type": "hello", "version": "0.1.0", "hostname": "lan-box"}))
        item = {"kind": "device", "device_id": cfg["devices"][0]["id"], "ts": 1_700_000_000, "ok": True,
                "system": {"sys_name": "core-sw01"}, "cpu": 12.0, "mem": 30.0, "ping": {"rtt_ms": 1.1, "loss_pct": 0}, "ports": []}
        ws.send_text(json.dumps({"type": "results", "batch_id": "000-a", "cycle_ms": 4100, "items": [item]}))
        assert json.loads(ws.receive_text()) == {"type": "ack", "batch_id": "000-a"}

    with app.state.lw.db.session() as s:
        d = s.scalar(select(Device).where(Device.hostname == "core-sw01"))
        assert d.status == "up" and d.cpu == 12.0
        p = s.get(Poller, ident["poller_id"])
        assert p.version == "0.1.0" and p.last_cycle_ms == 4100
    assert "core-sw01" in logged_in.get("/").text


def test_bad_poller_key_rejected(client):
    from starlette.websockets import WebSocketDisconnect
    import pytest
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/poller/ws", headers={"Authorization": "Bearer lwp_nope"}) as ws:
            ws.receive_text()


def test_rest_api_keys(logged_in):
    page = logged_in.post("/settings/apikeys", data={"name": "grafana", "scope": "ro"}).text
    key = re.search(r'class="secret">(lw_[^<]+)<', page).group(1)
    assert logged_in.get("/api/v1/devices").status_code == 401
    h = {"Authorization": f"Bearer {key}"}
    assert logged_in.get("/api/v1/devices", headers=h).json() == []
    assert logged_in.get("/api/v1/alerts", headers=h).status_code == 200
    assert logged_in.post("/api/v1/alerts/1/ack", headers=h).status_code == 403    # read-only key


def test_integration_secrets_are_masked(logged_in, app):
    r = logged_in.post("/integrations/new", data={"kind": "meraki", "name": "Meraki", "api_key": "supersecretkey123"})
    assert r.status_code == 200
    assert "supersecretkey123" not in r.text
    with app.state.lw.db.session() as s:
        from linkwatch.server.models import Integration
        integ = s.scalar(select(Integration))
        assert "supersecretkey123" not in integ.config_enc
        assert app.state.lw.vault.open(integ.config_enc)["api_key"] == "supersecretkey123"
    # saving the form without retyping the key keeps it
    logged_in.post(f"/integrations/{integ.id}", data={"name": "Meraki org", "api_key": "", "enabled": "on"})
    with app.state.lw.db.session() as s:
        integ = s.scalar(select(Integration))
        assert app.state.lw.vault.open(integ.config_enc)["api_key"] == "supersecretkey123" and integ.name == "Meraki org"
    # the browser filling the sign-in password into the key field is refused, and the key is kept
    r = logged_in.post(f"/integrations/{integ.id}", data={"name": "Meraki org", "api_key": "pw-for-tests", "enabled": "on"})
    assert "sign-in password" in r.text
    with app.state.lw.db.session() as s:
        integ = s.scalar(select(Integration))
        assert app.state.lw.vault.open(integ.config_enc)["api_key"] == "supersecretkey123"
    form = logged_in.get(f"/integrations/{integ.id}").text
    assert 'autocomplete="new-password"' in form


def test_csv_import(logged_in):
    ident = enroll(logged_in)
    csv = b"hostname,ip,site,type\nsw-a,10.0.0.10,HQ,Switch\nsw-b,10.0.0.11,Branch,Switch\n,,,\n"
    r = logged_in.post("/devices/import", data={"poller_id": str(ident["poller_id"]), "snmp_profile_id": ""},
                       files={"file": ("d.csv", csv, "text/csv")})
    assert "Imported 2 devices" in r.text


def test_discovery_scan_and_bulk_add(logged_in, app):
    ident = enroll(logged_in)
    logged_in.post("/settings/snmp", data={"name": "lab", "version": "2c", "community": "public"})
    logged_in.post("/devices/new", data={"hostname": "old-sw", "ip": "10.9.0.1", "type": "Switch",
                                         "poller_id": str(ident["poller_id"]), "snmp_profile_id": "", "ping": "on"})
    assert "at most 4096" in logged_in.post("/discovery", data={"targets": "10.0.0.0/16", "poller_id": ident["poller_id"]}).text
    assert logged_in.get("/discovery").status_code == 200

    with logged_in.websocket_connect("/api/poller/ws", headers={"Authorization": f"Bearer {ident['key']}"}) as ws:
        json.loads(ws.receive_text())   # config
        r = logged_in.post("/discovery", data={"targets": "10.9.0.0/29", "poller_id": ident["poller_id"], "profile_id": "1"})
        assert r.status_code == 200 and "Scanning" in r.text
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "discover" and msg["targets"] == "10.9.0.0/29"
        assert msg["profiles"] == [{"id": 1, "creds": {"version": "2c", "community": "public"}}]
        job = msg["job_id"]
        ws.send_text(json.dumps({"type": "discovery_result", "job_id": job, "scanned": 6, "total": 6, "found": [
            {"ip": "10.9.0.1", "rtt_ms": 0.4},
            {"ip": "10.9.0.2", "rtt_ms": 0.6, "profile_id": 1, "sys_name": "core-fw", "sys_descr": "Palo Alto Networks PA-440 series firewall"},
            {"ip": "10.9.0.3", "rtt_ms": 1.2}]}))
        ws.send_text(json.dumps({"type": "results", "batch_id": "barrier", "items": []}))
        assert json.loads(ws.receive_text())["type"] == "ack"

    page = logged_in.get(f"/discovery/{job}").text
    assert "3 found, 2 not monitored yet" in page and "core-fw" in page and "monitored" in page
    r = logged_in.post(f"/discovery/{job}/add", data={"ip": ["10.9.0.1", "10.9.0.2", "10.9.0.3"], "type_10.9.0.3": "Printer", "site": "Lab"})
    assert "Added 2 devices" in r.text
    with app.state.lw.db.session() as s:
        fw = s.scalar(select(Device).where(Device.ip == "10.9.0.2"))
        pr = s.scalar(select(Device).where(Device.ip == "10.9.0.3"))
        assert (fw.hostname, fw.type, fw.snmp_profile_id, fw.source, fw.site.name) == ("core-fw", "Firewall", 1, "snmp", "Lab")
        assert (pr.hostname, pr.type, pr.snmp_profile_id, pr.source) == ("10.9.0.3", "Printer", None, "ping")
        assert len(s.scalars(select(Device).where(Device.ip == "10.9.0.1")).all()) == 1


def test_discovery_needs_connected_poller(logged_in):
    ident = enroll(logged_in)
    r = logged_in.post("/discovery", data={"targets": "10.9.0.0/30", "poller_id": ident["poller_id"]})
    assert "not connected" in r.text


def test_unifi_pages(logged_in, app):
    import respx
    from linkwatch.integrations import build
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    from linkwatch.server.models import Device, Integration
    from tests.linkwatch.test_integrations import mock_unifi

    assert "Wi-Fi &amp; clients" not in logged_in.get("/").text          # nav item only once UniFi is set up
    with respx.mock:
        mock_unifi()
        client = build("unifi", {"host": "192.168.1.1", "api_key": "k"})
        records = client.collect()
    db = app.state.lw.db
    with db.session() as s:
        integ = Integration(kind="unifi", name="Home UniFi", config_enc=app.state.lw.vault.seal({"host": "192.168.1.1", "api_key": "k"}))
        s.add(integ)
        s.flush()
        ingest_integration(s, Alerter(s), integ, {"ok": True, "records": records, "data": client.data})
        iid = integ.id
        ap_id = s.scalar(select(Device.id).where(Device.external_id == "aa:aa:aa:00:00:01"))
    page = logged_in.get("/unifi").text
    assert "Wi-Fi &amp; clients" in page and "laptop" in page and "Fiber Co" in page and "ap-lobby" in page
    assert f'href="/unifi/{iid}/ssids/Office"' in page
    r = logged_in.get(f"/unifi/{iid}/clients/cc:00:00:00:00:01")
    assert r.status_code == 200 and "-55 dBm" in r.text and "Apple" in r.text
    assert logged_in.get(f"/unifi/{iid}/clients/ee:ee:ee:ee:ee:ee").status_code == 200      # gone, history only
    r = logged_in.get(f"/unifi/{iid}/ssids/Office")
    assert r.status_code == 200 and "laptop" in r.text and "phone" not in r.text
    assert logged_in.get(f"/unifi/{iid}/ssids/Nope").status_code == 404
    series = logged_in.get(f"/ui/metrics/integration/{iid}/ssid:Office").json()
    assert series["a"] == [4_000_000.0] and series["c"] == [1.0]
    assert logged_in.get(f"/ui/metrics/integration/{iid}/ssid%3AOffice").json()["a"] == [4_000_000.0]
    assert "Wi-Fi clients" in logged_in.get(f"/devices/{ap_id}").text
    assert "Wi-Fi traffic" in logged_in.get(f"/devices/{ap_id}?tab=graphs").text
    assert f'href="/unifi?i={iid}"' in logged_in.get(f"/integrations/{iid}").text


def test_integration_pages(logged_in, app):
    import copy
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    from linkwatch.server.models import Integration, IntegrationMetric
    from tests.linkwatch.sample_integrations import DATA, RECORDS

    ids = {}
    db = app.state.lw.db
    with db.session() as s:
        for kind, data in DATA.items():
            integ = Integration(kind=kind, name=f"My {kind}", config_enc=app.state.lw.vault.seal({}), status="never")
            s.add(integ)
            s.flush()
            ingest_integration(s, Alerter(s), integ, {"ok": True, "records": RECORDS[kind], "data": copy.deepcopy(data)})
            ids[kind] = integ.id
        keys = {(m.integration_id, m.key) for m in s.scalars(select(IntegrationMetric))}
    assert {(ids["zscaler"], k) for k in ("objects", "zpa:connectors", "zdx:3", "zdx:average", "zcc:devices", "zia:inventory")} <= keys
    assert {(ids["meraki"], "clients"), (ids["meraki"], "uplink:Q2-MX/wan1"), (ids["panos"], "sessions"),
            (ids["fortigate"], "tunnels"), (ids["proxmox"], "guests"), (ids["proxmox"], "storage:pve-01/local-zfs")} <= keys

    nav = logged_in.get("/").text
    assert f'href="/integrations/{ids["meraki"]}/overview"' in nav and "My zscaler" in nav

    z = logged_in.get(f"/integrations/{ids['zscaler']}/overview").text
    assert "ZDX average score" in z and "ac-hq-02" in z and "1 optional panel" in z
    for tab, text in [("zia", "HQ Guest"), ("zpa", "UPGRADE_FAILED".lower().replace("_", " ")), ("zdx", "Salesforce"),
                      ("zcc", "LT-0042"), ("ztb", "No sites")]:
        r = logged_in.get(f"/integrations/{ids['zscaler']}/overview?tab={tab}")
        assert r.status_code == 200 and text in r.text, tab
    assert "dal-mx" in logged_in.get(f"/integrations/{ids['meraki']}/overview").text
    pa = logged_in.get(f"/integrations/{ids['panos']}/overview").text
    assert "WildFire License" in pa and "(expired)" in pa and "to-azure" in pa
    assert "grace" in logged_in.get(f"/integrations/{ids['fortigate']}/overview").text
    sw = logged_in.get(f"/integrations/{ids['sonicwall']}/overview").text
    assert "hopper" in sw and "Capture ATP" in sw and "Active/Standby" in sw and "Not offered by this firmware: IPsec tunnels" in sw
    assert (ids["sonicwall"], "sslvpn:users") in keys
    assert "local-zfs" in logged_in.get(f"/integrations/{ids['proxmox']}/overview").text
    assert logged_in.get("/integrations/999/overview").status_code == 404
    series = logged_in.get(f"/ui/metrics/integration/{ids['zscaler']}/objects").json()
    assert series["a"] == [1.0] and series["b"] == [3.0] and series["c"] == [1.0]


def test_integration_page_before_first_sync(logged_in, app):
    from linkwatch.server.models import Integration
    with app.state.lw.db.session() as s:
        integ = Integration(kind="panos", name="New PA", config_enc=app.state.lw.vault.seal({}))
        s.add(integ)
        s.flush()
        iid = integ.id
    r = logged_in.get(f"/integrations/{iid}/overview")
    assert r.status_code == 200 and "hasn't synced yet" in r.text


def test_integration_pages_with_sparse_data(logged_in, app):
    """A tenant that returns almost nothing still gets a page, not an error."""
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    from linkwatch.server.models import Integration
    with app.state.lw.db.session() as s:
        ids = []
        for kind in ("zscaler", "meraki", "panos", "fortigate", "proxmox"):
            integ = Integration(kind=kind, name=f"Sparse {kind}", config_enc=app.state.lw.vault.seal({}))
            s.add(integ)
            s.flush()
            data = {"type": kind, "products": {"zia": {"ok": True, "objects": 0}}} if kind == "zscaler" else {"type": kind}
            ingest_integration(s, Alerter(s), integ, {"ok": True, "records": [], "data": data})
            ids.append(integ.id)
    for iid in ids:
        assert logged_in.get(f"/integrations/{iid}/overview").status_code == 200, iid
    assert logged_in.get(f"/integrations/{ids[0]}/overview?tab=zia").status_code == 200
