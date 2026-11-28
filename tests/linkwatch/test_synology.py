"""Synology DSM: inventory, actions, the NAS pages and their safety rails.

None of this has been run against a real NAS; the API shapes follow DSM 7.2's web UI traffic and Synology's API guides."""
import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from sqlalchemy import select

from linkwatch.integrations import IntegrationError, build
from linkwatch.integrations import synology as syno
from linkwatch.server.gateway import RpcError
from linkwatch.server.ingest import integration_series
from linkwatch.server.models import AuditEvent, Event, Integration, Poller

BASE = "https://10.10.5.20:5001/webapi"
CFG = {"host": "10.10.5.20", "username": "linkwatch", "password": "pw", "allow_control": True}

APIS = {name: {"path": "entry.cgi", "minVersion": 1, "maxVersion": v} for name, v in {
    "SYNO.API.Auth": 7, "SYNO.Core.System": 3, "SYNO.Core.System.Utilization": 1, "SYNO.Storage.CGI.Storage": 1,
    "SYNO.Core.Hardware.FanSpeed": 1, "SYNO.Core.ExternalDevice.UPS": 1, "SYNO.Core.Network.Interface": 1,
    "SYNO.Core.Share": 1, "SYNO.Core.Share.Snapshot": 2, "SYNO.Core.Package": 2, "SYNO.Core.Package.Control": 1,
    "SYNO.Docker.Container": 1, "SYNO.Docker.Container.Resource": 1, "SYNO.Virtualization.API.Guest": 1,
    "SYNO.Virtualization.API.Guest.Action": 1, "SYNO.Backup.Task": 1, "SYNO.Core.CurrentConnection": 1,
    "SYNO.Core.SecurityScan.Status": 1, "SYNO.Core.SecurityScan.Operation": 1, "SYNO.Core.Upgrade.Server": 2,
    "SYNO.Storage.CGI.Pool": 1, "SYNO.Storage.CGI.Smart": 1}.items()}

DATA = {
    ("SYNO.Core.System", "info"): {"model": "DS920+", "serial": "2040ABC", "firmware_ver": "DSM 7.2.1-69057 Update 5",
                                   "up_time": "100:00:30", "sys_temp": 41, "temperature_warning": False, "ram_size": 8192,
                                   "cpu_series": "J4125", "cpu_cores": "4"},
    ("SYNO.Core.System.Utilization", "get"): {"cpu": {"user_load": 7, "system_load": 3, "other_load": 2, "1min_load": 40},
                                              "memory": {"real_usage": 35, "total_real": 8000000, "avail_real": 5000000},
                                              "network": [{"device": "total", "rx": 1000, "tx": 500}, {"device": "eth0", "rx": 1000, "tx": 500}]},
    ("SYNO.Storage.CGI.Storage", "load_info"): {
        "disks": [{"id": "sata1", "name": "Drive 1", "model": "WD40EFRX ", "vendor": "WDC", "serial": "WD-1", "size_total": "4000787030016",
                   "status": "normal", "smart_status": "normal", "temp": 36, "unc": 0, "remain_life": -1, "used_by": "reuse_1"},
                  {"id": "sata2", "name": "Drive 2", "model": "WD40EFRX", "vendor": "WDC", "status": "normal", "smart_status": "warning",
                   "temp": 52, "unc": 12, "used_by": "reuse_1"}],
        "storagePools": [{"id": "reuse_1", "num_id": 1, "status": "normal", "device_type": "shr_with_1_disk_protect",
                          "size": {"total": "7000000000000", "used": "3500000000000"}, "disks": ["sata1", "sata2"]}],
        "volumes": [{"id": "volume_1", "vol_path": "/volume1", "status": "normal", "fs_type": "btrfs", "pool_path": "reuse_1",
                     "size": {"total": "6000000000000", "used": "5700000000000"}}]},
    ("SYNO.Core.System", "info", "network"): {"server_name": "vault", "nif": [{"ip": "10.10.5.20"}]},
    ("SYNO.Core.Hardware.FanSpeed", "get"): {"dual_fan_speed": "quietfan"},
    ("SYNO.Core.ExternalDevice.UPS", "get"): {"enable": True, "model": "Back-UPS 700", "status": "usb_ups_status_online", "charge": 100, "runtime": 1800},
    ("SYNO.Core.Network.Interface", "list"): [{"ifname": "eth0", "ip": "10.10.5.20", "mask": "255.255.255.0", "speed": 1000, "status": "connected", "type": "lan"}],
    ("SYNO.Core.Share", "list"): {"shares": [{"name": "docker", "vol_path": "/volume1", "support_snapshot": True, "enable_recycle_bin": True},
                                             {"name": "usbshare1", "vol_path": "/volumeUSB1"}]},
    ("SYNO.Core.Share.Snapshot", "list"): {"total": 2, "snapshots": [{"time": "GMT+01-2026.11.01-03.00.00", "desc": "nightly", "schedule_snapshot": True},
                                                                     {"time": "GMT+01-2026.11.20-03.00.00", "desc": "", "lock": True}]},
    ("SYNO.Core.Package", "list"): {"packages": [{"id": "ContainerManager", "name": "Container Manager", "version": "24.0.2",
                                                  "additional": {"status": "running", "startable": True}},
                                                 {"id": "HyperBackup", "name": "Hyper Backup", "version": "4.1", "additional": {"status": "stop"}}]},
    ("SYNO.Docker.Container", "list"): {"containers": [{"name": "plex", "image": "plexinc/pms-docker:latest", "status": "running", "up_time": 3600},
                                                       {"name": "old", "image": "busybox", "status": "exited"}]},
    ("SYNO.Docker.Container.Resource", "get"): {"resources": [{"name": "plex", "cpu": 12.5, "memory": 524288000, "memoryPercent": 6.4}]},
    ("SYNO.Virtualization.API.Guest", "list"): {"guests": [{"guest_id": "a1b2c3d4-0000-1111", "guest_name": "win11", "status": "running",
                                                            "vcpu_num": 2, "vram_size": 4096, "vdisks": [{}]}]},
    ("SYNO.Backup.Task", "list"): {"task_list": [{"task_id": 3, "name": "To B2", "status": "none", "state": "backupable", "target_type": "cloud_image",
                                                  "last_bkp_time": "2026/11/27 03:00", "last_bkp_result": "failed", "next_bkp_time": "2026/11/28 03:00"}]},
    ("SYNO.Core.CurrentConnection", "list"): {"items": [{"who": "adam", "type": "SMB", "from": "10.10.5.50", "time": "2026/11/27 20:00", "descr": "media"}]},
    ("SYNO.Core.SecurityScan.Status", "system_get"): {"sysStatus": "safe", "lastScanTime": "1764200000", "sysProgress": 100,
                                                       "items": {"malware": {"failSeverity": "safe", "fail": {"danger": 0, "warning": 0}}}},
    ("SYNO.Core.Upgrade.Server", "check"): {"update": {"available": True, "version": "DSM 7.2.2-72806", "reboot": "now"}},
}


def params(request) -> dict:
    q = dict(request.url.params)
    if request.method == "POST":
        q.update({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
    return q


class FakeDsm:
    """Answers DSM Web API calls from DATA; records every call."""

    def __init__(self, data=None, errors=None):
        self.data = dict(DATA if data is None else data)
        self.errors = dict(errors or {})
        self.calls: list[dict] = []
        self.logins = 0

    def __call__(self, request):
        q = params(request)
        self.calls.append(q)
        api, method = q.get("api"), q.get("method")
        if api == "SYNO.API.Info":
            return httpx.Response(200, json={"success": True, "data": APIS})
        if api == "SYNO.API.Auth":
            self.logins += 1
            if (api, method) in self.errors:
                return httpx.Response(200, json={"success": False, "error": {"code": self.errors[(api, method)]}})
            return httpx.Response(200, json={"success": True, "data": {"sid": f"sid{self.logins}"}})
        key = (api, method, q["type"].strip('"')) if q.get("type") in ("network", '"network"') else (api, method)
        if key in self.errors:
            code = self.errors[key]
            if isinstance(code, list):          # one error, then success
                code = code.pop(0) if code else None
            if code:
                return httpx.Response(200, json={"success": False, "error": {"code": code}})
        if key in self.data:
            return httpx.Response(200, json={"success": True, "data": self.data[key]})
        return httpx.Response(200, json={"success": True, "data": {}})


@pytest.fixture(autouse=True)
def fresh_sessions():
    syno._SESSIONS.clear()
    yield
    syno._SESSIONS.clear()


@pytest.fixture
def dsm():
    fake = FakeDsm()
    with respx.mock:
        respx.route(url__startswith=BASE).mock(side_effect=fake)
        yield fake


# ------------------------------------------------------------------ integration
def test_collect_reads_everything(dsm):
    n = build("synology", CFG)
    recs = n.collect()
    assert len(recs) == 1
    r = recs[0]
    assert r["hostname"] == "vault" and r["type"] == "NAS" and r["ip"] == "10.10.5.20" and r["external_id"] == "nas-2040ABC"
    assert r["platform"] == "Synology DS920+ DSM 7.2.1-69057 Update 5" and r["cpu"] == 12.0 and r["mem"] == 35.0
    assert r["uptime_s"] == 100 * 3600 + 30 and r["status"] == "warn"
    d = n.data
    assert d["volumes"][0]["pct"] == 95.0 and d["pools"][0]["pct"] == 50.0
    assert d["disks"][0]["model"] == "WD40EFRX" and d["disks"][0]["life_pct"] is None
    assert d["util"]["rx_bps"] == 8000 and d["util"]["mem_total"] == 8000000 * 1024
    assert d["ups"]["status"] == "online" and not d["ups"]["on_battery"]
    docker = d["shares"][0]
    assert docker["snapshot_count"] == 2 and docker["snapshots"][0]["time"] == "GMT+01-2026.11.20-03.00.00" and docker["snapshots"][0]["locked"]
    assert d["shares"][1]["snapshots"] is None                     # not snapshot-capable, not asked
    assert {p["id"]: p["status"] for p in d["packages"]} == {"ContainerManager": "running", "HyperBackup": "stopped"}
    assert d["containers"][1]["name"] == "plex" and d["containers"][1]["cpu"] == 12.5 and d["containers"][1]["running"]
    assert d["vms"][0]["id"] == "a1b2c3d4-0000-1111" and d["vms"][0]["running"]
    assert d["backups"][0]["ok"] is False and d["dsm_update"] == {"available": True, "version": "DSM 7.2.2-72806", "reboot": True, "type": None}
    assert d["security"]["status"] == "safe" and d["connections"][0]["user"] == "adam"
    assert d["problems"] == ["Drive 2 SMART: warning", "/volume1 is 95% full", "Backup To B2 last result: failed"]
    assert d["unavailable"] == []
    # one login, password sent in a POST body, never in a URL
    assert dsm.logins == 1
    assert all("passwd" not in c or c.get("api") == "SYNO.API.Auth" for c in dsm.calls)
    login = next(c for c in dsm.calls if c.get("api") == "SYNO.API.Auth")
    assert login["version"] == "6" and login["session"] == "Linkwatch" and login["format"] == "sid"
    assert all(c["_sid"] == "sid1" for c in dsm.calls if c.get("api") not in ("SYNO.API.Info", "SYNO.API.Auth"))
    snap_list = next(c for c in dsm.calls if c.get("api") == "SYNO.Core.Share.Snapshot")
    assert snap_list["name"] == '"docker"' and json.loads(snap_list["additional"]) == ["desc", "lock", "schedule_snapshot"]
    # series for the graphs
    pts = dict((k, (a, b, c)) for k, a, b, c in integration_series(d))
    assert pts["load"] == (12.0, 35.0, 41.0) and pts["net"] == (8000.0, 4000.0, None) and pts["vol:volume_1"][0] == 95.0


def test_session_is_reused_and_renewed(dsm):
    build("synology", CFG).collect()
    build("synology", CFG).collect()
    assert dsm.logins == 1                                         # the second sync reuses the session
    dsm.errors[("SYNO.Core.System", "info")] = [119]               # DSM forgot the session: log in again and retry
    build("synology", CFG).collect()
    assert dsm.logins == 2


def test_missing_packages_and_permissions(dsm, monkeypatch):
    for k in ("SYNO.Docker.Container", "SYNO.Virtualization.API.Guest", "SYNO.Backup.Task"):
        monkeypatch.delitem(APIS, k)                               # packages not installed: their APIs don't exist
    dsm.errors[("SYNO.Core.SecurityScan.Status", "system_get")] = 105
    n = build("synology", CFG)
    n.collect()
    assert n.data["containers"] is None and n.data["vms"] is None and n.data["backups"] is None
    assert n.data["security"] is None
    assert n.data["unavailable"] == ["Security Advisor: SYNO.Core.SecurityScan.Status system_get: the DSM account lacks permission "
                                     "(the account must be in the administrators group; see docs/synology.md)"]


@pytest.mark.parametrize("code,msg", [(400, "rejected the account name or password"), (403, "needs a 2-step verification code"),
                                      (407, "Auto Block")])
def test_login_errors_are_plain(dsm, code, msg):
    dsm.errors[("SYNO.API.Auth", "login")] = code
    with pytest.raises(IntegrationError, match=msg):
        build("synology", CFG).collect()


def test_device_token_is_sent(dsm):
    build("synology", {**CFG, "device_token": "DEVTOKEN"}).collect()
    login = next(c for c in dsm.calls if c.get("api") == "SYNO.API.Auth")
    assert login["device_id"] == "DEVTOKEN" and login["device_name"] == "Linkwatch"


def test_not_a_nas():
    with respx.mock:
        respx.route(url__startswith=BASE).mock(return_value=httpx.Response(200, text="<html>router</html>"))
        with pytest.raises(IntegrationError, match="isn't JSON"):
            build("synology", CFG).collect()


@pytest.mark.parametrize("name,p,api,method,sent", [
    ("system_reboot", {}, "SYNO.Core.System", "reboot", {"force": "false", "local": "true"}),
    ("system_shutdown", {}, "SYNO.Core.System", "shutdown", {"force": "false"}),
    ("package_stop", {"package": "HyperBackup"}, "SYNO.Core.Package.Control", "stop", {"id": '"HyperBackup"'}),
    ("container_restart", {"container": "plex"}, "SYNO.Docker.Container", "restart", {"name": '"plex"'}),
    ("vm_poweron", {"guest": "a1b2c3d4-0000-1111"}, "SYNO.Virtualization.API.Guest.Action", "poweron", {"guest_id": "a1b2c3d4-0000-1111"}),
    ("backup_run", {"task": "3"}, "SYNO.Backup.Task", "backup", {"task_id": "3"}),
    ("backup_cancel", {"task": "3"}, "SYNO.Backup.Task", "cancel", {"task_id": "[3]"}),
    ("scrub_start", {"pool": "reuse_1"}, "SYNO.Storage.CGI.Pool", "data_scrubbing", {"pool_path": '"reuse_1"'}),
    ("snapshot_create", {"share": "docker", "description": "pre-upgrade", "lock": "1"}, "SYNO.Core.Share.Snapshot", "create",
     {"name": '"docker"', "snapinfo": '{"desc": "pre-upgrade", "lock": true}'}),
    ("snapshot_delete", {"share": "docker", "snapshot": "GMT+01-2026.11.01-03.00.00"}, "SYNO.Core.Share.Snapshot", "delete",
     {"snapshots": '["GMT+01-2026.11.01-03.00.00"]'}),
    ("security_scan", {}, "SYNO.Core.SecurityScan.Operation", "start", {"items": '"ALL"'}),
])
def test_actions_call_the_right_api(dsm, name, p, api, method, sent):
    out = build("synology", CFG).action(name, p)
    assert out["message"]
    call = dsm.calls[-1]
    assert (call["api"], call["method"]) == (api, method) and call["_sid"] == "sid1"
    assert {k: call.get(k) for k in sent} == sent


def test_actions_need_control_and_valid_targets(dsm):
    with pytest.raises(IntegrationError, match="turned off"):
        build("synology", {**CFG, "allow_control": False}).action("system_reboot", {})
    n = build("synology", CFG)
    for name, p, msg in [("container_stop", {"container": "a b"}, "Invalid container"),
                         ("package_start", {"package": "../x"}, "Invalid package"),
                         ("backup_run", {"task": "x"}, "must be a number"),
                         ("snapshot_delete", {"share": "docker", "snapshot": "yesterday"}, "Invalid snapshot"),
                         ("snapshot_create", {"share": "a/b"}, "Invalid shared folder"),
                         ("rm_rf", {}, "Unknown Synology action")]:
        with pytest.raises(IntegrationError, match=msg):
            n.action(name, p)
    assert not [c for c in dsm.calls if c.get("method") in ("stop", "start", "backup", "delete")]


def test_read_ops_work_without_control(dsm):
    dsm.data[("SYNO.Storage.CGI.Smart", "get_smart_info")] = {"healthInfo": {"overview": "normal"},
                                                               "smart_info": [{"id": 5, "name": "Reallocated_Sector_Ct", "current": 100, "raw": "0", "status": "OK"}]}
    out = build("synology", {**CFG, "allow_control": False}).action("disk_smart", {"disk": "sata1"})
    assert out["attributes"][0]["name"] == "Reallocated_Sector_Ct" and dsm.calls[-1]["device"] == '"/dev/sata1"'


# ------------------------------------------------------------------ pages
def _data():
    with respx.mock:
        fake = FakeDsm()
        respx.route(url__startswith=BASE).mock(side_effect=fake)
        n = build("synology", CFG)
        n.collect()
    syno._SESSIONS.clear()
    return n.data


@pytest.fixture
def box(app):
    state = app.state.lw
    with state.db.session() as s:
        p = Poller(name="site-a", key_hash="k" * 64, features=["rpc"])
        s.add(p)
        s.flush()
        i = Integration(kind="synology", name="Home NAS", poller_id=p.id, status="ok", config_enc=state.vault.seal(CFG), data=_data())
        s.add(i)
        s.flush()
        pid, iid = p.id, i.id
    state.hub.conns[pid] = object()
    calls = []

    def fake_call(poller_id, payload, timeout=60):
        calls.append(payload)
        if payload["action"] == "disk_smart":
            return {"disk": "sata1", "health": {"overview": "normal"}, "attributes": [{"id": 194, "name": "Temperature_Celsius", "current": 36}]}
        if payload["action"] == "container_start" and payload["params"].get("container") == "broken":
            raise RpcError("SYNO.Docker.Container start: error 1400")
        return {"message": f"{payload['action']} ok"}
    state.hub.call_sync = fake_call
    yield {"iid": iid, "pid": pid, "calls": calls}
    state.hub.conns.pop(pid, None)


def test_nas_pages(logged_in, box):
    iid = box["iid"]
    r = logged_in.get("/nas", follow_redirects=False)
    assert r.headers["location"] == f"/nas/{iid}"                   # one NAS: straight to it
    page = logged_in.get(f"/nas/{iid}").text
    assert ">NAS</span>" in page and "vault" in page and "DS920+" in page and "Needs attention" in page
    assert "/volume1 is 95% full" in page and "DSM 7.2.2-72806 available" in page
    assert 'value="system_reboot"' in page and 'data-confirm="typed" data-expect="vault"' in page
    storage = logged_in.get(f"/nas/{iid}?tab=storage").text
    assert "Storage Pool 1" in storage and "WD40EFRX" in storage and 'value="scrub_start"' in storage
    shares = logged_in.get(f"/nas/{iid}?tab=shares").text
    assert "GMT+01-2026.11.01-03.00.00" in shares and 'value="snapshot_create"' in shares
    assert shares.count('value="snapshot_delete"') == 1               # the locked snapshot has no delete button
    apps = logged_in.get(f"/nas/{iid}?tab=apps").text
    assert "plexinc/pms-docker" in apps and 'value="container_restart"' in apps and 'value="package_start"' in apps
    assert "win11" in logged_in.get(f"/nas/{iid}?tab=vms").text
    backups = logged_in.get(f"/nas/{iid}?tab=backups").text
    assert "To B2" in backups and 'value="backup_run"' in backups
    users = logged_in.get(f"/nas/{iid}?tab=users").text
    assert "10.10.5.50" in users and "Run scan now" in users
    disk = logged_in.get(f"/nas/{iid}/disk/sata1").text
    assert "Temperature_Celsius" in disk and box["calls"][-1]["params"] == {"disk": "sata1"}
    assert logged_in.get(f"/nas/{iid}/disk/..%2Fetc").status_code == 404
    assert f'href="/nas/{iid}">NAS controls</a>' in logged_in.get(f"/integrations/{iid}/overview").text


def _post(client, iid, **data):
    return client.post(f"/nas/{iid}/action", data={"back": f"/nas/{iid}?tab=apps", **data}, follow_redirects=False)


def test_actions_are_confirmed_audited_and_admin_only(app, logged_in, box):
    iid, calls = box["iid"], box["calls"]
    _post(logged_in, iid, action="container_stop", container="plex")              # needs confirming
    assert not calls
    r = _post(logged_in, iid, action="container_stop", container="plex", confirm="yes")
    assert calls[-1] == {"op": "integration_action", "integration_id": iid, "action": "container_stop",
                         "params": {"container": "plex"}, "refresh": True}
    assert r.headers["location"] == f"/nas/{iid}?tab=apps"
    n = len(calls)
    _post(logged_in, iid, action="system_reboot", confirm="yes", confirm_text="Home NAS")   # must type the DSM name
    assert len(calls) == n
    _post(logged_in, iid, action="system_reboot", confirm="yes", confirm_text="vault")
    assert calls[-1]["action"] == "system_reboot"
    _post(logged_in, iid, action="snapshot_create", share="docker", description="x", has_lock="1")
    assert calls[-1]["params"] == {"share": "docker", "description": "x", "lock": "0"}
    _post(logged_in, iid, action="container_start", container="broken")
    with app.state.lw.db.session() as s:
        acts = [(a.action, a.detail) for a in s.scalars(select(AuditEvent).where(AuditEvent.action.like("Synology%")))]
        assert ("Synology: stop", "container plex on Home NAS: container_stop ok") in acts
        assert ("Synology: reboot nas", "NAS vault on Home NAS: system_reboot ok") in acts
        assert any(a == "Synology start failed" and "error 1400" in d for a, d in acts)
        assert s.scalar(select(Event).where(Event.message.like("admin: Reboot NAS NAS vault%")))
    r = logged_in.post(f"/nas/{iid}/action", data={"action": "package_start", "package": "x", "back": "https://evil.example/"}, follow_redirects=False)
    assert r.headers["location"] == f"/nas/{iid}"

    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    from fastapi.testclient import TestClient
    viewer = TestClient(app)
    viewer.post("/login", data={"username": "noc", "password": "noc-password-123"})
    n = len(calls)
    page = viewer.get(f"/nas/{iid}?tab=apps").text
    assert "plex" in page and 'name="action"' not in page
    viewer.post(f"/nas/{iid}/action", data={"action": "package_start", "package": "HyperBackup"})
    assert len(calls) == n


def test_control_off_makes_pages_read_only(app, logged_in, box):
    with app.state.lw.db.session() as s:
        s.get(Integration, box["iid"]).config_enc = app.state.lw.vault.seal({**CFG, "allow_control": False})
    page = logged_in.get(f"/nas/{box['iid']}").text
    assert "Control actions are off" in page and 'value="system_reboot"' not in page
    _post(logged_in, box["iid"], action="package_start", package="HyperBackup")
    assert not box["calls"]


def test_offline_poller_shows_last_sync(app, logged_in, box):
    app.state.lw.hub.conns.pop(box["pid"])
    page = logged_in.get(f"/nas/{box['iid']}?tab=apps").text
    assert "is not connected" in page and "plex" in page and 'value="container_stop"' not in page


def test_no_menu_without_a_nas(logged_in):
    assert ">NAS</span>" not in logged_in.get("/").text
    assert "No NAS connected" in logged_in.get("/nas").text
