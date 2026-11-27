"""Proxmox VE: inventory, actions, the Hypervisors pages, the poller request channel and text consoles.

None of this has been run against a real Proxmox cluster; the API shapes follow the PVE 8 API viewer."""
import asyncio
import json
import re
import time
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from sqlalchemy import select
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from linkwatch.integrations import IntegrationError, build
from linkwatch.integrations.proxmox import Proxmox, upid_node
from linkwatch.poller import pveterm
from linkwatch.server.gateway import RpcError
from linkwatch.server.models import AuditEvent, Event, Integration, Poller

API = "https://10.10.5.11:8006/api2/json"
CFG = {"host": "10.10.5.11", "token_id": "lw@pve!ops", "token_secret": "s3cret", "allow_control": True}
UPID = "UPID:pve-01:0000A1B2:0012C3D4:6745F00D:qmshutdown:101:lw@pve!ops:"


def form(call) -> dict:
    return {k: v[0] for k, v in parse_qs(call.request.content.decode()).items()}


# ------------------------------------------------------------------ integration
@respx.mock
def test_collect_lists_every_guest_for_the_hypervisor_pages():
    respx.get(f"{API}/cluster/resources").mock(return_value=httpx.Response(200, json={"data": [
        {"type": "node", "node": "pve-01", "status": "online", "cpu": 0.1, "mem": 1, "maxmem": 4, "maxcpu": 8},
        {"type": "qemu", "vmid": 101, "name": "web", "status": "running", "node": "pve-01", "cpu": 0.25, "mem": 1, "maxmem": 4,
         "tags": "prod;web", "hastate": "started"},
        {"type": "qemu", "vmid": 9000, "name": "tmpl-debian", "status": "stopped", "node": "pve-01", "template": 1},
        {"type": "lxc", "vmid": 102, "name": "dns", "status": "stopped", "node": "pve-01", "lock": "backup"}]}))
    respx.get(f"{API}/cluster/status").mock(return_value=httpx.Response(200, json={"data": []}))
    p = build("proxmox", CFG)
    recs = p.collect()
    assert [r["external_id"] for r in recs] == ["node-pve-01", "qemu-101", "lxc-102"]     # templates aren't devices
    vms = {v["vmid"]: v for v in p.data["vms"]}
    assert set(vms) == {101, 102, 9000} and vms[9000]["template"] is True
    assert vms[101]["tags"] == ["prod", "web"] and vms[101]["cpu"] == 25.0 and vms[101]["hastate"] == "started"
    assert vms[102]["cpu"] is None and vms[102]["lock"] == "backup"
    assert p.data["guests"]["templates"] == 1 and p.data["control"] is True


@respx.mock
def test_power_actions_post_to_the_right_endpoint():
    route = respx.post(f"{API}/nodes/pve-01/qemu/101/status/shutdown").mock(return_value=httpx.Response(200, json={"data": UPID}))
    out = build("proxmox", CFG).action("shutdown", {"node": "pve-01", "type": "qemu", "vmid": "101"})
    assert out == {"upid": UPID, "message": "Shut down requested."}
    assert route.calls[0].request.headers["Authorization"] == "PVEAPIToken=lw@pve!ops=s3cret"
    assert form(route.calls[0]) == {"timeout": "180"}
    hib = respx.post(f"{API}/nodes/pve-01/qemu/101/status/suspend").mock(return_value=httpx.Response(200, json={"data": UPID}))
    build("proxmox", CFG).action("hibernate", {"node": "pve-01", "type": "qemu", "vmid": 101})
    assert form(hib.calls[0]) == {"todisk": "1"}


def test_actions_need_control_switched_on_and_valid_parameters():
    ro = build("proxmox", {**CFG, "allow_control": False})
    with pytest.raises(IntegrationError, match="turned off"):
        ro.action("start", {"node": "pve-01", "type": "qemu", "vmid": 101})
    p = build("proxmox", CFG)
    for params, msg in [({"node": "../../access", "type": "qemu", "vmid": 101}, "Invalid node"),
                        ({"node": "pve-01", "type": "qemu", "vmid": "101/../../x"}, "VMID must be a number"),
                        ({"node": "pve-01", "type": "openvz", "vmid": 101}, "isn't available"),
                        ({"node": "pve-01", "type": "lxc", "vmid": 101}, "isn't available")]:   # reset is VM-only
        with pytest.raises(IntegrationError, match=msg):
            p.action("reset", params)
    with pytest.raises(IntegrationError, match="Invalid snapshot"):
        p.action("snapshot_delete", {"node": "pve-01", "type": "qemu", "vmid": 101, "snapname": "x/../../y"})
    with pytest.raises(IntegrationError, match="Unknown Proxmox action"):
        p.action("rm_rf", {})


@respx.mock
def test_lifecycle_actions_send_proxmox_parameters():
    p = build("proxmox", CFG)
    g = {"node": "pve-01", "type": "qemu", "vmid": 101}
    mig = respx.post(f"{API}/nodes/pve-01/qemu/101/migrate").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("migrate", {**g, "target": "pve-02", "online": "1", "with_local_disks": "1"})
    assert form(mig.calls[0]) == {"target": "pve-02", "online": "1", "with-local-disks": "1"}
    ct_mig = respx.post(f"{API}/nodes/pve-01/lxc/102/migrate").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("migrate", {"node": "pve-01", "type": "lxc", "vmid": 102, "target": "pve-02"})
    assert form(ct_mig.calls[0]) == {"target": "pve-02", "restart": "1"}
    clone = respx.post(f"{API}/nodes/pve-01/qemu/101/clone").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("clone", {**g, "newid": "150", "name": "web-clone", "target": "pve-02", "storage": "local-zfs", "full": "1"})
    assert form(clone.calls[0]) == {"newid": "150", "full": "1", "name": "web-clone", "target": "pve-02", "storage": "local-zfs"}
    ct_clone = respx.post(f"{API}/nodes/pve-01/lxc/102/clone").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("clone", {"node": "pve-01", "type": "lxc", "vmid": 102, "newid": 151, "name": "dns2", "full": "0"})
    assert form(ct_clone.calls[0])["hostname"] == "dns2"
    snap = respx.post(f"{API}/nodes/pve-01/qemu/101/snapshot").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("snapshot_create", {**g, "snapname": "pre-upgrade", "description": "before 12.4", "vmstate": "1"})
    assert form(snap.calls[0]) == {"snapname": "pre-upgrade", "description": "before 12.4", "vmstate": "1"}
    rb = respx.post(f"{API}/nodes/pve-01/qemu/101/snapshot/pre-upgrade/rollback").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("snapshot_rollback", {**g, "snapname": "pre-upgrade"})
    assert rb.called
    dump = respx.post(f"{API}/nodes/pve-01/vzdump").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("backup", {**g, "storage": "pbs", "mode": "snapshot"})
    assert form(dump.calls[0]) == {"vmid": "101", "storage": "pbs", "mode": "snapshot", "compress": "zstd"}
    rest = respx.post(f"{API}/nodes/pve-01/qemu").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("restore", {**g, "volid": "pbs:backup/vm/101/2026-11-01T00:00:00Z", "newid": 152})
    assert form(rest.calls[0]) == {"vmid": "152", "archive": "pbs:backup/vm/101/2026-11-01T00:00:00Z", "unique": "1"}
    with pytest.raises(IntegrationError, match="new VMID"):
        p.action("restore", {**g, "volid": "pbs:backup/x", "newid": 101})
    cfg = respx.put(f"{API}/nodes/pve-01/qemu/101/config").mock(return_value=httpx.Response(200, json={"data": None}))
    assert p.action("resize", {**g, "cores": "4", "memory": "8192"}) == {"upid": None, "message": "Set 4 cores and 8192 MiB."}
    assert form(cfg.calls[0]) == {"cores": "4", "memory": "8192"}
    grow = respx.put(f"{API}/nodes/pve-01/qemu/101/resize").mock(return_value=httpx.Response(200, json={"data": None}))
    p.action("disk_grow", {**g, "disk": "scsi0", "size": "10g"})
    assert form(grow.calls[0]) == {"disk": "scsi0", "size": "+10G"}
    with pytest.raises(IntegrationError, match="Invalid size"):
        p.action("disk_grow", {**g, "disk": "scsi0", "size": "-10G"})
    dele = respx.delete(f"{API}/nodes/pve-01/qemu/101").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("delete", {**g, "purge": "1"})
    assert dict(dele.calls[0].request.url.params) == {"purge": "1", "destroy-unreferenced-disks": "1"}
    node = respx.post(f"{API}/nodes/pve-01/status").mock(return_value=httpx.Response(200, json={"data": None}))
    assert p.action("node_reboot", {"node": "pve-01"})["message"] == "pve-01 is rebooting."
    assert form(node.calls[0]) == {"command": "reboot"}
    ma = respx.post(f"{API}/nodes/pve-01/migrateall").mock(return_value=httpx.Response(200, json={"data": UPID}))
    p.action("node_migrateall", {"node": "pve-01", "target": "pve-02"})
    assert form(ma.calls[0]) == {"target": "pve-02"}


@respx.mock
def test_proxmox_errors_reach_the_admin():
    respx.post(f"{API}/nodes/pve-01/qemu/101/status/start").mock(
        return_value=httpx.Response(403, extensions={"reason_phrase": b"Permission check failed (/vms/101, VM.PowerMgmt)"}))
    with pytest.raises(IntegrationError, match=r"lacks a privilege .*VM.PowerMgmt"):
        build("proxmox", CFG).action("start", {"node": "pve-01", "type": "qemu", "vmid": 101})
    respx.post(f"{API}/nodes/pve-01/qemu/101/migrate").mock(return_value=httpx.Response(
        400, json={"errors": {"target": "target is local node."}, "data": None}))
    with pytest.raises(IntegrationError, match="target: target is local node"):
        build("proxmox", CFG).action("migrate", {"node": "pve-01", "type": "qemu", "vmid": 101, "target": "pve-02"})


@respx.mock
def test_guest_detail_gathers_everything_and_tolerates_missing_privileges():
    g = f"{API}/nodes/pve-01/qemu/101"
    respx.get(f"{g}/status/current").mock(return_value=httpx.Response(200, json={"data": {
        "status": "running", "name": "web", "cpu": 0.12, "cpus": 4, "mem": 2 * 2**30, "maxmem": 8 * 2**30, "uptime": 3600, "ha": {"managed": 0}}}))
    respx.get(f"{g}/config").mock(return_value=httpx.Response(200, json={"data": {
        "cores": 4, "memory": 8192, "scsi0": "local-zfs:vm-101-disk-0,size=32G", "ide2": "none,media=cdrom", "net0": "virtio=AA:BB,bridge=vmbr0",
        "serial0": "socket", "cipassword": "**********", "unused0": "local-zfs:vm-101-disk-9"}}))
    respx.get(f"{g}/snapshot").mock(return_value=httpx.Response(200, json={"data": [
        {"name": "pre-upgrade", "snaptime": 1700000000, "description": "x"}, {"name": "current", "parent": "pre-upgrade"}]}))
    respx.get(f"{API}/nodes").mock(return_value=httpx.Response(200, json={"data": [{"node": "pve-02", "status": "online"}, {"node": "pve-01", "status": "online"}]}))
    respx.get(f"{API}/nodes/pve-01/storage").mock(return_value=httpx.Response(200, json={"data": [
        {"storage": "local-zfs", "content": "images,rootdir", "active": 1}, {"storage": "pbs", "content": "backup", "active": 1}]}))
    respx.get(f"{g}/migrate").mock(return_value=httpx.Response(403, extensions={"reason_phrase": b"Permission check failed"}))
    respx.get(f"{API}/nodes/pve-01/storage/pbs/content").mock(return_value=httpx.Response(200, json={"data": [
        {"volid": "pbs:backup/vm/101/2026-11-01T00:00:00Z", "ctime": 1761955200, "size": 5 * 2**30}]}))
    respx.get(f"{API}/cluster/nextid").mock(return_value=httpx.Response(200, json={"data": "152"}))
    respx.get(f"{API}/cluster/tasks").mock(return_value=httpx.Response(200, json={"data": [
        {"upid": UPID, "type": "qmshutdown", "id": "101", "node": "pve-01", "starttime": 5, "endtime": 6, "status": "OK"},
        {"upid": "x", "type": "vzdump", "id": "102", "node": "pve-01", "starttime": 7}]}))
    d = build("proxmox", {**CFG, "allow_control": False}).action("guest_detail", {"node": "pve-01", "type": "qemu", "vmid": 101})
    assert d["status"]["name"] == "web" and d["serial"] is True
    assert "cipassword" not in d["config"] and "unused0" not in d["config"]
    assert d["disks"] == {"scsi0": "local-zfs:vm-101-disk-0,size=32G"} and list(d["nets"]) == ["net0"]
    assert [s["name"] for s in d["snapshots"]] == ["pre-upgrade"] and d["snapshot_parent"] == "pre-upgrade"
    assert [n["name"] for n in d["nodes"]] == ["pve-01", "pve-02"]
    assert d["backups"][0]["storage"] == "pbs" and d["nextid"] == "152"
    assert [t["type"] for t in d["tasks"]] == ["qmshutdown"]
    assert d["migrate"] is None and any("Migration check" in u for u in d["unavailable"])


@respx.mock
def test_task_status_and_log():
    assert upid_node(UPID) == "pve-01"
    with pytest.raises(IntegrationError):
        upid_node("UPID:../../etc:1")
    q = "UPID%3Apve-01%3A0000A1B2%3A0012C3D4%3A6745F00D%3Aqmshutdown%3A101%3Alw%40pve%21ops%3A"
    respx.get(f"{API}/nodes/pve-01/tasks/{q}/status").mock(return_value=httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK", "type": "qmshutdown"}}))
    respx.get(f"{API}/nodes/pve-01/tasks/{q}/log").mock(return_value=httpx.Response(200, json={"data": [{"n": 1, "t": "shutting down"}, {"n": 2, "t": "TASK OK"}]}))
    t = build("proxmox", CFG).action("task", {"upid": UPID})
    assert t["status"] == "stopped" and t["exitstatus"] == "OK" and t["log"] == ["shutting down", "TASK OK"]


def test_termproxy_framing():
    assert pveterm.frame_input("é".encode()) == b"0:2:\xc3\xa9"
    assert pveterm.frame_resize(120, 40) == b"1:120:40:"


# ------------------------------------------------------------------ pages and actions (poller faked)
VMS = [{"vmid": 101, "name": "web", "type": "qemu", "node": "pve-01", "status": "running", "template": False, "cpu": 12.0, "mem": 1,
        "maxmem": 4, "tags": ["prod"], "uptime_s": 60},
       {"vmid": 102, "name": "dns", "type": "lxc", "node": "pve-01", "status": "stopped", "template": False, "tags": []},
       {"vmid": 9000, "name": "tmpl", "type": "qemu", "node": "pve-01", "status": "stopped", "template": True, "tags": []}]
DETAIL = {"status": {"status": "running", "name": "web", "cpu": 0.1, "cpus": 2, "mem": 1, "maxmem": 4, "uptime": 60},
          "config": {"cores": 2, "memory": 4096, "scsi0": "local-zfs:vm-101-disk-0,size=32G"}, "disks": {"scsi0": "local-zfs:vm-101-disk-0,size=32G"},
          "nets": {}, "serial": False, "snapshots": [{"name": "pre-upgrade", "snaptime": 1700000000}], "snapshot_parent": "pre-upgrade",
          "nodes": [{"name": "pve-01", "status": "online"}, {"name": "pve-02", "status": "online"}],
          "storages": [{"name": "pbs", "content": ["backup"], "active": True}], "backups": [], "nextid": "150", "tasks": [],
          "migrate": {"allowed": ["pve-02"], "not_allowed": {}, "local_disks": []}, "unavailable": []}


@pytest.fixture
def cluster(app):
    """A Proxmox integration on a 'connected' poller, with the poller request channel replaced by a recorder."""
    state = app.state.lw
    with state.db.session() as s:
        p = Poller(name="site-a", key_hash="k" * 64, features=["rpc", "pveterm", "ssh"])
        s.add(p)
        s.flush()
        i = Integration(kind="proxmox", name="Lab cluster", poller_id=p.id, status="ok", config_enc=state.vault.seal(CFG),
                        data={"type": "proxmox", "nodes": [{"name": "pve-01", "status": "online", "cpu": 5, "mem": 1, "maxmem": 4,
                                                            "guests": 2, "running": 1}], "vms": VMS, "guests": {}})
        s.add(i)
        s.flush()
        pid, iid = p.id, i.id
    state.hub.conns[pid] = object()
    calls = []

    def fake_call(poller_id, payload, timeout=60):
        calls.append(payload)
        a = payload["action"]
        if a == "guest_detail":
            return DETAIL
        if a == "node_detail":
            return {"status": {"cpu": 0.1}, "storages": [], "nodes": DETAIL["nodes"], "tasks": [], "unavailable": []}
        if a == "tasks":
            return {"tasks": [{"upid": UPID, "type": "qmshutdown", "id": "101", "node": "pve-01", "status": "OK", "start": 1}]}
        if a == "task":
            return {"status": "stopped", "exitstatus": "OK", "log": ["TASK OK"]}
        if a == "start" and payload["params"]["vmid"] == "666":
            raise RpcError("VM 666 does not exist")
        return {"upid": UPID if a not in ("resize",) else None, "message": f"{a} ok"}
    state.hub.call_sync = fake_call
    yield {"iid": iid, "pid": pid, "calls": calls}
    state.hub.conns.pop(pid, None)


def test_hypervisor_pages(logged_in, cluster):
    iid = cluster["iid"]
    page = logged_in.get("/hypervisors").text
    assert "Hypervisors" in page and "All virtual machines" in page        # menu
    assert ">web</a>" in page and ">dns</a>" in page and ">tmpl</a>" not in page
    assert 'value="shutdown"' in page and 'value="start"' in page and 'data-confirm="yes"' in page
    assert ">tmpl</a>" in logged_in.get("/hypervisors?type=template").text
    assert ">dns</a>" not in logged_in.get("/hypervisors?status=running").text
    g = logged_in.get(f"/hypervisors/{iid}/guest/qemu/101").text
    assert "pre-upgrade" in g and "Migrate" in g and 'value="150"' in g and "Danger zone" in g
    assert cluster["calls"][-1]["params"] == {"node": "pve-01", "type": "qemu", "vmid": 101}
    assert "Console (Proxmox)" in g                                         # no serial port: graphical console link
    assert "Guests on pve-01" in logged_in.get(f"/hypervisors/{iid}/node/pve-01").text
    assert "qmshutdown" in logged_in.get(f"/hypervisors/{iid}/tasks").text
    assert logged_in.get(f"/ui/hypervisors/{iid}/task", params={"upid": UPID}).json()["exitstatus"] == "OK"
    assert logged_in.get(f"/ui/hypervisors/{iid}/task", params={"upid": "nope"}).status_code == 400
    c = logged_in.get(f"/hypervisors/console?i={iid}&node=pve-01&type=lxc&vmid=102")
    assert c.status_code == 200 and "/static/pveconsole.js" in c.text
    assert f'href="/hypervisors?i={iid}">Virtual machines</a>' in logged_in.get(f"/integrations/{iid}/overview").text


def _post(client, iid, **data):
    return client.post(f"/hypervisors/{iid}/action", data={"back": f"/hypervisors/{iid}/guest/qemu/101", **data}, follow_redirects=False)


def test_actions_are_confirmed_audited_and_admin_only(app, logged_in, cluster):
    iid, calls = cluster["iid"], cluster["calls"]
    g = {"node": "pve-01", "type": "qemu", "vmid": "101"}
    # destructive without confirming: refused, nothing sent
    r = _post(logged_in, iid, action="stop", **g)
    assert r.status_code == 303 and not calls
    # confirmed: sent, audited, and the page follows the task
    r = _post(logged_in, iid, action="stop", confirm="yes", **g)
    assert calls[-1] == {"op": "integration_action", "integration_id": iid, "action": "stop",
                         "params": {"node": "pve-01", "type": "qemu", "vmid": "101"}, "refresh": True}
    assert "task=UPID%3Apve-01" in r.headers["location"]
    # typed confirmation for delete
    n = len(calls)
    _post(logged_in, iid, action="delete", confirm="yes", confirm_text="102", has_purge="1", purge="on", **g)
    assert len(calls) == n
    r = _post(logged_in, iid, action="delete", confirm="yes", confirm_text="101", has_purge="1", purge="on", **g)
    assert calls[-1]["params"]["purge"] == "1" and r.headers["location"].startswith("/hypervisors?task=")
    # options: unticked boxes are sent as 0
    _post(logged_in, iid, action="migrate", confirm="yes", target="pve-02", has_online="1", has_with_local_disks="1", with_local_disks="on", **g)
    assert calls[-1]["params"] | {} == {**g, "target": "pve-02", "online": "0", "with_local_disks": "1"}
    # a failure is shown and audited
    _post(logged_in, iid, action="start", node="pve-01", type="qemu", vmid="666")
    with app.state.lw.db.session() as s:
        acts = [(a.action, a.detail) for a in s.scalars(select(AuditEvent).where(AuditEvent.action.like("Proxmox%")))]
        assert ("Proxmox: stop", "VM 101 (web) on pve-01 on Lab cluster: stop ok (task " + UPID + ")") in acts
        assert any(a == "Proxmox start failed" and "VM 666 does not exist" in d for a, d in acts)
        assert any(a == "Proxmox: delete guest" for a, _ in acts)
        assert s.scalar(select(Event).where(Event.message.like("admin: Stop VM 101%")))
    # back= can't redirect off-site
    r = logged_in.post(f"/hypervisors/{iid}/action", data={"action": "start", "back": "https://evil.example/", **g}, follow_redirects=False)
    assert r.headers["location"].startswith("/hypervisors")

    # viewers see no buttons and can't post
    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    from fastapi.testclient import TestClient
    viewer = TestClient(app)
    viewer.post("/login", data={"username": "noc", "password": "noc-password-123"})
    n = len(calls)
    page = viewer.get("/hypervisors").text
    assert ">web</a>" in page and 'value="shutdown"' not in page
    assert 'name="action"' not in viewer.get(f"/hypervisors/{iid}/guest/qemu/101").text
    viewer.post(f"/hypervisors/{iid}/action", data={"action": "start", **g})
    assert len(calls) == n + 1 and calls[-1]["action"] == "guest_detail"      # only the page view above went out
    assert viewer.get(f"/hypervisors/console?i={iid}&node=pve-01").status_code == 403


def test_control_switch_off_makes_pages_read_only(app, logged_in, cluster):
    with app.state.lw.db.session() as s:
        i = s.get(Integration, cluster["iid"])
        i.config_enc = app.state.lw.vault.seal({**CFG, "allow_control": False})
    page = logged_in.get("/hypervisors").text
    assert "Control actions are off" in page and 'value="shutdown"' not in page
    _post(logged_in, cluster["iid"], action="start", node="pve-01", type="qemu", vmid="101")
    assert not [c for c in cluster["calls"] if c["action"] == "start"]
    assert "Tick “Allow control actions”" in logged_in.get(f"/hypervisors/console?i={cluster['iid']}&node=pve-01").text


def test_offline_poller_shows_cached_inventory(app, logged_in, cluster):
    app.state.lw.hub.conns.pop(cluster["pid"])
    page = logged_in.get(f"/hypervisors/{cluster['iid']}/guest/qemu/101").text
    assert "is not connected" in page and ">web" in page and 'value="shutdown"' not in page


def test_no_menu_without_proxmox(logged_in):
    assert "All virtual machines" not in logged_in.get("/").text
    assert "No hypervisors connected" in logged_in.get("/hypervisors").text


# ------------------------------------------------------------------ end to end: real server, real poller
from tests.linkwatch.test_ssh import _free_port  # noqa: E402  (live_server comes from conftest)


async def _enroll(base, app, tmp_path, name="site-a"):
    async with httpx.AsyncClient(base_url=base, follow_redirects=True) as http:
        await http.post("/login", data={"username": "admin", "password": "pw-for-tests"})
        page = (await http.post("/pollers/token")).text
        token = re.search(r"LW_ENROLL_TOKEN=(\S+) ", page).group(1)
        cookie = "lw_session=" + http.cookies["lw_session"]
    from linkwatch.poller.main import Poller as LanPoller
    lan = LanPoller(base, tmp_path / "poller", enroll_token=token, name=name)
    task = asyncio.create_task(lan.run())
    for _ in range(200):
        if app.state.lw.hub.conns:
            pid = next(iter(app.state.lw.hub.conns))
            with app.state.lw.db.session() as s:
                if "rpc" in (s.get(Poller, pid).features or []):
                    return lan, task, pid, cookie
        await asyncio.sleep(0.05)
    raise AssertionError("poller did not connect")


def _add_integration(app, pid, cfg) -> int:
    with app.state.lw.db.session() as s:
        i = Integration(kind="proxmox", name="Lab", poller_id=pid, config_enc=app.state.lw.vault.seal(cfg), status="ok",
                        data={"vms": VMS, "nodes": []})
        s.add(i)
        s.flush()
        return i.id


def test_rpc_end_to_end(app, live_server, tmp_path, monkeypatch):
    seen = []

    def fake_action(self, name, params):
        seen.append((name, params, self.config["token_id"]))
        if name == "boom":
            raise IntegrationError("Proxmox said no")
        return {"upid": UPID, "message": "ok"}
    monkeypatch.setattr(Proxmox, "action", fake_action)

    async def scenario():
        lan, task, pid, _ = await _enroll(live_server, app, tmp_path)
        iid = _add_integration(app, pid, CFG)
        await asyncio.to_thread(lambda: asyncio.run_coroutine_threadsafe(app.state.lw.hub.push_config(pid), app.state.lw.hub.loop).result(5))
        for _ in range(100):
            if any(i["id"] == iid for i in lan.integrations):
                break
            await asyncio.sleep(0.05)
        hub = app.state.lw.hub
        payload = {"op": "integration_action", "integration_id": iid, "action": "shutdown", "params": {"node": "pve-01"}}
        out = await asyncio.to_thread(hub.call_sync, pid, payload, 10)
        assert out == {"upid": UPID, "message": "ok"} and seen[-1] == ("shutdown", {"node": "pve-01"}, "lw@pve!ops")
        with pytest.raises(RpcError, match="Proxmox said no"):
            await asyncio.to_thread(hub.call_sync, pid, {**payload, "action": "boom"}, 10)
        with pytest.raises(RpcError, match="doesn't run that integration"):
            await asyncio.to_thread(hub.call_sync, pid, {**payload, "integration_id": 999}, 10)
        task.cancel()
    asyncio.run(scenario())


def test_proxmox_console_end_to_end(app, live_server, tmp_path, monkeypatch):
    """Browser -> server -> poller -> a fake Proxmox termproxy WebSocket, and back."""
    monkeypatch.delenv("LW_TUNNEL", raising=False)
    received: list = []

    async def pve_handler(conn):
        received.append(("path", conn.request.path, conn.request.headers.get("Authorization")))
        auth = await conn.recv()
        received.append(("auth", auth))
        await conn.send(b"OK")
        await conn.send(b"root@dns:~# ")
        async for m in conn:
            received.append(("in", m))
            if isinstance(m, bytes) and m.startswith(b"0:"):
                await conn.send(b"echo:" + m.split(b":", 2)[2])

    def fake_termproxy(self, node, vtype, vmid):
        return f"/nodes/{node}/{vtype}/{vmid}/vncwebsocket", {"port": 5900, "ticket": "PVEVNC:abc+/=", "user": "lw@pve!ops"}
    monkeypatch.setattr(Proxmox, "termproxy", fake_termproxy)

    async def scenario():
        pve_port = _free_port()
        async with serve(pve_handler, "127.0.0.1", pve_port):
            lan, task, pid, cookie = await _enroll(live_server, app, tmp_path)
            iid = _add_integration(app, pid, {**CFG, "host": f"http://127.0.0.1:{pve_port}"})
            await asyncio.to_thread(lambda: asyncio.run_coroutine_threadsafe(app.state.lw.hub.push_config(pid), app.state.lw.hub.loop).result(5))
            for _ in range(100):
                if any(i["id"] == iid for i in lan.integrations):
                    break
                await asyncio.sleep(0.05)
            url = live_server.replace("http://", "ws://") + "/api/poller/ws/pveconsole"
            out, msgs = b"", []
            async with connect(url, additional_headers={"Cookie": cookie, "Origin": live_server}) as ws:
                await ws.send(json.dumps({"integration": iid, "node": "pve-01", "type": "lxc", "vmid": 102, "cols": 100, "rows": 30}))
                deadline = time.monotonic() + 15
                sent = False
                while time.monotonic() < deadline:
                    m = await asyncio.wait_for(ws.recv(), 15)
                    if isinstance(m, bytes):
                        out += m
                        if b"echo:ls" in out:
                            break
                        continue
                    m = json.loads(m)
                    msgs.append(m)
                    assert m["type"] != "error", m
                    if m["type"] == "ready" and not sent:
                        await ws.send(json.dumps({"type": "resize", "cols": 120, "rows": 40}))
                        await ws.send(b"ls\r")
                        sent = True
                await ws.send(json.dumps({"type": "close"}))
                try:
                    while True:
                        m = await asyncio.wait_for(ws.recv(), 5)
                        if isinstance(m, str) and json.loads(m)["type"] == "closed":
                            break
                except Exception:
                    pass
            assert b"root@dns:~# " in out and b"echo:ls\r" in out
            path = received[0]
            assert path[1] == "/api2/json/nodes/pve-01/lxc/102/vncwebsocket?port=5900&vncticket=PVEVNC%3Aabc%2B%2F%3D"
            assert path[2] == "PVEAPIToken=lw@pve!ops=s3cret"
            assert received[1] == ("auth", b"lw@pve!ops:PVEVNC:abc+/=\n")
            ins = [r[1] for r in received if r[0] == "in"]
            assert b"1:100:30:" in ins and b"1:120:40:" in ins and b"0:3:ls\r" in ins
            task.cancel()
        await asyncio.sleep(0.2)
        with app.state.lw.db.session() as s:
            acts = [a.action for a in s.scalars(select(AuditEvent))]
            assert "opened Proxmox console" in acts and "closed Proxmox console" in acts
    asyncio.run(scenario())
