"""SSH or remote desktop per device, from its operating system, with a per-device override."""
from types import SimpleNamespace as NS

from linkwatch.server.access import access_for, os_family
from linkwatch.server.models import Device

from .test_ssh import _add_device


def dev(**kw):
    base = dict(sys_descr=None, platform=None, sys_object_id=None, type="Other", access=None)
    return NS(**{**base, **kw})


def test_os_family():
    assert os_family(dev(sys_descr="Hardware: Intel64 Family 6 - Software: Windows Version 6.3 (Build 20348 Multiprocessor Free)")) == "windows"
    assert os_family(dev(sys_object_id="1.3.6.1.4.1.311.1.1.3.1.2")) == "windows"
    assert os_family(dev(platform="Windows Server 2022")) == "windows"
    assert os_family(dev(sys_descr="Linux pve01 6.8.12-4-pve #1 SMP x86_64")) == "unix"
    assert os_family(dev(sys_object_id="1.3.6.1.4.1.8072.3.2.10")) == "unix"
    assert os_family(dev(sys_descr="Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10")) == "network"
    assert os_family(dev(sys_descr="Linux edge 5.10 pfSense")) == "network"       # appliance beats the kernel it runs
    assert os_family(dev(type="Switch")) == "network"
    assert os_family(dev(type="Server")) is None


def test_access_rules():
    win = dev(sys_descr="Windows Server 2019")
    a = access_for(win)
    assert (a.ssh, a.rdp) == (False, True) and "runs Windows" in a.why
    a = access_for(dev(sys_descr="Ubuntu 24.04 Linux"))
    assert (a.ssh, a.rdp) == (True, False) and "Linux / Unix" in a.why
    assert (access_for(dev(type="Server")).ssh, access_for(dev(type="Server")).rdp) == (True, True)
    win.access = "both"
    assert (access_for(win).ssh, access_for(win).rdp) == (True, True)
    win.access = "ssh"
    assert (access_for(win).ssh, access_for(win).rdp) == (True, False)
    win.access = "none"
    assert not access_for(win).any


def test_device_page_greys_out_and_override(logged_in, app):
    pid, did = _add_device(app, poller_features=("ssh", "rdp"))
    with app.state.lw.db.session() as s:
        s.get(Device, did).sys_descr = "Hardware: x64 - Software: Windows Version 10.0 (Build 20348)"
    page = logged_in.get(f"/devices/{did}").text
    assert f'href="/rdp?device={did}"' in page and f'href="/ssh?device={did}"' not in page
    assert 'disabled title="This device runs Windows' in page
    # the console pages refuse the greyed-out kind too
    assert "runs Windows" in logged_in.get(f"/ssh?device={did}").text
    r = logged_in.post("/rdp/session", json={"device": did, "username": "a", "password": "b"},
                       headers={"origin": "http://testserver"})
    assert r.status_code == 409                       # allowed kind: only stopped by the poller being offline

    form = logged_in.get(f"/devices/{did}/edit").text
    assert 'name="access"' in form and "Detected: <b>Windows</b>" in form
    logged_in.post(f"/devices/{did}/edit", data={"hostname": "edge-fw", "ip": "10.9.9.1", "type": "Firewall",
                                                 "poller_id": str(pid), "ping": "on", "access": "both"})
    with app.state.lw.db.session() as s:
        assert s.get(Device, did).access == "both"
    page = logged_in.get(f"/devices/{did}").text
    assert f'href="/rdp?device={did}"' in page and f'href="/ssh?device={did}"' in page
    logged_in.post(f"/devices/{did}/edit", data={"hostname": "edge-fw", "ip": "10.9.9.1", "type": "Firewall",
                                                 "poller_id": str(pid), "ping": "on", "access": "auto"})
    with app.state.lw.db.session() as s:
        assert s.get(Device, did).access is None
