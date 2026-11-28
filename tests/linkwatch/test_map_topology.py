"""Network map: duplicates drawn once, API devices placed via UniFi ports, link speeds, WAN uplinks, hand-drawn links."""
from sqlalchemy import select

from linkwatch.server.models import Device, Integration, Neighbor, Port, Site
from linkwatch.server.topology import group_duplicates, norm_port, speed_label


def _by_name(m):
    return {n["name"]: n for n in m["nodes"]}


def test_helpers():
    assert norm_port("GigabitEthernet1/0/1") == norm_port("Gi1/0/1") == norm_port("gi 1/0/1")
    assert norm_port("Port 5") == norm_port("port 5") == "5"
    assert [speed_label(x) for x in (100, 1000, 2500, 10000, 25000, None)] == ["100M", "1G", "2.5G", "10G", "25G", ""]


def test_duplicates_are_drawn_once_and_sites_keep_same_named_boxes_apart(app):
    with app.state.lw.db.session() as s:
        a, b = Site(name="HQ"), Site(name="Branch")
        s.add_all([a, b])
        s.flush()
        ui = Integration(kind="unifi", name="UniFi", config_enc="-")
        s.add(ui)
        s.flush()
        snmp = Device(hostname="10.0.0.2", ip="10.0.0.2", sys_name="lab-sw01.lab.local", type="Switch", source="snmp", status="up", extra={})
        fqdn = Device(hostname="lab-sw01.lab.local", ip="lab-sw01.lab.local", type="Switch", source="snmp", status="up", extra={})
        api = Device(hostname="lab-sw01", type="Switch", source="unifi", integration_id=ui.id, external_id="m1", status="up",
                     extra={"mac": "aa:bb:cc:00:00:01"})
        twin = Device(hostname="soho702", ip="10.9.0.1", type="Firewall", source="snmp", status="up", serial="ABC12345", extra={})
        twin2 = Device(hostname="SOHO702-api", type="Firewall", source="sonicwall", status="up", serial="abc12345", extra={})
        gw1 = Device(hostname="gw", type="Router", site_id=a.id, extra={})
        gw2 = Device(hostname="gw", type="Router", site_id=b.id, extra={})
        vm = Device(hostname="lab-sw01", type="VM", source="proxmox", extra={})
        s.add_all([snmp, fqdn, api, twin, twin2, gw1, gw2, vm])
        s.flush()
        rep = group_duplicates(s.scalars(select(Device)).all())
        assert rep[snmp.id] == rep[fqdn.id] == rep[api.id] == snmp.id       # the polled row speaks for the group
        assert rep[twin.id] == rep[twin2.id] == twin.id
        assert rep[gw1.id] != rep[gw2.id]
        assert vm.id not in rep


def test_map_merges_places_api_devices_and_shows_speeds_and_wans(logged_in, app):
    with app.state.lw.db.session() as s:
        ui = Integration(kind="unifi", name="UniFi", config_enc="-", enabled=True)
        pve = Integration(kind="proxmox", name="PVE", config_enc="-", enabled=True)
        pan = Integration(kind="panos", name="PAN", config_enc="-", enabled=True)
        s.add_all([ui, pve, pan])
        s.flush()
        core = Device(hostname="lab-sw01", ip="10.0.0.2", sys_name="lab-sw01", type="Switch", source="snmp", status="up", extra={})
        core_api = Device(hostname="lab-sw01", type="Switch", source="unifi", integration_id=ui.id, external_id="sw", status="up",
                          extra={"mac": "aa:00:00:00:00:02"})
        gw = Device(hostname="zlabcgwm", type="Router", source="unifi", integration_id=ui.id, external_id="gw", status="up",
                    extra={"mac": "aa:00:00:00:00:01"})
        host = Device(hostname="pve1", ip="10.0.0.10", type="Hypervisor", source="proxmox", integration_id=pve.id,
                      external_id="node-pve1", status="up", extra={})
        fw = Device(hostname="pa-440", ip="192.168.1.1", type="Firewall", source="panos", integration_id=pan.id, external_id="0123",
                    status="up", extra={"ips": ["10.0.0.1"], "macs": ["b4:0c:25:00:00:01"]})
        dist = Device(hostname="dist-sw", ip="10.0.0.3", type="Switch", source="snmp", status="up", extra={})
        s.add_all([core, core_api, gw, host, fw, dist])
        s.flush()
        up = Port(device_id=core.id, ifindex=24, name="Gi1/0/24", speed_mbps=10000, in_bps=2e9, out_bps=1e9, util_pct=20.0)
        down = Port(device_id=dist.id, ifindex=1, name="Te1/1/1", speed_mbps=10000)
        s.add_all([up, down])
        s.flush()
        # the same link from both ends, the far end reported by its short name
        s.add(Neighbor(device_id=core.id, port_id=up.id, protocol="lldp", local_port="Gi1/0/24", remote_name="dist-sw",
                       remote_port="TenGigabitEthernet1/1/1", remote_device_id=dist.id))
        s.add(Neighbor(device_id=dist.id, port_id=down.id, protocol="lldp", local_port="Te1/1/1", remote_name="lab-sw01.lab.local",
                       remote_port="GigabitEthernet1/0/24"))
        # the gateway's uplink, reported against the UniFi row of the switch (a duplicate)
        s.add(Neighbor(device_id=gw.id, protocol="unifi", local_port=None, remote_name="lab-sw01", remote_port="port 1",
                       remote_device_id=core_api.id))
        ui.data = {"type": "unifi",
                   "switch_ports": [
                       {"switch": "lab-sw01", "switch_mac": "aa:00:00:00:00:02", "port": 7, "speed_mbps": 2500, "role": "shared",
                        "clients": [{"mac": "bc:24:11:00:00:01", "ip": "10.0.0.50"}, {"mac": "bc:24:11:00:00:02", "ip": "10.0.0.10"}]},
                       {"switch": "lab-sw01", "switch_mac": "aa:00:00:00:00:02", "port": 8, "speed_mbps": 1000, "role": "client",
                        "clients": [{"mac": "B4-0C-25-00-00-01", "ip": "10.0.0.1"}]},
                       {"switch": "lab-sw01", "switch_mac": "aa:00:00:00:00:02", "port": 1, "speed_mbps": 10000, "role": "unifi"}],
                   "wans": [{"name": "WAN1", "device": "zlabcgwm", "up": True, "speed_mbps": 1000, "down_bps": 250e6, "up_bps": 20e6,
                             "isp": "Fiber Co", "ip": "203.0.113.5"},
                            {"name": "WAN2", "device": "zlabcgwm", "up": True, "speed_mbps": 500, "down_bps": 1e6, "up_bps": 1e5, "isp": "Cable"},
                            {"name": "WAN3", "device": "zlabcgwm", "up": False, "speed_mbps": None, "isp": "LTE"}]}
        ids = {"core": core.id, "dist": dist.id, "gw": gw.id, "pve": host.id, "fw": fw.id}
    m = logged_in.get("/ui/map").json()
    nodes = _by_name(m)
    assert sorted(nodes) == ["Cable", "Fiber Co", "LTE", "dist-sw", "lab-sw01", "pa-440", "pve1", "zlabcgwm"]   # one lab-sw01
    assert {x["source"] for x in nodes["lab-sw01"]["merged"]} == {"snmp", "UniFi"}
    links = {frozenset((str(l["source"]), str(l["target"]))): l for l in m["links"] if l["protocol"] != "wan"}
    trunk = links[frozenset((str(ids["core"]), str(ids["dist"])))]
    assert trunk["speed"] == 10000 and trunk["speed_label"] == "10G" and trunk["util"] == 20.0 and set(trunk["sources"]) == {"lldp"}
    assert len([l for l in m["links"] if {l["source"], l["target"]} == {ids["core"], ids["dist"]}]) == 1   # both ends, one link
    assert links[frozenset((str(ids["gw"]), str(ids["core"])))]["source"] == ids["gw"]               # the duplicate is remapped
    assert links[frozenset((str(ids["core"]), str(ids["pve"])))]["speed_label"] == "2.5G"            # Proxmox host on port 7
    assert links[frozenset((str(ids["core"]), str(ids["fw"])))]["a_port"] == "Port 8"                # PAN found by its MAC
    wans = sorted((l for l in m["links"] if l["protocol"] == "wan"), key=lambda l: l["wan"])
    assert [(l["source"], l["target"], l["wan"], l["speed_label"]) for l in wans] == [
        (ids["gw"], "isp:fiber-co", "WAN1", "1G"), (ids["gw"], "isp:cable", "WAN2", "500M"), (ids["gw"], "isp:lte", "WAN3", "")]
    assert wans[0]["down_bps"] == 250e6 and wans[0]["util"] == 25.0 and wans[0]["isp"] == "Fiber Co" and wans[2]["up"] is False
    assert nodes["LTE"]["status"] == "down" and nodes["Fiber Co"]["isp"] and nodes["Fiber Co"]["kind"] == "fiber"
    # name the ISP behind each WAN on the map page
    page = logged_in.get("/map").text
    assert "Internet uplinks and ISPs" in page and "zlabcgwm|wan1" in page
    r = logged_in.post("/map/isps", data={"key": ["zlabcgwm|wan1", "zlabcgwm|wan2", "zlabcgwm|wan3"],
                                          "isp": ["Brightspeed Fiber", "Spectrum Business", "Starlink Satellite"]}, follow_redirects=False)
    assert r.status_code == 303
    nodes = _by_name(logged_in.get("/ui/map").json())
    assert {n: nodes[n]["kind"] for n in ("Brightspeed Fiber", "Spectrum Business", "Starlink Satellite")} == {
        "Brightspeed Fiber": "fiber", "Spectrum Business": "cable", "Starlink Satellite": "satellite"}
    assert "Fiber Co" not in nodes
    # two WANs on one ISP share its circle; clearing a name goes back to what the gateway reports
    logged_in.post("/map/isps", data={"key": ["zlabcgwm|wan2", "zlabcgwm|wan3"], "isp": ["Brightspeed Fiber", ""]})
    m = logged_in.get("/ui/map").json()
    assert sorted(n["name"] for n in m["nodes"] if n.get("isp")) == ["Brightspeed Fiber", "LTE"]
    assert len([l for l in m["links"] if l["target"] == "isp:brightspeed-fiber"]) == 2
    # a site filter keeps the ISPs out when no gateway is in view
    assert logged_in.get("/ui/map?site=Nowhere").json() == {"nodes": [], "links": []}


def test_marked_port_goes_to_the_internet_and_hand_drawn_links(logged_in, app):
    with app.state.lw.db.session() as s:
        fw = Device(hostname="edge-fw", ip="10.1.0.1", type="Firewall", source="snmp", status="up", extra={})
        sw = Device(hostname="core", ip="10.1.0.2", type="Switch", source="snmp", status="up", extra={})
        s.add_all([fw, sw])
        s.flush()
        isp = Port(device_id=fw.id, ifindex=3, name="ethernet1/3", alias="Comcast", speed_mbps=1000, in_bps=5e8, out_bps=1e7, oper="up", admin="up")
        auto = Port(device_id=fw.id, ifindex=4, name="ethernet1/4", alias="WAN2 backup", speed_mbps=100, oper="up", admin="up")
        s.add_all([isp, auto])
        s.flush()
        fid, sid, pid = fw.id, sw.id, isp.id
    # a port named WAN is picked up on its own
    m = logged_in.get("/ui/map").json()
    assert [l["wan"] for l in m["links"] if l["protocol"] == "wan"] == ["WAN2 backup"]
    # a marked port wins over guesses from names
    assert logged_in.post(f"/ports/{pid}/wan", follow_redirects=False).status_code == 303
    assert "Internet uplink: On" in logged_in.get(f"/ports/{pid}").text
    m = logged_in.get("/ui/map").json()
    wans = [l for l in m["links"] if l["protocol"] == "wan"]
    assert len(wans) == 1 and wans[0]["wan"] == "Comcast" and wans[0]["speed"] == 1000 and wans[0]["util"] == 50.0
    # draw a link by hand
    r = logged_in.post("/map/links", data={"a": fid, "a_port": "ethernet1/3", "b": sid, "b_port": "Gi1/0/1"}, follow_redirects=False)
    assert r.status_code == 303
    m = logged_in.get("/ui/map").json()
    hand = [l for l in m["links"] if l["protocol"] == "manual"]
    assert len(hand) == 1 and hand[0]["speed_label"] == "1G"
    page = logged_in.get("/map").text
    assert "Links drawn by hand" in page and "Gi1/0/1" in page
    with app.state.lw.db.session() as s:
        nid = s.scalar(select(Neighbor.id).where(Neighbor.protocol == "manual"))
    assert logged_in.post(f"/map/links/{nid}/delete", follow_redirects=False).status_code == 303
    assert not [l for l in logged_in.get("/ui/map").json()["links"] if l["protocol"] == "manual"]
    assert logged_in.post("/map/links", data={"a": fid, "b": fid}, follow_redirects=False).status_code == 303


def test_unresolved_neighbour_is_matched_on_the_map(logged_in, app):
    with app.state.lw.db.session() as s:
        sw = Device(hostname="acc-sw", ip="10.2.0.2", type="Switch", source="snmp", status="up", extra={})
        nas = Device(hostname="nas01", type="NAS", source="synology", status="up", extra={"mac": "00:11:32:aa:bb:cc"})
        s.add_all([sw, nas])
        s.flush()
        s.add(Neighbor(device_id=sw.id, protocol="lldp", local_port="Gi0/5", remote_name="DiskStation", remote_chassis="00-11-32-AA-BB-CC"))
        ids = (sw.id, nas.id)
    m = logged_in.get("/ui/map").json()
    assert [(l["source"], l["target"]) for l in m["links"]] == [ids]
