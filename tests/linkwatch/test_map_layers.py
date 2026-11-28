"""Layer 3 (subnets) and Layer 2 (VLAN) maps: SNMP collection, integration interfaces, UniFi clients, and the views."""
import asyncio

from linkwatch.poller import snmp_extra
from linkwatch.server.layers import build_l2, build_l3, vlan_from_name
from linkwatch.server.models import Device, Integration, Port


class FakeSnmp:
    def __init__(self, tables):
        self.tables = tables

    async def walk(self, base, max_rows=5000):
        pre = base + "."
        return {k[len(pre):]: v for k, v in self.tables.items() if k.startswith(pre)}

    async def get(self, oids):
        return {}


def test_vlan_from_interface_names():
    for name, want in [("Vlan10", 10), ("vlan-interface20", 20), ("eth0.30", 30), ("ethernet1/1.40", 40), ("X0:V50", 50),
                       ("igb1.60", 60), ("GigabitEthernet1/0/1", None), ("eth0", None), ("", None)]:
        assert vlan_from_name(name) == want, name


def test_portlist_bits():
    assert snmp_extra.portlist("c0:01") == [1, 2, 16]
    assert snmp_extra.portlist("") == []


def test_poller_reads_q_bridge_vlans_and_addresses():
    t = {
        # Q-BRIDGE: VLAN 10 "Users" untagged on bridge ports 1,2, tagged on 8; VLAN 20 "Voice" tagged on 8
        "1.3.6.1.2.1.17.7.1.4.3.1.1.10": "Users", "1.3.6.1.2.1.17.7.1.4.3.1.2.10": "c1", "1.3.6.1.2.1.17.7.1.4.3.1.4.10": "c0",
        "1.3.6.1.2.1.17.7.1.4.3.1.1.20": "Voice", "1.3.6.1.2.1.17.7.1.4.3.1.2.20": "01", "1.3.6.1.2.1.17.7.1.4.3.1.4.20": "00",
        "1.3.6.1.2.1.17.1.4.1.2.1": 101, "1.3.6.1.2.1.17.1.4.1.2.2": 102, "1.3.6.1.2.1.17.1.4.1.2.8": 108,
        "1.3.6.1.2.1.4.20.1.2.10.0.10.1": 500, "1.3.6.1.2.1.4.20.1.3.10.0.10.1": "255.255.255.0",
        "1.3.6.1.2.1.4.20.1.2.127.0.0.1": 1, "1.3.6.1.2.1.4.20.1.3.127.0.0.1": "255.0.0.0",
    }
    s = FakeSnmp(t)
    vl = asyncio.run(snmp_extra.vlans(s))
    assert vl == [{"id": 10, "name": "Users", "untagged": [101, 102], "tagged": [108]},
                  {"id": 20, "name": "Voice", "untagged": [], "tagged": [108]}]
    assert asyncio.run(snmp_extra.ip_addresses(s)) == [{"ip": "10.0.10.1", "prefix": 24, "ifindex": 500}]


def test_poller_reads_cisco_vtp_vlans():
    t = {"1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.1": "default", "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.30": "Cameras",
         "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.1002": "fddi-default",
         "1.3.6.1.4.1.9.9.68.1.2.2.1.2.5": 30, "1.3.6.1.4.1.9.9.46.1.6.1.1.14.24": 1}
    vl = asyncio.run(snmp_extra.vlans(FakeSnmp(t)))
    assert [(v["id"], v["name"], v["untagged"], v["tagged"]) for v in vl] == [(1, "default", [], [24]), (30, "Cameras", [5], [24])]


def _lab(s):
    pf = Integration(kind="pfsense", name="pf", config_enc="-", enabled=True,
                     data={"interfaces": [{"name": "LAN", "device": "igb1", "ip": "10.0.0.1", "subnet": 24},
                                          {"name": "USERS", "device": "igb1.10", "ip": "10.0.10.1", "subnet": "24"},
                                          {"name": "WAN", "device": "igb0", "ip": "203.0.113.5", "subnet": 29},
                                          {"name": "OPT", "device": "igb2", "ip": None}]})
    ui = Integration(kind="unifi", name="UniFi", config_enc="-", enabled=True,
                     data={"ssids": [{"name": "Corp", "vlan": 10}, {"name": "Guest", "vlan": 99}],
                           "clients": [{"mac": "11:11:11:11:11:11", "name": "laptop", "ip": "10.0.10.50", "vlan": 10, "network": "Users",
                                        "wired": False, "ap_mac": "aa:00:00:00:00:0a", "ssid": "Corp", "signal": -60},
                                       {"mac": "22:22:22:22:22:22", "name": "phone", "ip": "10.0.99.7", "vlan": 99, "network": "Guest",
                                        "wired": False, "ap_mac": "aa:00:00:00:00:0a", "ssid": "Guest"},
                                       {"mac": "33:33:33:33:33:33", "name": "printer", "ip": "10.0.0.60", "network": "Default", "wired": True,
                                        "switch_mac": "aa:00:00:00:00:02"}]})
    s.add_all([pf, ui])
    s.flush()
    fw = Device(hostname="pf1", ip="10.0.0.1", type="Firewall", source="pfsense", integration_id=pf.id, external_id="x", status="up", extra={})
    sw = Device(hostname="core-sw", ip="10.0.0.2", type="Switch", source="snmp", status="up",
                extra={"mac": "aa:00:00:00:00:02", "vlans": [{"id": 10, "name": "Users", "untagged": [1, 2], "tagged": [24]},
                                                             {"id": 20, "name": "Voice", "untagged": [], "tagged": [24]}],
                       "ip_addrs": [{"ip": "10.0.20.1", "prefix": 24, "ifindex": 1020}]})
    ap = Device(hostname="ap1", ip="10.0.0.5", type="Wireless", source="unifi", integration_id=ui.id, external_id="ap", status="up",
                extra={"mac": "aa:00:00:00:00:0a"})
    srv = Device(hostname="files", ip="10.0.10.20", type="Server", source="snmp", status="up", extra={})
    s.add_all([fw, sw, ap, srv])
    s.flush()
    s.add_all([Port(device_id=sw.id, ifindex=1, name="Gi1/0/1"), Port(device_id=sw.id, ifindex=2, name="Gi1/0/2"),
               Port(device_id=sw.id, ifindex=24, name="Gi1/0/24"), Port(device_id=sw.id, ifindex=1020, name="Vlan20", alias="Voice")])
    return fw, sw, ap, srv


def test_layer3_subnets_gateways_and_hosts(app):
    with app.state.lw.db.session() as s:
        fw, sw, ap, srv = _lab(s)
        s.flush()
        m = build_l3(s)
    nets = {n["name"]: n for n in m["nodes"] if n["kind"] == "subnet"}
    assert set(nets) == {"10.0.0.0/24", "10.0.10.0/24", "203.0.113.0/29", "10.0.20.0/24"}
    assert nets["10.0.10.0/24"]["vlan"] == 10 and nets["10.0.10.0/24"]["gateways"] == ["10.0.10.1"]
    assert nets["10.0.20.0/24"]["vlan"] == 20 and nets["10.0.20.0/24"]["label"] == "Voice"
    gw = {(l["source"], l["target"]): l for l in m["links"]}
    assert gw[(str(fw.id), "net:10.0.10.0/24")]["label"] == "10.0.10.1"
    assert gw[(str(sw.id), "net:10.0.20.0/24")]["kind"] == "gateway"
    assert gw[(str(ap.id), "net:10.0.0.0/24")]["kind"] == "host"          # an AP inside the LAN
    assert nets["10.0.10.0/24"]["hosts"] == 1 and nets["10.0.10.0/24"]["host_names"] == ["files"]   # a server is counted
    with app.state.lw.db.session() as s:
        every = build_l3(s, hosts=True)
    assert any(l["source"] == str(srv.id) for l in every["links"])


def test_layer2_vlan_bubbles(app):
    with app.state.lw.db.session() as s:
        fw, sw, ap, srv = _lab(s)
        s.flush()
        m = build_l2(s)
        with_clients = build_l2(s, clients=True)
    vl = {n["vid"] or n["name"]: n for n in m["nodes"] if n["kind"] == "vlan"}
    assert vl[10]["name"] == "Users" and vl[10]["subnets"] == ["10.0.10.0/24"] and vl[10]["ssids"] == ["Corp"]
    assert vl[20]["name"] == "Voice" and vl[99]["ssids"] == ["Guest"] and vl[99]["clients"] == 1
    links = {(l["source"], l["target"]): l for l in m["links"]}
    assert links[(str(sw.id), "vlan:10")]["label"] == "Gi1/0/1, Gi1/0/2 · tagged Gi1/0/24"
    assert links[(str(sw.id), "vlan:20")]["kind"] == "gateway"            # the switch routes VLAN 20 (interface Vlan20)
    assert links[(str(sw.id), "vlan:20")]["label"] == "tagged Gi1/0/24 · gateway 10.0.20.1"
    assert links[(str(fw.id), "vlan:10")]["kind"] == "gateway" and "10.0.10.1" in links[(str(fw.id), "vlan:10")]["label"]
    assert links[(str(ap.id), "vlan:99")]["label"] == "1 client"
    assert links[(str(srv.id), "vlan:10")]["kind"] == "host"              # placed by its address
    assert vl[1]["name"] == "Default" and vl[1]["clients"] == 1             # an untagged UniFi network is VLAN 1
    assert not any(n["kind"] == "client" for n in m["nodes"])
    assert {n["name"] for n in with_clients["nodes"] if n["kind"] == "client"} == {"laptop", "phone", "printer"}


def test_map_page_has_both_layer_maps(logged_in):
    html = logged_in.get("/map").text
    assert 'data-layer="l3"' in html and 'data-layer="l2"' in html and "/static/layers.js" in html
    assert logged_in.get("/ui/map/l3").json()["nodes"] == []
    assert logged_in.get("/ui/map/l2?clients=1").json()["nodes"] == []


def test_ingest_keeps_vlans_and_addresses(tmp_path):
    from linkwatch.server.ingest import ingest_batch

    from .test_ingest import batch, make_db, snmp_item
    db = make_db(tmp_path)
    item = snmp_item(1000, 1000, 1000)
    item.update(vlans=[{"id": 10, "name": "Users", "untagged": [1], "tagged": []}], ip_addrs=[{"ip": "10.0.10.1", "prefix": 24, "ifindex": 9}])
    with db.session() as s:
        ingest_batch(s, 1, batch(item))
    with db.session() as s:
        dev = s.get(Device, 10)
        assert dev.extra["vlans"][0]["name"] == "Users" and dev.extra["ip_addrs"][0]["ip"] == "10.0.10.1"
