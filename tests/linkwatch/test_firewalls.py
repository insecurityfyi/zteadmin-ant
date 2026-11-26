"""pfSense (REST API package v2) and VyOS (HTTPS API) integrations."""
from __future__ import annotations

import copy
import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from sqlalchemy import select

from linkwatch.integrations import build
from linkwatch.integrations.base import IntegrationError
from linkwatch.integrations.vyos import parse_table, to_bytes

PF = "https://10.0.0.1/api/v2"


def env(data):
    return httpx.Response(200, json={"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": data})


def mock_pfsense():
    respx.get(f"{PF}/status/system").mock(return_value=env({
        "platform": "Netgate 6100", "serial": "NTG6100-ABC", "netgate_id": "abc123", "uptime": "12 Days 03 Hours",
        "cpu_model": "Intel Atom C3558", "cpu_count": 4, "cpu_load_avg": [0.21, 0.3, 0.25], "cpu_usage": 5.3,
        "mem_usage": 23.0, "swap_usage": 0.0, "disk_usage": 7.0, "mbuf_usage": 1.2, "temp_c": 48.0}))
    respx.get(f"{PF}/system/version").mock(return_value=env({"version": "24.11-RELEASE", "patch": "0"}))
    respx.get(f"{PF}/system/hostname").mock(return_value=env({"hostname": "fw-hq", "domain": "example.lan"}))
    respx.get(f"{PF}/status/interfaces").mock(return_value=env([
        {"name": "wan", "descr": "WAN", "hwif": "ix0", "status": "up", "enable": True, "ipaddr": "203.0.113.2", "subnet": "29",
         "macaddr": "00:08:a2:00:00:01", "inbytes": 9_000_000_000, "outbytes": 1_000_000_000, "inerrs": 0, "outerrs": 0},
        {"name": "lan", "descr": "LAN", "hwif": "ix1", "status": "up", "enable": True, "ipaddr": "192.168.1.1", "subnet": "24",
         "inbytes": 1_000_000, "outbytes": 9_000_000, "inerrs": 3, "outerrs": 0},
        {"name": "opt1", "descr": "DMZ", "hwif": "ix2", "status": "no carrier", "enable": True}]))
    respx.get(f"{PF}/status/gateways").mock(return_value=env([
        {"name": "WAN_DHCP", "srcip": "203.0.113.2", "monitorip": "1.1.1.1", "delay": 4.2, "stddev": 0.4, "loss": 0.0, "status": "online", "substatus": "none"},
        {"name": "WAN2_LTE", "srcip": "10.64.0.2", "monitorip": "8.8.8.8", "delay": 0.0, "stddev": 0.0, "loss": 100.0, "status": "down", "substatus": "highloss"}]))
    respx.get(f"{PF}/firewall/states/size").mock(return_value=env({"currentstates": 1834, "maximumstates": 800000, "defaultmaximumstates": 800000}))
    respx.get(f"{PF}/status/dhcp_server/leases").mock(return_value=env([
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:01", "hostname": "laptop-ada", "if": "lan", "starts": "2026/11/26 10:00:00",
         "ends": "2026/11/26 12:00:00", "active_status": "active", "online_status": "online"}]))
    respx.get(f"{PF}/status/ipsec/sas").mock(return_value=env([
        {"con_id": "con1", "remote_host": "198.51.100.7", "state": "ESTABLISHED",
         "child_sas": [{"state": "INSTALLED", "bytes_in": 1000, "bytes_out": 2000}]}]))
    respx.get(f"{PF}/status/openvpn/servers").mock(return_value=env([
        {"name": "Remote access", "mode": "server_tls_user", "port": "1194",
         "conns": [{"common_name": "ada", "real_address": "198.51.100.20:51000", "virtual_addr": "10.8.0.2", "connect_time": "2026-11-26 09:00"}]}]))
    respx.get(f"{PF}/status/openvpn/clients").mock(return_value=env([]))
    respx.get(f"{PF}/status/wireguard/tunnels").mock(return_value=httpx.Response(404, json={"code": 404, "message": "Endpoint not found"}))
    respx.get(f"{PF}/status/services").mock(return_value=env([
        {"name": "unbound", "description": "DNS Resolver", "enabled": True, "status": True},
        {"name": "ntpd", "description": "NTP clock sync", "enabled": True, "status": False}]))
    respx.get(f"{PF}/status/carp").mock(return_value=env({"enable": False, "maintenance_mode": False, "vips": []}))


@respx.mock
def test_pfsense_collects_everything():
    mock_pfsense()
    integ = build("pfsense", {"host": "10.0.0.1", "api_key": "k3y"})
    rec = integ.collect()[0]
    assert respx.calls[0].request.headers["x-api-key"] == "k3y"
    assert (rec["external_id"], rec["hostname"], rec["type"], rec["cpu"], rec["mem"]) == ("NTG6100-ABC", "fw-hq.example.lan", "Firewall", 5.3, 23.0)
    assert rec["status"] == "warn" and "gateway down: WAN2_LTE" in rec["detail"] and "stopped: ntpd" in rec["detail"]
    assert "1/2 gateways up" in rec["detail"] and "1834 states" in rec["detail"]
    assert rec["platform"] == "pfSense Netgate 6100 24.11-RELEASE"
    assert {p["name"]: p["oper"] for p in rec["ports"]} == {"ix0": "up", "ix1": "up", "ix2": "down"}
    assert "203.0.113.2" in rec["extra"]["ips"]
    d = integ.data
    assert [g["state"] for g in d["gateways"]] == ["up", "down"]
    assert d["states"] == {"current": 1834, "max": 800000}
    assert d["leases"][0]["hostname"] == "laptop-ada"
    assert d["tunnels"] == [{"kind": "IPsec", "name": "con1", "remote": "198.51.100.7", "up": True, "state": "established",
                             "children_up": 1, "children": 1, "in_bytes": 1000.0, "out_bytes": 2000.0}]
    assert d["vpn_users"][0]["user"] == "ada"
    assert d["not_offered"] == ["WireGuard"] and d["unavailable"] == []
    assert "carp" not in d


@respx.mock
def test_pfsense_errors_explain_themselves():
    respx.get(f"{PF}/status/system").mock(return_value=httpx.Response(401, json={"code": 401, "message": "Authentication failed"}))
    with pytest.raises(IntegrationError, match="refused the API key"):
        build("pfsense", {"host": "10.0.0.1", "api_key": "bad"}).collect()
    respx.get(f"{PF}/status/system").mock(return_value=httpx.Response(404, text="<html>not found</html>"))
    with pytest.raises(IntegrationError, match="Install pfSense-pkg-RESTAPI"):
        build("pfsense", {"host": "10.0.0.1", "api_key": "k"}).collect()


VY_INTERFACES = """Codes: S - State, L - Link, u - Up, D - Down, A - Admin Down
Interface    IP Address         MAC                VRF        MTU  S/L    Description
-----------  -----------------  -----------------  -------  -----  -----  -------------
eth0         203.0.113.10/24    00:50:56:aa:00:01  default   1500  u/u    WAN uplink
             2001:db8::10/64
eth1         192.168.10.1/24    00:50:56:aa:00:02  default   1500  u/u    LAN
eth2         -                  00:50:56:aa:00:03  default   1500  A/D
lo           127.0.0.1/8        00:00:00:00:00:00  default  65536  u/u
wg0          10.10.0.1/24       n/a                default   1420  u/u    Site VPN
"""
VY_COUNTERS = """Interface    Rx Packets    Rx Bytes    Tx Packets    Tx Bytes    Rx Dropped    Tx Dropped    Rx Errors    Tx Errors
-----------  ------------  ----------  ------------  ----------  ------------  ------------  -----------  -----------
eth0         1000          5000000     900           400000      0             0             2            0
eth1         500           100000      700           4000000     0             0             0            0
"""
VY_VERSION = """Version:          VyOS 1.4.0
Release train:    sagitta
Built on:         Mon 15 Jan 2024 10:00 UTC
Hardware vendor:  VMware, Inc.
Hardware model:   VMware Virtual Platform
Hardware S/N:     VMware-42 1a 2b
"""
VY_UPTIME = """Uptime: 3d 4h 12m

Load averages:
1  minute:   2.5%
5  minutes:  1.8%
15 minutes:  1.2%
"""
VY_MEMORY = "Total: 1983\nFree:  1446\nUsed:  537\n"
VY_ROUTE = """Routing entry for 0.0.0.0/0
  Known via "static", distance 1, metric 0, best
  Last update 3d04h12m ago
  * 203.0.113.1, via eth0, weight 1
"""
VY_ROUTE_14 = """Routing entry for 0.0.0.0/0
  Known via "static", distance 1, metric 0, best
  * via 203.0.113.1, eth0, weight 1
"""
VY_IPSEC = """Connection          State    Uptime    Bytes In/Out    Packets In/Out    Remote address    Remote ID    Proposal
------------------  -------  --------  --------------  ----------------  ----------------  -----------  ----------------------------
branch-tunnel-0     up       3h12m     1.2M/350K       1K/900            198.51.100.30     N/A          AES_CBC_256/HMAC_SHA2_256_128
"""
VY_LEASES = """IP Address      MAC address        State    Lease start          Lease expiration     Remaining    Pool       Hostname
--------------  -----------------  -------  -------------------  -------------------  -----------  ---------  ----------
192.168.10.100  aa:bb:cc:00:00:01  active   2026/11/26 09:00:00  2026/11/27 09:00:00  20:00:00     LAN-POOL   printer
192.168.10.101  aa:bb:cc:00:00:02  expired  2026/11/25 09:00:00  2026/11/26 09:00:00  0:00:00      LAN-POOL
"""
VY_WG = """interface: wg0
  public key: AAAA
  listening port: 51820

peer: BBBB
  endpoint: 198.51.100.40:51820
  allowed ips: 10.10.0.2/32
  latest handshake: 1 minute, 2 seconds ago
  transfer: 1.50 MiB received, 3.00 MiB sent
"""
VY_CONFIG = {
    "system": {"host-name": "edge-01"},
    "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.10/24"], "description": "WAN uplink"},
                                "eth1": {"address": ["192.168.10.1/24"], "description": "LAN"}, "eth2": {"disable": {}}},
                   "wireguard": {"wg0": {"address": ["10.10.0.1/24"], "peer": {"branch": {}}}}},
    "vpn": {"ipsec": {"site-to-site": {"peer": {"branch": {"remote-address": "198.51.100.30"},
                                                "lab": {"remote-address": "198.51.100.99"}}}}},
}
VY_SHOW = {("version",): VY_VERSION, ("system", "uptime"): VY_UPTIME, ("system", "memory"): VY_MEMORY,
           ("interfaces",): VY_INTERFACES, ("interfaces", "counters"): VY_COUNTERS, ("ip", "route", "0.0.0.0/0"): VY_ROUTE,
           ("vpn", "ipsec", "sa"): VY_IPSEC, ("interfaces", "wireguard", "wg0", "summary"): VY_WG,
           ("dhcp", "server", "leases"): VY_LEASES}


def vyos_handler(request: httpx.Request) -> httpx.Response:
    form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
    if form.get("key") != "s3cret":
        return httpx.Response(401, json={"success": False, "error": "Valid API key is required", "data": None})
    data = json.loads(form["data"])
    if request.url.path == "/retrieve":
        return httpx.Response(200, json={"success": True, "data": VY_CONFIG, "error": None})
    out = VY_SHOW.get(tuple(data["path"]))
    if out is None:
        return httpx.Response(400, json={"success": False, "error": "Invalid command: show " + " ".join(data["path"]), "data": None})
    return httpx.Response(200, json={"success": True, "data": out, "error": None})


def test_vyos_text_tables():
    rows = parse_table(VY_INTERFACES, "Interface")
    assert rows[0]["Interface"] == "eth0" and rows[0]["S/L"] == "u/u" and rows[0]["_more"] == [["2001:db8::10/64"]]
    assert rows[2]["S/L"] == "A/D" and rows[2]["Description"] == ""
    leases = parse_table(VY_LEASES, "IP Address")
    assert leases[1]["Hostname"] == "" and leases[0]["Pool"] == "LAN-POOL"
    assert to_bytes("1.2M") == 1.2e6 and to_bytes("350K") == 350e3 and to_bytes("1.50 MiB") == 1.5 * 1024**2


@respx.mock
def test_vyos_collects_everything():
    route = respx.post(url__regex=r"https://10\.0\.0\.2/(retrieve|show)").mock(side_effect=vyos_handler)
    integ = build("vyos", {"host": "10.0.0.2", "api_key": "s3cret"})
    rec = integ.collect()[0]
    assert route.calls[0].request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert (rec["hostname"], rec["type"], rec["platform"], rec["status"]) == ("edge-01", "Router", "VyOS 1.4.0", "up")
    assert rec["serial"] == "VMware-42 1a 2b" and rec["cpu"] == 2.5 and rec["mem"] == 27.1
    ports = {p["name"]: p for p in rec["ports"]}
    assert set(ports) == {"eth0", "eth1", "eth2", "wg0"}
    assert ports["eth0"]["in_octets"] == 5e6 and ports["eth0"]["in_errors"] == 2 and ports["eth2"]["admin"] == "down"
    assert "203.0.113.10" in rec["extra"]["ips"] and "2001:db8::10" in rec["extra"]["ips"]
    d = integ.data
    eth0 = d["interfaces"][0]
    assert eth0["wan"] and eth0["addresses"] == ["203.0.113.10/24", "2001:db8::10/64"]
    assert d["gateways"] == [{"name": "eth0", "gateway": "203.0.113.1", "selected": True, "state": "up", "inactive": False, "protocol": "static"}]
    by = {t["name"]: t for t in d["tunnels"]}
    assert by["branch-tunnel-0"]["up"] and by["branch-tunnel-0"]["in_bytes"] == 1.2e6
    assert by["lab"]["up"] is False and "branch" not in by
    assert by["wg0"]["up"] and by["wg0"]["in_bytes"] == 1.5 * 1024**2
    assert [x["hostname"] for x in d["leases"]] == ["printer", None]
    assert set(d["not_offered"]) == {"OpenVPN", "Connection tracking"} and d["unavailable"] == []


@respx.mock
def test_vyos_route_format_and_bad_key():
    VY_SHOW[("ip", "route", "0.0.0.0/0")] = VY_ROUTE_14
    try:
        respx.post(url__regex=r"https://r1/(retrieve|show)").mock(side_effect=vyos_handler)
        integ = build("vyos", {"host": "r1", "api_key": "s3cret"})
        integ.collect()
        assert integ.data["gateways"][0]["gateway"] == "203.0.113.1"
        with pytest.raises(IntegrationError, match="refused the API key"):
            build("vyos", {"host": "r1", "api_key": "nope"}).collect()
    finally:
        VY_SHOW[("ip", "route", "0.0.0.0/0")] = VY_ROUTE


def test_pages_and_series(logged_in, app):
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    from linkwatch.server.models import Device, Integration, IntegrationMetric

    with respx.mock:
        mock_pfsense()
        pf = build("pfsense", {"host": "10.0.0.1", "api_key": "k"})
        pf_recs = pf.collect()
        respx.post(url__regex=r"https://10\.0\.0\.2/(retrieve|show)").mock(side_effect=vyos_handler)
        vy = build("vyos", {"host": "10.0.0.2", "api_key": "s3cret"})
        vy_recs = vy.collect()
    ids = {}
    with app.state.lw.db.session() as s:
        for kind, recs, data in (("pfsense", pf_recs, pf.data), ("vyos", vy_recs, vy.data)):
            integ = Integration(kind=kind, name=f"My {kind}", config_enc=app.state.lw.vault.seal({}), status="never")
            s.add(integ)
            s.flush()
            ingest_integration(s, Alerter(s), integ, {"ok": True, "records": copy.deepcopy(recs), "data": copy.deepcopy(data)})
            ids[kind] = integ.id
        keys = {(m.integration_id, m.key) for m in s.scalars(select(IntegrationMetric))}
        devs = {d.hostname: d for d in s.scalars(select(Device))}
        assert len(devs["fw-hq.example.lan"].ports) == 3 and devs["edge-01"].type == "Router"
    assert {(ids["pfsense"], k) for k in ("states", "tunnels", "vpn:users", "leases", "gw:WAN_DHCP", "gw:WAN2_LTE")} <= keys
    assert {(ids["vyos"], k) for k in ("tunnels", "leases")} <= keys
    p = logged_in.get(f"/integrations/{ids['pfsense']}/overview").text
    for text in ("WAN2_LTE", "laptop-ada", "DNS Resolver", "Not offered by this package version: WireGuard", "Netgate 6100", "1,834"):
        assert text in p, text
    v = logged_in.get(f"/integrations/{ids['vyos']}/overview").text
    for text in ("branch-tunnel-0", "printer", "203.0.113.1", "2001:db8::10/64", "sagitta", "WireGuard"):
        assert text in v, text
