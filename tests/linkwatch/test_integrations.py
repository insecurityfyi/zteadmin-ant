import json
import httpx
import pytest
import respx

from linkwatch.integrations import REGISTRY, IntegrationError, build
from linkwatch.integrations.panos import parse_top, parse_uptime


def test_registry_has_every_platform():
    assert set(REGISTRY) == {"zscaler", "meraki", "panos", "fortigate", "sonicwall", "unifi", "proxmox"}
    assert {k for k, c in REGISTRY.items() if c.runs_on == "server"} == {"zscaler", "meraki"}


def test_missing_required_field():
    with pytest.raises(IntegrationError, match="Missing"):
        build("meraki", {})


@respx.mock
def test_zscaler_oneapi_collects_all_products():
    token = respx.post("https://acme.zslogin.net/oauth2/v1/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t0k", "expires_in": 3600}))
    respx.get("https://api.zsapi.net/zia/api/v1/locations").mock(return_value=httpx.Response(200, json=[
        {"id": 1, "name": "HQ", "ipAddresses": ["203.0.113.4"]}]))
    respx.get("https://api.zsapi.net/zia/api/v1/greTunnels").mock(return_value=httpx.Response(200, json=[
        {"id": 7, "sourceIp": "203.0.113.4", "primaryDestVip": {"datacenter": "CHI1"}}]))
    respx.get("https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/999/connector").mock(return_value=httpx.Response(200, json={
        "totalPages": "1", "list": [
            {"id": "a1", "name": "ac-dc1", "privateIp": "10.50.1.10", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED", "currentVersion": "24.1"},
            {"id": "a2", "name": "ac-dc2", "controlChannelStatus": "ZPN_STATUS_DISCONNECTED"}]}))
    respx.get("https://api.zsapi.net/zdx/v1/apps").mock(return_value=httpx.Response(200, json=[
        {"id": 3, "name": "Outlook", "score": 82, "total_users": 40}, {"id": 4, "name": "Teams", "score": 21}]))
    respx.get("https://api.zsapi.net/zcc/papi/public/v1/getDevices").mock(return_value=httpx.Response(200, json=[
        {"agentVersion": "4.5", "osVersion": "Windows 11"}, {"agentVersion": "4.5", "osVersion": "macOS 15"}]))
    z = build("zscaler", {"vanity_domain": "acme", "client_id": "id", "client_secret": "s", "zpa_customer_id": "999"})
    recs = {r["external_id"]: r for r in z.collect()}
    assert token.call_count == 1                     # token cached across calls
    assert recs["zpa-ac-a1"]["status"] == "up" and recs["zpa-ac-a2"]["status"] == "down"
    assert recs["zdx-app-3"]["status"] == "up" and recs["zdx-app-4"]["status"] == "down"
    assert recs["zcc-summary"]["extra"]["devices"] == 2
    assert recs["zia-gre-7"]["ip"] == "203.0.113.4"
    assert z.errors == []
    req = respx.calls[1].request
    assert req.headers["Authorization"] == "Bearer t0k"


@respx.mock
def test_zscaler_product_failure_is_partial():
    respx.post("https://acme.zslogin.net/oauth2/v1/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.get("https://api.zsapi.net/zdx/v1/apps").mock(return_value=httpx.Response(403))
    respx.get("https://api.zsapi.net/zcc/papi/public/v1/getDevices").mock(return_value=httpx.Response(200, json=[]))
    z = build("zscaler", {"vanity_domain": "acme", "client_id": "id", "client_secret": "s",
                          "zia": False, "zpa": False, "zdx": True, "zcc": True})
    recs = z.collect()
    assert len(recs) == 1 and "ZDX" in z.errors[0]


@respx.mock
def test_zscaler_bad_credentials():
    respx.post("https://acme.zslogin.net/oauth2/v1/token").mock(return_value=httpx.Response(401))
    z = build("zscaler", {"vanity_domain": "acme", "client_id": "id", "client_secret": "bad", "zpa": False})
    with pytest.raises(IntegrationError, match="token request failed"):
        z.collect()


@respx.mock
def test_zscaler_ztb_api_key_flow_and_oneapi_hint():
    respx.post("https://acme.zslogin.net/oauth2/v1/token").mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    respx.get("https://api.zsapi.net/ztb/api/v2/Site/").mock(return_value=httpx.Response(401))
    base = {"vanity_domain": "acme", "client_id": "id", "client_secret": "s", "zia": False, "zpa": False, "zdx": False, "zcc": False, "ztb": True}
    with pytest.raises(IntegrationError, match="no ZTB access.*ZTB API key"):
        build("zscaler", base).collect()

    login = respx.post("https://acme.goairgap.com/api/v3/api-key-auth/login").mock(
        return_value=httpx.Response(200, json={"result": {"delegate_token": "dlg"}}))
    sites = respx.get("https://acme.goairgap.com/api/v2/Site/").mock(return_value=httpx.Response(
        200, json={"result": [{"id": "s1", "display_name": "Branch 7", "gateway_type": "ZTB-400", "status": "online"}]}))
    recs = build("zscaler", base | {"ztb_api_key": " zk-123 ", "ztb_tenant": "acme"}).collect()
    assert json.loads(login.calls.last.request.content) == {"api_key": "zk-123"}
    assert sites.calls.last.request.headers["authorization"] == "Bearer dlg"
    assert [(r["hostname"], r["status"], r["site"]) for r in recs] == [("ZTB Branch 7", "up", "Branch 7")]


@respx.mock
def test_meraki_paginates_and_maps_status():
    base = "https://api.meraki.com/api/v1"
    respx.get(f"{base}/organizations").mock(return_value=httpx.Response(200, json=[{"id": "55"}]))
    respx.get(f"{base}/organizations/55/networks").mock(return_value=httpx.Response(200, json=[{"id": "N1", "name": "Branch 02"}]))
    respx.get(f"{base}/organizations/55/devices/statuses").mock(return_value=httpx.Response(200, json=[
        {"serial": "Q1", "status": "online", "lanIp": "172.20.2.2"}, {"serial": "Q2", "status": "offline"}]))
    page2 = f"{base}/organizations/55/devices?startingAfter=Q1"
    respx.get(page2).mock(return_value=httpx.Response(200, json=[{"serial": "Q2", "name": "br02-ap03", "model": "MR46", "productType": "wireless", "networkId": "N1"}]))
    respx.get(f"{base}/organizations/55/devices", params={"perPage": "1000"}).mock(return_value=httpx.Response(
        200, json=[{"serial": "Q1", "name": "br02-sw01", "model": "MS120", "productType": "switch", "networkId": "N1"}],
        headers={"Link": f"<{page2}>; rel=next"}))
    recs = build("meraki", {"api_key": "k"}).collect()
    assert [(r["hostname"], r["status"], r["type"], r["site"]) for r in recs] == [
        ("br02-sw01", "up", "Switch", "Branch 02"), ("br02-ap03", "down", "Wireless", "Branch 02")]


@respx.mock
def test_meraki_key_cleanup_headers_and_401_hint():
    seen = {}

    def orgs(request):
        seen.update(request.headers)
        return httpx.Response(401, json={"errors": ["Invalid API key"]})
    respx.get("https://api.meraki.com/api/v1/organizations").mock(side_effect=orgs)
    with pytest.raises(IntegrationError, match="HTTP 401.*API access is enabled"):
        build("meraki", {"api_key": " Bearer abc123\n "}).collect()
    assert seen["authorization"] == "Bearer abc123" and "x-cisco-meraki-api-key" not in seen


@respx.mock
def test_meraki_follows_shard_redirect_with_key():
    respx.get("https://api.meraki.com/api/v1/organizations").mock(
        return_value=httpx.Response(307, headers={"Location": "https://n42.meraki.com/api/v1/organizations"}))
    shard = respx.get("https://n42.meraki.com/api/v1/organizations").mock(return_value=httpx.Response(200, json=[{"id": "7"}]))
    assert build("meraki", {"api_key": "k"}).org_id() == "7"
    assert shard.calls.last.request.headers["authorization"] == "Bearer k"
    respx.get("https://api.meraki.com/api/v1/organizations").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example/steal"}))
    with pytest.raises(IntegrationError, match="unexpected host"):
        build("meraki", {"api_key": "k"}).org_id()


@respx.mock
def test_meraki_org_name_resolves_to_id():
    respx.get("https://api.meraki.com/api/v1/organizations").mock(return_value=httpx.Response(
        200, json=[{"id": "111", "name": "Other"}, {"id": "2222", "name": "HCI-SOHO-Network"}]))
    assert build("meraki", {"api_key": "k", "org_id": "hci-soho-network"}).org_id() == "2222"
    with pytest.raises(IntegrationError, match=r"No organization named 'nope'.*HCI-SOHO-Network \(2222\)"):
        build("meraki", {"api_key": "k", "org_id": "nope"}).org_id()


PAN_INFO = """<response status="success"><result><system><hostname>dc-pa440</hostname><ip-address>10.50.0.1</ip-address>
<model>PA-440</model><serial>0123456789</serial><sw-version>11.1.2</sw-version><uptime>12 days, 3:04:05</uptime></system></result></response>"""
PAN_RES = """<response status="success"><result><![CDATA[top - 10:00:00 up 12 days
%Cpu(s):  3.0 us,  1.0 sy,  0.0 ni, 95.0 id,  0.0 wa
MiB Mem :   7928.0 total,   1000.0 free,   3964.0 used,   2964.0 buff/cache]]></result></response>"""
PAN_SESS = """<response status="success"><result><num-active>4120</num-active></result></response>"""


@respx.mock
def test_panos_system_info():
    def route(request):
        cmd = request.url.params["cmd"]
        assert request.headers["X-PAN-KEY"] == "k"
        if "system><info" in cmd:
            return httpx.Response(200, text=PAN_INFO)
        if "resources" in cmd:
            return httpx.Response(200, text=PAN_RES)
        if "session" in cmd:
            return httpx.Response(200, text=PAN_SESS)
        return httpx.Response(200, text='<response status="error"><msg>no HA</msg></response>')
    respx.get("https://10.50.0.1/api/").mock(side_effect=route)
    (rec,) = build("panos", {"host": "10.50.0.1", "api_key": "k"}).collect()
    assert rec["hostname"] == "dc-pa440" and rec["cpu"] == 5.0 and rec["mem"] == 50.0
    assert rec["uptime_s"] == parse_uptime("12 days, 3:04:05") and rec["extra"]["sessions"] == 4120


def test_panos_parsers():
    assert parse_uptime("0 days, 0:01:00") == 60
    assert parse_top("nothing") == (None, None)


@respx.mock
def test_fortigate_status_and_tunnels():
    respx.get("https://fw.lan/api/v2/monitor/system/status").mock(return_value=httpx.Response(200, json={
        "results": {"hostname": "edge-fw01", "model_number": "100F"}, "serial": "FG100F", "version": "v7.4.3"}))
    respx.get("https://fw.lan/api/v2/monitor/system/resource/usage").mock(return_value=httpx.Response(200, json={
        "results": {"cpu": [{"current": 12}], "mem": [{"current": 40}], "session": [{"current": 900}]}}))
    respx.get("https://fw.lan/api/v2/monitor/vpn/ipsec").mock(return_value=httpx.Response(200, json={"results": [
        {"name": "to-dc", "rgwy": "198.51.100.9", "proxyid": [{"status": "up"}]}, {"name": "old", "proxyid": [{"status": "down"}]}]}))
    recs = build("fortigate", {"host": "fw.lan", "api_token": "t"}).collect()
    assert recs[0]["cpu"] == 12 and recs[0]["hostname"] == "edge-fw01"
    assert [r["status"] for r in recs[1:]] == ["up", "down"]


@respx.mock
def test_proxmox_nodes_and_guests():
    respx.get("https://10.10.5.11:8006/api2/json/cluster/resources").mock(return_value=httpx.Response(200, json={"data": [
        {"type": "node", "node": "pve-01", "status": "online", "cpu": 0.42, "mem": 8 * 2**30, "maxmem": 32 * 2**30, "maxcpu": 16, "uptime": 99},
        {"type": "qemu", "vmid": 101, "name": "web", "status": "running", "node": "pve-01", "cpu": 0.1, "mem": 1, "maxmem": 4},
        {"type": "lxc", "vmid": 102, "name": "dns", "status": "stopped", "node": "pve-01"},
        {"type": "storage", "storage": "local"}]}))
    respx.get("https://10.10.5.11:8006/api2/json/cluster/status").mock(return_value=httpx.Response(200, json={"data": [
        {"type": "node", "name": "pve-01", "ip": "10.10.5.11"}]}))
    recs = build("proxmox", {"host": "10.10.5.11", "token_id": "mon@pve!lw", "token_secret": "x"}).collect()
    node = recs[0]
    assert node["ip"] == "10.10.5.11" and node["cpu"] == 42.0 and node["mem"] == 25.0
    assert [r["status"] for r in recs[1:]] == ["up", "off"]
    assert respx.calls[0].request.headers["Authorization"] == "PVEAPIToken=mon@pve!lw=x"


UNIFI = "https://192.168.1.1/proxy/network/api"
UNIFI_DEVICES = [
    {"_id": "1", "mac": "aa:aa:aa:00:00:01", "name": "ap-lobby", "type": "uap", "model": "U7PRO", "state": 1, "ip": "192.168.1.20",
     "version": "7.0.66", "uptime": 86400, "num_sta": 2, "satisfaction": 97, "system-stats": {"cpu": "12.5", "mem": "40.1"},
     "radio_table": [{"name": "wifi0", "radio": "ng", "channel": 6}, {"name": "wifi1", "radio": "na", "channel": 36}],
     "radio_table_stats": [{"name": "wifi0", "channel": 6, "num_sta": 1, "cu_total": 35}, {"name": "wifi1", "channel": 36, "num_sta": 1, "cu_total": 12}],
     "vap_table": [{"essid": "Office"}, {"essid": "Guest"}],
     "port_table": [{"port_idx": 1, "name": "Port 1", "up": True, "enable": True, "speed": 2500, "rx_bytes": 1000, "tx_bytes": 5000}]},
    {"_id": "2", "mac": "aa:aa:aa:00:00:02", "name": "sw-core", "type": "usw", "model": "USW24P", "state": 0, "num_sta": 1,
     "port_table": [{"port_idx": 1, "up": True, "speed": 1000, "rx_bytes": 10, "tx_bytes": 20, "poe_power": "4.20"},
                    {"port_idx": 2, "name": "printer", "up": False, "enable": True}]},
    {"_id": "3", "mac": "aa:aa:aa:00:00:03", "name": "udm", "type": "udm", "model": "UDMPRO", "state": 1, "serial": "X1",
     "wan1": {"up": True, "ip": "203.0.113.5", "rx_bytes-r": 1_250_000, "tx_bytes-r": 125_000, "speed": 1000},
     "wan2": {"up": False, "ip": "", "enable": True}},
]
UNIFI_CLIENTS = [
    {"mac": "cc:00:00:00:00:01", "hostname": "laptop", "ip": "192.168.1.50", "essid": "Office", "ap_mac": "aa:aa:aa:00:00:01",
     "radio": "na", "channel": 36, "signal": -55, "tx_rate": 866000, "rx_rate": 650000, "tx_bytes-r": 500_000, "rx_bytes-r": 50_000,
     "tx_bytes": 9_000_000, "rx_bytes": 1_000_000, "uptime": 3600, "satisfaction": 95, "oui": "Apple"},
    {"mac": "cc:00:00:00:00:02", "name": "phone", "essid": "Guest", "is_guest": True, "ap_mac": "aa:aa:aa:00:00:01", "radio": "ng",
     "signal": -78, "tx_bytes-r": 1000, "rx_bytes-r": 2000},
    {"mac": "cc:00:00:00:00:03", "hostname": "nas", "is_wired": True, "sw_mac": "aa:aa:aa:00:00:02", "sw_port": 5,
     "wired-tx_bytes-r": 10_000, "wired-rx_bytes-r": 20_000, "tx_bytes-r": 1, "rx_bytes-r": 1},
]


def mock_unifi(base=UNIFI):
    ok = lambda data: httpx.Response(200, json={"meta": {"rc": "ok"}, "data": data})  # noqa: E731
    respx.get(f"{base}/self/sites").mock(return_value=ok([{"name": "default", "desc": "Default"}]))
    respx.get(f"{base}/s/default/stat/device").mock(return_value=ok(UNIFI_DEVICES))
    respx.get(f"{base}/s/default/stat/sta").mock(return_value=ok(UNIFI_CLIENTS))
    respx.get(f"{base}/s/default/rest/wlanconf").mock(return_value=ok([
        {"name": "Office", "enabled": True, "security": "wpapsk", "vlan_enabled": True, "vlan": "20"},
        {"name": "Guest", "is_guest": True}, {"name": "IoT", "enabled": False}]))
    respx.get(f"{base}/s/default/stat/health").mock(return_value=ok([
        {"subsystem": "wan", "status": "ok", "isp_name": "Fiber Co", "wan_ip": "203.0.113.5"},
        {"subsystem": "www", "status": "ok", "latency": 9, "xput_down": 940.2, "xput_up": 880.1}]))


@respx.mock
def test_unifi_devices_clients_ssids_wan():
    mock_unifi()
    client = build("unifi", {"host": "192.168.1.1", "api_key": "k"})
    recs = client.collect()
    assert respx.calls[0].request.headers["X-API-KEY"] == "k"
    ap, sw, gw = recs
    assert (ap["type"], ap["status"], ap["cpu"], ap["mem"]) == ("Wireless", "up", 12.5, 40.1)
    assert "5 GHz ch 36" in ap["extra"]["radios"] and ap["ports"][0]["speed_mbps"] == 2500
    assert (sw["type"], sw["status"]) == ("Switch", "down")
    assert sw["ports"][1] == {**sw["ports"][1], "alias": "printer", "oper": "down", "speed_mbps": None}
    assert "PoE 4.20 W" in sw["ports"][0]["alias"]
    assert (gw["type"], gw["status"]) == ("Router", "warn") and gw["detail"].startswith("WAN2 down")

    data = client.data
    s = data["summary"]
    assert (s["clients"], s["wireless"], s["wired"], s["guests"], s["aps"], s["aps_up"]) == (3, 2, 1, 1, 1, 1)
    assert s["down_bps"] == 10_000_000 and s["up_bps"] == 1_000_000      # only the WAN that is up
    assert s["isp"] == "Fiber Co" and s["latency_ms"] == 9
    by = {x["name"]: x for x in data["ssids"]}
    assert by["Office"]["clients"] == 1 and by["Office"]["down_bps"] == 4_000_000 and by["Office"]["vlan"] == "20"
    assert by["IoT"]["clients"] == 0 and by["IoT"]["enabled"] is False
    laptop = data["clients"][0]
    assert (laptop["name"], laptop["ap"], laptop["band"], laptop["signal"], laptop["tx_rate_mbps"]) == ("laptop", "ap-lobby", "5 GHz", -55, 866.0)
    nas = next(c for c in data["clients"] if c["wired"])
    assert (nas["switch"], nas["switch_port"], nas["down_bps"], nas["ssid"]) == ("sw-core", 5, 80_000, None)
    assert data["aps"][0]["down_bps"] == 4_008_000 and data["aps"][0]["ssids"] == ["Guest", "Office"]
    assert "3 clients" in client.test()


@respx.mock
def test_unifi_username_login_on_classic_controller():
    respx.post("https://10.0.0.5:8443/api/auth/login").mock(return_value=httpx.Response(404))
    respx.post("https://10.0.0.5:8443/api/login").mock(return_value=httpx.Response(200, json={"meta": {"rc": "ok"}}))
    mock_unifi("https://10.0.0.5:8443/api")
    recs = build("unifi", {"host": "10.0.0.5:8443", "username": "ro", "password": "pw", "site": "Default"}).collect()
    assert len(recs) == 3


@respx.mock
def test_unifi_bad_key_explains_where_to_create_one():
    respx.get(f"{UNIFI}/self/sites").mock(return_value=httpx.Response(401))
    with pytest.raises(IntegrationError, match="Control Plane > Integrations"):
        build("unifi", {"host": "192.168.1.1", "api_key": "bad"}).collect()
    with pytest.raises(IntegrationError, match="API key, or a local username"):
        build("unifi", {"host": "192.168.1.1"})


@respx.mock
def test_unreachable_host_gives_clear_error():
    respx.get("https://10.9.9.9/api/v2/monitor/system/status").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(IntegrationError, match="Could not reach 10.9.9.9"):
        build("fortigate", {"host": "10.9.9.9", "api_token": "t"}).collect()


@respx.mock
def test_sonicwall_signs_in_collects_and_signs_out():
    base = "https://10.0.0.1/api/sonicos"
    login = respx.post(f"{base}/auth").mock(return_value=httpx.Response(200, json={"status": {"success": True}}))
    logout = respx.delete(f"{base}/auth").mock(return_value=httpx.Response(200, json={"status": {"success": True}}))
    respx.get(f"{base}/version").mock(return_value=httpx.Response(200, json={
        "model": "TZ 470", "serial_number": "2CB8ED000000", "firmware_version": "SonicOS 7.0.1-5145", "system_uptime": "12 Days"}))
    respx.get(f"{base}/interfaces/ipv4").mock(return_value=httpx.Response(200, json={"interfaces": [
        {"ipv4": {"name": "X0", "ip_assignment": {"zone": "LAN", "mode": {"static": {"ip": "192.168.168.168", "netmask": "255.255.255.0"}}}}},
        {"ipv4": {"name": "X1", "ip_assignment": {"zone": "WAN", "mode": {"dhcp": {}}}}}]}))
    respx.get(f"{base}/reporting/ssl-vpn/sessions").mock(return_value=httpx.Response(200, json=[
        {"user_name": "hopper", "client_wan_ip": "198.51.100.44", "virtual_ip": "192.168.200.10"}]))
    respx.get(f"{base}/reporting/license/security-services").mock(return_value=httpx.Response(200, json={
        "gateway_anti_virus": {"status": "Licensed", "expiration": "2027-03-01"}, "capture_atp": {"status": "Expired"}}))
    respx.get(f"{base}/reporting/high-availability/status").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/reporting/vpn/ipsec/tunnels").mock(return_value=httpx.Response(404))
    integ = build("sonicwall", {"host": "10.0.0.1", "username": "linkwatch", "password": "pw"})
    recs = integ.collect()
    assert login.called and logout.called
    assert login.calls[0].request.headers["authorization"].startswith("Basic ")
    r = recs[0]
    assert (r["external_id"], r["serial"], r["ip"], r["status"]) == ("2CB8ED000000", "2CB8ED000000", "10.0.0.1", "warn")
    assert "capture atp" in r["detail"] and "1 SSL VPN user" in r["detail"]
    d = integ.data
    assert d["interfaces"][0] == {"name": "X0", "zone": "LAN", "mode": "static", "ip": "192.168.168.168", "mask": "255.255.255.0",
                                  "comment": None, "mtu": None, "vlan": None, "shutdown": False}
    assert d["interfaces"][1]["mode"] == "dhcp"
    assert d["sslvpn"][0]["user"] == "hopper" and d["sslvpn"][0]["tunnel_ip"] == "192.168.200.10"
    assert {x["name"] for x in d["licenses"]} == {"gateway anti virus", "capture atp"}
    assert d["not_offered"] == ["High availability", "IPsec tunnels"] and d["unavailable"] == []


@respx.mock
def test_sonicwall_bad_login_and_logout_after_errors():
    base = "https://fw.lan:8443/api/sonicos"
    respx.post(f"{base}/auth").mock(return_value=httpx.Response(401))
    with pytest.raises(IntegrationError, match="RFC-2617 HTTP Basic"):
        build("sonicwall", {"host": "fw.lan:8443", "username": "x", "password": "y"}).collect()
    respx.post(f"{base}/auth").mock(return_value=httpx.Response(200, json={}))
    logout = respx.delete(f"{base}/auth").mock(return_value=httpx.Response(200))
    respx.get(url__startswith=f"{base}/").mock(return_value=httpx.Response(500))
    recs = build("sonicwall", {"host": "fw.lan:8443", "username": "x", "password": "y"}).collect()
    assert logout.called and recs[0]["external_id"] == "fw.lan:8443" and recs[0]["ip"] == "fw.lan"
