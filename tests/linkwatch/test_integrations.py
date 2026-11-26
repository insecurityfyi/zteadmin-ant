import httpx
import pytest
import respx

from linkwatch.integrations import REGISTRY, IntegrationError, build
from linkwatch.integrations.panos import parse_top, parse_uptime


def test_registry_has_every_platform():
    assert set(REGISTRY) == {"zscaler", "meraki", "panos", "fortigate", "unifi", "proxmox"}
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


@respx.mock
def test_unifi_devices():
    base = "https://192.168.1.1/proxy/network/integration/v1"
    respx.get(f"{base}/sites").mock(return_value=httpx.Response(200, json={"data": [{"id": "s1", "name": "Default"}]}))
    respx.get(f"{base}/sites/s1/devices").mock(return_value=httpx.Response(200, json={"totalCount": 2, "data": [
        {"id": "d1", "name": "ap-lobby", "model": "U7 Pro", "state": "ONLINE", "features": ["accessPoint"], "ipAddress": "192.168.1.20"},
        {"id": "d2", "name": "sw-core", "state": "OFFLINE", "features": ["switching"]}]}))
    recs = build("unifi", {"host": "192.168.1.1", "api_key": "k"}).collect()
    assert [(r["type"], r["status"]) for r in recs] == [("Wireless", "up"), ("Switch", "down")]


@respx.mock
def test_unreachable_host_gives_clear_error():
    respx.get("https://10.9.9.9/api/v2/monitor/system/status").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(IntegrationError, match="Could not reach 10.9.9.9"):
        build("fortigate", {"host": "10.9.9.9", "api_token": "t"}).collect()
