"""Wireless access points on the network map: UniFi and Meraki uplinks, mesh links, client counts."""
import time

import httpx
import respx
from sqlalchemy import select

from linkwatch.integrations import build
from linkwatch.server.models import Device, Integration, Neighbor


@respx.mock
def test_meraki_access_point_uplinks_mesh_and_clients():
    base = "https://api.meraki.com/api/v1"
    respx.get(f"{base}/organizations").mock(return_value=httpx.Response(200, json=[{"id": "55"}]))
    respx.get(f"{base}/organizations/55/networks").mock(return_value=httpx.Response(200, json=[
        {"id": "N1", "name": "Branch", "productTypes": ["switch", "wireless"]}]))
    respx.get(f"{base}/organizations/55/devices/statuses").mock(return_value=httpx.Response(200, json=[
        {"serial": s, "status": "online"} for s in ("SW", "AP1", "AP2")]))
    respx.get(f"{base}/organizations/55/devices").mock(return_value=httpx.Response(200, json=[
        {"serial": "SW", "name": "br-sw01", "mac": "aa:00:00:00:00:01", "productType": "switch", "networkId": "N1"},
        {"serial": "AP1", "name": "br-ap01", "mac": "aa:00:00:00:00:02", "productType": "wireless", "networkId": "N1"},
        {"serial": "AP2", "name": "br-ap02", "mac": "aa:00:00:00:00:03", "productType": "wireless", "networkId": "N1"}]))
    respx.get(f"{base}/networks/N1/topology/linkLayer").mock(return_value=httpx.Response(200, json={"links": [
        {"ends": [{"device": {"serial": "AP1"}, "discovered": {"lldp": {"portId": "0"}}},
                  {"device": {"serial": "SW"}, "discovered": {"lldp": {"portId": "Port 7"}}}]}]}))
    respx.get(f"{base}/networks/N1/wireless/meshStatuses").mock(return_value=httpx.Response(200, json=[
        {"serial": "AP2", "meshRoute": ["AP2", "AP1"]}]))
    respx.get(f"{base}/organizations/55/wireless/clients/overview/byDevice").mock(return_value=httpx.Response(200, json=[
        {"serial": "AP1", "counts": {"byStatus": {"online": 14}}}, {"serial": "AP2", "counts": {"byStatus": {"online": 3}}}]))
    recs = {r["external_id"]: r["extra"] for r in build("meraki", {"api_key": "k"}).collect()}
    assert recs["AP1"]["uplink_mac"] == "aa:00:00:00:00:01" and recs["AP1"]["uplink_port"] == "Port 7"
    assert not recs["AP1"]["uplink_wireless"] and recs["AP1"]["clients"] == 14
    assert recs["AP2"]["uplink_mac"] == "aa:00:00:00:00:02" and recs["AP2"]["uplink_wireless"] and recs["AP2"]["clients"] == 3
    assert "uplink_mac" not in recs["SW"]


def test_map_shows_access_points_with_mesh_links(logged_in, app):
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    with app.state.lw.db.session() as s:
        integ = Integration(kind="unifi", name="UniFi", config_enc="-", enabled=True)
        s.add(integ)
        s.flush()
        recs = [{"external_id": "sw", "hostname": "core-usw", "type": "Switch", "status": "up", "extra": {"mac": "aa:01"}},
                {"external_id": "ap1", "hostname": "lobby-ap", "type": "Wireless", "status": "up",
                 "extra": {"mac": "aa:02", "clients": 21, "uplink_mac": "aa:01", "uplink_port": 5, "uplink_wireless": False}},
                {"external_id": "ap2", "hostname": "yard-ap", "type": "Wireless", "status": "warn",
                 "extra": {"mac": "aa:03", "clients": 1, "uplink_mac": "aa:02", "uplink_wireless": True}},
                {"external_id": "ap3", "hostname": "spare-ap", "type": "Wireless", "status": "down", "extra": {"mac": "aa:04"}}]
        ingest_integration(s, Alerter(s), integ, {"ok": True, "records": recs, "ts": time.time()})
        assert {n.protocol for n in s.scalars(select(Neighbor))} == {"unifi", "unifi-mesh"}
        ids = {d.hostname: d.id for d in s.scalars(select(Device))}
    m = logged_in.get("/ui/map").json()
    nodes = {n["name"]: n for n in m["nodes"]}
    assert set(nodes) == {"core-usw", "lobby-ap", "yard-ap", "spare-ap"}      # unlinked APs are still drawn
    assert nodes["lobby-ap"]["ap"] and nodes["lobby-ap"]["clients"] == 21 and not nodes["core-usw"]["ap"]
    links = {(l["source"], l["target"]): l for l in m["links"]}
    assert not links[(ids["lobby-ap"], ids["core-usw"])]["mesh"] and links[(ids["lobby-ap"], ids["core-usw"])]["b_port"] == "port 5"
    assert links[(ids["yard-ap"], ids["lobby-ap"])]["mesh"]
    m = logged_in.get("/ui/map?hide_aps=1").json()
    assert [n["name"] for n in m["nodes"]] == ["core-usw"] and m["links"] == []     # switches draw even with no links
    assert "Hide access points" in logged_in.get("/map").text
