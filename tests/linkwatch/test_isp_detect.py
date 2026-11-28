"""Working out each WAN's ISP: typed names, IP ranges under Settings, the gateway's report, and a cached RDAP lookup."""
import json

import httpx

from linkwatch.server import isp
from linkwatch.server.db import set_setting
from linkwatch.server.models import Device, Integration


def test_ranges_aliases_and_rdap():
    rows, bad = isp.parse_ranges("100.64.0.0/10 = Starlink Satellite\n203.0.113.0/24, Brightspeed Fiber\n# a comment\n"
                                 "203.0.113.128/25\tBrightspeed Business\nnot a range")
    assert bad == ["not a range"] and len(rows) == 3
    assert isp.by_range(rows, "100.100.1.2") == "Starlink Satellite"
    assert isp.by_range(rows, "203.0.113.200") == "Brightspeed Business"      # the most specific range wins
    assert isp.by_range(rows, "203.0.113.5") == "Brightspeed Fiber" and isp.by_range(rows, "8.8.8.8") == ""
    assert isp.ranges_text(rows).splitlines()[0] == "100.64.0.0/10 = Starlink Satellite"
    assert [isp.tidy(x) for x in ("CHARTER-COMMUNICATIONS", "SpaceX Services, Inc.", "Brightspeed", "Acme Net")] == \
        ["Spectrum", "Starlink", "Brightspeed", "Acme Net"]
    body = {"name": "SPACEX-STARLINK", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse desk"]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "SpaceX Services, Inc."]]]}]}
    assert isp.rdap_owner(body) == "SpaceX Services, Inc." and isp.rdap_owner({"name": "NET-1"}) == "NET-1"
    assert isp.is_public("98.97.1.1") and not isp.is_public("100.64.1.1") and not isp.is_public("192.168.1.1")


def test_refresh_caches_lookups(app):
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, json={"name": "CHARTER-NET", "entities": []})
    http = httpx.Client(transport=httpx.MockTransport(handler))
    with app.state.lw.db.session() as s:
        assert isp.refresh(s, ["24.0.0.1", "192.168.1.1", "24.0.0.1"], http) == 1      # private addresses are skipped
        assert isp.cached(s, "24.0.0.1") == "Spectrum"
        assert isp.refresh(s, ["24.0.0.1"], http) == 0                                # cached
        set_setting(s, isp.LOOKUP_SETTING, "off")
        assert isp.refresh(s, ["24.0.0.2"], http) == 0
    assert seen == ["https://rdap.org/ip/24.0.0.1"]


def test_map_picks_the_isp_by_precedence(logged_in, app):
    with app.state.lw.db.session() as s:
        ui = Integration(kind="unifi", name="UniFi", config_enc="-", enabled=True)
        s.add(ui)
        s.flush()
        s.add(Device(hostname="zlabcgwm", type="Router", source="unifi", integration_id=ui.id, external_id="gw", status="up",
                     extra={"mac": "aa:00:00:00:00:01"}))
        ui.data = {"type": "unifi", "wans": [
            {"name": "WAN1", "device": "zlabcgwm", "up": True, "speed_mbps": 1000, "ip": "203.0.113.5"},
            {"name": "WAN2", "device": "zlabcgwm", "up": True, "speed_mbps": 500, "ip": "24.0.0.9", "isp": "Charter Communications"},
            {"name": "WAN3", "device": "zlabcgwm", "up": True, "speed_mbps": 300, "ip": "100.79.1.2"},
            {"name": "WAN4", "device": "zlabcgwm", "up": True, "ip": "98.97.1.1"}]}
        set_setting(s, isp.CACHE_SETTING, json.dumps({"98.97.1.1": {"isp": "Starlink", "ts": 9e9}}))
    # Settings: IP ranges
    r = logged_in.post("/settings/isps", data={"ranges": "100.64.0.0/10 = Starlink Satellite\n203.0.113.0/24 = Brightspeed Fiber",
                                               "lookup": "on"}, follow_redirects=False)
    assert r.status_code == 303
    page = logged_in.get("/settings").text
    assert "Internet providers" in page and "100.64.0.0/10 = Starlink Satellite" in page
    wans = {l["wan"]: l for l in logged_in.get("/ui/map").json()["links"] if l["protocol"] == "wan"}
    assert (wans["WAN1"]["isp"], wans["WAN1"]["isp_source"]) == ("Brightspeed Fiber", "range")
    assert (wans["WAN2"]["isp"], wans["WAN2"]["isp_source"]) == ("Spectrum", "gateway")
    assert (wans["WAN3"]["isp"], wans["WAN3"]["isp_source"]) == ("Starlink Satellite", "range")
    assert (wans["WAN4"]["isp"], wans["WAN4"]["isp_source"]) == ("Starlink", "lookup")
    # a name typed for one WAN beats everything
    logged_in.post("/map/isps", data={"key": ["zlabcgwm|wan2"], "isp": ["Spectrum Business"]})
    wans = {l["wan"]: l for l in logged_in.get("/ui/map").json()["links"] if l["protocol"] == "wan"}
    assert (wans["WAN2"]["isp"], wans["WAN2"]["isp_source"], wans["WAN2"]["isp_detected"]) == ("Spectrum Business", "manual", "Spectrum")
    assert "from the gateway" in logged_in.get("/map").text
    # a bad line is refused and nothing changes
    r = logged_in.post("/settings/isps", data={"ranges": "nonsense"}, follow_redirects=True)
    assert "Could not read" in r.text and "100.64.0.0/10 = Starlink Satellite" in logged_in.get("/settings").text
