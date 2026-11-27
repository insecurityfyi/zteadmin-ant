"""SSE platforms (Netskope, Cato, Prisma Access, Cloudflare) against mocked APIs.

The response shapes follow each vendor's published docs; none of this has been checked
against a live tenant.
"""
import json

import httpx
import pytest
import respx

from linkwatch.integrations import REGISTRY, IntegrationError, build, sse


@pytest.fixture(autouse=True)
def clear_cache():
    sse._CACHE.clear()
    yield
    sse._CACHE.clear()


def test_sse_registry_and_fields():
    for kind in ("netskope", "cato", "prisma", "cloudflare"):
        cls = REGISTRY[kind]
        assert cls.sse and cls.runs_on == "server"
        names = [f.name for f in cls.fields]
        assert set(cls.sections) <= set(names) and "ai_category" in names, kind
        assert all(k in dict(sse.SECTIONS) for k in cls.sections)


def test_helpers():
    assert sse.status_of("Connected") == "up" and sse.status_of("DISCONNECTED") == "down" and sse.status_of("degraded") == "warn"
    assert sse.status_of(None) == "unknown"
    assert sse.worst(["up", "down"]) == "warn" and sse.worst(["down", "down"]) == "down" and sse.worst(["up"]) == "up"
    assert sse.worst([]) == "unknown"
    assert sse.is_ai("Generative AI", "x") and sse.is_ai("Business", "ChatGPT") and not sse.is_ai("File Sharing", "Box")
    assert sse.is_ai("LLM Tools", "x", ai_category="LLM Tools") and not sse.is_ai("Generative AI", "x", ai_category="LLM Tools")


# Netskope ---------------------------------------------------------------------
NS = "https://acme.goskope.com"


@respx.mock
def test_netskope_collects_every_section():
    respx.get(f"{NS}/api/v2/steering/ipsec/tunnels").mock(return_value=httpx.Response(200, json={"result": [
        {"id": 11, "site": "Dallas", "status": "up", "sourceidentity": "203.0.113.4", "pops": [{"name": "DFW1"}, {"name": "IAH1"}], "enabled": True},
        {"id": 12, "site": "Austin", "status": "down", "sourceidentity": "203.0.113.9", "pops": ["DFW1"]}]}))
    respx.get(f"{NS}/api/v2/steering/gre/tunnels").mock(return_value=httpx.Response(404))
    respx.get(f"{NS}/api/v2/infrastructure/publishers").mock(return_value=httpx.Response(200, json={"data": {"publishers": [
        {"publisher_id": 5, "publisher_name": "pub-dc1", "status": "connected", "apps_count": 4, "assessment": {"version": "118.0.0", "ip_address": "10.0.0.5"}},
        {"publisher_id": 6, "publisher_name": "pub-dc2", "status": "not registered"}]}, "status": "success"}))
    respx.get(f"{NS}/api/v2/steering/apps/private").mock(return_value=httpx.Response(200, json={"data": {"private_apps": [{"app_name": "intranet"}]}}))

    def datasearch(request):
        t = request.url.path.rsplit("/", 1)[-1]
        q = request.url.params
        if t == "clientstatus":
            return httpx.Response(200, json={"result": [
                {"device_id": "d1", "hostname": "LT-1", "user": "ada@contoso.com", "os": "Windows", "os_version": "11", "client_version": "120.1", "status": "Enabled", "timestamp": 1700000000},
                {"device_id": "d1", "hostname": "LT-1", "user": "ada@contoso.com", "client_version": "119.0", "status": "Disabled", "timestamp": 1600000000},
                {"device_id": "d2", "hostname": "MB-2", "user": "bob@contoso.com", "os": "Mac", "client_version": "120.1", "status": "Disabled", "timestamp": 1700000500}],
                "status": {"execution": "SUCCESS"}})
        if t == "application" and "user" in q.get("groupbys", ""):
            return httpx.Response(200, json={"result": [{"app": "ChatGPT", "user": "a"}, {"app": "ChatGPT", "user": "b"}, {"app": "Box", "user": "a"}]})
        if t == "application" and q.get("query"):
            return httpx.Response(200, json={"result": [{"app": "DeepSeek", "events": 9}]})
        if t == "application":
            assert "count(_id)" in q["fields"] and q["groupbys"] == "app,appcategory,ccl"
            return httpx.Response(200, json={"result": [
                {"app": "Box", "appcategory": "Cloud Storage", "ccl": "high", "events": 900, "up": 5e8, "down": 9e8},
                {"app": "ChatGPT", "appcategory": "Generative AI", "ccl": "medium", "events": 300, "up": 2e8, "down": 6e8},
                {"app": "DeepSeek", "appcategory": "Generative AI", "ccl": "poor", "events": 9, "up": 1e3, "down": 1e3}]})
        if t == "alert" and "groupbys" in q:
            return httpx.Response(200, json={"result": [{"dlp_rule_severity": "high", "n": 3}, {"dlp_rule_severity": "low", "n": 1}]})
        if t == "alert":
            assert q["query"] == "alert_type eq 'DLP'"
            return httpx.Response(200, json={"result": [
                {"timestamp": 1700000000, "user": "ada@contoso.com", "app": "ChatGPT", "dlp_profile": "PII", "dlp_rule": "SSN", "dlp_rule_severity": "high", "action": "block"}]})
        return httpx.Response(404)
    respx.get(url__regex=rf"{NS}/api/v2/events/datasearch/.*").mock(side_effect=datasearch)
    respx.get(f"{NS}/api/v2/policy/npa/rules").mock(return_value=httpx.Response(200, json={"data": [
        {"rule_name": "Engineers to Git", "rule_order": {"order": 2}, "enabled": "1",
         "rule_data": {"privateApps": ["git"], "userGroups": ["Engineering"], "match_criteria_action": {"action_name": "allow"}}},
        {"rule_name": "Default deny", "rule_order": 9, "enabled": "0", "rule_data": {"match_criteria_action": {"action_name": "block"}}}]}))

    n = build("netskope", {"tenant": "acme", "token": " tok\n"})
    recs = {r["external_id"]: r for r in n.collect()}
    assert n.errors == []
    req = respx.calls[0].request
    assert req.headers["Netskope-Api-Token"] == "tok"
    d = n.data
    assert d["sse"] and set(d["products"]) == {"sites", "private", "users", "policy", "apps", "dlp"}
    assert recs["sites-ipsec-11"]["status"] == "up" and recs["sites-ipsec-12"]["status"] == "down"
    assert recs["sites-ipsec-11"]["extra"]["product"] == "sites"
    assert any("GRE tunnels" in u for u in d["unavailable"])
    assert recs["private-5"]["status"] == "up" and recs["private-6"]["status"] == "down" and d["private"]["apps"] == 1
    assert d["users"]["total"] == 2 and d["users"]["connected"] == 1
    assert {x["version"] for x in d["users"]["devices"]} == {"120.1"}       # newest status per device wins
    rules = d["policy"]["rulebases"][0]["rules"]
    assert rules[0]["name"] == "Engineers to Git" and rules[0]["scope"] == "Engineering" and not rules[1]["enabled"]
    apps = {a["name"]: a for a in d["apps"]["items"]}
    assert apps["ChatGPT"]["ai"] and not apps["Box"]["ai"] and apps["ChatGPT"]["users"] == 2 and apps["ChatGPT"]["bytes"] == 8e8
    assert apps["DeepSeek"]["action"] == "block"
    assert d["dlp"]["total"] == 4 and d["dlp"]["ai_incidents"] == 1 and d["dlp"]["incidents"][0]["profile"] == "PII"
    assert recs["dlp-summary"]["status"] == "warn"
    assert d["gaps"]["policy"]


@respx.mock
def test_netskope_bad_token_fails_cleanly():
    respx.get(url__regex=rf"{NS}/.*").mock(return_value=httpx.Response(401))
    with pytest.raises(IntegrationError, match="refused"):
        build("netskope", {"tenant": "https://acme.goskope.com/", "token": "bad", "sites": False, "apps": False, "dlp": False}).collect()


@respx.mock
def test_netskope_datasearch_failure_in_body():
    respx.get(f"{NS}/api/v2/events/datasearch/clientstatus").mock(return_value=httpx.Response(200, json={
        "status": {"execution": "FAILED", "message": "invalid query"}}))
    n = build("netskope", {"tenant": "acme.goskope.com", "token": "t", "sites": False, "private": False, "policy": False, "apps": False, "dlp": False})
    with pytest.raises(IntegrationError, match="invalid query"):
        n.collect()


# Cato -----------------------------------------------------------------------
CATO = "https://api.catonetworks.com/api/v1/graphql2"


@respx.mock
def test_cato_collects_and_falls_back_on_schema_errors():
    seen = []

    def gql(request):
        body = json.loads(request.content)
        q, v = body["query"], body["variables"]
        assert request.headers["x-api-key"] == "k" and v["accountID"] == "123"
        seen.append(q.split("(")[0])
        if "query sites" in q and "devices" in q:
            return httpx.Response(200, json={"errors": [{"message": "Cannot query field \"countryName\""}]})
        if "query sites" in q:
            return httpx.Response(200, json={"data": {"accountSnapshot": {"sites": [
                {"id": "1", "connectivityStatus": "connected", "operationalStatus": "active", "popName": "Dallas", "info": {"name": "HQ", "type": "BRANCH"}},
                {"id": "2", "connectivityStatus": "disconnected", "operationalStatus": "active", "popName": "Austin", "info": {"name": "Lab"}}]}}})
        if "accountMetrics" in q:
            return httpx.Response(200, json={"data": {"accountMetrics": {"sites": [
                {"id": "1", "metrics": {"rtt": 12.5, "lostUpstreamPcnt": 0.1, "lostDownstreamPcnt": 0.4, "bytesDownstream": 3600e6, "bytesUpstream": 360e6}}]}}})
        if "query users" in q:
            return httpx.Response(200, json={"data": {"accountSnapshot": {"users": [
                {"id": "u1", "connectivityStatus": "connected", "name": "Ada", "deviceName": "LT-1", "version": "5.10", "info": {"email": "ada@contoso.com"}},
                {"id": "u2", "connectivityStatus": "disconnected", "name": "Bob", "version": "5.9"}]}}})
        if "query policy" in q:
            return httpx.Response(200, json={"data": {"policy": {"internetFirewall": {"policy": {"enabled": True, "rules": [
                {"rule": {"id": "r1", "name": "Block DeepSeek", "index": 1, "enabled": True, "action": {"action": "BLOCK"}}}]}}, "wanFirewall": None}}})
        if "appStats" in q:
            dims = [d["fieldName"] for d in v["dimensions"]]
            if dims == ["application", "category"]:
                return httpx.Response(200, json={"data": {"appStats": {"records": [
                    {"fieldsMap": {"application": "ChatGPT", "category": "Generative AI", "traffic": "8000", "upstream": "3000", "downstream": "5000", "flows_created": "40"}},
                    {"fieldsMap": {"application": "Office 365", "category": "Business", "traffic": "90000"}}]}}})
            if "ad_name" in json.dumps(v["measures"]):
                return httpx.Response(200, json={"data": {"appStats": {"records": [{"fieldsMap": {"application": "ChatGPT", "ad_name": "7"}}]}}})
            return httpx.Response(200, json={"errors": [{"message": "unknown dimension sanctioned"}]})
        if "events(" in q:
            return httpx.Response(200, json={"data": {"events": {"records": [
                {"fieldsMap": {"application": "ChatGPT", "rule_name": "PII to AI", "severity": "High", "action": "Block", "event_count": "5"}},
                {"fieldsMap": {"application": "Box", "rule_name": "PII to AI", "severity": "Low", "action": "Monitor", "event_count": "2"}}]}}})
        return httpx.Response(400)
    respx.post(CATO).mock(side_effect=gql)
    c = build("cato", {"account_id": "123", "api_key": "k"})
    recs = {r["external_id"]: r for r in c.collect()}
    d = c.data
    assert c.errors == [] and "private" not in d["products"]
    assert recs["sites-1"]["status"] == "up" and recs["sites-2"]["status"] == "down"
    hq = next(x for x in d["sites"]["items"] if x["name"] == "HQ")
    assert hq["rtt_ms"] == 12.5 and hq["loss_pct"] == 0.4 and round(hq["down_bps"]) == 8_000_000
    assert d["users"]["total"] == 2 and d["users"]["connected"] == 1 and d["users"]["devices"][0]["user"] == "ada@contoso.com"
    assert d["policy"]["rulebases"][0]["rules"][0]["action"] == "block"
    apps = {a["name"]: a for a in d["apps"]["items"]}
    assert apps["ChatGPT"]["ai"] and apps["ChatGPT"]["users"] == 7 and apps["ChatGPT"]["up"] == 3000
    assert any("risk" in u for u in d["unavailable"])
    assert d["dlp"]["total"] == 7 and d["dlp"]["ai_incidents"] == 5 and d["dlp"]["by_severity"][0] == ["High", 5]


@respx.mock
def test_cato_bad_key():
    respx.post(CATO).mock(return_value=httpx.Response(200, json={"errors": [{"message": "permission denied"}]}))
    with pytest.raises(IntegrationError, match="Check the API key"):
        build("cato", {"account_id": "1", "api_key": "x", "apps": False, "dlp": False}).collect()


# Prisma Access ---------------------------------------------------------------
PA = "https://api.sase.paloaltonetworks.com"


@respx.mock
def test_prisma_collects_with_insights_fallback():
    token = respx.post("https://auth.apps.paloaltonetworks.com/oauth2/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 899}))
    respx.get(f"{PA}/sse/config/v1/remote-networks").mock(return_value=httpx.Response(200, json={"data": [
        {"id": "rn1", "name": "Dallas", "region": "us-southwest", "ipsec_tunnel": "dal-t1", "subnets": ["10.1.0.0/16"], "license_type": "FWAAS-AGGREGATE"},
        {"id": "rn2", "name": "Austin", "region": "us-southwest", "ipsec_tunnel": "aus-t1"}], "total": 2}))
    respx.post(f"{PA}/insights/v3.0/resource/query/tunnels/tunnel_list").mock(return_value=httpx.Response(404))
    tl = respx.post(f"{PA}/api/sase/v2.0/resource/custom/query/tunnels/tunnel_list").mock(return_value=httpx.Response(200, json={"data": [
        {"tunnel_name": "dal-t1", "site_name": "Dallas", "tunnel_state": 1, "edge_location_display_name": "US Central", "avg_throughput": 5e6, "node_type_name": "Remote Network"},
        {"tunnel_name": "dal-t2", "site_name": "Dallas", "tunnel_state": 0, "node_type_name": "Remote Network"},
        {"tunnel_name": "sc-dc", "site_name": "DC1", "tunnel_state": 1, "node_type_name": "Service Connection"}]}))
    respx.get(f"{PA}/sse/connector/v2.0/api/connectors").mock(return_value=httpx.Response(200, json={"items": [
        {"id": "z1", "name": "ztna-dc1", "status": "online", "version": "1.2.0"}]}))
    respx.get(f"{PA}/sse/config/v1/service-connections").mock(return_value=httpx.Response(200, json={"data": [{"id": "s1", "name": "DC1", "ipsec_tunnel": "sc-dc"}]}))
    respx.post(f"{PA}/insights/v3.0/resource/query/users/agent/connected_user_list").mock(return_value=httpx.Response(200, json={"data": [
        {"user_name": "ada", "device_name": "LT-1", "client_os": "Windows", "agent_version": "6.2.1"}]}))

    def rules(request):
        f, pos = request.url.params["folder"], request.url.params["position"]
        if f == "Shared" and pos == "pre":
            return httpx.Response(200, json={"data": [
                {"name": "Block GenAI", "action": "deny", "category": ["artificial-intelligence"], "source_user": ["any"], "profile_setting": {"group": ["best-practice"]}},
                {"name": "Allow web", "action": "allow", "disabled": True, "profile_setting": {"group": ["dlp-group"]}}]})
        return httpx.Response(200, json={"data": []})
    respx.get(f"{PA}/sse/config/v1/security-rules").mock(side_effect=rules)
    respx.post(f"{PA}/insights/v3.0/resource/query/applications/application_list").mock(return_value=httpx.Response(200, json={"data": [
        {"app_name": "openai-chatgpt", "app_category": "Generative AI", "total_bytes": 9e6, "user_count": 12},
        {"app_name": "ms-office365", "app_category": "business-systems", "total_bytes": 9e8, "user_count": 300}]}))
    respx.get(f"{PA}/sse/config/v1/data-filtering-profiles").mock(return_value=httpx.Response(200, json={"data": [{"name": "PII", "rules": [{"name": "SSN"}]}]}))
    respx.get(f"{PA}/sse/config/v1/profile-groups").mock(return_value=httpx.Response(200, json={"data": [{"name": "dlp-group", "data_filtering": ["PII"]}]}))

    p = build("prisma", {"tsg_id": "1234567890", "client_id": "svc@1234567890.iam.panserviceaccount.com", "client_secret": "s", "region": "Europe"})
    recs = {r["external_id"]: r for r in p.collect()}
    d = p.data
    assert p.errors == [], p.errors
    assert token.call_count == 1 and tl.call_count == 1          # token and tunnel list shared across tabs
    treq = token.calls[0].request
    assert b"scope=tsg_id%3A1234567890" in treq.content and treq.headers["Authorization"].startswith("Basic ")
    assert tl.calls[0].request.headers["X-PANW-Region"] == "europe" and tl.calls[0].request.headers["Prisma-Tenant"] == "1234567890"
    assert recs["sites-rn1"]["status"] == "warn" and recs["sites-rn2"]["status"] == "unknown"
    assert {x["name"] for x in d["sites"]["items"]} == {"Dallas", "Austin"}
    priv = {x["name"]: x for x in d["private"]["items"]}
    assert priv["ztna-dc1"]["status"] == "up" and priv["DC1"]["status"] == "up"
    assert d["users"]["total"] == 1 and d["users"]["devices"][0]["version"] == "6.2.1"
    rb = d["policy"]["rulebases"][0]
    assert rb["name"] == "Shared: pre-rules" and rb["rules"][0]["action"] == "deny" and not rb["rules"][1]["enabled"]
    apps = {a["name"]: a for a in d["apps"]["items"]}
    assert apps["openai-chatgpt"]["ai"] and apps["openai-chatgpt"]["users"] == 12 and not apps["ms-office365"]["ai"]
    assert d["dlp"]["profiles"][0]["detail"] == "SSN" and d["dlp"]["rules"][0]["name"] == "Allow web"


@respx.mock
def test_prisma_bad_credentials():
    respx.post("https://auth.apps.paloaltonetworks.com/oauth2/access_token").mock(return_value=httpx.Response(401))
    with pytest.raises(IntegrationError, match="Token request failed"):
        build("prisma", {"tsg_id": "1", "client_id": "c", "client_secret": "bad", "apps": False, "dlp": False}).collect()


# Cloudflare ---------------------------------------------------------------------
CF = "https://api.cloudflare.com/client/v4/accounts/abc"


def ok(result, pages=1):
    return httpx.Response(200, json={"success": True, "result": result, "result_info": {"total_pages": pages}})


@respx.mock
def test_cloudflare_collects_every_section():
    respx.get(f"{CF}/magic/ipsec_tunnels").mock(return_value=ok({"ipsec_tunnels": [
        {"id": "t1", "name": "dal_ipsec", "customer_endpoint": "203.0.113.4", "cloudflare_endpoint": "162.159.0.1", "interface_address": "10.200.0.1/31"}]}))
    respx.get(f"{CF}/magic/gre_tunnels").mock(return_value=httpx.Response(403))
    respx.get(f"{CF}/cfd_tunnel").mock(return_value=ok([
        {"id": "c1", "name": "dc1", "status": "healthy", "tun_type": "cfd_tunnel", "connections": [
            {"colo_name": "DFW", "client_version": "2024.10.0", "origin_ip": "198.51.100.2"}, {"colo_name": "IAH", "client_version": "2024.10.0"}]},
        {"id": "c2", "name": "lab", "status": "down", "connections": []}]))
    respx.get(f"{CF}/teamnet/routes").mock(return_value=ok([{"network": "10.0.0.0/8"}]))
    pages = respx.get(f"{CF}/devices").mock(side_effect=[
        ok([{"id": "d1", "name": "LT-1", "device_type": "windows", "os_version": "11", "version": "2024.9", "last_seen": "2000-01-01T00:00:00Z",
             "user": {"email": "ada@contoso.com"}}], pages=2),
        ok([{"id": "d2", "name": "MB-2", "device_type": "mac", "version": "2024.9", "last_seen": None}], pages=2)])
    respx.get(f"{CF}/access/users").mock(return_value=ok([{"email": "a", "gateway_seat": True}, {"email": "b", "gateway_seat": False}]))
    respx.get(f"{CF}/gateway/rules").mock(return_value=ok([
        {"name": "Block AI", "action": "block", "enabled": True, "filters": ["http"], "precedence": 10, "traffic": "any(app.type.ids[*] in {25})"},
        {"name": "DLP to AI", "action": "block", "enabled": True, "filters": ["http"], "precedence": 5, "traffic": "any(dlp.profiles[*] in {\"p1\"})",
         "identity": "identity.email == \"x\""},
        {"name": "Block malware", "action": "block", "enabled": False, "filters": ["dns"], "precedence": 1, "traffic": "any(dns.security_category[*] in {80})"}]))
    respx.get(f"{CF}/access/apps").mock(return_value=ok([{"name": "Wiki", "domain": "wiki.contoso.com", "type": "self_hosted", "policies": [{"name": "Staff"}]}]))
    respx.get(f"{CF}/gateway/app_types").mock(return_value=ok([
        {"id": 25, "name": "Artificial Intelligence"}, {"id": 2, "name": "Business"},
        {"id": 1199, "name": "ChatGPT", "application_type_id": 25}, {"id": 500, "name": "Salesforce", "application_type_id": 2}]))

    def gql(request):
        q = json.loads(request.content)["query"]
        if "__type" in q:
            return httpx.Response(200, json={"data": {"__type": {"fields": [{"name": "action"}, {"name": "httpApplicationIds"}, {"name": "httpHost"}]}}})
        if "magicTransport" in q:
            return httpx.Response(200, json={"data": {"viewer": {"accounts": [{"magicTransportTunnelHealthChecksAdaptiveGroups": [
                {"count": 9, "dimensions": {"tunnelName": "dal_ipsec", "resultStatus": "healthy"}},
                {"count": 1, "dimensions": {"tunnelName": "dal_ipsec", "resultStatus": "unhealthy"}}]}]}}})
        assert "httpApplicationIds action" in q
        return httpx.Response(200, json={"data": {"viewer": {"accounts": [{"gatewayL7RequestsAdaptiveGroups": [
            {"count": 70, "dimensions": {"httpApplicationIds": "1199", "action": "allow"}},
            {"count": 30, "dimensions": {"httpApplicationIds": [1199], "action": "block"}},
            {"count": 500, "dimensions": {"httpApplicationIds": "500", "action": "allow"}}]}]}}})
    respx.post("https://api.cloudflare.com/client/v4/graphql").mock(side_effect=gql)
    respx.get(f"{CF}/dlp/profiles").mock(return_value=ok([
        {"id": "p1", "name": "Financial", "type": "predefined", "entries": [{"enabled": True}, {"enabled": False}]},
        {"id": "p2", "name": "Unused", "type": "custom", "entries": [{"enabled": False}]}]))

    c = build("cloudflare", {"account_id": "abc", "api_token": "Bearer cf-token", "sites": True})
    recs = {r["external_id"]: r for r in c.collect()}
    d = c.data
    assert c.errors == [], c.errors
    assert respx.calls[0].request.headers["Authorization"] == "Bearer cf-token"
    assert recs["sites-ipsec-t1"]["status"] == "warn" and d["sites"]["items"][0]["loss_pct"] == 10.0
    assert recs["private-c1"]["status"] == "up" and recs["private-c2"]["status"] == "down"
    assert d["private"]["items"][0]["location"] == "DFW, IAH" and d["private"]["apps"] == 1
    assert pages.call_count == 2 and d["users"]["total"] == 2 and d["users"]["seats"] == 1 and d["users"]["connected"] == 0
    names = [rb["name"] for rb in d["policy"]["rulebases"]]
    assert names == ["Gateway DNS rules", "Gateway HTTP rules", "Access applications"]
    assert d["policy"]["rulebases"][1]["rules"][0]["name"] == "DLP to AI"
    apps = {a["name"]: a for a in d["apps"]["items"]}
    assert apps["ChatGPT"]["ai"] and apps["ChatGPT"]["events"] == 100 and apps["ChatGPT"]["action"] == "partly blocked"
    assert apps["Salesforce"]["category"] == "Business" and not apps["Salesforce"]["ai"]
    assert d["dlp"]["profiles"][0]["detail"] == "1 of 2 detections on" and not d["dlp"]["profiles"][1]["enabled"]
    assert [r["name"] for r in d["dlp"]["rules"]] == ["DLP to AI"]


@respx.mock
def test_cloudflare_sites_off_by_default_and_partial_failure():
    respx.get(f"{CF}/cfd_tunnel").mock(return_value=ok([{"id": "c1", "name": "dc1", "status": "degraded"}]))
    respx.get(f"{CF}/teamnet/routes").mock(return_value=httpx.Response(403))
    respx.get(f"{CF}/devices").mock(return_value=httpx.Response(403))
    c = build("cloudflare", {"account_id": "abc", "api_token": "t", "policy": False, "apps": False, "dlp": False})
    recs = c.collect()
    assert "sites" not in c.data["products"] and recs[0]["status"] == "warn"
    assert c.data["products"]["users"]["ok"] is False and "WARP devices" in c.errors[0]


@respx.mock
def test_slow_sections_are_cached_hourly():
    respx.get(f"{CF}/dlp/profiles").mock(return_value=ok([{"name": "Financial", "entries": []}]))
    respx.get(f"{CF}/gateway/rules").mock(return_value=ok([]))
    cfg = {"account_id": "abc", "api_token": "t", "private": False, "users": False, "policy": False, "apps": False}
    build("cloudflare", cfg).collect()
    c2 = build("cloudflare", cfg)
    c2.collect()
    assert respx.calls.call_count == 2 and c2.data["dlp"]["profiles"][0]["name"] == "Financial"


@respx.mock
def test_rate_limit_is_retried(monkeypatch):
    monkeypatch.setattr(sse.SSEIntegration, "_sleep", staticmethod(lambda s: None))
    route = respx.get(f"{CF}/cfd_tunnel").mock(side_effect=[httpx.Response(429, headers={"Retry-After": "1"}), ok([])])
    respx.get(f"{CF}/teamnet/routes").mock(return_value=ok([]))
    c = build("cloudflare", {"account_id": "abc", "api_token": "t", "users": False, "policy": False, "apps": False, "dlp": False})
    c.collect()
    assert route.call_count == 2 and c.data["products"]["private"]["ok"]
