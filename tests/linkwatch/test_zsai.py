"""Zscaler Endpoint AI Security: collection, control actions and the pages."""
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select

from linkwatch.integrations import IntegrationError, build
from linkwatch.server.models import AuditEvent, Event, Integration

API = "https://use2.api.zsai.sqrx.io"
TOKEN_URL = "https://id.zsai.sqrx.io/v1/auth/token"
CFG = {"domain": "zsai.sqrx.io", "region": "use2", "client_id": "cid", "client_secret": "sec", "allow_control": True}
DEVICE = {"id": "dev-1", "hostname": "LAPTOP-7", "os": "macos", "status": "active", "agent_version": "2.4.1",
          "users": [{"email": "ana@acme.test"}], "last_seen_at": "2026-11-27T10:00:00Z"}
POLICY = {"id": 7, "name": "Block MCP", "enabled": True, "priority": 10, "os_platforms": ["macos"], "version": 3,
          "rules": [{"action": "block", "match": {"tool": "mcp"}}], "updated_at": "2026-11-20T00:00:00Z"}
PROFILE = {"id": 2, "name": "Engineering", "enabled": True, "is_default": False, "settings": {"scan": True}, "version": 1}
TOKENS = {"items": [{"id": 5, "label": "Fleet 2026", "status": "active", "token_preview": "zst_ab…", "use_count": 3}]}
LISTS = {
    "/api/v1/devices/stats": {"total": 2, "active": 2, "online": 1, "health": [{"value": "online", "count": 1}, {"value": "stale", "count": 1}],
                               "os": [{"value": "macos", "count": 2}]},
    "/api/v1/devices": {"items": [DEVICE, DEVICE], "next_cursor": None},     # the duplicate is dropped
    "/api/v1/events/summary": {"events": 40, "users": 3},
    "/api/v1/events/severities": {"total": 40, "bands": [{"band": "low", "count": 30}, {"band": "high", "count": 8},
                                                              {"band": "critical", "count": 2}]},
    "/api/v1/events": {"items": [{"id": "e1", "event_time": "2026-11-27T09:00:00Z", "user_email": "ana@acme.test",
                                  "tool_name": "Claude Code", "severity": "critical", "verdict": "block",
                                  "pattern_matches": [{"name": "AWS key"}]}]},
    "/api/v1/ai-assistants": {"items": [{"framework": "claude-code", "email": "ana@acme.test", "hostname": "LAPTOP-7",
                                         "mcp_server_count": 2, "suspicious_mcp_server_count": 1}]},
    "/api/v1/ai-assistants/mcp-servers": {"items": [{"name": "github", "transport": "stdio", "findings_count": 1, "users": 2}]},
    "/api/v1/ai-models": {"items": [{"name": "llama3:8b", "platform": "ollama", "users": 1}]},
    "/api/v1/browser-extensions": {"items": [{"name": "Some AI helper", "identifier": "abc", "risk_rating": 8.5, "users": 4}]},
    "/api/v1/policies": {"items": [POLICY]},
    "/api/v1/setting-profiles": {"items": [{**PROFILE, "id": 1, "name": "Default", "is_default": True}, PROFILE]},
    "/api/v1/enroll-tokens": TOKENS,
    "/api/v1/managed-users": {"items": [{"id": 9, "login_id": "ana", "primary_email": "ana@acme.test", "disabled": False}]},
    "/api/v1/audit-log": {"items": [{"occurred_at": "2026-11-27T08:00:00Z", "actor": "admin@acme.test", "action": "policy.update",
                                     "details": {"policy_id": 7}}]},
}


def token(router=respx):
    return router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900}))


def lists(router=respx):
    for path, body in LISTS.items():
        router.get(f"{API}{path}").mock(return_value=httpx.Response(200, json=body))


def sent(route, n=-1):
    return json.loads(route.calls[n].request.content)


@respx.mock
def test_collect_reads_fleet_activity_ai_tools_policy_and_audit():
    tok = token()
    lists()
    z = build("zsai", CFG)
    [rec] = z.collect()
    assert tok.calls[0].request.content.decode().count("grant_type=client_credentials") == 1
    assert rec["external_id"] == "zsai-fleet" and rec["status"] == "warn" and "10 high-severity" in rec["detail"]
    d = z.data
    assert set(d["products"]) == {"devices", "activity", "ai", "policy", "audit"} and not d["unavailable"]
    assert [x["hostname"] for x in d["devices"]] == ["LAPTOP-7"] and d["devices"][0]["users"] == ["ana@acme.test"]
    assert d["activity"]["severe"][0]["patterns"] == ["AWS key"]
    assert d["ai"]["assistants"][0]["suspicious"] == 1 and d["ai"]["mcp_servers"][0]["name"] == "github"
    assert d["policy"]["policies"][0]["rules"] == 1 and d["policy"]["profiles"][0]["default"] is True
    assert d["policy"]["tokens"][0]["preview"] == "zst_ab…" and d["audit"][0]["action"] == "policy.update"
    ev = [c.request for c in respx.calls if c.request.url.path == "/api/v1/events"]
    assert any(r.url.params.get("pattern_severity") == "high,critical" for r in ev)
    assert all(c.request.headers["authorization"] == "Bearer tok" for c in respx.calls if c.request.url.host.startswith("use2."))


@respx.mock
def test_missing_panel_is_reported_not_fatal_and_bad_settings_refused():
    token()
    lists()
    respx.get(f"{API}/api/v1/audit-log").mock(return_value=httpx.Response(403, json={"error": "forbidden", "message": "role lacks audit"}))
    z = build("zsai", CFG)
    z.collect()
    assert "audit" not in z.data["products"] and "role lacks audit" in z.data["unavailable"][0]
    with pytest.raises(IntegrationError, match="Console domain"):
        build("zsai", {**CFG, "domain": "evil.example"})
    with pytest.raises(IntegrationError, match="Region"):
        build("zsai", {**CFG, "region": "x.evil.example/"})
    assert build("zsai", {**CFG, "domain": "https://console.endpoint-ai.zscaler.com/"}).base == "https://use2.api.endpoint-ai.zscaler.com"


@respx.mock
def test_rate_limit_is_retried_and_token_refreshed():
    token()
    route = respx.get(f"{API}/api/v1/devices/dev-1").mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(401), httpx.Response(200, json=DEVICE)])
    z = build("zsai", CFG)
    z._sleep = lambda s: None
    assert z.action("device_get", {"device_id": "dev-1"})["device"]["hostname"] == "LAPTOP-7" and route.call_count == 3


@respx.mock
def test_writes_need_control_and_ids_are_checked():
    token()
    respx.get(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(200, json=POLICY, headers={"ETag": '"v3"'}))
    respx.get(f"{API}/api/v1/policies/7/assignments").mock(return_value=httpx.Response(200, json={"tenant_wide": True}))
    respx.get(f"{API}/api/v1/devices/dev-1").mock(return_value=httpx.Response(200, json=DEVICE))
    z = build("zsai", {**CFG, "allow_control": False})
    with pytest.raises(IntegrationError, match="Allow control actions"):
        z.action("policy_disable", {"policy_id": "7"})
    got = z.action("policy_get", {"policy_id": "7"})                     # reads still work
    assert got["etag"] == '"v3"' and got["assignments"] == {"tenant_wide": True}
    with pytest.raises(IntegrationError, match="Unknown"):
        z.action("drop_tables", {})
    z = build("zsai", CFG)
    for name, p in (("device_revoke", {"device_id": "../policies"}), ("policy_delete", {"policy_id": "7/../../x"}),
                    ("device_bind_user", {"device_id": "dev-1", "email": "a@b/../x"}), ("user_disable", {"user_id": "x"})):
        with pytest.raises(IntegrationError, match="Invalid"):
            z.action(name, p)


@respx.mock
def test_device_actions_and_typed_confirmation():
    token()
    respx.get(f"{API}/api/v1/devices/dev-1").mock(return_value=httpx.Response(200, json=DEVICE))
    revoke = respx.post(f"{API}/api/v1/devices/dev-1/revoke").mock(return_value=httpx.Response(200, json={}))
    delete = respx.delete(f"{API}/api/v1/devices/dev-1").mock(return_value=httpx.Response(204))
    bind = respx.post(f"{API}/api/v1/devices/dev-1/users").mock(return_value=httpx.Response(200, json={}))
    unbind = respx.delete(f"{API}/api/v1/devices/dev-1/users/ana@acme.test").mock(return_value=httpx.Response(204))
    ident = respx.put(f"{API}/api/v1/devices/dev-1/auto-identity").mock(return_value=httpx.Response(200, json={}))
    z = build("zsai", CFG)
    with pytest.raises(IntegrationError, match="Type LAPTOP-7"):
        z.action("device_revoke", {"device_id": "dev-1", "confirm_text": "dev-1"})
    assert not revoke.called
    assert "Revoked LAPTOP-7" in z.action("device_revoke", {"device_id": "dev-1", "confirm_text": "LAPTOP-7"})["message"]
    z.action("device_delete", {"device_id": "dev-1", "confirm_text": "LAPTOP-7"})
    z.action("device_bind_user", {"device_id": "dev-1", "email": "ana@acme.test"})
    z.action("device_unbind_user", {"device_id": "dev-1", "email": "ana@acme.test"})
    z.action("device_auto_identity", {"device_id": "dev-1", "enabled": "0"})
    assert delete.called and unbind.called and sent(bind) == {"email": "ana@acme.test"} and sent(ident) == {"enabled": False}


@respx.mock
def test_enrollment_tokens():
    token()
    respx.get(f"{API}/api/v1/enroll-tokens").mock(return_value=httpx.Response(200, json=TOKENS))
    create = respx.post(f"{API}/api/v1/enroll-tokens").mock(return_value=httpx.Response(201, json={
        "id": 6, "token": "zst_secret_value", "expires_at": "2026-12-05T00:00:00Z"}))
    extend = respx.post(f"{API}/api/v1/enroll-tokens/5/extend").mock(return_value=httpx.Response(200, json={"expires_at": "2027-01-01T00:00:00Z"}))
    revoke = respx.post(f"{API}/api/v1/enroll-tokens/5/revoke").mock(return_value=httpx.Response(200, json={}))
    z = build("zsai", CFG)
    r = z.action("token_create", {"label": "Lab Macs", "ttl_hours": "48", "max_uses": "10"})
    assert r["secret"] == "zst_secret_value" and "zst_secret" not in r["what"] and "zst_secret" not in r["message"]
    assert sent(create) == {"label": "Lab Macs", "ttl_hours": 48, "max_uses": 10}
    with pytest.raises(IntegrationError, match="Lifetime"):
        z.action("token_create", {"label": "x", "ttl_hours": "999999"})
    assert "2027-01-01" in z.action("token_extend", {"token_id": "5", "days": "30"})["message"] and sent(extend) == {"days": 30}
    with pytest.raises(IntegrationError, match="Type Fleet 2026"):
        z.action("token_revoke", {"token_id": "5", "confirm_text": "Fleet"})
    z.action("token_revoke", {"token_id": "5", "confirm_text": "Fleet 2026"})
    assert revoke.call_count == 1
    with pytest.raises(IntegrationError, match="No enrollment token"):
        z.action("token_extend", {"token_id": "99"})


@respx.mock
def test_policy_changes_send_if_match_and_only_allowed_fields():
    token()
    respx.get(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(200, json=POLICY, headers={"ETag": '"v3"'}))
    patch = respx.patch(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(200, json=POLICY))
    assign = respx.put(f"{API}/api/v1/policies/7/assignments").mock(return_value=httpx.Response(200, json={}))
    delete = respx.delete(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(204))
    create = respx.post(f"{API}/api/v1/policies").mock(return_value=httpx.Response(201, json={"id": 8}))
    validate = respx.post(f"{API}/api/v1/policies/validate").mock(return_value=httpx.Response(200, json={
        "valid": False, "errors": [{"message": "rules[0].action: unknown"}]}))
    z = build("zsai", CFG)

    z.action("policy_disable", {"policy_id": "7"})
    assert patch.calls[-1].request.headers["if-match"] == '"v3"' and sent(patch)["enabled"] is False
    z.action("policy_update", {"policy_id": "7", "etag": '"v2"',
                               "json": json.dumps({"name": "Block MCP", "rules": [], "id": 99, "version": 1, "tenant_id": "x"})})
    assert patch.calls[-1].request.headers["if-match"] == '"v2"' and sent(patch) == {"name": "Block MCP", "rules": []}
    z.action("policy_assign", {"policy_id": "7", "json": json.dumps({"tenant_wide": False, "users": ["ana@acme.test"], "x": 1})})
    assert sent(assign) == {"tenant_wide": False, "users": ["ana@acme.test"]}
    assert z.action("policy_create", {"json": json.dumps({"name": "New", "rules": [], "enabled": False})})["id"] == 8
    assert sent(create) == {"name": "New", "rules": [], "enabled": False}
    r = z.action("policy_validate", {"json": json.dumps({"rules": [{"action": "nope"}]}), "policy_id": "7"})
    assert not r["valid"] and "unknown" in r["message"] and sent(validate) == {"rules": [{"action": "nope"}], "policy_id": 7}
    with pytest.raises(IntegrationError, match="valid JSON"):
        z.action("policy_update", {"policy_id": "7", "json": "{nope"})
    with pytest.raises(IntegrationError, match="Type Block MCP"):
        z.action("policy_delete", {"policy_id": "7", "confirm_text": "block mcp"})
    z.action("policy_delete", {"policy_id": "7", "confirm_text": "Block MCP"})
    assert delete.calls[0].request.headers["if-match"] == '"v3"'

    patch.mock(return_value=httpx.Response(412, json={"error": "precondition_failed"}))
    with pytest.raises(IntegrationError, match="changed it since"):
        z.action("policy_enable", {"policy_id": "7"})


@respx.mock
def test_profiles_and_managed_users():
    token()
    respx.get(f"{API}/api/v1/setting-profiles/2").mock(return_value=httpx.Response(200, json=PROFILE, headers={"ETag": "W/\"p1\""}))
    respx.get(f"{API}/api/v1/setting-profiles/1").mock(return_value=httpx.Response(200, json={**PROFILE, "id": 1, "is_default": True}))
    patch = respx.patch(f"{API}/api/v1/setting-profiles/2").mock(return_value=httpx.Response(200, json=PROFILE))
    off = respx.post(f"{API}/api/v1/managed-users/9/disable").mock(return_value=httpx.Response(200, json={"login_id": "ana"}))
    z = build("zsai", CFG)
    z.action("profile_disable", {"profile_id": "2"})
    assert sent(patch) == {"enabled": False} and patch.calls[-1].request.headers["if-match"] == 'W/"p1"'
    z.action("profile_update", {"profile_id": "2", "json": json.dumps({"settings": {"scan": False}, "is_default": True})})
    assert sent(patch) == {"settings": {"scan": False}}
    with pytest.raises(IntegrationError, match="default setting profile"):
        z.action("profile_disable", {"profile_id": "1"})
    assert "Sign-in off for ana" in z.action("user_disable", {"user_id": "9"})["message"] and off.called


# ------------------------------------------------------------------ pages
@pytest.fixture
def zsai(app):
    with respx.mock:
        token()
        lists()
        client = build("zsai", CFG)
        client.collect()
        data = {**client.data, "ts": "2026-11-27T10:00:00Z"}
    state = app.state.lw
    with state.db.session() as s:
        i = Integration(kind="zsai", name="Endpoint AI", status="ok", config_enc=state.vault.seal(CFG), data=data)
        s.add(i)
        s.flush()
        return i.id


def _post(client, iid, **data):
    return client.post(f"/integrations/{iid}/zsai/action", data=data, follow_redirects=False)


def test_tabs_render(logged_in, zsai):
    for tab, text in (("overview", "Fleet health"), ("devices", "LAPTOP-7"), ("activity", "AWS key"), ("ai", "llama3:8b"),
                      ("policy", "Block MCP"), ("audit", "policy.update")):
        page = logged_in.get(f"/integrations/{zsai}/overview?tab={tab}")
        assert page.status_code == 200 and text in page.text, tab
    page = logged_in.get(f"/integrations/{zsai}/overview?tab=policy").text
    assert f"/integrations/{zsai}/zsai/policy/7" in page and f"/integrations/{zsai}/zsai/profile/2" in page
    assert 'value="token_create"' in page and 'data-confirm="typed"' in page and "/static/hv.js" in page


def test_actions_confirm_audit_resync_and_viewers(app, logged_in, zsai):
    with respx.mock(assert_all_mocked=True) as mock:
        token(mock)
        lists(mock)
        mock.get(f"{API}/api/v1/devices/dev-1").mock(return_value=httpx.Response(200, json=DEVICE))
        revoke = mock.post(f"{API}/api/v1/devices/dev-1/revoke").mock(return_value=httpx.Response(200, json={}))
        create = mock.post(f"{API}/api/v1/enroll-tokens").mock(return_value=httpx.Response(201, json={"id": 6, "token": "zst_secret_value"}))
        # not confirmed, then confirmed without the typed name: nothing is sent
        _post(logged_in, zsai, action="device_revoke", device_id="dev-1")
        _post(logged_in, zsai, action="device_revoke", device_id="dev-1", confirm="yes")
        assert not revoke.called
        r = _post(logged_in, zsai, action="device_revoke", device_id="dev-1", confirm="yes", confirm_text="LAPTOP-7",
                  what="device LAPTOP-7", back="https://evil.example/")
        assert r.headers["location"] == f"/integrations/{zsai}/overview" and revoke.called
        # wrong typed name: the integration refuses it
        r = _post(logged_in, zsai, action="device_revoke", device_id="dev-1", confirm="yes", confirm_text="LAPTOP")
        assert revoke.call_count == 1
        page = logged_in.post(f"/integrations/{zsai}/zsai/action", data={"action": "token_create", "label": "Lab"})
        assert page.status_code == 200 and "zst_secret_value" in page.text and create.called
    with app.state.lw.db.session() as s:
        acts = [(a.action, a.detail) for a in s.scalars(select(AuditEvent).where(AuditEvent.action.like("Endpoint AI%")))]
        assert any(a == "Endpoint AI: revoke device" and "LAPTOP-7 (dev-1)" in d for a, d in acts)
        assert any(a == "Endpoint AI revoke device failed" for a, _ in acts)
        assert not any("zst_secret_value" in d for _, d in acts)
        assert s.scalar(select(Event).where(Event.message.like("admin: Revoke device on Endpoint AI%")))
        assert s.get(Integration, zsai).last_sync is not None                    # collected again after the change

    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    viewer = TestClient(app)
    viewer.post("/login", data={"username": "noc", "password": "noc-password-123"})
    page = viewer.get(f"/integrations/{zsai}/overview?tab=devices").text
    assert "LAPTOP-7" in page and 'value="device_revoke"' not in page
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        route = mock.route().mock(return_value=httpx.Response(200, json={}))
        _post(viewer, zsai, action="user_disable", user_id="9", confirm="yes")
        viewer.post(f"/integrations/{zsai}/zsai/validate", data={"json": "{}"})
        assert not route.called


def test_control_off_is_read_only(app, logged_in, zsai):
    with app.state.lw.db.session() as s:
        s.get(Integration, zsai).config_enc = app.state.lw.vault.seal({**CFG, "allow_control": False})
    page = logged_in.get(f"/integrations/{zsai}/overview?tab=devices").text
    assert "Control actions are off" in page and 'value="device_revoke"' not in page
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        route = mock.route().mock(return_value=httpx.Response(200, json={}))
        r = _post(logged_in, zsai, action="user_disable", user_id="9", confirm="yes")
        assert r.status_code == 303 and not route.called


def test_policy_and_profile_editors(logged_in, zsai):
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as mock:
        token(mock)
        lists(mock)
        mock.get(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(200, json=POLICY, headers={"ETag": '"v3"'}))
        mock.get(f"{API}/api/v1/policies/7/assignments").mock(return_value=httpx.Response(200, json={"tenant_wide": True}))
        mock.get(f"{API}/api/v1/setting-profiles/2").mock(return_value=httpx.Response(200, json=PROFILE, headers={"ETag": '"p1"'}))
        mock.post(f"{API}/api/v1/policies/validate").mock(return_value=httpx.Response(200, json={"valid": True, "errors": []}))
        patch = mock.patch(f"{API}/api/v1/policies/7").mock(return_value=httpx.Response(200, json=POLICY))
        page = logged_in.get(f"/integrations/{zsai}/zsai/policy/7").text
        assert "Block MCP" in page and 'name="etag" value="&#34;v3&#34;"' in page and 'value="policy_update"' in page
        assert 'formaction="/integrations/' in page and "&#34;tenant_wide&#34;: true" in page
        assert 'value="policy_create"' in logged_in.get(f"/integrations/{zsai}/zsai/policy/new").text
        page = logged_in.post(f"/integrations/{zsai}/zsai/validate", data={"policy_id": "7", "etag": '"v3"', "json": '{"rules": []}'}).text
        assert "The rules are valid." in page and not patch.called
        r = _post(logged_in, zsai, action="policy_update", policy_id="7", etag='"v3"', json='{"priority": 5}', confirm="yes",
                  back=f"/integrations/{zsai}/zsai/policy/7")
        assert r.headers["location"] == f"/integrations/{zsai}/zsai/policy/7" and sent(patch) == {"priority": 5}
        page = logged_in.get(f"/integrations/{zsai}/zsai/profile/2").text
        assert "Engineering" in page and 'value="profile_update"' in page
        assert logged_in.get(f"/integrations/{zsai}/zsai/policy/x..y").status_code == 404
