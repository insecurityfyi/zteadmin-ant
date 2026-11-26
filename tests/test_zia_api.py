import httpx
import pytest
import respx

from app.zia.auth import AuthError, LegacyAuth, OneApiAuth, obfuscate_api_key
from app.zia.client import ZiaApiError, ZiaClient
from app.zia.policies import classify_action, fetch_all_rules, normalise_rule

BASE = "https://api.zsapi.net/zia/api/v1"
TOKEN = "https://acme.zslogin.net/oauth2/v1/token"


def oneapi_client():
    return ZiaClient(OneApiAuth("acme", "cid", "secret"), http=httpx.Client(), sleep=lambda s: None)


def test_obfuscate_api_key():
    # n = "123456", r = "061728"
    assert obfuscate_api_key("abcdefghijkl", 1600000123456) == "bcdefgcidjek"


@respx.mock
def test_oneapi_token_is_fetched_once_and_sent_as_bearer():
    token = respx.post(TOKEN).mock(return_value=httpx.Response(200, json={"access_token": "t1", "expires_in": 3600}))
    rules = respx.get(f"{BASE}/urlFilteringRules").mock(return_value=httpx.Response(200, json=[{"id": 1}]))
    c = oneapi_client()
    assert c.get("urlFilteringRules") == [{"id": 1}]
    c.get("urlFilteringRules")
    assert token.call_count == 1
    assert rules.calls[0].request.headers["Authorization"] == "Bearer t1"
    body = token.calls[0].request.content.decode()
    assert "grant_type=client_credentials" in body and "audience=https%3A%2F%2Fapi.zscaler.com" in body


@respx.mock
def test_oneapi_bad_credentials_raise_auth_error():
    respx.post(TOKEN).mock(return_value=httpx.Response(401, json={}))
    with pytest.raises(AuthError):
        oneapi_client().get("urlFilteringRules")


@respx.mock
def test_retries_on_429_using_body_retry_after():
    respx.post(TOKEN).mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    route = respx.get(f"{BASE}/users").mock(side_effect=[
        httpx.Response(429, json={"Retry-After": "2 seconds"}),
        httpx.Response(200, json=[]),
    ])
    slept = []
    c = ZiaClient(OneApiAuth("acme", "cid", "s"), http=httpx.Client(), sleep=slept.append)
    assert c.get("users") == []
    assert route.call_count == 2 and slept == [2.0]


@respx.mock
def test_reauthenticates_once_on_401():
    token = respx.post(TOKEN).mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    respx.get(f"{BASE}/status").mock(side_effect=[httpx.Response(401), httpx.Response(200, json={"status": "ACTIVE"})])
    assert oneapi_client().get("status") == {"status": "ACTIVE"}
    assert token.call_count == 2


@respx.mock
def test_paging_stops_on_short_page():
    respx.post(TOKEN).mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    route = respx.get(f"{BASE}/users").mock(side_effect=[
        httpx.Response(200, json=[{"id": i} for i in range(2)]),
        httpx.Response(200, json=[{"id": 9}]),
    ])
    assert len(oneapi_client().get_paged("users", page_size=2)) == 3
    assert route.calls[1].request.url.params["page"] == "2"


@respx.mock
def test_legacy_login_uses_session_cookie():
    login = respx.post("https://zsapi.zscalertwo.net/api/v1/authenticatedSession").mock(
        return_value=httpx.Response(200, json={}, headers={"Set-Cookie": "JSESSIONID=abc; Path=/"}))
    rules = respx.get("https://zsapi.zscalertwo.net/api/v1/urlFilteringRules").mock(return_value=httpx.Response(200, json=[]))
    c = ZiaClient(LegacyAuth("zscalertwo.net", "admin@acme", "pw", "abcdefghijkl"), http=httpx.Client())
    c.get("urlFilteringRules")
    assert login.called and rules.calls[0].request.headers["Cookie"] == "JSESSIONID=abc"
    sent = login.calls[0].request.content.decode()
    assert '"username":"admin@acme"' in sent.replace(" ", "") and "abcdefghijkl" not in sent


@pytest.mark.parametrize("raw,expected", [
    ("ALLOW", "Allowed"), ("BLOCK_DROP", "Blocked"), ("BLOCK_RESET", "Blocked"), ("ISOLATE", "Isolated"),
    ("ISOLATE_WEBMAIL_VIEW", "Isolated"), ("CAUTION", "Caution"), ("DO_NOT_DECRYPT", "Allowed"), ("", "Other"),
])
def test_classify_action(raw, expected):
    assert classify_action(raw) == expected


def test_normalise_rules_of_different_shapes():
    ssl = normalise_rule("SSL inspection", {"id": 1, "name": "Bypass", "order": 2, "action": {"type": "DO_NOT_DECRYPT"},
                                            "urlCategories": ["HEALTH"], "lastModifiedTime": 1700000000})
    assert ssl.action == "Allowed" and ssl.raw_action == "DO_NOT_DECRYPT"
    assert ssl.criteria == [("URL categories", "HEALTH")] and ssl.last_modified.startswith("2023-11-14")
    app = normalise_rule("Cloud app control", {"name": "Mail", "actions": ["ALLOW_WEBMAIL_VIEW", "ISOLATE_WEBMAIL_VIEW"],
                                               "groups": [{"id": 5, "name": "Contractors"}]})
    assert app.action == "Isolated" and app.applies_to == "Groups: Contractors"
    ft = normalise_rule("File type control", {"name": "Exe", "filteringAction": "BLOCK", "fileTypes": list("abcdefgh")})
    assert ft.action == "Blocked" and ft.criteria[0][1].endswith("and 2 more")


@respx.mock
def test_fetch_all_rules_collects_errors_per_type():
    respx.post(TOKEN).mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    respx.get(f"{BASE}/urlFilteringRules").mock(return_value=httpx.Response(200, json=[{"id": 1, "name": "A", "order": 1, "action": "BLOCK"}]))
    respx.get(f"{BASE}/webDlpRules").mock(return_value=httpx.Response(403))
    respx.get(f"{BASE}/webApplicationRules/ruleTypeMapping").mock(return_value=httpx.Response(200, json={"Webmail": "WEBMAIL"}))
    respx.get(f"{BASE}/webApplicationRules/WEBMAIL").mock(return_value=httpx.Response(200, json=[{"id": 2, "name": "B", "actions": ["BLOCK_WEBMAIL_SEND"]}]))
    respx.get(url__regex=rf"{BASE}/.*").mock(return_value=httpx.Response(200, json=[]))
    rules, errors = fetch_all_rules(oneapi_client())
    assert [r["name"] for r in rules] == ["A", "B"]
    assert list(errors) == ["DLP"] and "403" in errors["DLP"]


def test_api_error_message():
    assert "HTTP 404" in str(ZiaApiError("x", 404))
