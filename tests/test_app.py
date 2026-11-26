import httpx
import respx
from fastapi.testclient import TestClient

from app.config import Config
from app.db import Store
from app.main import create_app
from app.services.settings import load_settings, Settings
from app.services.sync import run_sync
from app.crypto import load_fernet
from tests.test_logs import PORTAL_CSV


def client_for(config, store=None):
    return TestClient(create_app(config, store or Store(":memory:")))


def test_all_pages_render_with_sample_tenant(config):
    c = client_for(config)
    for path in ["/", "/users", "/users?window=48", "/logs", "/logs?type=DNS+control&action=Blocked", "/rules",
                 "/rules?type=Cloud+firewall", "/import", "/setup", "/sources", "/healthz"]:
        r = c.get(path)
        assert r.status_code == 200, path
    assert "Showing a sample tenant" in c.get("/").text


def test_empty_tenant_renders_without_demo(tmp_path):
    cfg = Config(data_dir=tmp_path, secret_key=None, password=None, demo=False, sync_minutes=60)
    c = client_for(cfg)
    for path in ["/", "/users", "/logs", "/rules"]:
        assert c.get(path).status_code == 200


def test_import_replaces_sample_data(config):
    store = Store(":memory:")
    c = client_for(config, store)
    r = c.post("/import", data={"feed": "web"}, files={"file": ("web.csv", PORTAL_CSV, "text/csv")}, follow_redirects=False)
    assert r.status_code == 303
    assert store.query("SELECT COUNT(*) AS n FROM log_events")[0]["n"] == 2
    assert "Imported 2 rows" in c.get(r.headers["location"]).text


def test_import_reports_unusable_file(config):
    c = client_for(config)
    r = c.post("/import", data={"feed": "web"}, files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")})
    assert "Nothing imported" in r.text


def test_secrets_are_encrypted_and_never_echoed(config):
    store = Store(":memory:")
    c = client_for(config, store)
    c.post("/setup", data={"mode": "oneapi", "vanity_domain": "acme", "client_id": "cid", "client_secret": "s3cret-value",
                           "action": "save"})
    raw = store.get_setting("client_secret")
    assert raw and "s3cret-value" not in raw
    assert "s3cret-value" not in c.get("/setup").text
    # A blank secret on a later save keeps the stored one.
    c.post("/setup", data={"mode": "oneapi", "vanity_domain": "acme", "client_id": "cid", "client_secret": "", "action": "save"})
    assert load_settings(store, load_fernet(None, config.data_dir)).client_secret == "s3cret-value"


def test_password_protects_ui(tmp_path):
    cfg = Config(data_dir=tmp_path, secret_key=None, password="pw", demo=True, sync_minutes=60)
    c = client_for(cfg)
    assert c.get("/").status_code == 401
    assert c.get("/", auth=("admin", "pw")).status_code == 200


def test_cross_origin_post_refused(config):
    c = client_for(config)
    r = c.post("/setup", data={"action": "save"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


@respx.mock
def test_sync_stores_snapshots_and_replaces_demo(store):
    from app.services.demo import seed_demo
    seed_demo(store, n_events=50)
    base = "https://api.zsapi.net/zia/api/v1"
    respx.post("https://acme.zslogin.net/oauth2/v1/token").mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
    respx.get(f"{base}/urlFilteringRules").mock(return_value=httpx.Response(200, json=[{"id": 7, "name": "Real rule", "order": 1, "action": "BLOCK"}]))
    respx.get(f"{base}/users").mock(return_value=httpx.Response(200, json=[{"id": 1, "name": "Ana", "email": "ana@acme.example", "department": {"name": "IT"}}]))
    respx.get(f"{base}/status").mock(return_value=httpx.Response(200, json={"status": "PENDING"}))
    respx.get(f"{base}/webApplicationRules/ruleTypeMapping").mock(return_value=httpx.Response(200, json={}))
    respx.post("https://api.zsapi.net/zins/graphql").mock(return_value=httpx.Response(200, json={"errors": [{"message": "bad field"}]}))
    respx.get(url__regex=rf"{base}/.*").mock(return_value=httpx.Response(200, json=[]))

    s = Settings(mode="oneapi", vanity_domain="acme", client_id="c", client_secret="s")
    status = run_sync(store, s, s.build_client(http=httpx.Client()))
    assert status["counts"]["rules"] == 1 and status["counts"]["users"] == 1
    assert "bandwidth" in status["errors"]
    assert store.get_snapshot("rules")["demo"] is False
    assert store.snapshot_data("users")[0]["department"] == "IT"
    assert store.query("SELECT COUNT(*) AS n FROM log_events")[0]["n"] == 0  # sample events removed
