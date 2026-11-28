"""Script and stylesheet links carry a hash of the static files, so a deploy can't leave browsers on an old map.js."""
import re

from linkwatch.server import app as app_mod


def test_asset_version_follows_file_contents(tmp_path):
    (tmp_path / "map.js").write_text("old")
    before = app_mod.asset_version(tmp_path)
    assert before == app_mod.asset_version(tmp_path)          # stable while nothing changes
    (tmp_path / "map.js").write_text("new")
    assert app_mod.asset_version(tmp_path) != before
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.css").write_text("a")
    assert app_mod.asset_version(tmp_path) not in (before,)


def test_pages_link_assets_by_content_hash(logged_in):
    html = logged_in.get("/map").text
    want = app_mod.asset_version()
    assert f"/static/map.js?v={want}" in html
    assert f"/static/app.css?v={want}" in html
    assert not re.search(r"\?v=0\.1\.0", html)


def test_healthz_reports_build(client, monkeypatch):
    body = client.get("/healthz").json()
    assert body["ok"] is True and "build" in body
