"""VisCon1 branding: the name, a logo per theme, icons, and the old internal names left alone."""
from pathlib import Path

from linkwatch import APP_FULL_NAME, APP_NAME
from linkwatch.server.notify import send_one
from linkwatch.server.alerts import AlertEvent
from linkwatch.server.themes import THEMES, logo_for

BRAND = Path(__file__).resolve().parents[2] / "linkwatch" / "server" / "static" / "brand"


def test_name():
    assert (APP_NAME, APP_FULL_NAME) == ("VisCon1", "Visibility and Control One")


def test_logo_per_theme():
    assert logo_for("light") == "light"
    assert logo_for("as400") == "green"
    assert logo_for("auto") == "auto"
    for t in ("midnight", "zscaler", "graphite", "navy"):
        assert logo_for(t) == "dark"
    assert "as400" in THEMES


def test_brand_files_exist_and_respect_reduced_motion():
    for f in ("light", "dark", "green"):
        animated = (BRAND / f"viscon1-{f}.svg").read_text()
        assert "prefers-reduced-motion: reduce" in animated
        assert "animation: none !important" in (BRAND / f"viscon1-{f}-static.svg").read_text()
        for png in (f"favicon-{f}-32.png", f"icon-{f}-192.png", f"icon-{f}-512.png", f"apple-touch-icon-{f}.png"):
            assert (BRAND / png).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", png


def test_pages_show_the_theme_logo(logged_in, client):
    page = client.get("/login").text
    assert "<title>Sign in · VisCon1</title>" in page and "Visibility and Control One" in page
    assert "viscon1-dark.svg" in page and "viscon1-light.svg" in page       # auto: swaps with the device setting
    assert "Linkwatch" not in page
    page = logged_in.get("/").text
    assert "· VisCon1</title>" in page and "Linkwatch" not in page
    logged_in.post("/account/theme", data={"theme": "light"})
    page = logged_in.get("/").text
    assert "/static/brand/viscon1-light.svg" in page and "viscon1-dark.svg" not in page
    assert "viscon1-light-static.svg" in page                               # reduced motion + favicon
    logged_in.post("/account/theme", data={"theme": "navy"})
    assert "/static/brand/viscon1-dark.svg" in logged_in.get("/").text
    logged_in.post("/account/theme", data={"theme": "as400"})
    page = logged_in.get("/").text
    assert 'data-theme="as400"' in page and "/static/brand/viscon1-green.svg" in page
    assert "apple-touch-icon-green.png" in page


def test_favicon_and_manifest_are_public(client):
    r = client.get("/favicon.ico")
    assert r.status_code == 200 and r.content[:4] == b"\x89PNG"
    m = client.get("/manifest.webmanifest").json()
    assert m["short_name"] == "VisCon1" and m["icons"][0]["src"].startswith("/static/brand/")
    assert client.get("/static/brand/viscon1-green.svg").status_code == 200


def test_slack_alert_names_the_app():
    sent = {}

    class Http:
        def post(self, url, json):
            sent.update(json)

            class R:
                def raise_for_status(self):
                    pass
            return R()

    send_one("slack", {"url": "https://hooks.example/x"}, AlertEvent("opened", 1, "crit", "core down", None, "core"),
             "https://nms.example", http=Http())
    assert "Open VisCon1 alerts" in sent["text"]
