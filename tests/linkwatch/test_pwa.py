"""VisCon1 as an installable app: manifest, service worker, offline page, and Web Push alert notifications."""
import base64
import json
from pathlib import Path

import httpx
import respx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from linkwatch.server import push
from linkwatch.server.alerts import AlertEvent
from linkwatch.server.models import PushSubscription

from .test_admin import sign_in

BRAND = Path(__file__).resolve().parents[2] / "linkwatch" / "server" / "static" / "brand"
FCM = "https://fcm.googleapis.com/fcm/send/abc123"


class Browser:
    """The browser side of Web Push: its key pair and auth secret, and RFC 8291 decryption."""

    def __init__(self, endpoint=FCM):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.auth = b"0123456789abcdef"
        self.endpoint = endpoint

    def subscription(self, **extra):
        return {"endpoint": self.endpoint, "keys": {"p256dh": push.b64u(self.public), "auth": push.b64u(self.auth)}, **extra}

    def decrypt(self, body: bytes) -> dict:
        salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
        as_public, ct = body[21:21 + idlen], body[21 + idlen:]
        assert rs == 4096 and idlen == 65
        secret = self.key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
        kdf = lambda salt, ikm, info, n: HKDF(hashes.SHA256(), n, salt, info).derive(ikm)
        ikm = kdf(self.auth, secret, b"WebPush: info\x00" + self.public + as_public, 32)
        cek = kdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
        nonce = kdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
        plain = AESGCM(cek).decrypt(nonce, ct, None)
        assert plain.endswith(b"\x02")
        return json.loads(plain[:-1])


def check_vapid(header: str, endpoint: str) -> dict:
    t, k = (p.split("=", 1)[1] for p in header.removeprefix("vapid ").split(", "))
    head, claims, sig = t.split(".")
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), push.unb64u(k))
    raw = push.unb64u(sig)
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
               f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))       # raises if the signature is wrong
    c = json.loads(push.unb64u(claims))
    assert c["aud"] == "https://fcm.googleapis.com" and json.loads(push.unb64u(head))["alg"] == "ES256"
    return c


# ------------------------------------------------------------------ installable app
def test_manifest_is_installable(client):
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/manifest+json")
    m = r.json()
    assert m["short_name"] == "VisCon1" and m["display"] == "standalone" and m["scope"] == "/" and m["id"] == "/"
    purposes = {(i["sizes"], i["purpose"]) for i in m["icons"]}
    assert {("192x192", "any"), ("512x512", "any"), ("192x192", "maskable"), ("512x512", "maskable")} <= purposes
    for i in m["icons"]:
        assert client.get(i["src"]).status_code == 200, i["src"]
    assert [s["url"] for s in m["shortcuts"]][:2] == ["/", "/alerts?state=open"]


def test_manifest_follows_site_theme(logged_in, client):
    logged_in.post("/admin/theme", data={"theme": "as400"})
    m = client.get("/manifest.webmanifest").json()
    assert m["background_color"] == m["theme_color"] == "#020a04" and "icon-green-maskable-512.png" in json.dumps(m)


def test_maskable_and_badge_icons_exist():
    for f in ("dark", "light", "green"):
        for n in (192, 512):
            assert (BRAND / f"icon-{f}-maskable-{n}.png").read_bytes()[:4] == b"\x89PNG"
    assert (BRAND / "badge-96.png").read_bytes()[:4] == b"\x89PNG"


def test_service_worker_and_offline_page_are_public(client):
    from linkwatch.server.app import asset_version
    r = client.get("/sw.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert r.headers["service-worker-allowed"] == "/" and r.headers["cache-control"] == "no-cache"
    assert "__VERSION__" not in r.text and f'"{asset_version()}"' in r.text
    assert 'addEventListener("push"' in r.text and "notificationclick" in r.text
    r = client.get("/offline")
    assert r.status_code == 200 and "can't be reached" in r.text


def test_pages_link_the_app(logged_in, client):
    for page in (client.get("/login").text, logged_in.get("/").text):
        assert '<link rel="manifest" href="/manifest.webmanifest">' in page
        assert "/static/pwa.js" in page and 'name="theme-color"' in page and "apple-mobile-web-app-capable" in page
    page = logged_in.get("/account").text
    assert 'id="app"' in page and "data-push-on" in page


# ------------------------------------------------------------------ Web Push
def test_encrypt_round_trip_and_vapid_signature(app):
    b = Browser()
    lw = app.state.lw
    with lw.db.session() as s:
        vapid = push.Vapid.load(s, lw.vault, "https://nms.example")
        again = push.Vapid.load(s, lw.vault, "https://nms.example")
    assert vapid.public_key == again.public_key and len(push.unb64u(vapid.public_key)) == 65    # kept, not remade
    msg = {"title": "[CRITICAL] core down", "body": "x" * 1000}
    assert b.decrypt(push.encrypt(json.dumps(msg).encode(), push.b64u(b.public), push.b64u(b.auth))) == msg
    claims = check_vapid(vapid.authorization(FCM), FCM)
    assert claims["sub"] == "https://nms.example"


def test_subscribe_test_and_unsubscribe(logged_in):
    b = Browser()
    key = logged_in.get("/account/push/key").json()["publicKey"]
    r = logged_in.post("/account/push/subscribe", json=b.subscription(min_severity="crit"),
                       headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1"})
    assert r.status_code == 200 and r.json()["label"] == "iPhone · Safari" and r.json()["min_severity"] == "crit"
    assert logged_in.post("/account/push/status", json={"endpoint": FCM}).json()["subscribed"] is True
    assert "iPhone · Safari" in logged_in.get("/account").text
    with respx.mock:
        route = respx.post(FCM).mock(return_value=httpx.Response(201))
        assert logged_in.post("/account/push/test", json={"endpoint": FCM}).status_code == 200
        req = route.calls[0].request
    assert req.headers["content-encoding"] == "aes128gcm" and req.headers["ttl"] == "300"
    assert req.headers["authorization"].endswith(f"k={key}")
    check_vapid(req.headers["authorization"], FCM)
    assert b.decrypt(req.content)["title"] == "VisCon1 test notification"
    # subscribing again updates the same row
    logged_in.post("/account/push/subscribe", json=b.subscription(min_severity="info"))
    with logged_in.app.state.lw.db.session() as s:
        rows = s.scalars(select(PushSubscription)).all()
        assert len(rows) == 1 and rows[0].min_severity == "info"
    assert logged_in.post("/account/push/unsubscribe", json={"endpoint": FCM}).status_code == 200
    assert logged_in.post("/account/push/status", json={"endpoint": FCM}).json()["subscribed"] is False


def test_only_real_push_services_and_valid_keys(logged_in):
    for bad in ("https://10.0.0.5/hook", "http://fcm.googleapis.com/x", "https://fcm.googleapis.com.evil.example/x"):
        assert logged_in.post("/account/push/subscribe", json=Browser(bad).subscription()).status_code == 400, bad
    sub = Browser().subscription()
    sub["keys"]["auth"] = "short"
    assert logged_in.post("/account/push/subscribe", json=sub).status_code == 400
    for ok in ("https://web.push.apple.com/QGx", "https://updates.push.services.mozilla.com/wpush/v2/x",
               "https://wns2-par02p.notify.windows.com/w/?token=x"):
        assert logged_in.post("/account/push/subscribe", json=Browser(ok).subscription()).status_code == 200, ok


def test_viewers_can_turn_on_notifications(app, logged_in):
    logged_in.post("/admin/users", data={"username": "noc", "password": "noc-password-123", "role": "viewer"})
    viewer, code = sign_in(app, "noc", "noc-password-123")
    assert code == 303
    assert viewer.post("/account/push/subscribe", json=Browser().subscription()).status_code == 200
    # and nobody else can see or remove it
    with app.state.lw.db.session() as s:
        sid = s.scalar(select(PushSubscription.id))
    logged_in.post(f"/account/push/{sid}/delete")
    with app.state.lw.db.session() as s:
        assert s.get(PushSubscription, sid) is not None
    viewer.post(f"/account/push/{sid}/delete")
    with app.state.lw.db.session() as s:
        assert s.get(PushSubscription, sid) is None


def test_alerts_are_pushed_by_severity_and_dead_subscriptions_dropped(app, logged_in):
    phone, laptop = Browser(FCM), Browser("https://updates.push.services.mozilla.com/wpush/v2/gone")
    logged_in.post("/account/push/subscribe", json=phone.subscription(min_severity="crit"))
    logged_in.post("/account/push/subscribe", json=laptop.subscription(min_severity="info"))
    events = [AlertEvent("opened", 7, "crit", "core-sw1 down", "No ping for 2 polls", "core-sw1"),
              AlertEvent("opened", 8, "warn", "High CPU on fw1", None, "fw1")]
    with respx.mock:
        ok = respx.post(FCM).mock(return_value=httpx.Response(201))
        gone = respx.post(laptop.endpoint).mock(return_value=httpx.Response(410))
        app.state.lw.notifier.dispatch(events, background=False)
    assert ok.call_count == 1 and gone.call_count == 1                 # the warning is below the phone's minimum
    m = phone.decrypt(ok.calls[0].request.content)
    assert m == {"title": "[CRITICAL] core-sw1 down", "body": "No ping for 2 polls", "severity": "crit",
                 "url": "/alerts?state=open", "tag": "alert-7", "renotify": True, "requireInteraction": True}
    assert ok.calls[0].request.headers["urgency"] == "high"
    with app.state.lw.db.session() as s:
        left = s.scalars(select(PushSubscription)).all()
        assert [p.endpoint for p in left] == [FCM] and left[0].last_result.startswith("Sent: [CRITICAL]")
    # a resolve replaces the notification it resolves
    with respx.mock:
        ok = respx.post(FCM).mock(return_value=httpx.Response(201))
        app.state.lw.notifier.dispatch([AlertEvent("resolved", 7, "crit", "core-sw1 down", None, "core-sw1")], background=False)
    m = phone.decrypt(ok.calls[0].request.content)
    assert m["tag"] == "alert-7" and m["title"].startswith("[RESOLVED]") and m["requireInteraction"] is False


def test_http_ece_agrees_if_installed():
    """Cross-check against the reference implementation when it's available."""
    import pytest
    ece = pytest.importorskip("http_ece")
    b = Browser()
    body = push.encrypt(b'{"t":1}', push.b64u(b.public), push.b64u(b.auth))
    assert ece.decrypt(body, private_key=b.key, auth_secret=b.auth, version="aes128gcm") == b'{"t":1}'
