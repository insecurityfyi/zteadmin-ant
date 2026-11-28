"""VisCon1 as an installable app (PWA): the web app manifest, the service worker, the offline page, and
Web Push subscriptions for alert notifications on each phone, tablet or computer a user turns them on."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Body, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select

from .. import APP_FULL_NAME, APP_NAME
from . import push
from .models import PushSubscription, User, utcnow
from .security import sha256
from .themes import logo_for, site_theme

router = APIRouter(include_in_schema=False)
HERE = Path(__file__).parent
SEVERITIES = {"crit": "Critical only", "warn": "Warning and critical", "info": "Everything, including info"}
# Push services of the browsers that support Web Push. Subscriptions elsewhere are refused, so a signed-in user
# can't make the server POST to an arbitrary (say, internal) address.
PUSH_HOSTS = ("fcm.googleapis.com", "android.googleapis.com", "push.apple.com", "push.services.mozilla.com",
              "notify.windows.com")
# background colour of each theme (app.css --bg); "auto" uses the icon's own dark backdrop
THEME_BG = {"auto": "#11141d", "midnight": "#0f172a", "light": "#f8fafc", "zscaler": "#0b1f33", "graphite": "#18181b",
            "navy": "#0a1628", "as400": "#020a04"}


def st(request: Request):
    return request.app.state.lw


def theme_color(theme: str) -> str:
    return THEME_BG.get(theme, THEME_BG["auto"])


def asset_version(request: Request) -> str:
    """The content hash the pages put on static links (?v=), so the app's cache and icons change with each release."""
    return st(request).templates.env.globals["asset_version"]


def manifest_for(theme: str, v: str) -> dict:
    fam = logo_for(theme)
    fam = "dark" if fam == "auto" else fam
    icons = [{"src": f"/static/brand/icon-{fam}-{n}.png?v={v}", "sizes": f"{n}x{n}", "type": "image/png",
              "purpose": "any"} for n in (192, 512)]
    icons += [{"src": f"/static/brand/icon-{fam}-maskable-{n}.png?v={v}", "sizes": f"{n}x{n}",
               "type": "image/png", "purpose": "maskable"} for n in (192, 512)]
    short = [("Dashboard", "/"), ("Open alerts", "/alerts?state=open"), ("Network map", "/map"), ("Devices", "/devices")]
    return {
        "id": "/", "name": f"{APP_NAME} ({APP_FULL_NAME})", "short_name": APP_NAME,
        "description": "Network monitoring, alerts, the network map and remote consoles.",
        "start_url": "/?source=app", "scope": "/", "display": "standalone", "display_override": ["standalone", "minimal-ui"],
        "orientation": "any", "background_color": theme_color(theme), "theme_color": theme_color(theme),
        "categories": ["business", "productivity", "utilities"], "icons": icons,
        "shortcuts": [{"name": n, "url": u, "icons": [{"src": icons[0]["src"], "sizes": "192x192"}]} for n, u in short],
    }


@router.get("/manifest.webmanifest")
def manifest(request: Request):
    with st(request).db.session() as s:
        theme = site_theme(s)
    return JSONResponse(manifest_for(theme, asset_version(request)), media_type="application/manifest+json",
                        headers={"Cache-Control": "public, max-age=3600"})


@router.get("/sw.js")
def service_worker(request: Request):
    # served from the root so it controls every page; never cached, so a new release is picked up at once
    body = (HERE / "static" / "sw.js").read_text().replace("__VERSION__", asset_version(request))
    return Response(body, media_type="text/javascript",
                    headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})


@router.get("/offline", response_class=HTMLResponse)
def offline(request: Request):
    with st(request).db.session() as s:
        theme = site_theme(s)
    return st(request).templates.TemplateResponse(request, "offline.html", {"theme": theme})


# ------------------------------------------------------------------ push subscriptions (each user, any role)
def device_label(ua: str) -> str:
    os_name = next((n for pat, n in ((r"iPhone", "iPhone"), (r"iPad", "iPad"), (r"Android", "Android"),
                                     (r"Windows", "Windows"), (r"Mac OS X|Macintosh", "Mac"), (r"CrOS", "ChromeOS"),
                                     (r"Linux", "Linux")) if re.search(pat, ua)), "Device")
    browser = next((n for pat, n in ((r"Edg/", "Edge"), (r"Firefox/|FxiOS", "Firefox"), (r"OPR/", "Opera"),
                                     (r"Chrome/|CriOS", "Chrome"), (r"Safari/", "Safari")) if re.search(pat, ua)), "")
    return f"{os_name} · {browser}" if browser else os_name


def push_host_allowed(endpoint: str) -> bool:
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and any(host == h or host.endswith("." + h) for h in PUSH_HOSTS)


@router.get("/account/push/key")
def push_key(request: Request):
    with st(request).db.session() as s:
        vapid = push.Vapid.load(s, st(request).vault, st(request).config.public_url)
    return {"publicKey": vapid.public_key}


def _sub_json(sub: PushSubscription) -> dict:
    return {"id": sub.id, "label": sub.label, "min_severity": sub.min_severity}


@router.post("/account/push/subscribe")
async def push_subscribe(request: Request):
    data = await request.json()
    endpoint = str(data.get("endpoint") or "")
    keys = data.get("keys") or {}
    p256dh, auth = str(keys.get("p256dh") or ""), str(keys.get("auth") or "")
    if not push_host_allowed(endpoint):
        return JSONResponse({"detail": "That browser's push service isn't supported."}, status_code=400)
    try:
        if len(push.unb64u(p256dh)) != 65 or len(push.unb64u(auth)) != 16:
            raise ValueError
    except ValueError:
        return JSONResponse({"detail": "The subscription keys are not valid."}, status_code=400)
    sev = str(data.get("min_severity") or "")
    old = str(data.get("old_endpoint") or "")
    me = request.state.user
    with st(request).db.session() as s:
        sub = s.scalar(select(PushSubscription).where(PushSubscription.endpoint_hash == sha256(endpoint)))
        if sub is None and old:
            sub = s.scalar(select(PushSubscription).where(PushSubscription.endpoint_hash == sha256(old),
                                                          PushSubscription.user_id == me.id))
        if sub is None:
            sub = PushSubscription(user_id=me.id, min_severity=sev if sev in SEVERITIES else "warn")
            s.add(sub)
        elif sev in SEVERITIES:
            sub.min_severity = sev
        sub.user_id, sub.endpoint, sub.endpoint_hash, sub.p256dh, sub.auth = me.id, endpoint, sha256(endpoint), p256dh, auth
        sub.label = device_label(request.headers.get("user-agent", ""))
        s.flush()
        return _sub_json(sub)


def _mine(s, request: Request, endpoint: str = "", sub_id: int | None = None) -> PushSubscription | None:
    q = select(PushSubscription).where(PushSubscription.user_id == request.state.user.id)
    q = q.where(PushSubscription.id == sub_id) if sub_id is not None else q.where(PushSubscription.endpoint_hash == sha256(endpoint))
    return s.scalar(q)


@router.post("/account/push/status")
async def push_status(request: Request):
    """Is this browser's subscription (by endpoint) registered here, and with what setting?"""
    data = await request.json()
    with st(request).db.session() as s:
        sub = _mine(s, request, str(data.get("endpoint") or ""))
        return {"subscribed": sub is not None, **(_sub_json(sub) if sub else {})}


@router.post("/account/push/unsubscribe")
async def push_unsubscribe(request: Request):
    data = await request.json()
    with st(request).db.session() as s:
        sub = _mine(s, request, str(data.get("endpoint") or ""))
        if sub is not None:
            s.delete(sub)
    return {"ok": True}


@router.post("/account/push/test")
def push_test(request: Request, data: dict = Body(...)):
    # a plain def: FastAPI runs it in a worker thread, so the push request doesn't hold up the event loop
    lw = st(request)
    with lw.db.session() as s:
        sub = _mine(s, request, str(data.get("endpoint") or ""))
        if sub is None:
            return JSONResponse({"detail": "Notifications are not turned on for this device."}, status_code=404)
        vapid = push.Vapid.load(s, lw.vault, lw.config.public_url)
        msg = {"title": f"{APP_NAME} test notification", "body": f"Alerts will appear like this on {sub.label}.",
               "url": "/account#app", "tag": "viscon1-test", "severity": "info"}
        try:
            with httpx.Client(timeout=15) as http:
                push.send(vapid, sub, msg, http, ttl=300)
        except push.Gone:
            s.delete(sub)
            return JSONResponse({"detail": "The push service says this subscription has expired. Turn notifications on again."},
                                status_code=410)
        except Exception as exc:
            sub.last_result = f"Failed: {exc.__class__.__name__}: {exc}"[:255]
            return JSONResponse({"detail": f"Sending failed: {exc}"}, status_code=502)
        sub.last_sent, sub.last_result = utcnow(), "Sent: test notification"
    return {"ok": True}


@router.post("/account/push/{sub_id}/severity")
async def push_severity(request: Request, sub_id: int):
    form = await request.form()
    sev = str(form.get("min_severity") or "")
    with st(request).db.session() as s:
        sub = _mine(s, request, sub_id=sub_id)
        if sub is not None and sev in SEVERITIES:
            sub.min_severity = sev
    from .app import flash
    flash(request, "Notification setting saved.")
    return RedirectResponse("/account#app", status_code=303)


@router.post("/account/push/{sub_id}/delete")
def push_delete(request: Request, sub_id: int):
    with st(request).db.session() as s:
        sub = _mine(s, request, sub_id=sub_id)
        if sub is not None:
            s.delete(sub)
    from .app import flash
    flash(request, "That device will no longer get alert notifications.")
    return RedirectResponse("/account#app", status_code=303)


def subscriptions_for(s, user: User) -> list[PushSubscription]:
    return list(s.scalars(select(PushSubscription).where(PushSubscription.user_id == user.id).order_by(PushSubscription.created_at)))
