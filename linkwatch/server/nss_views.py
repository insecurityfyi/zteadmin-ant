"""Zscaler Cloud NSS: the ingest endpoint a feed pushes to, the user activity pages, and the feed settings."""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select

from . import nss
from .db import get_setting, set_setting
from .models import NssToken, utcnow
from .security import new_secret, sha256
from .users import audit
from .web import back, flash, render, st

router = APIRouter(include_in_schema=False)
RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}
_auth_failures: dict[str, list[float]] = defaultdict(list)
_token_touch: dict[int, list] = {}       # token id -> [events since last save, last save time, ip]


def token_hash(token: str) -> str:
    return sha256("nss:" + token.strip())


def store_dir(config) -> Path:
    if getattr(config, "nss_dir", ""):
        return Path(config.nss_dir)
    url = config.database_url
    if url.startswith("sqlite:///") and url.split("///", 1)[1] not in ("", ":memory:"):
        return Path(url.split("///", 1)[1]).parent / "nss"
    return Path("./data/nss")


def _limits(s) -> tuple[float, float]:
    def num(key, default):
        try:
            return float(get_setting(s, key, str(default)))
        except (TypeError, ValueError):
            return float(default)
    return num("nss_max_gb", nss.DEFAULT_MAX_GB), num("nss_min_free_gb", nss.DEFAULT_MIN_FREE_GB)


def store(request: Request) -> nss.NssStore:
    app = request.app
    s = getattr(app.state, "nss", None)
    if s is None:
        state = st(request)
        with state.db.session() as db:
            max_gb, free_gb = _limits(db)
        s = nss.NssStore(store_dir(state.config), int(max_gb * nss.GB), int(free_gb * nss.GB))
        app.state.nss = s
    return s


def _ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def _bearer(request: Request) -> str:
    h = request.headers.get("authorization", "").strip()
    if h.lower().startswith("bearer "):
        h = h[7:]
    return h.strip() or request.headers.get("x-api-key", "").strip()


# ------------------------------------------------------------------ ingest
@router.post("/api/nss/ingest")
@router.post("/api/nss/ingest/{feed}")
async def ingest(request: Request, feed: str | None = None):
    """Cloud NSS HTTPS feed target. Send the token as `Authorization: Bearer <token>`."""
    ip = _ip(request) or "?"
    now = time.time()
    _auth_failures[ip] = [t for t in _auth_failures[ip] if now - t < 900]
    if len(_auth_failures[ip]) >= 20:
        return JSONResponse({"ok": False, "error": "too many failed attempts"}, status_code=429)
    if feed is not None and feed not in nss.FEEDS:
        raise HTTPException(404, "Unknown feed type; use web, fw, dns, tunnel or other")
    token = _bearer(request)
    state = st(request)
    tok_id = None
    if token:
        with state.db.session() as s:
            tok_id = s.scalar(select(NssToken.id).where(NssToken.token_hash == token_hash(token)))
    if tok_id is None:
        _auth_failures[ip].append(now)
        return JSONResponse({"ok": False, "error": "missing or unknown token"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > nss.MAX_BODY:
        return JSONResponse({"ok": False, "error": "batch too large"}, status_code=413)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > nss.MAX_BODY:
            return JSONResponse({"ok": False, "error": "batch too large"}, status_code=413)
    store_ = store(request)
    try:
        n = await asyncio.to_thread(store_.ingest, bytes(body), request.headers.get("content-encoding"), feed)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)[:200]}, status_code=400)
    except OSError as e:
        store_.note_error(f"Could not store a batch: {e}")
        return JSONResponse({"ok": False, "error": "log storage unavailable"}, status_code=507)
    _touch(state, tok_id, n, ip)
    return {"ok": True, "accepted": n}


def _touch(state, tok_id: int, n: int, ip: str) -> None:
    """Count events per token without a database write on every batch (at most one per 15 s per token)."""
    t = _token_touch.setdefault(tok_id, [0, 0.0, ip])
    t[0] += n
    t[2] = ip
    if time.time() - t[1] < 15:
        return
    with state.db.session() as s:
        tok = s.get(NssToken, tok_id)
        if tok is not None:
            tok.events = (tok.events or 0) + t[0]
            tok.last_used, tok.last_ip = utcnow(), ip[:64]
    t[0], t[1] = 0, time.time()


# ------------------------------------------------------------------ activity pages
def _since(range_: str) -> int | None:
    secs = RANGES.get(range_, 86400)
    return int(time.time()) - secs if secs else None


def _dt(epoch) -> datetime | None:
    return datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None) if epoch else None


def _common(request: Request, range_: str) -> dict:
    s = store(request)
    return {"range": range_ if range_ in RANGES else "24h", "ranges": list(RANGES), "info": s.info(),
            "feeds": nss.FEEDS, "dt": _dt}


@router.get("/logs", response_class=HTMLResponse)
async def logs_home(request: Request, range: str = "24h"):
    s = store(request)
    data = await asyncio.to_thread(s.summary, _since(range))
    with st(request).db.session() as db:
        has_tokens = db.scalar(select(NssToken.id).limit(1)) is not None
    return render(request, "logs.html", {**_common(request, range), "d": data, "has_tokens": has_tokens, "section": "logs"})


@router.get("/logs/user", response_class=HTMLResponse)
async def logs_user(request: Request, u: str = "", range: str = "24h"):
    s = store(request)
    since = _since(range)
    data = await asyncio.to_thread(s.summary, since, u)
    recent = await asyncio.to_thread(s.events, since=since, user=u, limit=30)
    blocked = await asyncio.to_thread(s.events, since=since, user=u, blocked=True, limit=10)
    return render(request, "logs_user.html", {**_common(request, range), "d": data, "u": u, "recent": recent,
                                              "blocked_events": blocked, "section": "logs"})


@router.get("/logs/events", response_class=HTMLResponse)
async def logs_events(request: Request, u: str | None = None, feed: str = "", blocked: str = "", q: str = "",
                      range: str = "24h", before: int | None = None):
    s = store(request)
    limit = 200
    rows = await asyncio.to_thread(s.events, since=_since(range), before=before, user=u, feed=feed if feed in nss.FEEDS else None,
                                   blocked=blocked == "1", q=q.strip()[:120] or None, limit=limit)
    more = rows[-1]["ts"] if len(rows) >= limit else None
    return render(request, "logs_events.html", {**_common(request, range), "rows": rows, "u": u, "feed": feed, "blocked": blocked,
                                                "q": q, "more": more, "section": "logs"})


@router.get("/logs/events/{seg}/{eid}", response_class=HTMLResponse)
async def logs_event(request: Request, seg: str, eid: int):
    e = await asyncio.to_thread(store(request).event, seg, eid)
    if e is None:
        raise HTTPException(404, "That event is no longer stored (the oldest logs are removed to stay under the size cap).")
    return render(request, "logs_event.html", {**_common(request, "24h"), "e": e, "section": "logs",
                                               "raw": json.dumps(e["raw"], indent=2, ensure_ascii=False) if e["raw"] else None})


@router.get("/ui/logs/series")
async def logs_series(request: Request, u: str | None = None, range: str = "24h"):
    rng = {"6h": "1h"}.get(range, range)
    since = _since(rng if rng in RANGES else "24h") or int(time.time()) - 30 * 86400
    if rng == "1h":
        since = int(time.time()) - 6 * 3600
    data = await asyncio.to_thread(store(request).summary, since, u)
    hours = dict(data["hours"])
    start, end = since // 3600 * 3600, int(time.time()) // 3600 * 3600
    ts = list(range_(start, end + 1, 3600))
    iso = [datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") for t in ts]
    return {"ts": iso, "a": [hours.get(t, [0, 0])[0] for t in ts], "b": [hours.get(t, [0, 0])[1] for t in ts]}


range_ = range   # the handlers above shadow range() with a query parameter of that name


# ------------------------------------------------------------------ settings (admin only: /admin is admin-gated)
def _settings_ctx(request: Request, new_token: str | None = None) -> dict:
    with st(request).db.session() as s:
        tokens = list(s.scalars(select(NssToken).order_by(NssToken.created_at)))
        for t in tokens:
            s.expunge(t)
            t.events = (t.events or 0) + _token_touch.get(t.id, [0])[0]   # counted but not saved yet
        max_gb, free_gb = _limits(s)
    base = st(request).config.public_url.rstrip("/")
    return {"tokens": tokens, "new_token": new_token, "max_gb": max_gb, "min_free_gb": free_gb, "info": store(request).info(),
            "endpoint": base + "/api/nss/ingest", "feeds": nss.FEEDS, "dt": _dt, "section": "admin"}


@router.get("/admin/nss", response_class=HTMLResponse)
def nss_settings(request: Request):
    return render(request, "admin_nss.html", _settings_ctx(request))


@router.post("/admin/nss/tokens", response_class=HTMLResponse)
async def nss_token_create(request: Request):
    form = await request.form()
    name = str(form.get("name", "")).strip()[:120] or "Cloud NSS feed"
    token = new_secret("vcnss", 32)
    with st(request).db.session() as s:
        s.add(NssToken(name=name, prefix=token[:12], token_hash=token_hash(token)))
        audit(s, request.state.user.username, _ip(request), "created a Cloud NSS feed token", name)
    return render(request, "admin_nss.html", _settings_ctx(request, new_token=token))


@router.post("/admin/nss/tokens/{tid}/delete")
def nss_token_delete(request: Request, tid: int):
    with st(request).db.session() as s:
        tok = s.get(NssToken, tid)
        if tok is not None:
            audit(s, request.state.user.username, _ip(request), "deleted a Cloud NSS feed token", tok.name)
            s.delete(tok)
            flash(request, f"Token “{tok.name}” deleted. Feeds using it now get 401 Unauthorized.")
    _token_touch.pop(tid, None)
    return back("/admin/nss")


@router.post("/admin/nss/storage")
async def nss_storage(request: Request):
    form = await request.form()
    try:
        max_gb = float(form.get("max_gb", ""))
        free_gb = float(form.get("min_free_gb", ""))
    except ValueError:
        flash(request, "Enter the cap and free-space floor as numbers of GB.", "bad")
        return back("/admin/nss")
    if not (1 <= max_gb <= 100000) or not (0 <= free_gb <= 100000):
        flash(request, "The cap must be between 1 and 100000 GB, and the free-space floor between 0 and 100000 GB.", "bad")
        return back("/admin/nss")
    s_ = store(request)
    with st(request).db.session() as s:
        set_setting(s, "nss_max_gb", f"{max_gb:g}")
        set_setting(s, "nss_min_free_gb", f"{free_gb:g}")
        audit(s, request.state.user.username, _ip(request), "changed Cloud NSS log storage", f"cap {max_gb:g} GB, keep {free_gb:g} GB free")
    s_.max_bytes, s_.min_free = int(max_gb * nss.GB), int(free_gb * nss.GB)
    await asyncio.to_thread(s_.enforce)
    flash(request, f"Log storage is capped at {max_gb:g} GB; the oldest logs are removed first once it is full.")
    return back("/admin/nss")


@router.post("/admin/nss/clear")
async def nss_clear(request: Request):
    form = await request.form()
    if str(form.get("confirm", "")).strip().upper() != "DELETE":
        flash(request, "Type DELETE to confirm.", "bad")
        return back("/admin/nss")
    await asyncio.to_thread(store(request).clear)
    with st(request).db.session() as s:
        audit(s, request.state.user.username, _ip(request), "deleted all stored Cloud NSS logs")
    flash(request, "All stored Zscaler logs were deleted.")
    return back("/admin/nss")
