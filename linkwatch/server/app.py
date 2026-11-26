"""Linkwatch web app factory."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from .config import Config
from .db import Database
from .gateway import Hub
from .models import User, utcnow
from .notify import Notifier
from .security import Vault, sha256, verify_password
from .users import audit, sync_admin_from_env

log = logging.getLogger("linkwatch")
HERE = Path(__file__).parent
PUBLIC_PREFIXES = ("/static/", "/login", "/healthz", "/api/poller/", "/api/v1/")
VIEWER_MAY_POST = ("/logout", "/account")


@dataclass
class AppState:
    config: Config
    db: Database
    vault: Vault
    notifier: Notifier
    hub: Hub
    templates: Jinja2Templates


def fmt_bps(v) -> str:
    if v is None:
        return "–"
    v = float(v)
    for unit in ("b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"):
        if v < 1000 or unit == "Tb/s":
            return f"{v:.0f} {unit}" if unit == "b/s" else f"{v:.1f} {unit}" if v < 100 else f"{v:.0f} {unit}"
        v /= 1000
    return f"{v:.1f} Tb/s"


def fmt_ago(dt: datetime | None) -> str:
    if not dt:
        return "never"
    secs = (utcnow() - dt).total_seconds()
    if secs < 60:
        return f"{max(int(secs), 0)} s ago"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400 * 2:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} d ago"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "–"
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def fmt_speed(mbps) -> str:
    if not mbps:
        return "–"
    return f"{mbps // 1000}G" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps}M"


def fmt_bytes(v) -> str:
    if v is None:
        return "–"
    v = float(v)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1000 or unit == "TB":
            return f"{v:.0f} {unit}" if unit == "B" or v >= 100 else f"{v:.1f} {unit}"
        v /= 1000
    return f"{v:.1f} TB"


def flash(request: Request, message: str, kind: str = "ok") -> None:
    request.session.setdefault("flash", []).append([kind, message])


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.from_env()
    db = Database(config.database_url)
    db.init()
    vault = Vault(config.secret_key)
    notifier = Notifier(db, vault, config.public_url)
    hub = Hub(db, vault, notifier, config.poll_interval)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters.update(bps=fmt_bps, ago=fmt_ago, duration=fmt_duration, speed=fmt_speed, bytes=fmt_bytes,
                                 num=lambda n: f"{int(n or 0):,}",
                                 pct=lambda v: "–" if v is None else f"{v:.0f}%")
    templates.env.globals.update(version=__version__, public_url=config.public_url)
    state = AppState(config, db, vault, notifier, hub, templates)

    sync_admin_from_env(db, config.admin_password)
    with db.session() as s:
        if not s.scalar(select(func.count(User.id))):
            log.warning("No users exist and LW_ADMIN_PASSWORD is not set: nobody can sign in until it is.")

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        hub.loop = asyncio.get_running_loop()
        task = None
        if config.background:
            from .jobs import background
            task = asyncio.create_task(background(state))
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Linkwatch", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.lw = state
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    failures: dict[str, list[float]] = defaultdict(list)

    def client_ip(request: Request) -> str | None:
        return request.headers.get("x-real-ip") or (request.client.host if request.client else None)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        request.state.user = None
        if path.startswith(PUBLIC_PREFIXES) or path in ("/api/docs", "/api/openapi.json"):
            return await call_next(request)
        uid = request.session.get("uid")
        user = None
        if uid:
            with db.session() as s:
                user = s.get(User, uid)
                if user is not None and (user.disabled or sha256("pwv:" + user.password_hash)[:20] != request.session.get("pwv")):
                    user = None   # disabled, deleted or password changed since this session signed in
        if user is None:
            request.session.clear()
            if path.startswith("/ui/"):
                return JSONResponse({"detail": "Not signed in"}, status_code=401)
            return RedirectResponse(f"/login?next={path}", status_code=303)
        request.state.user = user
        writing = request.method not in ("GET", "HEAD", "OPTIONS")
        if (path.startswith("/admin") or (writing and not path.startswith(VIEWER_MAY_POST))) and user.role != "admin":
            if path.startswith("/ui/"):
                return JSONResponse({"detail": "Your account is read-only"}, status_code=403)
            flash(request, "Your account is read-only. Ask an admin to make this change." if writing
                  else "Only admins can open Administration.", "warn")
            ref = request.headers.get("referer") or "/"
            return RedirectResponse(ref if "/admin" not in ref else "/", status_code=303)
        response = await call_next(request)
        if writing and response.status_code < 400 and not path.startswith(("/logout", "/admin", "/account")):
            with db.session() as s:
                audit(s, user.username, client_ip(request), f"{request.method} {path}")
        return response

    # Added after the middleware above so it wraps it (sessions must be decoded first).
    app.add_middleware(SessionMiddleware, secret_key=sha256("session:" + config.secret_key), session_cookie="lw_session",
                       max_age=12 * 3600, same_site="lax", https_only=config.public_url.startswith("https://"))

    @app.get("/healthz")
    def healthz():
        with db.session() as s:
            s.execute(text("SELECT 1"))
        return {"ok": True, "version": __version__}

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/"):
        return templates.TemplateResponse(request, "login.html", {"next": next, "error": None})

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/")):
        ip = client_ip(request) or "?"
        now = time.time()
        failures[ip] = [t for t in failures[ip] if now - t < 900]
        if len(failures[ip]) >= 8:
            return templates.TemplateResponse(request, "login.html", {"next": next, "error": "Too many attempts. Wait 15 minutes.",
                                                                       "username": username}, status_code=429)
        username = username.strip()
        with db.session() as s:
            user = s.scalar(select(User).where(func.lower(User.username) == username.lower()))
            ok = user is not None and not user.disabled and verify_password(password, user.password_hash)
            if not ok:
                if user is None:
                    verify_password(password, "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")  # same timing
                audit(s, username, ip, "sign-in failed", "account disabled" if user is not None and user.disabled else None)
            else:
                user.last_login = utcnow()
                audit(s, user.username, ip, "signed in")
                uid, pwv = user.id, sha256("pwv:" + user.password_hash)[:20]
        if ok:
            request.session.clear()
            request.session["uid"], request.session["pwv"] = uid, pwv
            failures.pop(ip, None)
            return RedirectResponse(next if next.startswith("/") and not next.startswith("//") else "/", status_code=303)
        failures[ip].append(now)
        return templates.TemplateResponse(request, "login.html", {"next": next, "error": "Wrong username or password.",
                                                                   "username": username}, status_code=401)

    @app.post("/logout")
    def logout(request: Request):
        user = getattr(request.state, "user", None)
        if user is not None:
            with db.session() as s:
                audit(s, user.username, client_ip(request), "signed out")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    from .admin import router as admin_router
    from .api import router as api_router
    from .unifi_views import router as unifi_router
    from .web import router as web_router
    app.include_router(api_router)
    app.include_router(web_router)
    app.include_router(unifi_router)
    app.include_router(admin_router)
    return app
