"""Linkwatch web app factory."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from .config import Config
from .db import Database
from .gateway import Hub
from .models import utcnow
from .notify import Notifier
from .security import Vault, sha256

log = logging.getLogger("linkwatch")
HERE = Path(__file__).parent
PUBLIC_PREFIXES = ("/static/", "/login", "/healthz", "/api/poller/", "/api/v1/")


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
    templates.env.filters.update(bps=fmt_bps, ago=fmt_ago, duration=fmt_duration, speed=fmt_speed,
                                 num=lambda n: f"{int(n or 0):,}",
                                 pct=lambda v: "–" if v is None else f"{v:.0f}%")
    templates.env.globals.update(version=__version__, public_url=config.public_url)
    state = AppState(config, db, vault, notifier, hub, templates)

    if not config.admin_password:
        log.warning("LW_ADMIN_PASSWORD is not set: the web UI will refuse every login until it is.")

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

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if path.startswith(PUBLIC_PREFIXES) or path in ("/api/docs", "/api/openapi.json") or request.session.get("auth"):
            return await call_next(request)
        if path.startswith("/ui/"):
            return JSONResponse({"detail": "Not signed in"}, status_code=401)
        return RedirectResponse(f"/login?next={path}", status_code=303)

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
    def login(request: Request, password: str = Form(""), next: str = Form("/")):
        ip = request.client.host if request.client else "?"
        now = time.time()
        failures[ip] = [t for t in failures[ip] if now - t < 900]
        if len(failures[ip]) >= 8:
            return templates.TemplateResponse(request, "login.html", {"next": next, "error": "Too many attempts. Wait 15 minutes."}, status_code=429)
        if config.admin_password and secrets.compare_digest(password.encode(), config.admin_password.encode()):
            request.session.clear()
            request.session["auth"] = True
            failures.pop(ip, None)
            return RedirectResponse(next if next.startswith("/") and not next.startswith("//") else "/", status_code=303)
        failures[ip].append(now)
        msg = "Wrong password." if config.admin_password else "Login is disabled until LW_ADMIN_PASSWORD is set on the server."
        return templates.TemplateResponse(request, "login.html", {"next": next, "error": msg}, status_code=401)

    @app.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    from .api import router as api_router
    from .web import router as web_router
    app.include_router(api_router)
    app.include_router(web_router)
    return app
