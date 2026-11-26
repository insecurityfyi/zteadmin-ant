"""Zscaler Toolbox: ZIA module web app."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Config
from .crypto import load_fernet
from .db import Store
from .services import views
from .services.demo import ensure_demo
from .services.logs_import import FEEDS, parse_upload
from .services.settings import load_settings, save_settings
from .services.sync import run_sync, test_connection
from .zia.auth import ZIA_CLOUDS
from .zia.insights import DEFAULT_QUERY
from .zia.policies import POLICY_TYPES

log = logging.getLogger("toolbox")
HERE = Path(__file__).parent
MAX_UPLOAD = 200 * 1024 * 1024


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1000 or unit == "PB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} PB"


def fmt_ago(iso, ref: datetime | None = None) -> str:
    if not iso:
        return "never"
    dt = datetime.fromisoformat(iso) if isinstance(iso, str) else iso
    secs = ((ref or datetime.now(timezone.utc)) - dt).total_seconds()
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400 * 2:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} d ago"


def fmt_time(iso) -> str:
    if not iso:
        return ""
    dt = datetime.fromisoformat(iso) if isinstance(iso, str) else iso
    return dt.strftime("%a %d %b %H:%M UTC")


def create_app(config: Config | None = None, store: Store | None = None) -> FastAPI:
    config = config or Config.from_env()
    store = store or Store(config.data_dir / "toolbox.db")
    fernet = load_fernet(config.secret_key, config.data_dir)
    if config.demo:
        ensure_demo(store)

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters.update(bytes=fmt_bytes, ago=fmt_ago, time=fmt_time, num=lambda n: f"{int(n or 0):,}")
    security = HTTPBasic(auto_error=False)

    def guard(request: Request, creds: HTTPBasicCredentials | None = Depends(security)):
        if config.password:
            ok = creds is not None and secrets.compare_digest(creds.username, "admin") and \
                secrets.compare_digest(creds.password, config.password)
            if not ok:
                raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Basic"})
        if request.method == "POST":
            # Same-origin check for form posts (basic CSRF protection).
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin and urlparse(origin).netloc != request.headers.get("host"):
                raise HTTPException(403, "Cross-origin form post refused")

    sync_lock = asyncio.Lock()

    async def do_sync() -> dict | None:
        settings = load_settings(store, fernet)
        if not settings.configured:
            return None
        async with sync_lock:
            return await asyncio.to_thread(run_sync, store, settings)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        async def loop():
            while True:
                try:
                    await do_sync()
                    days = int(load_settings(store, fernet).log_retention_days or 30)
                    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
                    store.prune_events(datetime.fromtimestamp(cutoff, timezone.utc).isoformat(timespec="seconds"))
                except Exception:  # keep the loop alive
                    log.exception("background sync failed")
                await asyncio.sleep(config.sync_minutes * 60)

        task = asyncio.create_task(loop())
        yield
        task.cancel()

    app = FastAPI(title="Zscaler Toolbox", lifespan=lifespan, dependencies=[Depends(guard)], docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.state.store = store

    def render(request: Request, name: str, **ctx):
        settings = load_settings(store, fernet)
        rules_snap = store.get_snapshot("rules")
        ctx |= {
            "nav": name.split(".")[0],
            "demo": bool(rules_snap and rules_snap["demo"]),
            "connected": settings.configured,
            "settings": settings,
            "sync_status": store.snapshot_data("sync_status"),
            "policy_types": POLICY_TYPES,
        }
        return templates.TemplateResponse(request, name, ctx)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        return render(request, "overview.html", o=views.overview(store))

    @app.get("/users", response_class=HTMLResponse)
    def users(request: Request, window: int = 168, q: str = ""):
        window = 48 if window == 48 else 168
        return render(request, "users.html", u=views.users(store, window, q), q=q)

    @app.get("/logs", response_class=HTMLResponse)
    def logs(request: Request, type: str = "", action: str = "", q: str = "", sel: int | None = None):
        data = views.logs(store, type, action, q)
        selected = next((r for r in data["rows"] if r["id"] == sel), data["rows"][0] if data["rows"] else None)
        return render(request, "logs.html", l=data, selected=selected, f={"type": type, "action": action, "q": q},
                      actions=views.ACTIONS)

    @app.get("/rules", response_class=HTMLResponse)
    def rules(request: Request, type: str = ""):
        return render(request, "rules.html", r=views.rules_with_hits(store, type), ftype=type)

    @app.get("/import", response_class=HTMLResponse)
    def import_page(request: Request, msg: str = ""):
        return render(request, "import.html", imports=store.imports(), feeds=FEEDS, msg=msg)

    @app.post("/import")
    async def import_upload(request: Request, feed: str = Form("web"), file: UploadFile = File(...)):
        feed = feed if feed in FEEDS else "web"
        content = await file.read(MAX_UPLOAD + 1)
        if len(content) > MAX_UPLOAD:
            return render(request, "import.html", imports=store.imports(), feeds=FEEDS,
                          error="That file is over 200 MB. Split the export and upload it in parts.")
        events, skipped, cmap = parse_upload(content, feed)
        if not events:
            missing = ", ".join(cmap.missing()) or "any rows with a readable time"
            return render(request, "import.html", imports=store.imports(), feeds=FEEDS,
                          error=f"Nothing imported from {file.filename}: could not find {missing}. "
                                f"Columns seen: {', '.join(cmap.headers[:25])}")
        snap = store.get_snapshot("rules")
        if snap and snap["demo"]:
            store.clear_demo()  # real logs replace the sample tenant
        import_id = store.add_import(file.filename or "upload", feed, len(events), skipped, cmap.unmapped)
        for e in events:
            e["import_id"] = import_id
        store.add_events(events)
        return RedirectResponse(f"/import?msg={quote(f'Imported {len(events)} rows from {file.filename}')}", status_code=303)

    @app.get("/setup", response_class=HTMLResponse)
    def setup(request: Request, msg: str = "", ok: int = 1):
        return render(request, "setup.html", clouds=ZIA_CLOUDS, default_query=DEFAULT_QUERY, msg=msg, ok=ok)

    @app.post("/setup")
    async def setup_save(request: Request):
        form = {k: str(v) for k, v in (await request.form()).items()}
        form.setdefault("insights_enabled", "0")
        save_settings(store, fernet, form)
        if form.get("action") == "test":
            ok, msg = await asyncio.to_thread(test_connection, load_settings(store, fernet))
            return RedirectResponse(f"/setup?ok={int(ok)}&msg={quote(msg[:300])}", status_code=303)
        return RedirectResponse("/setup?msg=Saved", status_code=303)

    @app.post("/sync")
    async def sync_now():
        status = await do_sync()
        if status is None:
            return RedirectResponse("/setup?ok=0&msg=Connect+a+ZIA+tenant+first", status_code=303)
        return RedirectResponse("/", status_code=303)

    @app.get("/sources", response_class=HTMLResponse)
    def sources(request: Request):
        return render(request, "sources.html")

    return app

