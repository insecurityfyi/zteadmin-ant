"""The overview dashboard: a grid of widgets each user can add, remove, move, resize and configure.

A layout is a list of {"id", "type", "w", "opts"} kept on the user (``users.dashboard``). Users without one see the
site default (setting ``dashboard_default``, which an admin sets from their own layout), or else ``DEFAULT_LAYOUT``.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .db import get_setting, set_setting
from .models import Alert, Device, Event, Integration, Poller, Port, Sensor, Site, User
from .web import back, flash, render, st

router = APIRouter(include_in_schema=False)
WIDTHS = (3, 4, 6, 8, 12)
MAX_WIDGETS = 40


@dataclass(frozen=True)
class Opt:
    name: str
    label: str
    kind: str = "select"            # select | number | text | device | port | site
    choices: tuple = ()
    default: Any = ""


@dataclass(frozen=True)
class Widget:
    title: str
    width: int
    load: Callable[[Session, dict], dict]
    help: str = ""
    options: list[Opt] = field(default_factory=list)


def _limit(o: dict, default: int = 8) -> int:
    try:
        return max(1, min(50, int(o.get("limit") or default)))
    except (TypeError, ValueError):
        return default


def _int(v: Any) -> int | None:
    try:
        return int(v) if str(v).strip() else None
    except (TypeError, ValueError):
        return None


def _devices(s: Session, site: str = "") -> list[Device]:
    q = select(Device).options(selectinload(Device.site)).where(Device.disabled.is_(False))
    rows = s.scalars(q).all()
    return [d for d in rows if (d.site.name if d.site else "") == site] if site else rows


# loaders: each returns the template context for one widget -------------------------------------------
def load_summary(s: Session, o: dict) -> dict:
    devices = _devices(s)
    counts = {k: sum(1 for d in devices if d.status == k) for k in ("up", "down", "warn", "unknown", "off")}
    alerts = s.execute(select(Alert.severity, func.count(Alert.id)).where(Alert.state == "open").group_by(Alert.severity)).all()
    busiest = s.execute(select(Port, Device.hostname).join(Device).where(Port.util_pct.is_not(None))
                        .order_by(Port.util_pct.desc()).limit(1)).first()
    pollers = s.scalars(select(Poller).where(Poller.revoked.is_(False))).all()
    return {"devices": len(devices), "counts": counts, "open": sum(n for _, n in alerts),
            "crit": sum(n for sev, n in alerts if sev == "crit"),
            "ports_total": s.scalar(select(func.count(Port.id))) or 0,
            "ports_up": s.scalar(select(func.count(Port.id)).where(Port.oper == "up")) or 0,
            "top_port": busiest[0] if busiest else None, "top_host": busiest[1] if busiest else None,
            "worst_cycle": max((p.last_cycle_ms or 0 for p in pollers), default=0)}


def load_traffic(s: Session, o: dict) -> dict:
    pid = _int(o.get("port_id"))
    row = None
    if pid:
        row = s.execute(select(Port, Device.hostname).join(Device).where(Port.id == pid)).first()
    if row is None:
        row = s.execute(select(Port, Device.hostname).join(Device).where(Port.util_pct.is_not(None))
                        .order_by(Port.util_pct.desc()).limit(1)).first()
    return {"port": row[0] if row else None, "host": row[1] if row else None, "fixed": bool(pid)}


def load_alerts(s: Session, o: dict) -> dict:
    q = select(Alert).options(selectinload(Alert.device)).where(Alert.state.in_(("open", "ack")))
    if o.get("severity") == "crit":
        q = q.where(Alert.severity == "crit")
    return {"alerts": s.scalars(q.order_by(Alert.severity.asc(), Alert.opened_at.desc()).limit(_limit(o))).all()}


def load_sites(s: Session, o: dict) -> dict:
    sites: dict[str, list[Device]] = {}
    for d in _devices(s):
        sites.setdefault(d.site.name if d.site else "No site", []).append(d)
    return {"sites": sorted(sites.items())}


def load_busiest(s: Session, o: dict) -> dict:
    return {"ports": s.execute(select(Port, Device.hostname).join(Device).where(Port.util_pct.is_not(None))
                               .order_by(Port.util_pct.desc()).limit(_limit(o, 6))).all()}


TOP_METRICS = {"cpu": ("CPU", "%"), "mem": ("Memory", "%"), "ping_ms": ("Latency", " ms"), "loss_pct": ("Packet loss", "%")}


def load_top(s: Session, o: dict) -> dict:
    metric = o.get("metric") if o.get("metric") in TOP_METRICS else "cpu"
    devs = [d for d in _devices(s, o.get("site") or "") if getattr(d, metric) is not None and d.status != "off"]
    devs.sort(key=lambda d: -getattr(d, metric))
    label, unit = TOP_METRICS[metric]
    scale = 100.0 if unit == "%" else max([getattr(d, metric) for d in devs] + [1.0])
    return {"rows": [(d, getattr(d, metric)) for d in devs[:_limit(o, 6)]], "metric": metric, "label": label, "unit": unit,
            "scale": scale, "pct": unit == "%"}


DEVICE_GRAPHS = {"cpu": "CPU and memory", "ping": "Latency and loss", "traffic": "Traffic (all ports)"}


def load_device_graph(s: Session, o: dict) -> dict:
    dev = s.get(Device, _int(o.get("device_id")) or 0)
    return {"device": dev, "metric": o.get("metric") if o.get("metric") in DEVICE_GRAPHS else "cpu"}


def load_down(s: Session, o: dict) -> dict:
    states = ("down", "warn") if o.get("include") != "down" else ("down",)
    devs = [d for d in _devices(s) if d.status in states]
    devs.sort(key=lambda d: (d.status != "down", d.status_since))
    return {"devices": devs[:_limit(o, 10)], "total": len(devs)}


def load_events(s: Session, o: dict) -> dict:
    q = select(Event).options(selectinload(Event.device)).order_by(Event.at.desc())
    if o.get("kind"):
        q = q.where(Event.kind == o["kind"])
    return {"events": s.scalars(q.limit(_limit(o, 10))).all()}


def load_integrations(s: Session, o: dict) -> dict:
    rows = s.scalars(select(Integration).order_by(Integration.name)).all()
    counts = dict(s.execute(select(Device.integration_id, func.count(Device.id)).group_by(Device.integration_id)).all())
    return {"integrations": rows, "counts": counts}


def load_sensors(s: Session, o: dict) -> dict:
    kind = o.get("kind") if o.get("kind") in ("temperature", "storage", "fan", "power") else "temperature"
    q = select(Sensor, Device).join(Device).where(Sensor.kind == kind, Device.disabled.is_(False))
    rows = s.execute(q).all()
    bad = [r for r in rows if r[0].status in ("warn", "crit")]
    rest = sorted((r for r in rows if r not in bad and r[0].value is not None), key=lambda r: -(r[0].value or 0))
    return {"rows": (bad + rest)[:_limit(o, 8)], "kind": kind, "total": len(rows), "bad": len(bad)}


def load_map(s: Session, o: dict) -> dict:
    h = _int(o.get("height")) or 420
    return {"site": o.get("site") or "", "height": max(200, min(1000, h))}


def load_note(s: Session, o: dict) -> dict:
    return {"text": str(o.get("text") or "")[:2000]}


SITE = Opt("site", "Site", "site")
LIMIT = Opt("limit", "Rows", "number", default=8)
WIDGETS: dict[str, Widget] = {
    "summary": Widget("Summary", 12, load_summary, "Devices up, open alerts, ports, busiest port and poll cycle."),
    "traffic": Widget("Traffic graph", 8, load_traffic, "Traffic on one port, or the busiest port right now.",
                      [Opt("port_id", "Port (blank = busiest now)", "port")]),
    "alerts": Widget("Open alerts", 4, load_alerts, "Open and acknowledged alerts, worst first.",
                     [Opt("severity", "Show", choices=(("", "All severities"), ("crit", "Critical only"))), LIMIT]),
    "sites": Widget("Devices by site", 4, load_sites, "A coloured tile for every device, grouped by site."),
    "busiest": Widget("Busiest ports", 4, load_busiest, "Ports with the highest utilisation at the last poll.", [Opt("limit", "Rows", "number", default=6)]),
    "top": Widget("Top devices", 4, load_top, "Devices ranked by CPU, memory, latency or loss.",
                  [Opt("metric", "Rank by", choices=tuple((k, v[0]) for k, v in TOP_METRICS.items()), default="cpu"), SITE,
                   Opt("limit", "Rows", "number", default=6)]),
    "device_graph": Widget("Device graph", 6, load_device_graph, "CPU and memory, latency and loss, or total traffic for one device.",
                           [Opt("device_id", "Device", "device"), Opt("metric", "Graph", choices=tuple(DEVICE_GRAPHS.items()), default="cpu")]),
    "down": Widget("Devices with problems", 4, load_down, "Devices that are down or need attention.",
                   [Opt("include", "Show", choices=(("", "Down and warning"), ("down", "Down only"))), Opt("limit", "Rows", "number", default=10)]),
    "events": Widget("Event log", 6, load_events, "The latest events network-wide.",
                     [Opt("kind", "Kind", choices=(("", "All"), ("device", "Device up/down"), ("port", "Ports"), ("alert", "Alerts"),
                                                   ("sensor", "Sensors"), ("integration", "Integrations"), ("poller", "Pollers"),
                                                   ("config", "Changes"))), Opt("limit", "Rows", "number", default=10)]),
    "integrations": Widget("Integrations", 4, load_integrations, "Each integration's sync state and object count."),
    "sensors": Widget("Health sensors", 4, load_sensors, "Sensors in alarm first, then the highest readings.",
                      [Opt("kind", "Sensor type", choices=(("temperature", "Temperature"), ("storage", "Storage"), ("fan", "Fans"),
                                                           ("power", "Power")), default="temperature"), LIMIT]),
    "map": Widget("Network map", 12, load_map, "The LLDP/CDP network map.", [SITE, Opt("height", "Height (px)", "number", default=420)]),
    "note": Widget("Note", 4, load_note, "Your own text: on-call numbers, links, reminders.", [Opt("text", "Text", "text")]),
}

DEFAULT_LAYOUT = [
    {"type": "summary", "w": 12}, {"type": "traffic", "w": 8}, {"type": "alerts", "w": 4},
    {"type": "sites", "w": 4}, {"type": "busiest", "w": 4}, {"type": "top", "w": 4, "opts": {"metric": "cpu"}},
]


def clean_layout(raw: Any) -> list[dict]:
    """Keep only known widget types, legal widths and short scalar options."""
    out = []
    for w in raw if isinstance(raw, list) else []:
        if not isinstance(w, dict) or w.get("type") not in WIDGETS:
            continue
        spec = WIDGETS[w["type"]]
        width = _int(w.get("w"))
        opts = {}
        for o in spec.options:
            v = (w.get("opts") or {}).get(o.name) if isinstance(w.get("opts"), dict) else None
            if v not in (None, ""):
                opts[o.name] = str(v)[:2000] if o.kind == "text" else str(v)[:120]
        wid = str(w.get("id") or "")
        out.append({"id": wid if re.fullmatch(r"[a-z0-9]{4,16}", wid) else secrets.token_hex(4), "type": w["type"],
                    "w": width if width in WIDTHS else spec.width, "opts": opts})
        if len(out) >= MAX_WIDGETS:
            break
    return out


def layout_for(s: Session, user: User | None) -> tuple[list[dict], str]:
    """The layout to show and where it came from: 'user', 'site' or 'builtin'."""
    if user is not None and user.dashboard:
        lay = clean_layout(user.dashboard)
        if lay:
            return lay, "user"
    try:
        site = clean_layout(json.loads(get_setting(s, "dashboard_default") or "null"))
    except ValueError:
        site = []
    if site:
        return site, "site"
    return clean_layout(DEFAULT_LAYOUT), "builtin"


def _headline(s: Session) -> tuple[str, int, int]:
    devices = _devices(s)
    down = [d for d in devices if d.status == "down"]
    warn = sum(1 for d in devices if d.status == "warn")
    if not devices:
        return "No devices yet", 0, 0
    if down:
        by_site: dict[str, int] = {}
        for d in down:
            k = d.site.name if d.site else "no site"
            by_site[k] = by_site.get(k, 0) + 1
        where = ", ".join(f"{n} at {k}" for k, n in sorted(by_site.items(), key=lambda kv: -kv[1])[:2])
        return f"{len(down)} device{'s' if len(down) != 1 else ''} down ({where})", len(devices), len(down)
    if warn:
        return f"All devices reachable, {warn} need attention", len(devices), 0
    return "Everything is up", len(devices), 0


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, edit: int = 0):
    user = getattr(request.state, "user", None)
    with st(request).db.session() as s:
        me = s.get(User, user.id) if user else None
        layout, source = layout_for(s, me)
        widgets = []
        for w in layout:
            try:
                ctx = WIDGETS[w["type"]].load(s, w["opts"])
            except Exception as exc:  # noqa: BLE001 - one broken widget mustn't take the page down
                ctx = {"error": str(exc)[:200]}
            widgets.append({**w, "spec": WIDGETS[w["type"]], "ctx": ctx})
        headline, n_devices, _ = _headline(s)
        sites = sorted(n for n in s.scalars(select(Site.name)))
        n_sites = len({d.site_id for d in _devices(s)})
        pollers = s.scalar(select(func.count(Poller.id)).where(Poller.revoked.is_(False))) or 0
        interval = st(request).hub.interval(s)
        pick_devices = s.execute(select(Device.id, Device.hostname).order_by(Device.hostname).limit(3000)).all()
    return render(request, "dashboard.html", {
        "widgets": widgets, "layout_source": source, "headline": headline, "n_devices": n_devices, "n_sites": n_sites,
        "pollers": pollers, "interval": interval, "edit": bool(edit), "catalog": WIDGETS, "widths": WIDTHS,
        "site_names": sites, "pick_devices": pick_devices, "layout_json": json.dumps(layout),
    })


@router.get("/ui/dashboard/ports", include_in_schema=False)
def port_picker(request: Request, q: str = ""):
    """Ports matching a search, for the traffic widget's settings."""
    like = f"%{q.strip()}%"
    with st(request).db.session() as s:
        rows = s.execute(select(Port.id, Port.name, Port.alias, Device.hostname).join(Device)
                         .where((Device.hostname.ilike(like)) | (Port.name.ilike(like)) | (Port.alias.ilike(like)))
                         .order_by(Device.hostname, Port.ifindex).limit(30)).all()
    return [{"id": r[0], "label": f"{r[3]} {r[1]}" + (f" ({r[2]})" if r[2] else "")} for r in rows]


@router.post("/account/dashboard")
async def save_layout(request: Request):
    """Save the signed-in user's layout (JSON body: {"layout": [...]}) — viewers may customise their own dashboard."""
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"detail": "Expected JSON"}, status_code=400)
    layout = clean_layout((body or {}).get("layout"))
    with st(request).db.session() as s:
        user = s.get(User, request.state.user.id)
        user.dashboard = layout
    return {"ok": True, "widgets": len(layout)}


@router.post("/account/dashboard/reset")
def reset_layout(request: Request):
    with st(request).db.session() as s:
        s.get(User, request.state.user.id).dashboard = None
    flash(request, "Dashboard reset to the default layout.")
    return back("/")


@router.post("/admin/dashboard/default")
def make_default(request: Request):
    with st(request).db.session() as s:
        layout, _ = layout_for(s, s.get(User, request.state.user.id))
        set_setting(s, "dashboard_default", json.dumps(layout))
    flash(request, "Your layout is now the default for everyone who hasn't customised theirs.")
    return back("/")
