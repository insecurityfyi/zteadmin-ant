"""Network-wide pages: every port, one port, health readings and the event log."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from .models import Device, Event, Port
from .web import render, st

router = APIRouter(include_in_schema=False)
PAGE = 200
HEALTH = {
    "cpu": ("Processors", "CPU load from the last poll", Device.cpu, "pct", "cpu"),
    "mem": ("Memory", "Memory used from the last poll", Device.mem, "pct", "mem"),
    "ping": ("Latency", "Ping round trip from each device's poller", Device.ping_ms, "ms", "ping"),
    "loss": ("Packet loss", "Ping loss from each device's poller", Device.loss_pct, "pct", "loss"),
}


def _page(v) -> int:
    try:
        return max(1, int(v))
    except (TypeError, ValueError):
        return 1


@router.get("/ports", response_class=HTMLResponse)
def ports_page(request: Request, q: str = "", state: str = "", errors: str = "", sort: str = "traffic", page: str = "1"):
    pg = _page(page)
    with st(request).db.session() as s:
        query = select(Port, Device.hostname, Device.status).join(Device, Device.id == Port.device_id).where(Device.disabled.is_(False))
        if q:
            like = f"%{q}%"
            query = query.where(or_(Port.name.ilike(like), Port.alias.ilike(like), Device.hostname.ilike(like)))
        if state == "up":
            query = query.where(Port.oper == "up")
        elif state == "down":
            query = query.where(Port.admin == "up", Port.oper != "up")
        elif state == "shutdown":
            query = query.where(Port.admin != "up")
        if errors:
            query = query.where(func.coalesce(Port.in_err_rate, 0) + func.coalesce(Port.out_err_rate, 0) > 0)
        busiest = func.coalesce(Port.in_bps, 0) + func.coalesce(Port.out_bps, 0)
        order = {"util": [func.coalesce(Port.util_pct, -1).desc()],
                 "errors": [(func.coalesce(Port.in_err_rate, 0) + func.coalesce(Port.out_err_rate, 0)).desc()],
                 "name": [Device.hostname, Port.ifindex]}.get(sort, [busiest.desc()])
        total = s.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = s.execute(query.order_by(*order, Port.id).offset((pg - 1) * PAGE).limit(PAGE)).all()
        counts = {"all": s.scalar(select(func.count(Port.id))) or 0,
                  "up": s.scalar(select(func.count(Port.id)).where(Port.oper == "up")) or 0,
                  "down": s.scalar(select(func.count(Port.id)).where(Port.admin == "up", Port.oper != "up")) or 0,
                  "shutdown": s.scalar(select(func.count(Port.id)).where(Port.admin != "up")) or 0}
    return render(request, "ports.html", {"rows": rows, "q": q, "state": state, "errors": errors, "sort": sort, "page": pg,
                                          "pages": max(1, -(-total // PAGE)), "total": total, "counts": counts})


@router.get("/ports/{port_id}", response_class=HTMLResponse)
def port_page(request: Request, port_id: int):
    with st(request).db.session() as s:
        p = s.get(Port, port_id, options=[selectinload(Port.device).selectinload(Device.site)])
        if p is None:
            raise HTTPException(404, "No such port")
        events = s.scalars(select(Event).where(Event.port_id == p.id).order_by(Event.id.desc()).limit(50)).all()
        siblings = s.scalars(select(Port).where(Port.device_id == p.device_id).order_by(Port.ifindex)).all()
    return render(request, "port.html", {"p": p, "d": p.device, "events": events, "siblings": siblings})


@router.get("/health", response_class=HTMLResponse)
def health_page(request: Request, metric: str = "cpu"):
    if metric not in HEALTH:
        metric = "cpu"
    title, sub, col, unit, key = HEALTH[metric]
    with st(request).db.session() as s:
        rows = s.scalars(select(Device).options(selectinload(Device.site)).where(Device.disabled.is_(False), col.is_not(None))
                         .order_by(col.desc(), Device.hostname)).all()
        missing = s.scalar(select(func.count(Device.id)).where(Device.disabled.is_(False), col.is_(None))) or 0
    values = [getattr(d, {"cpu": "cpu", "mem": "mem", "ping": "ping_ms", "loss": "loss_pct"}[metric]) for d in rows]
    avg = sum(values) / len(values) if values else None
    return render(request, "health.html", {"metric": metric, "metrics": HEALTH, "title": title, "sub": sub, "unit": unit,
                                           "key": key, "rows": rows, "values": values, "avg": avg, "missing": missing})


@router.get("/eventlog", response_class=HTMLResponse)
def eventlog(request: Request, kind: str = "", severity: str = "", q: str = "", device: str = "", page: str = "1"):
    pg = _page(page)
    with st(request).db.session() as s:
        query = select(Event).options(selectinload(Event.device))
        if kind:
            query = query.where(Event.kind == kind)
        if severity:
            query = query.where(Event.severity == severity)
        if device.isdigit():
            query = query.where(Event.device_id == int(device))
        if q:
            like = f"%{q}%"
            query = query.outerjoin(Device, Device.id == Event.device_id).where(or_(Event.message.ilike(like), Device.hostname.ilike(like)))
        total = s.scalar(select(func.count()).select_from(query.subquery())) or 0
        events = s.scalars(query.order_by(Event.id.desc()).offset((pg - 1) * PAGE).limit(PAGE)).all()
        dev = s.get(Device, int(device)) if device.isdigit() else None
    return render(request, "eventlog.html", {"events": events, "kind": kind, "severity": severity, "q": q, "device": device,
                                             "dev": dev, "page": pg, "pages": max(1, -(-total // PAGE)), "total": total})
