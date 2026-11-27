"""Network-wide pages: every port, one port, health readings and the event log."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from .models import Device, Event, Neighbor, Port, Sensor
from .web import render, st

router = APIRouter(include_in_schema=False)
PAGE = 200
HEALTH = {
    "cpu": ("Processors", "CPU load from the last poll", Device.cpu, "pct", "cpu"),
    "mem": ("Memory", "Memory used from the last poll", Device.mem, "pct", "mem"),
    "ping": ("Latency", "Ping round trip from each device's poller", Device.ping_ms, "ms", "ping"),
    "loss": ("Packet loss", "Ping loss from each device's poller", Device.loss_pct, "pct", "loss"),
}


SENSOR_PAGES = {"temperature": ("Temperature", "°C"), "fan": ("Fans", "rpm"), "power": ("Power", "W"),
                "voltage": ("Voltage", "V"), "state": ("Component state", ""), "storage": ("Storage", "%"),
                "system": ("Load and TCP/IP", ""), "diskio": ("Disk I/O", "B/s"), "custom": ("Custom OID values", "")}


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
    if metric in SENSOR_PAGES:
        with st(request).db.session() as s:
            q = select(Sensor).options(selectinload(Sensor.device)).join(Device, Device.id == Sensor.device_id).where(
                Device.disabled.is_(False))
            q = q.where(Sensor.kind == metric) if metric != "voltage" else q.where(Sensor.kind.in_(("voltage", "current")))
            rows = s.scalars(q).all()
            if metric in ("system", "custom"):     # mixed units: group by device, then name
                rows = sorted(rows, key=lambda x: ({"crit": 0, "warn": 1}.get(x.status, 2), x.device.hostname.lower(), x.name))
            else:
                rows = sorted(rows, key=lambda x: ({"crit": 0, "warn": 1}.get(x.status, 2), -(x.value or 0)))
            kinds = dict(s.execute(select(Sensor.kind, func.count(Sensor.id)).group_by(Sensor.kind)).all())
        return render(request, "health.html", {"metric": metric, "metrics": HEALTH, "sensor_pages": SENSOR_PAGES,
                                               "kinds": kinds, "sensor_rows": rows, "title": SENSOR_PAGES[metric][0],
                                               "rows": [], "values": [], "missing": 0, "avg": None, "unit": "", "key": "",
                                               "sub": "Readings from the last poll"})
    if metric not in HEALTH:
        metric = "cpu"
    title, sub, col, unit, key = HEALTH[metric]
    with st(request).db.session() as s:
        rows = s.scalars(select(Device).options(selectinload(Device.site)).where(Device.disabled.is_(False), col.is_not(None))
                         .order_by(col.desc(), Device.hostname)).all()
        missing = s.scalar(select(func.count(Device.id)).where(Device.disabled.is_(False), col.is_(None))) or 0
    values = [getattr(d, {"cpu": "cpu", "mem": "mem", "ping": "ping_ms", "loss": "loss_pct"}[metric]) for d in rows]
    avg = sum(values) / len(values) if values else None
    with st(request).db.session() as s:
        kinds = dict(s.execute(select(Sensor.kind, func.count(Sensor.id)).group_by(Sensor.kind)).all())
    return render(request, "health.html", {"metric": metric, "metrics": HEALTH, "sensor_pages": SENSOR_PAGES, "kinds": kinds,
                                           "sensor_rows": None, "title": title, "sub": sub, "unit": unit,
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


@router.get("/map", response_class=HTMLResponse)
def network_map(request: Request, site: str = "", focus: str = "", external: str = ""):
    with st(request).db.session() as s:
        from .models import Site
        sites = sorted(s.scalars(select(Site.name)))
        links = s.scalar(select(func.count(Neighbor.id))) or 0
    return render(request, "map.html", {"sites": sites, "site": site, "focus": focus, "external": external, "link_count": links})


def _clients(d: Device) -> int | None:
    ex = d.extra or {}
    v = ex.get("clients", (ex.get("api") or {}).get("clients"))
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


@router.get("/ui/map", include_in_schema=False)
def map_data(request: Request, site: str = "", external: str = "", all: str = "", hide_aps: str = ""):
    """Nodes and links for the network map. Links come from LLDP/CDP neighbours and integration uplinks.

    Wireless access points are always drawn (on their uplink when it is known) unless ``hide_aps`` is set.
    """
    with st(request).db.session() as s:
        devs = {d.id: d for d in s.scalars(select(Device).options(selectinload(Device.site)).where(Device.disabled.is_(False)))}
        if site:
            devs = {i: d for i, d in devs.items() if d.site and d.site.name == site}
        if hide_aps:
            devs = {i: d for i, d in devs.items() if d.type != "Wireless"}
        rows = s.scalars(select(Neighbor).options(selectinload(Neighbor.port)).where(Neighbor.device_id.in_(list(devs) or [0]))).all()
        links: dict[tuple, dict] = {}
        ghosts: dict[str, dict] = {}
        for n in rows:
            if n.remote_device_id in devs:
                b = n.remote_device_id
            elif external and (n.remote_name or n.remote_chassis):
                gid = "x:" + (n.remote_name or n.remote_chassis).lower()
                ghosts.setdefault(gid, {"id": gid, "name": n.remote_name or n.remote_chassis, "status": "external",
                                        "type": (n.remote_platform or "")[:40], "ip": n.remote_ip})
                b = gid
            else:
                continue
            a = n.device_id
            key = tuple(sorted([str(a), str(b)])) + tuple(sorted([str(n.local_port or ""), str(n.remote_port or "")]))
            p = n.port
            util = p.util_pct if p is not None else None
            cur = links.get(key)
            if cur is None:
                links[key] = {"source": a, "target": b, "protocol": n.protocol, "a_port": n.local_port, "b_port": n.remote_port,
                              "mesh": n.protocol.endswith("-mesh"),
                              "speed": p.speed_mbps if p is not None else None, "util": util,
                              "bps": max(p.in_bps or 0, p.out_bps or 0) if p is not None else None}
            elif util is not None and (cur["util"] is None or util > cur["util"]):
                cur.update(util=util, speed=p.speed_mbps, bps=max(p.in_bps or 0, p.out_bps or 0))
        linked = {x for k in links.values() for x in (k["source"], k["target"])}
        nodes = [{"id": d.id, "name": d.hostname, "status": d.status, "type": d.type, "ip": d.ip,
                  "site": d.site.name if d.site else None, "platform": d.platform, "ap": d.type == "Wireless",
                  "clients": _clients(d) if d.type == "Wireless" else None}
                 for d in devs.values() if all or d.id in linked or d.type == "Wireless"]
    return {"nodes": nodes + list(ghosts.values()), "links": list(links.values())}
