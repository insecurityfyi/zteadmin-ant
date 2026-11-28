"""Network-wide pages: every port, one port, health readings and the event log."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from . import events
from .app import flash
from .models import Device, Event, Neighbor, Port, Sensor
from .topology import build_map, norm_port, set_isp_names, set_wan_port, wan_port_ids
from .web import _who, render, st

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
        is_wan = p.id in wan_port_ids(s)
    return render(request, "port.html", {"p": p, "d": p.device, "events": events, "siblings": siblings, "is_wan": is_wan})


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
        manual = s.scalars(select(Neighbor).options(selectinload(Neighbor.device), selectinload(Neighbor.remote_device))
                           .where(Neighbor.protocol == "manual").order_by(Neighbor.id)).all()
        devices = s.execute(select(Device.id, Device.hostname).where(Device.disabled.is_(False))
                            .where(Device.type.not_in(("VM", "Container"))).order_by(func.lower(Device.hostname))).all()
        wans = sorted((l for l in build_map(s)["links"] if l["protocol"] == "wan"), key=lambda l: (l["gateway"].lower(), l["wan"] or ""))
    return render(request, "map.html", {"sites": sites, "site": site, "focus": focus, "external": external, "link_count": links,
                                        "manual": manual, "devices": devices, "wans": wans})


@router.get("/ui/map", include_in_schema=False)
def map_data(request: Request, site: str = "", external: str = "", all: str = "", hide_aps: str = "", clients: str = ""):
    """Nodes and links for the network map (see topology.py): duplicates grouped into one node, links from LLDP/CDP,
    integration uplinks, UniFi switch ports and links drawn by hand, and an Internet cloud for gateways' WAN uplinks.

    Wireless access points are always drawn (on their uplink when it is known) unless ``hide_aps`` is set.
    ``clients`` adds UniFi clients on their AP (with signal and band) or switch port.
    """
    with st(request).db.session() as s:
        return build_map(s, site=site, external=bool(external), show_all=bool(all), hide_aps=bool(hide_aps),
                         clients=bool(clients))


@router.post("/map/links")
async def map_link_add(request: Request):
    """A link drawn by hand, for boxes that send no LLDP and no integration can place (a firewall, a hypervisor)."""
    form = await request.form()
    try:
        a, b = int(form.get("a") or 0), int(form.get("b") or 0)
    except ValueError:
        a = b = 0
    with st(request).db.session() as s:
        da, db_ = s.get(Device, a), s.get(Device, b)
        if da is None or db_ is None or a == b:
            flash(request, "Pick two different devices to link.", "warn")
            return RedirectResponse("/map#manual-links", status_code=303)
        a_port = str(form.get("a_port") or "").strip()[:255] or None
        b_port = str(form.get("b_port") or "").strip()[:255] or None
        port = next((p for p in da.ports if a_port and norm_port(a_port) in (norm_port(p.name), norm_port(p.alias))), None)
        s.add(Neighbor(device_id=a, port_id=port.id if port else None, protocol="manual", local_port=a_port,
                       remote_name=db_.hostname, remote_port=b_port, remote_ip=db_.ip if db_.ip and len(db_.ip) <= 64 else None,
                       remote_device_id=b))
        events.log(s, "config", f"Map link to {db_.hostname} added by {_who(request)}", "info", da, username=_who(request))
    flash(request, f"Linked {da.hostname} to {db_.hostname}.", "ok")
    return RedirectResponse("/map#manual-links", status_code=303)


@router.post("/map/isps")
async def map_isps(request: Request):
    """Name the ISP behind each WAN uplink; WANs with the same ISP share one circle on the map. Empty = what the API says."""
    form = await request.form()
    keys, names = form.getlist("key"), form.getlist("isp")
    with st(request).db.session() as s:
        set_isp_names(s, {str(k): str(n) for k, n in zip(keys, names)})
        events.log(s, "config", f"Map ISP names updated by {_who(request)}", "info", username=_who(request))
    flash(request, "ISP names saved.", "ok")
    return RedirectResponse("/map#wan-isps", status_code=303)


@router.post("/map/links/{link_id}/delete")
def map_link_delete(request: Request, link_id: int):
    with st(request).db.session() as s:
        n = s.get(Neighbor, link_id)
        if n is None or n.protocol != "manual":
            raise HTTPException(404)
        events.log(s, "config", f"Map link to {n.remote_name} removed by {_who(request)}", "info", n.device_id, username=_who(request))
        s.delete(n)
    flash(request, "Link removed.", "ok")
    return RedirectResponse("/map#manual-links", status_code=303)


@router.post("/ports/{port_id}/wan")
def port_wan_toggle(request: Request, port_id: int):
    """Mark a port as an Internet uplink: the map draws it to the Internet cloud with its speed and traffic."""
    with st(request).db.session() as s:
        p = s.get(Port, port_id)
        if p is None:
            raise HTTPException(404)
        on = p.id not in wan_port_ids(s)
        set_wan_port(s, p.id, on)
        events.log(s, "config", f"Port {p.name}: Internet uplink on the map turned {'on' if on else 'off'} by {_who(request)}",
                   "info", p.device_id, p, username=_who(request))
    nxt = str(request.query_params.get("next") or "")
    return RedirectResponse(nxt if nxt.startswith("/") and not nxt.startswith("//") else f"/ports/{port_id}", status_code=303)


@router.get("/ui/map/l3", include_in_schema=False)
def map_l3_data(request: Request, site: str = "", hosts: str = ""):
    """Subnets and the routed interfaces on them, for the Layer 3 map under the network map (see layers.py)."""
    from .layers import build_l3
    with st(request).db.session() as s:
        return build_l3(s, site=site, hosts=bool(hosts))


@router.get("/ui/map/l2", include_in_schema=False)
def map_l2_data(request: Request, site: str = "", clients: str = ""):
    """VLANs and the devices on each, for the Layer 2 map under the network map (see layers.py)."""
    from .layers import build_l2
    with st(request).db.session() as s:
        return build_l2(s, site=site, clients=bool(clients))
