"""UniFi pages: the Wi-Fi and clients dashboard, one client, one SSID."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from .models import Device, Integration
from .web import back, render, st

router = APIRouter(include_in_schema=False)


def _unifi(s, iid: int | None) -> tuple[Integration | None, list[Integration]]:
    all_ = s.scalars(select(Integration).where(Integration.kind == "unifi").order_by(Integration.name)).all()
    if iid is None:
        return (all_[0] if all_ else None), all_
    integ = next((i for i in all_ if i.id == iid), None)
    if integ is None:
        raise HTTPException(404, "No such UniFi integration")
    return integ, all_


def _ctx(s, integ: Integration, others: list[Integration]) -> dict[str, Any]:
    data = integ.data or {}
    ts = data.get("ts")
    devices = {d.external_id: d.id for d in s.scalars(select(Device).where(Device.integration_id == integ.id))}
    return {"integ": integ, "others": others, "data": data, "summary": data.get("summary") or {},
            "data_ts": datetime.fromisoformat(ts.rstrip("Z")) if ts else None, "device_ids": devices}


@router.get("/unifi", response_class=HTMLResponse)
def unifi_home(request: Request, i: int | None = None):
    with st(request).db.session() as s:
        integ, others = _unifi(s, i)
        if integ is None:
            return render(request, "unifi.html", {"integ": None, "others": []})
        ctx = _ctx(s, integ, others)
    return render(request, "unifi.html", ctx)


@router.get("/unifi/{iid}", response_class=HTMLResponse)
def unifi_dashboard(request: Request, iid: int):
    return back(f"/unifi?i={iid}")


@router.get("/unifi/{iid}/clients/{mac}", response_class=HTMLResponse)
def unifi_client(request: Request, iid: int, mac: str):
    with st(request).db.session() as s:
        integ, others = _unifi(s, iid)
        ctx = _ctx(s, integ, others)
    client = next((c for c in ctx["data"].get("clients") or [] if c.get("mac") == mac), None)
    if client is not None and not client.get("wired"):
        from .wireless import normalize
        client = normalize({"clients": [dict(client)]})["clients"][0]     # older snapshots lack the Wi-Fi quality fields
    ctx.update(mac=mac, c=client, series=f"client:{mac}")
    return render(request, "unifi_client.html", ctx)


@router.get("/unifi/{iid}/ssids/{name:path}", response_class=HTMLResponse)
def unifi_ssid(request: Request, iid: int, name: str):
    with st(request).db.session() as s:
        integ, others = _unifi(s, iid)
        ctx = _ctx(s, integ, others)
    ssids = ctx["data"].get("ssids") or []
    ssid = next((x for x in ssids if x.get("series") == f"ssid:{name}"), None) or next((x for x in ssids if x.get("name") == name), None)
    if ssid is None:
        raise HTTPException(404, "That SSID is not in the latest UniFi data")
    full = ssid["name"]
    clients = [c for c in ctx["data"].get("clients") or [] if c.get("ssid") == full and c.get("site") == ssid.get("site")]
    aps = [a for a in ctx["data"].get("aps") or [] if full in (a.get("ssids") or [])]
    ctx.update(ssid=ssid, clients=clients, aps=aps)
    return render(request, "unifi_ssid.html", ctx)
