"""One page per integration: its sync state, the objects it reports, and the vendor's own telemetry."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..integrations import REGISTRY
from .models import Device, Integration
from .web import back, render, st

router = APIRouter(include_in_schema=False)
ZSCALER_TABS = [("overview", "Overview"), ("zia", "ZIA"), ("zpa", "ZPA"), ("zdx", "ZDX"), ("zcc", "Client Connector"), ("ztb", "Zero Trust Branch")]


@router.get("/integrations/{iid}/overview", response_class=HTMLResponse)
def integration_overview(request: Request, iid: int, tab: str = "overview"):
    with st(request).db.session() as s:
        integ = s.get(Integration, iid, options=[selectinload(Integration.poller)])
        if integ is None:
            raise HTTPException(404, "No such integration")
        if integ.kind == "unifi":
            return back(f"/unifi?i={iid}")
        devices = s.scalars(select(Device).where(Device.integration_id == iid)
                            .options(selectinload(Device.site)).order_by(Device.type, Device.hostname).limit(2000)).all()
    data: dict[str, Any] = integ.data or {}
    ts = data.get("ts")
    counts = {k: sum(1 for d in devices if d.status == k) for k in ("up", "warn", "down", "off", "unknown")}
    ctx: dict[str, Any] = {"integ": integ, "cls": REGISTRY.get(integ.kind), "data": data, "devices": devices, "counts": counts,
                           "data_ts": datetime.fromisoformat(ts.rstrip("Z")) if ts else None, "nav_iid": iid,
                           "device_by_ext": {d.external_id: d for d in devices}}
    if integ.kind == "zscaler":
        products = data.get("products") or {}
        tabs = [(k, label) for k, label in ZSCALER_TABS if k == "overview" or k in products]
        ctx.update(tabs=tabs, tab=tab if tab in dict(tabs) else "overview")
        if ctx["tab"] != "overview":
            ctx["devices"] = [d for d in devices if (d.extra or {}).get("product") == ctx["tab"]]
    return render(request, "integration_view.html", ctx)
