"""JSON endpoints: poller enrollment and WebSocket, the public REST API (/api/v1) and chart data for the UI (/ui)."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, WebSocket
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from .gateway import EnrollError
from .models import Alert, ApiKey, Device, DeviceMetric, IntegrationMetric, Port, PortMetric, utcnow
from .security import sha256

router = APIRouter()
RANGES = {"6h": (timedelta(hours=6), False), "24h": (timedelta(hours=24), False), "7d": (timedelta(days=7), False),
          "30d": (timedelta(days=30), True), "1y": (timedelta(days=365), True)}
_enroll_attempts: dict[str, list[float]] = defaultdict(list)


def lw(request: Request):
    return request.app.state.lw


def client_ip(request) -> str | None:
    return request.client.host if request.client else None


# ------------------------------------------------------------------ poller
class EnrollBody(BaseModel):
    token: str
    name: str | None = None
    hostname: str | None = None
    version: str | None = None


@router.post("/api/poller/enroll", include_in_schema=False)
def enroll(body: EnrollBody, request: Request):
    ip = client_ip(request) or "?"
    now = time.time()
    _enroll_attempts[ip] = [t for t in _enroll_attempts[ip] if now - t < 900]
    if len(_enroll_attempts[ip]) >= 10:
        raise HTTPException(429, "Too many enrollment attempts")
    _enroll_attempts[ip].append(now)
    try:
        return lw(request).hub.enroll(body.token, body.name or "", body.hostname, body.version, ip)
    except EnrollError as exc:
        raise HTTPException(403, str(exc)) from None


@router.websocket("/api/poller/ws")
async def poller_ws(ws: WebSocket):
    state = ws.app.state.lw
    poller = await asyncio.to_thread(state.hub.authenticate, ws.headers.get("authorization"))
    if poller is None:
        await ws.close(code=1008)   # before accept: the client sees HTTP 403
        return
    await ws.accept()
    await state.hub.serve(ws, poller, ws.headers.get("x-real-ip") or (ws.client.host if ws.client else None))


# ------------------------------------------------------------------ auth for /api/v1
def api_key(request: Request, authorization: str | None = Header(None)) -> ApiKey:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Send an API key as 'Authorization: Bearer lw_...'")
    with lw(request).db.session() as s:
        key = s.scalar(select(ApiKey).where(ApiKey.key_hash == sha256(authorization[7:].strip())))
        if key is None:
            raise HTTPException(401, "Unknown API key")
        key.last_used = utcnow()
        return key


def writable(key: ApiKey = Depends(api_key)) -> ApiKey:
    if key.scope != "rw":
        raise HTTPException(403, "This API key is read-only")
    return key


def device_json(d: Device) -> dict[str, Any]:
    return {"id": d.id, "hostname": d.hostname, "ip": d.ip, "type": d.type, "platform": d.platform,
            "site": d.site.name if d.site else None, "status": d.status, "status_reason": d.status_reason,
            "status_since": d.status_since.isoformat() + "Z" if d.status_since else None, "source": d.source,
            "poller": d.poller.name if d.poller else None, "cpu": d.cpu, "mem": d.mem, "ping_ms": d.ping_ms,
            "loss_pct": d.loss_pct, "uptime_s": d.uptime_s, "serial": d.serial, "detail": d.detail,
            "last_polled": d.last_polled.isoformat() + "Z" if d.last_polled else None}


def port_json(p: Port) -> dict[str, Any]:
    return {"id": p.id, "ifindex": p.ifindex, "name": p.name, "alias": p.alias, "speed_mbps": p.speed_mbps,
            "admin": p.admin, "oper": p.oper, "in_bps": p.in_bps, "out_bps": p.out_bps, "util_pct": p.util_pct,
            "in_errors_per_poll": p.in_err_rate, "out_errors_per_poll": p.out_err_rate}


def alert_json(a: Alert) -> dict[str, Any]:
    return {"id": a.id, "rule": a.rule_key, "severity": a.severity, "title": a.title, "detail": a.detail,
            "state": a.state, "device_id": a.device_id, "opened_at": a.opened_at.isoformat() + "Z",
            "resolved_at": a.resolved_at.isoformat() + "Z" if a.resolved_at else None}


@router.get("/api/v1/devices", tags=["devices"])
def list_devices(request: Request, status: str | None = None, _: ApiKey = Depends(api_key)):
    with lw(request).db.session() as s:
        q = select(Device).options(selectinload(Device.site), selectinload(Device.poller)).order_by(Device.hostname)
        if status:
            q = q.where(Device.status == status)
        return [device_json(d) for d in s.scalars(q)]


@router.get("/api/v1/devices/{device_id}", tags=["devices"])
def get_device(device_id: int, request: Request, _: ApiKey = Depends(api_key)):
    with lw(request).db.session() as s:
        d = s.get(Device, device_id)
        if d is None:
            raise HTTPException(404, "No such device")
        return device_json(d) | {"ports": [port_json(p) for p in d.ports], "extra": d.extra}


@router.get("/api/v1/devices/{device_id}/metrics", tags=["devices"])
def device_metrics_api(device_id: int, request: Request, range: str = "24h", _: ApiKey = Depends(api_key)):
    return _device_series(request, device_id, range)


@router.get("/api/v1/ports/{port_id}/metrics", tags=["devices"])
def port_metrics_api(port_id: int, request: Request, range: str = "24h", _: ApiKey = Depends(api_key)):
    return _port_series(request, port_id, range)


@router.get("/api/v1/alerts", tags=["alerts"])
def list_alerts(request: Request, state: str = "open", _: ApiKey = Depends(api_key)):
    with lw(request).db.session() as s:
        q = select(Alert).order_by(Alert.opened_at.desc()).limit(500)
        if state == "open":
            q = q.where(Alert.state.in_(("open", "ack")))
        elif state in ("ack", "resolved"):
            q = q.where(Alert.state == state)
        return [alert_json(a) for a in s.scalars(q)]


@router.post("/api/v1/alerts/{alert_id}/ack", tags=["alerts"])
def ack_alert_api(alert_id: int, request: Request, _: ApiKey = Depends(writable)):
    with lw(request).db.session() as s:
        a = s.get(Alert, alert_id)
        if a is None:
            raise HTTPException(404, "No such alert")
        if a.state == "open":
            a.state, a.acked_at = "ack", utcnow()
        return alert_json(a)


@router.post("/api/v1/devices/{device_id}/poll", tags=["devices"])
def poll_now_api(device_id: int, request: Request, _: ApiKey = Depends(writable)):
    state = lw(request)
    with state.db.session() as s:
        d = s.get(Device, device_id)
        if d is None:
            raise HTTPException(404, "No such device")
        sent = state.hub.send_soon(d.poller_id, {"type": "poll_now", "device_id": d.id})
    return {"queued": sent}


# ------------------------------------------------------------------ chart data for the UI (session auth)
def _window(rng: str):
    span, hourly = RANGES.get(rng, RANGES["24h"])
    return utcnow() - span, hourly


def _device_series(request: Request, device_id: int, rng: str) -> dict[str, list]:
    since, hourly = _window(rng)
    with lw(request).db.session() as s:
        rows = s.execute(select(DeviceMetric.ts, DeviceMetric.cpu, DeviceMetric.mem, DeviceMetric.ping_ms, DeviceMetric.loss_pct)
                         .where(DeviceMetric.device_id == device_id, DeviceMetric.hourly.is_(hourly), DeviceMetric.ts >= since)
                         .order_by(DeviceMetric.ts)).all()
    return {"ts": [r[0].isoformat() + "Z" for r in rows], "cpu": [r[1] for r in rows], "mem": [r[2] for r in rows],
            "ping": [r[3] for r in rows], "loss": [r[4] for r in rows]}


def _port_series(request: Request, port_id: int, rng: str) -> dict[str, list]:
    since, hourly = _window(rng)
    with lw(request).db.session() as s:
        rows = s.execute(select(PortMetric.ts, PortMetric.in_bps, PortMetric.out_bps, PortMetric.in_err, PortMetric.out_err)
                         .where(PortMetric.port_id == port_id, PortMetric.hourly.is_(hourly), PortMetric.ts >= since)
                         .order_by(PortMetric.ts)).all()
        speed = s.scalar(select(Port.speed_mbps).where(Port.id == port_id))
    cap = speed * 1e6 if speed else None
    util = (lambda v: None if v is None or not cap else min(100.0, v / cap * 100))
    return {"ts": [r[0].isoformat() + "Z" for r in rows], "in": [r[1] for r in rows], "out": [r[2] for r in rows],
            "in_err": [r[3] for r in rows], "out_err": [r[4] for r in rows],
            "util_in": [util(r[1]) for r in rows], "util_out": [util(r[2]) for r in rows]}


def _device_traffic(request: Request, device_id: int, rng: str) -> dict[str, list]:
    """All of a device's ports added up per poll."""
    since, hourly = _window(rng)
    with lw(request).db.session() as s:
        rows = s.execute(select(PortMetric.ts, func.sum(PortMetric.in_bps), func.sum(PortMetric.out_bps))
                         .join(Port, Port.id == PortMetric.port_id)
                         .where(Port.device_id == device_id, PortMetric.hourly.is_(hourly), PortMetric.ts >= since)
                         .group_by(PortMetric.ts).order_by(PortMetric.ts)).all()
    return {"ts": [r[0].isoformat() + "Z" for r in rows], "in": [r[1] for r in rows], "out": [r[2] for r in rows]}


@router.get("/ui/metrics/device/{device_id}/traffic", include_in_schema=False)
def device_traffic_ui(device_id: int, request: Request, range: str = "24h"):
    return _device_traffic(request, device_id, range)


@router.get("/ui/metrics/device/{device_id}", include_in_schema=False)
def device_metrics_ui(device_id: int, request: Request, range: str = "24h"):
    return _device_series(request, device_id, range)


@router.get("/ui/metrics/port/{port_id}", include_in_schema=False)
def port_metrics_ui(port_id: int, request: Request, range: str = "24h"):
    return _port_series(request, port_id, range)


def _integration_series(request: Request, integration_id: int, key: str, rng: str) -> dict[str, list]:
    since, hourly = _window(rng)
    with lw(request).db.session() as s:
        rows = s.execute(select(IntegrationMetric.ts, IntegrationMetric.a, IntegrationMetric.b, IntegrationMetric.c)
                         .where(IntegrationMetric.integration_id == integration_id, IntegrationMetric.key == key,
                                IntegrationMetric.hourly.is_(hourly), IntegrationMetric.ts >= since)
                         .order_by(IntegrationMetric.ts)).all()
    return {"ts": [r[0].isoformat() + "Z" for r in rows], "a": [r[1] for r in rows], "b": [r[2] for r in rows],
            "c": [r[3] for r in rows]}


@router.get("/ui/metrics/integration/{integration_id}/{key:path}", include_in_schema=False)
def integration_metrics_ui(integration_id: int, key: str, request: Request, range: str = "24h"):
    return _integration_series(request, integration_id, key, range)


@router.get("/api/v1/integrations/{integration_id}/metrics", tags=["integrations"])
def integration_metrics_api(integration_id: int, key: str, request: Request, range: str = "24h", _: ApiKey = Depends(api_key)):
    """Series such as clients, wan:total, ssid:<name>, ap:<mac>, client:<mac>. a = down b/s, b = up b/s (clients: a = total)."""
    return _integration_series(request, integration_id, key, range)


@router.get("/api/v1/integrations/{integration_id}/data", tags=["integrations"])
def integration_data_api(integration_id: int, request: Request, _: ApiKey = Depends(api_key)):
    """Latest snapshot an integration reported beyond devices (UniFi: summary, wans, ssids, aps, clients)."""
    from .models import Integration
    with lw(request).db.session() as s:
        integ = s.get(Integration, integration_id)
        if integ is None:
            raise HTTPException(404, "No such integration")
        return integ.data or {}
