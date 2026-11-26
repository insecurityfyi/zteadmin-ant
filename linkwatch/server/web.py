"""HTML pages."""
from __future__ import annotations

import csv
import io
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from ..common.discovery import TargetError, expand_targets, guess_type
from .discovery import AUTO_ADD, DEVICE_TYPES, SCHEDULES, add_from_job, in_order, move_profile, ordered_profiles, run_rule, start_job
from ..integrations import REGISTRY, IntegrationError, build
from .app import flash
from .db import set_setting
from .models import (
    Alert,
    AlertRule,
    ApiKey,
    Device,
    DiscoveryJob,
    DiscoveryRule,
    EnrollToken,
    Integration,
    Poller,
    Port,
    SnmpProfile,
    Transport,
    utcnow,
)
from .ingest import site_by_name
from .notify import KINDS as TRANSPORT_KINDS
from .notify import send_one
from .alerts import AlertEvent
from .security import mask, new_secret, sha256

router = APIRouter(include_in_schema=False)
SNMP_AUTH = ["SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"]
SNMP_PRIV = ["AES", "AES192", "AES256", "DES"]


def st(request: Request):
    return request.app.state.lw


def render(request: Request, name: str, ctx: dict[str, Any] | None = None, status_code: int = 200) -> HTMLResponse:
    ctx = dict(ctx or {})
    ctx["flashes"] = request.session.pop("flash", [])
    ctx["nav"] = name.split(".")[0].split("_")[0]
    with st(request).db.session() as s:
        ctx["open_alerts"] = s.scalar(select(func.count(Alert.id)).where(Alert.state == "open")) or 0
        ctx["pollers_total"] = s.scalar(select(func.count(Poller.id)).where(Poller.revoked.is_(False))) or 0
        ctx["has_unifi"] = bool(s.scalar(select(func.count(Integration.id)).where(Integration.kind == "unifi")))
    ctx["pollers_connected"] = len(st(request).hub.conns)
    ctx["me"] = getattr(request.state, "user", None)
    return st(request).templates.TemplateResponse(request, name, ctx, status_code=status_code)


def back(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def push_poller(request: Request, poller_id: int | None) -> None:
    st(request).hub.push_config_soon(poller_id)


# ------------------------------------------------------------------ dashboard
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with st(request).db.session() as s:
        devices = s.scalars(select(Device).options(selectinload(Device.site)).where(Device.disabled.is_(False))).all()
        counts = {k: sum(1 for d in devices if d.status == k) for k in ("up", "down", "warn", "unknown", "off")}
        sites: dict[str, list[Device]] = {}
        for d in devices:
            sites.setdefault(d.site.name if d.site else "No site", []).append(d)
        alerts = s.scalars(select(Alert).options(selectinload(Alert.device)).where(Alert.state.in_(("open", "ack")))
                           .order_by(Alert.severity.asc(), Alert.opened_at.desc()).limit(8)).all()
        busiest = s.execute(select(Port, Device.hostname).join(Device).where(Port.util_pct.is_not(None))
                            .order_by(Port.util_pct.desc()).limit(6)).all()
        top_cpu = sorted([d for d in devices if d.cpu is not None and d.status != "off"], key=lambda d: -d.cpu)[:6]
        ports_total = s.scalar(select(func.count(Port.id))) or 0
        ports_up = s.scalar(select(func.count(Port.id)).where(Port.oper == "up")) or 0
        pollers = s.scalars(select(Poller).where(Poller.revoked.is_(False))).all()
        interval = st(request).hub.interval(s)
        top_port = busiest[0][0] if busiest else None
        top_port_host = busiest[0][1] if busiest else None
    worst_cycle = max((p.last_cycle_ms or 0 for p in pollers), default=0)
    down = [d for d in devices if d.status == "down"]
    if not devices:
        headline = "No devices yet"
    elif down:
        by_site: dict[str, int] = {}
        for d in down:
            by_site[d.site.name if d.site else "no site"] = by_site.get(d.site.name if d.site else "no site", 0) + 1
        where = ", ".join(f"{n} at {k}" for k, n in sorted(by_site.items(), key=lambda kv: -kv[1])[:2])
        headline = f"{len(down)} device{'s' if len(down) != 1 else ''} down ({where})"
    elif counts["warn"]:
        headline = f"All devices reachable, {counts['warn']} need attention"
    else:
        headline = "Everything is up"
    return render(request, "dashboard.html", {
        "devices": devices, "counts": counts, "sites": sorted(sites.items()), "alerts": alerts, "busiest": busiest,
        "top_cpu": top_cpu, "ports_total": ports_total, "ports_up": ports_up, "pollers": pollers, "interval": interval,
        "worst_cycle": worst_cycle, "headline": headline, "top_port": top_port, "top_port_host": top_port_host,
    })


# ------------------------------------------------------------------ devices
@router.get("/devices", response_class=HTMLResponse)
def devices(request: Request, q: str = "", status: str = "", type: str = "", site: str = ""):
    with st(request).db.session() as s:
        query = select(Device).options(selectinload(Device.site), selectinload(Device.poller)).order_by(Device.hostname)
        if q:
            like = f"%{q}%"
            query = query.where(or_(Device.hostname.ilike(like), Device.ip.ilike(like), Device.platform.ilike(like),
                                    Device.serial.ilike(like), Device.sys_name.ilike(like)))
        if status:
            query = query.where(Device.status == status)
        if type:
            query = query.where(Device.type == type)
        rows = s.scalars(query).all()
        if site:
            rows = [d for d in rows if (d.site.name if d.site else "") == site]
        types = sorted({t for t in s.scalars(select(Device.type).distinct()) if t})
        from .models import Site
        site_names = sorted(n for n in s.scalars(select(Site.name)))
        total = s.scalar(select(func.count(Device.id))) or 0
    return render(request, "devices.html", {"devices": rows, "q": q, "status": status, "type": type, "site": site,
                                            "types": types, "site_names": site_names, "total": total})


def _device_form_ctx(s, device: Device | None = None) -> dict[str, Any]:
    from .models import Site
    return {"device": device, "pollers": s.scalars(select(Poller).where(Poller.revoked.is_(False)).order_by(Poller.name)).all(),
            "profiles": s.scalars(select(SnmpProfile).order_by(SnmpProfile.name)).all(),
            "site_names": sorted(s.scalars(select(Site.name))), "types": DEVICE_TYPES}


@router.get("/devices/new", response_class=HTMLResponse)
def device_new(request: Request):
    with st(request).db.session() as s:
        ctx = _device_form_ctx(s)
    return render(request, "device_form.html", ctx)


def _apply_device_form(s, d: Device, form) -> str | None:
    hostname, ip = (form.get("hostname") or "").strip(), (form.get("ip") or "").strip()
    if not hostname or not ip:
        return "Hostname and IP address are required."
    d.hostname, d.ip = hostname[:255], ip[:255]
    d.type = form.get("type") or "Network"
    site = site_by_name(s, form.get("site"))
    d.site_id = site.id if site else None
    d.poller_id = int(form["poller_id"]) if form.get("poller_id") else None
    d.snmp_profile_id = int(form["snmp_profile_id"]) if form.get("snmp_profile_id") else None
    d.ping = form.get("ping") == "on"
    d.disabled = form.get("disabled") == "on"
    if d.source in ("snmp", "ping"):
        d.source = "snmp" if d.snmp_profile_id else "ping"
    if not d.poller_id:
        return "Pick the poller that can reach this device."
    if not d.snmp_profile_id and not d.ping:
        return "Turn on ping or choose SNMP credentials, otherwise there is nothing to poll."
    return None


@router.post("/devices/new")
async def device_create(request: Request):
    form = await request.form()
    with st(request).db.session() as s:
        d = Device(source="snmp", extra={})
        err = _apply_device_form(s, d, form)
        if err:
            ctx = _device_form_ctx(s)
            ctx.update(error=err, form=form)
            s.rollback()
            return render(request, "device_form.html", ctx, 400)
        s.add(d)
        s.flush()
        dev_id, poller_id = d.id, d.poller_id
    push_poller(request, poller_id)
    flash(request, "Device added. It is polled on the next cycle; use Poll now to check it right away.")
    return back(f"/devices/{dev_id}")


@router.get("/devices/import", response_class=HTMLResponse)
def device_import_page(request: Request):
    with st(request).db.session() as s:
        ctx = _device_form_ctx(s)
    return render(request, "device_import.html", ctx)


@router.post("/devices/import")
async def device_import(request: Request, file: UploadFile = File(...), poller_id: int = Form(...),
                        snmp_profile_id: str = Form("")):
    raw = (await file.read(5_000_000)).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    added = skipped = 0
    with st(request).db.session() as s:
        profiles = {p.name.lower(): p.id for p in s.scalars(select(SnmpProfile))}
        existing = set(s.scalars(select(Device.ip)))
        for row in reader:
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            ip, host = row.get("ip"), row.get("hostname") or row.get("ip")
            if not ip or ip in existing:
                skipped += 1
                continue
            prof = profiles.get(row.get("snmp_profile", "").lower()) or (int(snmp_profile_id) if snmp_profile_id else None)
            site = site_by_name(s, row.get("site"))
            s.add(Device(hostname=host[:255], ip=ip[:255], type=row.get("type") or "Network", site_id=site.id if site else None,
                         poller_id=poller_id, snmp_profile_id=prof, ping=True, source="snmp" if prof else "ping", extra={}))
            existing.add(ip)
            added += 1
    push_poller(request, poller_id)
    flash(request, f"Imported {added} devices" + (f", skipped {skipped} (missing IP or already present)" if skipped else "") + ".")
    return back("/devices")


# ------------------------------------------------------------------ discovery
def _discovery_ctx(s) -> dict[str, Any]:
    ctx = _device_form_ctx(s)
    ctx["profiles"] = ordered_profiles(s)
    ctx |= {"schedules": SCHEDULES, "auto_add_modes": AUTO_ADD}
    return ctx


@router.get("/discovery", response_class=HTMLResponse)
def discovery_page(request: Request):
    with st(request).db.session() as s:
        ctx = _discovery_ctx(s)
        ctx["jobs"] = s.scalars(select(DiscoveryJob).options(selectinload(DiscoveryJob.poller), selectinload(DiscoveryJob.rule))
                                .order_by(DiscoveryJob.id.desc()).limit(15)).all()
        ctx["rules"] = s.scalars(select(DiscoveryRule).options(selectinload(DiscoveryRule.poller)).order_by(DiscoveryRule.name)).all()
        names = {p.id: p.name for p in ctx["profiles"]}
    ctx["profile_names"] = names
    ctx["connected"] = set(st(request).hub.conns)
    return render(request, "discovery.html", ctx)


def _int(v, default: int = 0) -> int:
    try:
        return int(v or default)
    except (TypeError, ValueError):
        return default


@router.post("/discovery")
async def discovery_start(request: Request):
    form = await request.form()
    targets = str(form.get("targets") or "").strip()
    poller_id = _int(form.get("poller_id"))
    profile_ids = [int(v) for v in form.getlist("profile_id") if str(v).isdigit()]
    with st(request).db.session() as s:
        if not s.get(Poller, poller_id):
            flash(request, "Choose a poller.", "warn")
            return back("/discovery")
        try:
            job = start_job(st(request), s, poller_id, targets, in_order(s, profile_ids))
        except TargetError as exc:
            flash(request, str(exc), "warn")
            return back("/discovery")
        if job.status == "failed":
            flash(request, "That poller is not connected right now, so the scan could not start.", "warn")
        jid = job.id
    return back(f"/discovery/{jid}")


def _read_rule(form, rule: DiscoveryRule) -> str | None:
    rule.name = str(form.get("name") or "").strip()[:120] or "Saved scan"
    rule.targets = str(form.get("targets") or "").strip()[:5000]
    try:
        expand_targets(rule.targets)
    except TargetError as exc:
        return str(exc)
    rule.poller_id = _int(form.get("poller_id")) or None
    rule.profile_ids = [int(v) for v in form.getlist("profile_id") if str(v).isdigit()]
    hours = _int(form.get("interval_hours"))
    rule.interval_hours = hours if hours in SCHEDULES else 0
    mode = str(form.get("auto_add") or "off")
    rule.auto_add = mode if mode in AUTO_ADD else "off"
    rule.site_name = str(form.get("site_name") or "").strip()[:120] or None
    rule.enabled = form.get("enabled") == "on"
    return None if rule.poller_id else "Choose a poller."


@router.post("/discovery/rules")
async def discovery_rule_create(request: Request):
    form = await request.form()
    rule = DiscoveryRule(profile_ids=[])
    if err := _read_rule(form, rule):
        flash(request, err, "warn")
        return back("/discovery#rules")
    with st(request).db.session() as s:
        s.add(rule)
    flash(request, f"Saved scan '{rule.name}'." + (" It runs on its schedule while the poller is connected." if rule.interval_hours else ""))
    return back("/discovery#rules")


@router.get("/discovery/rules/{rid}", response_class=HTMLResponse)
def discovery_rule_page(request: Request, rid: int):
    with st(request).db.session() as s:
        rule = s.get(DiscoveryRule, rid)
        if rule is None:
            raise HTTPException(404)
        ctx = _discovery_ctx(s)
        ctx["rule"] = rule
        ctx["jobs"] = s.scalars(select(DiscoveryJob).where(DiscoveryJob.rule_id == rid).order_by(DiscoveryJob.id.desc()).limit(10)).all()
    return render(request, "discovery_rule.html", ctx)


@router.post("/discovery/rules/{rid}")
async def discovery_rule_update(request: Request, rid: int):
    form = await request.form()
    with st(request).db.session() as s:
        rule = s.get(DiscoveryRule, rid)
        if rule is None:
            raise HTTPException(404)
        if err := _read_rule(form, rule):
            s.rollback()
            flash(request, err, "warn")
            return back(f"/discovery/rules/{rid}")
        name = rule.name
    flash(request, f"Saved '{name}'.")
    return back("/discovery#rules")


@router.post("/discovery/rules/{rid}/run")
def discovery_rule_run(request: Request, rid: int):
    with st(request).db.session() as s:
        rule = s.get(DiscoveryRule, rid)
        if rule is None:
            raise HTTPException(404)
        job = run_rule(st(request), s, rule)
        if job.status == "failed":
            flash(request, "That scan's poller is not connected right now.", "warn")
        jid = job.id
    return back(f"/discovery/{jid}")


@router.post("/discovery/rules/{rid}/delete")
def discovery_rule_delete(request: Request, rid: int):
    with st(request).db.session() as s:
        rule = s.get(DiscoveryRule, rid)
        if rule is not None:
            s.delete(rule)
    flash(request, "Deleted the saved scan. Devices it added stay.")
    return back("/discovery#rules")


@router.post("/discovery/order")
async def discovery_order(request: Request):
    form = await request.form()
    with st(request).db.session() as s:
        move_profile(s, _int(form.get("profile_id")), str(form.get("dir") or "up"))
    return back("/discovery#order")


@router.get("/discovery/{jid}", response_class=HTMLResponse)
def discovery_job(request: Request, jid: int):
    with st(request).db.session() as s:
        job = s.get(DiscoveryJob, jid, options=[selectinload(DiscoveryJob.poller), selectinload(DiscoveryJob.rule)])
        if job is None:
            raise HTTPException(404)
        ips = [r["ip"] for r in job.results or []]
        known = {ip: did for ip, did in s.execute(select(Device.ip, Device.id).where(Device.ip.in_(ips)))} if ips else {}
        names = {p.id: p.name for p in s.scalars(select(SnmpProfile))}
        rows = [r | {"known": known.get(r["ip"]), "type": guess_type(r.get("sys_descr"), r.get("sys_object_id")),
                     "profile": names.get(r.get("profile_id"))} for r in job.results or []]
        ctx = _device_form_ctx(s)
    ctx |= {"job": job, "rows": rows, "new_count": sum(1 for r in rows if not r["known"])}
    return render(request, "discovery_job.html", ctx)


@router.post("/discovery/{jid}/add")
async def discovery_add(request: Request, jid: int):
    form = await request.form()
    chosen = set(form.getlist("ip"))
    with st(request).db.session() as s:
        job = s.get(DiscoveryJob, jid)
        if job is None:
            raise HTTPException(404)
        types = {ip: str(form.get(f"type_{ip}") or "") for ip in chosen}
        added = add_from_job(s, job, chosen, str(form.get("site") or "").strip() or None, types)
        poller_id = job.poller_id
    push_poller(request, poller_id)
    flash(request, f"Added {added} device{'s' if added != 1 else ''}. They are polled on the next cycle." if added else "Nothing new was selected.")
    return back("/devices" if added else f"/discovery/{jid}")


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: int):
    with st(request).db.session() as s:
        d = s.get(Device, device_id, options=[selectinload(Device.site), selectinload(Device.poller),
                                              selectinload(Device.snmp_profile), selectinload(Device.integration),
                                              selectinload(Device.ports)])
        if d is None:
            raise HTTPException(404, "No such device")
        ports = sorted(d.ports, key=lambda p: (-(max(p.in_bps or 0, p.out_bps or 0)), p.ifindex))
        alerts = s.scalars(select(Alert).where(Alert.device_id == d.id).order_by(Alert.opened_at.desc()).limit(10)).all()
    return render(request, "device.html", {"d": d, "ports": ports, "alerts": alerts,
                                           "connected": d.poller_id in st(request).hub.conns})


@router.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def device_edit(request: Request, device_id: int):
    with st(request).db.session() as s:
        d = s.get(Device, device_id, options=[selectinload(Device.site), selectinload(Device.integration)])
        if d is None:
            raise HTTPException(404)
        ctx = _device_form_ctx(s, d)
    return render(request, "device_form.html", ctx)


@router.post("/devices/{device_id}/edit")
async def device_update(request: Request, device_id: int):
    form = await request.form()
    with st(request).db.session() as s:
        d = s.get(Device, device_id)
        if d is None:
            raise HTTPException(404)
        old_poller = d.poller_id
        if d.source not in ("snmp", "ping"):
            d.disabled = form.get("disabled") == "on"
            site = site_by_name(s, form.get("site"))
            d.site_id = site.id if site else d.site_id
            new_poller = None
        else:
            err = _apply_device_form(s, d, form)
            if err:
                s.rollback()
                ctx = _device_form_ctx(s, s.get(Device, device_id))
                ctx.update(error=err, form=form)
                return render(request, "device_form.html", ctx, 400)
            new_poller = d.poller_id
    push_poller(request, old_poller)
    if new_poller != old_poller:
        push_poller(request, new_poller)
    flash(request, "Saved.")
    return back(f"/devices/{device_id}")


@router.post("/devices/{device_id}/delete")
def device_delete(request: Request, device_id: int):
    with st(request).db.session() as s:
        d = s.get(Device, device_id)
        if d is None:
            raise HTTPException(404)
        poller_id, name = d.poller_id, d.hostname
        s.delete(d)
    push_poller(request, poller_id)
    flash(request, f"Deleted {name} and its history.")
    return back("/devices")


@router.post("/devices/{device_id}/poll")
def device_poll(request: Request, device_id: int):
    with st(request).db.session() as s:
        d = s.get(Device, device_id)
        if d is None:
            raise HTTPException(404)
        sent = st(request).hub.send_soon(d.poller_id, {"type": "poll_now", "device_id": d.id})
    flash(request, "Asked the poller to poll it now. Refresh in a few seconds." if sent
          else "Its poller is not connected right now.", "ok" if sent else "warn")
    return back(f"/devices/{device_id}")


@router.post("/ports/{port_id}/alert")
def port_alert_toggle(request: Request, port_id: int):
    with st(request).db.session() as s:
        p = s.get(Port, port_id)
        if p is None:
            raise HTTPException(404)
        p.alert_on_down = not p.alert_on_down
        dev_id = p.device_id
    return back(f"/devices/{dev_id}#ports")


# ------------------------------------------------------------------ alerts
@router.get("/alerts", response_class=HTMLResponse)
def alerts(request: Request, state: str = "open"):
    with st(request).db.session() as s:
        q = select(Alert).options(selectinload(Alert.device)).order_by(Alert.opened_at.desc())
        if state == "resolved":
            q = q.where(Alert.state == "resolved", Alert.resolved_at >= utcnow() - timedelta(days=7)).limit(300)
        else:
            q = q.where(Alert.state == state if state == "ack" else Alert.state == "open")
        rows = s.scalars(q).all()
        counts = {k: s.scalar(select(func.count(Alert.id)).where(Alert.state == k)) or 0 for k in ("open", "ack")}
        counts["resolved"] = s.scalar(select(func.count(Alert.id)).where(
            Alert.state == "resolved", Alert.resolved_at >= utcnow() - timedelta(days=7))) or 0
        rules = s.scalars(select(AlertRule).order_by(AlertRule.id)).all()
        daily = s.execute(select(func.date(Alert.opened_at), Alert.severity, func.count(Alert.id))
                          .where(Alert.opened_at >= utcnow() - timedelta(days=14))
                          .group_by(func.date(Alert.opened_at), Alert.severity)).all()
    days = []
    today = utcnow().date()
    for i in range(13, -1, -1):
        day = today - timedelta(days=i)
        days.append({"label": day.strftime("%d %b"),
                     "crit": sum(n for d0, sev, n in daily if str(d0) == str(day) and sev == "crit"),
                     "warn": sum(n for d0, sev, n in daily if str(d0) == str(day) and sev != "crit")})
    return render(request, "alerts.html", {"alerts": rows, "state": state, "counts": counts, "rules": rules, "days": days})


@router.post("/alerts/{alert_id}/ack")
def alert_ack(request: Request, alert_id: int):
    with st(request).db.session() as s:
        a = s.get(Alert, alert_id)
        if a and a.state == "open":
            a.state, a.acked_at = "ack", utcnow()
    return back("/alerts")


@router.post("/alerts/rules/{rule_id}")
async def rule_update(request: Request, rule_id: int):
    form = await request.form()
    with st(request).db.session() as s:
        r = s.get(AlertRule, rule_id)
        if r is None:
            raise HTTPException(404)
        r.enabled = form.get("enabled") == "on"
        if form.get("severity") in ("crit", "warn", "info"):
            r.severity = form["severity"]
        try:
            if r.threshold is not None and form.get("threshold"):
                r.threshold = float(form["threshold"])
            if form.get("polls"):
                r.polls = max(1, min(20, int(form["polls"])))
        except ValueError:
            flash(request, "Threshold and polls must be numbers.", "warn")
            return back("/alerts#rules")
    flash(request, f"Rule '{r.name}' saved.")
    return back("/alerts#rules")


# ------------------------------------------------------------------ pollers
@router.get("/pollers", response_class=HTMLResponse)
def pollers(request: Request):
    with st(request).db.session() as s:
        rows = s.scalars(select(Poller).order_by(Poller.name)).all()
        counts = dict(s.execute(select(Device.poller_id, func.count(Device.id)).group_by(Device.poller_id)).all())
        integ_counts = dict(s.execute(select(Integration.poller_id, func.count(Integration.id)).group_by(Integration.poller_id)).all())
        interval = st(request).hub.interval(s)
    new_token = request.session.pop("new_token", None)
    return render(request, "pollers.html", {"pollers": rows, "counts": counts, "integ_counts": integ_counts,
                                            "connected": set(st(request).hub.conns), "interval": interval,
                                            "new_token": new_token})


@router.post("/pollers/token")
def poller_token(request: Request):
    token = new_secret("enr", 24)
    with st(request).db.session() as s:
        s.add(EnrollToken(token_hash=sha256(token), hint=token[-4:], expires_at=utcnow() + timedelta(hours=24)))
    request.session["new_token"] = token
    return back("/pollers#install")


@router.post("/pollers/{poller_id}/revoke")
async def poller_revoke(request: Request, poller_id: int):
    with st(request).db.session() as s:
        p = s.get(Poller, poller_id)
        if p is None:
            raise HTTPException(404)
        p.revoked = True
        name = p.name
    ws = st(request).hub.conns.get(poller_id)
    if ws is not None:
        await ws.close(code=4003)
    flash(request, f"Revoked {name}. It can no longer connect; its devices stay until you move or delete them.")
    return back("/pollers")


@router.post("/pollers/{poller_id}/delete")
def poller_delete(request: Request, poller_id: int):
    with st(request).db.session() as s:
        p = s.get(Poller, poller_id)
        if p is None or not p.revoked:
            flash(request, "Revoke the poller before deleting it.", "warn")
            return back("/pollers")
        s.delete(p)
    flash(request, "Poller deleted.")
    return back("/pollers")


# ------------------------------------------------------------------ integrations
@router.get("/integrations", response_class=HTMLResponse)
def integrations(request: Request):
    with st(request).db.session() as s:
        rows = s.scalars(select(Integration).options(selectinload(Integration.poller)).order_by(Integration.name)).all()
    return render(request, "integrations.html", {"integrations": rows, "registry": REGISTRY})


def _integration_ctx(s, kind: str, integ: Integration | None = None, values: dict | None = None) -> dict[str, Any]:
    cls = REGISTRY.get(kind)
    if cls is None:
        raise HTTPException(404, "Unknown integration type")
    return {"cls": cls, "kind": kind, "integ": integ, "values": values or {},
            "pollers": s.scalars(select(Poller).where(Poller.revoked.is_(False)).order_by(Poller.name)).all()}


@router.get("/integrations/new", response_class=HTMLResponse)
def integration_new(request: Request, kind: str):
    with st(request).db.session() as s:
        ctx = _integration_ctx(s, kind)
    ctx["values"] = {f.name: f.default for f in ctx["cls"].fields}
    return render(request, "integration_form.html", ctx)


def _read_integration_form(cls, form, existing: dict | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in cls.fields:
        if f.kind == "bool":
            out[f.name] = form.get(f.name) == "on"
        elif f.kind == "password":
            v = (form.get(f.name) or "").strip()
            out[f.name] = v or (existing or {}).get(f.name, "")
        else:
            out[f.name] = (form.get(f.name) or "").strip()
    return out


@router.post("/integrations/new")
async def integration_create(request: Request):
    form = await request.form()
    kind = form.get("kind", "")
    with st(request).db.session() as s:
        ctx = _integration_ctx(s, kind)
        cls = ctx["cls"]
        cfg = _read_integration_form(cls, form, None)
        err = _validate_integration(cls, cfg, form, st(request).config.admin_password, getattr(request.state, "user", None))
        if err:
            ctx.update(values=cfg, error=err, name=form.get("name"))
            return render(request, "integration_form.html", ctx, 400)
        integ = Integration(kind=kind, name=(form.get("name") or cls.label).strip()[:120], config_enc=st(request).vault.seal(cfg),
                            poller_id=int(form["poller_id"]) if cls.runs_on == "poller" and form.get("poller_id") else None)
        s.add(integ)
        s.flush()
        iid, pid = integ.id, integ.poller_id
    push_poller(request, pid)
    flash(request, "Integration saved. Use Test to check the credentials." + (" It syncs within a minute." if cls.runs_on == "server" else ""))
    return back(f"/integrations/{iid}")


def _validate_integration(cls, cfg: dict, form, admin_password: str | None = None, user=None) -> str | None:
    from .security import verify_password
    for f in cls.fields:
        typed = (form.get(f.name) or "").strip()
        if f.kind == "password" and typed and not typed.startswith("••") and (
                typed == admin_password or (user is not None and verify_password(typed, user.password_hash))):
            return (f"{f.label} is your Linkwatch sign-in password, most likely filled in by the browser. "
                    "Clear the field (blank keeps the saved value) or paste the real one.")
    missing = [f.label for f in cls.fields if f.required and f.kind != "bool" and not str(cfg.get(f.name, "")).strip()]
    if missing:
        return "Fill in: " + ", ".join(missing)
    if cls.runs_on == "poller" and not form.get("poller_id"):
        return "Choose the poller that can reach this system. On-prem APIs are called from inside your network."
    return None


@router.get("/integrations/{iid}", response_class=HTMLResponse)
def integration_edit(request: Request, iid: int):
    with st(request).db.session() as s:
        integ = s.get(Integration, iid, options=[selectinload(Integration.poller)])
        if integ is None:
            raise HTTPException(404)
        cfg = st(request).vault.open(integ.config_enc)
        ctx = _integration_ctx(s, integ.kind, integ)
        ctx["values"] = {f.name: (mask(cfg.get(f.name)) if f.kind == "password" else cfg.get(f.name, f.default)) for f in ctx["cls"].fields}
        ctx["objects"] = s.scalars(select(Device).where(Device.integration_id == iid).order_by(Device.hostname).limit(500)).all()
    ctx["test_result"] = request.session.pop("test_result", None)
    return render(request, "integration_form.html", ctx)


@router.post("/integrations/{iid}")
async def integration_update(request: Request, iid: int):
    form = await request.form()
    with st(request).db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None:
            raise HTTPException(404)
        cls = REGISTRY[integ.kind]
        old = st(request).vault.open(integ.config_enc)
        cfg = _read_integration_form(cls, form, old)
        for f in cls.fields:   # a masked value posted back means "unchanged"
            if f.kind == "password" and str(form.get(f.name, "")).startswith("••"):
                cfg[f.name] = old.get(f.name, "")
        err = _validate_integration(cls, cfg, form, st(request).config.admin_password, getattr(request.state, "user", None))
        if err:
            flash(request, err, "warn")
            return back(f"/integrations/{iid}")
        old_poller = integ.poller_id
        integ.name = (form.get("name") or integ.name).strip()[:120]
        integ.config_enc = st(request).vault.seal(cfg)
        integ.enabled = form.get("enabled") == "on"
        integ.poller_id = int(form["poller_id"]) if cls.runs_on == "poller" and form.get("poller_id") else None
        new_poller = integ.poller_id
    push_poller(request, old_poller)
    if new_poller != old_poller:
        push_poller(request, new_poller)
    flash(request, "Saved.")
    return back(f"/integrations/{iid}")


@router.post("/integrations/{iid}/test")
def integration_test(request: Request, iid: int):
    with st(request).db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None:
            raise HTTPException(404)
        kind, cfg = integ.kind, st(request).vault.open(integ.config_enc)
    if REGISTRY[kind].runs_on == "poller":
        request.session["test_result"] = ["warn", "This system is reached through a poller, so it is tested on the poller's next "
                                          "cycle. Check the status above after the next sync, or press Sync now."]
        return back(f"/integrations/{iid}")
    try:
        client = build(kind, cfg)
        try:
            msg = client.test()
            errs = getattr(client, "errors", [])
        finally:
            client.close()
        request.session["test_result"] = ["ok" if not errs else "warn", msg + ("" if not errs else " Problems: " + "; ".join(errs))]
    except IntegrationError as exc:
        request.session["test_result"] = ["bad", str(exc)]
    return back(f"/integrations/{iid}")


@router.post("/integrations/{iid}/sync")
async def integration_sync(request: Request, iid: int):
    import asyncio
    from .jobs import run_server_integration
    with st(request).db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None:
            raise HTTPException(404)
        kind, pid = integ.kind, integ.poller_id
    if REGISTRY[kind].runs_on == "server":
        await asyncio.to_thread(run_server_integration, st(request), iid)
        flash(request, "Synced.")
    else:
        await st(request).hub.push_config(pid) if pid else None
        flash(request, "Sent the latest settings to the poller; it runs on the next cycle.")
    return back(f"/integrations/{iid}")


@router.post("/integrations/{iid}/delete")
def integration_delete(request: Request, iid: int):
    with st(request).db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None:
            raise HTTPException(404)
        pid = integ.poller_id
        for d in s.scalars(select(Device).where(Device.integration_id == iid)):
            if d.source == integ.kind:
                s.delete(d)
            else:
                d.integration_id, d.external_id = None, None
                d.extra = {k: v for k, v in (d.extra or {}).items() if k != "api"}
        s.delete(integ)
    push_poller(request, pid)
    flash(request, "Integration and the objects it created were deleted.")
    return back("/integrations")


# ------------------------------------------------------------------ settings
@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    with st(request).db.session() as s:
        profiles = s.scalars(select(SnmpProfile).order_by(SnmpProfile.name)).all()
        usage = dict(s.execute(select(Device.snmp_profile_id, func.count(Device.id)).group_by(Device.snmp_profile_id)).all())
        transports = s.scalars(select(Transport).order_by(Transport.name)).all()
        keys = s.scalars(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
        interval = st(request).hub.interval(s)
    return render(request, "settings.html", {
        "profiles": profiles, "usage": usage, "transports": transports, "keys": keys, "interval": interval,
        "transport_kinds": TRANSPORT_KINDS, "auth_protocols": SNMP_AUTH, "priv_protocols": SNMP_PRIV,
        "new_key": request.session.pop("new_key", None)})


@router.post("/settings/interval")
def settings_interval(request: Request, interval: int = Form(...)):
    interval = max(60, min(3600, interval))
    with st(request).db.session() as s:
        set_setting(s, "poll_interval", str(interval))
        pollers = s.scalars(select(Poller.id)).all()
    for pid in pollers:
        push_poller(request, pid)
    flash(request, f"Polling every {interval} seconds.")
    return back("/settings")


@router.post("/settings/snmp")
async def snmp_profile_save(request: Request):
    form = await request.form()
    name = (form.get("name") or "").strip()
    version = form.get("version") or "2c"
    if not name:
        flash(request, "Give the credential set a name.", "warn")
        return back("/settings#snmp")
    if version == "2c":
        cfg = {"version": "2c", "community": form.get("community") or ""}
        if not cfg["community"]:
            flash(request, "Enter the community string.", "warn")
            return back("/settings#snmp")
    else:
        cfg = {"version": "3", "username": form.get("username") or "", "level": form.get("level") or "authPriv",
               "auth_protocol": form.get("auth_protocol") or "SHA", "auth_key": form.get("auth_key") or "",
               "priv_protocol": form.get("priv_protocol") or "AES", "priv_key": form.get("priv_key") or ""}
        if not cfg["username"] or (cfg["level"] != "noAuthNoPriv" and len(cfg["auth_key"]) < 8) or \
                (cfg["level"] == "authPriv" and len(cfg["priv_key"]) < 8):
            flash(request, "SNMPv3 needs a username, and passphrases of at least 8 characters.", "warn")
            return back("/settings#snmp")
    if form.get("port"):
        cfg["port"] = int(form["port"])
    with st(request).db.session() as s:
        if s.scalar(select(SnmpProfile).where(SnmpProfile.name == name)):
            flash(request, "A credential set with that name already exists.", "warn")
            return back("/settings#snmp")
        s.add(SnmpProfile(name=name, version=cfg["version"], config_enc=st(request).vault.seal(cfg)))
    flash(request, f"Saved SNMP credentials '{name}'.")
    return back("/settings#snmp")


@router.post("/settings/snmp/{pid}/delete")
def snmp_profile_delete(request: Request, pid: int):
    with st(request).db.session() as s:
        p = s.get(SnmpProfile, pid)
        if p is None:
            raise HTTPException(404)
        if s.scalar(select(func.count(Device.id)).where(Device.snmp_profile_id == pid)):
            flash(request, "Devices still use these credentials. Move them to another set first.", "warn")
            return back("/settings#snmp")
        s.delete(p)
    flash(request, "Deleted.")
    return back("/settings#snmp")


@router.post("/settings/transports")
async def transport_save(request: Request):
    form = await request.form()
    kind = form.get("kind", "")
    if kind not in TRANSPORT_KINDS:
        raise HTTPException(400)
    if kind == "email":
        cfg = {k: (form.get(k) or "").strip() for k in ("host", "port", "username", "password", "sender", "recipients")}
        cfg["starttls"] = form.get("starttls") == "on"
        ok = cfg["host"] and cfg["sender"] and cfg["recipients"]
    else:
        cfg = {"url": (form.get("url") or "").strip()}
        ok = cfg["url"].startswith("https://")
    if not ok:
        flash(request, "Fill in the server, sender and recipients." if kind == "email" else "The webhook URL must start with https://", "warn")
        return back("/settings#transports")
    with st(request).db.session() as s:
        s.add(Transport(kind=kind, name=(form.get("name") or TRANSPORT_KINDS[kind][0]).strip()[:120],
                        config_enc=st(request).vault.seal(cfg), min_severity=form.get("min_severity") or "warn"))
    flash(request, "Notification target added. Use Send test to check it.")
    return back("/settings#transports")


@router.post("/settings/transports/{tid}/test")
def transport_test(request: Request, tid: int):
    with st(request).db.session() as s:
        t = s.get(Transport, tid)
        if t is None:
            raise HTTPException(404)
        try:
            send_one(t.kind, st(request).vault.open(t.config_enc),
                     AlertEvent("opened", 0, "info", "Linkwatch test notification", "If you can read this, alerts will reach you here.", None),
                     st(request).config.public_url)
            t.last_result = "Test sent"
            flash(request, f"Test sent to {t.name}.")
        except Exception as exc:
            t.last_result = f"Failed: {exc.__class__.__name__}: {exc}"[:255]
            flash(request, f"Could not send: {exc}", "bad")
    return back("/settings#transports")


@router.post("/settings/transports/{tid}/delete")
def transport_delete(request: Request, tid: int):
    with st(request).db.session() as s:
        t = s.get(Transport, tid)
        if t:
            s.delete(t)
    return back("/settings#transports")


@router.post("/settings/apikeys")
def apikey_create(request: Request, name: str = Form(...), scope: str = Form("ro")):
    key = new_secret("lw", 24)
    with st(request).db.session() as s:
        s.add(ApiKey(name=name.strip()[:120] or "API key", prefix=key[:7], key_hash=sha256(key), scope="rw" if scope == "rw" else "ro"))
    request.session["new_key"] = key
    return back("/settings#api")


@router.post("/settings/apikeys/{kid}/delete")
def apikey_delete(request: Request, kid: int):
    with st(request).db.session() as s:
        k = s.get(ApiKey, kid)
        if k:
            s.delete(k)
    flash(request, "API key revoked.")
    return back("/settings#api")
