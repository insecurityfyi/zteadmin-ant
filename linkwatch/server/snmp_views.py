"""Pages for adding SNMP polling to devices an API integration found (one device or many at once)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from . import snmp_attach as sa
from .app import flash
from .models import Device, Poller, SnmpProfile
from .web import _who, back, push_poller, render, st

router = APIRouter(include_in_schema=False)
MAX_DEVICES = 200


def _ids(raw) -> list[int]:
    out: list[int] = []
    for part in raw if isinstance(raw, list) else str(raw or "").split(","):
        part = str(part).strip()
        if part.isdigit() and int(part) not in out:
            out.append(int(part))
    return out[:MAX_DEVICES]


def _ctx(s, ids: list[int]) -> dict[str, Any]:
    devs = s.scalars(select(Device).options(selectinload(Device.integration), selectinload(Device.site))
                     .where(Device.id.in_(ids or [0])).order_by(Device.hostname)).all()
    rows, skipped = [], []
    for d in devs:
        if not sa.api_only(d):
            skipped.append(d)
            continue
        rows.append({"d": d, "twin": sa.twin_of(s, d)})
    pollers = s.scalars(select(Poller).where(Poller.revoked.is_(False)).order_by(Poller.name)).all()
    integ_pollers = [r["d"].integration.poller_id for r in rows if r["d"].integration and r["d"].integration.poller_id]
    default_poller = max(set(integ_pollers), key=integ_pollers.count) if integ_pollers else (pollers[0].id if pollers else None)
    return {"rows": rows, "skipped": skipped, "pollers": pollers, "default_poller": default_poller,
            "profiles": s.scalars(select(SnmpProfile).order_by(SnmpProfile.name)).all(),
            "auth_protocols": sa.SNMP_AUTH, "priv_protocols": sa.SNMP_PRIV, "ids": ",".join(str(r["d"].id) for r in rows),
            "section": "devices"}


@router.get("/devices/add-snmp", response_class=HTMLResponse)
def add_snmp_page(request: Request, ids: str = ""):
    with st(request).db.session() as s:
        ctx = _ctx(s, _ids(ids))
        if not ctx["rows"] and len(ctx["skipped"]) == 1:
            return back(f"/devices/{ctx['skipped'][0].id}")
    return render(request, "device_snmp.html", ctx)


def _profile_from_form(request: Request, s, form, fallback_name: str) -> tuple[SnmpProfile | None, str | None]:
    """The credential set chosen, or a new one made from the form's v2c/v3 fields."""
    choice = str(form.get("profile") or "")
    if choice.isdigit():
        p = s.get(SnmpProfile, int(choice))
        return (p, None) if p else (None, "Those SNMP credentials no longer exist.")
    cfg, err = sa.read_snmp_creds(form)
    if err:
        return None, err
    name = (str(form.get("name") or "").strip() or fallback_name)[:120]
    if s.scalar(select(SnmpProfile.id).where(SnmpProfile.name == name)):
        return None, f"A credential set called “{name}” already exists. Choose it from the list or pick another name."
    p = SnmpProfile(name=name, version=cfg["version"], config_enc=st(request).vault.seal(cfg))
    s.add(p)
    s.flush()
    return p, None


@router.post("/devices/add-snmp")
async def add_snmp(request: Request):
    form = await request.form()
    ids = _ids(str(form.get("ids") or ""))
    who = _who(request)
    pollers_touched: set[int] = set()
    with st(request).db.session() as s:
        ctx = _ctx(s, ids)

        def fail(msg: str):
            s.rollback()
            ctx2 = _ctx(s, ids)
            ctx2.update(error=msg, form=form)
            return render(request, "device_snmp.html", ctx2, 400)

        rows = ctx["rows"]
        if not rows:
            flash(request, "None of those devices came from an integration without SNMP, so there was nothing to add.", "warn")
            return back("/devices")
        try:
            poller_id = int(form.get("poller_id") or 0)
        except ValueError:
            poller_id = 0
        poller = s.get(Poller, poller_id) if poller_id else None
        if poller is None or poller.revoked:
            return fail("Pick the poller that can reach these devices over SNMP (UDP 161).")
        # what to do with each device: merge into the SNMP device for the same box, or start polling it
        plan = []
        for r in rows:
            d = r["d"]
            ip = str(form.get(f"ip_{d.id}") or "").strip()
            action = str(form.get(f"action_{d.id}") or ("merge" if r["twin"] else "attach"))
            if action == "skip":
                continue
            if action == "merge":
                twin = sa.twin_of(s, d, ip or None)
                if twin is None:
                    return fail(f"No SNMP device matches {d.hostname} any more. Choose “Poll it over SNMP” instead.")
                plan.append((d, "merge", twin, ip))
                continue
            if not ip:
                return fail(f"Enter the address {d.hostname} answers SNMP on.")
            clash = sa.ip_in_use(s, ip, d.id)
            if clash is not None:
                return fail(f"{clash.hostname} already polls {ip}. Merge {d.hostname} into it instead, so there is one device.")
            plan.append((d, "attach", None, ip))
        if not plan:
            flash(request, "Every device was set to skip, so nothing changed.", "warn")
            return back("/devices")
        profile = None
        if any(p[1] == "attach" for p in plan):
            profile, err = _profile_from_form(request, s, form, f"{plan[0][0].hostname} SNMP" if len(plan) == 1 else "API devices SNMP")
            if err:
                return fail(err)
        ping = form.get("ping") == "on"
        merged = attached = 0
        last_id = None
        for d, action, twin, ip in plan:
            if action == "merge":
                last_id = sa.merge_with(s, d, twin, who).id
                pollers_touched.add(twin.poller_id or 0)
                merged += 1
            else:
                sa.attach(s, d, poller_id=poller.id, profile=profile, ip=ip, ping=ping, who=who)
                last_id = d.id
                attached += 1
        pollers_touched.add(poller.id)
    for pid in pollers_touched:
        push_poller(request, pid or None)
    if attached == 1 and merged == 0:      # one device: poll it straight away so the page fills in
        st(request).hub.send_soon(poller.id, {"type": "poll_now", "device_id": last_id})
    parts = []
    if attached:
        parts.append(f"{poller.name} now polls {attached} device{'s' if attached != 1 else ''} over SNMP")
    if merged:
        parts.append(f"merged {merged} into the SNMP device{'s' if merged != 1 else ''} already watching the same box")
    msg = " and ".join(parts) + ". API data keeps showing on the same device."
    flash(request, msg[0].upper() + msg[1:])
    return back(f"/devices/{last_id}" if attached + merged == 1 else "/devices")


@router.post("/ui/devices/snmp-test")
async def snmp_test(request: Request):
    """Try SNMP credentials against an address through a poller before they are saved on any device."""
    body = await request.json()
    try:
        poller_id = int(body.get("poller_id") or 0)
    except (TypeError, ValueError):
        poller_id = 0
    ip = str(body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Enter the address to test."}, status_code=400)
    with st(request).db.session() as s:
        poller = s.get(Poller, poller_id) if poller_id else None
        if poller is None or poller.revoked:
            return JSONResponse({"error": "Pick a poller."}, status_code=400)
        choice = str(body.get("profile") or "")
        if choice.isdigit():
            p = s.get(SnmpProfile, int(choice))
            if p is None:
                return JSONResponse({"error": "Those SNMP credentials no longer exist."}, status_code=400)
            creds = st(request).vault.open(p.config_enc)
        else:
            creds, err = sa.read_snmp_creds(body)
            if err:
                return JSONResponse({"error": err}, status_code=400)
        name, feats = poller.name, poller.features
    if feats is not None and "snmp_probe" not in feats:
        return {"error": f"Poller {name} is too old to test credentials before they are saved. Update it, or save "
                         "and use Poll now on the device."}
    res = await st(request).hub.snmp_test(poller_id, {"ip": ip, "snmp": creds, "mode": "system"})
    if res.get("error"):
        return {"error": res["error"]}
    vals = {r.get("label"): r.get("value") for r in res.get("rows") or []}
    return {"ok": True, "poller": name, "ip": ip, "sys_name": vals.get("sysName"),
            "sys_descr": str(vals.get("sysDescr") or "").splitlines()[0][:200] or None,
            "sys_object_id": vals.get("sysObjectID")}


@router.post("/devices/{device_id}/snmp/remove")
def remove_snmp(request: Request, device_id: int):
    with st(request).db.session() as s:
        d = s.get(Device, device_id, options=[selectinload(Device.integration), selectinload(Device.ports)])
        if d is None:
            raise HTTPException(404)
        if d.integration_id is None or d.source not in ("snmp", "ping"):
            flash(request, "Only a device that an integration also reports can go back to API data only.", "warn")
            return back(f"/devices/{device_id}")
        poller_id = d.poller_id
        sa.detach(s, d, _who(request))
        name = d.integration.name if d.integration else "the integration"
    push_poller(request, poller_id)
    flash(request, f"Stopped SNMP polling. {name} data refreshes on its next sync.")
    return back(f"/devices/{device_id}")
