"""Custom OIDs and MIBs: list, add, edit, test and delete custom OIDs; upload, browse and search MIB files."""
from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import delete, func, or_, select

from . import mibs
from . import oids as co
from .models import CustomOid, Device, MibModule, Poller, Sensor
from .web import back, flash, render, st

router = APIRouter(include_in_schema=False)


def _value_counts(s) -> Counter:
    """How many sensor values each custom OID produced at the last poll, network-wide."""
    out: Counter = Counter()
    for key in s.scalars(select(Sensor.key).where(Sensor.kind == "custom")):
        head = key.split(".", 1)[0]
        if head.startswith("oid") and head[3:].isdigit():
            out[int(head[3:])] += 1
    return out


def _sensors_of(s, oid_id: int):
    return or_(Sensor.key == f"oid{oid_id}", Sensor.key.like(f"oid{oid_id}.%"))


@router.get("/oids", response_class=HTMLResponse)
def oids_page(request: Request):
    with st(request).db.session() as s:
        defs = s.scalars(select(CustomOid).order_by(func.lower(CustomOid.name))).all()
        counts = _value_counts(s)
        snmp_devs = s.scalars(select(Device).where(Device.snmp_profile_id.is_not(None), Device.disabled.is_(False))).all()
        devices = {c.id: sum(1 for d in snmp_devs if co.in_scope(c, d, unknown_sys_oid_ok=False)) for c in defs}
        modules = s.scalars(select(MibModule).order_by(MibModule.name)).all()
        old_pollers = [p.name for p in s.scalars(select(Poller).where(Poller.revoked.is_(False)))
                       if p.id in st(request).hub.conns and "custom_oids" not in (p.features or [])]
    return render(request, "oids.html", {"defs": defs, "counts": counts, "devices": devices, "modules": modules,
                                         "old_pollers": old_pollers, "presets": co.PRESETS, "describe_scope": co.describe_scope,
                                         "value_types": co.VALUE_TYPES, "bundled": sorted(p.stem for p in mibs.BUNDLED.glob("*.txt")),
                                         "section": "health"})


def _form(request: Request, c, problems=(), status_code: int = 200) -> HTMLResponse:
    with st(request).db.session() as s:
        types = sorted({t for t in s.scalars(select(Device.type).distinct()) if t})
        devices = s.execute(select(Device.id, Device.hostname, Device.ip, Device.sys_object_id)
                            .where(Device.snmp_profile_id.is_not(None), Device.disabled.is_(False))
                            .order_by(func.lower(Device.hostname))).all()
    states = ", ".join(f"{k}={v}" for k, v in (c.states or {}).items())
    return render(request, "oid_form.html", {"c": c, "problems": list(problems), "types": types, "devices": devices,
                                             "value_types": co.VALUE_TYPES, "modes": co.MODES, "vendors": co.VENDORS,
                                             "presets": co.PRESETS, "states_text": states, "section": "health"},
                  status_code=status_code)


def _blank(**kw) -> SimpleNamespace:
    base = dict(id=None, name="", oid="", mib_name=None, mode="get", label_oid=None, value_type="gauge", scale=None, unit=None,
                states=None, ok_values=None, category=None, match_type=None, match_sys_oid=None, match_name=None, enabled=True,
                description=None)
    base.update({k: v for k, v in kw.items() if k in base})
    return SimpleNamespace(**base)


@router.get("/oids/new", response_class=HTMLResponse)
def oid_new(request: Request, preset: int = -1, oid: str = "", copy: int = 0):
    c = _blank()
    if 0 <= preset < len(co.PRESETS):
        c = _blank(**co.PRESETS[preset])
    elif copy:
        with st(request).db.session() as s:
            src = s.get(CustomOid, copy)
            if src is not None:
                c = _blank(**{k: getattr(src, k) for k in vars(_blank()) if k != "id"})
                c.name = f"{src.name} (copy)"
    elif oid:
        with st(request).db.session() as s:
            try:
                num, obj = mibs.find(s, oid)
            except mibs.MibError as exc:
                flash(request, str(exc), "warn")
                num, obj = oid, None
        hint = mibs.suggest(obj)
        if obj and obj.get("node") == "scalar" and num == obj["oid"]:
            num += ".0"
        c = _blank(oid=num, name=(obj or {}).get("name", ""), **hint)
    return _form(request, c)


@router.post("/oids/new")
async def oid_create(request: Request):
    form = await request.form()
    with st(request).db.session() as s:
        c, problems = co.def_from_form(s, form)
        if problems:
            return _form(request, c, problems, 400)
        s.add(c)
        s.flush()
        name = c.name
    st(request).hub.push_all_soon()
    flash(request, f"Added “{name}”. Pollers start reading it on their next poll; values show on each device's Health tab.")
    return back("/oids")


@router.get("/oids/{oid_id}", response_class=HTMLResponse)
def oid_edit(request: Request, oid_id: int):
    with st(request).db.session() as s:
        c = s.get(CustomOid, oid_id)
        if c is None:
            raise HTTPException(404, "No such custom OID")
    return _form(request, c)


@router.post("/oids/{oid_id}")
async def oid_save(request: Request, oid_id: int):
    form = await request.form()
    with st(request).db.session() as s:
        c = s.get(CustomOid, oid_id)
        if c is None:
            raise HTTPException(404, "No such custom OID")
        before = (c.oid, c.mode, c.label_oid)
        c, problems = co.def_from_form(s, form, c)
        if problems:
            shown = _blank(**{k: getattr(c, k) for k in vars(_blank())})
            shown.id = oid_id
            s.rollback()
            return _form(request, shown, problems, 400)
        if (c.oid, c.mode, c.label_oid) != before:
            s.execute(delete(Sensor).where(Sensor.kind == "custom", _sensors_of(s, c.id)))   # old rows no longer apply
        name = c.name
    st(request).hub.push_all_soon()
    flash(request, f"Saved “{name}”.")
    return back("/oids")


@router.post("/oids/{oid_id}/delete")
def oid_delete(request: Request, oid_id: int):
    with st(request).db.session() as s:
        c = s.get(CustomOid, oid_id)
        if c is None:
            raise HTTPException(404, "No such custom OID")
        name = c.name
        s.execute(delete(Sensor).where(Sensor.kind == "custom", _sensors_of(s, oid_id)))
        s.delete(c)
    st(request).hub.push_all_soon()
    flash(request, f"Deleted “{name}” and its history.")
    return back("/oids")


@router.post("/ui/oids/test")
async def oid_test(request: Request):
    """Read an OID from one device through its poller, before (or after) saving it."""
    body = await request.json()
    try:
        device_id = int(body.get("device_id") or 0)
    except (TypeError, ValueError):
        device_id = 0
    with st(request).db.session() as s:
        d = s.get(Device, device_id)
        if d is None or d.snmp_profile_id is None:
            return JSONResponse({"error": "Choose a device that is polled over SNMP."}, status_code=400)
        try:
            oid, obj = mibs.find(s, str(body.get("oid") or ""))
            mode = body.get("mode") if body.get("mode") in co.MODES else ("walk" if obj and obj.get("node") == "column" else "get")
            if obj and obj.get("node") == "scalar" and mode == "get" and oid == obj["oid"]:
                oid += ".0"
            label = mibs.find(s, str(body["label_oid"]))[0] if mode == "walk" and body.get("label_oid") else None
        except mibs.MibError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        poller_id, host = d.poller_id, d.hostname
    if not poller_id:
        return JSONResponse({"error": f"{host} has no poller."}, status_code=400)
    res = await st(request).hub.snmp_test(poller_id, {"device_id": device_id, "oid": oid, "mode": mode, "label_oid": label})
    rows = res.get("rows") or []
    return {"oid": oid, "mode": mode, "device": host, "error": res.get("error"), "rows": rows[:50],
            "note": None if rows or res.get("error") else ("The device has no value at that OID. A table column needs "
                                                           "“Table column”; a single value usually ends in .0.")}


# ------------------------------------------------------------------ MIBs
@router.get("/ui/mibs/search")
def mib_search(request: Request, q: str = ""):
    with st(request).db.session() as s:
        hits = mibs.search(s, q)
    return [{"module": o["module"], "name": o["name"], "oid": o["oid"], "node": o["node"], "type": o.get("type"),
             "units": o.get("units"), "descr": o.get("descr"), "suggest": mibs.suggest(o)} for o in hits]


@router.post("/mibs/upload")
async def mib_upload(request: Request):
    form = await request.form()
    files = [f for f in form.getlist("files") if isinstance(f, UploadFile) or hasattr(f, "read")]
    if not files:
        flash(request, "Choose one or more MIB files.", "warn")
        return back("/oids#mibs")
    added, problems = [], []
    with st(request).db.session() as s:
        for f in files[:50]:
            raw = await f.read()
            try:
                added += mibs.store(s, f.filename or "mib", raw)
            except mibs.MibError as exc:
                problems.append(str(exc))
        broken = {m.name: m.error for m in s.scalars(select(MibModule).where(MibModule.name.in_(added)))} if added else {}
    good = [n for n in added if not broken.get(n)]
    if good:
        flash(request, f"Loaded {', '.join(good)}. Search for its objects when adding a custom OID.")
    for n in added:
        if broken.get(n):
            problems.append(f"{n}: {broken[n]}")
    for p in problems:
        flash(request, p, "warn")
    return back("/oids#mibs")


@router.get("/mibs/{mib_id}", response_class=HTMLResponse)
def mib_detail(request: Request, mib_id: int, q: str = ""):
    with st(request).db.session() as s:
        m = s.get(MibModule, mib_id)
        if m is None:
            raise HTTPException(404, "No such MIB")
        objs = [o for o in (m.objects or []) if not q or q.lower() in o["name"].lower() or o["oid"].startswith(q)]
    return render(request, "mib.html", {"m": m, "objs": objs, "q": q, "section": "health"})


@router.post("/mibs/{mib_id}/delete")
def mib_delete(request: Request, mib_id: int):
    with st(request).db.session() as s:
        m = s.get(MibModule, mib_id)
        if m is None:
            raise HTTPException(404, "No such MIB")
        name = m.name
        s.delete(m)
        s.flush()
        mibs.recompile(s, [x.name for x in s.scalars(select(MibModule))])   # anything that imported it now reports so
    flash(request, f"Deleted {name}. Custom OIDs already added from it keep working; they store the numeric OID.")
    return back("/oids#mibs")

