"""The alert rule builder: create, edit, preview and delete custom alert rules."""
from __future__ import annotations

from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from . import custom_rules as cr
from . import events
from .alerts import Alerter
from .models import AlertRule, Device, Integration, Site
from .web import _who, back, flash, render, st

router = APIRouter(include_in_schema=False)


def _choices(s) -> dict:
    return {"types": sorted({t for t in s.scalars(select(Device.type).distinct()) if t}),
            "sites": sorted(s.scalars(select(Site.name))),
            "sources": sorted({x for x in s.scalars(select(Device.source).distinct()) if x} |
                              {k for k in s.scalars(select(Integration.kind).distinct())} | {"snmp", "ping"})}


def _metrics_json() -> dict:
    return {e: [{"key": k, "label": m.label, "unit": m.unit, "states": list(m.states)} for k, m in ms.items()]
            for e, ms in cr.METRICS.items()}


def _form(request: Request, rule, problems=(), status_code=200):
    with st(request).db.session() as s:
        ctx = _choices(s)
    ctx.update(rule=rule, problems=list(problems), entities=cr.ENTITIES, metrics=_metrics_json(), num_ops=cr.NUM_OPS,
               state_ops=cr.STATE_OPS, sensor_kinds=cr.SENSOR_KINDS, section="Alerts")
    return render(request, "alert_rule.html", ctx, status_code=status_code)


def _blank(entity: str = "device") -> SimpleNamespace:
    return SimpleNamespace(id=None, name="", entity=entity if entity in cr.METRICS else "device", metric="cpu" if entity == "device" else
                           ("util_pct" if entity == "port" else "value"), op=">", threshold=None, value_text="",
                           severity="warn", polls=3, enabled=True, scope={})


@router.get("/alerts/rules/new", response_class=HTMLResponse)
def rule_new(request: Request, entity: str = "device", copy: int = 0):
    rule = _blank(entity)
    if copy:
        with st(request).db.session() as s:
            src = s.get(AlertRule, copy)
            if src is not None and cr.is_custom(src):
                rule = SimpleNamespace(**{k: getattr(src, k) for k in ("entity", "metric", "op", "threshold", "value_text",
                                                                         "severity", "polls", "enabled", "scope")},
                                       id=None, name=f"{src.name} (copy)")
    return _form(request, rule)


@router.post("/alerts/rules/new")
async def rule_create(request: Request):
    form = await request.form()
    rule, problems = cr.rule_from_form(form)
    if problems:
        return _form(request, rule, problems, 400)
    rule.created_by = _who(request)
    with st(request).db.session() as s:
        s.add(rule)
        events.log(s, "config", f"Alert rule '{rule.name}' created by {_who(request)}", "info", username=_who(request))
    flash(request, f"Rule '{rule.name}' saved. It's checked on every poll from now on.")
    return back("/alerts#custom")


@router.get("/alerts/rules/{rule_id}/edit", response_class=HTMLResponse)
def rule_edit(request: Request, rule_id: int):
    with st(request).db.session() as s:
        rule = s.get(AlertRule, rule_id)
        if rule is None or not cr.is_custom(rule):
            raise HTTPException(404, "No such custom rule")
        s.expunge(rule)
    return _form(request, rule)


@router.post("/alerts/rules/{rule_id}/edit")
async def rule_save(request: Request, rule_id: int):
    form = await request.form()
    with st(request).db.session() as s:
        rule = s.get(AlertRule, rule_id)
        if rule is None or not cr.is_custom(rule):
            raise HTTPException(404, "No such custom rule")
        rule, problems = cr.rule_from_form(form, rule)
        if problems:
            s.expunge(rule)
            s.rollback()
    if problems:
        return _form(request, rule, problems, 400)
    with st(request).db.session() as s:
        cr.forget(s, rule.key)          # the condition may have changed: start counting polls again
        events.log(s, "config", f"Alert rule '{rule.name}' changed by {_who(request)}", "info", username=_who(request))
    flash(request, f"Rule '{rule.name}' saved. Open alerts it no longer matches clear on the next poll.")
    return back("/alerts#custom")


@router.post("/alerts/rules/{rule_id}/delete")
def rule_delete(request: Request, rule_id: int):
    with st(request).db.session() as s:
        rule = s.get(AlertRule, rule_id)
        if rule is None or not cr.is_custom(rule):
            raise HTTPException(404, "No such custom rule")
        name, key = rule.name, rule.key
        alerter = Alerter(s)
        for (k, ref), a in list(alerter.open.items()):
            if k == key:
                alerter.set(k, ref, False, device=a.device)
        cr.forget(s, key)
        s.delete(rule)
        events.log(s, "config", f"Alert rule '{name}' deleted by {_who(request)}", "info", username=_who(request))
    st(request).notifier.dispatch(alerter.events)
    flash(request, f"Rule '{name}' deleted and its open alerts cleared.")
    return back("/alerts#custom")


@router.post("/alerts/rules/preview")
async def rule_preview(request: Request):
    """What the rule in the form would match right now (JSON for the builder's live preview)."""
    form = await request.form()
    rule, problems = cr.rule_from_form(form)
    if problems:
        return {"problems": problems, "text": cr.describe(rule)}
    with st(request).db.session() as s:
        return cr.preview(s, rule)
