"""Zscaler AI tab control: ZIA generative AI policy and AI Guard.

The Zscaler integration runs on this server, so actions call Zscaler directly (in a worker thread) rather than
through a poller. Read-only pages (rule and AI Guard object details, the scan box) go live to Zscaler too.

Safety rails, the same as the Proxmox and Synology pages:
* only admins can post actions (the login middleware blocks viewers' POSTs, and each handler checks again);
* the integration must have *Allow control actions* ticked (checked here and again in the integration);
* every action needs a confirmation from the dialog, and deletes and credential resets need the object's name typed;
* every action, whether it worked or not, goes to the audit log and the event log. Rule bodies, JSON and scanned
  text are never logged, only what was changed and the outcome.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm.attributes import flag_modified

from ..integrations import IntegrationError, build
from ..integrations.zscaler_ai_control import (
    ACTIONS,
    GUARD_KINDS,
    ID_RE,
    SIMPLE_ACTIONS,
)
from . import events
from .app import flash
from .models import Integration
from .users import audit
from .web import back, render, st

log = logging.getLogger("linkwatch.zscaler_ai")
router = APIRouter(include_in_schema=False)

# Form fields passed through to the integration. Lists come from multi-selects.
TEXT_KEYS = ("rule_id", "simple_action", "name", "description", "order", "app", "app_id", "kind", "id", "json",
             "confirm_text", "content", "direction", "policy_id")
LIST_KEYS = ("actions", "applications")
CHECKBOXES = ("enabled", "prompt_capture")


def _is_admin(request: Request) -> bool:
    u = getattr(request.state, "user", None)
    return bool(u and u.role == "admin")


def _ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def _load(request: Request, iid: int) -> tuple[Integration, dict]:
    """The Zscaler integration row (detached) and its decrypted settings."""
    state = st(request)
    with state.db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None or integ.kind != "zscaler":
            raise HTTPException(404, "No such Zscaler integration")
        s.expunge(integ)
    return integ, state.vault.open(integ.config_enc)


def _run(cfg: dict, name: str, params: dict, refresh_ai: dict | None = None) -> tuple[dict, dict | None]:
    """Build the client, run one action, and (after a change) re-read the AI policy so the page is current."""
    client = build("zscaler", cfg)
    try:
        result = client.action(name, params)
        ai = None
        if refresh_ai is not None:
            try:
                ai = client.refresh_ai_policy(refresh_ai)
                if result.get("app") and result.get("sanctioned"):
                    for a in ai.get("apps") or []:
                        if a.get("name") == result["app"]:
                            a["sanctioned"] = result["sanctioned"]
            except Exception:  # noqa: BLE001 - the action worked; a stale page is not a failure
                log.exception("Refreshing the AI tab after %s failed", name)
        return result, ai
    finally:
        client.close()


def _save_ai(request: Request, iid: int, ai: dict) -> None:
    with st(request).db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None:
            return
        data = dict(integ.data or {})
        data["ai"] = ai
        integ.data = data
        flag_modified(integ, "data")


def _safe_back(value: Any, iid: int) -> str:
    default = f"/integrations/{iid}/overview?tab=ai"
    v = str(value or "")
    if not v.startswith(f"/integrations/{iid}/") or "//" in v or "\\" in v:
        return default
    return v


def _form_params(form) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for k in TEXT_KEYS:
        v = form.get(k)
        if v is not None:
            params[k] = str(v) if k in ("json", "content", "description") else str(v).strip()
    for k in LIST_KEYS:
        if f"has_{k}" in form or k in form:
            params[k] = [str(v) for v in form.getlist(k)]
    for k in CHECKBOXES:          # an unticked box is absent from the form; say so explicitly
        if f"has_{k}" in form:
            params[k] = "1" if form.get(k) in ("on", "1", "true") else "0"
        elif k in form:
            params[k] = str(form.get(k))
    return params


# ------------------------------------------------------------------ actions
@router.post("/integrations/{iid}/ai/action")
async def ai_action(request: Request, iid: int):
    form = await request.form()
    name = str(form.get("action") or "")
    back_to = _safe_back(form.get("back"), iid)
    user = getattr(request.state, "user", None)
    if user is None or user.role != "admin":
        flash(request, "Only admins can change Zscaler policy.", "warn")
        return back(back_to)
    act = ACTIONS.get(name)
    if act is None:
        flash(request, "Unknown action.", "bad")
        return back(back_to)
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    params = _form_params(form)
    what = str(form.get("what") or "")[:120]

    def log_it(ok: bool, text: str) -> None:
        with st(request).db.session() as s:
            audit(s, user.username, _ip(request), f"Zscaler AI: {act.label.lower()}" if ok else f"Zscaler AI {act.label.lower()} failed",
                  f"{text} ({integ.name})")
            events.log(s, "integration", f"{user.username}: {act.label} on {integ.name}{'' if ok else ' failed'}: {text}",
                       "info" if ok else "warn", username=user.username)

    problem = None
    if not cfg.get("allow_control"):
        problem = "Control actions are turned off for this integration. Tick “Allow control actions” in its settings first."
    elif act.confirm in ("yes", "typed") and form.get("confirm") != "yes":
        problem = f"{act.label} needs confirming. Use the button again and confirm in the dialog."
    elif act.confirm == "typed" and not str(form.get("confirm_text") or "").strip():
        problem = f"To {act.label.lower()}, type the name shown in the confirmation box."
    if problem:
        flash(request, problem, "warn")
        return back(back_to)
    try:
        result, ai = await asyncio.to_thread(_run, cfg, name, params, (integ.data or {}).get("ai") or {})
    except IntegrationError as exc:
        await asyncio.to_thread(log_it, False, f"{what or name}: {exc}")
        flash(request, f"{act.label} failed: {exc}", "bad")
        return back(back_to)
    except Exception as exc:  # noqa: BLE001 - shown to the admin and logged, never a 500 mid-change
        log.exception("Zscaler AI action %s crashed", name)
        await asyncio.to_thread(log_it, False, f"{what or name}: {exc.__class__.__name__}")
        flash(request, f"{act.label} failed: {exc.__class__.__name__}", "bad")
        return back(back_to)
    await asyncio.to_thread(log_it, True, f"{result.get('what') or what or name}: {result.get('message') or 'done'}")
    if ai is not None:
        await asyncio.to_thread(_save_ai, request, iid, ai)
    if name == "guard_regenerate":
        # Show the new secret once, on a page of its own: never in a redirect, the session or the logs.
        return render(request, "integration_ai_secret.html", {"integ": integ, "nav_iid": iid, "result": result,
                                                              "back_to": f"/integrations/{iid}/overview?tab=ai"})
    flash(request, result.get("message") or f"{act.label} done.")
    if name == "rule_create" and result.get("rule_id"):
        back_to = f"/integrations/{iid}/ai/rule/{result['rule_id']}"
    elif name == "rule_delete" or (name == "guard_delete" and "/ai/guard/" in back_to):
        back_to = f"/integrations/{iid}/overview?tab=ai"
    elif name == "guard_create" and result.get("id") is not None and ID_RE.match(str(result["id"])):
        back_to = f"/integrations/{iid}/ai/guard/{params.get('kind')}/{result['id']}"
    return back(back_to)


# ------------------------------------------------------------------ rule editor
@router.get("/integrations/{iid}/ai/rule/{rid}", response_class=HTMLResponse)
async def ai_rule(request: Request, iid: int, rid: str):
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    creating = rid == "new"
    if not creating and not ID_RE.match(rid):
        raise HTTPException(404)
    ai = (integ.data or {}).get("ai") or {}
    rule: dict[str, Any] = {}
    error = None
    available: list[str] = []
    try:
        if not creating:
            rule = (await asyncio.to_thread(lambda: _run(cfg, "rule_get", {"rule_id": rid})[0]))["rule"]
        got = await asyncio.to_thread(lambda: _run(cfg, "rule_available_actions", {"apps": rule.get("applications") or []})[0])
        available = got["actions"]
    except IntegrationError as exc:
        error = str(exc)
    names: dict[str, str] = ai.get("app_names") or {}
    chosen = [str(a) for a in rule.get("applications") or []]
    catalog = sorted(set(names) | set(chosen), key=lambda a: (names.get(a) or a).lower())
    for a in rule.get("actions") or []:
        if a not in available:
            available.append(str(a))
    return render(request, "integration_ai_rule.html", {
        "integ": integ, "nav_iid": iid, "rid": rid, "creating": creating, "rule": rule, "error": error,
        "available": available, "catalog": catalog, "names": names, "chosen": chosen,
        "control": bool(cfg.get("allow_control")), "is_admin": _is_admin(request), "actions": ACTIONS,
        "simple": SIMPLE_ACTIONS, "rule_json": json.dumps(rule, indent=2, sort_keys=True, default=str) if rule else ""})


# ------------------------------------------------------------------ AI Guard object editor
@router.get("/integrations/{iid}/ai/guard/{kind}/{oid}", response_class=HTMLResponse)
async def ai_guard(request: Request, iid: int, kind: str, oid: str):
    if kind not in GUARD_KINDS:
        raise HTTPException(404)
    creating = oid == "new"
    if not creating and not ID_RE.match(oid):
        raise HTTPException(404)
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    label, _, editable = GUARD_KINDS[kind]
    obj: dict[str, Any] = {}
    error = None
    if not creating:
        try:
            got = await asyncio.to_thread(lambda: _run(cfg, "guard_get", {"kind": kind, "id": oid})[0])
            obj = got["object"]
        except IntegrationError as exc:
            error = str(exc)
    template = {"policies": {"name": "", "description": "", "inputDetectorPolicies": [], "outputDetectorPolicies": []},
                "rules": {"name": "", "policyId": None, "enabled": True, "ruleOrder": 1,
                          "matchCriteria": {"type": "DAS_APPLICATION", "llmApplications": []}},
                "applications": {"name": "", "ownerEmail": "", "applicationSettings": {"includeEventContents": True}},
                "providers": {"name": "", "providerType": "OPENAI"}}.get(kind, {})
    return render(request, "integration_ai_guard.html", {
        "integ": integ, "nav_iid": iid, "kind": kind, "oid": oid, "label": label, "editable": editable, "creating": creating,
        "obj": obj, "error": error, "control": bool(cfg.get("allow_control")), "is_admin": _is_admin(request),
        "actions": ACTIONS, "json_text": json.dumps(obj if obj else template, indent=2, sort_keys=not creating, default=str)})


# ------------------------------------------------------------------ AI Guard scan
@router.get("/integrations/{iid}/ai/scan", response_class=HTMLResponse)
async def ai_scan_page(request: Request, iid: int):
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    return render(request, "integration_ai_scan.html", _scan_ctx(integ, cfg, iid))


def _scan_ctx(integ: Integration, cfg: dict, iid: int, **kw) -> dict:
    items = ((integ.data or {}).get("ai") or {}).get("aiguard_items") or {}
    return {"integ": integ, "nav_iid": iid, "has_key": bool(str(cfg.get("aiguard_api_key") or "").strip()),
            "policies": items.get("policies") or [], "content": "", "direction": "IN", "policy_id": "", "scan": None,
            "error": None, **kw}


@router.post("/integrations/{iid}/ai/scan", response_class=HTMLResponse)
async def ai_scan(request: Request, iid: int):
    form = await request.form()
    user = getattr(request.state, "user", None)
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    if user is None or user.role != "admin":
        flash(request, "Only admins can scan text with AI Guard.", "warn")
        return back(f"/integrations/{iid}/overview?tab=ai")
    params = _form_params(form)
    ctx = _scan_ctx(integ, cfg, iid, content=params.get("content", ""), direction=params.get("direction") or "IN",
                    policy_id=params.get("policy_id", ""))
    try:
        result, _ = await asyncio.to_thread(_run, cfg, "scan", params)
        ctx["scan"] = result["scan"]
        outcome = f"{ctx['scan'].get('action') or 'no action'}, severity {ctx['scan'].get('severity') or 'none'}"
    except IntegrationError as exc:
        ctx["error"] = str(exc)
        outcome = f"failed: {exc}"

    def log_it() -> None:
        with st(request).db.session() as s:
            # The scanned text itself is never stored.
            audit(s, user.username, _ip(request), "Zscaler AI Guard scan",
                  f"{len(params.get('content') or '')} characters, direction {params.get('direction') or 'IN'}: {outcome} ({integ.name})")
    await asyncio.to_thread(log_it)
    return render(request, "integration_ai_scan.html", ctx)

