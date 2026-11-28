"""Zscaler Endpoint AI Security control: devices, enrollment tokens, policies, setting profiles and managed users.

The integration runs on this server, so actions call the Endpoint AI API directly (in a worker thread). After a
change the integration is collected again so the page shows the new state.

Safety rails, the same as the ZIA AI, Proxmox and Synology pages:
* only admins can post actions (the login middleware blocks viewers' POSTs, and each handler checks again);
* the integration must have *Allow control actions* ticked (checked here and again in the integration);
* every action needs a confirmation from the dialog, and revokes and deletes need the object's name typed, which the
  integration checks against the name the API returns;
* every action, whether it worked or not, goes to the audit log and the event log. Policy bodies and enrollment
  secrets are never logged, only what was changed and the outcome.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..integrations import IntegrationError, build
from ..integrations.zsai import (
    ACTIONS,
    ASSIGN_FIELDS,
    INT_ID_RE,
    POLICY_CREATE_FIELDS,
    PROFILE_FIELDS,
)
from . import events
from .app import flash
from .models import Integration
from .users import audit
from .web import back, render, st

log = logging.getLogger("linkwatch.zsai")
router = APIRouter(include_in_schema=False)

TEXT_KEYS = ("device_id", "email", "enabled", "label", "ttl_hours", "max_uses", "token_id", "days", "policy_id",
             "profile_id", "user_id", "etag", "json", "confirm_text")
NEW_POLICY = {"name": "", "enabled": False, "priority": 100, "os_platforms": [], "rules": [],
              "assignments": {"tenant_wide": False, "users": [], "groups": [], "device_groups": []},
              "change_note": "Created from VisCon1"}


def _is_admin(request: Request) -> bool:
    u = getattr(request.state, "user", None)
    return bool(u and u.role == "admin")


def _ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def _load(request: Request, iid: int) -> tuple[Integration, dict]:
    state = st(request)
    with state.db.session() as s:
        integ = s.get(Integration, iid)
        if integ is None or integ.kind != "zsai":
            raise HTTPException(404, "No such Endpoint AI Security integration")
        s.expunge(integ)
    return integ, state.vault.open(integ.config_enc)


def _call(cfg: dict, name: str, params: dict) -> dict:
    client = build("zsai", cfg)
    try:
        return client.action(name, params)
    finally:
        client.close()


def _resync(request: Request, iid: int) -> None:
    from .jobs import run_server_integration
    try:
        run_server_integration(st(request), iid)
    except Exception:
        log.exception("Refreshing Endpoint AI integration %s after an action failed", iid)


def _safe_back(value: Any, iid: int) -> str:
    default = f"/integrations/{iid}/overview"
    v = str(value or "")
    if not v.startswith(f"/integrations/{iid}/") or "//" in v or "\\" in v:
        return default
    return v


def _form_params(form) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for k in TEXT_KEYS:
        v = form.get(k)
        if v is not None:
            params[k] = str(v) if k == "json" else str(v).strip()
    return params


@router.post("/integrations/{iid}/zsai/action")
async def zsai_action(request: Request, iid: int):
    form = await request.form()
    name = str(form.get("action") or "")
    back_to = _safe_back(form.get("back"), iid)
    user = getattr(request.state, "user", None)
    if user is None or user.role != "admin":
        flash(request, "Only admins can change Endpoint AI Security.", "warn")
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
            audit(s, user.username, _ip(request),
                  f"Endpoint AI: {act.label.lower()}" if ok else f"Endpoint AI {act.label.lower()} failed", f"{text} ({integ.name})")
            events.log(s, "integration", f"{user.username}: {act.label} on {integ.name}{'' if ok else ' failed'}: {text}",
                       "info" if ok else "warn", username=user.username)

    problem = None
    if not cfg.get("allow_control"):
        problem = "Control actions are turned off for this integration. Tick “Allow control actions” in its settings first."
    elif act.confirm in ("yes", "typed") and form.get("confirm") != "yes":
        problem = f"{act.label} needs confirming. Use the button again and confirm in the dialog."
    elif act.confirm == "typed" and not params.get("confirm_text"):
        problem = f"To {act.label.lower()}, type the name shown in the confirmation box."
    if problem:
        flash(request, problem, "warn")
        return back(back_to)
    try:
        result = await asyncio.to_thread(_call, cfg, name, params)
    except IntegrationError as exc:
        await asyncio.to_thread(log_it, False, f"{what or name}: {exc}")
        flash(request, f"{act.label} failed: {exc}", "bad")
        return back(back_to)
    except Exception as exc:
        log.exception("Endpoint AI action %s crashed", name)
        await asyncio.to_thread(log_it, False, f"{what or name}: {exc.__class__.__name__}")
        flash(request, f"{act.label} failed: {exc.__class__.__name__}", "bad")
        return back(back_to)
    await asyncio.to_thread(log_it, True, f"{result.get('what') or what or name}: {result.get('message') or 'done'}")
    await asyncio.to_thread(_resync, request, iid)
    if name == "token_create":
        # The enrollment secret is shown once, on a page of its own: never in a redirect, the session or the logs.
        return render(request, "integration_zsai_token.html", {"integ": integ, "nav_iid": iid, "result": result,
                                                               "back_to": f"/integrations/{iid}/overview?tab=policy"})
    flash(request, result.get("message") or f"{act.label} done.")
    if name == "policy_create" and result.get("id") is not None and INT_ID_RE.match(str(result["id"])):
        back_to = f"/integrations/{iid}/zsai/policy/{result['id']}"
    elif name == "policy_delete":
        back_to = f"/integrations/{iid}/overview?tab=policy"
    return back(back_to)


@router.post("/integrations/{iid}/zsai/validate", response_class=HTMLResponse)
async def zsai_validate(request: Request, iid: int):
    """Dry-run the policy rules in the editor (read-only, so it doesn't need control actions on)."""
    form = await request.form()
    params = _form_params(form)
    pid = params.get("policy_id") or "new"
    if not _is_admin(request):
        flash(request, "Only admins can edit Endpoint AI policies.", "warn")
        return back(f"/integrations/{iid}/overview?tab=policy")
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    try:
        result = await asyncio.to_thread(_call, cfg, "policy_validate", params)
        check = {"ok": result["valid"], "message": result["message"], "errors": result["errors"]}
    except IntegrationError as exc:
        check = {"ok": False, "message": str(exc), "errors": []}
    return await _policy_page(request, integ, cfg, iid, pid, json_text=params.get("json") or "", etag=params.get("etag"), check=check)


@router.get("/integrations/{iid}/zsai/policy/{pid}", response_class=HTMLResponse)
async def zsai_policy(request: Request, iid: int, pid: str):
    if pid != "new" and not INT_ID_RE.match(pid):
        raise HTTPException(404)
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    return await _policy_page(request, integ, cfg, iid, pid)


async def _policy_page(request: Request, integ: Integration, cfg: dict, iid: int, pid: str, json_text: str | None = None,
                       etag: str | None = None, check: dict | None = None) -> HTMLResponse:
    creating = pid == "new"
    policy: dict[str, Any] = {}
    assignments: Any = None
    error = None
    if not creating:
        try:
            got = await asyncio.to_thread(_call, cfg, "policy_get", {"policy_id": pid})
            policy, assignments = got["policy"], got["assignments"]
            etag = etag or got.get("etag")
        except IntegrationError as exc:
            error = str(exc)
    if json_text is None:
        if creating:
            json_text = json.dumps(NEW_POLICY, indent=2)
        else:
            json_text = json.dumps({k: policy[k] for k in POLICY_CREATE_FIELDS if k in policy and k != "assignments"},
                                   indent=2, default=str) if policy else ""
    assign_src = assignments if isinstance(assignments, dict) else {}
    assign_text = json.dumps({k: assign_src.get(k, [] if k not in ("tenant_wide", "change_note") else False)
                              for k in ASSIGN_FIELDS if k != "change_note"}, indent=2, default=str)
    return render(request, "integration_zsai_policy.html", {
        "integ": integ, "nav_iid": iid, "pid": pid, "creating": creating, "policy": policy, "error": error,
        "etag": etag or "", "json_text": json_text, "assign_text": assign_text, "check": check,
        "full_json": json.dumps(policy, indent=2, sort_keys=True, default=str) if policy else "",
        "control": bool(cfg.get("allow_control")), "is_admin": _is_admin(request), "actions": ACTIONS})


@router.get("/integrations/{iid}/zsai/profile/{pid}", response_class=HTMLResponse)
async def zsai_profile(request: Request, iid: int, pid: str):
    if not INT_ID_RE.match(pid):
        raise HTTPException(404)
    integ, cfg = await asyncio.to_thread(_load, request, iid)
    profile: dict[str, Any] = {}
    etag = ""
    error = None
    try:
        got = await asyncio.to_thread(_call, cfg, "profile_get", {"profile_id": pid})
        profile, etag = got["profile"], got.get("etag") or ""
    except IntegrationError as exc:
        error = str(exc)
    return render(request, "integration_zsai_profile.html", {
        "integ": integ, "nav_iid": iid, "pid": pid, "profile": profile, "etag": etag, "error": error,
        "json_text": json.dumps({k: profile[k] for k in PROFILE_FIELDS if k in profile}, indent=2, default=str) if profile else "",
        "control": bool(cfg.get("allow_control")), "is_admin": _is_admin(request), "actions": ACTIONS})
