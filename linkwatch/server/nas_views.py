"""NAS: Synology DSM storage, apps, backups and security, with control actions.

The pages read the Synology integration's last sync (``Integration.data``, refreshed every poll and a few seconds after
each action). SMART details and every action go live to DSM through the integration's poller (``Hub.call_sync`` ->
poller ``rpc`` -> ``Synology.action``), because the NAS is usually on a LAN the server can't reach.

Safety rails, the same as the Hypervisors pages:
* only admins can post actions (the login middleware and an explicit check here);
* the integration must have *Allow control actions* ticked (checked here and again on the poller);
* disruptive actions need a confirmation from the dialog; rebooting or shutting down the NAS needs its name typed;
* every action, whether it worked or not, goes to the audit log and the event log.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..integrations.base import host_url
from ..integrations.synology import ACTIONS, DISK_RE, expected_confirm
from . import events
from .app import flash
from .gateway import RpcError, outdated_poller_message
from .models import Device, Integration
from .users import audit
from .web import back, render, st

router = APIRouter(include_in_schema=False)
TABS = [("overview", "Overview"), ("storage", "Storage"), ("shares", "Shares and snapshots"), ("apps", "Packages and containers"),
        ("vms", "Virtual machines"), ("backups", "Backups"), ("users", "Users and security")]
TARGET_KEYS = ("package", "container", "guest", "task", "pool", "share", "snapshot", "description")


class Nas:
    """What the pages need about one Synology integration, read in one session."""

    def __init__(self, integ: Integration, config: dict, connected: bool):
        self.id, self.name, self.status, self.enabled = integ.id, integ.name, integ.status, integ.enabled
        self.last_sync, self.last_error = integ.last_sync, integ.last_error
        self.poller_id = integ.poller_id
        self.poller_name = integ.poller.name if integ.poller else None
        self.poller_features = list(integ.poller.features or []) if integ.poller else []
        self.connected = connected
        self.data: dict[str, Any] = integ.data or {}
        self.control = bool(config.get("allow_control"))
        self.web_url = None
        if str(config.get("host") or "").strip():
            try:
                self.web_url = host_url(str(config["host"]), 5001)
            except Exception:
                pass

    @property
    def system(self) -> dict:
        return self.data.get("system") or {}

    @property
    def confirm_name(self) -> str:
        return expected_confirm(self.data, self.name)

    @property
    def can_rpc(self) -> bool:
        return self.connected and "rpc" in self.poller_features

    def why_offline(self) -> str | None:
        if not self.poller_id:
            return "No poller is assigned to this integration."
        if not self.connected:
            return f"Poller {self.poller_name} is not connected, so actions and live details are unavailable."
        if "rpc" not in self.poller_features:
            return outdated_poller_message(self.poller_name or "the poller", "Synology actions")
        return None

    def name_of(self, section: str, key: str) -> str | None:
        """The display name of the thing an action targets, from the last sync."""
        rows = self.data.get(section) or []
        field = {"vms": "id", "backups": "id", "pools": "id", "packages": "id"}.get(section, "name")
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and str(r.get(field)) == str(key):
                return r.get("name")
        return None


def _user(request: Request):
    return getattr(request.state, "user", None)


def _is_admin(request: Request) -> bool:
    u = _user(request)
    return bool(u and u.role == "admin")


def _ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def boxes(request: Request, iid: int | None = None) -> list[Nas]:
    state = st(request)
    with state.db.session() as s:
        q = select(Integration).where(Integration.kind == "synology").options(selectinload(Integration.poller)).order_by(Integration.name)
        if iid is not None:
            q = q.where(Integration.id == iid)
        return [Nas(i, state.vault.open(i.config_enc), bool(i.poller_id and i.poller_id in state.hub.conns)) for i in s.scalars(q)]


def nas_or_404(request: Request, iid: int) -> Nas:
    found = boxes(request, iid)
    if not found:
        raise HTTPException(404, "No such Synology integration")
    return found[0]


def rpc(request: Request, n: Nas, action: str, params: dict, refresh: bool = False, timeout: float = 60.0) -> dict:
    problem = n.why_offline()
    if problem:
        raise RpcError(problem)
    return st(request).hub.call_sync(n.poller_id, {"op": "integration_action", "integration_id": n.id, "action": action,
                                                    "params": params, "refresh": refresh}, timeout)


# ------------------------------------------------------------------ pages
@router.get("/nas", response_class=HTMLResponse)
def nas_index(request: Request):
    all_ = boxes(request)
    if len(all_) == 1:
        return back(f"/nas/{all_[0].id}")
    return render(request, "nas_list.html", {"boxes": all_})


@router.get("/nas/{iid}", response_class=HTMLResponse)
def nas_page(request: Request, iid: int, tab: str = "overview"):
    n = nas_or_404(request, iid)
    tabs = [(k, label) for k, label in TABS if k not in ("vms",) or n.data.get("vms") is not None]
    tab = tab if tab in dict(tabs) else "overview"
    with st(request).db.session() as s:
        device_id = s.scalar(select(Device.id).where(Device.integration_id == iid).limit(1))
    return render(request, "nas.html", {"n": n, "d": n.data, "tabs": tabs, "tab": tab, "actions": ACTIONS,
                                        "is_admin": _is_admin(request), "device_id": device_id, "nas_iid": iid})


@router.get("/nas/{iid}/disk/{disk}", response_class=HTMLResponse)
def disk_page(request: Request, iid: int, disk: str):
    if not DISK_RE.match(disk):
        raise HTTPException(404)
    n = nas_or_404(request, iid)
    row = next((x for x in n.data.get("disks") or [] if isinstance(x, dict) and x.get("id") == disk), None)
    smart, error = None, None
    try:
        smart = rpc(request, n, "disk_smart", {"disk": disk}, timeout=45)
    except RpcError as exc:
        error = str(exc)
    if row is None and smart is None:
        raise HTTPException(404, error or "No such disk")
    return render(request, "nas_disk.html", {"n": n, "disk": row or {"id": disk, "name": disk}, "smart": smart or {}, "error": error,
                                             "nas_iid": iid})


# ------------------------------------------------------------------ actions
def _describe(n: Nas, name: str, p: dict) -> str:
    act = ACTIONS[name]
    if not act.target:
        return f"NAS {n.confirm_name}"
    key = p.get(act.target, "")
    label = {"package": "package", "container": "container", "guest": "VM", "task": "backup task", "pool": "pool",
             "share": "shared folder"}[act.target]
    section = {"package": "packages", "container": "containers", "guest": "vms", "task": "backups", "pool": "pools",
               "share": "shares"}[act.target]
    shown = n.name_of(section, key)
    out = f"{label} {key}" + (f" ({shown})" if shown and shown != key else "")
    if p.get("snapshot"):
        out += f" [snapshot {p['snapshot']}]"
    return out


@router.post("/nas/{iid}/action")
async def action(request: Request, iid: int):
    form = await request.form()
    name = str(form.get("action") or "")
    back_to = str(form.get("back") or "")
    if not back_to.startswith(f"/nas/{iid}") or "//" in back_to:
        back_to = f"/nas/{iid}"
    user = _user(request)
    if user is None or user.role != "admin":
        flash(request, "Only admins can control the NAS.", "warn")
        return back(back_to)
    act = ACTIONS.get(name)
    if act is None:
        flash(request, "Unknown action.", "bad")
        return back(back_to)
    n = await asyncio.to_thread(nas_or_404, request, iid)
    params: dict[str, Any] = {}
    for k in TARGET_KEYS:
        v = form.get(k)
        if v is not None:
            params[k] = str(v).strip()
    if "has_lock" in form:
        params["lock"] = "1" if form.get("lock") in ("on", "1", "true") else "0"
    desc = _describe(n, name, params)

    def log_it(ok: bool, text: str) -> None:
        with st(request).db.session() as s:
            audit(s, user.username, _ip(request), f"Synology: {act.label.lower()}" if ok else f"Synology {act.label.lower()} failed",
                  f"{desc} on {n.name}: {text}")
            events.log(s, "integration", f"{user.username}: {act.label} {desc} ({n.name}){'' if ok else ' failed'}: {text}",
                       "info" if ok else "warn", username=user.username)

    problem = None
    if not n.control:
        problem = "Control actions are turned off for this NAS. Tick “Allow control actions” in its settings first."
    elif act.confirm == "yes" and form.get("confirm") != "yes":
        problem = f"{act.label} needs confirming. Use the button again and confirm in the dialog."
    elif act.confirm == "typed" and str(form.get("confirm_text") or "").strip() != n.confirm_name:
        problem = f"To {act.label.lower()}, type {n.confirm_name} in the confirmation box."
    if problem:
        flash(request, problem, "warn")
        return back(back_to)
    try:
        result = await asyncio.to_thread(rpc, request, n, name, params, True, 90.0)
    except RpcError as exc:
        await asyncio.to_thread(log_it, False, str(exc))
        flash(request, f"{act.label} failed: {exc}", "bad")
        return back(back_to)
    await asyncio.to_thread(log_it, True, result.get("message") or "done")
    flash(request, (result.get("message") or f"{act.label} sent.") + " The page updates after the next sync, in a few seconds.")
    return back(back_to)
