"""Hypervisors: Proxmox VE guests and nodes, with control actions.

The inventory comes from the Proxmox integration's regular sync (``Integration.data["vms"]``). Detail pages and
every action go live to Proxmox through the integration's poller (``Hub.call_sync`` -> poller ``rpc`` ->
``Proxmox.action``), because the cluster is usually on a LAN the server can't reach.

Safety rails, in order:
* only admins can post actions or open consoles (the login middleware and an explicit check here);
* the integration must have *Allow control actions* ticked (checked here and again on the poller);
* destructive actions need a confirmation from the dialog, and the worst ones need the VMID or node name typed;
* every action, whether it worked or not, goes to the audit log and the event log.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..integrations.proxmox import ACTIONS, GUEST_TYPES, NODE_RE, UPID_RE
from . import events
from .app import flash
from .gateway import RpcError, TunnelError, outdated_poller_message
from .models import Device, Integration
from .ssh import _same_origin, _send, _size, _ws_user
from .users import audit
from .web import back, render, st

log = logging.getLogger("linkwatch.hypervisors")
router = APIRouter(include_in_schema=False)
IDLE_TIMEOUT = 30 * 60
MAX_SESSION = 12 * 3600


class Cluster:
    """What the pages need about one Proxmox integration, read in one session."""

    def __init__(self, integ: Integration, config: dict, connected: bool):
        self.id, self.name, self.status, self.enabled = integ.id, integ.name, integ.status, integ.enabled
        self.last_sync, self.last_error = integ.last_sync, integ.last_error
        self.poller_id = integ.poller_id
        self.poller_name = integ.poller.name if integ.poller else None
        self.poller_features = list(integ.poller.features or []) if integ.poller else []
        self.connected = connected
        self.data: dict[str, Any] = integ.data or {}
        self.control = bool(config.get("allow_control"))
        host = str(config.get("host") or "").strip()
        self.web_url = None
        if host:
            from ..integrations.base import host_url
            try:
                self.web_url = host_url(host, 8006)
            except Exception:
                pass

    @property
    def vms(self) -> list[dict]:
        return [v for v in self.data.get("vms") or [] if isinstance(v, dict)]

    @property
    def nodes(self) -> list[dict]:
        return [n for n in self.data.get("nodes") or [] if isinstance(n, dict)]

    @property
    def can_rpc(self) -> bool:
        return self.connected and "rpc" in self.poller_features

    def why_offline(self) -> str | None:
        if not self.poller_id:
            return "No poller is assigned to this integration."
        if not self.connected:
            return f"Poller {self.poller_name} is not connected, so live details and actions are unavailable."
        if "rpc" not in self.poller_features:
            return outdated_poller_message(self.poller_name or "the poller", "Proxmox actions")
        return None

    def find(self, vtype: str, vmid: int) -> dict | None:
        return next((v for v in self.vms if v.get("type") == vtype and str(v.get("vmid")) == str(vmid)), None)


def _user(request: Request):
    return getattr(request.state, "user", None)


def _is_admin(request: Request) -> bool:
    u = _user(request)
    return bool(u and u.role == "admin")


def _ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def clusters(request: Request, iid: int | None = None) -> list[Cluster]:
    state = st(request)
    with state.db.session() as s:
        q = select(Integration).where(Integration.kind == "proxmox").options(selectinload(Integration.poller)).order_by(Integration.name)
        if iid is not None:
            q = q.where(Integration.id == iid)
        return [Cluster(i, state.vault.open(i.config_enc), bool(i.poller_id and i.poller_id in state.hub.conns)) for i in s.scalars(q)]


def cluster_or_404(request: Request, iid: int) -> Cluster:
    found = clusters(request, iid)
    if not found:
        raise HTTPException(404, "No such Proxmox integration")
    return found[0]


def rpc(request: Request, c: Cluster, action: str, params: dict, refresh: bool = False, timeout: float = 60.0) -> dict:
    problem = c.why_offline()
    if problem:
        raise RpcError(problem)
    return st(request).hub.call_sync(c.poller_id, {"op": "integration_action", "integration_id": c.id, "action": action,
                                                    "params": params, "refresh": refresh}, timeout)


def _device_links(request: Request, iid: int) -> dict[str, int]:
    with st(request).db.session() as s:
        return {ext: did for ext, did in s.execute(select(Device.external_id, Device.id).where(Device.integration_id == iid))}


# ------------------------------------------------------------------ pages
@router.get("/hypervisors", response_class=HTMLResponse)
def hypervisors(request: Request, i: int | None = None, node: str = "", status: str = "", type: str = "", q: str = ""):
    all_clusters = clusters(request)
    shown = [c for c in all_clusters if i is None or c.id == i]
    rows = []
    for c in shown:
        for v in c.vms:
            if node and v.get("node") != node:
                continue
            if type == "template":
                if not v.get("template"):
                    continue
            elif v.get("template"):
                continue
            elif type and v.get("type") != type:
                continue
            if status and (v.get("status") or "") != status:
                continue
            if q:
                hay = " ".join(str(x) for x in (v.get("name"), v.get("vmid"), v.get("node"), " ".join(v.get("tags") or []), v.get("pool")) if x).lower()
                if q.lower() not in hay:
                    continue
            rows.append((c, v))
    totals = {"nodes": sum(len(c.nodes) for c in shown),
              "nodes_online": sum(1 for c in shown for n in c.nodes if n.get("status") == "online"),
              "guests": sum(1 for c in shown for v in c.vms if not v.get("template")),
              "running": sum(1 for c in shown for v in c.vms if not v.get("template") and v.get("status") == "running"),
              "vms": sum(1 for c in shown for v in c.vms if not v.get("template") and v.get("type") == "qemu"),
              "cts": sum(1 for c in shown for v in c.vms if not v.get("template") and v.get("type") == "lxc"),
              "templates": sum(1 for c in shown for v in c.vms if v.get("template"))}
    return render(request, "hypervisors.html", {"clusters": all_clusters, "shown": shown, "rows": rows, "totals": totals,
                                                "f": {"i": i, "node": node, "status": status, "type": type, "q": q},
                                                "is_admin": _is_admin(request), "hv_iid": i, "hv_page": "guests",
                                                "actions": ACTIONS})


@router.get("/hypervisors/{iid}/guest/{vtype}/{vmid}", response_class=HTMLResponse)
def guest_page(request: Request, iid: int, vtype: str, vmid: int, node: str = "", task: str = ""):
    if vtype not in GUEST_TYPES:
        raise HTTPException(404)
    c = cluster_or_404(request, iid)
    row = c.find(vtype, vmid)
    node = node if NODE_RE.match(node or "") else (row or {}).get("node") or ""
    detail, error = None, None
    if not node:
        error = "This guest isn't in the last sync. Press Sync now on the integration, then try again."
    else:
        try:
            detail = rpc(request, c, "guest_detail", {"node": node, "type": vtype, "vmid": vmid}, timeout=45)
        except RpcError as exc:
            error = str(exc)
    if row is None and detail is None:
        raise HTTPException(404, error or "No such guest")
    name = (detail or {}).get("status", {}).get("name") or (row or {}).get("name") or f"{vtype} {vmid}"
    status = (detail or {}).get("status", {}).get("status") or (row or {}).get("status") or "unknown"
    other_nodes = [n["name"] for n in (detail or {}).get("nodes") or [] if n.get("name") != node and n.get("status") == "online"] \
        or [n.get("name") for n in c.nodes if n.get("name") != node and n.get("status") == "online"]
    dev_id = _device_links(request, iid).get(f"{vtype}-{vmid}")
    return render(request, "hv_guest.html", {
        "c": c, "row": row or {}, "d": detail or {}, "error": error, "vtype": vtype, "vmid": vmid, "node": node, "name": name,
        "status": status, "running": status == "running", "other_nodes": other_nodes, "actions": ACTIONS,
        "is_admin": _is_admin(request), "task": task if UPID_RE.match(task or "") else None, "device_id": dev_id,
        "hv_iid": iid, "hv_page": "guests"})


@router.get("/hypervisors/{iid}/node/{node}", response_class=HTMLResponse)
def node_page(request: Request, iid: int, node: str, task: str = ""):
    if not NODE_RE.match(node):
        raise HTTPException(404)
    c = cluster_or_404(request, iid)
    cached = next((n for n in c.nodes if n.get("name") == node), None)
    detail, error = None, None
    try:
        detail = rpc(request, c, "node_detail", {"node": node}, timeout=45)
    except RpcError as exc:
        error = str(exc)
    if cached is None and detail is None:
        raise HTTPException(404, error or "No such node")
    guests = [v for v in c.vms if v.get("node") == node]
    other_nodes = [n["name"] for n in (detail or {}).get("nodes") or [] if n.get("name") != node and n.get("status") == "online"] \
        or [n.get("name") for n in c.nodes if n.get("name") != node and n.get("status") == "online"]
    return render(request, "hv_node.html", {
        "c": c, "n": cached or {"name": node}, "d": detail or {}, "error": error, "node": node, "guests": guests,
        "other_nodes": other_nodes, "actions": ACTIONS, "is_admin": _is_admin(request),
        "task": task if UPID_RE.match(task or "") else None, "device_id": _device_links(request, iid).get(f"node-{node}"),
        "hv_iid": iid, "hv_page": "nodes"})


@router.get("/hypervisors/{iid}/tasks", response_class=HTMLResponse)
def tasks_page(request: Request, iid: int):
    c = cluster_or_404(request, iid)
    tasks, error = [], None
    try:
        tasks = rpc(request, c, "tasks", {}, timeout=30).get("tasks") or []
    except RpcError as exc:
        error = str(exc)
    return render(request, "hv_tasks.html", {"c": c, "tasks": tasks, "error": error, "hv_iid": iid, "hv_page": "tasks"})


@router.get("/ui/hypervisors/{iid}/task")
def task_json(request: Request, iid: int, upid: str = ""):
    if not UPID_RE.match(upid):
        return JSONResponse({"error": "Invalid task ID."}, status_code=400)
    c = cluster_or_404(request, iid)
    try:
        return rpc(request, c, "task", {"upid": upid}, timeout=20)
    except RpcError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)


# ------------------------------------------------------------------ actions
def _describe(name: str, p: dict, row: dict | None) -> str:
    act = ACTIONS[name]
    if act.scope == "node":
        what = f"node {p.get('node')}"
    else:
        label = "VM" if p.get("type") == "qemu" else "container"
        what = f"{label} {p.get('vmid')}" + (f" ({row.get('name')})" if row and row.get("name") else "") + f" on {p.get('node')}"
    extra = []
    for k in ("target", "snapname", "storage", "newid", "volid", "cores", "memory", "disk", "size", "mode"):
        if p.get(k) not in (None, ""):
            extra.append(f"{k}={str(p[k])[:80]}")
    return what + (f" [{', '.join(extra)}]" if extra else "")


PARAM_KEYS = ("target", "online", "with_local_disks", "restart", "newid", "name", "full", "storage", "snapname", "description",
              "vmstate", "mode", "compress", "notes", "volid", "cores", "memory", "disk", "size", "purge")
CHECKBOXES = ("online", "with_local_disks", "restart", "full", "vmstate", "purge")


@router.post("/hypervisors/{iid}/action")
async def action(request: Request, iid: int):
    form = await request.form()
    name = str(form.get("action") or "")
    back_to = str(form.get("back") or "")
    if not back_to.startswith("/hypervisors") or "//" in back_to:
        back_to = "/hypervisors"
    user = _user(request)
    if user is None or user.role != "admin":
        flash(request, "Only admins can control virtual machines.", "warn")
        return back(back_to)
    act = ACTIONS.get(name)
    if act is None:
        flash(request, "Unknown action.", "bad")
        return back(back_to)
    c = await asyncio.to_thread(cluster_or_404, request, iid)
    node = str(form.get("node") or "")
    params: dict[str, Any] = {"node": node}
    if act.scope == "guest":
        params.update(type=str(form.get("type") or ""), vmid=str(form.get("vmid") or ""))
    for k in PARAM_KEYS:
        v = form.get(k)
        if v is not None:
            params[k] = str(v).strip()
    for k in CHECKBOXES:          # an unticked box is absent from the form; say so explicitly
        if f"has_{k}" in form:
            params[k] = "1" if form.get(k) in ("on", "1", "true") else "0"
    row = c.find(params.get("type", ""), params.get("vmid", 0)) if act.scope == "guest" else None
    desc = _describe(name, params, row)

    def log_it(ok: bool, text: str) -> None:
        with st(request).db.session() as s:
            audit(s, user.username, _ip(request), f"Proxmox: {act.label.lower()}" if ok else f"Proxmox {act.label.lower()} failed",
                  f"{desc} on {c.name}: {text}")
            events.log(s, "integration", f"{user.username}: {act.label} {desc} ({c.name}){'' if ok else ' failed'}: {text}",
                       "info" if ok else "warn", username=user.username)

    problem = None
    if not c.control:
        problem = "Control actions are turned off for this integration. Tick “Allow control actions” in its settings first."
    elif act.confirm == "yes" and form.get("confirm") != "yes":
        problem = f"{act.label} needs confirming. Use the button again and confirm in the dialog."
    elif act.confirm == "typed":
        expect = node if act.scope == "node" else str(params.get("vmid"))
        if str(form.get("confirm_text") or "").strip() != expect:
            problem = f"To {act.label.lower()}, type {expect} in the confirmation box."
    if problem:
        flash(request, problem, "warn")
        return back(back_to)
    try:
        result = await asyncio.to_thread(rpc, request, c, name, params, True, 90.0)
    except RpcError as exc:
        await asyncio.to_thread(log_it, False, str(exc))
        flash(request, f"{act.label} failed: {exc}", "bad")
        return back(back_to)
    upid = result.get("upid")
    await asyncio.to_thread(log_it, True, (result.get("message") or "done") + (f" (task {upid})" if upid else ""))
    flash(request, result.get("message") or f"{act.label} sent.")
    if name == "delete" and back_to.startswith(f"/hypervisors/{iid}/guest/"):
        back_to = "/hypervisors"
    if upid:
        back_to = re.sub(r"[?&]task=[^&]*", "", back_to)
        back_to += ("&" if "?" in back_to else "?") + "task=" + quote(upid, safe="")
    return back(back_to)


# ------------------------------------------------------------------ text console
@router.get("/hypervisors/console", response_class=HTMLResponse)
def console_page(request: Request, i: int, node: str, type: str = "", vmid: int | None = None):
    if not _is_admin(request):
        raise HTTPException(403, "Only admins can open a console.")
    from .themes import theme_for
    c = cluster_or_404(request, i)
    if not NODE_RE.match(node) or (type and (type not in GUEST_TYPES or not vmid)):
        raise HTTPException(400, "Bad console target")
    row = c.find(type, vmid) if type else None
    label = (row or {}).get("name") or (f"{type} {vmid}" if type else f"{node} shell")
    error = None
    if not c.control:
        error = "Consoles are a control action. Tick “Allow control actions” on this integration first."
    elif not c.connected:
        error = f"Poller {c.poller_name or '(none)'} is not connected."
    elif "pveterm" not in c.poller_features:
        error = outdated_poller_message(c.poller_name or "the poller", "Proxmox consoles")
    with st(request).db.session() as s:
        theme = theme_for(s, request.state.user)
    novnc = None
    if c.web_url and type:
        novnc = (f"{c.web_url}/?console={'kvm' if type == 'qemu' else 'lxc'}&novnc=1&vmid={vmid}&node={quote(node)}"
                 f"&vmname={quote(label)}&resize=scale")
    elif c.web_url:
        novnc = f"{c.web_url}/?console=shell&novnc=1&node={quote(node)}&resize=scale"
    return st(request).templates.TemplateResponse(request, "hv_console.html", {
        "c": c, "label": label, "node": node, "vtype": type or None, "vmid": vmid, "error": error, "theme": theme, "novnc": novnc,
        "target": {"integration": c.id, "node": node, "type": type or None, "vmid": vmid}})


@router.websocket("/api/poller/ws/pveconsole")
async def pve_console_ws(ws: WebSocket):
    """Browser side of a Proxmox text console. Text frames are JSON control messages; binary frames are terminal bytes."""
    user = await asyncio.to_thread(_ws_user, ws)
    if user is None or user.role != "admin" or not _same_origin(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    ip = ws.headers.get("x-real-ip") or (ws.client.host if ws.client else None)
    try:
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), 120))
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect, RuntimeError, KeyError):
        await ws.close()
        return
    try:
        await _console(ws, user.username, ip, hello)
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def _console(ws: WebSocket, who: str, ip: str | None, hello: dict) -> None:
    state = ws.app.state.lw

    def load() -> Cluster | None:
        with state.db.session() as s:
            i = s.get(Integration, int(hello.get("integration") or 0), options=[selectinload(Integration.poller)])
            if i is None or i.kind != "proxmox":
                return None
            return Cluster(i, state.vault.open(i.config_enc), bool(i.poller_id and i.poller_id in state.hub.conns))

    def log_it(action: str, detail: str) -> None:
        with state.db.session() as s:
            audit(s, who, ip, action, detail)

    c = await asyncio.to_thread(load)
    node, vtype, vmid = str(hello.get("node") or ""), hello.get("type") or None, hello.get("vmid")
    if c is None:
        await _send(ws, "error", text="No such Proxmox integration.")
        return
    if not NODE_RE.match(node) or (vtype is not None and (vtype not in GUEST_TYPES or not str(vmid or "").isdigit())):
        await _send(ws, "error", text="Bad console target.")
        return
    if not c.control:
        await _send(ws, "error", text="Control actions are turned off for this integration.")
        return
    if not c.connected:
        await _send(ws, "error", text=f"Poller {c.poller_name or '(none)'} is not connected.")
        return
    if "pveterm" not in c.poller_features:
        await _send(ws, "error", text=outdated_poller_message(c.poller_name or "the poller", "Proxmox consoles"))
        return
    where = (f"{'VM' if vtype == 'qemu' else 'container'} {vmid} on {node}" if vtype else f"shell on node {node}") + f" ({c.name})"
    cols, rows = _size(hello)
    await _send(ws, "status", text=f"Asking poller {c.poller_name} to open the Proxmox console…")
    try:
        tws, done = await state.hub.open_tunnel(c.poller_id, message={
            "type": "pve_term_open", "integration_id": c.id, "node": node, "vmtype": vtype,
            "vmid": int(vmid) if vtype else None, "cols": cols, "rows": rows})
    except TunnelError as exc:
        await asyncio.to_thread(log_it, "Proxmox console failed", f"{where}: {exc}")
        await _send(ws, "error", text=str(exc))
        return
    await asyncio.to_thread(log_it, "opened Proxmox console", where)
    await _send(ws, "ready", text=f"Connected to {where}")
    started, last = time.monotonic(), [time.monotonic()]
    typed = shown = 0

    async def from_poller() -> str:
        nonlocal shown
        while True:
            msg = await tws.receive()
            if msg["type"] == "websocket.disconnect":
                return "the console ended"
            if msg.get("bytes"):
                shown += len(msg["bytes"])
                last[0] = time.monotonic()
                await ws.send_bytes(msg["bytes"])

    async def from_browser() -> str:
        nonlocal typed
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                return "window closed"
            if msg.get("bytes"):
                typed += len(msg["bytes"])
                last[0] = time.monotonic()
                await tws.send_bytes(msg["bytes"])
            elif msg.get("text"):
                try:
                    ctl = json.loads(msg["text"])
                except ValueError:
                    continue
                if ctl.get("type") == "resize":
                    c2, r2 = _size(ctl)
                    await tws.send_text(json.dumps({"type": "resize", "cols": c2, "rows": r2}))
                elif ctl.get("type") == "close":
                    return "closed by the user"

    async def watchdog() -> str:
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            if now - last[0] > IDLE_TIMEOUT:
                return f"idle for {IDLE_TIMEOUT // 60} minutes"
            if now - started > MAX_SESSION:
                return f"reached the {MAX_SESSION // 3600} hour limit"

    tasks = [asyncio.create_task(x) for x in (from_poller(), from_browser(), watchdog())]
    reason = "closed"
    try:
        finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        try:
            reason = finished.pop().result()
        except (WebSocketDisconnect, RuntimeError):
            reason = "window closed"
        except Exception as exc:
            reason = f"{exc.__class__.__name__}: {exc}"
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        done.set()
    mins = (time.monotonic() - started) / 60
    await asyncio.to_thread(log_it, "closed Proxmox console", f"{where}, {mins:.0f} min, {typed} bytes typed, {shown} bytes shown ({reason})")
    await _send(ws, "closed", text=reason)
