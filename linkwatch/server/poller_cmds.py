"""Commands pushed to pollers from the Pollers page, the poller naming scheme, and factory reset.

Reload config
    The server sends the poller's configuration again, then asks it (rpc ``status``) what it now holds. The command
    passes when the poller reports the same number of devices, local APIs and path probes that it was sent.

Update
    A poller runs in a container and can't replace its own image, so ``install-poller.sh`` also installs a small
    helper on the host: a systemd path unit that watches ``control/update.request`` in the poller's volume. The
    poller writes that file (rpc ``update``), the helper runs the install script again (pull the latest image,
    recreate the container, wait for it to connect) and writes ``control/update.result``. The new container sends
    that result up as ``update_result``; the command passes when it reports success, and shows the version and build
    the poller came back with. No result within ``UPDATE_TIMEOUT`` fails it.

Factory reset
    The poller deletes its key, spool and update state and goes back to waiting for an enrollment token (rpc
    ``factory_reset``); the server then deletes its record.
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .gateway import RpcError, update_command
from .models import Poller, PollerCommand, utcnow

log = logging.getLogger("linkwatch.poller_cmds")

KINDS = {"reload": "Reload config", "update": "Update"}
RELOAD_TIMEOUT = 30.0
ACCEPT_TIMEOUT = 30.0
UPDATE_TIMEOUT = 600.0          # pulling an image on a slow line can take a while
RESET_TIMEOUT = 30.0
BASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$")


class CommandFailed(Exception):
    pass


# ------------------------------------------------------------------ naming
def base_name_problem(base: str) -> str | None:
    if not base:
        return None
    if not BASE_NAME.match(base) or base.endswith("."):
        return ("Use up to 60 letters, digits, dots, dashes or underscores, starting with a letter or digit "
                "and not ending with a dot, e.g. poller-hq.")
    return None


def next_poller_name(s: Session, base: str) -> str:
    """``<base>.N`` with the lowest N (from 1) that no poller uses."""
    pat = re.compile(rf"^{re.escape(base)}\.(\d+)$")
    used = {int(m.group(1)) for name in s.scalars(select(Poller.name).where(Poller.name.like(f"{base}.%")))
            if (m := pat.match(name))}
    n = 1
    while n in used:
        n += 1
    return f"{base}.{n}"


def describe(p: Poller | None) -> str | None:
    if p is None or not p.version:
        return None
    return f"v{p.version}" + (f" ({p.build})" if p.build else "")


# ------------------------------------------------------------------ commands
def expire_stale(s: Session) -> None:
    """Fail commands still pending long after their timeout (the server restarted while it waited)."""
    now = utcnow()
    for c in s.scalars(select(PollerCommand).where(PollerCommand.state == "pending")):
        limit = (UPDATE_TIMEOUT + ACCEPT_TIMEOUT if c.kind == "update" else RELOAD_TIMEOUT) + 120
        if c.requested_at < now - timedelta(seconds=limit):
            c.state, c.finished_at = "failed", now
            c.detail = "No result. The server restarted while it was waiting; send the command again."


def latest(s: Session) -> dict[int, PollerCommand]:
    """The newest command of each poller."""
    ids = select(func.max(PollerCommand.id)).group_by(PollerCommand.poller_id)
    return {c.poller_id: c for c in s.scalars(select(PollerCommand).where(PollerCommand.id.in_(ids)))}


def command_json(c: PollerCommand | None) -> dict | None:
    if c is None:
        return None
    return {"id": c.id, "kind": c.kind, "label": KINDS.get(c.kind, c.kind), "state": c.state, "detail": c.detail,
            "username": c.username, "requested_at": c.requested_at.isoformat() + "Z",
            "finished_at": c.finished_at.isoformat() + "Z" if c.finished_at else None, "before": c.before, "after": c.after}


def start(state, poller_ids: list[int], kind: str, username: str | None) -> list[str]:
    """Record a command for each poller and run them in the background. Returns the poller names it went to.

    Must be called on the event loop (from an async route)."""
    hub = state.hub
    hub.loop = hub.loop or asyncio.get_running_loop()
    started: list[tuple[int, int]] = []
    names: list[str] = []
    with state.db.session() as s:
        for p in s.scalars(select(Poller).where(Poller.id.in_(poller_ids), Poller.revoked.is_(False)).order_by(Poller.name)):
            c = PollerCommand(poller_id=p.id, kind=kind, username=username, before=describe(p))
            s.add(c)
            s.flush()
            started.append((c.id, p.id))
            names.append(p.name)
    for cid, pid in started:
        task = asyncio.get_running_loop().create_task(run(state, cid, pid, kind))
        hub.cmd_tasks.add(task)
        task.add_done_callback(hub.cmd_tasks.discard)
    return names


def _finish(state, cid: int, ok: bool, detail: str, after: str | None = None) -> None:
    from . import events
    with state.db.session() as s:
        c = s.get(PollerCommand, cid)
        if c is None:
            return
        c.state, c.detail, c.finished_at = ("ok" if ok else "failed"), detail[:1000], utcnow()
        c.after = after
        p = s.get(Poller, c.poller_id)
        events.log(s, "poller", f"{KINDS.get(c.kind, c.kind)} on {p.name if p else 'a poller'} "
                                f"{'passed' if ok else 'failed'}: {detail}", "ok" if ok else "warn", username=c.username)


def _poller(state, pid: int) -> tuple[str, list[str], str | None]:
    with state.db.session() as s:
        p = s.get(Poller, pid)
        if p is None:
            raise CommandFailed("The poller no longer exists.")
        return p.name, list(p.features or []), describe(p)


async def run(state, cid: int, pid: int, kind: str) -> None:
    try:
        if kind == "reload":
            detail, after = await run_reload(state, pid)
        else:
            detail, after = await run_update(state, pid, cid)
        await asyncio.to_thread(_finish, state, cid, True, detail, after)
    except (CommandFailed, RpcError) as exc:
        await asyncio.to_thread(_finish, state, cid, False, str(exc))
    except Exception as exc:  # noqa: BLE001
        log.exception("Poller command %s failed", cid)
        await asyncio.to_thread(_finish, state, cid, False, f"{exc.__class__.__name__}: {exc}")


async def run_reload(state, pid: int) -> tuple[str, str | None]:
    hub = state.hub
    name, feats, _ = await asyncio.to_thread(_poller, state, pid)
    if pid not in hub.conns:
        raise CommandFailed("The poller is not connected.")
    cfg = await asyncio.to_thread(hub.build_config, pid)
    if not await hub.send(pid, cfg):
        raise CommandFailed("The poller disconnected.")
    if "commands" not in feats:
        raise CommandFailed("Sent the configuration, but this poller's image is too old to confirm it. "
                            f"Update it (on the host: {update_command(name)}), then reload again.")
    got = await hub.call(pid, {"op": "status"}, RELOAD_TIMEOUT)
    want = {"devices": len(cfg["devices"]), "integrations": len(cfg["integrations"]), "probes": len(cfg.get("probes") or [])}
    words = {"devices": "devices", "integrations": "local APIs", "probes": "path probes"}
    wrong = [f"{got.get(k)} {words[k]} (sent {v})" for k, v in want.items() if got.get(k) != v]
    if wrong:
        raise CommandFailed("The poller didn't apply the configuration: it reports " + ", ".join(wrong) + ".")
    after = f"v{got.get('version')}" + (f" ({got['build']})" if got.get("build") else "")
    return (f"Applied: {want['devices']} devices, {want['integrations']} local APIs, {want['probes']} path probes.", after)


async def run_update(state, pid: int, cid: int) -> tuple[str, str | None]:
    hub = state.hub
    name, feats, before = await asyncio.to_thread(_poller, state, pid)
    if pid not in hub.conns:
        raise CommandFailed("The poller is not connected.")
    if "self_update" not in feats:
        raise CommandFailed("This poller's host doesn't have a working update helper yet (not installed, or the poller "
                            "can't write to its control folder). Run this once on the host, after which Update works "
                            f"from here: {update_command(name)}")
    req = f"u{cid}-{secrets.token_hex(6)}"
    fut: asyncio.Future = asyncio.get_running_loop().create_future()
    hub.update_waiters[req] = (pid, fut)
    try:
        await hub.call(pid, {"op": "update", "request": req}, ACCEPT_TIMEOUT)
        try:
            msg = await asyncio.wait_for(fut, UPDATE_TIMEOUT)
        except asyncio.TimeoutError:
            raise CommandFailed(f"No result from the poller host within {UPDATE_TIMEOUT / 60:.0f} minutes. On the host, "
                                "check: journalctl -u linkwatch-poller-helper") from None
    finally:
        hub.update_waiters.pop(req, None)
    if not msg.get("ok"):
        err = str(msg.get("error") or "no detail").strip()
        raise CommandFailed(f"The update failed on the host: {err}"[:1000])
    _, _, after = await asyncio.to_thread(_poller, state, pid)
    image = str(msg.get("image") or "")[:24]
    if after and after != before:
        detail = f"Updated from {before or 'an unknown version'} to {after}."
    elif msg.get("changed"):
        detail = f"Pulled a new image and restarted ({after or 'version unknown'})."
    else:
        detail = f"Already on the latest image ({after or 'version unknown'}); restarted and reconnected."
    if image:
        detail += f" Image {image}."
    return detail, after


# ------------------------------------------------------------------ factory reset
async def factory_reset(state, pid: int) -> str | None:
    """Tell a connected poller to wipe its enrollment. Returns None on success, or why it failed."""
    hub = state.hub
    if pid not in hub.conns:
        return "The poller is not connected."
    try:
        await hub.call(pid, {"op": "factory_reset"}, RESET_TIMEOUT)
    except RpcError as exc:
        return str(exc)
    return None
