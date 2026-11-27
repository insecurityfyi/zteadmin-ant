"""Poller gateway: enrollment and the long-lived WebSocket each poller opens to the server."""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import shlex
from datetime import timedelta
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..integrations import REGISTRY
from .db import get_setting
from .ingest import ingest_batch
from .models import Device, DiscoveryJob, EnrollToken, Integration, Poller, utcnow
from .security import new_secret, sha256

log = logging.getLogger("linkwatch.gateway")


PUBLIC_URL = ""      # set by create_app, so update commands can name the server


def update_command(name: str | None = None) -> str:
    """The one-line poller update. It names the server so it also works on pollers that were started by hand."""
    cmd = "curl -fsSL https://raw.githubusercontent.com/insecurityfyi/zteadmin-ant/main/deploy/install-poller.sh | sudo bash"
    if PUBLIC_URL:
        cmd += f" -s -- --server {PUBLIC_URL}"
        if name:
            cmd += f" --name {shlex.quote(name)}"
    return cmd


def outdated_poller_message(poller: str, label: str) -> str:
    return (f"Poller {poller} is running an older image that doesn't support {label}. Update it on the poller host with: "
            f"{update_command(poller if poller != 'the poller' else None)} "
            "(no token needed: it pulls the latest image and keeps the poller's key), then press Sync now.")


class EnrollError(Exception):
    pass


class TunnelError(Exception):
    pass


class RpcError(Exception):
    """A request to a poller failed: not connected, too old, timed out, or the poller reported an error."""


MAX_TUNNELS_PER_POLLER = 8


class Hub:
    def __init__(self, db, vault, notifier, default_interval: int):
        self.db, self.vault, self.notifier = db, vault, notifier
        self.default_interval = default_interval
        self.conns: dict[int, WebSocket] = {}
        self.loop: asyncio.AbstractEventLoop | None = None
        # reverse tunnels: the server asks a poller to open one, the poller dials back in on its own WebSocket
        self.pending_tunnels: dict[str, tuple[int, asyncio.Future]] = {}
        self.open_tunnels: dict[int, int] = {}
        self.tests: dict[str, asyncio.Future] = {}          # custom OID "Test" requests waiting for a poller's answer
        # requests the server sends a poller and waits on (Proxmox actions and lookups)
        self.pending_rpcs: dict[str, tuple[int, asyncio.Future]] = {}

    def interval(self, s) -> int:
        try:
            return max(60, int(get_setting(s, "poll_interval", str(self.default_interval))))
        except ValueError:
            return self.default_interval

    # enrollment -----------------------------------------------------------
    def enroll(self, token: str, name: str, hostname: str | None, version: str | None, ip: str | None) -> dict[str, Any]:
        with self.db.session() as s:
            row = s.scalar(select(EnrollToken).where(EnrollToken.token_hash == sha256(token or "")))
            if row is None or row.used_at is not None or row.expires_at < utcnow():
                raise EnrollError("The enrollment token is invalid, used or expired. Create a new one on the Pollers page.")
            base = (name or hostname or "poller").strip()[:100] or "poller"
            final, n = base, 2
            while s.scalar(select(Poller.id).where(Poller.name == final)):
                final, n = f"{base}-{n}", n + 1
            key = new_secret("lwp", 32)
            poller = Poller(name=final, key_hash=sha256(key), hostname=hostname, version=version, last_ip=ip)
            s.add(poller)
            s.flush()
            row.used_at, row.poller_id = utcnow(), poller.id
            return {"poller_id": poller.id, "name": final, "key": key}

    def authenticate(self, auth_header: str | None) -> Poller | None:
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        with self.db.session() as s:
            p = s.scalar(select(Poller).where(Poller.key_hash == sha256(auth_header[7:].strip())))
            return None if p is None or p.revoked else p

    # config -----------------------------------------------------------------
    def build_config(self, poller_id: int) -> dict[str, Any]:
        from .oids import enabled_defs, poller_defs
        with self.db.session() as s:
            devices = []
            defs = enabled_defs(s)
            for d in s.scalars(select(Device).where(Device.poller_id == poller_id, Device.disabled.is_(False))):
                if d.integration_id is not None and d.source not in ("snmp", "ping"):
                    continue
                if not d.ip:
                    continue
                snmp = self.vault.open(d.snmp_profile.config_enc) if d.snmp_profile else None
                dev = {"id": d.id, "ip": d.ip, "hostname": d.hostname, "ping": d.ping, "snmp": snmp}
                if snmp:
                    dev["oids"] = poller_defs(defs, d)
                devices.append(dev)
            integrations = []
            for i in s.scalars(select(Integration).where(Integration.poller_id == poller_id, Integration.enabled.is_(True))):
                cls = REGISTRY.get(i.kind)
                if cls and cls.runs_on == "poller":
                    integrations.append({"id": i.id, "kind": i.kind, "config": self.vault.open(i.config_enc)})
            from .paths import poller_probes
            return {"type": "config", "interval": self.interval(s), "devices": devices, "integrations": integrations,
                    "probes": poller_probes(s, poller_id)}

    async def push_config(self, poller_id: int) -> None:
        ws = self.conns.get(poller_id)
        if ws is None:
            return
        cfg = await asyncio.to_thread(self.build_config, poller_id)
        try:
            await ws.send_text(json.dumps(cfg))
        except Exception:
            pass

    def push_config_soon(self, poller_id: int | None) -> None:
        """Callable from sync request handlers (thread pool)."""
        if poller_id and self.loop and poller_id in self.conns:
            asyncio.run_coroutine_threadsafe(self.push_config(poller_id), self.loop)

    def push_all_soon(self) -> None:
        """Send fresh config to every connected poller (after a change that affects all of them)."""
        for pid in list(self.conns):
            self.push_config_soon(pid)

    async def snmp_test(self, poller_id: int, message: dict, timeout: float = 30.0) -> dict:
        """Ask a poller to read an OID from a device now and wait for the answer."""
        ws = self.conns.get(poller_id)
        if ws is None:
            return {"error": "That device's poller is not connected."}
        req = secrets.token_hex(8)
        fut = asyncio.get_running_loop().create_future()
        self.tests[req] = fut
        try:
            await ws.send_text(json.dumps({**message, "type": "snmp_test", "req": req}))
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return {"error": "No answer from the poller within 30 seconds."}
        finally:
            self.tests.pop(req, None)

    def send_soon(self, poller_id: int | None, message: dict) -> bool:
        ws = self.conns.get(poller_id or 0)
        if ws is None or self.loop is None:
            return False
        asyncio.run_coroutine_threadsafe(ws.send_text(json.dumps(message)), self.loop)
        return True

    # requests to a poller ---------------------------------------------------
    async def call(self, poller_id: int, payload: dict, timeout: float = 60.0) -> dict:
        """Send ``{"type": "rpc", "id": ..., **payload}`` to a poller and wait for its ``rpc_result``.

        Returns the result dict; raises RpcError when the poller is offline, times out or reports an error."""
        ws = self.conns.get(poller_id)
        if ws is None:
            raise RpcError("The poller is not connected.")
        rid = secrets.token_urlsafe(16)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending_rpcs[rid] = (poller_id, fut)
        try:
            await ws.send_text(json.dumps({**payload, "type": "rpc", "id": rid}))
            reply = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise RpcError(f"The poller did not answer within {timeout:.0f} s.") from None
        except RuntimeError:
            raise RpcError("The poller disconnected.") from None
        finally:
            self.pending_rpcs.pop(rid, None)
        if not reply.get("ok"):
            raise RpcError(str(reply.get("error") or "The poller could not complete the request.")[:1000])
        result = reply.get("result")
        return result if isinstance(result, dict) else {}

    def call_sync(self, poller_id: int, payload: dict, timeout: float = 60.0) -> dict:
        """``call`` from a sync request handler (thread pool)."""
        if self.loop is None or poller_id not in self.conns:
            raise RpcError("The poller is not connected.")
        fut = asyncio.run_coroutine_threadsafe(self.call(poller_id, payload, timeout), self.loop)
        try:
            return fut.result(timeout + 5)
        except TimeoutError:
            fut.cancel()
            raise RpcError(f"The poller did not answer within {timeout:.0f} s.") from None

    def _rpc_result(self, poller_id: int, msg: dict) -> None:
        entry = self.pending_rpcs.get(str(msg.get("id") or ""))
        if entry is not None and entry[0] == poller_id and not entry[1].done():
            entry[1].set_result(msg)

    # reverse tunnels --------------------------------------------------------
    async def open_tunnel(self, poller_id: int, host: str = "", port: int = 0, timeout: float = 20.0,
                          message: dict | None = None) -> tuple[WebSocket, asyncio.Event]:
        """Ask a connected poller for a TCP connection to host:port on its network.

        The poller connects to host:port itself and then opens a second outbound WebSocket to
        /api/poller/ws/tunnel/<sid> that carries the raw bytes, so nothing ever connects in to the poller's
        network. Returns that WebSocket (after the poller confirmed the TCP connection) and an Event to set when
        the caller is done with it.

        ``message`` replaces the ``tunnel_open`` request with another kind (e.g. ``pve_term_open``, where the poller
        connects to a Proxmox console itself); the poller answers on the tunnel socket the same way."""
        ws = self.conns.get(poller_id)
        if ws is None:
            raise TunnelError("The poller is not connected.")
        if self.open_tunnels.get(poller_id, 0) >= MAX_TUNNELS_PER_POLLER:
            raise TunnelError(f"This poller already has {MAX_TUNNELS_PER_POLLER} sessions open. Close one first.")
        sid = secrets.token_urlsafe(24)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending_tunnels[sid] = (poller_id, fut)
        try:
            req = {**message, "sid": sid} if message else {"type": "tunnel_open", "sid": sid, "host": host, "port": port}
            await ws.send_text(json.dumps(req))
            tws, done = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise TunnelError(f"The poller did not open the tunnel within {timeout:.0f} s.") from None
        finally:
            self.pending_tunnels.pop(sid, None)
        try:
            first = await asyncio.wait_for(tws.receive_text(), timeout)
            reply = json.loads(first)
        except (asyncio.TimeoutError, ValueError, KeyError, RuntimeError, WebSocketDisconnect):
            done.set()
            raise TunnelError("The poller closed the tunnel before it was ready.") from None
        if not reply.get("ok"):
            done.set()
            raise TunnelError(str(reply.get("error") or "The poller could not open the connection.")[:300])
        self.open_tunnels[poller_id] = self.open_tunnels.get(poller_id, 0) + 1

        async def release() -> None:
            await done.wait()
            self.open_tunnels[poller_id] = max(0, self.open_tunnels.get(poller_id, 1) - 1)
        asyncio.get_running_loop().create_task(release())
        return tws, done

    async def serve_tunnel(self, ws: WebSocket, poller: Poller, sid: str) -> None:
        """The poller's side of a tunnel: hand the socket to whoever asked for it and hold it until they finish."""
        entry = self.pending_tunnels.get(sid)
        if entry is None or entry[0] != poller.id or entry[1].done():
            await ws.close(code=1008)
            return
        await ws.accept()
        done = asyncio.Event()
        entry[1].set_result((ws, done))
        await done.wait()
        try:
            await ws.close()
        except Exception:
            pass

    # websocket --------------------------------------------------------------
    def _event(self, message: str, severity: str) -> None:
        from . import events
        try:
            with self.db.session() as s:
                events.log(s, "poller", message, severity)
        except Exception:
            log.exception("Could not write the event log")

    def _check_support(self, poller_id: int, kinds: list[str] | None) -> None:
        """Flag integrations this poller's image is too old to run, instead of a generic error from the poller."""
        with self.db.session() as s:
            p = s.get(Poller, poller_id)
            for i in s.scalars(select(Integration).where(Integration.poller_id == poller_id, Integration.enabled.is_(True))):
                cls = REGISTRY.get(i.kind)
                if cls is None or cls.runs_on != "poller":
                    continue
                if kinds is None or i.kind not in kinds:
                    i.status, i.last_error = "error", outdated_poller_message(p.name if p else "the poller", cls.label)

    def _touch(self, poller_id: int, **fields) -> None:
        with self.db.session() as s:
            p = s.get(Poller, poller_id)
            if p:
                p.last_seen = utcnow()
                for k, v in fields.items():
                    if v is not None:
                        setattr(p, k, v)

    def _set_features(self, poller_id: int, feats: list[str]) -> None:
        with self.db.session() as s:
            p = s.get(Poller, poller_id)
            if p:
                p.features = feats

    def _ingest(self, poller_id: int, batch: dict) -> None:
        with self.db.session() as s:
            alerter = ingest_batch(s, poller_id, batch)
            p = s.get(Poller, poller_id)
            if p:
                p.last_seen = utcnow()
                if batch.get("cycle_ms") is not None and not batch.get("partial"):
                    p.last_cycle_ms = int(batch["cycle_ms"])
            # prune duplicate-detection memory after a week
            from .models import ProcessedBatch
            s.query(ProcessedBatch).filter(ProcessedBatch.at < utcnow() - timedelta(days=7)).delete()
        if alerter:
            self.notifier.dispatch(alerter.events)

    def _discovery(self, poller_id: int, msg: dict) -> None:
        if self._discovery_update(poller_id, msg):
            self.push_config_soon(poller_id)   # a saved scan auto-added devices

    def _discovery_update(self, poller_id: int, msg: dict) -> bool:
        """Store progress or results; returns True when devices were auto-added."""
        added = False
        with self.db.session() as s:
            job = s.get(DiscoveryJob, int(msg.get("job_id") or 0))
            if job is None or job.poller_id != poller_id or job.status in ("done", "failed"):
                return False
            job.total = int(msg.get("total") or job.total or 0)
            job.scanned = int(msg.get("scanned") or 0)
            if msg.get("type") == "discovery_progress":
                job.status = "running"
                return False
            if msg.get("error"):
                job.status, job.error = "failed", str(msg["error"])[:1000]
            else:
                job.status = "done"
                clean = []
                for r in (msg.get("found") or [])[:5000]:
                    if not isinstance(r, dict) or not r.get("ip"):
                        continue
                    clean.append({k: (str(r.get(k))[:500] if r.get(k) is not None else None)
                                  for k in ("ip", "sys_name", "sys_descr", "sys_object_id")}
                                 | {"rtt_ms": r.get("rtt_ms") if isinstance(r.get("rtt_ms"), (int, float)) else None,
                                    "profile_id": r.get("profile_id") if isinstance(r.get("profile_id"), int) else None})
                job.results = clean
                if job.rule_id:
                    from .discovery import auto_add
                    added = auto_add(s, job) > 0
            job.finished_at = utcnow()
        return added

    async def serve(self, ws: WebSocket, poller: Poller, client_ip: str | None) -> None:
        self.loop = asyncio.get_running_loop()
        old = self.conns.get(poller.id)
        if old is not None:
            try:
                await old.close(code=4000)
            except Exception:
                pass
        self.conns[poller.id] = ws
        await asyncio.to_thread(self._touch, poller.id, last_ip=client_ip)
        log.info("Poller %s connected from %s", poller.name, client_ip)
        await asyncio.to_thread(self._event, f"Poller {poller.name} connected from {client_ip or 'unknown address'}", "ok")
        try:
            await self.push_config(poller.id)
            while True:
                msg = json.loads(await ws.receive_text())
                t = msg.get("type")
                if t == "hello":
                    kinds = [str(k)[:32] for k in msg.get("integrations") or []][:50] or None
                    feats = [str(k)[:32] for k in msg.get("features") or []][:20]
                    await asyncio.to_thread(self._touch, poller.id, version=str(msg.get("version") or "")[:32] or None,
                                            hostname=str(msg.get("hostname") or "")[:255] or None, integrations=kinds)
                    await asyncio.to_thread(self._set_features, poller.id, feats)
                    await asyncio.to_thread(self._check_support, poller.id, kinds)
                elif t == "results":
                    await asyncio.to_thread(self._ingest, poller.id, msg)
                    await ws.send_text(json.dumps({"type": "ack", "batch_id": msg.get("batch_id")}))
                elif t in ("discovery_progress", "discovery_result"):
                    await asyncio.to_thread(self._discovery, poller.id, msg)
                elif t == "snmp_test_result":
                    fut = self.tests.get(str(msg.get("req") or ""))
                    if fut is not None and not fut.done():
                        fut.set_result(msg)
                elif t == "rpc_result":
                    self._rpc_result(poller.id, msg)
                elif t == "pong":
                    await asyncio.to_thread(self._touch, poller.id)
        except (WebSocketDisconnect, RuntimeError):
            pass
        except ValueError:
            log.warning("Poller %s sent invalid JSON; closing", poller.name)
            await ws.close(code=1003)
        finally:
            if self.conns.get(poller.id) is ws:
                del self.conns[poller.id]
                for rid, (pid, fut) in list(self.pending_rpcs.items()):
                    if pid == poller.id and not fut.done():
                        fut.set_exception(RuntimeError("disconnected"))
                await asyncio.to_thread(self._event, f"Poller {poller.name} disconnected", "warn")
            log.info("Poller %s disconnected", poller.name)
