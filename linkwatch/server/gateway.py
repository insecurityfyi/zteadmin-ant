"""Poller gateway: enrollment and the long-lived WebSocket each poller opens to the server."""
from __future__ import annotations

import asyncio
import json
import logging
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


class EnrollError(Exception):
    pass


class Hub:
    def __init__(self, db, vault, notifier, default_interval: int):
        self.db, self.vault, self.notifier = db, vault, notifier
        self.default_interval = default_interval
        self.conns: dict[int, WebSocket] = {}
        self.loop: asyncio.AbstractEventLoop | None = None

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
        with self.db.session() as s:
            devices = []
            for d in s.scalars(select(Device).where(Device.poller_id == poller_id, Device.disabled.is_(False))):
                if d.integration_id is not None and d.source not in ("snmp", "ping"):
                    continue
                if not d.ip:
                    continue
                snmp = self.vault.open(d.snmp_profile.config_enc) if d.snmp_profile else None
                devices.append({"id": d.id, "ip": d.ip, "hostname": d.hostname, "ping": d.ping, "snmp": snmp})
            integrations = []
            for i in s.scalars(select(Integration).where(Integration.poller_id == poller_id, Integration.enabled.is_(True))):
                cls = REGISTRY.get(i.kind)
                if cls and cls.runs_on == "poller":
                    integrations.append({"id": i.id, "kind": i.kind, "config": self.vault.open(i.config_enc)})
            return {"type": "config", "interval": self.interval(s), "devices": devices, "integrations": integrations}

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

    def send_soon(self, poller_id: int | None, message: dict) -> bool:
        ws = self.conns.get(poller_id or 0)
        if ws is None or self.loop is None:
            return False
        asyncio.run_coroutine_threadsafe(ws.send_text(json.dumps(message)), self.loop)
        return True

    # websocket --------------------------------------------------------------
    def _touch(self, poller_id: int, **fields) -> None:
        with self.db.session() as s:
            p = s.get(Poller, poller_id)
            if p:
                p.last_seen = utcnow()
                for k, v in fields.items():
                    if v is not None:
                        setattr(p, k, v)

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
        try:
            await self.push_config(poller.id)
            while True:
                msg = json.loads(await ws.receive_text())
                t = msg.get("type")
                if t == "hello":
                    await asyncio.to_thread(self._touch, poller.id, version=str(msg.get("version") or "")[:32] or None,
                                            hostname=str(msg.get("hostname") or "")[:255] or None)
                elif t == "results":
                    await asyncio.to_thread(self._ingest, poller.id, msg)
                    await ws.send_text(json.dumps({"type": "ack", "batch_id": msg.get("batch_id")}))
                elif t in ("discovery_progress", "discovery_result"):
                    await asyncio.to_thread(self._discovery, poller.id, msg)
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
            log.info("Poller %s disconnected", poller.name)
