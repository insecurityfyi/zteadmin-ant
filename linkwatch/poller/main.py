"""Linkwatch remote poller.

Runs inside your LAN. It only ever opens outbound connections:

1. First start: ``POST {LW_SERVER}/api/poller/enroll`` with the one-time
   enrollment token. The server answers with this poller's ID and a long
   random key, saved to ``{LW_DATA_DIR}/identity.json`` (mode 0600).
2. Then it holds a WebSocket open to ``wss://{server}/api/poller/ws``,
   authenticated with that key. The server pushes the device list and
   credentials down that socket; the poller pushes results up it.
3. Polling keeps running when the socket is down. Batches are spooled to disk
   and resent, in order, once the server is reachable again.

Environment:
    LW_SERVER        https://utilz.perrego.net
    LW_ENROLL_TOKEN  one-time token from the Pollers page (first start only)
    LW_POLLER_NAME   optional display name (defaults to the hostname)
    LW_DATA_DIR      /var/lib/linkwatch
    LW_CONCURRENCY   simultaneous device polls (default 32)
"""
from __future__ import annotations

import asyncio
import itertools
import json
import logging
import os
import random
import socket
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from .. import __version__
from ..common.discovery import TargetError, expand_targets
from ..integrations import IntegrationError, build
from .discover import scan
from .ping import ping
from .snmp import SnmpEngine, SnmpError, SnmpSession, poll_device
from .spool import Spool

log = logging.getLogger("linkwatch.poller")


_seq = itertools.count()


def new_batch_id() -> str:
    """Sortable by creation order (the spool resends in this order), unique across restarts."""
    return f"{int(time.time() * 1000):015d}-{next(_seq) % 1_000_000:06d}-{uuid.uuid4().hex[:6]}"


class Poller:
    def __init__(self, server: str, data_dir: Path, enroll_token: str | None = None,
                 name: str | None = None, concurrency: int = 32):
        self.server = server.rstrip("/")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.enroll_token = enroll_token
        self.name = name or socket.gethostname()
        self.spool = Spool(self.data_dir / "spool")
        self.sem = asyncio.Semaphore(concurrency)
        self.engine = SnmpEngine()
        self.devices: list[dict] = []
        self.integrations: list[dict] = []
        self.interval = 300
        self.ws: ClientConnection | None = None
        self.configured = asyncio.Event()
        self.wake = asyncio.Event()
        self.last_cycle_ms: int | None = None
        self._poll_now: set[int] = set()
        self.outbox: list[dict] = []   # discovery results waiting for a connection
        self.discovering: set[int] = set()

    # identity -------------------------------------------------------------
    @property
    def identity_file(self) -> Path:
        return self.data_dir / "identity.json"

    def load_identity(self) -> dict | None:
        try:
            return json.loads(self.identity_file.read_text())
        except (OSError, ValueError):
            return None

    async def enroll(self) -> dict:
        if not self.enroll_token:
            raise SystemExit("No identity yet and LW_ENROLL_TOKEN is not set. Create a token on the Pollers page.")
        async with httpx.AsyncClient(timeout=30) as http:
            resp = await http.post(f"{self.server}/api/poller/enroll", json={
                "token": self.enroll_token, "name": self.name, "hostname": socket.gethostname(), "version": __version__})
        if resp.status_code != 200:
            raise SystemExit(f"Enrollment failed (HTTP {resp.status_code}): {resp.text[:200]}")
        ident = resp.json()
        tmp = self.identity_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(ident))
        tmp.chmod(0o600)
        os.replace(tmp, self.identity_file)
        log.info("Enrolled as poller %s (%s)", ident["poller_id"], ident.get("name"))
        return ident

    @property
    def ws_url(self) -> str:
        base = self.server.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
        return f"{base}/api/poller/ws"

    # main loop ------------------------------------------------------------
    async def run(self) -> None:
        ident = self.load_identity() or await self.enroll()
        asyncio.create_task(self.schedule_loop())
        backoff = 2.0
        while True:
            try:
                async with connect(self.ws_url, additional_headers={"Authorization": f"Bearer {ident['key']}"},
                                   ping_interval=30, ping_timeout=30, max_size=32 * 2**20, open_timeout=20) as ws:
                    self.ws = ws
                    backoff = 2.0
                    log.info("Connected to %s", self.ws_url)
                    await ws.send(json.dumps({"type": "hello", "version": __version__, "hostname": socket.gethostname(),
                                              "spooled": len(self.spool)}))
                    for batch in self.spool.pending():
                        await ws.send(json.dumps(batch))
                    while self.outbox:
                        await ws.send(json.dumps(self.outbox[0]))
                        self.outbox.pop(0)
                    async for raw in ws:
                        await self.handle(json.loads(raw))
            except InvalidStatus as exc:
                code = exc.response.status_code
                if code in (401, 403):
                    log.error("Server refused this poller's key (HTTP %s). It may have been revoked; delete %s and re-enroll.",
                              code, self.identity_file)
                    backoff = 300.0
                else:
                    log.warning("Server answered HTTP %s", code)
            except (OSError, ConnectionClosed, asyncio.TimeoutError) as exc:
                log.warning("Connection lost: %s", exc.__class__.__name__)
            finally:
                self.ws = None
            await asyncio.sleep(backoff + random.uniform(0, backoff / 2))
            backoff = min(backoff * 2, 120.0)

    async def handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "config":
            self.devices = msg.get("devices", [])
            self.integrations = msg.get("integrations", [])
            self.interval = max(60, int(msg.get("interval", 300)))
            log.info("Config: %d devices, %d integrations, every %ds", len(self.devices), len(self.integrations), self.interval)
            first = not self.configured.is_set()
            self.configured.set()
            if first:
                self.wake.set()
        elif t == "ack":
            self.spool.ack(msg.get("batch_id", ""))
        elif t == "poll_now":
            self._poll_now.add(int(msg.get("device_id", 0)))
            self.wake.set()
        elif t == "discover":
            job = int(msg.get("job_id") or 0)
            if job and job not in self.discovering:
                self.discovering.add(job)
                asyncio.create_task(self.discover(msg))
        elif t == "ping" and self.ws:
            await self.ws.send(json.dumps({"type": "pong"}))

    async def send_or_queue(self, msg: dict, queue: bool = True) -> None:
        if self.ws:
            try:
                await self.ws.send(json.dumps(msg))
                return
            except ConnectionClosed:
                pass
        if queue:
            self.outbox.append(msg)

    async def discover(self, msg: dict) -> None:
        job = int(msg["job_id"])
        try:
            hosts = expand_targets(str(msg.get("targets") or ""))
            log.info("Discovery %s: scanning %d addresses with %d credential sets", job, len(hosts), len(msg.get("profiles") or []))

            async def progress(done: int, total: int) -> None:
                await self.send_or_queue({"type": "discovery_progress", "job_id": job, "scanned": done, "total": total}, queue=False)
            await progress(0, len(hosts))
            found = await scan(hosts, list(msg.get("profiles") or []), engine=self.engine, progress=progress)
            log.info("Discovery %s: %d of %d addresses answered", job, len(found), len(hosts))
            out = {"type": "discovery_result", "job_id": job, "scanned": len(hosts), "total": len(hosts), "found": found}
        except TargetError as exc:
            out = {"type": "discovery_result", "job_id": job, "error": str(exc)}
        except Exception as exc:
            log.exception("Discovery %s failed", job)
            out = {"type": "discovery_result", "job_id": job, "error": f"{exc.__class__.__name__}: {exc}"}
        finally:
            self.discovering.discard(job)
        await self.send_or_queue(out)

    async def schedule_loop(self) -> None:
        await self.configured.wait()
        next_full = 0.0
        while True:
            full = time.monotonic() >= next_full
            only = set(self._poll_now)
            self._poll_now.clear()
            self.wake.clear()
            if full:
                next_full = time.monotonic() + self.interval
            if full or only:
                try:
                    await self.cycle(only_devices=None if full else only)
                except Exception:  # never let one bad cycle stop polling
                    log.exception("Poll cycle failed")
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=max(1.0, next_full - time.monotonic()))
            except asyncio.TimeoutError:
                pass

    async def cycle(self, only_devices: set[int] | None = None) -> None:
        started = time.monotonic()
        devices = [d for d in self.devices if not only_devices or d["id"] in only_devices]
        items = list(await asyncio.gather(*(self.poll_one(d) for d in devices)))
        if not only_devices:
            items += await asyncio.gather(*(self.run_integration(i) for i in self.integrations))
        self.last_cycle_ms = int((time.monotonic() - started) * 1000)
        batch = {"type": "results", "batch_id": new_batch_id(), "cycle_ms": self.last_cycle_ms,
                 "partial": bool(only_devices), "items": items}
        self.spool.put(batch)
        log.info("Cycle done: %d items in %.1fs", len(items), self.last_cycle_ms / 1000)
        if self.ws:
            try:
                await self.ws.send(json.dumps(batch))
            except ConnectionClosed:
                pass  # stays in the spool; resent on reconnect

    async def poll_one(self, dev: dict) -> dict[str, Any]:
        async with self.sem:
            item: dict[str, Any] = {"kind": "device", "device_id": dev["id"], "ts": time.time(), "ok": False, "error": None}
            ping_task = asyncio.create_task(ping(dev["ip"])) if dev.get("ping", True) else None
            if dev.get("snmp"):
                try:
                    item.update(await poll_device(SnmpSession(dev["ip"], dev["snmp"], engine=self.engine)))
                    item["ok"] = True
                except SnmpError as exc:
                    item["error"] = f"SNMP: {exc}"
                except Exception as exc:  # malformed agent replies etc.
                    item["error"] = f"SNMP: {exc.__class__.__name__}: {exc}"
            if ping_task:
                item["ping"] = await ping_task
                if not dev.get("snmp"):
                    item["ok"] = bool(item["ping"] and item["ping"]["loss_pct"] < 100)
            return item

    async def run_integration(self, integ: dict) -> dict[str, Any]:
        item: dict[str, Any] = {"kind": "integration", "integration_id": integ["id"], "ts": time.time(), "ok": False, "error": None}

        def work():
            client = build(integ["kind"], integ["config"])
            try:
                return client.collect(), list(getattr(client, "errors", []) or [])
            finally:
                client.close()
        try:
            item["records"], item["warnings"] = await asyncio.to_thread(work)
            item["ok"] = True
        except IntegrationError as exc:
            item["error"] = str(exc)
        except Exception as exc:
            item["error"] = f"{exc.__class__.__name__}: {exc}"
        return item


def main() -> None:
    logging.basicConfig(level=os.environ.get("LW_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    server = os.environ.get("LW_SERVER")
    if not server:
        raise SystemExit("Set LW_SERVER, e.g. https://utilz.perrego.net")
    poller = Poller(server, Path(os.environ.get("LW_DATA_DIR", "/var/lib/linkwatch")),
                    enroll_token=os.environ.get("LW_ENROLL_TOKEN"), name=os.environ.get("LW_POLLER_NAME"),
                    concurrency=int(os.environ.get("LW_CONCURRENCY", "32")))
    asyncio.run(poller.run())


if __name__ == "__main__":
    main()
