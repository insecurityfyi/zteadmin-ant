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
    LW_TUNNEL        on (default) / off: allow SSH consoles through this poller (see tunnel.py)
    LW_TUNNEL_PORTS  ports a tunnel may reach (default 22,3389; "any" for all)
    LW_BUILD         image build id, set when the image is built (reported to the server)

Commands from the Pollers page (rpc ``status``, ``update``, ``factory_reset``): see linkwatch/server/poller_cmds.py.
Updates go through a helper on the host that watches ``{LW_DATA_DIR}/control`` (installed by install-poller.sh).
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import logging
import os
import random
import re
import shutil
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
from . import mtr, pveterm, tunnel
from .discover import scan
from .ping import ping
from .snmp import SnmpEngine, SnmpError, SnmpSession, poll_device
from .spool import Spool

# what the "Add SNMP" Test button reads to prove a set of credentials works
SYSTEM_OIDS = {"1.3.6.1.2.1.1.5.0": "sysName", "1.3.6.1.2.1.1.1.0": "sysDescr", "1.3.6.1.2.1.1.2.0": "sysObjectID",
               "1.3.6.1.2.1.1.3.0": "sysUpTime"}

log = logging.getLogger("linkwatch.poller")
BUILD = os.environ.get("LW_BUILD") or "dev"


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
        self.probes: list[dict] = []          # path probes (mtr) assigned to this poller
        self.probe_due: dict[int, float] = {}
        self.probe_wake = asyncio.Event()
        self.probe_sem = asyncio.Semaphore(4)
        self.probing: set[int] = set()
        self.key: str | None = None
        self.tunnels: set[asyncio.Task] = set()
        self.control = self.data_dir / "control"      # shared with the update helper on the host
        try:
            self.control.mkdir(exist_ok=True)
        except OSError:
            pass
        self.background: list[asyncio.Task] = []
        self.reset_done = asyncio.Event()
        self._result_sent: str | None = None
        self.result_poll = 3.0                     # seconds between looks at control/update.result

    # identity -------------------------------------------------------------
    @property
    def identity_file(self) -> Path:
        return self.data_dir / "identity.json"

    def load_identity(self) -> dict | None:
        try:
            return json.loads(self.identity_file.read_text())
        except (OSError, ValueError):
            return None

    @property
    def reset_file(self) -> Path:
        return self.data_dir / "factory-reset.json"

    def token_is_stale(self) -> bool:
        """After a factory reset the container may still carry the token it was first enrolled with (used, so it
        would only fail). Wait for a new one instead of retrying it."""
        try:
            marker = json.loads(self.reset_file.read_text())
        except (OSError, ValueError):
            return False
        return not self.enroll_token or marker.get("token_sha") == _sha(self.enroll_token)

    async def wait_for_enrollment(self) -> None:
        log.warning("This poller has been factory reset and is not enrolled. To enroll it again, create a token on the "
                    "Pollers page and run install-poller.sh --server URL --token enr_... on this host.")
        while True:
            await asyncio.sleep(3600)

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
        self.reset_file.unlink(missing_ok=True)
        log.info("Enrolled as poller %s (%s)", ident["poller_id"], ident.get("name"))
        return ident

    @property
    def ws_base(self) -> str:
        return self.server.replace("https://", "wss://", 1).replace("http://", "ws://", 1)

    @property
    def ws_url(self) -> str:
        return f"{self.ws_base}/api/poller/ws"

    # main loop ------------------------------------------------------------
    async def run(self) -> None:
        ident = self.load_identity()
        if ident is None and self.token_is_stale():
            await self.wait_for_enrollment()
        ident = ident or await self.enroll()
        self.key = ident["key"]
        self.background = [asyncio.create_task(self.schedule_loop()), asyncio.create_task(self.probe_loop()),
                           asyncio.create_task(self.watch_update_result())]
        backoff = 2.0
        while not self.reset_done.is_set():
            try:
                async with connect(self.ws_url, additional_headers={"Authorization": f"Bearer {ident['key']}"},
                                   ping_interval=30, ping_timeout=30, max_size=32 * 2**20, open_timeout=20) as ws:
                    self.ws = ws
                    backoff = 2.0
                    log.info("Connected to %s", self.ws_url)
                    from ..integrations import REGISTRY
                    await ws.send(json.dumps({"type": "hello", "version": __version__, "build": BUILD,
                                              "hostname": socket.gethostname(),
                                              "spooled": len(self.spool), "integrations": sorted(REGISTRY),
                                              "features": self.features()}))
                    self._result_sent = None        # (re)send the last update result on this connection
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
            if self.reset_done.is_set():
                break
            await asyncio.sleep(backoff + random.uniform(0, backoff / 2))
            backoff = min(backoff * 2, 120.0)
        await self.wait_for_enrollment()

    def features(self) -> list[str]:
        feats = ["custom_oids"]
        if mtr.available():
            feats.append("mtr")
        if tunnel.enabled():
            feats += ["ssh", "pveterm"]
        if tunnel.allows(3389):
            feats.append("rdp")
        feats += ["rpc", "snmp_probe", "commands", "factory_reset"]
        if self.helper_info():
            feats.append("self_update")
        return feats

    # commands from the Pollers page ------------------------------------------
    def helper_info(self) -> dict | None:
        """What install-poller.sh wrote about the update helper on the host, if it installed one."""
        try:
            info = json.loads((self.control / "helper.json").read_text())
        except (OSError, ValueError):
            return None
        return info if isinstance(info, dict) else None

    def status(self) -> dict:
        return {"version": __version__, "build": BUILD, "devices": len(self.devices), "integrations": len(self.integrations),
                "probes": len(self.probes), "configured": self.configured.is_set(), "interval": self.interval,
                "spooled": len(self.spool)}

    def request_update(self, req: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", req):
            raise IntegrationError("Invalid update request id.")
        if not self.helper_info():
            raise IntegrationError("This host has no update helper. Run install-poller.sh once on the host to add it.")
        tmp = self.control / ".update.request.tmp"
        tmp.write_text(req + "\n")
        os.replace(tmp, self.control / "update.request")      # the host's path unit fires on this file
        log.info("Asked the host to update this poller (request %s)", req)
        return {"accepted": True, **self.status()}

    def read_update_result(self) -> dict | None:
        try:
            res = json.loads((self.control / "update.result").read_text())
        except (OSError, ValueError):
            return None
        return res if isinstance(res, dict) and res.get("id") else None

    async def watch_update_result(self) -> None:
        """Send the host helper's result once per connection (the new container starts before the helper writes it)."""
        while True:
            res = self.read_update_result()
            if res and res["id"] != self._result_sent and self.ws:
                try:
                    await self.ws.send(json.dumps({**res, "type": "update_result"}))
                    self._result_sent = res["id"]
                except ConnectionClosed:
                    pass
            await asyncio.sleep(self.result_poll)

    def wipe(self) -> None:
        """Back to the state before enrollment: no key, no buffered results, no update state, no config in memory."""
        for name in ("identity.json", "identity.tmp"):
            (self.data_dir / name).unlink(missing_ok=True)
        shutil.rmtree(self.spool.dir, ignore_errors=True)
        for name in ("update.request", "update.result", ".update.request.tmp"):
            (self.control / name).unlink(missing_ok=True)
        marker = {"at": time.time(), "token_sha": _sha(self.enroll_token) if self.enroll_token else None}
        self.reset_file.write_text(json.dumps(marker))
        self.devices, self.integrations, self.key = [], [], None
        self.set_probes([])
        log.warning("Factory reset: deleted this poller's key, spool and update state")

    async def after_reset(self) -> None:
        self.reset_done.set()
        me = asyncio.current_task()
        for t in self.background + list(self.tunnels):
            if t is not me:
                t.cancel()
        if self.ws:
            try:
                await self.ws.close()
            except Exception:  # noqa: BLE001
                pass

    async def handle(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "config":
            self.devices = msg.get("devices", [])
            self.integrations = msg.get("integrations", [])
            self.interval = max(60, int(msg.get("interval", 300)))
            self.set_probes(msg.get("probes") or [])
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
        elif t == "probe_now":
            pid = int(msg.get("probe_id") or 0)
            if any(p["id"] == pid for p in self.probes):
                self.probe_due[pid] = 0.0
                self.probe_wake.set()
        elif t == "tunnel_open":
            sid, host = str(msg.get("sid") or ""), str(msg.get("host") or "")
            try:
                port = int(msg.get("port") or 22)
            except (TypeError, ValueError):
                port = 0
            if sid and self.key:
                task = asyncio.create_task(tunnel.run(self.ws_base, self.key, sid, host, port))
                self.tunnels.add(task)
                task.add_done_callback(self.tunnels.discard)
        elif t == "rpc":
            task = asyncio.create_task(self.rpc(msg))
            self.tunnels.add(task)
            task.add_done_callback(self.tunnels.discard)
        elif t == "pve_term_open":
            sid = str(msg.get("sid") or "")
            if sid and self.key:
                integ = next((i for i in self.integrations if i.get("id") == msg.get("integration_id")), None)
                vtype = msg.get("vmtype") if msg.get("vmtype") in ("qemu", "lxc") else None
                task = asyncio.create_task(pveterm.run(self.ws_base, self.key, sid, integ, str(msg.get("node") or ""), vtype,
                                                       msg.get("vmid"), int(msg.get("cols") or 80), int(msg.get("rows") or 24)))
                self.tunnels.add(task)
                task.add_done_callback(self.tunnels.discard)
        elif t == "snmp_test":
            asyncio.create_task(self.snmp_test(msg))
        elif t == "ping" and self.ws:
            await self.ws.send(json.dumps({"type": "pong"}))

    async def snmp_test(self, msg: dict) -> None:
        """Read one OID (or walk one column) from one device right now, for the custom OID page's Test button."""
        out: dict[str, Any] = {"type": "snmp_test_result", "req": str(msg.get("req") or "")}
        dev = next((d for d in self.devices if d.get("id") == msg.get("device_id")), None)
        if isinstance(msg.get("snmp"), dict) and msg.get("ip"):
            dev = {"ip": str(msg["ip"]), "snmp": msg["snmp"]}     # credentials being tried before they are saved
        oid = str(msg.get("oid") or "").strip().strip(".")
        try:
            if dev is None or not dev.get("snmp"):
                raise SnmpError("This poller has no SNMP credentials for that device")
            sess = SnmpSession(dev["ip"], dev["snmp"], engine=self.engine)
            if msg.get("mode") == "system":
                got = await asyncio.wait_for(sess.get(list(SYSTEM_OIDS)), timeout=20)
                if all(v is None for v in got.values()):
                    raise SnmpError("The device answered but returned no system information")
                out["rows"] = [{"index": oid_, "value": got.get(oid_), "label": label} for oid_, label in SYSTEM_OIDS.items()
                               if got.get(oid_) is not None]
            elif msg.get("mode") == "walk":
                values = await asyncio.wait_for(sess.walk(oid, max_rows=50), timeout=20)
                labels = {}
                if msg.get("label_oid"):
                    labels = await asyncio.wait_for(sess.walk(str(msg["label_oid"]).strip("."), max_rows=50), timeout=20)
                out["rows"] = [{"index": k, "value": v, "label": labels.get(k)} for k, v in values.items()]
            else:
                got = await asyncio.wait_for(sess.get([oid]), timeout=20)
                v = got.get(oid)
                out["rows"] = [] if v is None else [{"index": "", "value": v, "label": None}]
            out["rows"] = [{k: (x if isinstance(x, (int, float, str)) or x is None else str(x)) for k, x in r.items()}
                           for r in out["rows"]]
        except asyncio.TimeoutError:
            out["error"] = "The device did not answer in time"
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"{exc.__class__.__name__}: {exc}" if not isinstance(exc, SnmpError) else str(exc)
        await self.send_or_queue(out, queue=False)

    async def rpc(self, msg: dict) -> None:
        """Answer one request from the server. Only integrations assigned to this poller can be used, with the
        configuration the server pushed; ``op`` "integration_action" runs ``Integration.action``."""
        rid = msg.get("id")
        reply: dict[str, Any] = {"type": "rpc_result", "id": rid, "ok": False}
        try:
            op = msg.get("op")
            if op == "status":
                reply["result"], reply["ok"] = self.status(), True
                await self.send_or_queue(reply, queue=False)
                return
            if op == "update":
                reply["result"], reply["ok"] = self.request_update(str(msg.get("request") or "")), True
                await self.send_or_queue(reply, queue=False)
                return
            if op == "factory_reset":
                self.wipe()
                reply["result"], reply["ok"] = {"reset": True}, True
                await self.send_or_queue(reply, queue=False)
                await self.after_reset()
                return
            if op != "integration_action":
                raise IntegrationError(f"This poller doesn't know the request {op!r}. Update it.")
            integ = next((i for i in self.integrations if i.get("id") == msg.get("integration_id")), None)
            if integ is None:
                raise IntegrationError("This poller doesn't run that integration. Press Sync now and try again.")
            name, params = str(msg.get("action") or ""), msg.get("params") or {}

            def work():
                client = build(integ["kind"], integ["config"])
                try:
                    if not hasattr(client, "action"):
                        raise IntegrationError(f"{integ['kind']} has no actions.")
                    return client.action(name, params)
                finally:
                    client.close()
            reply["result"] = await asyncio.wait_for(asyncio.to_thread(work), 90)
            reply["ok"] = True
            log.info("Request %s on integration %s done", name, integ["id"])
            if msg.get("refresh"):
                asyncio.create_task(self.refresh_integration(integ, delay=6.0))
        except IntegrationError as exc:
            reply["error"] = str(exc)
        except asyncio.TimeoutError:
            reply["error"] = "The request took longer than 90 seconds."
        except Exception as exc:
            log.exception("Request failed")
            reply["error"] = f"{exc.__class__.__name__}: {exc}"
        await self.send_or_queue(reply, queue=False)

    async def refresh_integration(self, integ: dict, delay: float = 0.0) -> None:
        """Collect one integration now (after an action) instead of waiting for the next cycle."""
        await asyncio.sleep(delay)
        item = await self.run_integration(integ)
        batch = {"type": "results", "batch_id": new_batch_id(), "partial": True, "items": [item]}
        self.spool.put(batch)
        if self.ws:
            try:
                await self.ws.send(json.dumps(batch))
            except ConnectionClosed:
                pass

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
                    item.update(await poll_device(SnmpSession(dev["ip"], dev["snmp"], engine=self.engine), dev.get("oids")))
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

    # path probes ------------------------------------------------------------
    def set_probes(self, probes: list[dict]) -> None:
        now = time.monotonic()
        old = {p["id"]: p for p in self.probes}
        self.probes = [p for p in probes if isinstance(p, dict) and p.get("id") and p.get("target")]
        for p in self.probes:
            prev = old.get(p["id"])
            if prev is None or any(prev.get(k) != p.get(k) for k in ("target", "protocol", "port", "count")):
                self.probe_due[p["id"]] = now + random.uniform(0, 10)    # new or changed: run soon, spread out
        live = {p["id"] for p in self.probes}
        for pid in [k for k in self.probe_due if k not in live]:
            del self.probe_due[pid]
        if self.probes:
            log.info("Config: %d path probes", len(self.probes))
        self.probe_wake.set()

    async def probe_loop(self) -> None:
        while True:
            now = time.monotonic()
            for p in list(self.probes):
                if self.probe_due.get(p["id"], 0) <= now and p["id"] not in self.probing:
                    self.probe_due[p["id"]] = now + max(60, int(p.get("interval") or 300))
                    self.probing.add(p["id"])
                    asyncio.create_task(self.run_probe(p))
            nxt = min(self.probe_due.values(), default=now + 30)
            self.probe_wake.clear()
            try:
                await asyncio.wait_for(self.probe_wake.wait(), timeout=min(30.0, max(1.0, nxt - time.monotonic())))
            except asyncio.TimeoutError:
                pass

    async def run_probe(self, probe: dict) -> None:
        try:
            async with self.probe_sem:
                item = await mtr.trace(probe)
            if item.get("error"):
                log.warning("Path probe %s to %s: %s", probe["id"], probe.get("target"), item["error"])
            batch = {"type": "results", "batch_id": new_batch_id(), "partial": True, "items": [item]}
            self.spool.put(batch)
            if self.ws:
                try:
                    await self.ws.send(json.dumps(batch))
                except ConnectionClosed:
                    pass
        except Exception:
            log.exception("Path probe %s failed", probe.get("id"))
        finally:
            self.probing.discard(probe["id"])

    async def run_integration(self, integ: dict) -> dict[str, Any]:
        item: dict[str, Any] = {"kind": "integration", "integration_id": integ["id"], "ts": time.time(), "ok": False, "error": None}

        def work():
            client = build(integ["kind"], integ["config"])
            try:
                return client.collect(), list(getattr(client, "errors", []) or []), getattr(client, "data", None)
            finally:
                client.close()
        try:
            item["records"], item["warnings"], data = await asyncio.to_thread(work)
            if data:
                item["data"] = data
            item["ok"] = True
        except IntegrationError as exc:
            item["error"] = str(exc)
        except Exception as exc:
            item["error"] = f"{exc.__class__.__name__}: {exc}"
        return item


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


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
