"""Subnet discovery on the poller: a ping sweep and an SNMP probe with each saved credential set."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from ..common.discovery import SYS_DESCR, SYS_NAME, SYS_OBJECT_ID
from .ping import ping
from .snmp import SnmpEngine, SnmpError, SnmpSession


async def probe_snmp(ip: str, profiles: list[dict], engine: SnmpEngine) -> dict[str, Any] | None:
    """Try each credential set in order; the first one that answers wins."""
    for prof in profiles:
        try:
            sess = SnmpSession(ip, prof["creds"], engine=engine, timeout=1.0, retries=0)
            got = await sess.get([SYS_NAME, SYS_DESCR, SYS_OBJECT_ID])
        except SnmpError:
            continue
        except Exception:  # malformed replies, bad credentials config
            continue
        if any(v is not None for v in got.values()):
            return {"profile_id": prof.get("id"), "sys_name": got.get(SYS_NAME), "sys_descr": got.get(SYS_DESCR),
                    "sys_object_id": got.get(SYS_OBJECT_ID)}
    return None


async def scan(hosts: list[str], profiles: list[dict], engine: SnmpEngine | None = None, concurrency: int = 64,
               progress: Callable[[int, int], Awaitable[None]] | None = None,
               pinger=ping, prober=probe_snmp) -> list[dict[str, Any]]:
    """Returns one entry per host that answered ping or SNMP, in address order."""
    engine = engine or SnmpEngine()
    sem = asyncio.Semaphore(concurrency)
    found: dict[str, dict[str, Any]] = {}
    done = 0
    last = time.monotonic()

    async def one(ip: str) -> None:
        nonlocal done, last
        async with sem:
            p, s = await asyncio.gather(pinger(ip, count=1, timeout_s=1), prober(ip, profiles, engine) if profiles else _none())
            alive = bool(p and p.get("loss_pct", 100) < 100)
            if alive or s:
                found[ip] = {"ip": ip, "rtt_ms": p.get("rtt_ms") if alive else None, **(s or {})}
            done += 1
            if progress and time.monotonic() - last > 3:
                last = time.monotonic()
                await progress(done, len(hosts))

    await asyncio.gather(*(one(ip) for ip in hosts))
    return [found[ip] for ip in hosts if ip in found]


async def _none() -> None:
    return None
