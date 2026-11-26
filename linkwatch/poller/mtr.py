"""Hop-by-hop path tests with mtr (ICMP, UDP or TCP), run by the poller for path probes.

mtr does the probing; its JSON report gives one row per hop with loss, latency and jitter.
mtr-packet needs CAP_NET_RAW, so the container must run with --cap-add=NET_RAW.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from typing import Any

log = logging.getLogger("linkwatch.poller")

PROTOCOLS = ("icmp", "udp", "tcp")
HINT = ("mtr can't open a raw socket in this container. Add --cap-add=NET_RAW to the run command "
        "(AddCapability=NET_RAW in a .container file), then restart the poller.")
_TARGET = re.compile(r"^[A-Za-z0-9.:\-_]{1,253}$")
FIELDS = "LSRNABWVJMXI"     # loss, sent, received, last, avg, best, worst, stdev and the four jitter columns


def available() -> bool:
    return shutil.which("mtr") is not None


def command(target: str, protocol: str = "icmp", port: int | None = None, count: int = 10, max_hops: int = 30) -> list[str]:
    if not _TARGET.match(target or "") or target.startswith("-"):
        raise ValueError(f"Not a valid host name or address: {target!r}")
    cmd = [shutil.which("mtr") or "mtr", "--json", "--no-dns", "-o", FIELDS, "-c", str(max(1, min(int(count), 100))),
           "-m", str(max(1, min(int(max_hops), 64)))]
    if protocol == "tcp":
        cmd += ["--tcp", "-P", str(port or 443)]
    elif protocol == "udp":
        cmd += ["--udp"] + (["-P", str(port)] if port else [])
    cmd.append(target)
    return cmd


def _f(v) -> float | None:
    try:
        return round(float(v), 3)
    except (TypeError, ValueError):
        return None


def parse(text: str) -> list[dict[str, Any]]:
    """mtr --json report -> [{n, ip, loss, sent, last, avg, best, worst, stdev, jitter}], with silent hops as ip None."""
    hubs = (json.loads(text).get("report") or {}).get("hubs") or []
    hops = []
    for h in hubs:
        host = str(h.get("host") or "")
        ip = None if host in ("", "???") else host
        loss = _f(h.get("Loss%"))
        hops.append({"n": int(h.get("count") or len(hops) + 1), "ip": ip, "loss": 100.0 if ip is None else (loss or 0.0),
                     "sent": int(h.get("Snt") or 0), "last": _f(h.get("Last")) if ip else None,
                     "avg": _f(h.get("Avg")) if ip else None, "best": _f(h.get("Best")) if ip else None,
                     "worst": _f(h.get("Wrst")) if ip else None, "stdev": _f(h.get("StDev")) if ip else None,
                     "jitter": _f(h.get("Javg")) if ip else None})
    return hops


async def trace(probe: dict[str, Any]) -> dict[str, Any]:
    """Run one probe and return the result item the server ingests."""
    item: dict[str, Any] = {"kind": "probe", "probe_id": probe["id"], "ts": time.time(), "ok": False, "error": None, "hops": []}
    if not available():
        item["error"] = "mtr is not installed in this poller image. Update the poller."
        return item
    count = int(probe.get("count") or 10)
    try:
        cmd = command(str(probe.get("target") or ""), str(probe.get("protocol") or "icmp"), probe.get("port"), count,
                      int(probe.get("max_hops") or 30))
    except ValueError as exc:
        item["error"] = str(exc)
        return item
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as exc:     # EPERM executing mtr-packet with file capabilities outside the bounding set
        item["error"] = f"{HINT} ({exc.strerror or exc})"
        return item
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=count * 2 + 60)
    except asyncio.TimeoutError:
        proc.kill()
        item["error"] = "mtr did not finish in time"
        return item
    if proc.returncode != 0 or not out.strip():
        msg = (err or out).decode(errors="replace").strip()[:300] or f"mtr exited with code {proc.returncode}"
        if re.search(r"Operation not permitted|Permission denied|mtr-packet|raw socket", msg, re.IGNORECASE):
            msg = f"{HINT} ({msg})"
        item["error"] = msg
        return item
    try:
        item["hops"] = parse(out.decode(errors="replace"))
    except (ValueError, AttributeError) as exc:
        item["error"] = f"Could not read mtr output: {exc}"
        return item
    item["ok"] = True
    return item
