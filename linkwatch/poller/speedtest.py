"""Internet speed tests with librespeed-cli (LGPL-3.0, built into the poller image), run by the poller on a schedule.

librespeed-cli measures download and upload against a LibreSpeed server: the nearest public one, a list of public
server IDs, or your own server list (``--server-json``). It also reports the public address the server saw and the
network that owns it, which the server uses to put the result under the right ISP.

Packet loss, latency and jitter come from a short ICMP burst to the same server with the system ``ping``
(librespeed's own ping is an HTTP round trip, used only when ICMP isn't allowed in the container).

A test only measures the WAN the poller's traffic leaves by. Each "lane" can bind to a source address, so a gateway
with policy routing by source can send each lane out a different WAN (see docs/speedtest.md).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import shutil
import time
from typing import Any
from urllib.parse import urlparse

from .ping import parse as parse_ping

log = logging.getLogger("linkwatch.poller")

BINARY = "librespeed-cli"
MDEV = re.compile(r"= [\d.]+/[\d.]+/[\d.]+/([\d.]+)")


def available() -> bool:
    return shutil.which(BINARY) is not None


def _source(value: Any) -> str | None:
    """A lane's bind address, or None for the default route. Raises ValueError for anything that isn't an IP."""
    v = str(value or "").strip()
    if not v or v.lower() == "default":
        return None
    return str(ipaddress.ip_address(v))


def command(cfg: dict[str, Any], lane: dict[str, Any]) -> list[str]:
    """The librespeed-cli command line for one lane. Never shares results with librespeed.org (no --share)."""
    cmd = [shutil.which(BINARY) or BINARY, "--json", "--no-icmp", "--duration", str(max(5, min(int(lane.get("duration") or 10), 30)))]
    src = _source(lane.get("source"))
    if src:
        cmd += ["--source", src]
        cmd.append("--ipv6" if ":" in src else "--ipv4")
    server_json = str(cfg.get("server_json") or "").strip()
    if server_json:
        if urlparse(server_json).scheme not in ("http", "https"):
            raise ValueError("The server list must be an http(s) URL")
        cmd += ["--server-json", server_json]
    for sid in cfg.get("server_ids") or []:
        cmd += ["--server", str(int(sid))]
    if lane.get("no_upload"):
        cmd.append("--no-upload")
    return cmd


def parse(text: str) -> dict[str, Any]:
    """librespeed-cli --json (a list with one report) -> the fields we keep."""
    data = json.loads(text)
    rep = data[0] if isinstance(data, list) and data else data
    if not isinstance(rep, dict):
        raise ValueError("no report in the output")
    client = rep.get("client") or {}
    server = rep.get("server") or {}

    def f(v):
        try:
            return round(float(v), 3)
        except (TypeError, ValueError):
            return None
    return {"download_mbps": f(rep.get("download")), "upload_mbps": f(rep.get("upload")), "http_ping_ms": f(rep.get("ping")),
            "http_jitter_ms": f(rep.get("jitter")), "bytes_sent": int(rep.get("bytes_sent") or 0),
            "bytes_received": int(rep.get("bytes_received") or 0),
            "public_ip": str(client.get("ip") or "")[:45] or None, "org": str(client.get("org") or "")[:120] or None,
            "server": {"name": str(server.get("name") or "")[:120], "url": str(server.get("url") or "")[:300]}}


async def icmp(host: str, source: str | None, count: int = 20) -> dict[str, Any] | None:
    """Loss, average RTT and jitter (mdev) from a burst of pings, or None when ping can't run here."""
    binary = shutil.which("ping")
    if not binary or not host:
        return None
    cmd = [binary, "-n", "-q", "-c", str(count), "-i", "0.2", "-W", "1"] + (["-I", source] if source else []) + [host]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=count + 10)
    except (OSError, asyncio.TimeoutError):
        return None
    text = out.decode(errors="replace")
    if "packets transmitted" not in text:
        return None
    got = parse_ping(text)
    m = MDEV.search(text)
    got["jitter_ms"] = float(m.group(1)) if m else None
    return got


async def run(cfg: dict[str, Any], lane: dict[str, Any], trigger: str = "schedule") -> dict[str, Any]:
    """Run one lane and return the result item the server ingests."""
    item: dict[str, Any] = {"kind": "speedtest", "ts": time.time(), "ok": False, "error": None, "trigger": trigger,
                            "lane": {"key": lane.get("key") or "default", "source": lane.get("source") or None}}
    if not available():
        item["error"] = "librespeed-cli is not in this poller image. Update the poller."
        return item
    try:
        cmd = command(cfg, lane)
    except ValueError as exc:
        item["error"] = str(exc)
        return item
    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as exc:
        item["error"] = f"Could not start librespeed-cli: {exc.strerror or exc}"
        return item
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        proc.kill()
        item["error"] = "The speed test did not finish within 3 minutes"
        return item
    item["duration_s"] = round(time.monotonic() - started, 1)
    if proc.returncode != 0 or not out.strip():
        msg = (err or out).decode(errors="replace").strip()
        item["error"] = (msg.splitlines()[-1] if msg else f"librespeed-cli exited with code {proc.returncode}")[:300]
        return item
    try:
        item.update(parse(out.decode(errors="replace")))
    except (ValueError, TypeError, AttributeError) as exc:
        item["error"] = f"Could not read the speed test output: {exc}"
        return item
    host = urlparse(item["server"]["url"]).hostname or ""
    src = _source(lane.get("source"))
    burst = await icmp(host, src) if host else None
    if burst and burst.get("rtt_ms") is not None:
        item.update(ping_ms=burst["rtt_ms"], jitter_ms=burst.get("jitter_ms"), loss_pct=burst["loss_pct"], latency_from="icmp")
    else:
        item.update(ping_ms=item.get("http_ping_ms"), jitter_ms=item.get("http_jitter_ms"),
                    loss_pct=burst["loss_pct"] if burst else None, latency_from="http")
    item["ok"] = item.get("download_mbps") is not None
    if not item["ok"]:
        item["error"] = "The speed test returned no download result"
    return item


# ------------------------------------------------------------------ scheduling
def next_due(last_run: float | None, interval_h: float, jitter_min: float, now: float, rnd) -> float:
    """When the next scheduled run is due (wall clock). A poller that has never run starts 2 to 15 minutes from now,
    so a fleet of pollers (or a restart) doesn't saturate a link at the same moment."""
    if not last_run:
        return now + rnd(120, 900)
    jit = max(0.0, jitter_min) * 60
    return max(now + 60, last_run + max(1.0, interval_h) * 3600 + rnd(-jit, jit))


def runnable(lane: dict[str, Any], last_bytes: int | None) -> str | None:
    """Why a lane must be skipped (monthly data cap), or None to run it."""
    if lane.get("blocked"):
        return lane.get("blocked_reason") or "Monthly data cap reached"
    budget = lane.get("budget_bytes")
    if budget is not None and last_bytes and last_bytes > budget:
        return "Skipped: another test would go over this month's data cap"
    return None
