"""ICMP reachability using the system ping binary (works rootless in containers)."""
from __future__ import annotations

import asyncio
import re
import shutil

LOSS = re.compile(r"([\d.]+)% packet loss")
RTT = re.compile(r"= [\d.]+/([\d.]+)/")


def parse(output: str) -> dict:
    loss = LOSS.search(output)
    rtt = RTT.search(output)
    return {"loss_pct": float(loss.group(1)) if loss else 100.0, "rtt_ms": float(rtt.group(1)) if rtt else None}


async def ping(host: str, count: int = 3, timeout_s: int = 1) -> dict | None:
    binary = shutil.which("ping")
    if not binary:
        return None
    proc = await asyncio.create_subprocess_exec(
        binary, "-n", "-q", "-c", str(count), "-i", "0.2", "-W", str(timeout_s), host,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=count * timeout_s + 5)
    except asyncio.TimeoutError:
        proc.kill()
        return {"loss_pct": 100.0, "rtt_ms": None}
    return parse(out.decode(errors="replace"))
