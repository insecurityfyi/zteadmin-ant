"""Palo Alto Networks PAN-OS XML API (on-prem, called by a poller)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field


def parse_uptime(text: str | None) -> int | None:
    """'12 days, 3:04:05' -> seconds."""
    if not text:
        return None
    m = re.match(r"\s*(?:(\d+)\s+days?,\s*)?(\d+):(\d+):(\d+)", text)
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s


def parse_top(text: str) -> tuple[float | None, float | None]:
    """CPU and memory percent from the 'show system resources' top output."""
    cpu = mem = None
    m = re.search(r"Cpu\(s\):.*?([\d.]+)\s*id", text)
    if m:
        cpu = round(100.0 - float(m.group(1)), 1)
    m = re.search(r"(?:KiB|MiB) Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used", text)
    if m:
        total, _free, used = (float(x) for x in m.groups())
        mem = round(100.0 * used / total, 1) if total else None
    return cpu, mem


class PanOS(Integration):
    kind = "panos"
    label = "Palo Alto PAN-OS"
    runs_on = "poller"
    description = "XML API: system info, CPU and memory, sessions and HA state."
    fields = [
        Field("host", "Firewall address", help="Management IP or hostname, e.g. 10.50.0.1"),
        Field("api_key", "API key", "password", help="Generate with: https://<fw>/api/?type=keygen (use a read-only admin)."),
        verify_field(),
    ]

    def op(self, cmd: str) -> ET.Element:
        resp = self._get(f"{host_url(self.config['host'])}/api/", params={"type": "op", "cmd": cmd},
                         headers={"X-PAN-KEY": self.config["api_key"]})
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as exc:
            raise IntegrationError("PAN-OS returned something that is not XML") from exc
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())[:200]
            raise IntegrationError(f"PAN-OS error: {msg or 'unknown'}")
        return root

    def collect(self) -> list[Record]:
        info = self.op("<show><system><info></info></system></show>").find("./result/system")
        if info is None:
            raise IntegrationError("PAN-OS system info was empty")
        g = lambda tag: (info.findtext(tag) or "").strip() or None  # noqa: E731
        cpu = mem = None
        try:
            res = self.op("<show><system><resources></resources></system></show>")
            cpu, mem = parse_top(res.findtext("./result") or "")
        except IntegrationError:
            pass
        sessions = ha = None
        try:
            sessions = self.op("<show><session><info></info></session></show>").findtext("./result/num-active")
        except IntegrationError:
            pass
        try:
            ha = self.op("<show><high-availability><state></state></high-availability></show>").findtext("./result/group/local-info/state")
        except IntegrationError:
            pass
        detail = f"PAN-OS {g('sw-version') or '?'}, {sessions or '?'} active sessions" + (f", HA {ha}" if ha else "")
        return [Record(
            external_id=g("serial") or self.config["host"], hostname=g("hostname") or self.config["host"],
            ip=g("ip-address") or self.config["host"], type="Firewall",
            platform=f"Palo Alto {g('model') or ''} PAN-OS {g('sw-version') or ''}".strip(), site=None, status="up",
            cpu=cpu, mem=mem, uptime_s=parse_uptime(g("uptime")), serial=g("serial"), detail=detail,
            extra={"sessions": int(sessions) if sessions and sessions.isdigit() else None, "ha_state": ha,
                   "threat_version": g("threat-version"), "app_version": g("app-version")},
        )]
