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
        self.data = {"type": "panos", "unavailable": [], "system": {
            k: g(k) for k in ("hostname", "model", "serial", "sw-version", "app-version", "threat-version", "av-version",
                              "wildfire-version", "url-filtering-version", "global-protect-client-package-version",
                              "uptime", "ip-address", "family", "vm-license", "multi-vsys", "operational-mode")}}
        ports = self._telemetry()
        rec = Record(
            external_id=g("serial") or self.config["host"], hostname=g("hostname") or self.config["host"],
            ip=g("ip-address") or self.config["host"], type="Firewall",
            platform=f"Palo Alto {g('model') or ''} PAN-OS {g('sw-version') or ''}".strip(), site=None, status="up",
            cpu=cpu, mem=mem, uptime_s=parse_uptime(g("uptime")), serial=g("serial"), detail=detail,
            extra={"sessions": int(sessions) if sessions and sessions.isdigit() else None, "ha_state": ha,
                   "threat_version": g("threat-version"), "app_version": g("app-version")},
        )
        # every interface address and MAC, so the map can find the firewall in switch tables and LLDP
        ifs = self.data.get("interfaces") or []
        ips = sorted({str(i["ip"]).split("/")[0] for i in ifs if re.match(r"^\d{1,3}(\.\d{1,3}){3}", str(i.get("ip") or ""))})
        macs = sorted({str(i["mac"]).lower() for i in ifs if i.get("mac")})
        if ips:
            rec["extra"]["ips"] = ips
        if macs:
            rec["extra"]["macs"] = macs
        if ports:
            rec["ports"] = ports
        return [rec]

    def _optional(self, label: str, cmd: str):
        try:
            return self.op(cmd)
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    def _telemetry(self) -> list[dict]:
        d = self.data
        txt = lambda el, tag: (el.findtext(tag) or "").strip() if el is not None else ""  # noqa: E731
        num = lambda v: float(v) if re.fullmatch(r"-?\d+(\.\d+)?", v or "") else None  # noqa: E731
        si = self._optional("Session info", "<show><session><info></info></session></show>")
        r = si.find("./result") if si is not None else None
        if r is not None:
            d["sessions"] = {"active": num(txt(r, "num-active")), "max": num(txt(r, "num-max")), "tcp": num(txt(r, "num-tcp")),
                             "udp": num(txt(r, "num-udp")), "cps": num(txt(r, "cps")), "pps": num(txt(r, "pps")),
                             "throughput_bps": (num(txt(r, "kbps")) or 0) * 1000 if txt(r, "kbps") else None}
        ha = self._optional("High availability", "<show><high-availability><state></state></high-availability></show>")
        if ha is not None and ha.find("./result/group") is not None:
            grp = ha.find("./result/group")
            d["ha"] = {"mode": txt(grp, "mode"), "local": txt(grp, "local-info/state"), "peer": txt(grp, "peer-info/state"),
                       "peer_ip": txt(grp, "peer-info/mgmt-ip"), "sync": txt(grp, "running-sync")}
        lic = self._optional("Licences", "<request><license><info></info></license></request>")
        if lic is not None:
            d["licenses"] = [{"feature": txt(e, "feature"), "expires": txt(e, "expires"), "expired": txt(e, "expired") == "yes"}
                             for e in lic.findall("./result/licenses/entry")]
        gp = self._optional("GlobalProtect users", "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>")
        if gp is not None:
            users = gp.findall("./result/entry")
            d["globalprotect"] = {"count": len(users), "users": [
                {"user": txt(e, "username") or txt(e, "primary-username"), "virtual_ip": txt(e, "virtual-ip"),
                 "public_ip": txt(e, "public-ip"), "client": txt(e, "client"), "login": txt(e, "login-time"),
                 "gateway": txt(e, "domain") or txt(e, "computer")} for e in users[:500]]}
        vpn = self._optional("IPsec tunnels", "<show><vpn><flow></flow></vpn></show>")
        if vpn is not None:
            d["tunnels"] = [{"name": txt(e, "name"), "state": txt(e, "state"), "peer": txt(e, "peerip"),
                             "local": txt(e, "localip"), "interface": txt(e, "inner-if") or txt(e, "outer-if")}
                            for e in vpn.findall(".//IPSec/entry")]
        ifs = self._optional("Interfaces", "<show><interface>all</interface></show>")
        counters = self._optional("Interface counters", "<show><counter><interface>all</interface></counter></show>")
        hw: dict[str, dict] = {}
        if ifs is not None:
            for e in ifs.findall("./result/hw/entry"):
                hw[txt(e, "name")] = {"state": txt(e, "state"), "speed": txt(e, "speed"), "mac": txt(e, "mac"), "id": txt(e, "id")}
            d["interfaces"] = [{"name": txt(e, "name"), "zone": txt(e, "zone"), "ip": txt(e, "ip"), "vsys": txt(e, "vsys"), "tag": txt(e, "tag"),
                                "state": hw.get(txt(e, "name").split(".")[0], {}).get("state"),
                                "mac": hw.get(txt(e, "name").split(".")[0], {}).get("mac") or None}
                               for e in ifs.findall("./result/ifnet/entry")]
        ports: list[dict] = []
        if counters is not None:
            seen = set()
            for i, e in enumerate(counters.iter("entry")):
                name = txt(e, "name")
                if not name or name in seen or "ibytes" not in {c.tag for c in e}:
                    continue
                seen.add(name)
                info = hw.get(name, {})
                idx = int(info["id"]) if info.get("id", "").isdigit() else 10000 + i
                up = info.get("state", "up") == "up"
                ports.append({"ifindex": idx, "name": name, "alias": "", "admin": "up", "oper": "up" if up else "down",
                              "speed_mbps": int(info["speed"]) if info.get("speed", "").isdigit() else None,
                              "in_octets": num(txt(e, "ibytes")), "out_octets": num(txt(e, "obytes")),
                              "in_errors": num(txt(e, "ierrors")), "out_errors": num(txt(e, "oerrors")) if txt(e, "oerrors") else None, "counter_bits": 64})
        return ports
