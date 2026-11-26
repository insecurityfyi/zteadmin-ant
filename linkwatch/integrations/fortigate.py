"""Fortinet FortiGate REST API (on-prem, called by a poller)."""
from __future__ import annotations

from .base import Field, Integration, Record, host_url, verify_field


class FortiGate(Integration):
    kind = "fortigate"
    label = "Fortinet FortiGate"
    runs_on = "poller"
    description = "REST API: system status, CPU, memory, sessions and IPsec tunnels."
    fields = [
        Field("host", "FortiGate address", help="Management IP or hostname, with :port if not 443."),
        Field("api_token", "REST API token", "password", help="System > Administrators > Create new > REST API Admin (read-only profile)."),
        verify_field(),
    ]

    def _api(self, path: str, params: dict | None = None) -> dict:
        return self._get(f"{host_url(self.config['host'])}{path}", params=params,
                         headers={"Authorization": f"Bearer {self.config['api_token']}"}).json()

    def _optional(self, label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    def _interfaces(self) -> list[dict]:
        body = self._optional("Interfaces", lambda: self._api("/api/v2/monitor/system/interface", {"include_vlan": "true"}))
        results = (body or {}).get("results") or {}
        rows = results.values() if isinstance(results, dict) else results
        ports, table = [], []
        for i, p in enumerate(sorted(rows, key=lambda p: str(p.get("name")))):
            idx = int(p["id"]) if str(p.get("id", "")).isdigit() else 20000 + i
            up = bool(p.get("link"))
            table.append({"name": p.get("name"), "alias": p.get("alias"), "ip": p.get("ip"), "mask": p.get("mask"),
                          "up": up, "speed": p.get("speed"), "vlan": p.get("vlanid")})
            ports.append({"ifindex": idx, "name": p.get("name") or str(idx), "alias": p.get("alias") or "",
                          "admin": "up", "oper": "up" if up else "down",
                          "speed_mbps": int(float(p["speed"])) if up and p.get("speed") else None,
                          "in_octets": p.get("rx_bytes"), "out_octets": p.get("tx_bytes"),
                          "in_errors": p.get("rx_errors"), "out_errors": p.get("tx_errors"), "counter_bits": 64})
        self.data["interfaces"] = table
        return ports

    def collect(self) -> list[Record]:
        status = self._api("/api/v2/monitor/system/status")
        res = status.get("results") or {}
        usage = (self._api("/api/v2/monitor/system/resource/usage", {"interval": "1-min"}).get("results") or {})
        cur = lambda k: ((usage.get(k) or [{}])[0] or {}).get("current")  # noqa: E731
        tunnels = self._api("/api/v2/monitor/vpn/ipsec").get("results") or []
        serial = status.get("serial") or res.get("serial")
        name = res.get("hostname") or self.config["host"]
        self.data = {"type": "fortigate", "unavailable": [], "system": {
            "hostname": name, "model": res.get("model_name") or res.get("model_number") or res.get("model"), "serial": serial,
            "version": status.get("version"), "build": status.get("build")},
            "resources": {k: cur(k) for k in ("cpu", "mem", "disk", "session", "session6", "setuprate", "npu_session")},
            "tunnels": [{"name": t.get("name"), "remote": t.get("rgwy"), "comment": t.get("comments"),
                         "phase2_up": sum(1 for p in t.get("proxyid") or [] if p.get("status") == "up"),
                         "phase2": len(t.get("proxyid") or []), "in_bytes": t.get("incoming_bytes"),
                         "out_bytes": t.get("outgoing_bytes")}
                        for t in tunnels]}
        ports = self._interfaces()
        self._optional("SSL VPN users", lambda: self.data.__setitem__("sslvpn", [
            {"user": u.get("user_name"), "remote": u.get("remote_host"), "since": u.get("last_login_time"),
             "tunnel_ip": ((u.get("subsessions") or [{}])[0] or {}).get("aip")}
            for u in self._api("/api/v2/monitor/vpn/ssl").get("results") or []]))
        self._optional("FortiGuard licences", lambda: self.data.__setitem__("licenses", [
            {"feature": k, "status": (v or {}).get("status"), "expires": (v or {}).get("expires")}
            for k, v in (self._api("/api/v2/monitor/license/status").get("results") or {}).items() if isinstance(v, dict)]))
        out: list[Record] = [Record(
            external_id=serial or self.config["host"], hostname=name, ip=self.config["host"].split(":")[0],
            type="Firewall", platform=f"FortiGate {res.get('model_number') or res.get('model') or ''} {status.get('version') or ''}".strip(),
            site=None, status="up", cpu=cur("cpu"), mem=cur("mem"), serial=serial,
            detail=f"FortiOS {status.get('version') or '?'}, {cur('session') or '?'} sessions, {len(tunnels)} IPsec tunnels",
            extra={"build": status.get("build"), "sessions": cur("session")},
        )]
        if ports:
            out[0]["ports"] = ports
        for t in tunnels:
            proxies = t.get("proxyid") or []
            up = any(p.get("status") == "up" for p in proxies)
            out.append(Record(
                external_id=f"{serial}-vpn-{t.get('name')}", hostname=f"{name} VPN {t.get('name')}", ip=t.get("rgwy"),
                type="VPN tunnel", platform="FortiGate IPsec", site=None, status="up" if up else "down",
                detail=f"Remote gateway {t.get('rgwy') or '?'}, {sum(1 for p in proxies if p.get('status') == 'up')}/{len(proxies)} phase 2 up",
                extra={"incoming_bytes": t.get("incoming_bytes"), "outgoing_bytes": t.get("outgoing_bytes")},
            ))
        return out
