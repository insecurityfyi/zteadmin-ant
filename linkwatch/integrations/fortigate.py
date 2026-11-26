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

    def collect(self) -> list[Record]:
        status = self._api("/api/v2/monitor/system/status")
        res = status.get("results") or {}
        usage = (self._api("/api/v2/monitor/system/resource/usage", {"interval": "1-min"}).get("results") or {})
        cur = lambda k: ((usage.get(k) or [{}])[0] or {}).get("current")  # noqa: E731
        tunnels = self._api("/api/v2/monitor/vpn/ipsec").get("results") or []
        serial = status.get("serial") or res.get("serial")
        name = res.get("hostname") or self.config["host"]
        out: list[Record] = [Record(
            external_id=serial or self.config["host"], hostname=name, ip=self.config["host"].split(":")[0],
            type="Firewall", platform=f"FortiGate {res.get('model_number') or res.get('model') or ''} {status.get('version') or ''}".strip(),
            site=None, status="up", cpu=cur("cpu"), mem=cur("mem"), serial=serial,
            detail=f"FortiOS {status.get('version') or '?'}, {cur('session') or '?'} sessions, {len(tunnels)} IPsec tunnels",
            extra={"build": status.get("build"), "sessions": cur("session")},
        )]
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
