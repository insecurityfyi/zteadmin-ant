"""UniFi Network official integration API (on-prem console, called by a poller).

Uses ``/proxy/network/integration/v1`` on a UniFi OS console (UDM, UCG,
Cloud Key Gen2+) with an API key from Settings > Control Plane > Integrations.
"""
from __future__ import annotations

from .base import Field, Integration, Record, host_url, verify_field

STATE = {"ONLINE": "up", "OFFLINE": "down", "PENDING_ADOPTION": "off", "UPDATING": "warn",
         "GETTING_READY": "warn", "ADOPTING": "warn", "DELETING": "off", "CONNECTION_INTERRUPTED": "down", "ISOLATED": "down"}


class UniFi(Integration):
    kind = "unifi"
    label = "UniFi Network"
    runs_on = "poller"
    description = "Network API: access points, switches and gateways with their state."
    fields = [
        Field("host", "UniFi console address", help="e.g. 192.168.1.1"),
        Field("api_key", "API key", "password", help="UniFi Network > Settings > Control Plane > Integrations."),
        verify_field(),
    ]

    def _api(self, path: str, params: dict | None = None) -> dict:
        return self._get(f"{host_url(self.config['host'])}/proxy/network/integration/v1{path}", params=params,
                         headers={"X-API-KEY": self.config["api_key"], "Accept": "application/json"}).json()

    def collect(self) -> list[Record]:
        out: list[Record] = []
        for site in self._api("/sites", {"limit": 200}).get("data", []):
            offset = 0
            while True:
                body = self._api(f"/sites/{site['id']}/devices", {"limit": 200, "offset": offset})
                devices = body.get("data", [])
                for d in devices:
                    feats = d.get("features") or []
                    kind = "Wireless" if "accessPoint" in feats else "Switch" if "switching" in feats else "Router"
                    out.append(Record(
                        external_id=d.get("id"), hostname=d.get("name") or d.get("macAddress"), ip=d.get("ipAddress"),
                        type=kind, platform=f"UniFi {d.get('model') or ''}".strip(), site=site.get("name"),
                        status=STATE.get(str(d.get("state", "")).upper(), "unknown"),
                        detail=f"Firmware {d.get('firmwareVersion') or '?'}", extra={"mac": d.get("macAddress")},
                    ))
                offset += len(devices)
                if not devices or offset >= int(body.get("totalCount") or 0):
                    break
        return out
