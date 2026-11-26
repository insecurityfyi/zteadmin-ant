"""Cisco Meraki Dashboard API v1 (cloud, called from the server)."""
from __future__ import annotations

import re

from .base import Field, Integration, IntegrationError, Record

BASE = "https://api.meraki.com/api/v1"
TYPES = {"switch": "Switch", "wireless": "Wireless", "appliance": "Firewall", "camera": "Camera",
         "sensor": "Sensor", "cellularGateway": "Router", "systemsManager": "Endpoint"}
STATUS = {"online": "up", "alerting": "warn", "offline": "down", "dormant": "off"}


class Meraki(Integration):
    kind = "meraki"
    label = "Cisco Meraki"
    runs_on = "server"
    description = "Dashboard API: devices, status and uplinks across your organization."
    fields = [
        Field("api_key", "API key", "password", help="Organization > Settings > Dashboard API access, then your profile > API keys."),
        Field("org_id", "Organization ID", required=False, help="Leave blank to use the first organization the key can see."),
    ]

    def _paged(self, path: str, params: dict | None = None) -> list[dict]:
        url: str | None = BASE + path
        items: list[dict] = []
        params = {"perPage": 1000, **(params or {})}
        for _ in range(50):
            if not url:
                break
            resp = self._get(url, params=params, headers={"Authorization": f"Bearer {self.config['api_key']}"})
            body = resp.json()
            items.extend(body if isinstance(body, list) else [body])
            m = re.search(r'<([^>]+)>;\s*rel=next', resp.headers.get("Link", ""))
            url, params = (m.group(1), None) if m else (None, None)
        return items

    def org_id(self) -> str:
        org = str(self.config.get("org_id") or "").strip()
        if org:
            return org
        orgs = self._paged("/organizations")
        if not orgs:
            raise IntegrationError("The API key cannot see any organization")
        return str(orgs[0]["id"])

    def collect(self) -> list[Record]:
        org = self.org_id()
        networks = {n["id"]: n.get("name") for n in self._paged(f"/organizations/{org}/networks")}
        statuses = {s["serial"]: s for s in self._paged(f"/organizations/{org}/devices/statuses")}
        out: list[Record] = []
        for d in self._paged(f"/organizations/{org}/devices"):
            st = statuses.get(d["serial"], {})
            ip = st.get("lanIp") or d.get("lanIp") or st.get("publicIp")
            out.append(Record(
                external_id=d["serial"], hostname=d.get("name") or d["serial"], ip=ip,
                type=TYPES.get(d.get("productType", ""), "Network"), platform=f"Meraki {d.get('model', '')}".strip(),
                site=networks.get(d.get("networkId")), status=STATUS.get(st.get("status", ""), "unknown"),
                serial=d["serial"], detail=f"Firmware {d.get('firmware') or '?'}",
                extra={"mac": d.get("mac"), "publicIp": st.get("publicIp"), "lastReportedAt": st.get("lastReportedAt")},
            ))
        return out
