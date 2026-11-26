"""Cisco Meraki Dashboard API v1 (cloud, called from the server)."""
from __future__ import annotations

import re

import httpx

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
        Field("org_id", "Organization ID", required=False, help="Numeric ID or the organization's name. Leave blank to use the first organization the key can see."),
    ]

    def _key(self) -> str:
        """The key as pasted, minus whitespace/newlines and a stray "Bearer " prefix."""
        key = re.sub(r"\s+", "", str(self.config.get("api_key") or ""))
        return key[6:] if key.lower().startswith("bearer") else key

    def _get(self, url: str, **kw):
        # Bearer only: Meraki rejects newer keys sent in X-Cisco-Meraki-API-Key. Redirects to a regional
        # shard are followed by hand so the Authorization header is re-sent (httpx drops it across hosts).
        headers = {"Authorization": f"Bearer {self._key()}", "Accept": "application/json"}
        try:
            for _ in range(5):
                resp = super()._get(url, headers=headers, **kw)
                loc = resp.headers.get("Location") if resp.status_code in (301, 302, 303, 307, 308) else None
                if not loc:
                    return resp
                target = httpx.URL(url).join(loc)
                if target.scheme != "https" or not (target.host == "meraki.com" or target.host.endswith(".meraki.com")):
                    raise IntegrationError(f"Meraki redirected to an unexpected host: {target.host}")
                url, kw = str(target), {k: v for k, v in kw.items() if k != "params"}
            raise IntegrationError("Too many redirects from the Meraki API")
        except IntegrationError as exc:
            if "rejected the credentials" in str(exc):
                raise IntegrationError(
                    f"{exc}. Meraki refused the API key: check it was copied whole, that API access is enabled under "
                    "Organization > Settings, and that the server's IP is allowed if the organization restricts API access by IP") from None
            raise

    def _paged(self, path: str, params: dict | None = None) -> list[dict]:
        url: str | None = BASE + path
        items: list[dict] = []
        params = {"perPage": 1000, **(params or {})}
        for _ in range(50):
            if not url:
                break
            resp = self._get(url, params=params)
            body = resp.json()
            items.extend(body if isinstance(body, list) else [body])
            m = re.search(r'<([^>]+)>;\s*rel=next', resp.headers.get("Link", ""))
            url, params = (m.group(1), None) if m else (None, None)
        return items

    def org_id(self) -> str:
        org = str(self.config.get("org_id") or "").strip()
        if org.isdigit():
            return org
        orgs = self._paged("/organizations")
        if not orgs:
            raise IntegrationError("The API key cannot see any organization")
        if not org:
            return str(orgs[0]["id"])
        for o in orgs:   # a name was typed instead of the numeric ID
            if org.lower() in (str(o.get("name", "")).strip().lower(), str(o.get("id"))):
                return str(o["id"])
        seen = ", ".join(f"{o.get('name')} ({o.get('id')})" for o in orgs[:10])
        raise IntegrationError(f"No organization named '{org}'. This key can see: {seen}. Use one of those IDs, or leave Organization ID blank.")

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
