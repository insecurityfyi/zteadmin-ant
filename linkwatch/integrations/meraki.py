"""Cisco Meraki Dashboard API v1 (cloud, called from the server)."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

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

    def _optional(self, label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    def collect(self) -> list[Record]:
        self.data: dict[str, Any] = {"type": "meraki", "unavailable": []}
        org = self.org_id()
        nets = self._paged(f"/organizations/{org}/networks")
        networks = {n["id"]: n.get("name") for n in nets}
        statuses = {s["serial"]: s for s in self._paged(f"/organizations/{org}/devices/statuses")}
        devices = self._paged(f"/organizations/{org}/devices")
        self._telemetry(org, nets, devices, statuses)
        out: list[Record] = []
        for d in devices:
            st = statuses.get(d["serial"], {})
            ip = st.get("lanIp") or d.get("lanIp") or st.get("publicIp")
            out.append(Record(
                external_id=d["serial"], hostname=d.get("name") or d["serial"], ip=ip,
                type=TYPES.get(d.get("productType", ""), "Network"), platform=f"Meraki {d.get('model', '')}".strip(),
                site=networks.get(d.get("networkId")), status=STATUS.get(st.get("status", ""), "unknown"),
                serial=d["serial"], detail=f"Firmware {d.get('firmware') or '?'}",
                extra={"mac": d.get("mac"), "publicIp": st.get("publicIp"), "lastReportedAt": st.get("lastReportedAt"),
                       "ips": sorted({x for x in (st.get("lanIp"), d.get("lanIp"), st.get("wan1Ip"), st.get("wan2Ip"),
                                                  d.get("wan1Ip"), d.get("wan2Ip")) if x})},
            ))
        if any(d.get("productType") == "wireless" for d in devices):
            self._access_points(org, nets, devices, out)
        return out

    def _access_points(self, org: str, nets: list[dict], devices: list[dict], out: list[Record]) -> None:
        """Where each MR access point plugs in (link-layer topology), mesh repeaters, and clients per AP, for the map."""
        by_serial = {d["serial"]: d for d in devices}
        recs = {r["external_id"]: r for r in out}
        aps = {s for s, d in by_serial.items() if d.get("productType") == "wireless"}

        def uplink(ap: str, to: str, port, wireless: bool = False) -> None:
            peer = by_serial.get(to)
            if ap in recs and peer and peer.get("mac"):
                recs[ap]["extra"].update(uplink_mac=peer["mac"], uplink_name=peer.get("name") or to, uplink_port=port,
                                      uplink_wireless=wireless,
                                      uplink=f"{'mesh via' if wireless else 'wired to'} {peer.get('name') or to}{f' port {port}' if port else ''}")

        def topology():
            for n in [n for n in nets if "wireless" in (n.get("productTypes") or [])][:50]:
                body = self._get(f"{BASE}/networks/{n['id']}/topology/linkLayer").json()
                for link in body.get("links") or []:
                    ends = [e for e in link.get("ends") or [] if (e.get("device") or {}).get("serial")]
                    if len(ends) != 2:
                        continue
                    for me, other in (ends, ends[::-1]):
                        ap, sw = me["device"]["serial"], other["device"]["serial"]
                        if ap in aps and sw not in aps:
                            disc = other.get("discovered") or {}
                            port = (disc.get("lldp") or {}).get("portId") or (disc.get("cdp") or {}).get("portId")
                            uplink(ap, sw, port)
        self._optional("AP uplinks (link-layer topology)", topology)

        def mesh():
            for n in [n for n in nets if "wireless" in (n.get("productTypes") or [])][:50]:
                try:     # networks without mesh answer with an error: not worth reporting
                    rows = self._get(f"{BASE}/networks/{n['id']}/wireless/meshStatuses").json() or []
                except Exception:  # noqa: BLE001, S112
                    continue
                for m in rows if isinstance(rows, list) else []:
                    route = [x for x in m.get("meshRoute") or [] if x != m.get("serial")]
                    if route and m.get("serial") in aps:
                        uplink(m["serial"], route[0], None, wireless=True)
        self._optional("Wireless mesh", mesh)

        def clients():
            for row in self._paged(f"/organizations/{org}/wireless/clients/overview/byDevice"):
                serial = row.get("serial")
                online = ((row.get("counts") or {}).get("byStatus") or {}).get("online")
                if serial in recs and online is not None:
                    recs[serial]["extra"]["clients"] = int(online)
        self._optional("Clients per access point", clients)

    def _telemetry(self, org: str, nets: list[dict], devices: list[dict], statuses: dict) -> None:
        names = {d["serial"]: d.get("name") or d["serial"] for d in devices}
        net_names = {n["id"]: n.get("name") for n in nets}
        per_net: dict[str, Counter] = {}
        for d in devices:
            per_net.setdefault(d.get("networkId") or "", Counter())[STATUS.get(statuses.get(d["serial"], {}).get("status", ""), "unknown")] += 1
        self.data["networks"] = sorted(({"id": n["id"], "name": n.get("name"), "types": n.get("productTypes") or [],
                                         "tz": n.get("timeZone"), "tags": n.get("tags") or [], **dict(per_net.get(n["id"], Counter()))}
                                        for n in nets), key=lambda n: str(n["name"]).lower())
        self.data["by_type"] = {}
        for d in devices:
            t = TYPES.get(d.get("productType", ""), "Other")
            c = self.data["by_type"].setdefault(t, {"total": 0, "up": 0, "warn": 0, "down": 0, "off": 0, "unknown": 0})
            c["total"] += 1
            c[STATUS.get(statuses.get(d["serial"], {}).get("status", ""), "unknown")] += 1
        self.data["firmware"] = Counter(f"{d.get('model', '?')} {d.get('firmware') or '?'}" for d in devices).most_common(15)

        def uplinks():
            out = []
            for a in self._paged(f"/organizations/{org}/appliance/uplink/statuses"):
                for u in a.get("uplinks") or []:
                    out.append({"serial": a.get("serial"), "device": names.get(a.get("serial"), a.get("serial")),
                                "network": net_names.get(a.get("networkId")), "interface": u.get("interface"),
                                "status": u.get("status"), "ip": u.get("ip"), "public_ip": u.get("publicIp"),
                                "gateway": u.get("gateway"), "provider": u.get("provider"),
                                "ha_role": (a.get("highAvailability") or {}).get("role")})
            return out
        self.data["uplinks"] = self._optional("Appliance uplinks", uplinks) or []

        def loss_latency():
            out = []
            for u in self._paged(f"/organizations/{org}/devices/uplinksLossAndLatency", {"timespan": 300}):
                series = [p for p in u.get("timeSeries") or [] if p.get("latencyMs") is not None or p.get("lossPercent") is not None]
                last = series[-1] if series else {}
                out.append({"serial": u.get("serial"), "device": names.get(u.get("serial"), u.get("serial")), "uplink": u.get("uplink"),
                            "target": u.get("ip"), "latency_ms": last.get("latencyMs"), "loss_pct": last.get("lossPercent")})
            return out
        self.data["loss_latency"] = self._optional("Uplink loss and latency", loss_latency) or []

        def clients():
            body = self._get(f"{BASE}/organizations/{org}/clients/overview", params={"timespan": 3600}).json()
            usage = ((body.get("usages") or {}).get("overall") or {})
            # kilobytes over the hour -> average bits per second
            return {"total": (body.get("counts") or {}).get("total"),
                    "down_bps": usage.get("downstream") * 8000 / 3600 if usage.get("downstream") is not None else None,
                    "up_bps": usage.get("upstream") * 8000 / 3600 if usage.get("upstream") is not None else None}
        self.data["clients"] = self._optional("Client overview", clients) or {}

        def licensing():
            body = self._get(f"{BASE}/organizations/{org}/licenses/overview").json()
            return {"status": body.get("status"), "expires": body.get("expirationDate"), "model": "co-term"}
        self.data["licensing"] = self._optional("Licensing", licensing) or {}
