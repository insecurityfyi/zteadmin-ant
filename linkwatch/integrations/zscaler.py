"""Zscaler platform over OneAPI: ZIA, ZPA, ZDX, Client Connector and Zero Trust Branch.

One ZIdentity API client authenticates every product. Tokens come from
``https://<vanity>.zslogin.net/oauth2/v1/token`` (client-credentials grant,
audience ``https://api.zscaler.com``) and are sent as a Bearer token to
``https://api.zsapi.net`` (or ``https://api.<cloud>.zsapi.net`` for non
production clouds). Paths follow Zscaler's own Python SDK:

* ZIA   /zia/api/v1/locations, /zia/api/v1/greTunnels
* ZPA   /zpa/mgmtconfig/v1/admin/customers/{customerId}/connector
* ZDX   /zdx/v1/apps
* ZCC   /zcc/papi/public/v1/getDevices
* ZTB   /ztb/api/v2/Site/   (marked experimental in the SDK as well)
"""
from __future__ import annotations

import re
import time
from collections import Counter
from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record

TOKEN_AUDIENCE = "https://api.zscaler.com"


def _epoch(v) -> str | None:
    """ZPA sends epoch seconds or milliseconds as strings. Returns ISO UTC."""
    from datetime import datetime, timezone
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    if n > 1e11:
        n /= 1000
    return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
PRODUCTS = ("zia", "zpa", "zdx", "zcc", "ztb")


class Zscaler(Integration):
    kind = "zscaler"
    label = "Zscaler"
    runs_on = "server"
    description = "One OneAPI connection for ZIA, ZPA, ZDX, Client Connector and Zero Trust Branch."
    fields = [
        Field("vanity_domain", "ZIdentity vanity domain", help="The 'acme' in acme.zslogin.net."),
        Field("client_id", "API client ID"),
        Field("client_secret", "API client secret", "password"),
        Field("cloud", "Cloud", required=False, help="Leave blank for production. Set e.g. 'beta' for api.beta.zsapi.net."),
        Field("zpa_customer_id", "ZPA customer ID", required=False, help="Needed for ZPA. Shown in the ZPA admin portal under Public API."),
        Field("zia", "ZIA locations and tunnels", "bool", required=False, default=True),
        Field("zpa", "ZPA App Connectors", "bool", required=False, default=True),
        Field("zdx", "ZDX application scores", "bool", required=False, default=True),
        Field("zcc", "Client Connector device counts", "bool", required=False, default=True),
        Field("ztb", "Zero Trust Branch sites (experimental)", "bool", required=False, default=False),
        Field("ztb_api_key", "ZTB API key (optional)", "password", required=False,
              help="If ZTB refuses the OneAPI client: create an API key in the ZTB admin portal and paste it here."),
        Field("ztb_tenant", "ZTB portal address", required=False,
              help="Needed with a ZTB API key: the 'acme' in acme.goairgap.com, or the full https:// address."),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        cloud = str(config.get("cloud") or "").strip().strip(".")
        self.base = f"https://api.{cloud}.zsapi.net" if cloud else "https://api.zsapi.net"
        self._token: str | None = None
        self._token_exp = 0.0
        self.errors: list[str] = []
        self.data: dict[str, Any] = {"type": "zscaler", "products": {}, "unavailable": []}

    def _optional(self, label: str, fn):
        """Extra detail that some tenants or licences don't have: a failure is noted on the page, not an error."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - any failure here only hides one panel
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    # auth ---------------------------------------------------------------
    @property
    def token_url(self) -> str:
        return f"https://{self.config['vanity_domain'].strip()}.zslogin.net/oauth2/v1/token"

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_exp - 60:
            try:
                resp = self.http.post(self.token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                    "audience": TOKEN_AUDIENCE,
                })
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach ZIdentity: {exc.__class__.__name__}") from exc
            if resp.status_code != 200:
                raise IntegrationError(f"ZIdentity token request failed with HTTP {resp.status_code}. Check the vanity domain, client ID and secret.")
            body = resp.json()
            self._token = body["access_token"]
            self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self._token}"}

    def api(self, path: str, params: dict | None = None) -> Any:
        url = self.base + path
        reauthed = False
        for attempt in range(5):
            try:
                resp = self.http.get(url, params=params, headers=self._headers())
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach {self.base}: {exc.__class__.__name__}") from exc
            if resp.status_code == 429 and attempt < 4:
                try:
                    wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                except ValueError:
                    wait = 2.0
                self._sleep(min(max(wait, 0.5), 30))
                continue
            if resp.status_code == 401 and not reauthed:
                self._token, reauthed = None, True
                continue
            if resp.status_code in (401, 403):
                raise IntegrationError(f"GET {path} was refused (HTTP {resp.status_code}). Check the API client's roles for this product.")
            if resp.status_code >= 400:
                raise IntegrationError(f"GET {path} returned HTTP {resp.status_code}")
            return resp.json() if resp.content else None
        raise IntegrationError(f"GET {path} kept returning HTTP 429")

    @staticmethod
    def _sleep(seconds: float) -> None:
        time.sleep(seconds)

    def _enabled(self, product: str) -> bool:
        default = next(f.default for f in self.fields if f.name == product)
        return bool(self.config.get(product, default))

    # collection ---------------------------------------------------------
    def collect(self) -> list[Record]:
        records: list[Record] = []
        self.errors = []
        self.data = {"type": "zscaler", "products": {}, "unavailable": []}
        for product in PRODUCTS:
            if not self._enabled(product):
                continue
            try:
                got = getattr(self, f"_collect_{product}")()
                records.extend(got)
                self.data["products"][product] = {"ok": True, "objects": len(got)}
            except IntegrationError as exc:
                self.errors.append(f"{product.upper()}: {exc}")
                self.data["products"][product] = {"ok": False, "error": str(exc)}
        if self.errors and not records:
            raise IntegrationError("; ".join(self.errors))
        return records

    def _collect_zia(self) -> list[Record]:
        out: list[Record] = []
        locations = self._zia_paged("/zia/api/v1/locations")
        tunnels = self._zia_paged("/zia/api/v1/greTunnels")
        status = self._optional("ZIA activation status", lambda: self.api("/zia/api/v1/status")) or {}
        self.data["zia"] = {
            "activation": status.get("status") if isinstance(status, dict) else None,
            "locations": [{"id": loc.get("id"), "name": loc.get("name"), "country": loc.get("country"), "tz": loc.get("tz"),
                           "ips": loc.get("ipAddresses") or [], "vpn_credentials": len(loc.get("vpnCredentials") or []),
                           "up_kbps": loc.get("upBandwidth"), "down_kbps": loc.get("dnBandwidth"),
                           "firewall": loc.get("ofwEnabled"), "ssl_scan": loc.get("sslScanEnabled"),
                           "auth": loc.get("authRequired"), "xff": loc.get("xffForwardEnabled"),
                           "sub": bool(loc.get("parentId"))} for loc in locations],
            "tunnels": [{"id": t.get("id"), "source_ip": t.get("sourceIp"), "comment": t.get("comment"),
                         "primary": (t.get("primaryDestVip") or {}).get("datacenter"),
                         "primary_vip": (t.get("primaryDestVip") or {}).get("virtualIp"),
                         "secondary": (t.get("secondaryDestVip") or {}).get("datacenter"),
                         "secondary_vip": (t.get("secondaryDestVip") or {}).get("virtualIp"),
                         "inside": t.get("internalIpRange")} for t in tunnels],
        }
        for loc in locations:
            out.append(Record(
                external_id=f"zia-loc-{loc.get('id')}", hostname=f"ZIA location {loc.get('name', loc.get('id'))}",
                ip=None, type="Zscaler", platform="ZIA location", site=loc.get("name"), status="unknown",
                detail=", ".join(loc.get("ipAddresses") or []) or "No static IPs",
                extra={"product": "zia", "country": loc.get("country"), "vpnCredentials": len(loc.get("vpnCredentials") or [])},
            ))
        for t in tunnels:
            src = t.get("sourceIp", "")
            out.append(Record(
                external_id=f"zia-gre-{t.get('id')}", hostname=f"ZIA GRE {src}", ip=src or None, type="Zscaler",
                platform="ZIA GRE tunnel", site=None, status="unknown",
                detail=f"Primary {((t.get('primaryDestVip') or {}).get('datacenter') or '?')}, "
                       f"secondary {((t.get('secondaryDestVip') or {}).get('datacenter') or '?')}",
                extra={"product": "zia", "comment": t.get("comment")},
            ))
        return out

    def _zia_paged(self, path: str, page_size: int = 500) -> list[dict]:
        items: list[dict] = []
        for page in range(1, 50):
            chunk = self.api(path, {"page": page, "pageSize": page_size}) or []
            items.extend(chunk)
            if len(chunk) < page_size:
                break
        return items

    def _collect_zpa(self) -> list[Record]:
        cid = str(self.config.get("zpa_customer_id") or "").strip()
        if not cid:
            raise IntegrationError("ZPA customer ID is not set")
        base = f"/zpa/mgmtconfig/v1/admin/customers/{cid}"
        path = f"{base}/connector"
        out: list[Record] = []
        connectors: list[dict] = []
        page, pages = 1, 1
        while page <= pages and page <= 50:
            body = self.api(path, {"page": page, "pagesize": 500}) or {}
            pages = int(body.get("totalPages") or 1)
            for c in body.get("list", []):
                healthy = c.get("controlChannelStatus") == "ZPN_STATUS_AUTHENTICATED"
                connectors.append({"id": c.get("id"), "name": c.get("name"), "group": c.get("appConnectorGroupName"),
                                   "enabled": c.get("enabled", True) is not False, "healthy": healthy,
                                   "channel": str(c.get("controlChannelStatus", "unknown")).replace("ZPN_STATUS_", "").lower(),
                                   "version": c.get("currentVersion"), "expected": c.get("expectedVersion"),
                                   "upgrade": c.get("upgradeStatus"), "private_ip": c.get("privateIp"), "public_ip": c.get("publicIp"),
                                   "location": c.get("location"), "os": c.get("runtimeOS") or c.get("platform"),
                                   "last_connect": _epoch(c.get("lastBrokerConnectTime"))})
                out.append(Record(
                    external_id=f"zpa-ac-{c.get('id')}", hostname=c.get("name") or f"connector {c.get('id')}",
                    ip=c.get("privateIp") or None, type="Zscaler",
                    platform=f"ZPA App Connector {c.get('currentVersion') or ''}".strip(),
                    site=c.get("appConnectorGroupName"), status="up" if healthy else ("off" if c.get("enabled") is False else "down"),
                    detail=f"Control channel {str(c.get('controlChannelStatus', 'unknown')).replace('ZPN_STATUS_', '').lower()}, "
                           f"public IP {c.get('publicIp') or '?'}",
                    extra={"product": "zpa", "expectedVersion": c.get("expectedVersion"), "upgradeStatus": c.get("upgradeStatus")},
                ))
            page += 1
        count = lambda sub: int(((self.api(f"{base}/{sub}", {"page": 1, "pagesize": 1}) or {}).get("totalCount")) or 0)  # noqa: E731
        self.data["zpa"] = {"connectors": connectors,
                            "groups": self._optional("ZPA connector groups", lambda: count("appConnectorGroup")),
                            "applications": self._optional("ZPA application segments", lambda: count("application")),
                            "healthy": sum(1 for c in connectors if c["healthy"]),
                            "outdated": sum(1 for c in connectors if c["expected"] and c["version"] and c["expected"] != c["version"])}
        return out

    def _collect_zdx(self) -> list[Record]:
        out: list[Record] = []
        apps = self.api("/zdx/v1/apps", {"since": 2}) or []
        self.data["zdx"] = {"apps": [{"id": a.get("id"), "name": a.get("name"), "score": a.get("score"), "users": a.get("total_users"),
                                      "region": (a.get("most_impacted_region") or {}).get("country")
                                      if isinstance(a.get("most_impacted_region"), dict) else a.get("most_impacted_region")}
                                     for a in apps]}
        for app in apps:
            score = app.get("score")
            status = "unknown" if score is None else ("up" if score >= 66 else "warn" if score >= 34 else "down")
            out.append(Record(
                external_id=f"zdx-app-{app.get('id')}", hostname=f"ZDX {app.get('name')}", ip=None, type="Zscaler",
                platform="ZDX application", site=None, status=status,
                detail=f"Score {score if score is not None else 'n/a'} across {app.get('total_users', '?')} users",
                extra={"product": "zdx", "score": score, "most_impacted_region": app.get("most_impacted_region")},
            ))
        return out

    def _collect_zcc(self) -> list[Record]:
        devices: list[dict] = []
        for page in range(1, 40):
            chunk = self.api("/zcc/papi/public/v1/getDevices", {"page": page, "pageSize": 5000}) or []
            devices.extend(chunk)
            if len(chunk) < 5000:
                break
        versions = Counter(str(d.get("agentVersion") or "unknown") for d in devices)
        oses = Counter(str(d.get("osVersion") or d.get("type") or "unknown").split(" ")[0] for d in devices)
        states = Counter(str(d.get("registrationState") or "unknown") for d in devices)
        self.data["zcc"] = {"total": len(devices), "versions": versions.most_common(15), "os": oses.most_common(10),
                            "states": states.most_common(), "devices": [
                                {"hostname": d.get("machineHostname") or d.get("hostname"), "user": d.get("user") or d.get("userName"),
                                 "os": d.get("osVersion") or d.get("type"), "version": d.get("agentVersion"),
                                 "state": d.get("registrationState"), "model": d.get("deviceModel"),
                                 "last_seen": d.get("lastSeenTime") or d.get("last_seen_time")} for d in devices[:1000]]}
        return [Record(
            external_id="zcc-summary", hostname="Client Connector fleet", ip=None, type="Zscaler",
            platform="Zscaler Client Connector", site=None, status="up",
            detail=f"{len(devices)} enrolled devices, {len(versions)} agent versions",
            extra={"product": "zcc", "devices": len(devices), "versions": dict(versions.most_common(10)), "os": dict(oses.most_common(10))},
        )]

    def _ztb_legacy(self, path: str) -> Any:
        """ZTB's own API key flow: POST /api/v3/api-key-auth/login -> delegate_token -> Bearer."""
        tenant = str(self.config.get("ztb_tenant") or "").strip().rstrip("/")
        if not tenant:
            raise IntegrationError("Set 'ZTB portal address' (the 'acme' in acme.goairgap.com) to use the ZTB API key")
        base = tenant if tenant.startswith("https://") else f"https://{tenant.removesuffix('.goairgap.com')}.goairgap.com"
        key = re.sub(r"\s+", "", str(self.config.get("ztb_api_key") or ""))
        try:
            login = self.http.post(f"{base}/api/v3/api-key-auth/login", json={"api_key": key})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(base).host}: {exc.__class__.__name__}") from exc
        if login.status_code != 200:
            raise IntegrationError(f"ZTB API key login failed (HTTP {login.status_code}). Check the key and the portal address.")
        try:
            token = (login.json().get("result") or {})["delegate_token"]
        except (ValueError, KeyError, AttributeError, TypeError):
            raise IntegrationError("ZTB login answered without a delegate_token") from None
        resp = self._get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
        return resp.json() if resp.content else None

    def _collect_ztb(self) -> list[Record]:
        if str(self.config.get("ztb_api_key") or "").strip():
            body = self._ztb_legacy("/api/v2/Site/")
        else:
            try:
                body = self.api("/ztb/api/v2/Site/")
            except IntegrationError as exc:
                if "refused (HTTP 401)" in str(exc) or "refused (HTTP 403)" in str(exc):
                    raise IntegrationError(
                        "OneAPI refused /ztb/api/v2/Site/ (HTTP 401/403). Your ZIdentity API client has no ZTB access, or the "
                        "ZTB tenant isn't linked to ZIdentity yet. Either add ZTB to the API client's roles in ZIdentity, or "
                        "create an API key in the ZTB portal and fill in 'ZTB API key' and 'ZTB portal address'.") from None
                raise
        sites = body if isinstance(body, list) else (body or {}).get("result") or (body or {}).get("data") or (body or {}).get("sites") or []
        out: list[Record] = []
        self.data["ztb"] = {"sites": []}
        for s in sites:
            raw = str(s.get("status") or s.get("state") or s.get("health") or "").lower()
            self.data["ztb"]["sites"].append({
                "name": s.get("display_name") or s.get("name") or s.get("siteName") or s.get("id"),
                "status": raw or "unknown", "gateway": s.get("gatewayType") or s.get("gateway_type"),
                "location": s.get("location") or s.get("city") or s.get("address"),
                "details": {k: v for k, v in s.items() if isinstance(v, (str, int, float, bool)) and k not in ("id", "name", "display_name")}})
            status = "up" if raw in ("up", "online", "active", "healthy", "connected") else \
                     "down" if raw in ("down", "offline", "disconnected", "unhealthy") else "unknown"
            sid = s.get("id") or s.get("siteId") or s.get("site_id") or s.get("name")
            out.append(Record(
                external_id=f"ztb-site-{sid}", hostname=f"ZTB {s.get('display_name') or s.get('name') or s.get('siteName') or sid}", ip=None,
                type="Zscaler", platform="Zero Trust Branch site", site=s.get("display_name") or s.get("name") or s.get("siteName"), status=status,
                detail=f"Gateway type {s.get('gatewayType') or s.get('gateway_type') or '?'}", extra={"product": "ztb"},
            ))
        return out
