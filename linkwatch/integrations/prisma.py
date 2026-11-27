"""Palo Alto Networks Prisma Access (Prisma SASE) over the SASE APIs.

Auth: a service account in the tenant service group (TSG) with a read-only role (e.g. View
Only Administrator). Tokens come from ``https://auth.apps.paloaltonetworks.com/oauth2/access_token``
(client credentials, HTTP Basic, ``scope=tsg_id:<tsg>``) and last 15 minutes. Calls go to
``https://api.sase.paloaltonetworks.com``.

* Sites     Insights tunnel list (state, PoP, throughput) for remote networks and service
            connections; config: remote networks and their IPsec tunnels
* Private   ZTNA Connector API (connectors and their state), service connections from config
* Users     Insights connected GlobalProtect users
* Policy    config security rules, pre and post, for the Shared, Mobile Users and Remote Networks folders
* Apps / AI Insights application list (7 days)
* DLP       config data filtering / DLP profiles and the rules whose profile group uses them

None of this has been run against a real tenant. Insights queries are tried on the 3.0 path
first, then the 2.0 path.
"""
from __future__ import annotations

import time
from typing import Any, ClassVar

import httpx

from .base import Field, IntegrationError, Record
from .sse import SSEIntegration, counts, is_ai, num, section_fields, status_of

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE = "https://api.sase.paloaltonetworks.com"
SECTIONS = ["sites", "private", "users", "policy", "apps", "dlp"]
LABELS = {"sites": "Remote networks", "private": "ZTNA & service connections", "users": "Mobile users"}
FOLDERS = ("Shared", "Mobile Users", "Remote Networks")
TUNNEL_STATE = {0: "warn", 1: "up", 2: "down"}


class PrismaAccess(SSEIntegration):
    kind = "prisma"
    label = "Prisma Access"
    vendor = "Prisma Access"
    description = "SASE APIs: remote network tunnels, ZTNA connectors and service connections, mobile users, security rules, app and AI usage, DLP profiles."
    sections = SECTIONS
    labels = LABELS
    gaps: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "sites": [("Per-tunnel latency and loss", "Insights reports tunnel state and throughput; path quality is in Autonomous DEM, licensed separately.")],
        "users": [("Device inventory for disconnected users", "Insights lists connected GlobalProtect users; the full endpoint inventory is in Strata Cloud Manager or Cortex XDR.")],
        "policy": [("Rule hit counts", "Not in the configuration API; see Strata Cloud Manager's policy optimizer.")],
        "apps": [("Prompts and AI Access Security verdicts", "AI Access Security dashboards have no public API yet."),
                 ("Per-app action counts", "The Insights application list gives usage, not allowed versus blocked counts.")],
        "dlp": [("DLP incidents", "Enterprise DLP incidents live in the DLP service's own API and the SaaS Security console, not the SASE APIs used here.")],
    }
    fields: ClassVar[list[Field]] = [
        Field("tsg_id", "Tenant service group (TSG) ID", help="Common Services > Tenant Management. The numeric TSG ID."),
        Field("client_id", "Service account client ID", help="Identity & Access > Service accounts. Looks like name@1234567890.iam.panserviceaccount.com."),
        Field("client_secret", "Service account client secret", "password"),
        Field("region", "Insights region", required=False, default="americas",
              help="Your tenant's region for Insights and ZTNA Connector calls: americas, europe, uk, de, ca, au, jp, sg or in."),
        *section_fields(SECTIONS, LABELS),
        SSEIntegration.ai_category_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self._token: str | None = None
        self._token_exp = 0.0
        self._tunnels: list[dict] | None = None

    def tunnel_list(self) -> list[dict]:
        """Insights tunnel list for the last hour, shared by the sites and private tabs."""
        if self._tunnels is None:
            self._tunnels = self.insights("tunnels/tunnel_list", self._last(hours=1), "tunnel list")
        return self._tunnels

    # auth ---------------------------------------------------------------------
    def auth_headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_exp - 60:
            try:
                resp = self.http.post(AUTH_URL, data={"grant_type": "client_credentials", "scope": f"tsg_id:{str(self.config['tsg_id']).strip()}"},
                                      auth=(str(self.config["client_id"]).strip(), self.secret("client_secret")))
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach the Palo Alto Networks auth service: {exc.__class__.__name__}") from exc
            if resp.status_code != 200:
                raise IntegrationError(f"Token request failed with HTTP {resp.status_code}. Check the TSG ID, client ID and secret, "
                                       "and that the service account belongs to that TSG.")
            body = resp.json()
            self._token = body["access_token"]
            self._token_exp = time.time() + int(body.get("expires_in", 899))
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def reset_auth(self) -> bool:
        self._token = None
        return True

    @property
    def region(self) -> str:
        return str(self.config.get("region") or "americas").strip().lower()

    def config_list(self, path: str, params: dict | None = None, what: str | None = None) -> list[dict]:
        out: list[dict] = []
        offset = 0
        for _ in range(20):
            body = self.request("GET", BASE + path, params={**(params or {}), "limit": 200, "offset": offset}, what=what) or {}
            chunk = body.get("data") if isinstance(body, dict) else body
            chunk = [x for x in chunk or [] if isinstance(x, dict)]
            out.extend(chunk)
            total = int(num(body.get("total")) or 0) if isinstance(body, dict) else 0
            offset += len(chunk)
            if len(chunk) < 200 or (total and offset >= total):
                break
        return out

    def insights(self, resource: str, body: dict, what: str) -> list[dict]:
        """Insights query: 3.0 path, then the 2.0 path. Returns body.data."""
        headers = {"X-PANW-Region": self.region, "Prisma-Tenant": str(self.config["tsg_id"]).strip(), "Content-Type": "application/json"}
        last: Exception | None = None
        for path in (f"/insights/v3.0/resource/query/{resource}", f"/api/sase/v2.0/resource/custom/query/{resource}"):
            try:
                got = self.request("POST", BASE + path, json=body, headers=headers, what=what) or {}
            except IntegrationError as exc:
                if "404" not in str(exc):
                    raise
                last = exc
                continue
            data = got.get("data") if isinstance(got, dict) else got
            return [x for x in data or [] if isinstance(x, dict)]
        raise IntegrationError(f"{what}: no Insights query path answered ({last})")

    @staticmethod
    def _last(days: int = 0, hours: int = 0) -> dict:
        rule = {"property": "event_time", "operator": "last_n_days", "values": [days]} if days else \
               {"property": "event_time", "operator": "last_n_hours", "values": [hours]}
        return {"filter": {"operator": "AND", "rules": [rule]}}

    # sections -------------------------------------------------------------------
    def collect_sites(self) -> list[Record]:
        rns = self.optional("Remote networks (config)", lambda: self.config_list("/sse/config/v1/remote-networks", {"folder": "Remote Networks"}, "remote networks"))
        tunnels = self.optional("Tunnel state (Insights)", self.tunnel_list)
        if rns is None and tunnels is None:
            raise IntegrationError("Neither remote networks nor tunnel state answered: " + "; ".join(self.data["unavailable"][-2:])[:300])
        by_site: dict[str, list[dict]] = {}
        for t in tunnels or []:
            if str(t.get("node_type_name") or "").lower().startswith("service"):
                continue   # service connections are shown on the private tab
            st = TUNNEL_STATE.get(int(num(t.get("tunnel_state")) or 0) if t.get("tunnel_state") is not None else -1) or status_of(t.get("tunnel_state_name"))
            by_site.setdefault(str(t.get("site_name") or t.get("tunnel_name")), []).append({
                "name": t.get("tunnel_name"), "status": st, "pop": t.get("edge_location_display_name") or t.get("cloud_region_name"),
                "peer": t.get("instance_public_ip"), "detail": t.get("tunnel_monitoring_state_name"),
                "bps": num(t.get("avg_throughput"))})
        items = []
        names = {str(r.get("name")): r for r in rns or []}
        for name in sorted(set(names) | set(by_site)):
            r, ts = names.get(name) or {}, by_site.get(name) or []
            if not ts and r:
                ts = [{"name": r.get("ipsec_tunnel"), "status": "unknown"}] + ([{"name": r["secondary_ipsec_tunnel"], "status": "unknown"}] if r.get("secondary_ipsec_tunnel") else [])
            states = [t["status"] for t in ts]
            status = "up" if "up" in states else ("down" if states and all(s == "down" for s in states) else ("warn" if "warn" in states else "unknown"))
            if "up" in states and any(s in ("down", "warn") for s in states):
                status = "warn"
            bps = [t.get("bps") for t in ts if t.get("bps") is not None]
            items.append({"id": r.get("id") or name, "name": name, "type": "Remote network", "status": status,
                          "pop": next((t["pop"] for t in ts if t.get("pop")), None) or r.get("region"), "location": r.get("region"),
                          "tunnels": ts, "down_bps": sum(bps) if bps else None,
                          "detail": f"{r.get('license_type') or ''} {', '.join(r.get('subnets') or [])}".strip()[:160]})
        self.data["sites"] = {"items": items}
        return self.site_records(items, "Prisma Access remote network")

    def collect_private(self) -> list[Record]:
        items = []
        conns = self.optional("ZTNA connectors", lambda: self._ztna())
        for c in conns or []:
            items.append({"id": f"ztna-{c.get('id') or c.get('name')}", "name": str(c.get("name") or c.get("id")), "group": c.get("group_name") or c.get("connector_group"),
                          "status": status_of(c.get("status") or c.get("state")), "state": c.get("status") or c.get("state"),
                          "version": c.get("version") or c.get("software_version"), "ip": c.get("private_ip") or c.get("ip"),
                          "location": c.get("region") or c.get("location"), "platform": "ZTNA connector", "detail": "ZTNA connector"})
        scs = self.optional("Service connections", lambda: self.config_list("/sse/config/v1/service-connections", {"folder": "Service Connections"}, "service connections"))
        tunnels = self.optional("Service connection state (Insights)", lambda: [
            t for t in self.tunnel_list() if str(t.get("node_type_name") or "").lower().startswith("service")])
        state = {str(t.get("site_name") or t.get("tunnel_name")): TUNNEL_STATE.get(int(num(t.get("tunnel_state")) or 0), "unknown") for t in tunnels or []}
        for s in scs or []:
            items.append({"id": f"sc-{s.get('id') or s.get('name')}", "name": str(s.get("name")), "group": "Service connection",
                          "status": state.get(str(s.get("name")), "unknown"), "version": None, "location": s.get("region"),
                          "platform": "Service connection", "detail": f"tunnel {s.get('ipsec_tunnel') or '?'}" + (f", {', '.join(s.get('subnets') or [])}" if s.get("subnets") else "")})
        if conns is None and scs is None:
            raise IntegrationError("Neither ZTNA connectors nor service connections answered: " + "; ".join(self.data["unavailable"][-2:])[:300])
        self.data["private"] = {"items": items, "apps": None, "label": "ZTNA connectors and service connections"}
        return self.private_records(items, "Prisma Access connector")

    def _ztna(self) -> list[dict]:
        body = self.request("GET", BASE + "/sse/connector/v2.0/api/connectors", params={"limit": 500},
                            headers={"X-PANW-Region": self.region}, what="ZTNA connectors") or {}
        rows = body if isinstance(body, list) else body.get("items") or body.get("data") or body.get("connectors") or []
        return [r for r in rows if isinstance(r, dict)]

    def collect_users(self) -> list[Record]:
        rows = self.insights("users/agent/connected_user_list", self._last(hours=1), "connected users")
        devices = [{"hostname": r.get("device_name") or r.get("machine_name") or r.get("hostname"),
                    "user": r.get("user_name") or r.get("username") or r.get("source_user"),
                    "os": " ".join(str(x) for x in (r.get("client_os") or r.get("os"), r.get("client_os_version") or r.get("os_version")) if x) or None,
                    "version": r.get("agent_version") or r.get("client_version") or r.get("gp_version"),
                    "state": "connected", "last_seen": r.get("login_time") or r.get("event_time"),
                    "detail": " · ".join(str(x) for x in (r.get("edge_location_display_name") or r.get("location"), r.get("public_ip") or r.get("client_ip")) if x) or None}
                   for r in rows]
        self.data["users"] = self.fleet(devices, len(devices))
        return [self.fleet_record(self.data["users"], "GlobalProtect")]

    def collect_policy(self) -> list[Record]:
        rulebases = []
        for folder in FOLDERS:
            for position in ("pre", "post"):
                got = self.optional(f"Security rules {folder} ({position})", lambda folder=folder, position=position: self.config_list(
                    "/sse/config/v1/security-rules", {"folder": folder, "position": position}, f"security rules ({folder})"))
                if not got:
                    continue
                rules = [{"order": i + 1, "name": r.get("name"), "enabled": not r.get("disabled"), "action": str(r.get("action") or "").lower() or None,
                          "match": "; ".join(f"{k}: {', '.join(map(str, r.get(k) or []))}" for k in ("application", "category", "destination", "service")
                                             if r.get(k) and r.get(k) != ["any"])[:240] or "any",
                          "scope": ", ".join(map(str, (r.get("source_user") or []) + [z for z in r.get("from") or [] if z != "any"])) or "any",
                          "description": r.get("description"),
                          "profile": ((r.get("profile_setting") or {}).get("group") or [None])[0] if isinstance(r.get("profile_setting"), dict) else None}
                         for i, r in enumerate(got)]
                rulebases.append({"name": f"{folder}: {position}-rules", "rules": rules})
        if not rulebases and len([u for u in self.data["unavailable"] if u.startswith("Security rules")]) == len(FOLDERS) * 2:
            raise IntegrationError("No security rules could be read: " + self.data["unavailable"][-1][:300])
        self.data["policy"] = {"rulebases": rulebases}
        n = sum(len(rb["rules"]) for rb in rulebases)
        return [self.summary_record("policy", "Security policy", "Prisma Access security rules", f"{n} rules in {len(rulebases)} rule bases")]

    def collect_apps(self) -> list[Record]:
        _, _, label = self.window(7)
        rows = self.insights("applications/application_list", self._last(days=7), "application list")
        cat = self.ai_category()
        items = []
        for r in rows:
            name = str(r.get("app_name") or r.get("application") or r.get("app") or "Unknown")
            category = r.get("app_category") or r.get("category") or r.get("app_sub_category") or r.get("subcategory")
            up, down = num(r.get("bytes_sent") or r.get("upload_bytes")), num(r.get("bytes_received") or r.get("download_bytes"))
            total = num(r.get("total_bytes") or r.get("bytes")) or ((up or 0) + (down or 0)) or None
            sanc = r.get("sanctioned_state") or r.get("is_sanctioned") or r.get("sanctioned")
            items.append({"name": name, "category": category, "bytes": total, "up": up, "down": down,
                          "users": int(num(r.get("user_count") or r.get("users") or r.get("unique_users")) or 0) if any(r.get(k) is not None for k in ("user_count", "users", "unique_users")) else None,
                          "events": int(num(r.get("sessions") or r.get("session_count") or r.get("hit_count")) or 0) or None,
                          "risk": num(r.get("risk_of_app") or r.get("risk") or r.get("app_risk")),
                          "sanctioned": None if sanc in (None, "") else ("sanctioned" if str(sanc).lower() in ("true", "sanctioned", "1", "yes") else "unsanctioned"),
                          "ai": is_ai(category, name, cat) or str(r.get("app_tag") or r.get("tags") or "").lower().find("generative") >= 0, "action": None})
        items.sort(key=lambda a: -(a["bytes"] or 0))
        self.data["apps"] = {"window": label, "items": items, "categories_seen": counts(a["category"] for a in items)[:20]}
        return [self.apps_record(self.data["apps"])]

    def collect_dlp(self) -> list[Record]:
        profiles = None
        for path in ("/sse/config/v1/data-filtering-profiles", "/config/security/v1/data-filtering-profiles"):
            try:
                profiles = self.config_list(path, {"folder": "Shared"}, "data filtering profiles")
                break
            except IntegrationError as exc:
                if "404" not in str(exc):
                    raise
        if profiles is None:
            raise IntegrationError("No DLP / data filtering profile API answered on this tenant")
        groups = self.optional("Profile groups", lambda: self.config_list("/sse/config/v1/profile-groups", {"folder": "Shared"}, "profile groups"))
        dlp_groups = {str(g.get("name")) for g in groups or [] if g.get("data_filtering")}
        rules = [{"name": r["name"], "action": r["action"], "enabled": r["enabled"], "covers": r["match"]}
                 for rb in (self.data.get("policy") or {}).get("rulebases") or [] for r in rb["rules"] if r.get("profile") in dlp_groups]
        self.data["dlp"] = {"profiles": [{"name": p.get("name"), "type": "data filtering", "enabled": True,
                                          "detail": ", ".join(str(x.get("name") or x.get("data_object")) for x in p.get("rules") or [] if isinstance(x, dict))[:160]}
                                         for p in profiles],
                            "rules": rules if self.data.get("policy") else None}
        return [self.summary_record("dlp", "DLP profiles", "Prisma Access DLP", f"{len(profiles)} data filtering profiles, {len(rules)} rules use them")]
