"""Cloudflare Zero Trust (Cloudflare One) over the Cloudflare API v4.

Auth: an account API token (My Profile or Manage Account > API Tokens) with read-only
permissions, sent as a Bearer token to ``https://api.cloudflare.com/client/v4``.

* Sites     Magic WAN IPsec and GRE tunnels (configuration; health only where the
            tunnel health-check GraphQL dataset answers)
* Private   Cloudflare Tunnels (cloudflared): status and connections per tunnel
* Users     WARP devices, plus Zero Trust user seats
* Policy    Gateway DNS / HTTP / network rules, Access applications
* Apps / AI Gateway HTTP request analytics (GraphQL), grouped by application, joined to
            Gateway's application list and categories
* DLP       DLP profiles, and Gateway rules that reference them

Not run against a real account yet. The GraphQL dimension names are looked up from the
schema on each refresh, so a renamed field shows as a note instead of breaking the tab.
"""
from __future__ import annotations

import re
import time
from typing import Any, ClassVar

from .base import Field, IntegrationError, Record
from .sse import SSEIntegration, counts, is_ai, num, section_fields, status_of

BASE = "https://api.cloudflare.com/client/v4"
SECTIONS = ["sites", "private", "users", "policy", "apps", "dlp"]
LABELS = {"sites": "Magic WAN tunnels", "private": "Cloudflare Tunnels", "users": "WARP devices", "policy": "Gateway & Access"}
TUNNEL_STATUS = {"healthy": "up", "degraded": "warn", "down": "down", "inactive": "off"}
L7_TYPE = "AccountGatewayL7RequestsAdaptiveGroupsDimensions"


class Cloudflare(SSEIntegration):
    kind = "cloudflare"
    label = "Cloudflare Zero Trust"
    vendor = "Cloudflare"
    description = "API v4: Cloudflare Tunnels, Magic WAN tunnels, WARP devices, Gateway and Access policies, app and AI usage, DLP profiles."
    sections = SECTIONS
    labels = LABELS
    gaps: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "sites": [("Magic WAN tunnel health, where the health-check dataset isn't available", "Health checks are only in GraphQL analytics on Magic WAN plans; otherwise tunnels show their configuration.")],
        "users": [("Device posture results", "Posture checks are configured over the API, but per-device results are only in logs (Logpush).")],
        "policy": [("Rule hit counts per rule", "Gateway analytics count by action, not by rule, over the API.")],
        "apps": [("Prompts sent to AI apps", "Captured only with Gateway's AI prompt logging, into logs (Logpush), not the analytics API."),
                 ("Per-app user counts", "Gateway HTTP analytics are sampled request counts; distinct users per app need Logpush.")],
        "dlp": [("DLP incidents and matched content", "DLP matches are recorded in Gateway HTTP logs (Logpush / Log Explorer), not in an incidents API.")],
    }
    fields: ClassVar[list[Field]] = [
        Field("account_id", "Account ID", help="On the account's Overview page in the dashboard, or in the URL after dash.cloudflare.com/."),
        Field("api_token", "API token", "password",
              help="API Tokens > Create custom token with read permissions listed in the setup guide (Zero Trust, Cloudflare Tunnel, Magic WAN, Account Analytics, DLP)."),
        *section_fields(SECTIONS, LABELS, defaults={"sites": False},
                        help={"sites": "Magic WAN IPsec and GRE tunnels. Leave off unless you use Magic WAN."}),
        SSEIntegration.ai_category_field(),
    ]

    @property
    def acct(self) -> str:
        return str(self.config.get("account_id") or "").strip()

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.secret('api_token')}", "Accept": "application/json"}

    def api(self, path: str, params: dict | None = None, what: str | None = None) -> Any:
        """GET /accounts/{id}<path> -> result, following page-based pagination."""
        out: list = []
        page = 1
        while page <= 50:
            body = self.request("GET", f"{BASE}/accounts/{self.acct}{path}", params={**(params or {}), "page": page, "per_page": 100}, what=what) or {}
            if body.get("success") is False:
                errs = body.get("errors") or [{}]
                raise IntegrationError(f"{what or path}: {str(errs[0].get('message') if isinstance(errs[0], dict) else errs[0])[:200]}")
            result = body.get("result")
            if not isinstance(result, list):
                return result
            out.extend(result)
            info = body.get("result_info") or {}
            pages = int(num(info.get("total_pages")) or 0)
            if not result or (pages and page >= pages) or (not pages and len(result) < 100):
                break
            page += 1
        return out

    def gql(self, query: str, variables: dict, what: str) -> dict:
        body = self.request("POST", f"{BASE}/graphql", json={"query": query, "variables": variables}, what=what) or {}
        if body.get("errors"):
            first = body["errors"][0]
            raise IntegrationError(f"{what}: {str(first.get('message') if isinstance(first, dict) else first)[:200]}")
        return body.get("data") or {}

    # sections -------------------------------------------------------------------
    def collect_sites(self) -> list[Record]:
        items: list[dict] = []
        found = 0
        for kind, path, key in (("IPsec", "/magic/ipsec_tunnels", "ipsec_tunnels"), ("GRE", "/magic/gre_tunnels", "gre_tunnels")):
            got = self.optional(f"Magic WAN {kind} tunnels", lambda path=path, kind=kind: self.api(path, what=f"Magic WAN {kind} tunnels"))
            if got is None:
                continue
            found += 1
            rows = got.get(key) if isinstance(got, dict) else got
            for t in rows or []:
                items.append({"id": f"{kind.lower()}-{t.get('id')}", "name": str(t.get("name") or t.get("id")), "type": f"Magic WAN {kind}",
                              "status": "unknown", "pop": None, "ip": t.get("customer_endpoint") or t.get("customer_gre_endpoint"),
                              "tunnels": [{"name": t.get("name"), "status": "unknown", "peer": t.get("customer_endpoint") or t.get("customer_gre_endpoint")}],
                              "detail": f"{kind} {t.get('interface_address') or ''} to {t.get('cloudflare_endpoint') or t.get('cloudflare_gre_endpoint') or '?'}".strip(),
                              "description": t.get("description")})
        if not found:
            raise IntegrationError("Magic WAN didn't answer (" + "; ".join(self.data["unavailable"][-2:])[:240] + "). Turn this area off if you don't use Magic WAN.")
        if items:
            self.optional("Magic WAN tunnel health", lambda: self._tunnel_health(items))
        self.data["sites"] = {"items": items}
        return self.site_records(items, "Magic WAN tunnel")

    def _tunnel_health(self, items: list[dict]) -> None:
        q = """query h($a: String!, $s: Time!) { viewer { accounts(filter: {accountTag: $a}) {
          magicTransportTunnelHealthChecksAdaptiveGroups(limit: 500, filter: {datetime_geq: $s}) {
            count dimensions { tunnelName resultStatus } } } } }"""
        start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 900))
        accts = (self.gql(q, {"a": self.acct, "s": start}, "Magic WAN health").get("viewer") or {}).get("accounts") or [{}]
        res: dict[str, dict[str, int]] = {}
        for g in accts[0].get("magicTransportTunnelHealthChecksAdaptiveGroups") or []:
            d = g.get("dimensions") or {}
            res.setdefault(str(d.get("tunnelName")), {}).setdefault(str(d.get("resultStatus")), 0)
            res[str(d.get("tunnelName"))][str(d.get("resultStatus"))] += int(g.get("count") or 0)
        for x in items:
            r = res.get(x["name"])
            if r:
                total, ok = sum(r.values()), r.get("healthy", 0)
                x["status"] = "up" if ok == total else ("down" if ok == 0 else "warn")
                x["loss_pct"] = round(100.0 * (total - ok) / total, 2) if total else None
                for t in x["tunnels"]:
                    t["status"] = x["status"]

    def collect_private(self) -> list[Record]:
        tunnels = self.api("/cfd_tunnel", {"is_deleted": "false"}, "Cloudflare Tunnels") or []
        items = []
        for t in tunnels:
            conns = t.get("connections") or []
            versions = sorted({str(c.get("client_version")) for c in conns if c.get("client_version")})
            colos = sorted({str(c.get("colo_name")) for c in conns if c.get("colo_name")})
            items.append({"id": t.get("id"), "name": str(t.get("name") or t.get("id")), "group": t.get("tun_type") or "cfd_tunnel",
                          "status": TUNNEL_STATUS.get(str(t.get("status")).lower(), status_of(t.get("status"))), "state": t.get("status"),
                          "version": ", ".join(versions) or None, "ip": ", ".join(sorted({str(c.get("origin_ip")) for c in conns if c.get("origin_ip")}))[:80] or None,
                          "location": ", ".join(colos) or None, "last_seen": t.get("conns_active_at") or t.get("conns_inactive_at"),
                          "detail": f"{len(conns)} connections" + (f" to {', '.join(colos)}" if colos else "")})
        routes = self.optional("Private network routes", lambda: len(self.api("/teamnet/routes", {"is_deleted": "false"}, "tunnel routes") or []))
        self.data["private"] = {"items": items, "apps": routes, "label": "Cloudflare Tunnels", "apps_label": "private network routes"}
        return self.private_records(items, "Cloudflare Tunnel")

    def collect_users(self) -> list[Record]:
        rows = self.api("/devices", what="WARP devices") or []
        now = time.time()
        devices = []
        for d in rows:
            user = d.get("user") if isinstance(d.get("user"), dict) else {}
            seen = d.get("last_seen")
            recent = _age(seen, now) is not None and _age(seen, now) < 3600
            devices.append({"hostname": d.get("name") or d.get("device_name"), "user": user.get("email") or user.get("name"),
                            "os": " ".join(str(x) for x in (d.get("device_type"), d.get("os_version")) if x) or None, "version": d.get("version"),
                            "state": "seen last hour" if recent else ("revoked" if d.get("revoked_at") else "idle"), "last_seen": seen,
                            "detail": d.get("model")})
        seats = self.optional("Zero Trust users", lambda: self.api("/access/users", what="Zero Trust users"))
        self.data["users"] = self.fleet(devices, sum(1 for d in devices if d["state"] == "seen last hour"))
        if seats is not None:
            self.data["users"]["seats"] = sum(1 for u in seats if u.get("gateway_seat") or u.get("access_seat"))
        return [self.fleet_record(self.data["users"], "Cloudflare WARP")]

    def collect_policy(self) -> list[Record]:
        rules = self.api("/gateway/rules", what="Gateway rules") or []
        by_kind: dict[str, list] = {}
        for r in rules:
            for f in r.get("filters") or ["other"]:
                by_kind.setdefault(str(f), []).append({
                    "order": num(r.get("precedence")) or 0, "name": r.get("name"), "enabled": bool(r.get("enabled")),
                    "action": str(r.get("action") or "").lower() or None, "match": _expr(r.get("traffic")) or "any",
                    "scope": _expr(r.get("identity")) or _expr(r.get("device_posture")) or "everyone", "description": r.get("description"),
                    "dlp": "dlp.profiles" in str(r.get("traffic") or "")})
        names = {"dns": "Gateway DNS rules", "http": "Gateway HTTP rules", "l4": "Gateway network rules", "egress": "Gateway egress rules"}
        rulebases = [{"name": names.get(k, f"Gateway {k} rules"), "rules": sorted(v, key=lambda r: r["order"])} for k, v in sorted(by_kind.items())]
        apps = self.optional("Access applications", lambda: self.api("/access/apps", what="Access applications"))
        if apps is not None:
            rulebases.append({"name": "Access applications", "rules": [
                {"order": i + 1, "name": a.get("name"), "enabled": True, "action": "access", "match": a.get("domain") or a.get("type"),
                 "scope": ", ".join(str(p.get("name")) for p in a.get("policies") or [] if isinstance(p, dict)) or "no policies",
                 "description": a.get("type")} for i, a in enumerate(apps)]})
        self.data["policy"] = {"rulebases": rulebases}
        return [self.summary_record("policy", "Gateway policy", "Cloudflare Gateway", f"{sum(1 for r in rules if r.get('enabled'))} enabled Gateway rules"
                                    + (f", {len(apps)} Access apps" if apps is not None else ""))]

    def collect_apps(self) -> list[Record]:
        start, end, label = self.window(7)
        types = self.optional("Gateway application list", lambda: self.api("/gateway/app_types", what="Gateway app types")) or []
        app_names = {str(t.get("id")): t.get("name") for t in types if t.get("application_type_id") is not None}
        type_names = {str(t.get("id")): t.get("name") for t in types if t.get("application_type_id") is None}
        app_type = {str(t.get("id")): type_names.get(str(t.get("application_type_id"))) for t in types if t.get("application_type_id") is not None}
        dims = {f["name"] for f in ((self.gql(f'query {{ __type(name: "{L7_TYPE}") {{ fields {{ name }} }} }}', {}, "Gateway analytics schema")
                                     .get("__type") or {}).get("fields") or [])}
        app_dim = next((d for d in ("httpApplicationIds", "applicationIds", "appIds") if d in dims), None)
        host_dim = "httpHost" if "httpHost" in dims else None
        if not app_dim and not host_dim:
            raise IntegrationError(f"Gateway HTTP analytics has no application or host dimension (has: {', '.join(sorted(dims))[:200]})")
        pick = [d for d in (app_dim or host_dim, "action" if "action" in dims else None) if d]
        q = """query a($a: String!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
          gatewayL7RequestsAdaptiveGroups(limit: 5000, filter: {datetime_geq: $s, datetime_leq: $e}, orderBy: [count_DESC]) {
            count dimensions { DIMS } } } } }""".replace("DIMS", " ".join(pick))
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        accts = (self.gql(q, {"a": self.acct, "s": iso(start), "e": iso(end)}, "Gateway HTTP analytics").get("viewer") or {}).get("accounts") or [{}]
        cat = self.ai_category()
        merged: dict[str, dict] = {}
        for g in accts[0].get("gatewayL7RequestsAdaptiveGroups") or []:
            d = g.get("dimensions") or {}
            raw = d.get(pick[0])
            ids = raw if isinstance(raw, list) else re.findall(r"\d+", str(raw)) if app_dim else [raw]
            for i in ids or ["unknown"]:
                name = app_names.get(str(i)) or (str(i) if not app_dim else f"App {i}")
                a = merged.setdefault(name, {"name": name, "category": app_type.get(str(i)), "events": 0, "blocked": 0})
                a["events"] += int(g.get("count") or 0)
                if str(d.get("action") or "").lower() in ("block", "blocked", "2"):
                    a["blocked"] += int(g.get("count") or 0)
        items = []
        for a in merged.values():
            a.update(ai=is_ai(a["category"], a["name"], cat), users=None, bytes=None, up=None, down=None, risk=None, sanctioned=None,
                     action=("block" if a["blocked"] >= a["events"] else "partly blocked") if a["blocked"] else ("allow" if "action" in pick else None))
            items.append(a)
        items.sort(key=lambda a: -a["events"])
        self.data["apps"] = {"window": label, "items": items, "categories_seen": counts(a["category"] for a in items)[:20],
                             "note": "Request counts from sampled Gateway HTTP analytics." + ("" if app_dim else " Grouped by host: this account's schema has no application dimension.")}
        return [self.apps_record(self.data["apps"])]

    def collect_dlp(self) -> list[Record]:
        profiles = self.api("/dlp/profiles", what="DLP profiles") or []
        out = []
        for p in profiles:
            entries = p.get("entries") or []
            on = sum(1 for e in entries if isinstance(e, dict) and e.get("enabled"))
            out.append({"name": p.get("name"), "type": p.get("type"), "enabled": on > 0 or not entries,
                        "detail": f"{on} of {len(entries)} detections on" if entries else (p.get("description") or "")})
        rules = None
        if self.data.get("policy"):
            rules = [{"name": r["name"], "action": r["action"], "enabled": r["enabled"], "covers": r["match"][:200]}
                     for rb in self.data["policy"]["rulebases"] for r in rb["rules"] if r.get("dlp")]
        else:
            got = self.optional("Gateway rules for DLP", lambda: self.api("/gateway/rules", what="Gateway rules"))
            if got is not None:
                rules = [{"name": r.get("name"), "action": r.get("action"), "enabled": bool(r.get("enabled")), "covers": _expr(r.get("traffic"))[:200]}
                         for r in got if "dlp.profiles" in str(r.get("traffic") or "")]
        self.data["dlp"] = {"profiles": out, "rules": rules}
        return [self.summary_record("dlp", "DLP profiles", "Cloudflare DLP", f"{len(out)} profiles, {sum(1 for p in out if p['enabled'])} in use"
                                    + (f", {len(rules)} Gateway rules apply them" if rules is not None else ""))]


def _expr(v: Any) -> str:
    return re.sub(r"\s+", " ", str(v or "")).strip()


def _age(v: Any, now: float) -> float | None:
    from datetime import datetime
    try:
        return now - datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
