"""Cloudflare-only tabs on top of the shared SSE ones: Gateway, Access, DEX & posture, Zones and Audit
log, plus Magic WAN and tunnel-route panels for the shared tabs. Mixed into ``Cloudflare``, which
provides ``api()``, ``api_root()``, ``gql()``, ``dims()`` and ``optional()``.

Every call is a read. Calls are listed in docs/cloudflare-zero-trust.md with the token permission
each needs; an area whose permission is missing shows its error on its own tab and the rest sync.
"""
from __future__ import annotations

import time
from collections import Counter
from datetime import datetime
from typing import Any

from .base import IntegrationError, Record
from .sse import counts, num

# Gateway DNS log ResolverDecision codes (Cloudflare's DNS log field reference). GraphQL may return
# the code or the name; anything whose name contains "blocked" counts as blocked.
RESOLVER_DECISIONS = {
    0: "unknown", 1: "allowedByQueryName", 2: "allowedByAnswer", 3: "blockedByQueryName", 4: "blockedByAnswer",
    5: "blockedByCategory", 6: "blockedAlwaysCategory", 7: "allowedOnNoLocation", 8: "allowedOnNoPolicyMatch",
    9: "overrideForSafeSearch", 10: "overrideApplied", 11: "allowedRule", 12: "blockedRule",
}
HTTP_ACTIONS = {0: "unknown", 1: "allow", 2: "block", 3: "isolate", 4: "do not inspect", 5: "override"}
DNS_TYPE = "AccountGatewayResolverQueriesAdaptiveGroupsDimensions"
L7_TYPE = "AccountGatewayL7RequestsAdaptiveGroupsDimensions"
L4_TYPE = "AccountGatewayL4SessionsAdaptiveGroupsDimensions"
MAX_ZONES = 50
TOKEN_WARN_DAYS = 30


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _when(v: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _label(v: Any, table: dict[int, str]) -> str:
    n = num(v)
    if n is not None and int(n) in table:
        return table[int(n)]
    return str(v if v not in (None, "") else "unknown")


def _blocked(label: str) -> bool:
    return "block" in label.lower()


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


class CloudflareExtras:
    """Cloudflare's own sections. Expects the host class to define api, api_root, gql, dims, optional, record."""

    data: dict[str, Any]

    # Gateway ------------------------------------------------------------------
    def collect_gateway(self) -> list[Record]:
        start, end = time.time() - 86400, time.time()
        g: dict[str, Any] = {"window": "24 hours"}
        g["dns"] = self.optional("Gateway DNS analytics", lambda: self._gw_dns(start, end))
        g["http"] = self.optional("Gateway HTTP analytics", lambda: self._gw_http(start, end))
        g["network"] = self.optional("Gateway network analytics", lambda: self._gw_l4(start, end))
        locs = self.optional("Gateway DNS locations", lambda: self.api("/gateway/locations", what="Gateway locations"))
        g["locations"] = [{"name": x.get("name"), "default": bool(x.get("client_default")), "ecs": bool(x.get("ecs_support")),
                           "networks": [n.get("network") for n in x.get("networks") or [] if isinstance(n, dict)],
                           "doh": x.get("doh_subdomain"), "ip": x.get("ip") or x.get("ipv4_destination")} for x in locs or []] if locs is not None else None
        lists = self.optional("Gateway lists", lambda: self.api("/gateway/lists", what="Gateway lists"))
        g["lists"] = [{"name": x.get("name"), "type": x.get("type"), "count": x.get("count"), "description": x.get("description")}
                      for x in lists or []] if lists is not None else None
        proxies = self.optional("Gateway proxy endpoints", lambda: self.api("/gateway/proxy_endpoints", what="proxy endpoints"))
        g["proxy_endpoints"] = [{"name": x.get("name"), "subdomain": x.get("subdomain"), "ips": x.get("ips") or []} for x in proxies or []] if proxies is not None else None
        conf = self.optional("Gateway settings", lambda: self.api("/gateway/configuration", what="Gateway settings"))
        g["settings"] = self._gw_settings((conf or {}).get("settings") or {}) if conf is not None else None
        if all(g.get(k) is None for k in ("dns", "http", "network", "locations", "lists", "settings")):
            raise IntegrationError("No Gateway call answered: " + "; ".join(self.data["unavailable"][-3:])[:300])
        self.data["gateway"] = g
        for key, part in (("gateway:dns", g.get("dns")), ("gateway:http", g.get("http")), ("gateway:network", g.get("network"))):
            if part:
                self.data.setdefault("metrics", []).append([key, part["total"], part["blocked"], None])
        dns, http = g.get("dns") or {}, g.get("http") or {}
        detail = ", ".join(x for x in (
            f"{dns['total']:,} DNS queries ({dns['blocked']:,} blocked)" if dns else "",
            f"{http['total']:,} HTTP requests ({http['blocked']:,} blocked)" if http else "") if x) or "configuration only"
        return [self.record("gateway", "summary", "Gateway traffic", "Cloudflare Gateway", "up", detail + " in 24 hours")]

    def _breakdown(self, rows: list[dict], key_dim: str, top_dim: str | None, table: dict[int, str]) -> dict[str, Any]:
        by: Counter = Counter()
        top: Counter = Counter()
        for r in rows:
            d = r.get("dimensions") or {}
            n = int(r.get("count") or 0)
            label = _label(d.get(key_dim), table)
            by[label] += n
            if top_dim and _blocked(label) and d.get(top_dim):
                top[str(d[top_dim])] += n
        total = sum(by.values())
        blocked = sum(n for k, n in by.items() if _blocked(k))
        return {"total": total, "blocked": blocked, "by_decision": [list(x) for x in by.most_common()],
                "top_blocked": [list(x) for x in top.most_common(15)]}

    def _gw_query(self, dataset: str, dims: list[str], start: float, end: float, what: str) -> list[dict]:
        q = """query q($a: String!, $s: Time!, $e: Time!) { viewer { accounts(filter: {accountTag: $a}) {
          DATASET(limit: 5000, filter: {datetime_geq: $s, datetime_leq: $e}, orderBy: [count_DESC]) { count dimensions { DIMS } } } } }"""
        q = q.replace("DATASET", dataset).replace("DIMS", " ".join(dims))
        accts = (self.gql(q, {"a": self.acct, "s": _iso(start), "e": _iso(end)}, what).get("viewer") or {}).get("accounts") or [{}]
        return accts[0].get(dataset) or []

    def _gw_dns(self, start: float, end: float) -> dict[str, Any]:
        have = self.dims(DNS_TYPE)
        if "resolverDecision" not in have:
            raise IntegrationError("this account's DNS analytics has no resolverDecision dimension")
        name = next((d for d in ("queryName", "queryNameReversed") if d in have), None)
        rows = self._gw_query("gatewayResolverQueriesAdaptiveGroups", ["resolverDecision", *([name] if name else [])], start, end, "Gateway DNS analytics")
        out = self._breakdown(rows, "resolverDecision", name, RESOLVER_DECISIONS)
        if name == "queryNameReversed":   # com.example.www -> www.example.com
            out["top_blocked"] = [[".".join(reversed(k.split("."))), n] for k, n in out["top_blocked"]]
        cat = next((d for d in ("categoryIds", "categoryNames") if d in have), None)
        if cat:
            names = {}
            if cat == "categoryIds":
                cats = self.optional("Gateway categories", lambda: self.api("/gateway/categories", what="Gateway categories")) or []
                for c in cats:
                    names[str(c.get("id"))] = c.get("name")
                    for sub in c.get("subcategories") or []:
                        names[str(sub.get("id"))] = sub.get("name")
            crow = self._gw_query("gatewayResolverQueriesAdaptiveGroups", [cat, "resolverDecision"], start, end, "DNS categories")
            blocked_cats: Counter = Counter()
            for r in crow:
                d = r.get("dimensions") or {}
                if _blocked(_label(d.get("resolverDecision"), RESOLVER_DECISIONS)):
                    for c in d.get(cat) if isinstance(d.get(cat), list) else [d.get(cat)]:
                        blocked_cats[names.get(str(c)) or str(c)] += int(r.get("count") or 0)
            out["top_blocked_categories"] = [list(x) for x in blocked_cats.most_common(10)]
        return out

    def _gw_http(self, start: float, end: float) -> dict[str, Any]:
        have = self.dims(L7_TYPE)
        if "action" not in have:
            raise IntegrationError("this account's HTTP analytics has no action dimension")
        host = "httpHost" if "httpHost" in have else None
        rows = self._gw_query("gatewayL7RequestsAdaptiveGroups", ["action", *([host] if host else [])], start, end, "Gateway HTTP analytics")
        return self._breakdown(rows, "action", host, HTTP_ACTIONS)

    def _gw_l4(self, start: float, end: float) -> dict[str, Any]:
        have = self.dims(L4_TYPE)
        act = next((d for d in ("action", "sessionAction", "decision") if d in have), None)
        if not act:
            raise IntegrationError("this account's network analytics has no action dimension")
        dest = next((d for d in ("destinationIp", "dstIp", "destinationPort") if d in have), None)
        rows = self._gw_query("gatewayL4SessionsAdaptiveGroups", [act, *([dest] if dest else [])], start, end, "Gateway network analytics")
        return self._breakdown(rows, act, dest, HTTP_ACTIONS)

    @staticmethod
    def _gw_settings(s: dict) -> list[list]:
        def on(*path):
            v: Any = s
            for p in path:
                v = v.get(p) if isinstance(v, dict) else None
            return v
        return [[label, value] for label, value in (
            ("TLS decryption", on("tls_decrypt", "enabled")),
            ("Activity logging", on("activity_log", "enabled")),
            ("Anti-virus scanning (upload / download)", f"{bool(on('antivirus', 'enabled_upload_phase'))} / {bool(on('antivirus', 'enabled_download_phase'))}"
             if isinstance(s.get("antivirus"), dict) else None),
            ("Browser isolation for URLs", on("browser_isolation", "url_browser_isolation_enabled")),
            ("Non-identity on-ramps can isolate", on("browser_isolation", "non_identity_enabled")),
            ("FIPS compliant TLS", on("fips", "tls")),
            ("Protocol detection", on("protocol_detection", "enabled")),
            ("Custom block page", on("block_page", "enabled")),
            ("Body scanning (DLP inspection mode)", on("body_scanning", "inspection_mode")),
            ("Extended email matching", on("extended_email_matching", "enabled")),
        ) if value is not None]

    # Access -------------------------------------------------------------------
    def collect_access(self) -> list[Record]:
        a: dict[str, Any] = {}
        apps = self.optional("Access applications", lambda: self.api("/access/apps", what="Access applications"))
        a["apps"] = [{"name": x.get("name"), "domain": x.get("domain") or ", ".join(map(str, x.get("self_hosted_domains") or [])), "type": x.get("type"),
                      "session": x.get("session_duration"), "idps": len(x.get("allowed_idps") or []) or "all",
                      "policies": [p.get("name") for p in x.get("policies") or [] if isinstance(p, dict)],
                      "auto_redirect": x.get("auto_redirect_to_identity"), "created": x.get("created_at")} for x in apps or []] if apps is not None else None
        pols = self.optional("Access reusable policies", lambda: self.api("/access/policies", what="Access policies"))
        a["policies"] = [{"name": p.get("name"), "decision": p.get("decision"), "apps": p.get("app_count"),
                          "include": _rules(p.get("include")), "require": _rules(p.get("require")), "exclude": _rules(p.get("exclude")),
                          "session": p.get("session_duration")} for p in pols or []] if pols is not None else None
        idps = self.optional("Identity providers", lambda: self.api("/access/identity_providers", what="identity providers"))
        a["idps"] = [{"name": x.get("name"), "type": x.get("type"), "scim": bool((x.get("scim_config") or {}).get("enabled"))} for x in idps or []] if idps is not None else None
        groups = self.optional("Access groups", lambda: self.api("/access/groups", what="Access groups"))
        a["groups"] = [{"name": x.get("name"), "include": _rules(x.get("include"))} for x in groups or []] if groups is not None else None
        now = time.time()
        toks = self.optional("Service tokens", lambda: self.api("/access/service_tokens", what="service tokens"))
        tokens = []
        for t in toks or []:
            exp = _when(t.get("expires_at"))
            days = None if exp is None else int((exp - now) // 86400)
            tokens.append({"name": t.get("name"), "expires": t.get("expires_at"), "days": days, "last_seen": t.get("last_seen_at"),
                           "status": "unknown" if days is None else ("down" if days < 0 else ("warn" if days <= TOKEN_WARN_DAYS else "up"))})
        a["service_tokens"] = sorted(tokens, key=lambda t: (t["days"] is None, t["days"] or 0)) if toks is not None else None
        org = self.optional("Zero Trust organization", lambda: self.api("/access/organizations", what="Zero Trust organization"))
        if isinstance(org, dict):
            a["org"] = {"name": org.get("name"), "auth_domain": org.get("auth_domain"), "session": org.get("session_duration"),
                        "warp_auth_session": org.get("warp_auth_session_duration"), "user_seat_expiry": org.get("user_seat_expiration_inactive_time")}
        logins = self.optional("Access login events", lambda: self._access_logins(now - 86400))
        a["logins"] = logins
        if logins is not None:
            self.data.setdefault("metrics", []).append(["access:logins", logins["allowed"], logins["denied"], None])
        if all(a.get(k) is None for k in ("apps", "policies", "idps", "service_tokens", "logins")):
            raise IntegrationError("No Access call answered: " + "; ".join(self.data["unavailable"][-3:])[:300])
        self.data["access"] = a
        out = [self.record("access", "summary", "Access", "Cloudflare Access", "up",
                           f"{len(a.get('apps') or [])} apps" + (f", {logins['allowed']} logins / {logins['denied']} denied in 24 h" if logins else ""))]
        bad = [t for t in tokens if t["status"] in ("warn", "down")]
        if toks is not None:
            out.append(self.record("access", "service-tokens", "Access service tokens", "Cloudflare Access service tokens",
                                   "down" if any(t["status"] == "down" for t in bad) else ("warn" if bad else "up"),
                                   f"{len(tokens)} tokens" + (f"; {', '.join(str(t['name']) for t in bad[:5])} expired or expiring within {TOKEN_WARN_DAYS} days" if bad else "")))
        return out

    def _access_logins(self, since: float) -> dict[str, Any]:
        body = self.request("GET", f"{self.base}/accounts/{self.acct}/access/logs/access_requests",
                            params={"since": _iso(since), "limit": 1000, "direction": "desc"}, what="Access login events") or {}
        rows = [r for r in body.get("result") or [] if isinstance(r, dict)]
        events = [{"time": r.get("created_at"), "user": r.get("user_email"), "app": r.get("app_domain") or r.get("app_uid"),
                   "allowed": bool(r.get("allowed")), "action": r.get("action"), "ip": r.get("ip_address"), "country": r.get("country"),
                   "idp": r.get("connection")} for r in rows]
        denied = [e for e in events if not e["allowed"]]
        return {"allowed": len(events) - len(denied), "denied": len(denied), "recent": events[:200],
                "top_denied_users": counts(e["user"] for e in denied)[:10], "by_app": counts(e["app"] for e in events)[:15],
                "capped": len(rows) >= 1000}

    # DEX & posture --------------------------------------------------------------
    def collect_dex(self) -> list[Record]:
        x: dict[str, Any] = {}
        fleet = self.optional("DEX fleet status", lambda: self.api("/dex/fleet-status/live", {"since_minutes": 10}, what="DEX fleet status"))
        if isinstance(fleet, dict):
            st = fleet.get("deviceStats") or fleet
            pairs = lambda k: [[str(i.get("value") or "unknown"), int(num(i.get("count")) or 0)] for i in st.get(k) or [] if isinstance(i, dict)]
            x["fleet"] = {"total": int(num(st.get("uniqueDevicesTotal")) or 0) or sum(n for _, n in pairs("byStatus")),
                          "by_status": pairs("byStatus"), "by_platform": pairs("byPlatform"), "by_version": pairs("byVersion"),
                          "by_colo": pairs("byColo"), "by_mode": pairs("byMode")}
            connected = sum(n for k, n in x["fleet"]["by_status"] if k.lower() == "connected")
            self.data.setdefault("metrics", []).append(["dex:fleet", x["fleet"]["total"], connected, None])
        tests = self.optional("DEX tests", self._dex_tests)
        x["tests"] = tests
        posture = self.optional("Device posture rules", lambda: self.api("/devices/posture", what="posture rules"))
        x["posture"] = [{"name": p.get("name"), "type": p.get("type"), "schedule": p.get("schedule"), "expiration": p.get("expiration"),
                         "platforms": sorted({str(m.get("platform")) for m in p.get("match") or [] if isinstance(m, dict) and m.get("platform")}),
                         "description": p.get("description")} for p in posture or []] if posture is not None else None
        integ = self.optional("Posture integrations", lambda: self.api("/devices/posture/integration", what="posture integrations"))
        x["posture_integrations"] = [{"name": i.get("name"), "type": i.get("type"), "interval": i.get("interval")} for i in integ or []] if integ is not None else None
        profiles = self.optional("Device settings profiles", self._device_profiles)
        x["profiles"] = profiles
        if all(x.get(k) is None for k in ("fleet", "tests", "posture", "profiles")):
            raise IntegrationError("No DEX or device call answered: " + "; ".join(self.data["unavailable"][-3:])[:300])
        self.data["dex"] = x
        f = x.get("fleet") or {}
        failing = [t for t in tests or [] if t.get("availability") is not None and t["availability"] < 95]
        return [self.record("dex", "summary", "Digital Experience (DEX)", "Cloudflare DEX", "warn" if failing else "up",
                            f"{f.get('total', 0)} devices in fleet status, {len(tests or [])} tests"
                            + (f", {len(failing)} below 95% availability" if failing else ""))]

    def _dex_tests(self) -> list[dict]:
        try:
            body = self.api("/dex/tests/overview", what="DEX test overview")
        except IntegrationError as exc:
            if "404" not in str(exc):
                raise
            body = None
        rows = []
        if isinstance(body, dict):
            rows = body.get("tests") or []
        if not rows:
            got = self.api("/dex/tests", what="DEX tests")
            rows = (got.get("dex_tests") if isinstance(got, dict) else got) or []
        out = []
        for t in rows:
            if not isinstance(t, dict):
                continue
            data = t.get("data") if isinstance(t.get("data"), dict) else {}
            avail = None
            for k, v in _walk(t):
                if k.lower().endswith("availabilitypct") and num(v) is not None:
                    avail = round(num(v), 1)
                    break
            fetch = next((num(v) for k, v in _walk(t.get("httpResults") or {}) if k.lower() in ("avgms", "avg") and num(v) is not None), None)
            rtt = next((num(v) for k, v in _walk(t.get("tracerouteResults") or {}) if k.lower() in ("avgms", "avg") and num(v) is not None), None)
            out.append({"name": t.get("name"), "kind": t.get("kind") or data.get("kind"), "host": t.get("host") or data.get("host"),
                        "enabled": t.get("enabled", True) is not False, "interval": t.get("interval"), "availability": avail,
                        "fetch_ms": fetch, "rtt_ms": rtt, "description": t.get("description")})
        return out

    def _device_profiles(self) -> list[dict]:
        rows = list(self.api("/devices/policies", what="device profiles") or [])
        default = self.optional("Default device profile", lambda: self.api("/devices/policy", what="default device profile"))
        if isinstance(default, dict):
            rows.append({**default, "name": default.get("name") or "Default", "default": True})
        return [{"name": p.get("name"), "default": bool(p.get("default")), "enabled": p.get("enabled", True) is not False,
                 "precedence": p.get("precedence"), "match": p.get("match"), "mode": (p.get("service_mode_v2") or {}).get("mode"),
                 "locked": bool(p.get("switch_locked")), "auto_connect": p.get("auto_connect"), "captive_portal": p.get("captive_portal"),
                 "allow_leave_org": p.get("allowed_to_leave"), "allow_disconnect": p.get("allow_mode_switch")}
                for p in sorted(rows, key=lambda p: (bool(p.get("default")), num(p.get("precedence")) or 0))]

    # Magic WAN extras (Sites tab) and tunnel routes (Private tab) ---------------
    def magic_extras(self) -> dict[str, Any]:
        m: dict[str, Any] = {}
        sites = self.optional("Magic WAN sites", lambda: self.api("/magic/sites", what="Magic WAN sites"))
        m["sites"] = [{"name": s.get("name"), "location": (s.get("location") or {}).get("lat") and f"{s['location'].get('lat')}, {s['location'].get('lon')}",
                       "ha": s.get("ha_mode"), "connector": s.get("connector_id"), "description": s.get("description")} for s in sites or []] if sites is not None else None
        conns = self.optional("Magic WAN connectors", lambda: self.api("/magic/connectors", what="Magic WAN connectors"))
        m["connectors"] = [{"id": c.get("id"), "serial": (c.get("device") or {}).get("serial_number"), "activated": c.get("activated"),
                            "version": c.get("last_seen_version") or c.get("version"), "last_heartbeat": c.get("last_heartbeat"),
                            "notes": c.get("notes")} for c in conns or []] if conns is not None else None
        routes = self.optional("Magic WAN static routes", lambda: self.api("/magic/routes", what="Magic WAN routes"))
        rows = routes.get("routes") if isinstance(routes, dict) else routes
        m["routes"] = [{"prefix": r.get("prefix"), "nexthop": r.get("nexthop"), "priority": r.get("priority"), "weight": r.get("weight"),
                        "description": r.get("description")} for r in rows or []] if routes is not None else None
        fw = self.optional("Magic Firewall rules", lambda: self.api("/rulesets/phases/magic_transit/entrypoint", what="Magic Firewall"))
        m["firewall"] = [{"order": i + 1, "description": r.get("description"), "action": r.get("action"), "enabled": r.get("enabled", True) is not False,
                          "expression": r.get("expression")} for i, r in enumerate((fw or {}).get("rules") or [])] if fw is not None else None
        return m

    def connector_records(self, m: dict) -> list[Record]:
        out = []
        for c in m.get("connectors") or []:
            age = None if not c.get("last_heartbeat") else time.time() - (_when(c["last_heartbeat"]) or 0)
            st = "off" if c.get("activated") is False else ("unknown" if age is None else ("up" if age < 900 else "down"))
            out.append(self.record("sites", f"connector-{c.get('id')}", f"Magic WAN Connector {c.get('serial') or c.get('id')}",
                                   "Magic WAN Connector", st, f"version {c.get('version') or '?'}"))
        return out

    def route_extras(self) -> dict[str, Any]:
        r: dict[str, Any] = {}
        routes = self.optional("Private network routes", lambda: self.api("/teamnet/routes", {"is_deleted": "false"}, "tunnel routes"))
        r["routes"] = [{"network": x.get("network"), "tunnel": x.get("tunnel_name") or x.get("tunnel_id"), "vnet": x.get("virtual_network_name") or x.get("virtual_network_id"),
                        "comment": x.get("comment")} for x in routes or []] if routes is not None else None
        vnets = self.optional("Virtual networks", lambda: self.api("/teamnet/virtual_networks", {"is_deleted": "false"}, "virtual networks"))
        r["vnets"] = [{"name": v.get("name"), "default": bool(v.get("is_default_network")), "comment": v.get("comment")} for v in vnets or []] if vnets is not None else None
        hosts = self.optional("Hostname routes", lambda: self.api("/zerotrust/routes/hostname", what="hostname routes"))
        r["hostnames"] = [{"hostname": h.get("hostname"), "tunnel": h.get("tunnel_name") or h.get("tunnel_id"), "comment": h.get("comment")}
                          for h in hosts or []] if hosts is not None else None
        return r

    # Zones --------------------------------------------------------------------
    def collect_zones(self) -> list[Record]:
        zones = self.api_root("/zones", {"account.id": self.acct}, "zones") or []
        items = []
        for z in zones:
            items.append({"id": z.get("id"), "name": z.get("name"), "status": z.get("status"), "paused": bool(z.get("paused")),
                          "plan": (z.get("plan") or {}).get("name"), "type": z.get("type"), "ns": z.get("name_servers") or [],
                          "modified": z.get("modified_on")})
        for z in items[:MAX_ZONES]:
            z["records"] = self.optional(f"DNS records for {z['name']}", lambda z=z: self._count(f"/zones/{z['id']}/dns_records"))
            settings = self.optional(f"Settings for {z['name']}", lambda z=z: self.api_root(f"/zones/{z['id']}/settings", what="zone settings"))
            s = {x.get("id"): x.get("value") for x in settings or [] if isinstance(x, dict)}
            z.update(ssl=s.get("ssl"), min_tls=s.get("min_tls_version"), https=s.get("always_use_https"), security=s.get("security_level"),
                     waf=s.get("waf"), hsts=bool((s.get("security_header") or {}).get("strict_transport_security", {}).get("enabled"))
                     if isinstance(s.get("security_header"), dict) else None)
        traffic = self.optional("Zone traffic analytics", lambda: self._zone_traffic([z["id"] for z in items[:MAX_ZONES]]))
        for z in items:
            z.update((traffic or {}).get(z["id"]) or {})
        self.data["zones"] = {"items": items, "capped": len(items) > MAX_ZONES}
        tot = lambda k: sum(z.get(k) or 0 for z in items)
        if traffic is not None:
            self.data.setdefault("metrics", []).append(["zones:traffic", tot("requests"), tot("threats"), tot("cached")])
        return [self.record("zones", z["id"], z["name"], f"Cloudflare zone ({z.get('plan') or 'plan?'})",
                            "off" if z["paused"] else {"active": "up", "pending": "warn", "initializing": "warn", "moved": "down", "deactivated": "down"}.get(str(z["status"]), "unknown"),
                            f"SSL {z.get('ssl') or '?'}" + (f", {z['records']} DNS records" if z.get("records") is not None else "")
                            + (f", {z['requests']:,.0f} requests / {z.get('threats') or 0:,.0f} threats yesterday" if z.get("requests") is not None else ""))
                for z in items]

    def _count(self, path: str) -> int:
        body = self.request("GET", self.base + path, params={"per_page": 1}, what="count") or {}
        return int(num((body.get("result_info") or {}).get("total_count")) or 0)

    def _zone_traffic(self, ids: list[str]) -> dict[str, dict]:
        if not ids:
            return {}
        day = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
        q = """query z($z: [String!], $d: Date!) { viewer { zones(filter: {zoneTag_in: $z}) { zoneTag
          httpRequests1dGroups(limit: 1, filter: {date: $d}) { sum { requests cachedRequests threats bytes } } } } }"""
        out: dict[str, dict] = {}
        for z in (self.gql(q, {"z": ids, "d": day}, "zone traffic").get("viewer") or {}).get("zones") or []:
            s = ((z.get("httpRequests1dGroups") or [{}])[0] or {}).get("sum") or {}
            out[str(z.get("zoneTag"))] = {"requests": num(s.get("requests")), "cached": num(s.get("cachedRequests")),
                                          "threats": num(s.get("threats")), "bytes": num(s.get("bytes"))}
        events = self.optional("WAF / security events", lambda: self._zone_events(ids))
        for zid, ev in (events or {}).items():
            out.setdefault(zid, {})["events"] = ev
        return out

    def _zone_events(self, ids: list[str]) -> dict[str, list]:
        q = """query e($z: [String!], $s: Time!) { viewer { zones(filter: {zoneTag_in: $z}) { zoneTag
          firewallEventsAdaptiveGroups(limit: 50, filter: {datetime_geq: $s}, orderBy: [count_DESC]) { count dimensions { action source } } } } }"""
        out: dict[str, list] = {}
        for z in (self.gql(q, {"z": ids, "s": _iso(time.time() - 86400)}, "security events").get("viewer") or {}).get("zones") or []:
            out[str(z.get("zoneTag"))] = [[f"{(g.get('dimensions') or {}).get('source')}: {(g.get('dimensions') or {}).get('action')}", int(g.get("count") or 0)]
                                          for g in z.get("firewallEventsAdaptiveGroups") or []]
        return out

    # Audit log ------------------------------------------------------------------
    def collect_audit(self) -> list[Record]:
        rows = self.api("/audit_logs", {"since": _iso(time.time() - 86400), "direction": "desc"}, what="audit log", max_pages=3) or []
        events = []
        for r in rows:
            actor, action, res = r.get("actor") or {}, r.get("action") or {}, r.get("resource") or {}
            events.append({"time": r.get("when"), "actor": actor.get("email") or actor.get("type"), "ip": actor.get("ip"),
                           "action": action.get("type"), "ok": action.get("result") is not False, "resource": res.get("type"),
                           "resource_id": res.get("id"), "interface": r.get("interface"),
                           "detail": _first(r.get("metadata") or {}, "name", "zone_name", "rule_name") if isinstance(r.get("metadata"), dict) else None})
        failed = [e for e in events if not e["ok"]]
        self.data["audit"] = {"events": events, "by_actor": counts(e["actor"] for e in events)[:10],
                              "by_action": counts(e["action"] for e in events)[:12], "failed": len(failed), "window": "24 hours"}
        self.data.setdefault("metrics", []).append(["audit:events", len(events), len(failed), None])
        return [self.record("audit", "summary", "Account audit log", "Cloudflare audit log", "up",
                            f"{len(events)} changes in 24 hours by {len({e['actor'] for e in events})} actors" + (f", {len(failed)} failed" if failed else ""))]


def _rules(v: Any) -> str:
    """Access include/require/exclude rules -> 'email: a@b, group: Staff'."""
    parts = []
    for r in v or []:
        if not isinstance(r, dict):
            continue
        for k, val in r.items():
            if isinstance(val, dict):
                inner = next((str(x) for x in val.values() if isinstance(x, (str, int))), "")
                parts.append(f"{k.replace('_', ' ')}: {inner}" if inner else k.replace("_", " "))
            else:
                parts.append(k.replace("_", " "))
    return ", ".join(parts)[:200]


def _walk(d: Any, depth: int = 0):
    """(key, value) pairs of a nested dict, depth-first, for fields whose nesting varies."""
    if depth > 4 or not isinstance(d, dict):
        return
    for k, v in d.items():
        yield k, v
        if isinstance(v, dict):
            yield from _walk(v, depth + 1)

