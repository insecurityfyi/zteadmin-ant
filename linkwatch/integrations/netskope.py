"""Netskope One (SSE) over REST API v2.

Auth: a REST API v2 token from Settings > Tools > REST API v2, sent in the ``Netskope-Api-Token``
header to ``https://<tenant>.goskope.com``. Grant it read-only access to the endpoints below.

* Sites      GET /api/v2/steering/ipsec/tunnels, /api/v2/steering/gre/tunnels (status per tunnel)
* Private    GET /api/v2/infrastructure/publishers, /api/v2/steering/apps/private (count)
* Users      GET /api/v2/events/datasearch/clientstatus (Netskope Client inventory)
* Policy     GET /api/v2/policy/npa/rules (Private Access rules); Real-time Protection has no API
* Apps / AI  GET /api/v2/events/datasearch/application, grouped by app with count() and sum()
* DLP        GET /api/v2/events/datasearch/alert?query=alert_type eq 'DLP'

None of this has been run against a real tenant yet; the response shapes follow Netskope's
published docs and are parsed defensively.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, ClassVar

from .base import Field, IntegrationError, Record
from .sse import SSEIntegration, counts, is_ai, num, section_fields, status_of

DATASEARCH = "/api/v2/events/datasearch/"
SECTIONS = ["sites", "private", "users", "policy", "apps", "dlp"]
LABELS = {"private": "Private Access", "users": "Netskope Client"}


def _rows(body: Any, *keys: str) -> list[dict]:
    """Netskope wraps lists differently per API: result, data, data.<name>, or a bare list."""
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]
    if not isinstance(body, dict):
        return []
    for k in (*keys, "result", "data", "items"):
        v = body.get(k)
        if isinstance(v, list):
            return [r for r in v if isinstance(r, dict)]
        if isinstance(v, dict):
            inner = _rows(v, *keys)
            if inner:
                return inner
    return []


class Netskope(SSEIntegration):
    kind = "netskope"
    label = "Netskope"
    vendor = "Netskope"
    description = "REST API v2: IPsec and GRE tunnels, NPA publishers, Netskope Client fleet, private access rules, app and AI usage, DLP alerts."
    sections = SECTIONS
    labels = LABELS
    gaps: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "sites": [("Tunnel throughput and latency", "The steering API returns tunnel configuration and up/down state, not traffic. Poll the tunnel's source router over SNMP to graph it.")],
        "users": [("Who is signed in right now", "Client status is a device inventory with a last-seen time; there is no live session list.")],
        "policy": [("Real-time Protection (web, CASB, AI) policies", "Netskope's REST API v2 doesn't expose Real-time Protection rules, only Private Access rules and URL lists. Review them in the admin console."),
                   ("Policy hit counts", "Use the Apps & AI and DLP tabs, which count events per app and policy.")],
        "apps": [("Prompts and responses sent to AI apps", "Only visible in Skope IT / incident forensics in the console, not over the API."),
                 ("Cloud Confidence Index per app", "The App Catalog API is licensed separately; risk is shown when events carry ccl.")],
        "dlp": [("DLP profile and rule definitions", "REST API v2 has no endpoint for DLP profiles; incidents and alerts are listed instead."),
                ("Matched content / forensics", "Kept in the incident forensics store, not returned by the events API.")],
    }
    fields: ClassVar[list[Field]] = [
        Field("tenant", "Tenant address", help="The 'acme' in acme.goskope.com, or the full address (e.g. acme.eu.goskope.com)."),
        Field("token", "REST API v2 token", "password", help="Settings > Tools > REST API v2 > New token. Read-only access to the endpoints listed in the setup guide."),
        *section_fields(SECTIONS, LABELS),
        SSEIntegration.ai_category_field(),
    ]

    @property
    def base(self) -> str:
        t = str(self.config.get("tenant") or "").strip().rstrip("/")
        t = re.sub(r"^https?://", "", t)
        return f"https://{t if '.' in t else t + '.goskope.com'}"

    def auth_headers(self) -> dict[str, str]:
        return {"Netskope-Api-Token": self.secret("token"), "Accept": "application/json"}

    def api(self, path: str, params: dict | None = None, what: str | None = None) -> Any:
        return self.request("GET", self.base + path, params=params, what=what)

    def search(self, event_type: str, **params) -> list[dict]:
        """Datasearch: GET /api/v2/events/datasearch/<type>. Reports failures in body.status with HTTP 200."""
        body = self.api(DATASEARCH + event_type, {k: v for k, v in params.items() if v is not None}, what=f"{event_type} events") or {}
        status = body.get("status") if isinstance(body, dict) else None
        if isinstance(status, dict) and str(status.get("execution", "")).upper() == "FAILED":
            raise IntegrationError(f"{event_type} search failed: {str(status.get('message') or '')[:200]}")
        return _rows(body, "result")

    # sections -------------------------------------------------------------------
    def collect_sites(self) -> list[Record]:
        items: list[dict] = []
        for kind, path in (("IPsec", "/api/v2/steering/ipsec/tunnels"), ("GRE", "/api/v2/steering/gre/tunnels")):
            tunnels = self.optional(f"{kind} tunnels", lambda path=path, kind=kind: _rows(self.api(path, what=f"{kind} tunnels"), "tunnels"))
            for t in tunnels or []:
                pops = t.get("pops") or []
                pop_names = [str(p.get("name") or p.get("popname") or p) if isinstance(p, dict) else str(p) for p in pops]
                st = status_of(t.get("status") or t.get("tunnel_status"))
                if t.get("enabled") is False:
                    st = "off"
                name = str(t.get("site") or t.get("name") or t.get("sitename") or t.get("id"))
                items.append({"id": f"{kind.lower()}-{t.get('id')}", "name": name, "type": f"{kind} tunnel", "status": st,
                              "pop": ", ".join(pop_names[:2]) or None, "ip": t.get("sourceidentity") or t.get("sourceip") or t.get("srcipidentity"),
                              "location": None, "bandwidth_mbps": num(t.get("bandwidth")),
                              "detail": f"{kind} from {t.get('sourceidentity') or t.get('sourceip') or '?'} to {', '.join(pop_names[:2]) or '?'}",
                              "tunnels": [{"name": f"{kind} {p}", "status": st, "pop": p} for p in pop_names] or [{"name": kind, "status": st}]})
        if not items and len([u for u in self.data["unavailable"] if "tunnels" in u]) == 2:
            raise IntegrationError("Neither the IPsec nor the GRE tunnel API answered: " + "; ".join(self.data["unavailable"][-2:])[:300])
        self.data["sites"] = {"items": items}
        return self.site_records(items, "Netskope tunnel")

    def collect_private(self) -> list[Record]:
        pubs = _rows(self.api("/api/v2/infrastructure/publishers", what="NPA publishers"), "publishers")
        items = []
        for p in pubs:
            a = p.get("assessment") if isinstance(p.get("assessment"), dict) else {}
            raw = p.get("status") or ("connected" if p.get("lbrokerconnect") else None)
            items.append({"id": p.get("publisher_id") or p.get("id"), "name": str(p.get("publisher_name") or p.get("name") or p.get("id")),
                          "group": (p.get("publisher_upgrade_profiles_name") or None), "status": status_of(raw) if raw is not None else "unknown",
                          "state": str(raw or "unknown"), "version": a.get("version") or p.get("version"), "expected": None,
                          "ip": a.get("ip_address") or p.get("ip_address"), "public_ip": a.get("public_ip"),
                          "location": p.get("stitcher_pop") or a.get("eee_support"), "apps": p.get("apps_count"),
                          "detail": f"{p.get('apps_count') or 0} apps" + (f", {p.get('common_name')}" if p.get("common_name") else "")})
        apps = self.optional("NPA private apps", lambda: len(_rows(self.api("/api/v2/steering/apps/private", what="private apps"), "private_apps")))
        self.data["private"] = {"items": items, "apps": apps, "label": "Publishers"}
        return self.private_records(items, "NPA publisher")

    def collect_users(self) -> list[Record]:
        start, end, _ = self.window(30)
        rows = self.search("clientstatus", starttime=start, endtime=end, limit=10000)
        latest: dict[str, dict] = {}
        for r in rows:   # one row per status event; keep the newest per device
            host = r.get("host_info") if isinstance(r.get("host_info"), dict) else {}
            key = str(r.get("device_id") or r.get("nsdeviceuid") or r.get("hostname") or host.get("hostname") or "")
            if key and (key not in latest or (num(r.get("timestamp")) or 0) > (num(latest[key].get("timestamp")) or 0)):
                latest[key] = r
        devices = []
        for r in latest.values():
            host = r.get("host_info") if isinstance(r.get("host_info"), dict) else {}
            devices.append({"hostname": r.get("hostname") or host.get("hostname"), "user": r.get("user") or r.get("username"),
                            "os": " ".join(str(x) for x in (r.get("os") or host.get("os"), r.get("os_version") or host.get("os_version")) if x) or None,
                            "version": r.get("client_version") or r.get("version"), "state": r.get("status") or r.get("client_status"),
                            "last_seen": _ts(r.get("timestamp"))})
        connected = sum(1 for d in devices if status_of(d["state"]) == "up" or str(d["state"] or "").lower() == "enabled")
        self.data["users"] = self.fleet(devices, connected)
        return [self.fleet_record(self.data["users"], "Netskope Client")]

    def collect_policy(self) -> list[Record]:
        rules = _rows(self.api("/api/v2/policy/npa/rules", what="Private Access rules"), "rules")
        out = []
        for i, r in enumerate(rules):
            d = r.get("rule_data") if isinstance(r.get("rule_data"), dict) else r
            acts = d.get("match_criteria_action") or d.get("actions") or {}
            action = acts.get("action_name") if isinstance(acts, dict) else (acts[0].get("actionName") if acts and isinstance(acts[0], dict) else acts)
            apps = d.get("privateApps") or d.get("private_apps") or []
            who = (d.get("users") or []) + (d.get("userGroups") or d.get("user_groups") or [])
            order = r.get("rule_order") or d.get("rule_order")
            if isinstance(order, dict):
                order = order.get("order")
            out.append({"order": num(order) or i + 1,
                        "name": r.get("rule_name") or d.get("rule_name") or r.get("name"), "enabled": str(r.get("enabled", "1")) not in ("0", "False", "false"),
                        "action": str(action or "allow").lower(), "match": ", ".join(str(a) for a in apps[:8]) or "any private app",
                        "scope": ", ".join(str(u) for u in who[:6]) or "everyone", "description": r.get("description") or d.get("description")})
        out.sort(key=lambda r: r["order"])
        self.data["policy"] = {"rulebases": [{"name": "Private Access rules", "rules": out}]}
        return [self.summary_record("policy", "Private Access rules", "Netskope NPA policy", f"{sum(1 for r in out if r['enabled'])} enabled rules")]

    def collect_apps(self) -> list[Record]:
        start, end, label = self.window(7)
        rows = self.search("application", starttime=start, endtime=end, limit=1000,
                           fields="app,appcategory,ccl,events=count(_id),up=sum(client_bytes),down=sum(server_bytes)",
                           groupbys="app,appcategory,ccl", orderbys="events desc")
        users_rows = self.optional("Users per app", lambda: self.search(
            "application", starttime=start, endtime=end, limit=10000, fields="app,user,events=count(_id)", groupbys="app,user"))
        users = Counter(str(r.get("app")) for r in users_rows or [] if r.get("user"))
        blocked_rows = self.optional("Blocked events per app", lambda: self.search(
            "application", starttime=start, endtime=end, limit=1000, query="action eq 'block'", fields="app,events=count(_id)", groupbys="app"))
        blocked = {str(r.get("app")): int(num(r.get("events")) or 0) for r in blocked_rows or []}
        cat = self.ai_category()
        merged: dict[str, dict] = {}
        for r in rows:
            name = str(r.get("app") or "Unknown")
            a = merged.setdefault(name, {"name": name, "category": r.get("appcategory"), "risk": r.get("ccl"), "events": 0, "up": 0.0, "down": 0.0})
            a["events"] += int(num(r.get("events")) or 0)
            a["up"] += num(r.get("up")) or 0
            a["down"] += num(r.get("down")) or 0
        items = []
        for a in merged.values():
            a.update(bytes=a["up"] + a["down"], users=users.get(a["name"]) if users_rows is not None else None, ai=is_ai(a["category"], a["name"], cat),
                     blocked=blocked.get(a["name"]) if blocked_rows is not None else None, sanctioned=None)
            a["action"] = ("block" if a["blocked"] and a["blocked"] >= a["events"] else "partly blocked") if a.get("blocked") else None
            items.append(a)
        items.sort(key=lambda a: -a["bytes"])
        self.data["apps"] = {"window": label, "items": items, "categories_seen": counts(a["category"] for a in items)[:20]}
        return [self.apps_record(self.data["apps"])]

    def collect_dlp(self) -> list[Record]:
        start, end, label = self.window(7)
        rows = self.search("alert", starttime=start, endtime=end, limit=200, query="alert_type eq 'DLP'",
                           fields="timestamp,user,app,policy,dlp_profile,dlp_rule,dlp_rule_severity,action,activity", orderbys="timestamp desc")
        sev = self.optional("DLP alerts by severity", lambda: self.search(
            "alert", starttime=start, endtime=end, query="alert_type eq 'DLP'", fields="dlp_rule_severity,n=count(_id)", groupbys="dlp_rule_severity"))
        incidents = [{"time": _ts(r.get("timestamp")), "user": r.get("user"), "app": r.get("app"), "policy": r.get("policy"),
                      "profile": r.get("dlp_profile"), "rule": r.get("dlp_rule"), "severity": r.get("dlp_rule_severity"),
                      "action": r.get("action"), "activity": r.get("activity")} for r in rows]
        by_sev = [[str(r.get("dlp_rule_severity") or "unknown"), int(num(r.get("n")) or 0)] for r in sev] if sev is not None else counts(i["severity"] for i in incidents)
        ai_hits = sum(1 for i in incidents if is_ai(None, i["app"], ""))
        profiles = counts(i["profile"] for i in incidents if i["profile"])
        self.data["dlp"] = {"window": label, "incidents": incidents, "by_severity": by_sev,
                            "profiles": [{"name": p, "type": "seen in alerts", "enabled": True, "detail": f"{n} alerts"} for p, n in profiles],
                            "total": sum(n for _, n in by_sev) or len(incidents), "ai_incidents": ai_hits}
        total = self.data["dlp"]["total"]
        return [self.summary_record("dlp", "DLP alerts", "Netskope DLP", f"{total} DLP alerts in 7 days, {ai_hits} on AI apps",
                                    "warn" if any(s in ("critical", "high") for s, n in by_sev if n) else "up", alerts=total)]


def _ts(v) -> str | None:
    n = num(v)
    if not n:
        return str(v) if v else None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

