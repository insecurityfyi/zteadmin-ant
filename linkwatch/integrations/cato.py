"""Cato Networks SASE Cloud over the GraphQL API.

Auth: an API key (Resources > API Keys, "View" permission) sent as ``x-api-key`` to
``https://api.catonetworks.com/api/v1/graphql2`` with the numeric account ID. Accounts on
other Cato regions use their own API host (e.g. api.us1.catonetworks.com); set it in the
form.

* Sites     accountSnapshot.sites: connectivity, PoP, socket interfaces and tunnel state;
            accountMetrics: per-site latency, packet loss, jitter and traffic for the last hour
* Users     accountSnapshot.users: SDP (Cato Client) users, connected or not, client version
* Policy    policy.internetFirewall / policy.wanFirewall rule bases
* Apps / AI appStats grouped by application and category over 7 days
* DLP       eventsFeed is a forward-only stream; instead events() aggregates DLP / CASB
            events for 7 days, grouped by severity, app and rule

Not run against a real account yet. Every query has a minimal fallback because a field this
account's schema doesn't have fails the whole GraphQL query.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from .base import Field, IntegrationError, Record
from .sse import SSEIntegration, counts, is_ai, num, section_fields, status_of, worst

SECTIONS = ["sites", "users", "policy", "apps", "dlp"]
LABELS = {"sites": "Sites & sockets", "users": "SDP users"}

SITES_Q = """query sites($accountID: ID!) { accountSnapshot(accountID: $accountID) { id sites {
  id connectivityStatus operationalStatus lastConnected connectedSince popName hostCount
  info { name type description countryName region connType }
  devices { id name connected haRole interfaces { id name connected physicalPort popName tunnelRemoteIP tunnelUptime type } } } } }"""
SITES_MIN = """query sites($accountID: ID!) { accountSnapshot(accountID: $accountID) { id sites {
  id connectivityStatus operationalStatus lastConnected popName info { name type } } } }"""
METRICS_Q = """query metrics($accountID: ID!, $timeFrame: TimeFrame!) { accountMetrics(accountID: $accountID, timeFrame: $timeFrame, groupInterfaces: true) {
  sites { id name metrics { bytesUpstream bytesDownstream rtt lostUpstreamPcnt lostDownstreamPcnt jitterUpstream jitterDownstream } } } }"""
USERS_Q = """query users($accountID: ID!) { accountSnapshot(accountID: $accountID) { id users {
  id connectivityStatus operationalStatus name deviceName lastConnected connectedSince version popName remoteIP
  info { name email } } } }"""
USERS_MIN = """query users($accountID: ID!) { accountSnapshot(accountID: $accountID) { id users { id connectivityStatus name version } } }"""
POLICY_Q = """query policy($accountId: ID!) { policy(accountId: $accountId) {
  internetFirewall { policy { enabled rules { rule { id name description index enabled action { action } } } } }
  wanFirewall { policy { enabled rules { rule { id name description index enabled action { action } } } } } } }"""
APPS_Q = """query appStats($accountID: ID!, $timeFrame: TimeFrame!, $measures: [Measure], $dimensions: [Dimension], $sort: [AppStatsSort!]) {
  appStats(accountID: $accountID, timeFrame: $timeFrame, measures: $measures, dimensions: $dimensions, sort: $sort) {
    records(limit: 1000) { fieldsMap } } }"""
EVENTS_Q = """query events($accountID: ID!, $timeFrame: TimeFrame!, $measures: [EventsMeasure], $dimensions: [EventsDimension], $filters: [EventsFilter]) {
  events(accountID: $accountID, timeFrame: $timeFrame, measures: $measures, dimensions: $dimensions, filters: $filters) {
    records(limit: 1000) { fieldsMap } } }"""


class Cato(SSEIntegration):
    kind = "cato"
    label = "Cato Networks"
    vendor = "Cato"
    description = "GraphQL API: site and socket connectivity with latency and loss, SDP users, firewall rules, app and AI usage, DLP events."
    sections = SECTIONS
    labels = LABELS
    gaps: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "sites": [("Separate private-access connectors", "Cato has no ZTNA connectors: private apps sit behind sockets or IPsec sites, which are listed here."),
                  ("IPsec tunnel negotiation detail", "The snapshot shows whether each site and socket interface is connected; phase 1/2 detail is only in the Cato Management Application.")],
        "users": [("Device OS and posture", "accountSnapshot lists users and their client version; device posture results aren't exposed.")],
        "policy": [("Rule hit counts", "The policy API returns rule definitions only."),
                   ("Application control and TLS inspection rules", "Not all policy types are in the API on every account; missing rule bases are listed under optional panels.")],
        "apps": [("Prompts sent to AI apps", "Cato's GenAI controls can log prompts to the event feed, but contents aren't summarised by the API."),
                 ("Per-app users, where AD user names aren't reported", "appStats counts distinct AD names; sites without identity show traffic but no user count.")],
        "dlp": [("DLP profile and data type definitions", "Not exposed over GraphQL; incidents are counted from events instead."),
                ("Incident content / matched data", "Only in the Cato Management Application.")],
    }
    fields: ClassVar[list[Field]] = [
        Field("account_id", "Account ID", help="The number in the Cato Management Application URL, e.g. 12345."),
        Field("api_key", "API key", "password", help="Resources > API Keys > New, permission View. Optionally limit it to the VisCon1 server's IP."),
        Field("api_host", "API host", required=False, help="Leave blank for api.catonetworks.com. Set e.g. api.us1.catonetworks.com for other regions."),
        *section_fields(SECTIONS, LABELS),
        SSEIntegration.ai_category_field(),
    ]

    @property
    def url(self) -> str:
        host = re.sub(r"^https?://", "", str(self.config.get("api_host") or "").strip()).split("/")[0] or "api.catonetworks.com"
        return f"https://{host}/api/v1/graphql2"

    @property
    def account(self) -> str:
        return str(self.config.get("account_id") or "").strip()

    def auth_headers(self) -> dict[str, str]:
        return {"x-api-key": self.secret("api_key"), "Content-Type": "application/json", "Accept": "application/json"}

    def gql(self, name: str, query: str, variables: dict | None = None, fallback: str | None = None) -> dict:
        """POST a query; GraphQL errors arrive with HTTP 200. Retry once with a smaller query if given."""
        body = self.request("POST", self.url, json={"query": query, "variables": {"accountID": self.account, **(variables or {})}},
                            what=f"Cato {name}") or {}
        errs = body.get("errors") if isinstance(body, dict) else None
        if errs:
            msg = errs[0].get("message") if isinstance(errs[0], dict) else str(errs[0])
            if re.search(r"permission|unauthori[sz]ed|api key", str(msg), re.IGNORECASE):
                raise IntegrationError(f"Cato {name}: {str(msg)[:200]}. Check the API key and account ID.")
            if fallback:
                return self.gql(name, fallback, variables)
            raise IntegrationError(f"Cato {name}: {str(msg)[:200]}")
        return (body or {}).get("data") or {}

    # sections -------------------------------------------------------------------
    def collect_sites(self) -> list[Record]:
        snap = (self.gql("sites", SITES_Q, fallback=SITES_MIN).get("accountSnapshot") or {})
        metrics = self.optional("Site latency and loss (accountMetrics)",
                                lambda: self.gql("metrics", METRICS_Q, {"timeFrame": "last.PT1H"}).get("accountMetrics") or {})
        by_site = {str(s.get("id")): s.get("metrics") or {} for s in (metrics or {}).get("sites") or []}
        items = []
        for s in snap.get("sites") or []:
            info = s.get("info") or {}
            tunnels = []
            for d in s.get("devices") or []:
                for i in d.get("interfaces") or []:
                    tunnels.append({"name": f"{d.get('name') or 'socket'} {i.get('name') or i.get('id')}".strip(),
                                    "status": "up" if i.get("connected") else "down", "peer": i.get("tunnelRemoteIP"),
                                    "pop": i.get("popName"), "detail": (d.get("haRole") or "").lower() or None})
            conn = status_of(s.get("connectivityStatus"))
            if conn == "up" and tunnels and any(t["status"] != "up" for t in tunnels):
                conn = worst([t["status"] for t in tunnels]) if any(t["status"] == "up" for t in tunnels) else "down"
            if str(s.get("operationalStatus") or "").lower() in ("disabled", "locked"):
                conn = "off"
            m = by_site.get(str(s.get("id"))) or {}
            secs = 3600.0
            loss = [x for x in (num(m.get("lostUpstreamPcnt")), num(m.get("lostDownstreamPcnt"))) if x is not None]
            jit = [x for x in (num(m.get("jitterUpstream")), num(m.get("jitterDownstream"))) if x is not None]
            items.append({"id": s.get("id"), "name": str(info.get("name") or s.get("id")), "type": info.get("type") or info.get("connType"),
                          "status": conn, "pop": s.get("popName"), "location": ", ".join(x for x in (info.get("region"), info.get("countryName")) if x) or None,
                          "last_change": s.get("connectedSince") or s.get("lastConnected"), "tunnels": tunnels,
                          "rtt_ms": num(m.get("rtt")), "loss_pct": max(loss) if loss else None, "jitter_ms": max(jit) if jit else None,
                          "down_bps": (num(m.get("bytesDownstream")) or 0) * 8 / secs if m.get("bytesDownstream") is not None else None,
                          "up_bps": (num(m.get("bytesUpstream")) or 0) * 8 / secs if m.get("bytesUpstream") is not None else None,
                          "detail": f"{s.get('hostCount')} hosts" if s.get("hostCount") is not None else (info.get("description") or "")})
        self.data["sites"] = {"items": items}
        return self.site_records(items, "Cato site")

    def collect_users(self) -> list[Record]:
        snap = self.gql("users", USERS_Q, fallback=USERS_MIN).get("accountSnapshot") or {}
        devices = []
        for u in snap.get("users") or []:
            info = u.get("info") or {}
            devices.append({"hostname": u.get("deviceName") or "–", "user": info.get("email") or info.get("name") or u.get("name"),
                            "os": None, "version": u.get("version"), "state": str(u.get("connectivityStatus") or "unknown").lower(),
                            "last_seen": u.get("connectedSince") if status_of(u.get("connectivityStatus")) == "up" else u.get("lastConnected"),
                            "detail": " · ".join(x for x in (u.get("popName"), u.get("remoteIP")) if x) or None})
        connected = sum(1 for d in devices if status_of(d["state"]) == "up")
        self.data["users"] = self.fleet(devices, connected)
        return [self.fleet_record(self.data["users"], "Cato SDP clients")]

    def collect_policy(self) -> list[Record]:
        pol = (self.gql("policy", POLICY_Q, {"accountId": self.account}).get("policy") or {})
        rulebases = []
        for key, name in (("internetFirewall", "Internet firewall"), ("wanFirewall", "WAN firewall")):
            p = ((pol.get(key) or {}).get("policy")) or {}
            rules = []
            for i, wrap in enumerate(p.get("rules") or []):
                r = (wrap or {}).get("rule") or {}
                action = r.get("action")
                rules.append({"order": num(r.get("index")) or i + 1, "name": r.get("name"), "enabled": r.get("enabled") is not False,
                              "action": str((action or {}).get("action") if isinstance(action, dict) else action or "").lower() or None,
                              "match": None, "scope": None, "description": r.get("description")})
            if p:
                rulebases.append({"name": name + ("" if p.get("enabled", True) else " (policy disabled)"), "rules": sorted(rules, key=lambda r: r["order"])})
        self.data["policy"] = {"rulebases": rulebases}
        n = sum(len(rb["rules"]) for rb in rulebases)
        return [self.summary_record("policy", "Firewall policy", "Cato firewall rules", f"{n} rules in {len(rulebases)} rule bases")]

    def collect_apps(self) -> list[Record]:
        _, _, label = self.window(7)
        tf = "last.P7D"
        sums = [{"fieldName": f, "aggType": "sum"} for f in ("traffic", "upstream", "downstream", "flows_created")]
        rows = self._records(self.gql("app usage", APPS_Q, {"timeFrame": tf, "measures": sums,
                                                            "dimensions": [{"fieldName": "application"}, {"fieldName": "category"}],
                                                            "sort": [{"fieldName": "traffic", "order": "desc"}]}).get("appStats"))
        users = self.optional("Users per app (appStats ad_name)", lambda: {
            str(r.get("application")): int(num(r.get("ad_name")) or 0) for r in self._records(self.gql("app users", APPS_Q, {
                "timeFrame": tf, "measures": [{"fieldName": "ad_name", "aggType": "count_distinct"}],
                "dimensions": [{"fieldName": "application"}]}).get("appStats"))})
        meta = self.optional("App risk and sanctioned state", lambda: {
            str(r.get("application")): r for r in self._records(self.gql("app risk", APPS_Q, {
                "timeFrame": tf, "measures": [{"fieldName": "traffic", "aggType": "sum"}],
                "dimensions": [{"fieldName": "application"}, {"fieldName": "risk_score"}, {"fieldName": "sanctioned"}]}).get("appStats"))})
        cat = self.ai_category()
        merged: dict[str, dict] = {}
        for r in rows:
            name = str(r.get("application") or "Unknown")
            a = merged.setdefault(name, {"name": name, "category": r.get("category"), "bytes": 0.0, "up": 0.0, "down": 0.0, "events": 0})
            a["bytes"] += num(r.get("traffic")) or 0
            a["up"] += num(r.get("upstream")) or 0
            a["down"] += num(r.get("downstream")) or 0
            a["events"] += int(num(r.get("flows_created")) or 0)
        items = []
        for a in merged.values():
            m = (meta or {}).get(a["name"]) or {}
            sanc = m.get("sanctioned")
            a.update(users=(users or {}).get(a["name"]) if users is not None else None, risk=num(m.get("risk_score")),
                     sanctioned=None if sanc in (None, "") else ("sanctioned" if str(sanc).lower() in ("true", "sanctioned", "1") else "unsanctioned"),
                     ai=is_ai(a["category"], a["name"], cat), action=None)
            items.append(a)
        items.sort(key=lambda a: -a["bytes"])
        self.data["apps"] = {"window": label, "items": items, "categories_seen": counts(a["category"] for a in items)[:20]}
        return [self.apps_record(self.data["apps"])]

    def collect_dlp(self) -> list[Record]:
        _, _, label = self.window(7)
        rows = self._records(self.gql("DLP events", EVENTS_Q, {
            "timeFrame": "last.P7D", "measures": [{"fieldName": "event_count", "aggType": "sum"}],
            "dimensions": [{"fieldName": "application"}, {"fieldName": "rule_name"}, {"fieldName": "severity"}, {"fieldName": "action"}],
            "filters": [{"fieldName": "event_sub_type", "operator": "in", "values": ["DLP", "CASB"]}]}).get("events"))
        sev: dict[str, int] = {}
        rules: dict[str, dict] = {}
        incidents = []
        total = ai = 0
        for r in rows:
            n = int(num(r.get("event_count")) or 0)
            total += n
            if is_ai(None, r.get("application"), ""):
                ai += n
            s = str(r.get("severity") or "unknown")
            sev[s] = sev.get(s, 0) + n
            if r.get("rule_name"):
                rules.setdefault(str(r["rule_name"]), {"name": r["rule_name"], "action": r.get("action"), "enabled": True, "covers": set()})["covers"].add(str(r.get("application") or "?"))
            incidents.append({"time": None, "user": None, "app": r.get("application"), "policy": r.get("rule_name"), "profile": None,
                              "rule": f"{n} events", "severity": r.get("severity"), "action": r.get("action")})
        self.data["dlp"] = {"window": label, "total": total, "ai_incidents": ai, "by_severity": sorted(([k, v] for k, v in sev.items()), key=lambda x: -x[1]),
                            "rules": [{**r, "covers": ", ".join(sorted(r["covers"])[:8])} for r in rules.values()],
                            "incidents": sorted(incidents, key=lambda i: -int(str(i["rule"]).split()[0]))[:200], "profiles": []}
        return [self.summary_record("dlp", "DLP events", "Cato DLP / CASB", f"{total} DLP and CASB events in 7 days, {ai} on AI apps", alerts=total)]

    @staticmethod
    def _records(node: Any) -> list[dict]:
        """appStats / events -> records[].fieldsMap as plain dicts."""
        recs = (node or {}).get("records") if isinstance(node, dict) else None
        return [r.get("fieldsMap") or {} for r in recs or [] if isinstance(r, dict)]
