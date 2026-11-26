"""Sample tenant shown until a real ZIA tenant is connected."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from ..db import Store
from ..zia.policies import normalise_rule

# (policy type, raw ZIA rule, relative weight in sample traffic)
_RULES = [
    ("URL filtering", {"name": "Block malicious and phishing", "order": 1, "action": "BLOCK", "urlCategories": ["MALICIOUS_CONTENT", "PHISHING", "SPYWARE_OR_ADWARE"]}, 3),
    ("URL filtering", {"name": "Isolate newly registered domains", "order": 2, "action": "ISOLATE", "urlCategories": ["NEWLY_REG_DOMAINS"], "cbiProfile": {"name": "Default isolation"}}, 6),
    ("URL filtering", {"name": "Caution on personal storage", "order": 3, "action": "CAUTION", "urlCategories": ["PERSONAL_NETWORK_STORAGE"], "departments": [{"name": "Finance"}, {"name": "Legal"}]}, 1),
    ("URL filtering", {"name": "Block gambling and adult", "order": 4, "action": "BLOCK", "urlCategories": ["GAMBLING", "ADULT_THEMES"]}, 2),
    ("URL filtering", {"name": "Allow business web", "order": 5, "action": "ALLOW", "urlCategories": ["ANY"]}, 40),
    ("URL filtering", {"name": "Legacy contractor allow", "order": 6, "action": "ALLOW", "urlCategories": ["STREAMING"], "groups": [{"name": "Contractors-2023"}], "lastModifiedBy": {"name": "former-admin@acme.example"}}, 0),
    ("Cloud app control", {"name": "Block unsanctioned GenAI uploads", "order": 1, "actions": ["BLOCK_AI_ML_UPLOAD"], "applications": ["UNSANCTIONED_AI"]}, 2),
    ("Cloud app control", {"name": "Isolate webmail for contractors", "order": 2, "actions": ["ISOLATE_WEBMAIL_VIEW"], "applications": ["GMAIL", "OUTLOOK_COM"], "groups": [{"name": "Contractors"}]}, 1),
    ("Cloud app control", {"name": "Allow sanctioned collaboration", "order": 3, "actions": ["ALLOW_ENTERPRISE_COLLABORATION"], "applications": ["MICROSOFT_365", "SLACK", "ZOOM"]}, 30),
    ("Cloud firewall", {"name": "Block outbound SMB and RDP", "order": 1, "action": "BLOCK_DROP", "nwServices": [{"name": "SMB"}, {"name": "RDP"}]}, 4),
    ("Cloud firewall", {"name": "Allow web and DNS", "order": 2, "action": "ALLOW", "nwServices": [{"name": "HTTP"}, {"name": "HTTPS"}, {"name": "DNS"}]}, 24),
    ("Cloud firewall", {"name": "Default Firewall Filtering Rule", "order": 3, "action": "BLOCK_DROP"}, 1),
    ("DNS control", {"name": "Block DNS tunnelling", "order": 1, "action": "BLOCK", "applications": ["DNS_TUNNEL"]}, 3),
    ("DNS control", {"name": "Block DoH to unsanctioned resolvers", "order": 2, "action": "BLOCK", "applications": ["DOH"]}, 1),
    ("DNS control", {"name": "Default DNS Rule", "order": 3, "action": "ALLOW"}, 26),
    ("SSL inspection", {"name": "Do not inspect health and banking", "order": 1, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["HEALTH", "FINANCE"]}, 0),
    ("File type control", {"name": "Block executables from uncategorised", "order": 1, "filteringAction": "BLOCK", "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_MSI"]}, 1),
    ("Sandbox", {"name": "Quarantine unknown files", "order": 1, "baRuleAction": "BLOCK"}, 1),
    ("DLP", {"name": "Block source code to personal repos", "order": 1, "action": "BLOCK", "dlpEngines": [{"name": "Source code"}], "departments": [{"name": "Engineering"}]}, 1),
]
_HOSTS = {
    "URL filtering": ["login-micros0ft-verify.example", "new-domain-7731.example", "dropbox.com", "casino-royal.example", "docs.github.com", "netflix.com"],
    "Cloud app control": ["chat.unsanctioned-ai.example", "mail.google.com", "acme.sharepoint.com"],
    "Cloud firewall": ["203.0.113.40:445", "198.51.100.7:443", "192.0.2.15:3389"],
    "DNS control": ["a8f3k2.tunnel-dns.example", "dns.quad-resolver.example", "api.salesforce.com"],
    "File type control": ["cdn.freeware-host.example"],
    "Sandbox": ["files.vendor-share.example"],
    "DLP": ["gitlab.com"],
    "SSL inspection": ["mybank.example"],
}
# Destinations that fit what each rule matches, so sample lines read correctly.
_RULE_HOSTS = {
    "Block malicious and phishing": ["login-micros0ft-verify.example", "secure-paypa1.example"],
    "Isolate newly registered domains": ["new-domain-7731.example", "fresh-shop-2026.example"],
    "Caution on personal storage": ["dropbox.com", "drive.google.com"],
    "Block gambling and adult": ["casino-royal.example"],
    "Allow business web": ["docs.github.com", "www.bbc.co.uk", "learn.microsoft.com", "www.nytimes.com"],
    "Block unsanctioned GenAI uploads": ["chat.unsanctioned-ai.example"],
    "Isolate webmail for contractors": ["mail.google.com", "outlook.live.com"],
    "Allow sanctioned collaboration": ["acme.sharepoint.com", "acme.slack.com", "zoom.us"],
    "Block outbound SMB and RDP": ["203.0.113.40:445", "192.0.2.15:3389"],
    "Allow web and DNS": ["198.51.100.7:443", "8.8.8.8:53"],
    "Default Firewall Filtering Rule": ["203.0.113.99:6667"],
    "Block DNS tunnelling": ["a8f3k2.tunnel-dns.example"],
    "Block DoH to unsanctioned resolvers": ["dns.quad-resolver.example"],
    "Default DNS Rule": ["api.salesforce.com", "login.microsoftonline.com"],
}

_FIRST = ["ana", "ben", "chloe", "dev", "ema", "femi", "grace", "hiro", "ines", "jon", "kai", "lena", "malik", "nora",
          "omar", "priya", "quinn", "rosa", "sam", "tara", "uri", "vik", "wen", "yara"]
_LAST = ["silva", "okafor", "martin", "patel", "novak", "adeyemi", "kim", "tanaka", "garcia", "berg", "reyes", "fischer",
         "hassan", "lund", "haddad", "rao", "byrne", "costa", "wright", "singh", "levi", "mehta", "zhou", "nasser"]
_DEPTS = ["Engineering", "Finance", "Sales", "Legal", "Marketing", "Support", "Contractors", "IT"]
_LOCS = ["New York HQ", "London", "Austin", "Frankfurt", "Singapore", "Remote (ZCC)", "Toronto", "Sao Paulo"]


def seed_demo(store: Store, n_events: int = 2500, seed: int = 7) -> None:
    rnd = random.Random(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rules = []
    for i, (ptype, raw, _) in enumerate(_RULES):
        raw = {"id": 1000 + i, "state": "ENABLED", "lastModifiedTime": int((now - timedelta(days=rnd.randint(2, 200))).timestamp()),
               "lastModifiedBy": {"name": "secops@acme.example"}} | raw
        rules.append(normalise_rule(ptype, raw).to_dict())
    store.put_snapshot("rules", rules, demo=True)

    users = [{"id": i, "name": f"{f.title()} {l.title()}", "email": f"{f}.{l}@acme.example",
              "department": rnd.choice(_DEPTS), "groups": [], "type": None} for i, (f, l) in enumerate(zip(_FIRST, _LAST))]
    store.put_snapshot("users", users, demo=True)
    user_loc = {u["email"]: rnd.choice(_LOCS) for u in users}
    store.put_snapshot("locations", [{"id": i, "name": n, "country": None, "ip_addresses": [],
                                      "vpn_credentials": ["vpn"] * (0 if "ZCC" in n else 2), "ssl_scan": True,
                                      "auth_required": True, "parent_id": 0} for i, n in enumerate(_LOCS)], demo=True)
    store.put_snapshot("gre_tunnels", [{"id": 1, "source_ip": "198.51.100.10", "comment": "London", "primary": "LON3 185.46.212.88",
                                        "secondary": "AMS2 185.46.212.89"}], demo=True)
    store.put_snapshot("activation", {"status": "ACTIVE"}, demo=True)

    weights = [w for *_, w in _RULES]
    events = []
    # Users who were away during the last two days, so the 48-hour view differs.
    away = set(rnd.sample([u["email"] for u in users], 5))
    for _ in range(n_events):
        idx = rnd.choices(range(len(_RULES)), weights=weights)[0]
        ptype, raw, _ = _RULES[idx]
        u = rnd.choice(users)
        hours_ago = rnd.random() * 168
        if u["email"] in away and hours_ago < 48:
            hours_ago += 48
        ts = now - timedelta(hours=hours_ago)
        work = 1.0 if ts.weekday() < 5 and 7 <= ts.hour <= 19 else 0.25
        size = int(rnd.lognormvariate(14, 1.4) * work)
        action = rules[idx]["action"]
        events.append({
            "ts": ts.isoformat(timespec="seconds"), "user": u["email"], "department": u["department"],
            "location": user_loc[u["email"]], "client_ip": f"10.{rnd.randint(20, 50)}.{rnd.randint(0, 250)}.{rnd.randint(1, 250)}",
            "destination": rnd.choice(_RULE_HOSTS.get(raw["name"]) or _HOSTS[ptype]), "category": None, "action": action, "policy_type": ptype,
            "rule_label": raw["name"], "bytes_in": size, "bytes_out": size // 5, "import_id": None,
            "raw": '{"note": "sample event"}',
        })
    import_id = store.add_import("sample-data", "web", len(events), 0, [], demo=True)
    for e in events:
        e["import_id"] = import_id
    store.add_events(events)


def ensure_demo(store: Store) -> None:
    if store.get_snapshot("rules") is None and not store.has_live_data():
        seed_demo(store)
