"""Integration payloads shaped like the collectors' output, for page tests and screenshots."""

ZSCALER = {"type": "zscaler", "unavailable": ["ZPA application segments: GET ... returned HTTP 403"],
           "products": {"zia": {"ok": True, "objects": 3}, "zpa": {"ok": True, "objects": 3}, "zdx": {"ok": True, "objects": 3},
                        "zcc": {"ok": True, "objects": 1}, "ztb": {"ok": False, "error": "OneAPI refused /ztb/api/v2/Site/ (HTTP 401/403)."},
                        "ai": {"ok": True, "objects": 1}},
           "zia": {"activation": "ACTIVE",
                   "locations": [{"id": 1, "name": "HQ", "country": "UNITED_STATES", "ips": ["198.51.100.10"], "vpn_credentials": 1,
                                  "up_kbps": 500000, "down_kbps": 1000000, "firewall": True, "ssl_scan": True, "auth": True, "xff": False, "sub": False},
                                 {"id": 2, "name": "HQ Guest", "country": "UNITED_STATES", "ips": [], "vpn_credentials": 0,
                                  "firewall": True, "ssl_scan": False, "auth": False, "xff": False, "sub": True}],
                   "tunnels": [{"id": 7, "source_ip": "198.51.100.10", "primary": "DFW1", "primary_vip": "165.225.0.1",
                                "secondary": "ATL2", "secondary_vip": "165.225.0.2", "inside": "172.17.0.0/29", "comment": "HQ edge"}]},
           "zpa": {"connectors": [
               {"id": "a1", "name": "ac-hq-01", "group": "HQ", "enabled": True, "healthy": True, "channel": "authenticated",
                "version": "24.302.1", "expected": "24.302.1", "private_ip": "10.0.0.20", "public_ip": "198.51.100.10",
                "location": "Dallas", "os": "RHEL 9", "last_connect": "2026-11-26T15:00:00Z"},
               {"id": "a2", "name": "ac-hq-02", "group": "HQ", "enabled": True, "healthy": False, "channel": "disconnected",
                "version": "24.220.4", "expected": "24.302.1", "upgrade": "UPGRADE_FAILED", "private_ip": "10.0.0.21"}],
               "groups": 2, "applications": None, "healthy": 1, "outdated": 1},
           "zdx": {"apps": [{"id": 3, "name": "Microsoft 365", "score": 81, "users": 240, "region": "United States"},
                            {"id": 4, "name": "Salesforce", "score": 29, "users": 80, "region": "Germany"}]},
           "zcc": {"total": 3, "versions": [["4.4.0.389", 2], ["4.3.0.243", 1]], "os": [["Windows", 2], ["macOS", 1]],
                   "states": [["Registered", 2], ["Removed", 1]],
                   "devices": [{"hostname": "LT-0042", "user": "ada@contoso.com", "os": "Windows 11", "version": "4.4.0.389",
                                "state": "Registered", "model": "Latitude 7440", "last_seen": "2026-11-26 14:58"}]},
           "ztb": {},
           "ai": {"refreshed": "2026-11-26T15:00:00Z", "window": {"days": 7, "end": "2026-11-25"},
                  "catalog": ["ChatGPT", "Claude", "DeepSeek", "Google Gemini", "Microsoft Copilot", "Perplexity"],
                  "categories_seen": [["AI & ML Applications", 5], ["File Sharing", 12]], "matched_categories": ["AI & ML Applications"],
                  "apps": [{"name": "ChatGPT", "category": "AI & ML Applications", "sanctioned": "sanctioned", "risk": 3, "users": 214,
                            "bytes": 6.2e9, "up": 1.4e9, "down": 4.8e9, "last_access": "2026-11-25T23:10:00Z",
                            "action": "allow", "rule": "ChatGPT Enterprise for staff", "prompt_capture": True},
                           {"name": "Microsoft Copilot", "category": "AI & ML Applications", "sanctioned": "sanctioned", "risk": 2, "users": 380,
                            "bytes": 3.1e9, "up": 6e8, "down": 2.5e9, "last_access": "2026-11-25T23:40:00Z",
                            "action": "allow", "rule": "Copilot", "prompt_capture": False},
                           {"name": "Google Gemini", "category": "AI & ML Applications", "sanctioned": "unsanctioned", "risk": 3, "users": 41,
                            "bytes": 4.2e8, "up": 9e7, "down": 3.3e8, "last_access": "2026-11-25T18:02:00Z",
                            "action": "caution", "rule": "Caution other AI", "prompt_capture": False},
                           {"name": "Perplexity", "category": "AI & ML Applications", "sanctioned": "unsanctioned", "risk": 4, "users": 17,
                            "bytes": 1.1e8, "up": 2e7, "down": 9e7, "last_access": "2026-11-24T11:20:00Z",
                            "action": "caution", "rule": "Caution other AI", "prompt_capture": False},
                           {"name": "DeepSeek", "category": "AI & ML Applications", "sanctioned": "unsanctioned", "risk": 5, "users": 3,
                            "bytes": 2e6, "up": 1.2e6, "down": 8e5, "last_access": "2026-11-21T09:00:00Z",
                            "action": "block", "rule": "Block DeepSeek", "prompt_capture": False}],
                  "summary": {"total_bytes": 9.4e10, "total_apps": 162, "apps": 5, "users": 512, "up": 2.1e9, "down": 7.7e9, "bytes": 9.8e9},
                  "rules": [{"name": "Block DeepSeek", "order": 1, "enabled": True, "action": "block", "apps": ["DeepSeek"], "app_ids": ["DEEPSEEK"],
                             "all_apps": False, "prompt_capture": False, "isolation": None, "scope": {}, "description": "Not approved by legal"},
                            {"name": "ChatGPT Enterprise for staff", "order": 2, "enabled": True, "action": "allow", "apps": ["ChatGPT"],
                             "app_ids": ["CHATGPT_AI"], "all_apps": False, "prompt_capture": True, "isolation": None,
                             "scope": {"groups": ["Staff", "Engineering"]}, "time_quota": None, "size_quota": None},
                            {"name": "Copilot", "order": 3, "enabled": True, "action": "allow", "apps": ["Microsoft Copilot"], "app_ids": ["MS_COPILOT"],
                             "all_apps": False, "prompt_capture": False, "isolation": None, "scope": {}},
                            {"name": "Caution other AI", "order": 4, "enabled": True, "action": "caution", "apps": [], "app_ids": [],
                             "all_apps": True, "prompt_capture": False, "isolation": None, "scope": {}},
                            {"name": "Isolate AI for contractors", "order": 5, "enabled": False, "action": "isolate", "apps": ["ChatGPT", "Claude"],
                             "app_ids": [], "all_apps": False, "prompt_capture": False, "isolation": "Contractor isolation",
                             "scope": {"departments": ["Contractors"]}}],
                  "dlp_rules": [{"name": "Block PII to AI", "order": 1, "action": "block", "enabled": True, "apps": ["ChatGPT", "Google Gemini"],
                                 "categories": ["General AI & ML"], "engines": ["PII", "PCI"]}],
                  "aiguard": None,
                  "not_exposed": [["DLP incidents on AI prompts", "The API exposes DLP rules, not the incidents they raise."],
                                  ["Isolation sessions", "Only isolation profiles are exposed, not sessions."]]}}

MERAKI = {"type": "meraki", "unavailable": [],
          "networks": [{"id": "N1", "name": "Dallas", "types": ["appliance", "switch", "wireless"], "tz": "America/Chicago", "tags": ["hq"], "up": 5, "warn": 1}],
          "by_type": {"Wireless": {"total": 4, "up": 3, "warn": 1, "down": 0, "off": 0, "unknown": 0},
                      "Firewall": {"total": 1, "up": 1, "warn": 0, "down": 0, "off": 0, "unknown": 0}},
          "firmware": [["MR46 wireless-30-7", 4], ["MX85 MX 18.211", 1]],
          "uplinks": [{"serial": "Q2-MX", "device": "dal-mx", "network": "Dallas", "interface": "wan1", "status": "active", "ip": "203.0.113.2",
                       "public_ip": "203.0.113.2", "provider": "Fiber Co"},
                      {"serial": "Q2-MX", "device": "dal-mx", "network": "Dallas", "interface": "wan2", "status": "failed", "ip": None}],
          "loss_latency": [{"serial": "Q2-MX", "device": "dal-mx", "uplink": "wan1", "target": "8.8.8.8", "latency_ms": 11.4, "loss_pct": 0.0}],
          "clients": {"total": 212, "down_bps": 48_000_000, "up_bps": 9_000_000}, "licensing": {"status": "OK", "expires": "Mar 1, 2028 UTC"}}

PANOS = {"type": "panos", "unavailable": ["GlobalProtect users: PAN-OS error: no gateway"],
         "system": {"hostname": "pa-edge", "model": "PA-440", "serial": "0123456789", "sw-version": "11.1.4-h7", "uptime": "21 days, 4:02:11",
                    "app-version": "8901-9100", "threat-version": "8901-9100"},
         "sessions": {"active": 18234, "max": 64000, "cps": 210, "pps": 52000, "throughput_bps": 412_000_000},
         "ha": {"mode": "Active-Passive", "local": "active", "peer": "passive", "peer_ip": "10.50.0.2", "sync": "synchronized"},
         "licenses": [{"feature": "Threat Prevention", "expires": "March 01, 2027", "expired": False},
                      {"feature": "WildFire License", "expires": "January 01, 2026", "expired": True}],
         "tunnels": [{"name": "to-azure", "state": "active", "peer": "20.1.2.3", "local": "203.0.113.2", "interface": "tunnel.1"},
                     {"name": "to-dr", "state": "init", "peer": "198.51.100.77", "local": "203.0.113.2", "interface": "tunnel.2"}],
         "interfaces": [{"name": "ethernet1/1", "zone": "untrust", "ip": "203.0.113.2/29", "state": "up"},
                        {"name": "ethernet1/2", "zone": "trust", "ip": "10.50.0.1/24", "state": "up"}]}

FORTIGATE = {"type": "fortigate", "unavailable": [],
             "system": {"hostname": "fg-branch", "model": "FortiGate 60F", "serial": "FGT60F000", "version": "v7.4.5", "build": 2702},
             "resources": {"cpu": 7, "mem": 41, "disk": 12, "session": 3021, "setuprate": 44},
             "tunnels": [{"name": "hq", "remote": "198.51.100.10", "phase2_up": 1, "phase2": 1, "in_bytes": 9_200_000_000, "out_bytes": 1_100_000_000}],
             "interfaces": [{"name": "wan1", "alias": "Fiber", "ip": "203.0.113.9", "up": True, "speed": 1000.0}],
             "sslvpn": [{"user": "grace", "remote": "198.51.100.200", "tunnel_ip": "10.212.134.200"}],
             "licenses": [{"feature": "antivirus", "status": "licensed", "expires": 1830000000}]}

SONICWALL = {"type": "sonicwall", "unavailable": [], "not_offered": ["IPsec tunnels"],
             "system": {"model": "TZ 470", "serial": "2CB8ED000000", "firmware": "SonicOS 7.0.1-5145", "uptime": "12 Days 03:10:44"},
             "interfaces": [{"name": "X0", "zone": "LAN", "mode": "static", "ip": "192.168.168.168", "mask": "255.255.255.0"},
                            {"name": "X1", "zone": "WAN", "mode": "dhcp"}],
             "sslvpn": [{"user": "hopper", "remote": "198.51.100.44", "tunnel_ip": "192.168.200.10"}],
             "licenses": [{"name": "Gateway Anti-Virus", "status": "Licensed", "expires": "2027-03-01"},
                          {"name": "Capture ATP", "status": "Expired", "expires": "2025-01-01"}],
             "ha": {"mode": "Active/Standby", "state": "Active"}}

PROXMOX = {"type": "proxmox", "unavailable": [],
           "nodes": [{"name": "pve-01", "status": "online", "cpu": 23.5, "maxcpu": 16, "mem": 40 * 2**30, "maxmem": 128 * 2**30, "uptime_s": 900000, "guests": 12, "running": 10}],
           "storage": [{"name": "local-zfs", "node": "pve-01", "type": "zfspool", "status": "available", "used": 700 * 2**30, "size": 800 * 2**30, "shared": False}],
           "guests": {"total": 12, "running": 10, "vms": 7, "containers": 5},
           "top_guests": [{"name": "poller-hq-01", "vmid": 105, "node": "pve-01", "type": "lxc", "cpu": 12.0, "mem": 2**29, "maxmem": 2**30, "netin": 9e9, "netout": 2e9}]}

RECORDS = {
    "zscaler": [{"external_id": "zpa-ac-a1", "hostname": "ac-hq-01", "type": "Zscaler", "status": "up", "extra": {"product": "zpa"}},
                {"external_id": "zpa-ac-a2", "hostname": "ac-hq-02", "type": "Zscaler", "status": "down", "detail": "Control channel disconnected", "extra": {"product": "zpa"}},
                {"external_id": "zia-loc-1", "hostname": "ZIA location HQ", "type": "Zscaler", "status": "unknown", "extra": {"product": "zia"}}],
    "meraki": [{"external_id": "Q2-MX", "hostname": "dal-mx", "type": "Firewall", "status": "up", "site": "Dallas"}],
    "panos": [{"external_id": "0123456789", "hostname": "pa-edge", "type": "Firewall", "status": "up", "cpu": 18.0, "mem": 52.0}],
    "fortigate": [{"external_id": "FGT60F000", "hostname": "fg-branch", "type": "Firewall", "status": "up", "cpu": 7, "mem": 41}],
    "sonicwall": [{"external_id": "2CB8ED000000", "hostname": "tz-branch", "type": "Firewall", "status": "warn"}],
    "proxmox": [{"external_id": "node-pve-01", "hostname": "pve-01", "type": "Hypervisor", "status": "up", "cpu": 23.5, "mem": 31.3},
                {"external_id": "lxc-105", "hostname": "poller-hq-01", "type": "Container", "status": "up"}],
}
DATA = {"zscaler": ZSCALER, "meraki": MERAKI, "panos": PANOS, "fortigate": FORTIGATE, "sonicwall": SONICWALL, "proxmox": PROXMOX}


def sse_sample(kind: str, vendor: str) -> dict:
    """One payload in the shared SSE shape (integrations/sse.py), reused for every SSE platform."""
    return {
        "type": kind, "sse": True, "vendor": vendor, "unavailable": ["GRE tunnels: GET /api/v2/steering/gre/tunnels returned HTTP 404"],
        "products": {"sites": {"ok": True, "objects": 2}, "private": {"ok": True, "objects": 2}, "users": {"ok": True, "objects": 1},
                     "policy": {"ok": True, "objects": 1}, "apps": {"ok": True, "objects": 1}, "dlp": {"ok": False, "error": "DLP events refused (HTTP 403)"}},
        "labels": {"sites": "Sites & tunnels", "private": "Connectors", "users": "Endpoints", "policy": "Policies", "apps": "Apps & AI", "dlp": "DLP"},
        "gaps": {"apps": [["Prompts sent to AI apps", "Only in the admin console."]], "dlp": [["DLP profile definitions", "No API."]]},
        "sites": {"items": [
            {"id": "s1", "name": "Dallas HQ", "type": "IPsec tunnel", "status": "up", "pop": "DFW1", "rtt_ms": 11.2, "loss_pct": 0.0, "down_bps": 8e6, "up_bps": 1e6,
             "tunnels": [{"name": "IPsec DFW1", "status": "up", "peer": "203.0.113.4"}, {"name": "IPsec IAH1", "status": "up"}]},
            {"id": "s2", "name": "Austin Lab", "type": "IPsec tunnel", "status": "down", "pop": "DFW1", "tunnels": [{"name": "IPsec DFW1", "status": "down"}],
             "detail": "Phase 1 down"}]},
        "private": {"items": [{"id": "p1", "name": "pub-dc1", "status": "up", "version": "118.0", "ip": "10.0.0.5", "detail": "4 apps"},
                              {"id": "p2", "name": "pub-dc2", "status": "down", "state": "not registered"}], "apps": 7},
        "users": {"total": 2, "connected": 1, "versions": [["120.1", 2]], "os": [["Windows", 1], ["Mac", 1]], "states": [["connected", 1], ["disconnected", 1]],
                  "devices": [{"hostname": "LT-0042", "user": "ada@contoso.com", "os": "Windows 11", "version": "120.1", "state": "connected", "last_seen": "2026-11-26T14:58:00Z"}]},
        "policy": {"rulebases": [{"name": "Internet firewall", "rules": [
            {"order": 1, "name": "Block DeepSeek", "enabled": True, "action": "block", "match": "DeepSeek", "scope": "everyone"},
            {"order": 2, "name": "Old rule", "enabled": False, "action": "allow", "match": "any", "scope": "Contractors"}]}]},
        "apps": {"window": {"days": 7, "end": "2026-11-26 15:00 UTC"}, "refreshed": "2026-11-26T15:00:00Z", "items": [
            {"name": "Microsoft 365", "category": "Business", "ai": False, "users": 400, "events": 9000, "bytes": 9e10, "up": 1e10, "down": 8e10},
            {"name": "ChatGPT", "category": "Generative AI", "ai": True, "users": 214, "events": 3000, "bytes": 6.2e9, "up": 1.4e9, "down": 4.8e9,
             "sanctioned": "sanctioned", "action": "allow", "rule": "ChatGPT Enterprise"},
            {"name": "DeepSeek", "category": "Generative AI", "ai": True, "users": 3, "events": 9, "bytes": 2e6, "up": 1e6, "down": 1e6,
             "sanctioned": "unsanctioned", "action": "block"}], "categories_seen": [["Business", 1], ["Generative AI", 2]]},
    }


SSE_KINDS = {"netskope": "Netskope", "cato": "Cato", "prisma": "Prisma Access", "cloudflare": "Cloudflare"}
for _k, _v in SSE_KINDS.items():
    DATA[_k] = sse_sample(_k, _v)
    RECORDS[_k] = [{"external_id": "sites-s1", "hostname": "Dallas HQ", "type": _v, "status": "up", "extra": {"product": "sites"}},
                   {"external_id": "sites-s2", "hostname": "Austin Lab", "type": _v, "status": "down", "extra": {"product": "sites"}},
                   {"external_id": "private-p1", "hostname": "pub-dc1", "type": _v, "status": "up", "extra": {"product": "private"}}]

# Cloudflare's own tabs on top of the shared SSE sample
DATA["cloudflare"]["products"].update({k: {"ok": True, "objects": 1} for k in ("gateway", "access", "dex", "zones", "audit")})
DATA["cloudflare"]["labels"].update({"gateway": "Gateway", "access": "Access", "dex": "DEX & posture", "zones": "Zones", "audit": "Audit log"})
DATA["cloudflare"].update({
    "metrics": [["gateway:dns", 940, 40, None], ["access:logins", 1, 1, None], ["zones:traffic", 10000, 12, 6000]],
    "gateway": {"window": "24 hours",
                "dns": {"total": 940, "blocked": 40, "by_decision": [["allowedOnNoPolicyMatch", 900], ["blockedByCategory", 30]],
                        "top_blocked": [["www.badsite.com", 30]], "top_blocked_categories": [["Security risks", 40]]},
                "http": {"total": 520, "blocked": 20, "by_decision": [["allow", 500], ["block", 20]], "top_blocked": [["chat.deepseek.com", 20]]},
                "network": None, "locations": [{"name": "HQ office", "default": True, "networks": ["203.0.113.0/24"], "doh": "abc123", "ecs": False}],
                "lists": [{"name": "Allowed AI", "type": "DOMAIN", "count": 4}], "proxy_endpoints": None,
                "settings": [["TLS decryption", True], ["Activity logging", False]]},
    "access": {"apps": [{"name": "Wiki", "domain": "wiki.contoso.com", "type": "self_hosted", "policies": ["Staff"], "session": "24h", "idps": "all"}],
               "policies": [{"name": "Staff", "decision": "allow", "apps": 3, "include": "email domain: contoso.com", "require": "", "exclude": ""}],
               "idps": [{"name": "Entra ID", "type": "azureAD", "scim": True}], "groups": [{"name": "Engineering", "include": "email: a@contoso.com"}],
               "service_tokens": [{"name": "ci-runner", "expires": "2026-12-08T00:00:00Z", "days": 10, "status": "warn"}],
               "org": {"name": "Contoso", "auth_domain": "contoso.cloudflareaccess.com", "session": "24h"},
               "logins": {"allowed": 1, "denied": 1, "top_denied_users": [["eve@example.com", 1]], "by_app": [["wiki.contoso.com", 2]], "capped": False,
                          "recent": [{"time": "2026-11-27T10:00:00Z", "user": "eve@example.com", "app": "wiki.contoso.com", "allowed": False, "ip": "198.51.100.9"}]}},
    "dex": {"fleet": {"total": 120, "by_status": [["connected", 100], ["disconnected", 20]], "by_platform": [["windows", 90]], "by_version": [["2024.9", 120]],
                      "by_colo": [], "by_mode": []},
            "tests": [{"name": "M365 reachability", "kind": "http", "host": "https://outlook.office.com", "enabled": True, "availability": 91.5, "fetch_ms": 210}],
            "posture": [{"name": "Disk encrypted", "type": "disk_encryption", "platforms": ["mac", "windows"]}],
            "posture_integrations": [{"name": "CrowdStrike", "type": "crowdstrike_s2s", "interval": "10m"}],
            "profiles": [{"name": "Contractors", "mode": "proxy", "match": "identity.groups.name in {\"Contractors\"}", "locked": True, "enabled": True}]},
    "zones": {"items": [{"id": "z1", "name": "contoso.com", "status": "active", "paused": False, "plan": "Pro Plan", "ssl": "flexible", "min_tls": "1.2",
                         "https": "on", "records": 42, "requests": 10000, "cached": 6000, "threats": 12, "events": [["waf: block", 7]]}], "capped": False},
    "audit": {"events": [{"time": "2026-11-27T09:00:00Z", "actor": "admin@contoso.com", "action": "rule_update", "ok": True, "resource": "gateway_rule",
                          "detail": "Block AI", "interface": "UI"}], "by_actor": [["admin@contoso.com", 1]], "by_action": [["rule_update", 1]], "failed": 0},
})
DATA["cloudflare"]["sites"]["magic"] = {"sites": [{"name": "Dallas branch", "ha": True}], "connectors": [{"id": "mc1", "serial": "SN-0001", "activated": True}],
                                        "routes": [{"prefix": "10.1.0.0/16", "nexthop": "10.200.0.0", "priority": 100}],
                                        "firewall": [{"order": 1, "description": "Allow ICMP", "action": "skip", "enabled": True, "expression": "ip.proto eq \"icmp\""}]}
DATA["cloudflare"]["private"].update({"routes": [{"network": "10.50.0.0/16", "tunnel": "dc1", "vnet": "default"}], "vnets": [{"name": "default", "default": True}],
                                      "hostnames": None})
