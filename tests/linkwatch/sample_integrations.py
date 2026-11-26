"""Integration payloads shaped like the collectors' output, for page tests and screenshots."""

ZSCALER = {"type": "zscaler", "unavailable": ["ZPA application segments: GET ... returned HTTP 403"],
           "products": {"zia": {"ok": True, "objects": 3}, "zpa": {"ok": True, "objects": 3}, "zdx": {"ok": True, "objects": 3},
                        "zcc": {"ok": True, "objects": 1}, "ztb": {"ok": False, "error": "OneAPI refused /ztb/api/v2/Site/ (HTTP 401/403)."}},
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
           "ztb": {}}

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
    "proxmox": [{"external_id": "node-pve-01", "hostname": "pve-01", "type": "Hypervisor", "status": "up", "cpu": 23.5, "mem": 31.3},
                {"external_id": "lxc-105", "hostname": "poller-hq-01", "type": "Container", "status": "up"}],
}
DATA = {"zscaler": ZSCALER, "meraki": MERAKI, "panos": PANOS, "fortigate": FORTIGATE, "proxmox": PROXMOX}
