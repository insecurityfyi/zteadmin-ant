"""Shared helpers for network discovery: target parsing (server validates, poller expands) and type guessing."""
from __future__ import annotations

import ipaddress
import re

MAX_HOSTS = 4096

SYS_NAME, SYS_DESCR, SYS_OBJECT_ID = "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"


class TargetError(ValueError):
    pass


def expand_targets(text: str, limit: int = MAX_HOSTS) -> list[str]:
    """'10.0.0.0/24, 10.0.1.5, 10.0.2.10-10.0.2.20' -> host IPs (no network/broadcast for /30 and larger)."""
    hosts: list[str] = []
    seen: set[str] = set()
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    raise TargetError(f"{tok}: only IPv4 ranges are supported")
                if net.num_addresses > limit:
                    raise TargetError(f"{tok} has {net.num_addresses} addresses; scan at most {limit} at a time (a /20)")
                ips = list(net.hosts()) or [net.network_address]
            elif "-" in tok:
                a, b = tok.split("-", 1)
                start = ipaddress.IPv4Address(a)
                end = ipaddress.IPv4Address(b) if "." in b else ipaddress.IPv4Address(f"{a.rsplit('.', 1)[0]}.{b}")
                if end < start:
                    raise TargetError(f"{tok}: the range ends before it starts")
                if int(end) - int(start) + 1 > limit:
                    raise TargetError(f"{tok} is more than {limit} addresses")
                ips = [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]
            else:
                ips = [ipaddress.IPv4Address(tok)]
        except TargetError:
            raise
        except ValueError:
            raise TargetError(f"'{tok}' is not an IPv4 address, range (10.0.0.10-50) or CIDR (10.0.0.0/24)") from None
        for ip in ips:
            s = str(ip)
            if s not in seen:
                seen.add(s)
                hosts.append(s)
                if len(hosts) > limit:
                    raise TargetError(f"That is more than {limit} addresses in total")
    if not hosts:
        raise TargetError("Enter at least one address, range or CIDR")
    return hosts


_TYPES = [
    ("Firewall", r"pan-os|palo alto|fortigate|fortios|adaptive security|\basa\b|firepower|sonicwall|pfsense|opnsense|sophos|checkpoint|check point|juniper.*\bsrx\d"),
    ("Wireless", r"wireless|access point|\baironet\b|aireos|\bwlc\b|meraki mr|unifi ap|\buap\b|ruckus|aruba ap|instant on ap"),
    ("Hypervisor", r"proxmox|-pve\b|vmware esxi|esxi|hyper-v|xcp-ng|xenserver"),
    ("Storage", r"synology|qnap|truenas|freenas|netapp|isilon|nimble|pure storage"),
    ("Power", r"\bups\b|apc |smart-ups|eaton|powerware|cyberpower|\bpdu\b|vertiv|liebert"),
    ("Printer", r"printer|jetdirect|laserjet|xerox|ricoh|kyocera|lexmark|brother nc"),
    ("Camera", r"camera|axis |hikvision|dahua|\bnvr\b"),
    ("Router", r"routeros|mikrotik|\bisr\b|\basr\b|ios xr|ios-xr|junos.*\bmx\d|juniper.*\bmx\d|vyos|edgeos|edgerouter|router"),
    ("Switch", r"switch|catalyst|nx-os|nexus|juniper.*\bex\d|\bios\b|ios-xe|junos|procurve|arubaos-cx|aruba|dell emc networking|extremexos|exos|unifi|meraki ms|\bicx\b|fastiron"),
    ("Server", r"linux|windows|freebsd|ubuntu|debian|red hat|centos|darwin|idrac|ilo|supermicro"),
]


def guess_type(sys_descr: str | None, sys_object_id: str | None = None) -> str:
    text = (sys_descr or "").lower()
    if text:
        for kind, pattern in _TYPES:
            if re.search(pattern, text):
                return kind
    oid = sys_object_id or ""
    if oid.startswith("1.3.6.1.4.1.25461."):
        return "Firewall"
    if oid.startswith("1.3.6.1.4.1.12356."):
        return "Firewall"
    if oid.startswith("1.3.6.1.4.1.318."):
        return "Power"
    return "Network"
