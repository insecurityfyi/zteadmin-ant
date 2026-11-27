"""Which remote access a device offers: SSH, remote desktop (RDP) or both.

By default it follows the operating system the device reports (SNMP sysDescr / sysObjectID, the platform an
integration gives, the device type): Windows gets Remote desktop, Linux, Unix and network gear get SSH, and a
device we can't place gets both. An admin can override it per device (Edit > Remote access), for example a
Windows server with OpenSSH, or a Linux box running xrdp."""
from __future__ import annotations

import re
from dataclasses import dataclass

MODES = {
    "auto": "Automatic, from the operating system",
    "ssh": "SSH only",
    "rdp": "Remote desktop only",
    "both": "SSH and remote desktop",
    "none": "Neither",
}
FAMILY_LABELS = {"windows": "Windows", "unix": "Linux / Unix", "network": "network equipment"}

_WINDOWS = re.compile(r"\bwindows\b|microsoft|\bwin(?:2k|xp|7|8|10|11|20\d\d)\b|hyper-v", re.I)
_UNIX = re.compile(r"linux|ubuntu|debian|cent ?os|red ?hat|rhel|rocky|alma|fedora|suse|alpine|freebsd|openbsd|netbsd|"
                   r"darwin|mac ?os|\bunix\b|sunos|solaris|\baix\b|hp-ux|proxmox|esxi|truenas|synology|qnap|"
                   r"raspbian|\blxc\b|container", re.I)
_NETWORK = re.compile(r"cisco|ios[- ]xe|nx-os|junos|juniper|forti(?:gate|os|net)|pan-os|palo alto|routeros|mikrotik|"
                      r"aruba|arista|sonicwall|sonicos|vyos|pfsense|opnsense|edgeos|edgeswitch|ubiquiti|unifi|meraki|"
                      r"procurve|comware|dell networking|extreme|brocade|huawei|zyxel|netgear|tp-link|ruckus|"
                      r"cumulus|checkpoint|check point|gaia|watchguard|sophos", re.I)
_NETWORK_TYPES = {"Switch", "Router", "Firewall", "Wireless", "Network"}


def os_family(d) -> str | None:
    """'windows', 'unix', 'network' or None when nothing says."""
    text = " ".join(str(x) for x in (getattr(d, "sys_descr", None), getattr(d, "platform", None)) if x)
    oid = getattr(d, "sys_object_id", None) or ""
    if oid.startswith("1.3.6.1.4.1.311.") or _WINDOWS.search(text):
        return "windows"
    if _NETWORK.search(text):
        return "network"
    if oid.startswith("1.3.6.1.4.1.8072."):      # net-snmp: Linux and the BSDs
        return "unix"
    if _UNIX.search(text):
        return "unix"
    if getattr(d, "type", None) in _NETWORK_TYPES:
        return "network"
    return None


@dataclass
class Access:
    ssh: bool
    rdp: bool
    mode: str
    family: str | None
    why: str          # shown on the greyed-out button

    @property
    def any(self) -> bool:
        return self.ssh or self.rdp


def access_for(d) -> Access:
    mode = getattr(d, "access", None) or "auto"
    if mode not in MODES:
        mode = "auto"
    fam = os_family(d)
    label = FAMILY_LABELS.get(fam or "", "")
    if mode == "ssh":
        return Access(True, False, mode, fam, "Remote access is set to SSH only for this device (Edit > Remote access).")
    if mode == "rdp":
        return Access(False, True, mode, fam, "Remote access is set to remote desktop only for this device (Edit > Remote access).")
    if mode == "both":
        return Access(True, True, mode, fam, "")
    if mode == "none":
        return Access(False, False, mode, fam, "Remote access is turned off for this device (Edit > Remote access).")
    if fam == "windows":
        return Access(False, True, mode, fam, "This device runs Windows, so it offers remote desktop. "
                                              "To use SSH as well (e.g. OpenSSH Server), change Edit > Remote access.")
    if fam in ("unix", "network"):
        return Access(True, False, mode, fam, f"This device looks like {label}, so it offers SSH. "
                                              "To use remote desktop as well (e.g. xrdp), change Edit > Remote access.")
    return Access(True, True, mode, fam, "")
