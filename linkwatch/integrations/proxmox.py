"""Proxmox VE API (on-prem, called by a poller).

Pair it with SNMP on the same host for hardware sensors and interface
counters: when a Proxmox node's IP matches a device already polled over SNMP,
the API data is attached to that device instead of creating a duplicate.
"""
from __future__ import annotations

from .base import Field, Integration, Record, host_url, pct, verify_field


class Proxmox(Integration):
    kind = "proxmox"
    label = "Proxmox VE"
    runs_on = "poller"
    description = "Cluster API: nodes, VMs and containers. Add the hosts over SNMP too for sensors and ports."
    fields = [
        Field("host", "Proxmox address", help="Any cluster node, e.g. 10.10.5.11 (port 8006 is assumed)."),
        Field("token_id", "API token ID", help="Format user@realm!tokenname, e.g. monitor@pve!linkwatch"),
        Field("token_secret", "API token secret", "password", help="Give the token the PVEAuditor role on /."),
        Field("include_guests", "Also list VMs and containers", "bool", required=False, default=True),
        verify_field(),
    ]

    def collect(self) -> list[Record]:
        base = host_url(self.config["host"], 8006)
        auth = {"Authorization": f"PVEAPIToken={self.config['token_id']}={self.config['token_secret']}"}
        resources = self._get(f"{base}/api2/json/cluster/resources", headers=auth).json().get("data", [])
        node_ips: dict[str, str] = {}
        try:
            for n in self._get(f"{base}/api2/json/cluster/status", headers=auth).json().get("data", []):
                if n.get("type") == "node" and n.get("ip"):
                    node_ips[n["name"]] = n["ip"]
        except Exception:  # standalone nodes still answer; tolerate odd setups
            pass
        include_guests = bool(self.config.get("include_guests", True))
        guests = [r for r in resources if r.get("type") in ("qemu", "lxc") and not r.get("template")]
        self.data = {"type": "proxmox", "unavailable": [],
                     "nodes": [{"name": r.get("node"), "status": r.get("status"), "cpu": round(100.0 * float(r.get("cpu") or 0), 1),
                                "maxcpu": r.get("maxcpu"), "mem": r.get("mem"), "maxmem": r.get("maxmem"), "uptime_s": r.get("uptime"),
                                "guests": sum(1 for g in guests if g.get("node") == r.get("node")),
                                "running": sum(1 for g in guests if g.get("node") == r.get("node") and g.get("status") == "running")}
                               for r in resources if r.get("type") == "node"],
                     "storage": [{"name": r.get("storage"), "node": r.get("node"), "type": r.get("plugintype"),
                                  "status": r.get("status"), "used": r.get("disk"), "size": r.get("maxdisk"),
                                  "shared": bool(r.get("shared"))} for r in resources if r.get("type") == "storage"],
                     "guests": {"total": len(guests), "running": sum(1 for g in guests if g.get("status") == "running"),
                                "vms": sum(1 for g in guests if g.get("type") == "qemu"),
                                "containers": sum(1 for g in guests if g.get("type") == "lxc")},
                     "top_guests": sorted(({"name": g.get("name"), "vmid": g.get("vmid"), "node": g.get("node"), "type": g.get("type"),
                                            "cpu": round(100.0 * float(g.get("cpu") or 0), 1), "mem": g.get("mem"), "maxmem": g.get("maxmem"),
                                            "netin": g.get("netin"), "netout": g.get("netout")}
                                           for g in guests if g.get("status") == "running"), key=lambda g: -g["cpu"])[:25]}
        out: list[Record] = []
        for r in resources:
            t = r.get("type")
            if t == "node":
                out.append(Record(
                    external_id=f"node-{r.get('node')}", hostname=r.get("node"), ip=node_ips.get(r.get("node")),
                    type="Hypervisor", platform="Proxmox VE", site=None,
                    status="up" if r.get("status") == "online" else "down",
                    cpu=round(100.0 * float(r.get("cpu") or 0), 1), mem=pct(r.get("mem"), r.get("maxmem")),
                    uptime_s=r.get("uptime"),
                    detail=f"{r.get('maxcpu', '?')} vCPU, {round((r.get('maxmem') or 0) / 2**30)} GiB RAM",
                    extra={"maxcpu": r.get("maxcpu"), "maxmem": r.get("maxmem"), "disk": r.get("disk"), "maxdisk": r.get("maxdisk")},
                ))
            elif t in ("qemu", "lxc") and include_guests and not r.get("template"):
                running = r.get("status") == "running"
                out.append(Record(
                    external_id=f"{t}-{r.get('vmid')}", hostname=r.get("name") or f"{t} {r.get('vmid')}", ip=None,
                    type="VM" if t == "qemu" else "Container", platform=f"Proxmox {'VM' if t == 'qemu' else 'LXC'} {r.get('vmid')}",
                    site=None, status="up" if running else "off",
                    cpu=round(100.0 * float(r.get("cpu") or 0), 1) if running else None,
                    mem=pct(r.get("mem"), r.get("maxmem")) if running else None, uptime_s=r.get("uptime") or None,
                    detail=f"On node {r.get('node')}, {r.get('maxcpu', '?')} vCPU", extra={"node": r.get("node"), "vmid": r.get("vmid")},
                ))
        return out
