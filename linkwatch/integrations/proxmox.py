"""Proxmox VE API (on-prem, called by a poller).

Pair it with SNMP on the same host for hardware sensors and interface
counters: when a Proxmox node's IP matches a device already polled over SNMP,
the API data is attached to that device instead of creating a duplicate.

Besides the inventory that ``collect`` returns every cycle, this module answers
on-demand requests from the server, relayed by the poller (see
``linkwatch.common.protocol``, message ``rpc``):

* read-only lookups for the Hypervisors pages (``guest_detail``, ``node_detail``,
  ``task``, ``tasks``), which work with the read-only PVEAuditor role;
* control actions (power, migrate, clone, snapshots, backups, resize, delete,
  node power), which only run when *Allow control actions* is ticked on the
  integration and the token has the matching privileges (see docs/proxmox.md).

Every parameter that ends up in an API path is checked against a strict pattern
first, so nothing the browser sends can reach a different API endpoint.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, pct, verify_field

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,62}$")
SNAP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,39}$")          # Proxmox's own rule for snapshot names
STORAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_.]{1,99}$")
VOLID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_.]*:[A-Za-z0-9_\-./:+]{1,250}$")     # PBS volids contain colons
DNSNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,61}[A-Za-z0-9])?$")
DISK_RE = re.compile(r"^((scsi|virtio|sata|ide)\d{1,2}|rootfs|mp\d{1,3})$")
GROW_RE = re.compile(r"^\+\d{1,6}(\.\d{1,3})?[KMGT]?$")
UPID_RE = re.compile(r"^UPID:([A-Za-z0-9][A-Za-z0-9.\-]{0,62}):[0-9A-Fa-f]{1,16}:[0-9A-Fa-f]{1,16}:[0-9A-Fa-f]{1,16}:[A-Za-z0-9_\-]{1,40}:[^\s/?#]{0,64}:[^\s/?#]{1,140}:$")
GUEST_TYPES = ("qemu", "lxc")
CONFIG_HIDE = {"cipassword", "digest"}


@dataclass(frozen=True)
class Action:
    """One thing an admin can do. ``confirm`` is None (no prompt), "yes" (an "are you sure" dialog) or "typed"
    (the admin types the VMID or node name). ``types`` limits guest actions to VMs or containers."""
    label: str
    scope: str                      # guest | node
    confirm: str | None = None
    types: tuple[str, ...] = GUEST_TYPES
    when: str = "any"               # running | stopped | any: which guests the button is offered for
    help: str = ""


ACTIONS: dict[str, Action] = {
    # guest power
    "start": Action("Start", "guest", when="stopped"),
    "shutdown": Action("Shut down", "guest", "yes", when="running", help="Asks the guest OS to shut down (ACPI for VMs)."),
    "reboot": Action("Reboot", "guest", "yes", when="running", help="Asks the guest OS to reboot."),
    "stop": Action("Stop", "guest", "yes", when="running", help="Pulls the plug: unsaved work in the guest is lost."),
    "reset": Action("Reset", "guest", "yes", types=("qemu",), when="running", help="Hard reset, like the reset button."),
    "suspend": Action("Pause", "guest", "yes", when="running", help="Freezes the guest in memory."),
    "hibernate": Action("Hibernate", "guest", "yes", types=("qemu",), when="running", help="Saves memory to disk and stops the VM."),
    "resume": Action("Resume", "guest", when="any"),
    # guest lifecycle
    "migrate": Action("Migrate", "guest", "yes"),
    "clone": Action("Clone", "guest"),
    "snapshot_create": Action("Take snapshot", "guest"),
    "snapshot_rollback": Action("Roll back to snapshot", "guest", "typed", help="Everything since the snapshot is lost."),
    "snapshot_delete": Action("Delete snapshot", "guest", "yes"),
    "backup": Action("Back up now", "guest"),
    "restore": Action("Restore as a new guest", "guest", help="Restores a backup to a new VMID; the original is untouched."),
    "resize": Action("Change CPU and memory", "guest", "yes", help="Takes effect at the next start unless hotplug is on."),
    "disk_grow": Action("Grow a disk", "guest", "yes", help="Disks can only grow. Extend the partition inside the guest afterwards."),
    "template": Action("Convert to template", "guest", "typed", when="stopped", help="Cannot be undone."),
    "delete": Action("Delete guest", "guest", "typed", when="stopped", help="Destroys the guest and its disks. Cannot be undone."),
    # node
    "node_startall": Action("Start all guests", "node", "yes", help="Starts every guest set to start at boot."),
    "node_stopall": Action("Stop all guests", "node", "typed", help="Shuts down every guest on this node."),
    "node_migrateall": Action("Migrate all guests", "node", "typed", help="Moves every guest off this node, e.g. before maintenance."),
    "node_reboot": Action("Reboot node", "node", "typed", help="Guests without HA go down with the node."),
    "node_shutdown": Action("Shut down node", "node", "typed", help="Someone has to power it back on."),
}
READ_OPS = ("guest_detail", "node_detail", "task", "tasks")


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise IntegrationError(f"{what} must be a number.") from None
    if not lo <= n <= hi:
        raise IntegrationError(f"{what} must be between {lo} and {hi}.")
    return n


def _match(rx: re.Pattern, v: Any, what: str) -> str:
    s = str(v or "").strip()
    if not rx.match(s):
        raise IntegrationError(f"Invalid {what}: {s[:60]!r}")
    return s


def _flag(v: Any) -> int:
    return 1 if str(v).lower() in ("1", "true", "on", "yes") else 0


def upid_node(upid: str) -> str:
    m = UPID_RE.match(upid or "")
    if not m:
        raise IntegrationError("Invalid task ID.")
    return m.group(1)


class Proxmox(Integration):
    kind = "proxmox"
    label = "Proxmox VE"
    runs_on = "poller"
    description = ("Cluster API: nodes, VMs and containers, with start, shutdown, migrate, clone, snapshots and backups "
                   "from the Hypervisors menu. Add the hosts over SNMP too for sensors and ports.")
    fields = [
        Field("host", "Proxmox address", help="Any cluster node, e.g. 10.10.5.11 (port 8006 is assumed)."),
        Field("token_id", "API token ID", help="Format user@realm!tokenname, e.g. linkwatch@pve!monitor"),
        Field("token_secret", "API token secret", "password",
              help="PVEAuditor on / is enough to monitor. For control actions see docs/proxmox.md for the role to grant."),
        Field("include_guests", "Also list VMs and containers", "bool", required=False, default=True),
        Field("allow_control", "Allow control actions", "bool", required=False, default=False,
              help="Lets admins start, stop, migrate, clone, snapshot, back up and delete guests and reboot nodes. "
                   "Every action is confirmed and written to the audit log."),
        verify_field(),
    ]

    # ------------------------------------------------------------------ HTTP
    @property
    def base(self) -> str:
        return host_url(self.config["host"], 8006)

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"PVEAPIToken={self.config['token_id']}={self.config['token_secret']}"}

    def _call(self, method: str, path: str, data: dict | None = None, params: dict | None = None) -> Any:
        """One API call. Proxmox puts its error text in the HTTP reason phrase, so pass that on to the admin."""
        url = f"{self.base}/api2/json{path}"
        try:
            resp = self.http.request(method, url, headers=self.auth, data=data, params=params)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from None
        if resp.status_code >= 400:
            reason = (resp.reason_phrase or "").strip()
            try:
                body = resp.json() or {}
                errors = body.get("errors") or {}
                if isinstance(errors, dict) and errors:
                    reason = "; ".join(f"{k}: {str(v).strip()}" for k, v in errors.items())
                elif body.get("message"):
                    reason = str(body["message"]).strip()
            except ValueError:
                pass
            if resp.status_code == 401:
                raise IntegrationError("Proxmox rejected the API token (HTTP 401). Check the token ID and secret.")
            if resp.status_code == 403:
                raise IntegrationError(f"The API token lacks a privilege for this ({reason or 'HTTP 403'}). "
                                       "See docs/proxmox.md for the role to grant.")
            raise IntegrationError(f"{method} {path} failed: {reason or 'HTTP ' + str(resp.status_code)}")
        try:
            return resp.json().get("data")
        except ValueError:
            return None

    def get(self, path: str, **params) -> Any:
        return self._call("GET", path, params=params or None)

    # ------------------------------------------------------------------ inventory
    def collect(self) -> list[Record]:
        base = self.base
        auth = self.auth
        resources = self._get(f"{base}/api2/json/cluster/resources", headers=auth).json().get("data", [])
        node_ips: dict[str, str] = {}
        try:
            for n in self._get(f"{base}/api2/json/cluster/status", headers=auth).json().get("data", []):
                if n.get("type") == "node" and n.get("ip"):
                    node_ips[n["name"]] = n["ip"]
        except Exception:  # standalone nodes still answer; tolerate odd setups
            pass
        include_guests = bool(self.config.get("include_guests", True))
        all_guests = [r for r in resources if r.get("type") in GUEST_TYPES]
        guests = [r for r in all_guests if not r.get("template")]
        self.data = {"type": "proxmox", "unavailable": [], "control": bool(self.config.get("allow_control")),
                     "nodes": [{"name": r.get("node"), "status": r.get("status"), "cpu": round(100.0 * float(r.get("cpu") or 0), 1),
                                "maxcpu": r.get("maxcpu"), "mem": r.get("mem"), "maxmem": r.get("maxmem"), "uptime_s": r.get("uptime"),
                                "ip": node_ips.get(r.get("node")),
                                "guests": sum(1 for g in guests if g.get("node") == r.get("node")),
                                "running": sum(1 for g in guests if g.get("node") == r.get("node") and g.get("status") == "running")}
                               for r in resources if r.get("type") == "node"],
                     "storage": [{"name": r.get("storage"), "node": r.get("node"), "type": r.get("plugintype"),
                                  "status": r.get("status"), "used": r.get("disk"), "size": r.get("maxdisk"),
                                  "shared": bool(r.get("shared"))} for r in resources if r.get("type") == "storage"],
                     "guests": {"total": len(guests), "running": sum(1 for g in guests if g.get("status") == "running"),
                                "vms": sum(1 for g in guests if g.get("type") == "qemu"),
                                "containers": sum(1 for g in guests if g.get("type") == "lxc"),
                                "templates": len(all_guests) - len(guests)},
                     "top_guests": sorted(({"name": g.get("name"), "vmid": g.get("vmid"), "node": g.get("node"), "type": g.get("type"),
                                            "cpu": round(100.0 * float(g.get("cpu") or 0), 1), "mem": g.get("mem"), "maxmem": g.get("maxmem"),
                                            "netin": g.get("netin"), "netout": g.get("netout")}
                                           for g in guests if g.get("status") == "running"), key=lambda g: -g["cpu"])[:25],
                     # every guest, for the Hypervisors pages (live details are fetched on demand)
                     "vms": [self._guest_row(g) for g in sorted(all_guests, key=lambda g: int(g.get("vmid") or 0))][:5000]}
        out: list[Record] = []
        for r in resources:
            t = r.get("type")
            if t == "node":
                ips = self._node_ips(r.get("node")) if r.get("status") == "online" else []
                node_ips.setdefault(r.get("node"), ips[0] if ips else None)
                out.append(Record(
                    external_id=f"node-{r.get('node')}", hostname=r.get("node"), ip=node_ips.get(r.get("node")),
                    type="Hypervisor", platform="Proxmox VE", site=None,
                    status="up" if r.get("status") == "online" else "down",
                    cpu=round(100.0 * float(r.get("cpu") or 0), 1), mem=pct(r.get("mem"), r.get("maxmem")),
                    uptime_s=r.get("uptime"),
                    detail=f"{r.get('maxcpu', '?')} vCPU, {round((r.get('maxmem') or 0) / 2**30)} GiB RAM",
                    extra={"maxcpu": r.get("maxcpu"), "maxmem": r.get("maxmem"), "disk": r.get("disk"), "maxdisk": r.get("maxdisk"),
                           **({"ips": ips} if ips else {})},
                ))
            elif t in GUEST_TYPES and include_guests and not r.get("template"):
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

    def _node_ips(self, node: str | None) -> list[str]:
        """The node's own addresses (bridges, bonds, NICs), so the map can find it in switch tables. Best effort."""
        if not node or not NODE_RE.match(str(node)):
            return []
        try:
            rows = self._get(f"{self.base}/api2/json/nodes/{node}/network", headers=self.auth).json().get("data", [])
        except Exception:  # noqa: BLE001 - a missing permission only costs the map a link
            return []
        ips = [str(n.get("address")).strip() for n in rows if isinstance(n, dict) and n.get("address")]
        return [ip for ip in dict.fromkeys(ips) if ip and not ip.startswith("127.")]

    @staticmethod
    def _guest_row(g: dict) -> dict:
        running = g.get("status") == "running"
        return {"vmid": g.get("vmid"), "name": g.get("name") or f"{g.get('type')} {g.get('vmid')}", "type": g.get("type"),
                "node": g.get("node"), "status": g.get("status"), "template": bool(g.get("template")),
                "cpu": round(100.0 * float(g.get("cpu") or 0), 1) if running else None, "maxcpu": g.get("maxcpu"),
                "mem": g.get("mem") if running else None, "maxmem": g.get("maxmem"), "disk": g.get("disk"), "maxdisk": g.get("maxdisk"),
                "uptime_s": g.get("uptime") or None, "netin": g.get("netin"), "netout": g.get("netout"),
                "tags": [t for t in re.split(r"[;, ]+", str(g.get("tags") or "")) if t][:10],
                "hastate": g.get("hastate"), "lock": g.get("lock"), "pool": g.get("pool")}

    # ------------------------------------------------------------------ on-demand requests
    def action(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one read-only lookup or control action. Raises IntegrationError with a message for the admin."""
        p = dict(params or {})
        if name in READ_OPS:
            return getattr(self, f"op_{name}")(p)
        act = ACTIONS.get(name)
        if act is None:
            raise IntegrationError(f"Unknown Proxmox action {name!r}.")
        if not self.config.get("allow_control"):
            raise IntegrationError("Control actions are turned off for this integration. An admin can tick "
                                   "“Allow control actions” in its settings.")
        node = _match(NODE_RE, p.get("node"), "node name")
        if act.scope == "node":
            return getattr(self, f"op_{name}")(node, p)
        vtype = p.get("type")
        if vtype not in act.types:
            raise IntegrationError(f"{act.label} isn't available for {'containers' if vtype == 'lxc' else 'this guest type'}.")
        vmid = _int(p.get("vmid"), 100, 999_999_999, "VMID")
        gpath = f"/nodes/{node}/{vtype}/{vmid}"
        if name in ("start", "shutdown", "reboot", "stop", "reset", "suspend", "resume", "hibernate"):
            return self._power(gpath, vtype, name)
        return getattr(self, f"op_{name}")(gpath, node, vtype, vmid, p)

    @staticmethod
    def _task(upid: Any, message: str) -> dict[str, Any]:
        return {"upid": upid if isinstance(upid, str) and upid.startswith("UPID:") else None, "message": message}

    def _power(self, gpath: str, vtype: str, name: str) -> dict[str, Any]:
        data: dict[str, Any] = {}
        verb = name
        if name == "hibernate":
            verb, data = "suspend", {"todisk": 1}
        if name == "shutdown" and vtype == "qemu":
            data = {"timeout": 180}
        upid = self._call("POST", f"{gpath}/status/{verb}", data=data or None)
        return self._task(upid, f"{ACTIONS[name].label} requested.")

    def op_migrate(self, gpath, node, vtype, vmid, p):
        target = _match(NODE_RE, p.get("target"), "target node")
        if target == node:
            raise IntegrationError("Pick a different node to migrate to.")
        data: dict[str, Any] = {"target": target}
        if vtype == "qemu":
            if _flag(p.get("online", 1)):
                data["online"] = 1
            if _flag(p.get("with_local_disks")):
                data["with-local-disks"] = 1
        elif _flag(p.get("restart", 1)):
            data["restart"] = 1        # a running container is stopped, moved and started again
        return self._task(self._call("POST", f"{gpath}/migrate", data=data), f"Migration to {target} started.")

    def op_clone(self, gpath, node, vtype, vmid, p):
        newid = _int(p.get("newid"), 100, 999_999_999, "New VMID")
        data: dict[str, Any] = {"newid": newid, "full": _flag(p.get("full", 1))}
        name = str(p.get("name") or "").strip()
        if name:
            data["name" if vtype == "qemu" else "hostname"] = _match(DNSNAME_RE, name, "name")
        if p.get("target"):
            data["target"] = _match(NODE_RE, p.get("target"), "target node")
        if p.get("storage"):
            if not data["full"]:
                raise IntegrationError("A target storage needs a full clone.")
            data["storage"] = _match(STORAGE_RE, p.get("storage"), "storage")
        if p.get("snapname"):
            data["snapname"] = _match(SNAP_RE, p.get("snapname"), "snapshot name")
        return self._task(self._call("POST", f"{gpath}/clone", data=data), f"Cloning to VMID {newid}.")

    def op_snapshot_create(self, gpath, node, vtype, vmid, p):
        snap = _match(SNAP_RE, p.get("snapname"), "snapshot name (letters, digits, - and _, starting with a letter)")
        data: dict[str, Any] = {"snapname": snap}
        if p.get("description"):
            data["description"] = str(p["description"])[:500]
        if vtype == "qemu" and _flag(p.get("vmstate")):
            data["vmstate"] = 1
        return self._task(self._call("POST", f"{gpath}/snapshot", data=data), f"Snapshot {snap} started.")

    def op_snapshot_rollback(self, gpath, node, vtype, vmid, p):
        snap = _match(SNAP_RE, p.get("snapname"), "snapshot name")
        return self._task(self._call("POST", f"{gpath}/snapshot/{snap}/rollback"), f"Rolling back to {snap}.")

    def op_snapshot_delete(self, gpath, node, vtype, vmid, p):
        snap = _match(SNAP_RE, p.get("snapname"), "snapshot name")
        return self._task(self._call("DELETE", f"{gpath}/snapshot/{snap}"), f"Deleting snapshot {snap}.")

    def op_backup(self, gpath, node, vtype, vmid, p):
        storage = _match(STORAGE_RE, p.get("storage"), "backup storage")
        mode = p.get("mode") or "snapshot"
        if mode not in ("snapshot", "suspend", "stop"):
            raise IntegrationError("Backup mode must be snapshot, suspend or stop.")
        compress = p.get("compress") or "zstd"
        if compress not in ("zstd", "lzo", "gzip", "0"):
            raise IntegrationError("Unknown compression.")
        data: dict[str, Any] = {"vmid": vmid, "storage": storage, "mode": mode, "compress": compress}
        if p.get("notes"):
            data["notes-template"] = str(p["notes"])[:200].replace("\n", " ")
        return self._task(self._call("POST", f"/nodes/{node}/vzdump", data=data), f"Backup to {storage} started.")

    def op_restore(self, gpath, node, vtype, vmid, p):
        volid = _match(VOLID_RE, p.get("volid"), "backup")
        newid = _int(p.get("newid"), 100, 999_999_999, "New VMID")
        if newid == vmid:
            raise IntegrationError("Restore into a new VMID; overwriting the existing guest isn't offered here.")
        data: dict[str, Any] = {"vmid": newid}
        if p.get("storage"):
            data["storage"] = _match(STORAGE_RE, p.get("storage"), "storage")
        if vtype == "qemu":
            data.update(archive=volid, unique=1)
        else:
            data.update(ostemplate=volid, restore=1, unique=1)
        return self._task(self._call("POST", f"/nodes/{node}/{vtype}", data=data), f"Restoring to VMID {newid}.")

    def op_resize(self, gpath, node, vtype, vmid, p):
        data: dict[str, Any] = {}
        if str(p.get("cores") or "").strip():
            data["cores"] = _int(p.get("cores"), 1, 512, "Cores")
        if str(p.get("memory") or "").strip():
            data["memory"] = _int(p.get("memory"), 16, 16 * 1024 * 1024, "Memory (MiB)")
        if not data:
            raise IntegrationError("Enter cores, memory or both.")
        self._call("PUT", f"{gpath}/config", data=data)
        parts = [f"{data['cores']} cores" if "cores" in data else "", f"{data['memory']} MiB" if "memory" in data else ""]
        return self._task(None, "Set " + " and ".join(x for x in parts if x) + ".")

    def op_disk_grow(self, gpath, node, vtype, vmid, p):
        disk = _match(DISK_RE, p.get("disk"), "disk")
        size = str(p.get("size") or "").replace(" ", "").upper()
        size = _match(GROW_RE, size if size.startswith("+") else "+" + size, "size (e.g. +10G)")
        upid = self._call("PUT", f"{gpath}/resize", data={"disk": disk, "size": size})
        return self._task(upid, f"Growing {disk} by {size[1:]}.")

    def op_template(self, gpath, node, vtype, vmid, p):
        return self._task(self._call("POST", f"{gpath}/template"), "Converting to a template.")

    def op_delete(self, gpath, node, vtype, vmid, p):
        params = {"purge": 1, "destroy-unreferenced-disks": 1} if _flag(p.get("purge", 1)) else None
        return self._task(self._call("DELETE", gpath, params=params), f"Deleting VMID {vmid}.")

    def op_node_startall(self, node, p):
        return self._task(self._call("POST", f"/nodes/{node}/startall"), f"Starting guests on {node}.")

    def op_node_stopall(self, node, p):
        return self._task(self._call("POST", f"/nodes/{node}/stopall"), f"Stopping guests on {node}.")

    def op_node_migrateall(self, node, p):
        target = _match(NODE_RE, p.get("target"), "target node")
        if target == node:
            raise IntegrationError("Pick a different node to migrate to.")
        data: dict[str, Any] = {"target": target}
        if _flag(p.get("with_local_disks")):
            data["with-local-disks"] = 1
        return self._task(self._call("POST", f"/nodes/{node}/migrateall", data=data), f"Moving guests from {node} to {target}.")

    def op_node_reboot(self, node, p):
        self._call("POST", f"/nodes/{node}/status", data={"command": "reboot"})
        return self._task(None, f"{node} is rebooting.")

    def op_node_shutdown(self, node, p):
        self._call("POST", f"/nodes/{node}/status", data={"command": "shutdown"})
        return self._task(None, f"{node} is shutting down.")

    # read-only lookups ----------------------------------------------------
    def _try(self, unavailable: list[str], what: str, fn, default=None):
        try:
            return fn()
        except IntegrationError as exc:
            unavailable.append(f"{what}: {exc}")
            return default

    def _nodes(self) -> list[dict]:
        return sorted(({"name": n.get("node"), "status": n.get("status")} for n in self.get("/nodes") or []), key=lambda n: n["name"] or "")

    def _storages(self, node: str) -> list[dict]:
        rows = self.get(f"/nodes/{node}/storage", enabled=1) or []
        return sorted(({"name": s.get("storage"), "type": s.get("type"), "content": str(s.get("content") or "").split(","),
                        "used": s.get("used"), "total": s.get("total"), "avail": s.get("avail"), "shared": bool(s.get("shared")),
                        "active": bool(s.get("active", 1))} for s in rows), key=lambda s: s["name"] or "")

    def _recent_tasks(self, vmid: int | None = None, node: str | None = None, limit: int = 15) -> list[dict]:
        rows = self.get("/cluster/tasks") or []
        out = []
        for t in rows:
            if vmid is not None and str(t.get("id") or "") != str(vmid):
                continue
            if node is not None and t.get("node") != node:
                continue
            out.append({"upid": t.get("upid"), "type": t.get("type"), "id": t.get("id"), "node": t.get("node"), "user": t.get("user"),
                        "start": t.get("starttime"), "end": t.get("endtime"), "status": t.get("status") or ("running" if not t.get("endtime") else "")})
        out.sort(key=lambda t: -(t["start"] or 0))
        return out[:limit]

    def op_guest_detail(self, p: dict) -> dict:
        node = _match(NODE_RE, p.get("node"), "node name")
        vtype = p.get("type")
        if vtype not in GUEST_TYPES:
            raise IntegrationError("Unknown guest type.")
        vmid = _int(p.get("vmid"), 100, 999_999_999, "VMID")
        gpath = f"/nodes/{node}/{vtype}/{vmid}"
        unavailable: list[str] = []
        status = self.get(f"{gpath}/status/current") or {}
        config = self._try(unavailable, "Configuration", lambda: self.get(f"{gpath}/config"), {}) or {}
        snaps = self._try(unavailable, "Snapshots", lambda: self.get(f"{gpath}/snapshot"), []) or []
        nodes = self._try(unavailable, "Nodes", self._nodes, []) or []
        storages = self._try(unavailable, "Storage", lambda: self._storages(node), []) or []
        migrate = None
        if vtype == "qemu":
            migrate = self._try(unavailable, "Migration check", lambda: self.get(f"{gpath}/migrate"), None)
        backups: list[dict] = []
        for s in [s for s in storages if "backup" in s["content"] and s["active"]][:6]:
            rows = self._try(unavailable, f"Backups on {s['name']}",
                             lambda s=s: self.get(f"/nodes/{node}/storage/{s['name']}/content", content="backup", vmid=vmid), []) or []
            backups += [{"volid": b.get("volid"), "storage": s["name"], "ctime": b.get("ctime"), "size": b.get("size"),
                         "notes": b.get("notes"), "protected": bool(b.get("protected")), "format": b.get("format")} for b in rows]
        backups.sort(key=lambda b: -(b["ctime"] or 0))
        nextid = self._try(unavailable, "Next free VMID", lambda: self.get("/cluster/nextid"), None)
        tasks = self._try(unavailable, "Recent tasks", lambda: self._recent_tasks(vmid=vmid), []) or []
        disks = {k: v for k, v in config.items() if DISK_RE.match(k) and "media=cdrom" not in str(v)}
        nets = {k: v for k, v in config.items() if re.match(r"^net\d+$", k)}
        return {
            "status": {k: status.get(k) for k in ("status", "qmpstatus", "name", "cpu", "cpus", "mem", "maxmem", "disk", "maxdisk",
                                                   "uptime", "netin", "netout", "diskread", "diskwrite", "lock", "tags", "template",
                                                   "running-machine", "running-qemu", "agent", "ha", "swap", "maxswap")},
            "config": {k: v for k, v in config.items() if k not in CONFIG_HIDE and not k.startswith("unused")},
            "disks": disks, "nets": nets, "serial": any(k.startswith("serial") for k in config),
            "snapshots": sorted(({"name": x.get("name"), "description": x.get("description"), "snaptime": x.get("snaptime"),
                                  "parent": x.get("parent"), "vmstate": bool(x.get("vmstate"))}
                                 for x in snaps if x.get("name") != "current"), key=lambda x: x["snaptime"] or 0),
            "snapshot_parent": next((x.get("parent") for x in snaps if x.get("name") == "current"), None),
            "nodes": nodes, "storages": storages, "backups": backups[:50], "nextid": nextid, "tasks": tasks,
            "migrate": {"allowed": [n if isinstance(n, str) else n.get("node") for n in (migrate.get("allowed_nodes") or [])],
                        "not_allowed": {k: (v.get("unavailable_storages") or v.get("reason") or v) if isinstance(v, dict) else v
                                        for k, v in (migrate.get("not_allowed_nodes") or {}).items()},
                        "local_disks": [d.get("volid") for d in (migrate.get("local_disks") or []) if isinstance(d, dict)]}
            if isinstance(migrate, dict) else None,
            "unavailable": unavailable,
        }

    def op_node_detail(self, p: dict) -> dict:
        node = _match(NODE_RE, p.get("node"), "node name")
        unavailable: list[str] = []
        status = self.get(f"/nodes/{node}/status") or {}
        version = self._try(unavailable, "Version", lambda: self.get(f"/nodes/{node}/version"), {}) or {}
        storages = self._try(unavailable, "Storage", lambda: self._storages(node), []) or []
        nodes = self._try(unavailable, "Nodes", self._nodes, []) or []
        tasks = self._try(unavailable, "Recent tasks", lambda: self._recent_tasks(node=node, limit=25), []) or []
        cpu = status.get("cpuinfo") or {}
        return {"status": {"cpu": status.get("cpu"), "loadavg": status.get("loadavg"), "uptime": status.get("uptime"),
                           "memory": status.get("memory"), "swap": status.get("swap"), "rootfs": status.get("rootfs"),
                           "kversion": status.get("kversion"), "pveversion": status.get("pveversion"),
                           "cpu_model": cpu.get("model"), "cpus": cpu.get("cpus"), "sockets": cpu.get("sockets")},
                "version": version.get("version"), "storages": storages, "nodes": nodes, "tasks": tasks, "unavailable": unavailable}

    def op_task(self, p: dict) -> dict:
        upid = str(p.get("upid") or "")
        node = upid_node(upid)
        q = quote(upid, safe="")
        status = self.get(f"/nodes/{node}/tasks/{q}/status") or {}
        log = self._call("GET", f"/nodes/{node}/tasks/{q}/log", params={"start": 0, "limit": 5000}) or []
        lines = [str(x.get("t", "")) for x in log if isinstance(x, dict)]
        return {"upid": upid, "node": node, "status": status.get("status"), "exitstatus": status.get("exitstatus"),
                "type": status.get("type"), "id": status.get("id"), "user": status.get("user"),
                "start": status.get("starttime"), "log": lines[-60:]}

    def op_tasks(self, p: dict) -> dict:
        return {"tasks": self._recent_tasks(limit=100)}

    # text consoles ----------------------------------------------------------
    def termproxy(self, node: str, vtype: str | None, vmid: Any) -> tuple[str, dict]:
        """Start a text console (LXC console, VM serial port or node shell) and return the websocket path and ticket."""
        node = _match(NODE_RE, node, "node name")
        if vtype:
            if vtype not in GUEST_TYPES:
                raise IntegrationError("Unknown guest type.")
            vmid = _int(vmid, 100, 999_999_999, "VMID")
            path = f"/nodes/{node}/{vtype}/{vmid}"
        else:
            path = f"/nodes/{node}"
        data = {"serial": "serial0"} if vtype == "qemu" else None
        info = self._call("POST", f"{path}/termproxy", data=data) or {}
        if not info.get("ticket") or not info.get("port"):
            raise IntegrationError("Proxmox did not return a console ticket.")
        return f"{path}/vncwebsocket", info
