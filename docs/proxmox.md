# Proxmox VE (8.x; 7.x should work)

Linkwatch reads a Proxmox VE cluster (or a single node) over its API with an API token, and, if you allow it, lets admins control virtual machines and containers from the **Hypervisors** menu. The calls run on a poller inside your network; nothing connects in to the cluster from the internet.

> **Not yet tested against a real cluster.** The API calls follow the Proxmox VE 8 API reference and are covered by tests against recorded API shapes, but nobody has pressed these buttons on real hardware yet. Try them on a lab VM first. The same is true of the other integrations in Linkwatch. See [What hasn't been tested](#what-hasnt-been-tested).

| Source | What it gives |
| --- | --- |
| **API** (this integration, called by your poller) | Nodes with CPU, memory and uptime; every VM, container and template with state, CPU, memory, disk, tags, HA state and locks; storage pools; live details per guest (hardware, snapshots, backups, recent tasks) |
| **Control actions** (optional, admins only) | Start, shut down, reboot, stop, reset, pause, hibernate, resume; migrate (live for VMs, restart mode for containers); clone (full or linked, to any node or storage, from a snapshot); take, roll back and delete snapshots; back up now and restore a backup as a new guest; change cores and memory; grow a disk; convert to a template; delete; per node: start all, stop all, migrate all, reboot, shut down; text consoles |
| **SNMP** (add the nodes as devices) | Interface traffic graphs, hardware sensors and disks. A node polled over SNMP and seen by the API shows as one device. |

## 1. Create a user and an API token

On any node, as root. Pick the variant you want:

**Monitoring only** (the read-only role that ships with Proxmox):

```sh
pveum user add linkwatch@pve --comment "Linkwatch monitoring"
pveum acl modify / --users linkwatch@pve --roles PVEAuditor
pveum user token add linkwatch@pve monitor --privsep 0
```

**Monitoring and control** (a role with exactly what the Hypervisors actions use):

```sh
pveum role add LinkwatchOperator --privs "Sys.Audit Sys.Console Sys.PowerMgmt Sys.Modify \
  VM.Audit VM.PowerMgmt VM.Console VM.Migrate VM.Clone VM.Allocate VM.Snapshot VM.Snapshot.Rollback VM.Backup \
  VM.Config.CPU VM.Config.Memory VM.Config.Disk VM.Config.Options VM.Config.HWType VM.Config.Network VM.Config.CDROM VM.Config.Cloudinit \
  Datastore.Audit Datastore.AllocateSpace Pool.Audit SDN.Use"
pveum user add linkwatch@pve --comment "Linkwatch"
pveum acl modify / --users linkwatch@pve --roles LinkwatchOperator
pveum user token add linkwatch@pve ops --privsep 0
```

The last command prints the token secret once. Copy it.

- `--privsep 0` makes the token carry the user's permissions. If you prefer privilege-separated tokens (`--privsep 1`), grant the role to the token as well: `pveum acl modify / --tokens 'linkwatch@pve!ops' --roles LinkwatchOperator`.
- On Proxmox VE 7, drop `SDN.Use` from the role (it doesn't exist there).
- You can grant the role on a narrower path, such as a pool (`/pool/lab`), instead of `/`. Guests outside it then don't show up, and node actions need `/nodes/<node>`.
- To use a GUI instead: **Datacenter > Permissions > Users / API Tokens / Roles / Permissions**.

What each action needs, if you want to trim the role:

| Action | Privileges |
| --- | --- |
| See everything | `Sys.Audit`, `VM.Audit`, `Datastore.Audit` (all in PVEAuditor) |
| Start, shut down, reboot, stop, reset, pause, hibernate, resume | `VM.PowerMgmt` |
| Text console | `VM.Console`; node shell: `Sys.Console` |
| Migrate | `VM.Migrate` |
| Clone | `VM.Clone` on the source, `VM.Allocate` and `Datastore.AllocateSpace` for the copy, `SDN.Use` on its bridges (PVE 8) |
| Snapshots | `VM.Snapshot`; roll back: `VM.Snapshot.Rollback` |
| Back up now | `VM.Backup`, `Datastore.AllocateSpace` on the backup storage |
| Restore as a new guest | `VM.Allocate`, `Datastore.AllocateSpace`, `VM.Config.*` |
| CPU and memory | `VM.Config.CPU`, `VM.Config.Memory` |
| Grow a disk | `VM.Config.Disk`, `Datastore.AllocateSpace` |
| Convert to template, delete | `VM.Allocate` |
| Node reboot, shut down | `Sys.PowerMgmt` |
| Node start all, stop all | `VM.PowerMgmt` |
| Node migrate all | `Sys.Modify`, `VM.Migrate` |

When the token lacks a privilege, Linkwatch shows Proxmox's own message, for example *Permission check failed (/vms/101, VM.PowerMgmt)*, and writes the failure to the audit log.

## 2. Add the integration

1. **Integrations > Connect an integration > Proxmox VE**.
2. **Proxmox address:** any node, for example `10.10.5.11` (port 8006 is assumed). **API token ID:** `linkwatch@pve!ops`. **Secret:** from step 1. **Poller:** one that can reach port 8006 on the nodes. Untick **Verify TLS** for Proxmox's default self-signed certificate.
3. Tick **Allow control actions** if you want admins to be able to control guests. Leave it off for monitoring only; the Hypervisors pages then show everything but offer no buttons, and the poller refuses any action even if asked.
4. **Test**, then **Save**. A **Hypervisors** menu appears.

## 3. Using it

**Hypervisors > All virtual machines** lists every guest with filters by cluster, node, type and state, quick Start, Shut down, Reboot and Console buttons, and the nodes at the top. Click a guest for its page:

- **Live state** from Proxmox (fetched through the poller when you open the page), hardware, snapshots, backups and recent tasks.
- **Power** buttons at the top. **Manage** has Back up now, Migrate (only nodes Proxmox says are possible are offered; local disks are flagged), Clone (the next free VMID is filled in), CPU and memory, and Grow a disk. The **Danger zone** has Convert to template and Delete, offered only when the guest is stopped.
- Long jobs (migrate, clone, backup, restore, shutdown) run as Proxmox tasks. After you start one, the page shows the task's live log at the top until it finishes. **Tasks** in the menu lists the cluster's recent tasks; click one for its log.
- The inventory refreshes a few seconds after each action, and on the normal poll interval otherwise.

A node's page has its live CPU, memory, disk and load, the guests on it, storage, and Shell, Start all, Stop all, Migrate all (to evacuate before maintenance), Reboot node and Shut down node.

### Safety rails

- Only **admins** see the buttons and can use them; read-only accounts see the same pages without them.
- **Allow control actions** must be ticked on the integration. The server checks it and so does the poller.
- Disruptive actions ask first. Stop, shut down, reboot, reset, pause, hibernate, migrate, resize and deleting a snapshot need a click in a confirmation dialog. Rolling back a snapshot, converting to a template, deleting a guest and every node action besides Start all need the VMID or node name typed in.
- Every action is in the **audit log** (Administration) with who, from where, what, on which guest and the Proxmox task ID, and in the **event log**. Failures are logged too.
- Restores always go to a **new** VMID. Overwriting an existing guest from a backup isn't offered.
- Values from the browser are checked against strict patterns (node names, VMIDs, snapshot names, storage IDs) before they are put in an API path.

### Consoles

The **Console** button opens a text terminal in a pop-out window. The poller asks Proxmox for a console ticket with the API token, opens Proxmox's console WebSocket and relays it to your browser through its outbound tunnel (the same tunnel SSH consoles use). Sessions are audited and close after 30 idle minutes.

- **Containers** work out of the box.
- **VMs** need a serial port (`qm set <vmid> --serial0 socket`) and a getty on it inside the guest (`systemctl enable --now serial-getty@ttyS0` on most Linux distributions). For anything else, **Console (Proxmox)** opens the graphical noVNC console in the Proxmox web UI; that only works if your browser can reach the cluster (for example on the management VLAN or a VPN), because Linkwatch doesn't relay VNC.
- **Node shell** asks you to sign in to the node, because the token's user isn't root.
- Consoles are refused when the poller host sets `LW_TUNNEL=off`. Pollers older than this release need updating; the page says so and gives the command.

## What hasn't been tested

Everything here was built from the Proxmox API documentation and tested against recorded responses and a fake console server. Not yet verified on real Proxmox:

- every control action end to end, in particular live migration with local disks, linked clones, restores from Proxmox Backup Server, and node migrate all;
- the exact privilege list above (it may be missing one for a corner case such as cloud-init VMs or SDN VNets);
- text consoles with API tokens (Proxmox documents `termproxy` for tickets and tokens, but this path hasn't been exercised), and the node shell sign-in;
- clusters with HA groups, where Proxmox may hand a power action to the HA manager instead of running it directly;
- Proxmox VE 7.

If an action fails, the message on the page and in the audit log is Proxmox's own error text, which is the quickest way to tell a missing privilege from a real problem.
