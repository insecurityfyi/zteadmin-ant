# Synology NAS (DSM 7.x; DSM 6.2 mostly works)

Linkwatch reads a Synology NAS over the DSM Web API (the same API DSM's own web interface uses) and, if you allow it, lets admins control it from the **NAS** menu: reboot or shut it down, start and stop packages, containers and virtual machines, run and cancel Hyper Backup tasks and data scrubbing, take and delete snapshots, and run Security Advisor. The calls run on a poller inside your network; nothing connects in to the NAS from the internet.

> **Not yet tested against a real NAS.** The API calls follow DSM 7.2's web interface traffic, Synology's published API guides (authentication, Virtual Machine Manager) and well-used community clients, and are covered by tests against those response shapes. Nobody has pressed these buttons on a real DiskStation yet. Some of the control calls are less certain than others; see [What hasn't been tested](#what-hasnt-been-tested). Try them on a NAS you can afford to reboot first.

| Source | What it gives |
| --- | --- |
| **DSM API** (this integration, called by your poller) | Model, serial, DSM version and update availability; CPU, memory, network and disk throughput; storage pools (RAID type, state, scrubbing), volumes (state, file system, % used, graphs) and every disk (temperature, status, SMART state, SSD life, bad sectors, full SMART attributes on demand); system temperature, fan mode and UPS (state, charge, runtime); network interfaces; shared folders with encryption, quota, recycle bin and snapshots; packages; Container Manager containers (with CPU and memory) and compose projects; Virtual Machine Manager guests; Hyper Backup tasks with last result and next run; connected users; Security Advisor results |
| **Control actions** (optional, admins only) | Reboot and shut down the NAS; start and stop packages; start, stop and restart containers; power on, shut down and force off VMs; back up now and cancel a running backup; run and stop data scrubbing on a pool; take a snapshot of a shared folder (optionally locked) and delete one; run a Security Advisor scan |
| **SNMP** (add the NAS as a device) | Interface traffic graphs, fan and power-supply status, and long-term disk temperature graphs from Synology's MIB. A NAS polled over SNMP and seen by the API shows as one device, matched on its address. |

A NAS with a problem (a volume or pool not healthy, a disk failing or flagged by SMART, a volume 90% full, a temperature warning, the UPS on battery, a failed backup, Security Advisor at risk or danger) shows as **warning** on the device list and the dashboard, with the problem as its detail line, so the usual alert rules apply.

## 1. Create a dedicated DSM account

Don't use your own admin account. A dedicated one can be locked down, audited separately, and disabled without locking you out.

1. **Control Panel > User & Group > User > Create.** Name: `linkwatch`. Description: *Linkwatch monitoring*. A long random password (Linkwatch stores it encrypted).
2. Tick **Disallow the user to change account password**.
3. **Join groups:** `administrators`. This is required: DSM only answers the system, storage, package, container and backup APIs for members of the administrators group, and returns *permission denied* (error 105) otherwise. There is no read-only administrator role in DSM.
4. **Assign shared folders permissions:** tick **No access** for every shared folder. Linkwatch never reads files; this stops the account being used for SMB, AFP, NFS or File Station even though it is an administrator. (Shares created later need the same; DSM's *Deny* always wins.)
5. **Assign application permissions:** **Deny** everything except **DSM**. The API sign-in counts as DSM.
6. Finish, then under **Control Panel > User & Group > Advanced > Password Settings**, if you use password expiry, make sure it can't expire this account's password (or set yourself a reminder: an expired password stops monitoring with *the account's password has expired*).

### 2-step verification (2FA)

The API signs in with a password, so the account needs either no 2FA prompt or a trusted-device token. Pick one:

**A. Exempt the account (simplest).** If you enforce 2FA under **Control Panel > Security > Account > 2-Factor Authentication**, enforce it for *specific users or groups* rather than all administrators, and leave `linkwatch` out. On DSM 7.2 also check **Adaptive Multi-Factor Authentication** on the same page: it asks for a second factor when an administrator signs in from a new place, so either leave it off or rely on option B. Compensate with step 3 below (the account can only sign in from the poller).

**B. Use a device token.** Keep 2FA on and give Linkwatch a token that marks the poller as a trusted device, the same thing DSM's *Remember this device* checkbox does:

1. Sign in to DSM once as `linkwatch` and set up the authenticator app when asked.
2. On the poller host, with a code from the authenticator at hand, run:
   ```sh
   podman exec -it linkwatch-poller python -m linkwatch.integrations.synology pair https://10.10.5.20:5001 linkwatch
   ```
   (`docker exec` if you run Docker; add `--insecure` for DSM's self-signed certificate.) It asks for the password and the 6-digit code and prints a device token.
3. Paste the token into the integration's **2FA device token** field.

If the token stops working (*the 2-step verification code or device token was rejected*), someone removed the trusted device in DSM (**Personal > Security > Sign-in Activity**, or a 2FA reset); run the pairing again.

### 3. Lock the account to the poller

- **Control Panel > Security > Firewall:** allow TCP 5001 (DSM over HTTPS) from the poller's address, if you use DSM's firewall.
- **Control Panel > Security > Protection > Auto Block:** keep it on. To stop a typo in the password locking the poller out, you can add the poller's address to the **Allow List** there; a blocked poller shows *DSM has blocked the poller's IP address (Auto Block)*.
- **Control Panel > Login Portal > Advanced** (DSM 7.2) or your firewall can restrict the administrator sign-in to the management network.

Linkwatch keeps one DSM session per NAS for up to 20 minutes and reuses it for every sync and action, so **Log Center > Connection** shows a `linkwatch` sign-in about three times an hour (and after the poller restarts), named *Linkwatch*, from the poller's address. A sign-in from anywhere else is worth a look.

## 2. Add the integration

1. **Integrations > Connect an integration > Synology NAS**.
2. **NAS address:** for example `10.10.5.20` (HTTPS on port 5001 is assumed; write `10.10.5.20:5443` if you changed it under **Control Panel > Login Portal**). **DSM account** and **Password:** from step 1. **2FA device token:** only for option B. **Poller:** one that can reach the NAS on that port. Untick **Verify TLS** if the NAS uses its default self-signed certificate.
3. Tick **Allow control actions** if you want admins to be able to control the NAS. Leave it off for monitoring only; the NAS pages then show everything with no buttons, and the poller refuses any action even if asked.
4. **Test**, then **Save**. A **NAS** menu appears.

For fan, power-supply and interface graphs, also add the NAS as an SNMP device (**Control Panel > Terminal & SNMP > SNMP** in DSM; SNMPv3 recommended, then **Devices > Add SNMP device** in Linkwatch with the same address).

## 3. Using it

The NAS page has tabs:

- **Overview:** CPU, memory, network, storage and temperature at a glance with graphs, volumes, model and DSM version (with any available update), UPS, Security Advisor state and network interfaces. **Needs attention** at the top lists every problem in plain words. **Reboot NAS** and **Shut down NAS** are at the top right.
- **Storage:** pools with RAID type, state and scrubbing (**Run now** / **Stop**), volumes with usage graphs, and every disk. Click a disk for its live SMART attributes.
- **Shares and snapshots:** shared folders, and for folders on Btrfs their newest snapshots (scheduled and locked ones marked). **Take snapshot** picks a folder, a description and whether to lock it; unlocked snapshots have **Delete**.
- **Packages and containers:** Container Manager containers with CPU and memory (**Start**, **Stop**, **Restart**), compose projects, and every package (**Start** / **Stop** for packages DSM allows to be stopped).
- **Virtual machines** (when Virtual Machine Manager is installed): VMs with state, vCPU and memory (**Power on**, **Shut down**, **Power off**).
- **Backups:** Hyper Backup tasks with destination, last result and next run (**Back up now**, **Cancel backup**).
- **Users and security:** Security Advisor results by category (**Run scan now**), DSM update state, and who is connected over which protocol from where.

Data comes from the last sync (the normal poll interval). After an action, the poller syncs the NAS again a few seconds later, so press reload to see the new state. The disk SMART page is fetched live when you open it.

Linkwatch doesn't install DSM or package updates: those can reboot the NAS and deserve a look at the release notes, so do them in DSM.

### Safety rails

- Only **admins** see the buttons and can use them; read-only accounts see the same pages without them.
- **Allow control actions** must be ticked on the integration. The server checks it, and so does the poller.
- Disruptive actions ask first. Stopping a package, container or VM, restarting a container, cancelling a backup, starting or stopping scrubbing and deleting a snapshot need a click in a confirmation dialog. **Reboot NAS** and **Shut down NAS** need the NAS's DSM server name typed in.
- Every action is in the **audit log** (Administration) with who, from where, what and on which NAS, and in the **event log**. Failures are logged too, with DSM's error.
- Values from the browser (package IDs, container names, VM IDs, task IDs, pool IDs, share names, snapshot names) are checked against strict patterns before they are sent to DSM.

### What each action calls

| Action | DSM API and method |
| --- | --- |
| Reboot, shut down | `SYNO.Core.System` `reboot` / `shutdown` |
| Package start, stop | `SYNO.Core.Package.Control` `start` / `stop` |
| Container start, stop, restart | `SYNO.Docker.Container` `start` / `stop` / `restart` (Container Manager on DSM 7.2; the Docker package on older DSM) |
| VM power on, shut down, power off | `SYNO.Virtualization.API.Guest.Action` `poweron` / `shutdown` / `poweroff` |
| Back up now, cancel | `SYNO.Backup.Task` `backup` / `cancel` |
| Data scrubbing run, stop | `SYNO.Storage.CGI.Pool` `data_scrubbing` / `cancel_data_scrubbing` |
| Snapshot take, delete | `SYNO.Core.Share.Snapshot` `create` / `delete` (Snapshot Replication or DSM 7.2's built-in snapshots) |
| Security Advisor scan | `SYNO.Core.SecurityScan.Operation` `start` |
| SMART attributes (read-only) | `SYNO.Storage.CGI.Smart` `get_smart_info` |

## Troubleshooting

| Message | Meaning |
| --- | --- |
| *DSM rejected the account name or password* | Wrong password, or the account is disabled or expired. |
| *needs a 2-step verification code* / *2-step verification is enforced* | Exempt the account or add a device token (above). |
| *DSM has blocked the poller's IP address* | Auto Block. Remove the address under **Control Panel > Security > Protection > Allow/Block List**. |
| *the DSM account lacks permission* | The account isn't in the `administrators` group. |
| *… isn't on this NAS (package not installed or DSM too old)* | The package behind that panel or action isn't installed (Container Manager, Virtual Machine Manager, Hyper Backup, Snapshot Replication). Panels for missing packages are simply hidden. |
| *The address answered but doesn't look like DSM* | Wrong port, or a reverse proxy in front of DSM. Use the NAS's own address and DSM port. |
| *the request's source IP doesn't match the login IP* | Something between the poller and the NAS (a load balancer or proxy with several exit addresses) changes the source address. Point the integration straight at the NAS. |
| Some parts listed as *not available with this account* | Each line is DSM's error for that panel; the rest of the page still works. |

## What hasn't been tested

Everything here was written from DSM's API traffic and documentation and tested against recorded response shapes, not a real NAS. In rough order of confidence:

- **Most certain:** sign-in (including device tokens), system information, utilisation, storage pools, volumes and disks, shares, packages, Virtual Machine Manager (Synology publishes that API), reboot and shut down.
- **Likely right, unverified:** Container Manager list and start/stop/restart, Hyper Backup task list and *Back up now*, Snapshot list/create/delete, connected users, Security Advisor results, DSM update check, UPS.
- **Least certain:** *Cancel backup*, *Run/Stop data scrubbing*, *Run Security Advisor scan* and the SMART attribute page. These method names come from community clients and DSM's web traffic and may differ between DSM versions. If one fails, the page shows DSM's error code (for example *the method doesn't exist* or *a parameter is invalid*) and nothing else is changed.
- Package start/stop with packages that have dependants (DSM may refuse, or stop the dependants too).
- DSM 6.2 (most read-only panels should work; Container Manager calls need the older Docker package; built-in snapshots need Snapshot Replication).
- High-availability (Synology High Availability) pairs, expansion units and multiple UPS units.

If an action fails, the message on the page and in the audit log includes DSM's error code, which is the quickest way to tell a permission problem from a wrong method name. Please report those so the call can be fixed.
