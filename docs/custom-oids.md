# Standard counters, custom OIDs and MIBs

Pollers only ever use numeric OIDs; they never load MIB files. What they read is decided on the server and pushed to
them over their existing connection, so adding a metric needs no code change and no poller redeploy.

## What every SNMP device is already asked for

| Area | OIDs | Where it shows |
| --- | --- | --- |
| System | sysDescr, sysObjectID, sysName, sysLocation, sysUpTime (`1.3.6.1.2.1.1.x.0`) | Device overview |
| CPU | hrProcessorLoad `1.3.6.1.2.1.25.3.3.1.2`, UCD ssCpuIdle `1.3.6.1.4.1.2021.11.11.0`, Cisco cpmCPUTotal5minRev `1.3.6.1.4.1.9.9.109.1.1.1.1.8`, SonicWall | CPU graph, Health > Processors |
| Memory | UCD memTotalReal/memAvailReal/buffers/cached `1.3.6.1.4.1.2021.4.x.0`, hrStorage RAM, Cisco memory pools | Memory graph |
| Interfaces | ifHCInOctets/ifHCOutOctets (64-bit, 32-bit fallback), ifInErrors/ifOutErrors, **ifInDiscards/ifOutDiscards** `1.3.6.1.2.1.2.2.1.13`/`.19`, ifOperStatus, ifAdminStatus, ifHighSpeed, ifName, ifAlias | Ports, port page (traffic, utilisation, errors, discards) |
| Load and processes | UCD laLoadInt 1/5/15 min `1.3.6.1.4.1.2021.10.1.5.1-3`, hrSystemProcesses `1.3.6.1.2.1.25.1.6.0`, swap used from memTotalSwap/memAvailSwap | Health tab > Load and TCP/IP |
| TCP | tcpCurrEstab `1.3.6.1.2.1.6.9.0`; per second: tcpActiveOpens `.6.5`, tcpPassiveOpens `.6.6`, tcpAttemptFails `.6.7`, tcpEstabResets `.6.8`, tcpOutSegs `.6.11`, tcpRetransSegs `.6.12` | Health tab > Load and TCP/IP |
| IP and UDP | per second: ipInReceives `1.3.6.1.2.1.4.3.0`, ipInHdrErrors `.4.4`, ipForwDatagrams `.4.6`, ipInDiscards `.4.8`, ipOutDiscards `.4.11`, udpNoPorts `1.3.6.1.2.1.7.2.0`, udpInErrors `.7.3` | Health tab > Load and TCP/IP |
| Disk I/O | UCD diskIOTable `1.3.6.1.4.1.2021.13.15.1.1` (diskIONReadX/diskIONWrittenX, 32-bit fallback), bytes per second per disk; loop and RAM devices and idle disks are skipped | Health tab > Disk I/O |
| Storage | hrStorageTable `1.3.6.1.2.1.25.2.3.1` (disks and flash) | Health tab > Storage |
| Hardware | ENTITY-MIB, ENTITY-SENSOR-MIB, CISCO-ENVMON-MIB, LM-SENSORS-MIB | Health tab, Inventory tab |
| Neighbours | LLDP-MIB, CISCO-CDP-MIB | Neighbours tab, map |

A device that doesn't implement one of these simply shows nothing for it. Counters are sent raw and turned into a
per-second rate on the server from two polls, so the first poll after adding a device shows no rate yet.

Load, TCP/IP and disk readings are stored as health sensors, so they get history and graphs, appear under
**Health > Load and TCP/IP** and **Health > Disk I/O**, and can drive alert rules ("Health sensor", type
"system" or "disk I/O", sensor name such as `TCP retransmits`). Port discards are a port metric in alert rules.

## Adding a custom OID

**Health > Custom OIDs and MIBs > Add custom OID** (admins).

1. **OID or MIB name.** Type a numeric OID (`1.3.6.1.4.1.12356.101.4.1.8.0`), a name (`ifHCInUcastPkts`,
   `IF-MIB::ifHCInUcastPkts`), or search the MIBs and click a result. Picking from a MIB fills in the read mode, value
   type, unit and state names from the MIB's own definition. A scalar gets `.0` added for you.
2. **Read.** *One value* does an SNMP GET. *Table column* walks the column and makes one reading per row; *Name each
   row from* is another column (for example `ifName` or `dskPath`) used to label the rows.
3. **Value type.**
   * *Gauge*: the value as read, times the multiplier.
   * *Counter*: the change per second between polls, times the multiplier (use 8 to turn bytes into bits).
   * *State*: numbers that mean something (`1=up, 2=down`). With *Healthy values* set, any other value marks the
     reading critical and opens the built-in **Sensor problem** alert.
   * *Text*: shown as text, no graph.
4. **Which devices.** Device type, a vendor (sysObjectID prefix, for example `1.3.6.1.4.1.9` for Cisco) and device
   name or IP patterns. Empty fields mean every SNMP device. The vendor prefix is also checked by the poller against
   each device's live sysObjectID, so a new device is handled from its first poll.
5. **Test** reads the OID from a chosen device now, through its poller, and shows the raw values, before you save.

Pollers get the change within seconds and read it on their next poll. Each value becomes a health sensor of type
"custom OID": it is graphed on the device's **Health** tab (switch to graphs), listed under **Health > Custom OID
values**, available to the dashboard's *Health sensors* widget, and usable in alert rules: **Alerts > rules > New**,
"Health sensor", sensor type "custom OID", sensor name matching the custom OID's name.

Changing a custom OID's OID or read mode clears its old readings; deleting one deletes its history.

Pollers need an image from this release or later to read custom OIDs. Older ones keep polling everything else and
are listed in a warning on the Custom OIDs page.

## MIB files

Upload vendor MIBs under **Custom OIDs and MIBs > MIB files** (several at once if one imports another). They are
compiled on the server with pysmi. The standard MIBs most vendor MIBs import (SNMPv2-SMI/TC/CONF, SNMPv2-MIB,
RFC1155-SMI, RFC-1212, RFC1213-MIB, RFC-1215, IF-MIB, IANAifType-MIB, SNMP-FRAMEWORK-MIB, INET-ADDRESS-MIB,
HCNUM-TC, HOST-RESOURCES-MIB, TCP-MIB, UDP-MIB, UCD-SNMP-MIB, NET-SNMP-MIB/TC) are built in and searchable without
uploading anything. If a MIB imports one that isn't there, it is listed with the missing names; upload those and it
is compiled again automatically.

Each MIB has a page listing its objects with a **Poll this** button. Deleting a MIB does not affect custom OIDs
already added from it, since they store the numeric OID.

## Finding an OID from a shell

From the poller host (Net-SNMP tools):

```sh
snmptranslate -On VENDOR-MIB::objectName       # name to numeric OID (needs the MIB in ~/.snmp/mibs)
snmpwalk -v2c -c COMMUNITY HOST 1.3.6.1.4.1.X  # see what a device answers under a subtree
snmpget  -v3 -l authPriv -u USER -a SHA -A AUTHPASS -x AES -X PRIVPASS HOST OID
```

## Useful OIDs to start from

The **Start from a common OID** list on the page has these ready to add:

| What | OID |
| --- | --- |
| Cisco CPU, 1 min, per CPU | cpmCPUTotal1minRev `1.3.6.1.4.1.9.9.109.1.1.1.1.7` |
| FortiGate sessions / CPU | fgSysSesCount `1.3.6.1.4.1.12356.101.4.1.8.0`, fgSysCpuUsage `.101.4.1.3.0` |
| Palo Alto sessions | panSessionActive `1.3.6.1.4.1.25461.2.1.2.3.3.0`, panSessionUtilization `.2.1.2.3.1.0` |
| Juniper CPU per component | jnxOperatingCPU `1.3.6.1.4.1.2636.3.1.13.1.8` (names from jnxOperatingDescr `.13.1.5`) |
| UPS battery charge | upsEstimatedChargeRemaining `1.3.6.1.2.1.33.1.2.4.0` |
| APC runtime / load | upsAdvBatteryRunTimeRemaining `1.3.6.1.4.1.318.1.1.1.2.2.3.0`, upsAdvOutputLoad `.1.1.1.4.2.3.0` |
| Synology temperature | `1.3.6.1.4.1.6574.1.2.0` |
| Disk use per mount (UCD) | dskPercent `1.3.6.1.4.1.2021.9.1.9` (names from dskPath `.9.1.2`) |
| Packets per interface | ifHCInUcastPkts `1.3.6.1.2.1.31.1.1.1.7` (names from ifName `.31.1.1.1.1`) |
| Your own script's output | nsExtendOutput1Line `1.3.6.1.4.1.8072.1.3.2.3.1.1` (Net-SNMP `extend`) |
