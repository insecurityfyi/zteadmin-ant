# Dashboard and alert rules

## Dashboard

The Overview page is a grid of widgets. Each person arranges their own, and read-only users can too.

1. Click **Customise** at the top right.
2. **Add a widget…** puts a new widget at the end of the grid.
3. Move a widget by dragging its ⠿ handle, or with the ← → buttons.
4. The width menu sets ¼, ⅓, ½, ⅔ or full width.
5. **Settings** picks what a widget shows, for example the port for a traffic graph, the device for a device graph, or the metric for "Top devices". **✕** removes the widget.
6. Every change saves as you make it. Click **Done** when you're finished.

**Reset** goes back to the default layout. Admins also get **Make default for everyone**: everyone who hasn't customised their own dashboard then sees that layout. Without one, Linkwatch uses its built-in layout. The Navy console theme has a built-in layout of its own, described below.

The **Last 24 hours** menu next to Customise changes the time range of every graph on the page.

### Navy console theme and the sidebar menu

**Administration > Appearance** sets the site theme and menu style. Each person can override both under **Your account**.

- **Navy console** is a dark navy theme with the Inter typeface and raised cards.
- **Menu** is either:
  - **Top menu**;
  - **Left sidebar**, with icons, the sections as an accordion, and Pollers and Administration at the bottom;
  - **Each theme's own**, the default: the sidebar for Navy console and the top menu for the other themes.
- On screens narrower than 900 px, the sidebar becomes the top menu.

With Navy console, anyone who hasn't customised their dashboard, and whose admin hasn't set a site-wide default, starts from:
- status cards;
- a tall network traffic graph;
- overall health;
- the highest CPU;
- the device table.

These widgets can be added to any theme's dashboard:

| Widget | Shows |
|---|---|
| Status cards | Total devices (and how many were added in the last 7 days), online with the percentage, offline devices and critical alerts, average latency of reachable devices, and bandwidth now. The latency and bandwidth cards have trend lines. |
| Network traffic | Inbound and outbound traffic summed over every monitored port. A link between two monitored devices counts on both ends. Settings can limit it to routers and firewalls, and make it tall (two rows high). |
| Overall health | A 0–100 score: the share of devices up (a device needing attention counts half), less 5 for each open critical alert and 2 for each warning. 90 and above is Good, 70 and above is Fair, anything lower is Poor. |
| Devices | Every device with a status pill, IP, site, poller (or integration), CPU and memory bars, and last poll. Down devices are listed first. It is searchable and shows one page at a time; Settings sets the rows per page. |

| Widget | Shows | Settings |
| --- | --- | --- |
| Summary | Devices up, open alerts, ports, busiest port, slowest poll cycle | |
| Traffic graph | In and out traffic for one port | Port (blank means whichever port is busiest) |
| Open alerts | Open and acknowledged alerts, worst first | All or critical only, rows |
| Devices by site | A coloured tile per device, grouped by site | |
| Busiest ports | Highest utilisation at the last poll | Rows |
| Top devices | Devices ranked by CPU, memory, latency or loss | Metric, site, rows |
| Device graph | CPU and memory, latency and loss, or total traffic | Device, graph |
| Devices with problems | Down (and optionally warning) devices, longest first | Down only, rows |
| Event log | The latest events | Kind, rows |
| Integrations | Sync state and object count for each integration | |
| Health sensors | Sensors in alarm, then the highest readings | Sensor type, rows |
| Network map | The LLDP/CDP map | Site, height |
| Note | Your own text. Links are clickable | Text |

## Alert rules

**Alerts > Your rules > New rule** opens the rule builder. Only admins can create or change rules.

A rule reads as a sentence: *when a* **port** *has* **utilisation** **above** **80** % *for* **3** *polls in a row*, raise a **warning**. You can watch any of these:

| Object | Metrics |
| --- | --- |
| Device | Status (up, down, warn, unknown), CPU %, memory %, latency ms, packet loss %, uptime in minutes, ports down |
| Port | Utilisation %, inbound Mb/s, outbound Mb/s, errors per poll, link state, admin state |
| Health sensor | Reading (in the sensor's unit), status (ok, warn, crit) |

**Applies to** narrows the rule by device type, site, data source (SNMP, ping or an integration), and name patterns for the device, port or sensor. A pattern list is comma-separated. Patterns use `*` and `?`, for example `core-*` or `Te1/1/*`, and plain text matches anywhere in the name. Leave a field empty to include everything.

The **Right now** panel shows which objects would alert with the current data, ignoring the poll count, so you can tune a rule before saving it.

### How custom rules behave

- They're checked on every poll or integration sync, just like the built-in rules.
- They use the same notifications, the same event log and the same acknowledge button.
- An alert opens once the condition has held for the set number of polls in a row, and clears on its own when it stops holding.
- Metrics such as CPU or port traffic aren't checked while a device is down, so one outage doesn't open a pile of alerts. Device status, latency and loss are still checked.
- Editing a rule resets its poll count. Alerts that no longer match clear on the next poll.
- Deleting a rule clears its open alerts.

### Examples

| Rule | Settings |
| --- | --- |
| Uplinks running hot | Port, utilisation, above 70, 3 polls; port name `uplink, Te*` |
| Something rebooted | Device, uptime, below 10, 1 poll; type Firewall |
| Hot inlet air | Health sensor, reading, at or above 35, 2 polls; sensor type temperature, sensor name `inlet` |
| Core switch losing links | Device, ports down, above 2, 1 poll; device name `core-*` |
| A branch firewall is down | Device, status, is, down, 1 poll, critical; device name `*-fw*` |

The built-in rules are still listed under **Built-in rules**, where you can change their thresholds, poll counts and severities, or turn them off.
