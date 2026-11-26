# zteadmin-ant

Two things live in this repository:

* **Linkwatch** (`linkwatch/`): self-hosted network monitoring with
  outbound-only remote pollers. Runs on the CentOS Stream 10 VPS (9 also works) at
  `utilz.perrego.net` and updates from GitHub with `deploy/update.sh` on the VPS.
* **Zscaler Toolbox, ZIA module** (`app/`): the earlier ZIA console. Its
  OneAPI work now also powers Linkwatch's Zscaler integration.

## Linkwatch

| Area | What it does |
| --- | --- |
| Layout | A top menu in the style of classic NMS consoles, or a left sidebar with icons: Overview (dashboard, event log, network map), Devices (by type, discovery), Ports, Health, Alerts, Map and Integrations. Six colour themes (Linkwatch auto light/dark, Midnight NOC, Classic Light, Zscaler Blue, Graphite + Orange, Navy console). The theme and the menu style each have a site default under Administration and a personal choice under Your account. Navy console uses the sidebar and has its own starting dashboard; see [docs/dashboard-and-alert-rules.md](docs/dashboard-and-alert-rules.md). |
| Dashboard | A grid of widgets each user arranges for themselves: summary, traffic graph for any port, open alerts, devices by site, busiest ports, top devices by CPU, memory, latency or loss, a graph for any device, devices with problems, the event log, integrations, health sensors, the network map and free-text notes. Drag to move, pick a width, configure each widget; admins can make their layout the default for everyone. See [docs/dashboard-and-alert-rules.md](docs/dashboard-and-alert-rules.md). |
| Devices | SNMP v2c/v3 and ping: system info, CPU, memory, every interface with traffic, errors and utilization, graphs for 6 h to 1 year. Each device has Overview, Graphs, Ports, Health, Inventory, Neighbours, Events and Alerts tabs. CSV import, and bulk disable, enable or delete (for example all ping-only devices). |
| Ports and health | Every interface across all devices with filters for down, shut down and errors; a page per port with traffic, utilisation and error graphs. Health pages rank devices by CPU, memory, latency and packet loss. |
| Sensors and inventory | Temperatures, fans, power supplies, voltages and state sensors over SNMP (ENTITY-SENSOR-MIB, Cisco environment MIB, LM-SENSORS), disk and flash usage, and the hardware inventory (chassis, modules, serials) from ENTITY-MIB. Each sensor has a graph; Health pages list them network-wide. Alerts for hot or failed sensors and full storage. |
| Neighbours and map | LLDP and CDP neighbours per port, matched to devices Linkwatch already knows, plus UniFi and Meraki uplinks. Wireless access points are always drawn, on the switch port they plug into, with an AP icon, their status and client count; wireless mesh uplinks are dashed. The network map draws them with link colour by utilisation; drag nodes to arrange, and positions are remembered. |
| Path probes | Pollers run MTR-style traces (ICMP, UDP or TCP to a chosen port) to any target on a schedule. Each probe shows a hop-by-hop diagram grouped by network, with loss, latency and jitter at every hop and each hop's AS number and provider, plus latency and loss graphs, a history of route and provider changes, and alerts for loss, latency and network changes. See [docs/path-probes.md](docs/path-probes.md). |
| Event log | Device and port up/down, alerts opening and clearing, poller connections, integration failures and configuration changes, per device and network-wide; kept 180 days. |
| Discovery | Ping sweep plus SNMP probe with your saved credentials, scheduled scans with auto-add, and an option to skip hosts that answer ping but not SNMP. |
| Alerts | Built-in rules for device down, platform-reported problems, high CPU and memory, port down, port errors, bandwidth, hot or failed sensors, full storage, failing integrations and offline pollers, plus a **rule builder** for your own: any device, port or sensor metric, compared with a value for N polls, limited by type, site, data source or name patterns, with a live preview of what it would match. Email, Teams, Slack or webhook. |
| Pollers | Run on your LAN and only connect out (WebSocket over HTTPS). Results are buffered on disk if the link drops. Enrolled with a one-time token and revocable. |
| Integrations | **Zscaler** over OneAPI (ZIA locations and tunnels, ZPA App Connectors, ZDX app scores, Client Connector fleet, Zero Trust Branch sites, generative AI app usage and AI policy; see [docs/zscaler-ai.md](docs/zscaler-ai.md)), **Cisco Meraki** (cloud); **Palo Alto PAN-OS**, **Fortinet FortiGate**, **SonicWall** (SonicOS 6.5/7 API: SSL VPN users, licences and security services, interfaces, HA; CPU, memory and connections over SNMP; see [docs/sonicwall.md](docs/sonicwall.md)), **pfSense** (REST API package: gateways with delay and loss, firewall states, DHCP leases, IPsec, OpenVPN and WireGuard, services, CARP; see [docs/pfsense.md](docs/pfsense.md)), **VyOS** (HTTPS API: interfaces, default gateways, IPsec, WireGuard, OpenVPN, DHCP leases; see [docs/vyos.md](docs/vyos.md)), **UniFi** (devices, ports, every client, per-SSID bandwidth, WAN; see [docs/unifi.md](docs/unifi.md)), **Proxmox VE** (called by a poller, inside your network). A box that's also polled over SNMP (a Proxmox node, a Meraki MX/MS/MR) shows as one device with both data sets, matched on serial number, any of its LAN/WAN addresses or its name. |
| Integration pages | Each integration has its own page under the Integrations menu: sync state and errors, the objects it reports, and the vendor's telemetry with graphs. Zscaler has ZIA, ZPA, ZDX, Client Connector, Zero Trust Branch and AI tabs; Meraki shows networks, uplinks with loss and latency, clients and licensing; PAN-OS and FortiGate show sessions, throughput, tunnels, VPN users, interfaces and licences; Proxmox shows nodes, guests and storage. |
| REST API | `/api/v1` with read-only or read-write keys; reference at `/api/docs` |
| Users and sign-in | Local accounts with admin or read-only roles and an audit log; **Microsoft Entra ID single sign-on** over SAML with roles from Entra app roles or groups (see [docs/entra-sso.md](docs/entra-sso.md)). |

```
linkwatch/server        FastAPI web app, PostgreSQL (SQLite for local runs), alerting
linkwatch/poller        the LAN poller (pysnmp, ping, local APIs, spool)
linkwatch/integrations  one module per platform, shared by server and poller
deploy/                 Quadlet units, nginx site, update.sh (+ auto-update timer), reset-password.sh, deploy.sh, bootstrap-centos9.sh
docs/                   install-centos9.md (VPS walkthrough, firewalld), poller.md
```

**Install on the VPS:** follow [docs/install-centos9.md](docs/install-centos9.md).
**Install a poller:** [docs/poller.md](docs/poller.md).

### Run it locally

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r linkwatch/requirements-dev.txt
export LW_SECRET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export LW_ADMIN_PASSWORD=changeme
uvicorn --factory linkwatch.server.app:create_app --port 8080       # http://localhost:8080
# in another shell, after creating a token on the Pollers page:
LW_SERVER=http://localhost:8080 LW_ENROLL_TOKEN=enr_... LW_DATA_DIR=./data/poller python -m linkwatch.poller
python -m pytest -q tests/linkwatch
```

### Server settings (environment)

| Variable | Default | |
| --- | --- | --- |
| `LW_SECRET_KEY` | (required) | Fernet key; encrypts stored credentials and signs sessions |
| `LW_ADMIN_PASSWORD` | (required to sign in) | Web UI password |
| `LW_DATABASE_URL` | `sqlite:///./data/linkwatch.db` | `postgresql+psycopg://user:pass@host/db` in production |
| `LW_PUBLIC_URL` | `http://localhost:8080` | Used in alert links and the poller install command |
| `LW_POLL_INTERVAL` | `300` | Seconds; can also be changed in Settings |
| `LW_RAW_DAYS` / `LW_HOURLY_DAYS` | `7` / `365` | Retention of 5-minute samples and hourly averages |

---

## Zscaler Toolbox (ZIA module)

A self-hosted console for Zscaler admins. It is being built one module at a
time; this first module covers **ZIA**. ZPA and ZDX come next.

## What the ZIA module does

| Page | What it shows | Where the data comes from |
| --- | --- | --- |
| Overview | Users seen and bandwidth over 7 days, actions per policy type, rules doing the most blocking, locations, configuration health | ZIA API + imported logs |
| Users | Users seen in the last 48 hours or 7 days, with traffic, blocks and isolations | Imported logs, matched to the ZIA user directory |
| Logs to rules | Each log line next to the rule that allowed, blocked, isolated or cautioned it: order, criteria, scope, last change | Imported logs joined to rules from the ZIA API |
| Policies | Every rule across URL filtering, cloud app control, cloud firewall, DNS control, IPS, SSL inspection, file type control, sandbox and DLP, with 7-day hit counts; rules with no hits are flagged | ZIA API + imported logs |
| Log import | Upload CSV exports from the ZIA portal (Web, Firewall or DNS Insights) | Portal exports |
| API setup | OneAPI (ZIdentity) or legacy API key, Z-Insights, retention | |

The module is **read-only**: it never changes ZIA policy.

### Why logs are imported

ZIA only sends per-transaction logs, with the rule that decided each one, through
Cloud NSS. Without NSS, the portal's Insights exports are the only way to get
them, so the toolbox imports those files. The importer also accepts NSS-style
JSON lines (`rulelabel`, `urlfilterrulelabel`, `dnsreqrulelabel`...), so an NSS
feed can be added later without changing the views.

To export: in the ZIA portal, open **Analytics > Web Insights** (or Firewall or
DNS Insights), switch to **Logs**, add the rule name columns (URL filter rule,
cloud app rule, DLP rule, firewall rule or DNS rule), pick the time range and
export to CSV. Times without a zone are read as UTC.

## Run it

```sh
cp .env.example .env        # set TOOLBOX_PASSWORD at least
docker compose up -d --build
open http://localhost:8080
```

It starts with a sample tenant so you can look around. Connect your tenant on
**API setup**, then press **Sync now** (it also syncs every
`TOOLBOX_SYNC_MINUTES`). Importing your first log file or completing a sync
replaces the sample data.

The compose file binds to `127.0.0.1` only. If you expose it, put it behind
TLS and set `TOOLBOX_PASSWORD` (HTTP basic auth, user `admin`).

### Connecting to ZIA

**OneAPI (recommended).** In ZIdentity, create an API client with the ZIA
resource and a read-only admin role. Enter your vanity domain (the `acme` in
`acme.zslogin.net`), client ID and secret. The toolbox requests tokens from
`https://<vanity>.zslogin.net/oauth2/v1/token` and calls
`https://api.zsapi.net/zia/api/v1`.

**Legacy API key.** For tenants not yet on ZIdentity: choose your ZIA cloud
and enter an admin username, password and the API key from
*Administration > API Key Management*.

Secrets are encrypted at rest with Fernet (`TOOLBOX_SECRET_KEY`, or a key
generated into the data volume) and never sent back to the browser.

### Z-Insights (experimental)

With OneAPI, the toolbox can pull the 7-day bandwidth trend from Z-Insights
(GraphQL at `https://api.zsapi.net/zins/graphql`). The built-in query follows
Zscaler's published examples but has **not yet been verified on a live tenant**;
you can override it on API setup. If it fails, the error shows under *Last sync*
and bandwidth falls back to imported logs.

## Develop

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
TOOLBOX_DATA_DIR=./data uvicorn --factory app.main:create_app --reload --port 8080
```

```
app/
  zia/        API auth (OneAPI, legacy), client with paging and 429 backoff,
              policy endpoints and rule normalisation, Z-Insights
  services/   sync, log import, page view models, settings, sample tenant
  templates/  server-rendered pages
tests/        pytest + respx (no network)
```
