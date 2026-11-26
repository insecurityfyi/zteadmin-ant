# zteadmin-ant

Two things live in this repository:

* **Linkwatch** (`linkwatch/`): self-hosted network monitoring with
  outbound-only remote pollers. Runs on the CentOS Stream 9 VPS at
  `utilz.perrego.net` and deploys from GitHub on every push to `main`.
* **Zscaler Toolbox, ZIA module** (`app/`): the earlier ZIA console. Its
  OneAPI work now also powers Linkwatch's Zscaler integration.

## Linkwatch

| Area | What it does |
| --- | --- |
| Dashboard | Devices up and down by site, open alerts, busiest ports, highest CPU, traffic graph |
| Devices | SNMP v2c/v3 and ping: system info, CPU, memory, every interface with traffic, errors and utilization, graphs for 6 h to 1 year. CSV import for bulk adds. |
| Alerts | Device down, platform-reported problems, high CPU and memory, port down, port errors, bandwidth, failing integrations, offline pollers. Email, Teams, Slack or webhook. |
| Pollers | Run on your LAN and only connect out (WebSocket over HTTPS). Results are buffered on disk if the link drops. Enrolled with a one-time token and revocable. |
| Integrations | **Zscaler** over OneAPI (ZIA locations and tunnels, ZPA App Connectors, ZDX app scores, Client Connector fleet, Zero Trust Branch sites), **Cisco Meraki** (cloud); **Palo Alto PAN-OS**, **Fortinet FortiGate**, **UniFi**, **Proxmox VE** (called by a poller, inside your network). A Proxmox node that's also polled over SNMP shows as one device with both data sets. |
| REST API | `/api/v1` with read-only or read-write keys; reference at `/api/docs` |

```
linkwatch/server        FastAPI web app, PostgreSQL (SQLite for local runs), alerting
linkwatch/poller        the LAN poller (pysnmp, ping, local APIs, spool)
linkwatch/integrations  one module per platform, shared by server and poller
deploy/                 Quadlet units, nginx site, deploy.sh, bootstrap-centos9.sh
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
