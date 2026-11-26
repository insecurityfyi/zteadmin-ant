# zteadmin-ant: Zscaler Toolbox

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
