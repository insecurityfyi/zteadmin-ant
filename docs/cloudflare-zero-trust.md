# Cloudflare Zero Trust

Linkwatch reads Cloudflare Zero Trust (Cloudflare One) over the **Cloudflare API v4**
and its **GraphQL analytics**, with a read-only API token. It has the shared SSE tabs
(see [sse.md](sse.md)) plus five tabs of its own, so the page covers nearly everything
the API can show:

| Tab | What it shows |
|---|---|
| Magic WAN | IPsec and GRE tunnels with health-check state and loss; Magic WAN sites, Connectors (with heartbeat), static routes and Magic Firewall rules |
| Cloudflare Tunnels | Every cloudflared / WARP Connector tunnel: healthy / degraded / down / inactive, connections, data centers, versions, origin IPs; private network routes, virtual networks, hostname routes |
| WARP devices | Every enrolled device: user, OS, WARP version, last seen; Zero Trust seats |
| Gateway & Access rules | Gateway DNS, HTTP and network rules in precedence order with their traffic and identity expressions; Access applications |
| **Gateway** | DNS queries, HTTP requests and network sessions for 24 hours by decision; top blocked domains, hosts, destinations and DNS categories; DNS locations, lists, proxy endpoints and Gateway settings (TLS decryption, AV, isolation, logging, FIPS...) |
| **Access** | Applications, reusable policies, identity providers (and SCIM), groups, team settings; service tokens with expiry; 24 hours of login events with denied users and logins per app |
| **DEX & posture** | DEX fleet status (connected, platform, version, mode, data center), DEX tests with availability and timings, device posture rules and integrations, WARP device profiles |
| Apps & AI | Requests per application over 7 days, allowed vs blocked; AI apps from Gateway's "Artificial Intelligence" app type |
| DLP | DLP profiles with enabled detections, and the Gateway rules that apply them |
| **Zones** | Every zone in the account: status, plan, SSL mode, minimum TLS, Always HTTPS, security level, DNS record count, yesterday's requests, cache and threats, and 24 hours of security (WAF) events by source and action |
| **Audit log** | Account changes for the last 24 hours: who, what, which resource, via UI or API, failures |

Graphs are kept for DNS and HTTP traffic (total and blocked), Access logins (allowed
and denied), DEX fleet (devices and connected), zone traffic (requests, cached,
threats) and audit events, alongside the shared ones (tunnels, devices, AI usage).

Alerts come for free from the objects the integration reports: a tunnel, Magic WAN
tunnel or Connector going down; a zone that's paused, pending or moved; a DEX test
below 95% availability; and **Access service tokens that have expired (down) or expire
within 30 days (warning)**.

> Not yet tested against a real account. Built from Cloudflare's API docs and tested
> against mocked responses. See "Least certain" below.

## 1. Create an API token

In the Cloudflare dashboard go to **Manage Account > Account API Tokens** (or **My
Profile > API Tokens**) and **Create Token > Create Custom Token**. Name it
`linkwatch`. Add these permissions, **all Read**. Leave out anything for an area you
don't use and switch that area off in Linkwatch.

**Account permissions**

| Permission | Used for |
|---|---|
| Cloudflare Tunnel | Tunnels, private network routes, virtual networks, hostname routes |
| Zero Trust | WARP devices, posture rules and integrations, device profiles, DEX, Zero Trust users and organization, Gateway rules, locations, lists, categories, app types, proxy endpoints and settings |
| Access: Apps and Policies | Access applications and reusable policies |
| Access: Organizations, Identity Providers, and Groups | Identity providers, groups, team settings |
| Access: Service Tokens | Service tokens and their expiry |
| Access: Audit Logs | Access login events |
| Account Analytics | Gateway DNS / HTTP / network analytics, Magic WAN tunnel health |
| Zero Trust: DLP (shown as "DLP" on some accounts) | DLP profiles |
| Magic WAN (or Magic Transit) | Magic WAN tunnels, sites, Connectors, static routes |
| Magic Firewall (and Account Rulesets) | Magic Firewall rules |
| Account Settings | The account audit log |

**Zone permissions**, for **All zones from an account** (your account):

| Permission | Used for |
|---|---|
| Zone | Zone list, status and plan |
| DNS | DNS record counts |
| Zone Settings | SSL mode, minimum TLS, Always HTTPS, security level |
| Analytics | Yesterday's requests, cache and threats, and security events |

Restrict the token to your account and, optionally, to the Linkwatch server's public
IP. Create it and copy it (it's shown once). Note your **account ID** from the
account's Overview page or the dashboard URL.

## 2. Add the integration

**Integrations > Add > Cloudflare Zero Trust**:

| Field | Value |
|---|---|
| Account ID | 32-character hex ID |
| API token | from step 1 |
| Areas | all on except **Magic WAN**, which is off by default; tick it if you use Magic WAN |
| App category for generative AI | leave blank unless you want a different category than Gateway's "Artificial Intelligence" |

Press **Test**, then **Sync now**. If a permission is missing, only that tab shows an
error (with the call that was refused), and the integration shows as "partly working".

## Refresh

Every sync (5 minutes by default): tunnels, devices, rules, Access, DEX and the audit
log. Gateway analytics at most every 15 minutes; apps, DLP and zones at most hourly,
to stay well inside Cloudflare's API limits (1,200 requests per 5 minutes per user).
A large account costs roughly 40 calls per sync plus 2 per zone (first 50 zones) each
hour.

## What each tab calls

All paths are under `https://api.cloudflare.com/client/v4`.

| Tab | Calls |
|---|---|
| Magic WAN | `/accounts/{id}/magic/ipsec_tunnels`, `/magic/gre_tunnels`, `/magic/sites`, `/magic/connectors`, `/magic/routes`, `/rulesets/phases/magic_transit/entrypoint`; GraphQL `magicTransportTunnelHealthChecksAdaptiveGroups` |
| Cloudflare Tunnels | `/accounts/{id}/cfd_tunnel?is_deleted=false`, `/teamnet/routes`, `/teamnet/virtual_networks`, `/zerotrust/routes/hostname` |
| WARP devices | `/accounts/{id}/devices`, `/access/users` |
| Gateway & Access rules | `/accounts/{id}/gateway/rules`, `/access/apps` |
| Gateway | GraphQL `gatewayResolverQueriesAdaptiveGroups`, `gatewayL7RequestsAdaptiveGroups`, `gatewayL4SessionsAdaptiveGroups`; `/gateway/locations`, `/gateway/lists`, `/gateway/proxy_endpoints`, `/gateway/configuration`, `/gateway/categories` |
| Access | `/access/apps`, `/access/policies`, `/access/identity_providers`, `/access/groups`, `/access/service_tokens`, `/access/organizations`, `/access/logs/access_requests` |
| DEX & posture | `/dex/fleet-status/live`, `/dex/tests/overview` (or `/dex/tests`), `/devices/posture`, `/devices/posture/integration`, `/devices/policies`, `/devices/policy` |
| Apps & AI | GraphQL `gatewayL7RequestsAdaptiveGroups` (7 days) by application, `/gateway/app_types` |
| DLP | `/accounts/{id}/dlp/profiles`, Gateway rules using `dlp.profiles` |
| Zones | `/zones?account.id=`, `/zones/{zone}/dns_records` (count), `/zones/{zone}/settings`; GraphQL `httpRequests1dGroups`, `firewallEventsAdaptiveGroups` |
| Audit log | `/accounts/{id}/audit_logs` (last 24 hours, up to 300 entries) |

GraphQL dimension names are read from the schema (`__type`) on each refresh, so a
renamed field shows as a note instead of breaking the tab.

## Not available through the API

Listed on each tab, too:

- **Individual log lines** (each DNS query, HTTP request or network session with user, device and matched rule), **DLP incidents and matched content**, **prompts sent to AI apps**, **per-device posture results** and **distinct users per app**: these are in Gateway and device logs. Send them to a SIEM or R2 with Logpush, or search them in Log Explorer.
- **Rule hit counts**: analytics count by decision or action, not by rule.
- **CASB findings**: Cloudflare's API-driven CASB findings aren't in the public API yet; see Zero Trust > CASB.
- **Email security (Area 1)** detections: a separate product and API, not included.
- **DEX history per device and remote captures**: per test and per device in the dashboard.
- **More than 1,000 Access logins a day** and **audit entries older than 24 hours**: the tabs read recent activity only and say when they're capped.

## Least certain

- DNS `resolverDecision` codes. Linkwatch maps the codes from the DNS log reference to names, and anything whose name contains "blocked" counts as blocked. If your account returns names instead of codes, they're used as is.
- The HTTP analytics application dimension (`httpApplicationIds` or similar) and the network analytics action dimension. Linkwatch looks them up and notes when they're missing.
- The DEX overview response shape (availability and timing fields are found by name), and the hostname-routes path.
- Exact permission names in the token editor differ slightly between accounts and change as Cloudflare renames products.
- Cloudflare is moving WARP devices to a newer devices API; `/devices` is still documented.
