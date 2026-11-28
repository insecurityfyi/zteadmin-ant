# SSE and SASE platforms

VisCon1 reads four SSE / SASE clouds alongside Zscaler:

| Platform | API | Setup guide |
|---|---|---|
| Netskope One | REST API v2 | [netskope.md](netskope.md) |
| Cato Networks | GraphQL API | [cato.md](cato.md) |
| Palo Alto Networks Prisma Access (Prisma SASE) | SASE APIs (configuration, Insights, ZTNA Connector) | [prisma-access.md](prisma-access.md) |
| Cloudflare Zero Trust (Cloudflare One) | Cloudflare API v4 and GraphQL analytics | [cloudflare-zero-trust.md](cloudflare-zero-trust.md) |

All four use **read-only credentials** and are called from the VisCon1 server, like
Zscaler and Meraki. Nothing is ever written to the platform.

> **Not yet tested against real tenants.** The collectors were built from each vendor's
> published API documentation and tested against mocked responses. Field names that the
> documentation didn't pin down are parsed defensively, and each guide lists what is
> least certain. Expect to adjust a few field names after the first sync against a real
> tenant; the integration page shows exactly which call failed and why.

## One page layout for every platform

Every SSE integration fills the same payload (see `linkwatch/integrations/sse.py`), so its
page has the same tabs, graphs and inventory as the others. Each platform only shows the
tabs its API supports, and can rename them (Netskope's private access tab is "Private
Access", Cloudflare's is "Cloudflare Tunnels").

| Tab | What it shows | Graphs |
|---|---|---|
| Overview | Headline numbers, which areas synced, everything the API can't show | Sites up, connectors healthy, devices |
| Sites & tunnels | Each site or tunnel with state, PoP, tunnels, latency, loss and traffic where the API has them | Sites up of total; latency and loss per site |
| Private access | Connectors (publishers, ZTNA connectors, service connections, cloudflared tunnels) with state and version | Healthy of total |
| Users & devices | Agent fleet: state, versions, OS, device list | Devices and connected |
| Policies | Each rule base in order: action, what it matches, who it applies to | |
| Apps & AI | Generative AI apps (users, events, data, sanctioned, policy) and all apps | AI data and users |
| DLP | Incidents by severity and recent incidents where exposed; profiles and the rules that apply them | Incidents and incidents on AI apps |

A platform can add tabs of its own. Cloudflare adds **Gateway**, **Access**, **DEX &
posture**, **Zones** and **Audit log**, plus Magic WAN and tunnel-route panels on the
shared tabs; see [cloudflare-zero-trust.md](cloudflare-zero-trust.md).

Each tab ends with **"Not available through <vendor>'s API"**, listing what the console
has but the API doesn't, and where to get it instead (usually log streaming to a SIEM).

Apps & AI and DLP are refreshed at most hourly, whatever the sync interval, because they
cover 7 days and some vendors meter their analytics APIs. A failed refresh isn't cached.

Every area can be switched off in the integration's settings. If one area fails (a
missing scope, an unlicensed product), the others still sync; the tab shows a red dot
and the error, and the integration shows as "partly working".

## What each API exposes

| | Zscaler | Netskope | Cato | Prisma Access | Cloudflare |
|---|---|---|---|---|---|
| Site / tunnel live state | No (config only) | Yes, per IPsec / GRE tunnel | Yes, per site and socket interface | Yes, Insights tunnel state | cloudflared: yes. Magic WAN: health checks where licensed |
| Site latency / loss | No | No | Yes (accountMetrics) | No (needs ADEM) | Magic WAN health-check loss |
| Private-access connectors | ZPA App Connectors | NPA publishers | n/a (sockets) | ZTNA connectors, service connections | Cloudflare Tunnels |
| Endpoint fleet | Client Connector | Netskope Client status | SDP users | Connected GlobalProtect users only | WARP devices |
| Security rules | AI & ML app rules | Private Access rules only | Internet and WAN firewall | Security rules, all folders | Gateway DNS / HTTP / network, Access apps |
| App usage | Z-Insights Shadow IT | Application events | appStats | Insights application list | Gateway HTTP analytics (request counts) |
| AI app identification | Category + catalogue | Category (Generative AI) | Category | Category | Gateway app type "Artificial Intelligence" |
| Users per app | Yes | Yes | AD users only | Yes | No (needs Logpush) |
| DLP incidents | No | Yes (DLP alerts) | Yes (DLP / CASB event counts) | No | No (Logpush) |
| DLP profiles / rules | DLP rules | Profiles seen in alerts | No | Data filtering profiles and rules | DLP profiles and rules |
| Prompts sent to AI | No | No | No | No | No |

The AI category can be overridden per integration (**App category for generative AI**)
if a tenant names it differently. With it blank, any category containing AI, ML,
generative or LLM counts, as do well-known AI apps by name.

## Alerts

The objects each integration reports (sites, connectors, the fleet and summary rows) are
ordinary VisCon1 objects, so the built-in rules apply: a site or connector that goes
**down** opens a "Device down" alert, and a **degraded** one (some tunnels down) opens a
"Problem reported" alert. The Generative AI usage row is marked as a problem when an
unsanctioned AI app is in use, and the DLP row when there are high or critical DLP alerts
(Netskope), as with Zscaler. The rule builder can match any of them by type or name, and
the SSE graphs can be added to dashboards like any other integration graph.
