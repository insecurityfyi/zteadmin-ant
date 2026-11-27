# Netskope

Linkwatch reads Netskope One over **REST API v2** with a read-only token. It shows
IPsec and GRE tunnels, NPA publishers, the Netskope Client fleet, Private Access rules,
app and generative AI usage, and DLP alerts. See [sse.md](sse.md) for the page layout
shared by all SSE platforms.

> Not yet tested against a real tenant. Built from Netskope's REST API v2 docs and
> tested against mocked responses.

## 1. Create a REST API v2 token

1. In the Netskope admin console go to **Settings > Tools > REST API v2**.
2. Choose **New Token**, name it `linkwatch`, and set an expiry you'll remember to renew.
3. Add these endpoints with **Read** privilege only:

| Endpoint | Used for |
|---|---|
| `/api/v2/steering/ipsec/tunnels` | Sites & tunnels |
| `/api/v2/steering/gre/tunnels` | Sites & tunnels (only if you use GRE) |
| `/api/v2/infrastructure/publishers` | Private Access |
| `/api/v2/steering/apps/private` | Private app count |
| `/api/v2/events/datasearch/clientstatus` | Netskope Client |
| `/api/v2/policy/npa/rules` | Policies |
| `/api/v2/events/datasearch/application` | Apps & AI |
| `/api/v2/events/datasearch/alert` | DLP |

4. Copy the token. It is shown once.

Leave out endpoints for areas you don't license, and switch those areas off in
Linkwatch so they don't show as failing.

## 2. Add the integration

**Integrations > Add > Netskope**:

| Field | Value |
|---|---|
| Tenant address | `acme` for acme.goskope.com, or the full host (e.g. `acme.eu.goskope.com`) |
| REST API v2 token | the token from step 1 |
| Areas | untick any you don't use |
| App category for generative AI | leave blank unless your tenant's category isn't "Generative AI" |

Press **Test**, then **Sync now**.

## What each tab uses

| Tab | Call | Notes |
|---|---|---|
| Sites & tunnels | `GET /api/v2/steering/ipsec/tunnels`, `/gre/tunnels` | Status per tunnel, PoPs, source identity. One of the two may be missing; the other is enough. |
| Private Access | `GET /api/v2/infrastructure/publishers`, `/steering/apps/private` | Publisher status, version and IP from the publisher's assessment. |
| Netskope Client | `GET /api/v2/events/datasearch/clientstatus` (30 days) | Newest status per device. "Connected" counts devices whose client is enabled. |
| Policies | `GET /api/v2/policy/npa/rules` | Private Access rules only. |
| Apps & AI | `GET /api/v2/events/datasearch/application` with `groupbys=app,appcategory,ccl` and `count()` / `sum()` fields | 7 days. Users per app from a second query grouped by app and user; blocked counts from a third with `action eq 'block'`. |
| DLP | `GET /api/v2/events/datasearch/alert?query=alert_type eq 'DLP'` | 200 newest alerts, plus counts by severity. Profiles are the ones seen in alerts. |

## Not available through the API

- **Real-time Protection policies** (web, CASB, AI app controls). REST API v2 doesn't expose them.
- **DLP profile and rule definitions.** Only alerts and incidents are exposed.
- **Prompts and responses** sent to AI apps, and DLP forensics. Console only.
- **Tunnel throughput and latency.** The steering API gives state, not traffic.

## Least certain

- The datasearch docs show both `groupbys`/`orderbys` and `groupby`/`sortby` spellings. Linkwatch sends `groupbys`/`orderbys`.
- The client status datasearch type (`clientstatus`) and its field names, and the list endpoint for IPsec tunnels, weren't fully confirmed in Netskope's public docs.
- Publisher status: some tenants return `status`, others only `lbrokerconnect`; both are handled.
