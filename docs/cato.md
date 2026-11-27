# Cato Networks

Linkwatch reads the Cato SASE Cloud over the **GraphQL API** with a view-only API key.
It shows site and socket connectivity with latency, loss and traffic, SDP users,
internet and WAN firewall rules, app and generative AI usage, and DLP / CASB events.
See [sse.md](sse.md) for the page layout shared by all SSE platforms.

> Not yet tested against a real account. Built from Cato's API reference and tested
> against mocked responses.

## 1. Create an API key

1. In the Cato Management Application go to **Resources > API Keys** (Account > API
   Keys on older accounts).
2. **New**, name it `linkwatch`, permission **View**.
3. Optionally restrict it to the Linkwatch server's public IP.
4. Copy the key. Note the **account ID**: the number in the management application's
   URL.

## 2. Add the integration

**Integrations > Add > Cato Networks**:

| Field | Value |
|---|---|
| Account ID | e.g. `12345` |
| API key | the key from step 1 |
| API host | blank for `api.catonetworks.com`; set your regional host if Cato gave you one (e.g. `api.us1.catonetworks.com`) |
| Areas | untick any you don't use |

Press **Test**, then **Sync now**. The endpoint is `https://<host>/api/v1/graphql2` with
the key in the `x-api-key` header.

## What each tab uses

| Tab | Query | Notes |
|---|---|---|
| Sites & sockets | `accountSnapshot.sites`, `accountMetrics` (last hour) | Connected / disconnected per site; each socket interface as a tunnel, with PoP and remote IP. A site whose interfaces are partly down shows degraded. Latency, loss, jitter and average traffic come from `accountMetrics`. |
| SDP users | `accountSnapshot.users` | Connected or not, client version, PoP, remote IP. |
| Policies | `policy.internetFirewall`, `policy.wanFirewall` | Rule order, name, enabled, action. |
| Apps & AI | `appStats` over `last.P7D` | Traffic, upstream, downstream and flows per application and category. Distinct AD users per app and risk / sanctioned state from two more optional queries. |
| DLP | `events` over `last.P7D`, `event_sub_type` in DLP, CASB | Counts by application, rule, severity and action. |

There's no Private access tab: Cato has no separate ZTNA connectors.

## Not available through the API

- **DLP profiles and data types**; the content that matched.
- **Rule hit counts.**
- **Device OS and posture** for SDP users.
- **Prompts** sent to AI apps.

## Least certain

- The `events` aggregation query and its field names (`event_count`, `rule_name`, `severity`) and the `policy` query shape vary by account and API release. Each query has a smaller fallback; a part that still fails is listed under "optional panels not available".
- `appStats` dimension names for risk and sanctioned state.
