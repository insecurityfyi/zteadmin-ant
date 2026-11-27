# Cloudflare Zero Trust

Linkwatch reads Cloudflare Zero Trust (Cloudflare One) over the **Cloudflare API v4**
and its GraphQL analytics, with a read-only API token. It shows Cloudflare Tunnels,
Magic WAN tunnels, WARP devices, Gateway and Access policies, app and generative AI
usage, and DLP profiles. See [sse.md](sse.md) for the page layout shared by all SSE
platforms.

> Not yet tested against a real account. Built from Cloudflare's API docs and tested
> against mocked responses.

## 1. Create an API token

1. In the Cloudflare dashboard go to **Manage Account > Account API Tokens** (or
   **My Profile > API Tokens**) and **Create Token > Custom token**.
2. Add these **Account** permissions, all **Read**:

| Permission | Used for |
|---|---|
| Cloudflare Tunnel | Cloudflare Tunnels and private network routes |
| Zero Trust | WARP devices, users, Gateway rules, app types, Access apps |
| Access: Apps and Policies | Access applications |
| Zero Trust: DLP (or DLP) | DLP profiles |
| Account Analytics | Gateway HTTP analytics, Magic WAN health |
| Magic WAN / Magic Transit | Magic WAN tunnels (only if you use it) |

3. Limit it to your account, optionally to the Linkwatch server's IP, and create it.
4. Note the **account ID** (the account's Overview page, or the dashboard URL).

## 2. Add the integration

**Integrations > Add > Cloudflare Zero Trust**:

| Field | Value |
|---|---|
| Account ID | 32-character hex ID |
| API token | from step 1 |
| Areas | **Magic WAN tunnels** is off by default; tick it if you use Magic WAN |

## What each tab uses

| Tab | Call | Notes |
|---|---|---|
| Magic WAN tunnels | `GET /accounts/{id}/magic/ipsec_tunnels`, `/magic/gre_tunnels`; GraphQL `magicTransportTunnelHealthChecksAdaptiveGroups` (last 15 min) | Health-check success rate gives up / degraded / down and a loss figure where the dataset is available. |
| Cloudflare Tunnels | `GET /accounts/{id}/cfd_tunnel?is_deleted=false`, `/teamnet/routes` | Healthy / degraded / down / inactive, connections, colos, cloudflared versions, origin IPs. |
| WARP devices | `GET /accounts/{id}/devices`, `/access/users` | "Seen last hour" counts as connected. Seats from Zero Trust users. |
| Gateway & Access | `GET /accounts/{id}/gateway/rules`, `/access/apps` | DNS, HTTP and network rules by precedence, with their traffic and identity expressions; Access apps with their policies. |
| Apps & AI | GraphQL `gatewayL7RequestsAdaptiveGroups` (7 days), `GET /gateway/app_types` | Request counts per application, allowed vs blocked. AI apps are those in Gateway's "Artificial Intelligence" app type. |
| DLP | `GET /accounts/{id}/dlp/profiles`, Gateway rules using `dlp.profiles` | Profiles with enabled detections, and the rules that apply them. |

The GraphQL dimension names are read from the schema on each refresh, so a renamed
field shows as a note instead of breaking the tab.

## Not available through the API

- **DLP incidents and matched content**, **prompts** sent to AI apps, **per-device posture results** and **distinct users per app**: these are in Gateway logs. Send them to a SIEM with Logpush.
- **Rule hit counts.**
- **Data volumes per app**: Gateway HTTP analytics give request counts, not bytes.

## Least certain

- The Gateway HTTP analytics application dimension (`httpApplicationIds` or similar). Linkwatch looks it up; if none exists it groups by host instead.
- The Magic WAN health-check dataset name and fields.
- Cloudflare is moving WARP devices to a newer devices API; `/devices` is still documented.
