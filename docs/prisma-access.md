# Palo Alto Networks Prisma Access

VisCon1 reads Prisma Access (Prisma SASE) over the **SASE APIs** with a read-only
service account. It shows remote network tunnels, ZTNA connectors and service
connections, connected mobile users, security rules, app and generative AI usage, and
DLP profiles. See [sse.md](sse.md) for the page layout shared by all SSE platforms.

> Not yet tested against a real tenant. Built from pan.dev and tested against mocked
> responses.

## 1. Create a service account

1. In Strata Cloud Manager / the hub go to **Common Services > Identity & Access**.
2. Select the tenant (TSG) Prisma Access runs in, then **Add Identity > Service Account**.
3. Copy the **client ID** and **client secret** (shown once).
4. Assign the role **View Only Administrator** (or a custom read-only role) on that TSG,
   with Prisma Access and Insights included.
5. Note the **TSG ID** (Common Services > Tenant Management).

## 2. Add the integration

**Integrations > Add > Prisma Access**:

| Field | Value |
|---|---|
| Tenant service group (TSG) ID | numeric ID |
| Service account client ID | `name@<tsg>.iam.panserviceaccount.com` |
| Service account client secret | from step 1 |
| Insights region | your tenant's region: `americas`, `europe`, `uk`, `de`, `ca`, `au`, `jp`, `sg` or `in` |
| Areas | untick any you don't use |

Tokens come from `https://auth.apps.paloaltonetworks.com/oauth2/access_token`
(client credentials, `scope=tsg_id:<tsg>`) and last 15 minutes; VisCon1 renews them.
API calls go to `https://api.sase.paloaltonetworks.com`.

## What each tab uses

| Tab | Call | Notes |
|---|---|---|
| Remote networks | `GET /sse/config/v1/remote-networks`; Insights `tunnels/tunnel_list` (last hour) | Tunnel state (initializing / up), PoP and average throughput per remote network. A network with one tunnel up and one not shows degraded. |
| ZTNA & service connections | `GET /sse/connector/v2.0/api/connectors`; `GET /sse/config/v1/service-connections` | Service connection state from the same tunnel list. |
| Mobile users | Insights `users/agent/connected_user_list` (last hour) | Connected GlobalProtect users. |
| Policies | `GET /sse/config/v1/security-rules` for Shared, Mobile Users and Remote Networks, pre and post | Action, applications / categories / destinations, users. |
| Apps & AI | Insights `applications/application_list` (7 days) | Bytes, users, risk and sanctioned state where returned. |
| DLP | `GET /sse/config/v1/data-filtering-profiles`, `/profile-groups` | Profiles, and security rules whose profile group includes data filtering. |

Insights calls are sent with `X-PANW-Region` and `Prisma-Tenant`. Each is tried on the
3.0 path (`/insights/v3.0/resource/query/...`) first, then the 2.0 path
(`/api/sase/v2.0/resource/custom/query/...`).

## Not available through the API

- **DLP incidents.** Enterprise DLP incidents are in the DLP service's own API and the SaaS Security console.
- **AI Access Security** verdicts and prompts.
- **Per-tunnel latency and loss** (Autonomous DEM, licensed separately).
- **Rule hit counts.**
- **Disconnected endpoints**: Insights lists connected users only.

## Least certain

- The Insights 3.0 resource paths for the tunnel list and connected users, and their field names. pan.dev documents the 1.0/2.0 tunnel list fields, which are what VisCon1 reads.
- pan.dev disagrees on whether Insights needs `X-PANW-Region`; VisCon1 sends it.
- The ZTNA Connector list path and its fields.
- Newer tenants may serve configuration under `/config/security/v1/` instead of `/sse/config/v1/`; the DLP profiles call tries both.
