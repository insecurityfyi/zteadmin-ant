# Zscaler Endpoint AI Security

VisCon1 can monitor and, if you allow it, control **Zscaler Endpoint AI Security**
(formerly SquareX). It uses the product's public API v1, as described by the tenant's
own OpenAPI document (`/api/v1/openapi.yaml`, version 1.0.0). The integration runs on
the VisCon1 server, so no poller is needed.

## Setting it up

1. In the Endpoint AI console, go to **Administration > API Access** and create an API
   credential. Give it a name, a role and an expiry. Copy the client ID and secret: the
   secret is shown only once.
   - A role with **read** capability is enough to monitor.
   - Control actions need a role with **write** capability (see [Roles](#roles)).
2. Note the **region** shown on the API Access page, such as `use2`, `usw2`, `euc1` or
   `apse1`.
3. In VisCon1, go to **Integrations > Add** and pick **Zscaler Endpoint AI Security**. Fill in:

| Field | What to enter |
|---|---|
| Console domain | `zsai.sqrx.io` or `endpoint-ai.zscaler.com`: the domain in your console's address |
| Region | The region from step 2 |
| API client ID and secret | The credential from step 1 |
| Allow control actions | Leave it off to monitor only. See [Control actions](#control-actions). |

VisCon1 exchanges the credential for a short-lived token at
`https://id.<domain>/v1/auth/token` (OAuth2 client credentials) and calls
`https://<region>.api.<domain>/api/v1/...`. The VisCon1 server needs outbound HTTPS to
both hosts.

## What it shows

The integration page has these tabs. Every panel except the fleet totals is optional: if
the credential's role can't read it, that panel is listed under "not available" and the
rest still loads.

| Tab | What you see | API |
|---|---|---|
| Overview | Devices online, AI events and users in the last 24 hours, high and critical events, AI tools seen, fleet health, operating systems, agent versions | `GET /devices/stats`, `/events/summary`, `/events/severities` |
| Devices | Every enrolled device (up to 5,000): host, status, user, OS, agent version and mode, last seen | `GET /devices?status=active,revoked` |
| AI activity | The latest high and critical events and the latest blocked events in the last 24 hours, with user, device, tool, verdict and the patterns that matched | `GET /events?pattern_severity=high,critical`, `GET /events?verdict=block` |
| AI tools | AI assistants (Claude Code, Cursor, Copilot and others) with their MCP server and skill counts, MCP servers with findings, local AI models, and AI browser extensions with their risk rating, all over 7 days | `GET /ai-assistants`, `/ai-assistants/mcp-servers`, `/ai-models`, `/browser-extensions?ai=true` |
| Policies & enrollment | Policies in priority order, setting profiles, enrollment tokens (preview only, never the secret) and managed users | `GET /policies`, `/setting-profiles`, `/enroll-tokens`, `/managed-users` |
| Audit log | The last 100 entries of the Endpoint AI audit log | `GET /audit-log` |

The integration also adds one object, **Endpoint AI fleet**, to the device list. It
turns to warning when there were high or critical AI events in the last 24 hours, so you
can alert on it like any other device.

The API allows two analytics calls at a time per tenant, so VisCon1 makes them one after
another. When the API answers HTTP 429, VisCon1 waits for the time in `Retry-After` and
tries again, up to four times.

## Control actions

Control is off until an admin ticks **Allow control actions** in the integration's
settings. Then admins (not viewers) get buttons on the Devices and Policies & enrollment
tabs, and editors for policies and setting profiles. The same rails apply as for the
ZIA AI tab, Proxmox and Synology:

- Only admins can run an action. The server checks this on every request.
- The control setting is checked by the web page and again by the integration.
- Every action asks for confirmation. Revoking or deleting a device, revoking an
  enrollment token and deleting a policy also need its name typed. The server checks the
  typed name against the name the API returns.
- Every action, whether it worked or not, is written to the audit log and the event log.
  Policy bodies and enrollment secrets are never logged.
- Policy and setting profile changes send the `If-Match` ETag from when the page loaded.
  If someone changed the object since, Endpoint AI refuses the change (HTTP 412) and
  VisCon1 asks you to reload.
- After a change, VisCon1 collects the integration again so the page is current.

### What you can do

| Action | Where | API call |
|---|---|---|
| Revoke a device (typed name) | Devices tab | `POST /devices/{id}/revoke` |
| Delete a device (typed name) | Devices tab | `DELETE /devices/{id}` |
| Bind or unbind a user | Devices tab | `POST /devices/{id}/users`, `DELETE /devices/{id}/users/{email}` |
| Turn automatic identity on or off | Devices tab | `PUT /devices/{id}/auto-identity` |
| Create an enrollment token | Policies & enrollment | `POST /enroll-tokens`. The secret is shown once on its own page and isn't stored. |
| Extend an enrollment token | Policies & enrollment | `POST /enroll-tokens/{id}/extend` |
| Revoke an enrollment token (typed label) | Policies & enrollment | `POST /enroll-tokens/{id}/revoke` |
| Create a policy | Policy editor | `POST /policies` |
| Edit a policy (JSON) | Policy editor | `PATCH /policies/{id}` with `If-Match` |
| Check a policy's rules without saving | Policy editor, **Validate** | `POST /policies/validate` (read-only) |
| Enable or disable a policy | Policies & enrollment, policy editor | `PATCH /policies/{id}` with `If-Match` |
| Change who a policy applies to | Policy editor | `PUT /policies/{id}/assignments` with `If-Match` |
| Delete a policy (typed name) | Policies & enrollment, policy editor | `DELETE /policies/{id}` with `If-Match` |
| Edit, enable or disable a setting profile | Setting profile editor | `PATCH /setting-profiles/{id}` with `If-Match`. The default profile stays read-only: change it in the console. |
| Turn a managed user's sign-in off or on | Policies & enrollment | `POST /managed-users/{id}/disable`, `/enable` |

The policy editor sends only the fields the API lets you change: `name`, `enabled`,
`priority`, `os_platforms`, `rules` and `change_note` (and `assignments` when creating).
The setting profile editor sends `name`, `enabled`, `priority`, `os_platforms`,
`settings` and `change_note`. Other fields in the JSON are ignored.

Devices pick up policy and setting profile changes on their next configuration check.
A revoked device that runs a managed agent can re-enroll within about an hour unless its
fleet enrollment token is revoked too.

### Roles

Each API operation in the OpenAPI document is marked with the capability it needs
(`x-required-capability`):

- **read**: everything on the tabs, plus opening a policy or setting profile and
  validating a policy.
- **write**: every control action above.

Give the API credential a role with read capability for monitoring. To use control
actions, give it a role with write capability too. If the role is missing a capability,
the action fails with "the credential's role doesn't allow it" and that's written to the
audit log.

## Not yet checked on a live tenant

This integration was built from the tenant's OpenAPI document and tested against mocked
responses. It hasn't yet been run against a live Endpoint AI tenant. In particular:

- the exact role names that carry read and write capability in the console;
- whether every tenant returns an `ETag` on policies and setting profiles (if not,
  changes are sent without `If-Match`);
- how long each list takes on a large fleet (devices are capped at 5,000).

If something doesn't match, the error from the API (with its `request_id`) is shown on
the page and in the audit log.
