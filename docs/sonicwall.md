# SonicWall (SonicOS 6.5.4 and 7.x)

Linkwatch reads SonicWall firewalls in two ways. Use both, on the same IP address, and they show as one device:

| Source | What it gives |
| --- | --- |
| **SonicOS API** (this integration, called by your poller) | Model, serial, firmware and uptime; interfaces with zone and addressing; connected SSL VPN users; licence and security-service status, with expired services flagged; HA state and IPsec tunnels on firmware that offers them |
| **SNMP** (add the firewall as a device) | CPU, memory, current and maximum connections (SonicWall MIB), and traffic, errors and utilisation for every interface, with graphs |

The SonicOS API has very little live telemetry, which is why SNMP is worth adding too.

## 1. Allow the API on the firewall

SonicOS 7: **Device > Settings > Administration > SonicOS API**. SonicOS 6.5: **Manage > System Setup > Appliance > Base Settings > SonicOS API**.

1. Tick **Enable SonicOS API**.
2. Tick **RFC-2617 HTTP Basic Access authentication**. Linkwatch signs in with HTTP Basic over HTTPS only.
3. Leave the other methods as they are. Session security can stay on.
4. Click **Accept**.

Also check that **HTTPS management** is allowed on the interface the poller reaches (Network > Interfaces > the interface > Management: HTTPS). If the management port isn't 443, put it in the address field, for example `10.0.0.1:8443`.

## 2. Create an admin for Linkwatch

Use a dedicated account. **Don't reuse your own**: SonicOS allows one configuring admin at a time, and an API sign-in can end a web session for the same account.

1. **Device > Users > Local Users & Groups > Add User**. Name it, for example `linkwatch`, and give it a long random password.
2. Under **Groups**, add it to an administrators group. The reporting endpoints (SSL VPN sessions, licences) need admin rights; a limited or read-only admin is refused on most builds.
3. On the group, turn on **"Members go straight to the management UI on web login"**. Without it the API refuses the sign-in.
4. Don't turn on two-factor authentication for this account.

Linkwatch only reads. Each sync signs in, makes a few GET requests and signs out straight away (`DELETE /api/sonicos/auth`), so the admin session is freed within a second or two. It never takes over another admin's session.

## 3. Add the integration

1. In Linkwatch: **Integrations > Connect an integration > SonicWall**.
2. Fill in:
   - **Firewall address:** for example `10.0.0.1` or `fw.example.lan:8443`.
   - **Admin username and password:** the account from step 2.
   - **Poller:** the poller on the network that can reach the firewall.
   - **Verify TLS:** untick this if the firewall uses its default self-signed certificate.
3. Click **Test**, then **Save**. The page appears under the **Integrations** menu.

## 4. Add SNMP for CPU, memory and traffic

1. On the firewall: **Device > Settings > Administration > SNMP**. Enable SNMP and set a v3 user, or a v2c community limited to the poller's IP.
2. Allow **SNMP** in the management options of the interface the poller reaches.
3. In Linkwatch, add the SNMP credentials under **Settings**, then add the firewall under **Devices > Add device** with the same IP. You can also let **Discovery** find it.

On the next sync the SonicWall integration attaches its data to that device. It matches on serial number, then IP address, then name.

## Troubleshooting

| You see | Do this |
| --- | --- |
| "The firewall refused the sign-in (HTTP 401)" | Check the password, that HTTP Basic is ticked in the SonicOS API settings, and that the group has "go straight to the management UI" set |
| HTTP 403 on sign-in | The API is turned off, or HTTPS management isn't allowed on that interface |
| "No free API sessions (HTTP 503)" | Too many admin sessions are open. Sign out of idle web sessions |
| Licences panel says the firewall returned an empty list | A known issue on some early SonicOS 7.0 builds. It's fixed in later 7.1 and 7.2 builds |
| "Not offered by this firmware: High availability, IPsec tunnels" | Those reporting endpoints don't exist on your build. The rest still works |

## What it calls

| Path | Used for |
| --- | --- |
| `POST /api/sonicos/auth`, `DELETE /api/sonicos/auth` | Sign in (HTTP Basic) and sign out |
| `GET /api/sonicos/interfaces/ipv4` | Interfaces, zones and addressing |
| `GET /api/sonicos/reporting/ssl-vpn/sessions` | Connected SSL VPN users |
| `GET /api/sonicos/reporting/license/security-services` | Licences and security services |
| `GET /api/sonicos/version` | Model, serial, firmware and uptime, where offered |
| `GET /api/sonicos/reporting/high-availability/status`, `GET /api/sonicos/reporting/vpn/ipsec/tunnels` | HA and IPsec tunnels, where the firmware offers them. Skipped quietly when missing |

SNMP OIDs (SONICWALL-FIREWALL-IP-STATISTICS-MIB): `1.3.6.1.4.1.8741.1.3.1.1` (maximum connections), `.2` (current connections), `.3` (CPU %) and `.4` (RAM %).
