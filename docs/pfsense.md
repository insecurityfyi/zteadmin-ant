# pfSense (CE and Plus)

pfSense doesn't ship a REST API of its own, so Linkwatch uses the free **pfSense REST API package** (pfrest, API v2, [pfrest.org](https://pfrest.org)). It's a community package, not supported by Netgate. Add SNMP as well, on the same IP address, and the two show as one device.

| Source | What it gives |
| --- | --- |
| **REST API package** (this integration, called by your poller) | Version, platform and serial; CPU, memory, disk, swap, MBUF and temperature; every gateway with delay, jitter and loss (graphed); interface status, addresses and counters; firewall states against the limit; DHCP leases; IPsec SAs, OpenVPN servers with connected users, OpenVPN clients and WireGuard tunnels; services and whether they run; CARP |
| **SNMP** (add the firewall as a device) | Interface traffic graphs from the standard MIBs, Host Resources storage, and the sensors and neighbours pages |

The device turns amber when a gateway is down or an enabled service has stopped.

## 1. Install the package

Package versions follow pfSense versions. At the time of writing the current package supports CE 2.8.1 and later, and Plus 25.11 and later. **Package v2.4.3 is the last one for CE 2.7.2.** It doesn't run on 32-bit hardware such as the SG-3100. Check the [releases page](https://github.com/pfrest/pfSense-pkg-RESTAPI/releases) for the file that matches your version.

From **Diagnostics > Command Prompt**, or over SSH (option 8):

```
# pfSense CE (use the file name for your version)
pkg-static add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg

# pfSense Plus
pkg-static -C /dev/null add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-26.03-pkg-RESTAPI.pkg
```

**After every pfSense upgrade, install the package again.** The upgrade removes it, and the integration then reports "The REST API package doesn't answer at this address".

## 2. Turn on API key authentication

**System > REST API > Settings**: under the authentication methods, add **API Key**. Basic is the only method on by default. Save.

## 3. Create a read-only user and key

API keys carry the privileges of the user that creates them, so use a dedicated user.

1. **System > User Manager > Groups > Add**, for example `linkwatch-ro`. Give it only the REST API privileges for the **GET** method of the endpoints listed at the end of this page. The package adds one privilege per endpoint and method. If that's too fiddly, give it **WebCfg - All pages** together with **User - Config: Deny Config Write**: the API then answers reads and refuses changes.
2. **System > User Manager > Users > Add**: a user such as `linkwatch` in that group, with a long random password.
3. Sign in to the web interface as that user. Open **System > REST API > Keys**, create a key, and copy it. You can't see it again later.

## 4. Add the integration

1. In Linkwatch: **Integrations > Connect an integration > pfSense**.
2. **Firewall address:** for example `10.0.0.1`, or `fw.example.lan:8443` if the web interface isn't on 443. **REST API key:** the key from step 3. **Poller:** one that can reach the firewall's web interface. Untick **Verify TLS** if the firewall uses its default self-signed certificate.
3. Click **Test**, then **Save**. The page appears under the **Integrations** menu.

The web interface must be reachable from the poller. Check the anti-lockout rule, or a pass rule on the interface the poller comes in on.

## 5. Add SNMP

1. On the firewall: **Services > SNMP**. Enable it, set a read community, and bind it to the interface the poller reaches. Keep the MibII, PF and Host Resources modules ticked.
2. Allow UDP 161 from the poller on that interface.
3. In Linkwatch, add the community under **Settings**, then add the firewall under **Devices > Add device** with the same IP address. You can also let **Discovery** find it.

The integration matches the SNMP device by serial number, any of its interface addresses, or its name. The SNMP device keeps its own port graphs.

## Troubleshooting

| You see | Do this |
| --- | --- |
| "The firewall refused the API key (HTTP 401)" | Check the key, and that API Key is ticked under System > REST API > Settings |
| "… was refused (HTTP 403)" on one panel | The key's user lacks the GET privilege for that endpoint. Add it to the group |
| "The REST API package doesn't answer at this address (HTTP 404)" | The package isn't installed, often after a pfSense upgrade. Install it again (step 1) |
| "Not offered by this package version: …" | An older package without that endpoint. The rest still works |
| Gateways show no delay or loss | Gateway monitoring is off for that gateway (System > Routing > Gateways > Disable Gateway Monitoring) |

## What it calls

All requests are `GET` with the `X-API-Key` header. Responses are wrapped as `{"code", "status", "response_id", "message", "data"}`.

| Path | Used for |
| --- | --- |
| `/api/v2/status/system` | Platform, serial, uptime, CPU, memory, disk, swap, MBUF, temperature |
| `/api/v2/system/version`, `/api/v2/system/hostname` | Version, host name |
| `/api/v2/status/interfaces` | Interface status, addresses and counters |
| `/api/v2/status/gateways` | Gateway status, delay, jitter and loss |
| `/api/v2/firewall/states/size` | Current and maximum firewall states |
| `/api/v2/status/dhcp_server/leases` | DHCP leases |
| `/api/v2/status/ipsec/sas` | IPsec SAs and child SAs |
| `/api/v2/status/openvpn/servers`, `/api/v2/status/openvpn/clients` | OpenVPN servers with their connected users, and client instances |
| `/api/v2/status/wireguard/tunnels` | WireGuard tunnels and peers |
| `/api/v2/status/services` | Services and whether they're running |
| `/api/v2/status/carp` | CARP status |
