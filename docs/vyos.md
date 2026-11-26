# VyOS (1.3, 1.4 and 1.5)

Linkwatch reads VyOS over its built-in HTTPS API. Add SNMP as well, on the same IP address, and the two show as one device.

| Source | What it gives |
| --- | --- |
| **HTTPS API** (this integration, called by your poller) | Version, hardware and serial; load and memory; interfaces with addresses, state, descriptions and counters; default gateways; IPsec SAs, with configured peers that have no SA shown as down; WireGuard peers and handshakes; OpenVPN users; DHCP leases |
| **SNMP** (add the router as a device) | Interface traffic graphs, storage, and LLDP neighbours on the map |

The device turns amber when an interface whose description mentions WAN, Internet, ISP or uplink loses link.

## 1. Turn on the API

In configuration mode:

```
set service https api keys id linkwatch key '<a long random key>'
set service https api rest                 # VyOS 1.5 and newer: the REST API is off until you add this
set service https listen-address <router address the poller reaches>
commit ; save
```

- **VyOS 1.3 and 1.4:** leave out `set service https api rest`. Those versions have no such option and serve the REST API as soon as a key exists.
- **VyOS 1.5 and newer** (including current rolling releases): the key command is the same, but the REST API stays off until `set service https api rest` is set. Without it, every call returns 404, and Linkwatch says the REST API is turned off.
- **Check:** `curl -k https://<router>/info` needs no key on 1.5 and newer. It returns the version and host name when the HTTPS service is up.
- **Other port:** `set service https port 8443`. Then add `:8443` to the address in Linkwatch.
- **Firewall:** if the router filters traffic to itself, allow TCP 443 (or your port) from the poller.

VyOS has no read-only API keys: every key has full rights. Linkwatch only calls `/retrieve` (to read the configuration), `/show` (to run show commands) and `/info`. Keep the key in Linkwatch only, and limit `listen-address` to the management network.

## 2. Add the integration

1. In Linkwatch: **Integrations > Connect an integration > VyOS**.
2. **Router address:** for example `10.0.0.2`. **API key:** the key from step 1. **Poller:** one that can reach the router. Untick **Verify TLS** for the default self-signed certificate.
3. Click **Test**, then **Save**. The page appears under the **Integrations** menu.

## 3. Add SNMP

```
set service snmp community linkwatch authorization ro
set service snmp community linkwatch client <poller IP>
set service lldp interface all
commit ; save
```

Then add the community under **Settings** in Linkwatch, and the router under **Devices > Add device** with the same IP address. The integration matches it by serial number, any of its addresses, or its host name. The SNMP device keeps its own port graphs.

## Troubleshooting

| You see | Do this |
| --- | --- |
| "The router refused the API key" | Check `show configuration commands \| match "https api"` and the key |
| "VyOS 1.5… is answering, but its REST API is turned off" or "POST /retrieve: Not Found" | Add `set service https api rest`, then commit and save (VyOS 1.5 and newer) |
| "The router's HTTPS API isn't answering (HTTP 404)" | Check that `service https api keys` has a key. On 1.5 and newer, also add `set service https api rest` |
| "Not offered by this VyOS version: …" | That show command doesn't exist on your version, for example `show interfaces counters` on older releases. Traffic then comes from SNMP |
| No CPU figure | Older versions don't print load percentages in `show system uptime`. Add SNMP |

## What it calls

Every call except `/info` is a `POST` with form fields `key` and `data`, the latter a JSON string. Replies are `{"success", "data", "error"}`.

| Call | Used for |
| --- | --- |
| `GET /info` (1.5 and newer, no key) | Version and host name, and telling "REST API off" apart from "no HTTPS service" |
| `/retrieve` `{"op": "showConfig", "path": []}` | Host name, interface descriptions and types, IPsec peers, WireGuard interfaces |
| `/show` `version` | Version, hardware model, serial |
| `/show` `system uptime`, `system memory` | Uptime, load, memory |
| `/show` `interfaces`, `interfaces counters` | Addresses, state and link, descriptions; bytes and errors |
| `/show` `ip route 0.0.0.0/0` | Default gateways |
| `/show` `vpn ipsec sa` | IPsec SAs |
| `/show` `interfaces wireguard <wgN> summary` | WireGuard peers and handshakes |
| `/show` `openvpn server` | Connected OpenVPN users |
| `/show` `dhcp server leases` | DHCP leases |
| `/show` `conntrack statistics` | Connection-tracking counters, where the version prints a total |

The show commands return text. Linkwatch reads the tables by their column headings, so extra columns in newer versions don't break it.
