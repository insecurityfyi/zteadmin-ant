# UniFi Network

Linkwatch reads the UniFi Network application on your console (UDM, UDM Pro/SE,
UCG, Cloud Key Gen2+, UniFi OS Server) or a self-hosted controller. It collects:

- **Access points, switches, gateways:** status, CPU, memory, uptime, firmware,
  every switch/AP port with traffic and errors, PoE draw, AP radios (channel,
  utilisation, clients), WAN1/WAN2 state. A gateway with a WAN down shows as a warning.
- **Clients:** name, IP, MAC, vendor, network/VLAN, SSID and AP (or switch and
  port), band, channel, signal, link rate, current download/upload, session
  totals, connected time and UniFi's experience score. Each client has its own
  bandwidth and signal graphs.
- **Directly attached clients:** the client list opens on **Directly attached**.
  Press **All MACs** to see every client. A client counts as directly attached when:
  - it is a Wi-Fi client associated to a UniFi AP, or
  - it is a wired client that is the only MAC on a UniFi switch port, and that port
    is not an uplink, not a port another UniFi device hangs off, and has no LLDP
    neighbour other than the client itself, or
  - it is a desk phone sharing its port with the PC plugged into it. The phone is
    recognised by speaking LLDP on that port, or by its vendor (Polycom, Yealink,
    Avaya, Mitel, Grandstream, Snom and others) or a name like "phone" or "sip".
    The PC behind it is tagged "behind a desk phone".

  Anything else is still listed under All MACs, with a tag saying why it isn't
  direct:
  - behind an uplink;
  - behind a UniFi device;
  - behind a desk phone;
  - shared port: several MACs on one port that aren't a phone and PC, which means
    an unmanaged switch or a hub;
  - behind a neighbour;
  - learned by the gateway: the client isn't on any UniFi switch port.
- **Switch ports:** every port on each UniFi switch and gateway, showing what's
  plugged in. That's the client's name and IP, or "uplink", "port to <UniFi
  device>", "LLDP neighbour <name>", or the MACs sharing the port. You can filter
  to Direct clients, In use or All ports.
- **SSIDs:** client count and bandwidth per SSID (summed from its clients), with graphs.
- **Internet:** throughput per WAN link and in total, ISP, WAN IP, latency and the
  last speed test.

Open it from **Wi-Fi & clients** in the menu (it appears once a UniFi
integration exists), or the button on the integration page. AP device pages also
get Wi-Fi traffic and client graphs. The same data is in the REST API:
`/api/v1/integrations/{id}/data` and `/api/v1/integrations/{id}/metrics?key=ssid:Office`.

## Which API, and who calls it

It uses the Network application's **local API** (`/proxy/network/api/s/<site>/stat/...`),
because the newer "integration" API has no per-client traffic or SSID figures.
Your **poller** calls it from inside the LAN; the VPS never reaches the console
and nothing is opened inbound.

## Setup

1. **Create an API key** (UniFi OS with Network 9.0 or later): UniFi Network >
   Settings > Control Plane > Integrations > Create API key. Copy it once.
   On a self-hosted controller or older firmware, create a local admin instead
   (Settings > Admins & Users, "Restrict to local access only", role *View Only*)
   and use its username and password. A ui.com account with two-factor won't work.
2. In Linkwatch: **Integrations > UniFi Network**.
   - *Poller that can reach it:* the poller on that LAN.
   - *UniFi console address:* e.g. `192.168.1.1`, or `10.0.0.5:8443` for a self-hosted controller.
   - *API key* (or username and password). Paste it into the form, not into chat or tickets.
   - *Site:* leave blank for all sites, or e.g. `default`.
   - Untick *Verify the TLS certificate* (consoles use a self-signed one).
3. Press **Test**. You should see "Found N UniFi devices, N clients and N SSIDs".
4. Graphs fill in after two or three poll intervals.

If a switch or AP is also polled over SNMP, Linkwatch keeps the SNMP ports and
adds the UniFi data to the same device.

## Troubleshooting

- *rejected the credentials (HTTP 401):* the key was revoked or mistyped, or the
  Network version is older than 9.0. Use a local username and password instead.
- *Could not reach ...:* the poller can't reach the console on 443 (or 8443).
  From the poller host: `curl -k https://192.168.1.1/`.
- Client data volume: the busiest 2000 clients are kept per sync, and per-client
  graphs for the busiest 1000. History follows `LW_RAW_DAYS` / `LW_HOURLY_DAYS`.
