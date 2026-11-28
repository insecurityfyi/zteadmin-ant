# Scheduled speed tests

Pollers can run internet speed tests on a schedule and send the results to VisCon1. Each result records download,
upload, latency, jitter and packet loss, and is filed under the ISP it went out through. The **Speed tests** page
(`/speedtests`) and the **Speed tests by ISP** dashboard widget show the latest result and the history for each ISP.

## How a test runs

- The poller image includes [librespeed-cli](https://github.com/librespeed/speedtest-cli) (LGPL-3.0), built from its
  tagged source when the image is built. Ookla's `speedtest` CLI is not used because its licence doesn't allow it to be
  redistributed in an image.
- Download and upload come from librespeed-cli. By default it uses the nearest public LibreSpeed server. You can pin
  server IDs (from `librespeed-cli --list`) or give the URL of a servers JSON file for a LibreSpeed server you host.
  Pinning one server keeps results comparable over time. Results are never shared with librespeed.org.
- Latency, jitter and packet loss come from 20 ICMP pings to the same server, sent right after the test. If ICMP isn't
  allowed in the container, latency and jitter come from librespeed's HTTP round trip and loss is left blank.
- Lanes run one after another, never at the same time, so they don't compete for the uplink.

## Settings (per poller)

Open **Speed tests**, then **Settings** under a poller.

| Setting | Default | Notes |
|---|---|---|
| Run on a schedule | off | "Run now" works whether or not this is on. |
| How often | every 6 hours | 1 to 24 hours. |
| Random offset | ± 20 minutes | Moves each run a little so tests don't always land on the same minute. |
| Lanes | one lane on the default route | Up to 4. See "Testing each ISP" below. |
| Length | 10 seconds per direction | 5 seconds is a light test for metered links. |
| Monthly cap (GB) | none | Per lane. See "Data caps" below. |
| Download only | off | Skips the upload half, which roughly halves the data used on asymmetric links. |

The poller saves when it last ran, so restarting or updating it doesn't trigger an extra test. A poller that has never
run a test starts its first one 2 to 15 minutes after the schedule is turned on.

## Which ISP a result belongs to

The first of these that gives an answer is used:

1. The ISP name typed for the lane.
2. **Settings > Internet providers**: the public address the test server saw is inside one of those ranges.
3. The map: a gateway WAN whose address is that public address.
4. The cached address lookup the map uses (RDAP).
5. The network owner the speed test server reported. For example, "AS14593 Space Exploration Technologies" is shown
   as Starlink and "Charter Communications" is shown as Spectrum.

Typing the ISP name for each lane is the most reliable choice, and it keeps the names the same as on the map
(Brightspeed Fiber, Spectrum Business, Starlink Satellite).

## Testing each ISP

A speed test only measures the WAN that the poller's traffic leaves by. With three WANs on the gateway (for example
Brightspeed Fiber, Spectrum Business and Starlink Satellite on zlabcgwm), a single lane on the default route measures
whichever WAN the gateway picks for it, usually the primary or the one load balancing chose. There are three ways to
measure each ISP.

### 1. One lane per WAN, routed by source address (recommended)

Give the poller host one extra address per WAN, and have the gateway route each address out its own WAN.

1. On the poller host, add secondary addresses on its LAN interface (the poller uses host networking, so it can bind
   to them directly). For example, with NetworkManager on CentOS:

   ```sh
   nmcli con mod "System eth0" +ipv4.addresses 192.168.10.21/24 +ipv4.addresses 192.168.10.22/24 +ipv4.addresses 192.168.10.23/24
   nmcli con up "System eth0"
   ```

2. On the gateway, add a policy route for each address:
   - **UniFi** (Cloud Gateway / UDM): *Settings > Routing > Policy-Based Routes* (called *Traffic Routes* on older
     versions). Source: the device or IP `192.168.10.21`, destination: Internet, interface: the WAN for that ISP.
     Turn off the kill switch if you want the test to fall back to another WAN when that one is down. Leave it on if
     you'd rather see the failure.
   - **pfSense / OPNsense**: a LAN firewall rule that passes traffic with source `192.168.10.21` and sets *Gateway*
     (under Advanced) to that WAN's gateway. Put it above the default LAN rule.
   - **VyOS**: `set policy route PBR rule 10 source address 192.168.10.21` and
     `set policy route PBR rule 10 set table 11`, a static default route in table 11 via that WAN, then apply the
     policy to the LAN interface.
3. On the Speed tests page, add a lane for each address and type its ISP name.

Source-address binding needs no extra container privileges.

### 2. A poller per WAN

If the gateway can't route by source, run a small poller (a Raspberry Pi is enough) on a network segment or VLAN
whose traffic always leaves by one WAN, and turn speed tests on for it.

### 3. Use the default route and let the label follow

If you only care about whichever WAN is active, keep one lane with no ISP name. Each result is labelled by the public
address it came from, so after a failover the results move to the backup ISP on the chart.

## Data caps (Starlink and other metered links)

A test downloads and uploads as fast as the link allows for the test length. As a rough guide, a 10-second test uses
about 0.4 GB on a 300 Mbps link and about 2 GB on a gigabit link. Every 6 hours, that's roughly 50 GB or 240 GB a month.

For a capped or metered lane:

- Set **Monthly cap (GB)**. VisCon1 adds up the data each lane used this calendar month (UTC). When a lane reaches its
  cap, its scheduled tests stop until the 1st of next month, an event is logged, and Run now is refused for that lane.
  The poller also skips a test that would go over the remaining budget, based on the size of its last test.
- Use the **5 second** length and **Download only**.
- Schedule tests less often, such as every 12 or 24 hours.

The Pollers table on the Speed tests page shows each lane's data this month, the average per test, and an estimate
for a month at the current schedule.

## Run now

**Run now** on the page header runs every lane on every poller (or the poller chosen in the filter). Each poller and
lane also has its own button, and the dashboard widget has one too. Results arrive in about a minute. Only admins see
these buttons.

## Data kept

Results are kept for 400 days.
