# Path probes

A path probe traces the route from a poller to a target, hop by hop, the way `mtr` does. Use it to watch the path to a SaaS service, a branch firewall, your ISP's gateway or a DNS resolver, and to see where loss or latency comes from and which providers carry the traffic.

Open **Paths** in the menu.

## Create a probe

Only admins can create or change probes. Click **New probe** and fill in:

| Field | What it does |
| --- | --- |
| Name | What the probe is called in the list and in alerts. |
| Target | A host name or IP address. The poller resolves names itself, so a name can resolve differently at each site. |
| Protocol | **ICMP** works like ping. **TCP** sends SYNs to the port you choose (443 by default) and **UDP** sends datagrams, so the trace follows the same firewall rules and load balancers as real application traffic. |
| Port | Required for TCP, optional for UDP. |
| Packets per hop | One packet a second, so 10 packets take about 10 seconds. More packets give steadier loss figures. |
| Schedule | From every minute to every hour. |
| Pollers | Each poller you pick runs the trace from its own network. Pick several to compare sites. |
| Alert thresholds | Loss (%) and latency (ms) at the target. They override the built-in rules for this probe. Leave them empty to use the rules. |

The first result arrives within a minute. **Run now** on the probe page asks the pollers to run it straight away.

## The probe page

- **Status cards**: loss at the target, average, best and worst latency, jitter, the number of hops, and how many public networks the path crosses.
- **Hop by hop**: a diagram of the path from the poller to the target.
  - Hops are grouped in coloured bands by network: the AS number and provider, or *Private network* or *Carrier-grade NAT* for addresses with no public AS.
  - Every hop shows its address, average latency, jitter and loss.
  - `+N ms` on a link is the latency that hop adds.
  - Green means no loss. Red means loss that carries on to the target, which is real loss.
  - Amber with a dashed ring means loss at that hop only. The router is limiting its own replies, and traffic through it is fine.
  - A grey dashed hop didn't reply at all, which is common and harmless when later hops answer.
- **Hops table**: every hop with its network, prefix, provider, loss, packets sent, and last, average, best, worst, standard deviation and jitter in ms.
- **Graphs**: latency (average, worst and jitter) and loss at the target, for 6 hours to 30 days.
- **Path changes**: each run whose path differed from the run before. **View path** shows the diagram for that run.
  - A *route change* means a hop answered from a different address. Load-balanced networks do this often.
  - A *network change* means the path now crosses different AS numbers, for example a new transit provider. A network change is also written to the event log under **Paths**.

With more than one poller, a tab for each poller shows its own path.

## Alerts

There are three built-in rules under **Alerts > Built-in rules**. You can change their thresholds, run counts and severity, or turn them off.

| Rule | Opens when | Default |
| --- | --- | --- |
| Path loss | Loss at the target is above the threshold for the set number of runs in a row | 20 %, 2 runs, warning |
| Path latency | Average latency to the target is above the threshold for the set number of runs in a row | 150 ms, 3 runs, warning |
| Path changed networks | The path crosses different AS numbers than on the run before. It clears once the path holds for the set number of runs | 3 runs, info |

A run that fails, for example because the poller can't run `mtr`, doesn't count as loss. Pausing or deleting a probe, or removing a poller from it, clears its alerts.

## Networks and providers

The server looks up the origin AS and holder of every public hop address with RIPEstat (`stat.ripe.net`). Results are cached for 30 days. Private, CGNAT, loopback and link-local addresses are never sent.

Only the hop addresses are sent. If the server can't reach RIPEstat, it stops trying for 10 minutes. Networks show as *Looking up…* until a lookup works, and the rest of the probe keeps working.

## Poller requirements

Probes run `mtr` inside the poller container, and its packet helper needs the `NET_RAW` capability.

- The install script already starts the poller with `--cap-add=NET_RAW` and `--network host`.
- On Podman's default bridge network the first hop is the bridge gateway, 10.88.0.1, not your LAN router. Host networking (the install script's default) starts the trace at your real gateway. Run the install command again with no arguments to move an older poller onto the host's network; it keeps its key.
- If you run the container by hand, add `--cap-add=NET_RAW` (in a Quadlet `.container` file, `AddCapability=NET_RAW`).
- Pollers on an image from before path probes show **needs update** when you pick pollers. Update them with the one-line command on the Pollers page. The poller keeps its key.

## Retention

Each run is kept for 30 days.
