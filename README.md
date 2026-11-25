# OmniVista Cirrus for Home Assistant

Brings Alcatel-Lucent Enterprise **OmniVista Cirrus** data into Home Assistant, with an automatically drawn **network map** card.

## What you get

| Where | Entities / data |
|---|---|
| Each AP / switch (HA device) | Online (connectivity), uptime, firmware, IP; APs also get client count (with per-SSID / per-band attributes) and *Channels* (e.g. `1 / 36`) |
| Each AP radio (2.4 / 5 / 6 GHz) | Channel, clients, channel utilisation, TX power, noise floor, channel width. Radios that appear later are added automatically |
| Each site | Wireless clients, wired clients (needs SSH MAC tables), one sensor per SSID |
| Tracked clients (opt-in) | `device_tracker` per chosen client: home/away plus IP, hostname, SSID, AP, RSSI, band, auth type, 802.1X user, VLAN, OS, traffic |
| Network map card | Internet → gateway → switches → APs / wired devices → clients grouped by SSID, with port + link-speed labels |

## Network map

The map is built from:

1. **Cirrus L2 topology + LLDP**: switch ports, neighbours (gateway, APs, LLDP-speaking hosts), link speed and state.
2. **Cirrus wireless sessions**: each client is attached to its AP and grouped by SSID.
3. **Switch MAC tables (optional, SSH)**: `show mac-learning` plus `show arp`, read directly from each OmniSwitch. This lets the map:
   - show wired clients on the right switch port, with IP from ARP,
   - place devices Cirrus has no LLDP link for (e.g. an AP behind an unmanaged switch) under the correct port,
   - draw an *Unmanaged device* when a port has several MACs and no LLDP neighbour.
4. **HA device registry**: if another integration knows a MAC (router, ESPHome, etc.), its name is used.

Inferred links (from MAC tables rather than LLDP) are dashed. Cirrus does not report the WAN link, so *Internet* is always drawn.

### Network map in the sidebar

The setup wizard's last step adds **Network** to Home Assistant's sidebar: a full-screen page with just the map, so you don't need to build a dashboard. Change the title, restrict it to administrators, or turn it off under the integration's **Configure** → **General**.

### Adding the map to a dashboard

The card is registered automatically when the integration loads; there is no resource to add.

**On an existing dashboard:** open the dashboard → ✏️ **Edit** → **Add card** → search for **OmniVista Cirrus network map** (or choose **Manual** and enter `type: custom:ovcirrus-network-map`).

**As its own full-screen dashboard:** Settings → **Dashboards** → **Add dashboard** → *New dashboard from scratch*, name it (e.g. "Network"), open it → ✏️ → ⋮ → **Raw configuration editor**, paste this and save:

```yaml
views:
  - title: Network
    path: network
    type: panel        # one card filling the whole view
    cards:
      - type: custom:ovcirrus-network-map
        height: 820
```

If the card shows "Custom element doesn't exist", refresh the browser (or clear the frontend cache in the HA app) after restarting Home Assistant.

### Card

The card is registered automatically. Add it to a dashboard:

```yaml
type: custom:ovcirrus-network-map
# all optional:
title: Network map
site: Home                # site name or id (default: first; a picker appears if several)
height: 640               # px
refresh: 30               # seconds
expand_clients: false     # start with AP client lists expanded
max_columns: 3            # client chips per row inside an SSID box
text_size: 11             # pt size of device names (8-30); other map labels scale with it; viewers can change it in the View menu
layout_editing: admin     # who can drag devices and save the layout: admin (default), true or false
snap_to_grid: true        # snap dragged devices to a grid (viewers can toggle it in edit mode)
grid_size: 20             # grid spacing in px
device_size: 1            # starting size of gateways, switches, APs and wired devices, relative to the default (0.5-4); viewers can change it
client_size: 1            # starting size of wireless and wired clients, relative to the default (0.5-4); viewers can change it
show_vlans: true          # VLAN legend above the map
link_graphs: false        # small traffic trend on the gateway's link labels (UniFi); viewers can toggle it
rate_ranges: [30m, 2h, 24h]  # bandwidth chart range buttons: 15m 30m 1h 2h 6h 12h 24h 3d 7d
rate_range: 2h            # range the bandwidth chart opens on
rate_unit: bits           # bits (b/s, Mb/s) or bytes (B/s, MB/s) for live rates and graphs
```

Click a node for details, use **+ / −** on a node to expand or collapse it, and the zoom buttons (or **fit**) to size the map. **View** opens the size settings: **Text** (map names and labels only), **Clients** and **Devices** (rings, photos, the AP client-count bubble and brand logos), each from 0.5× to 4× where 1× is the default size. Changes are remembered in each browser. Admins can **Save as default for all devices**, which stores the sizes in Home Assistant so every browser and the app start with them. **Reset** returns to the saved default.

**Edit layout** (admins) lets you drag switches, APs, gateways, wired and manual devices. Everything under a device moves with it, so an AP's wireless clients stay with their AP. Links, labels and boxes follow. Positions are saved in Home Assistant and shared by every dashboard. **Snap to grid** (on by default) aligns devices to a dot grid shown while editing; hold **Alt** while dragging to place a device freely. **Reset layout** returns to the automatic layout. The choice is remembered per browser, and boxes resize to fit.

### Addresses, UNPs and alerts

The card has three tabs: **Map**, **Addresses** and **Alerts**. All three are read-only.

**Addresses** lists every subnet with its DHCP pool, how full the pool is, and one row per address that is reserved or in use: *Gateway*, *Reserved* (a UniFi fixed-IP reservation), *DHCP* (inside the pool) or *Static* (outside it). Each row shows the device, its MAC and which sources saw it (UniFi, Cirrus, UPAM, switch ARP, manual devices). **Show free addresses** fills in the gaps. Conflicts are highlighted: one address used by two devices, or a reserved address in use by a different device. Click a name to find the device on the map.

Subnets, pools and reservations come from the UniFi gateway; for routed VLANs the gateway does not serve, the switches' IP interfaces in Cirrus are used. Each network with a DHCP pool gets a *DHCP pool usage* sensor (percent, with free / used / reserved counts as attributes).

**UNPs:** if the Cirrus application's user can read UPAM, the map shows a **UNPs** row (Access Role Profiles) next to the VLANs. Click one to highlight the clients UPAM put in it. A client's details show its access role, the VLAN it was given, the policy list, access policy and how it authenticated.

**Alerts** shows Cirrus alerts for the site, newest first, filtered by severity or text, with acknowledged ones hidden unless you ask for them. Click an alert for its details: the device and client as the map knows them, how many other alerts each had this week, and (fetched from Cirrus when you open it, read-only) the alert's category, first/last occurrence, count, firmware and radio, the client's alerts over the last 30 days, and every field Cirrus sent. The *Active alerts* sensor counts the unacknowledged ones, and each new one fires an `ovcirrus_alert` event (`id`, `severity`, `type`, `reason`, `device`, `device_mac`, `client_mac`, `ssid`, `site`, `time`):

```yaml
automation:
  - alias: Notify on Cirrus alert
    triggers:
      - trigger: event
        event_type: ovcirrus_alert
    conditions:
      - condition: template
        value_template: "{{ trigger.event.data.severity in ['critical', 'major'] }}"
    actions:
      - action: notify.mobile_app_phone
        data:
          title: "Network: {{ trigger.event.data.type }}"
          message: "{{ trigger.event.data.reason or '' }} ({{ trigger.event.data.device or 'unknown device' }})"
```

Admins can acknowledge alerts from the Alerts tab, one at a time or every alert the current filter shows. This acknowledges them in Cirrus too. Automations can do the same with the `ovcirrus.acknowledge_alerts` action: pass `ids` (the `id` from the event), or `alert_type` and/or `client_mac`, or nothing to acknowledge every unacknowledged alert:

```yaml
action: ovcirrus.acknowledge_alerts
data:
  alert_type: MAC Auth Failure
  client_mac: "60:74:F4:EA:F6:8E"
```

UNPs and alerts need the Cirrus application's user to have read access to UPAM and alerts; acknowledging needs write access to alerts. Without it, the integration keeps working and the card says what is missing.

### Register a device (preview)

**Register device** (Addresses tab, or **Register device…** on a selected device) works out what registering a device would do: a fixed IP from the UniFi gateway's DHCP (a reservation) and a Cirrus UNP for its MAC, plus a CoA if it is online in another UNP. It shows every request it would send and anything that would stop it. **It changes nothing yet**: writing is a later step.

The free addresses offered are ones UniFi and Cirrus know nothing about. **Check free addresses (ping)** pings them all from the Home Assistant host (and reads its ARP table, which also catches devices that drop pings on HA's own subnets) and drops any that answer; Preview pings the chosen address too. A few addresses known to be up are pinged as a check, so if the gateway's firewall blocks pings from HA to that network the form says the result proves nothing.

> **Firewall:** the ping check only works if the Home Assistant host may send ICMP (ping) to the network being checked. On a UniFi gateway, add a firewall rule allowing ICMP from HA's IP address to each network you register devices on (and the replies back), or the check reports that it proves nothing.

### Access: UNPs, SSIDs and the gateway firewall

The **Access** tab is read-only and shows what decides where a device lands and what it can reach:

- **UNPs (Cirrus access roles):** where each one is assigned (switches, AP groups), the VLAN and network it puts devices on, how many are online in it, and any captive portal or bandwidth limit. The VLAN is read per assignment (one read-only request per UNP, every topology refresh): a switch assignment shows its VLAN, and an AP group set to VLAN 0 shows **→ SSID VLAN** (the device stays on its SSID's VLAN). Devices online in a UNP also fill in its VLAN and network from their wireless VLAN and addresses. If none of your UNPs has Cirrus access rules (a policy list), the tab says so: access is then down to the VLAN and the gateway's firewall.
- **Wireless networks (SSIDs):** the VLANs each SSID's devices are on (tagged, or untagged on the AP port's native VLAN), the network that is, and which UNPs they're in. A wireless device whose UNP sets no VLAN, or that has no UNP, lands on its SSID's VLAN.
- **Gateway firewall:** read from the UniFi gateway with the same read-only account. Zone-based firewalls (UniFi Network 9+) show as a zone × zone grid: click a cell for the rules behind it, in the order the gateway checks them. Click a UNP's or SSID's zone to see only that row. Older rule-set firewalls are listed per rule set. Traffic rules and port forwards are listed too.

### Design a UNP (preview)

Admins can **Design a UNP** from the Access tab: a name, a VLAN (or none, so AP groups keep the SSID's VLAN), the switches and AP groups to apply it to, and access rules checked top to bottom, first match wins. **It creates nothing yet**: Preview shows the rules in plain English and every request Cirrus would receive (switch rules, a policy list, then the UNP itself).

- **Cirrus's own services first.** The list starts with the services Cirrus already has (read live from Cirrus, or a built-in copy of its defaults), so rules reuse names like "DNS (53)" and "HTTP-SSL (443)". Services Cirrus doesn't have, such as MQTT, Plex or Home Assistant, come from the designer's catalogue of about 70 or a search of the IANA service registry, are marked "new", and would be added to Cirrus's service list when used. Anything else is a custom protocol and port.
- **Destinations are friendly too:** anywhere, the internet (not local addresses), any local address, the gateway, Home Assistant, one of your networks, or an address or range.
- **Templates** to start from: guest internet only, IoT (Home Assistant plus internet basics), isolated, or no rules.
- It warns about rules that can never match because an earlier rule already decides that traffic, a VLAN shared by two gateway networks, a VLAN the switches don't have yet, and names already in use.

"The internet" can't be written as one switch rule, so it becomes "block this service to local ranges, then allow it anywhere". The request formats are matched to a UNP, policy list and policies built by hand in Cirrus; nothing is sent to Cirrus yet.

## Device identification

Every client, including ones the integration has never seen before, is identified live from:

| Source | Gives |
|---|---|
| IEEE MAC vendor registry (downloaded once, refreshed monthly) | Manufacturer from the MAC prefix |
| Hostname patterns | Type and brand (`iPhone`, `SonosZP`, `P110M`, `NIBE-…`, `amazon-…`) |
| Cirrus fingerprint | OS / device type |
| Cirrus device profiling (IoT inventory, read-only) | Category and a 0–100 score, from the DHCP options the device sent (55, 60) and the hosts it looked up |
| Home Assistant device registry | Exact model and integration, when another integration knows the MAC |
| UniFi gateway (optional) | Names you set in UniFi, hostnames and IPs |

Brand logos come from Home Assistant's brand images or Simple Icons. Switch and gateway images and exact OmniSwitch port layouts come from the [NetBox device-type library](https://github.com/netbox-community/devicetype-library) (CC0). All of these are downloaded the first time they are needed, then cached in `/config/ovcirrus_cache`. Your own photos in `/config/www/ovcirrus/<model>.png` always win.

Cirrus's profiling only sets a device's type when the match is specific (a camera, a thermostat, a TV…) and scores at least 70 (Cirrus gives real TP-Link cameras and TP-Link P110M plugs the same 57 as "IP Camera", so mid scores are not trusted). Vague or low-scored matches such as "Embedded OS" never rename a device: they show in its details as **Cirrus profile**, with the score and the evidence (DHCP request list, vendor class, hosts looked up, and where it was profiled), so you can judge them yourself. The UniFi gateway's own fingerprint guess is not used.

Admins can rename a device or change its type from the map's details panel; this is stored against the MAC.

### New devices

The first run records a baseline. After that, any MAC never seen before:

- fires an `ovcirrus_new_client` event (`mac`, `name`, `vendor`, `ip`, `where`, `type`, `site`),
- gets a **NEW** badge on the map for 24 hours,
- is listed by the *New devices (24h)* sensor.

Phones that rotate private MACs are matched back by distinctive hostnames where possible.

```yaml
automation:
  - alias: Notify on new network device
    triggers:
      - trigger: event
        event_type: ovcirrus_new_client
    actions:
      - action: notify.mobile_app_phone
        data:
          title: New device on the network
          message: "{{ trigger.event.data.name }} ({{ trigger.event.data.vendor or 'unknown vendor' }}), {{ trigger.event.data.ip }}, {{ trigger.event.data.where }}"
```

## Servers & manual devices

**From the map (admins):** click **+ Add device**. Enter a name, an IP and/or MAC, a type and, optionally, the switch and port. Without a port, the device is placed from the switch MAC table (or ARP / UniFi). Choose how to discover its services:

- **Quick scan:** about 40 common service ports (SSH, HTTP/S, SMB, NFS, RDP, VNC, Proxmox, Synology, Plex, Jellyfin, Home Assistant, MQTT, Modbus, databases, printers, RTSP…), with banners, page titles and TLS certificate names.
- **Full scan:** all 65,535 TCP ports, followed by a slower re-check of well-known ports (small embedded devices such as heat pumps and inverters can drop connections during the fast pass). Each open port is then identified from its banner or web page, and named from the integration's own list or, failing that, the [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/) (tagged *IANA*, since the registered use is not always what runs there). It can take a few minutes. No external tools such as nmap are needed.

Any wired device the map already shows (from the MAC table or LLDP) has **Add to map as a device** in its details, pre-filled with its name, IP, MAC and port. Added devices have **Edit device** / **Remove from map**, plus **Quick scan** / **Full scan** buttons.

**Unknown ports:** open ports that nothing recognises are flagged *unknown*. Click **Name this port** to say what runs there, either for that device only or for that port on every device. Your names replace "Unknown service" in all future scans, and **rename** / **Clear name** change or remove them.

The IANA list ships with the integration (`iana_ports.json`, about 6,000 TCP ports) and is refreshed with `python3 scripts/update_ports.py`.

Devices can also be added under **Configure** → **Servers & manual devices**. Scans repeat every 24 h by default (**Configure** → **General**). Only private / link-local addresses can be scanned, and some intrusion-detection systems will notice a scan.

### Your own pictures

Admins can give any client or manual device its own picture: open it on the map and click **Add picture** (PNG, JPEG or WebP, e.g. a photo of the actual Shelly relay). The browser shrinks it to 480 px before upload. It replaces the icon on the map and shows in the device's details. Pictures are stored in `/config/ovcirrus_photos`, belong to the device's MAC address (so they follow it between Wi-Fi and cable) and are included in backups.

## Speed test & WAN

- **Home Assistant Speedtest.net integration:** `sensor.*speedtest*_download / _upload / _ping` are picked up automatically by the card. Set `speedtest: {download: sensor.x, upload: sensor.y, ping: sensor.z}` in the card to choose others.
- **UniFi gateway** (Options → *UniFi gateway*, local read-only account): the gateway's last speed test, WAN status, WAN IP and ISP. Adds sensors (WAN download/upload/latency, last speed test, WAN IP, ISP) and an *Internet* connectivity binary sensor.

The newest result is shown on the Internet → gateway link, and both appear in the Internet node's details.

## UniFi gateway on the map

With the UniFi gateway connected, the gateway's panel shows:

- **Live port panel:** each port's link state, name and speed, with the WAN port marked. The gateway's links on the map show the live traffic of the port they use, and the Internet → gateway link shows the WAN download / upload and latency.
- **Ports** table with live rates and a trend line per port; click a row to chart that port.
- **Bandwidth** chart (download as an area, upload as a line, peak marked, hover for values) with range buttons.
- **Internet** (status, ISP, WAN IP, availability, latency, drops, last speed test) and **Health** (CPU, memory, temperatures, uptime, firmware, storage). Warnings, such as high temperature or an available update, show as a dot on the gateway.

**Bandwidth history** (Options → *Bandwidth history*): how often the gateway is read (5–60 s, default 15), how long every reading is kept (1–24 h, default 2) and how long 1-minute averages are kept (1–7 days, default 1). The history is saved to disk every few minutes and when Home Assistant stops, so it survives restarts (turn this off to keep it in memory only). In the card's **View** menu, viewers choose which range buttons appear, bits/s or bytes/s, and whether the map's links show trend lines.

## Backup & restore

Admins get **Backup & restore** in the map's **View** menu. **Download backup** saves one JSON file with the
integration's options, site selection, manual devices and scan results, device names and types, the map layout,
port names, the saved view and your own device images from `/config/www/ovcirrus` (up to 2 MB). Credentials (Cirrus
app ID / secret, UniFi password) are never included.

**Restore from file…** replaces those settings with the backup's, keeps the credentials already set up here, and
reloads the integration. To move to a new Home Assistant, add the integration with your credentials first, then restore.

## Installation

1. HACS → Integrations → ⋮ → *Custom repositories* → add `https://github.com/daveo2k/ha-network-map` (category *Integration*), install, restart HA.
   Or copy `custom_components/ovcirrus` into `/config/custom_components/` and restart.
2. Settings → Devices & services → *Add integration* → **OmniVista Cirrus**.
3. Choose your instance (default `uk.manage.ovcirrus.com`) and enter an **Application ID and secret**. Create these in Cirrus under your user profile → *Applications*. The application only sees the organizations its user can see.
4. Pick the organization and sites.
5. Optionally enable **Switch MAC tables (SSH)**.

### SSH / MAC tables

- Authentication is key-based only. Put the private key somewhere the **Home Assistant container** can read, e.g. `/config/.ssh/id_ed25519`. Keys inside the *Terminal & SSH* add-on are not visible to HA Core.
- For **SSH certificates**, place the signed certificate next to the key as `<key>-cert.pub` (e.g. `/config/.ssh/id_ed25519-cert.pub`); it is loaded automatically.
- The account only needs read access (`show` commands).
- Each switch gets its own **SSH address** field. It lists every address Cirrus knows for the switch: the device IP, LLDP management IPs, and every IPv4 VLAN interface that is up (labelled with VLAN id and name). Addresses that answer on the SSH port from Home Assistant come first, and one on Home Assistant's own subnet is pre-selected. Type any IP or hostname HA can reach, or clear the field to skip that switch. Every switch with an address is tested before saving, and the exact SSH error is shown if one fails.
- *known_hosts*: leave blank to skip host-key checking (LAN use), or point at a known_hosts file to verify.

### Presence tracking

Options → *Tracked clients* lets you pick which wireless clients get a `device_tracker`. Phones using private (randomised) MACs keep a stable MAC per SSID, but it changes if the user resets it.

## Notes

- Cirrus is polled every 60 s by default (Options → *Polling*). Topology and LLDP refresh every 5 minutes, and MAC tables every 120 s by default.
- Cirrus requires `X-Requested-With`, `Origin` and `Referer` headers on API calls. The client sends them.
- The Cirrus *wired/UNP sessions* API only lists clients that authenticate through UNP, which is why wired clients come from switch MAC tables instead.
- Diagnostics (Settings → device → *Download diagnostics*) redact the application secret and user names.

## Releases

Versions follow `MAJOR.MINOR.PATCH`. HACS shows the version from GitHub releases and offers updates when a new one is published. To publish one:

```bash
scripts/release.sh            # next patch version, e.g. 0.2.1 -> 0.2.2
scripts/release.sh minor      # 0.2.1 -> 0.3.0
scripts/release.sh 0.4.0      # a specific version
```

The script updates `manifest.json` and the card's cache-busting version, then commits, tags, pushes and creates the GitHub release with generated notes. It needs the GitHub CLI (`gh`) logged in.

## Licence

MIT. See [LICENSE](LICENSE).
