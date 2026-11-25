"""UNP designer: describe a UNP (name, VLAN, where it applies, access rules) and see the Cirrus requests it takes.

PREVIEW ONLY. Nothing here talks to Cirrus. It turns a friendly design into the requests the Cirrus API documents
(unified policies -> a policy list -> the Access Role Profile with its assignments) and checks them against what
the integration already knows, so the result can be read before any write step exists.

The request shapes follow Cirrus's published OpenAPI spec, corrected against a unified policy built by hand in
Cirrus (action under "qos" with DROP/ACCEPT, YES/IGNORE option flags, port ranges as "22:22"). Policy lists and
the UNP that uses one are still to be confirmed against a hand-built example before anything is sent.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# ---------------------------------------------------------------- services
# Well-known services with their registered ports (IANA service name and port registry, plus vendor docs for
# smart-home protocols). proto: TCP, UDP, TCP/UDP or ICMP. ports: "22", "67-68" or "80,443".
SERVICES: list[dict] = [
    {"id": s[0], "name": s[1], "proto": s[2], "ports": s[3], "group": s[4]}
    for s in [
        # Essentials
        ("dns", "DNS", "TCP/UDP", "53", "Essentials"),
        ("dhcp", "DHCP (to the server)", "UDP", "67", "Essentials"),
        ("ntp", "NTP (time)", "UDP", "123", "Essentials"),
        ("icmp", "Ping (ICMP)", "ICMP", "", "Essentials"),
        ("mdns", "mDNS / Bonjour", "UDP", "5353", "Essentials"),
        ("ssdp", "SSDP / UPnP discovery", "UDP", "1900", "Essentials"),
        ("dot", "DNS over TLS", "TCP", "853", "Essentials"),
        # Web
        ("http", "HTTP", "TCP", "80", "Web"),
        ("https", "HTTPS", "TCP", "443", "Web"),
        ("quic", "HTTPS over QUIC (HTTP/3)", "UDP", "443", "Web"),
        ("http-alt", "HTTP alternate", "TCP", "8080", "Web"),
        ("https-alt", "HTTPS alternate", "TCP", "8443", "Web"),
        # Remote access & files
        ("ssh", "SSH / SFTP", "TCP", "22", "Remote access & files"),
        ("telnet", "Telnet", "TCP", "23", "Remote access & files"),
        ("ftp", "FTP", "TCP", "21", "Remote access & files"),
        ("tftp", "TFTP", "UDP", "69", "Remote access & files"),
        ("rdp", "Remote Desktop (RDP)", "TCP/UDP", "3389", "Remote access & files"),
        ("vnc", "VNC", "TCP", "5900", "Remote access & files"),
        ("smb", "Windows file sharing (SMB)", "TCP", "445", "Remote access & files"),
        ("netbios", "NetBIOS", "UDP", "137-138", "Remote access & files"),
        ("afp", "Apple file sharing (AFP)", "TCP", "548", "Remote access & files"),
        ("nfs", "NFS", "TCP/UDP", "2049", "Remote access & files"),
        ("rsync", "rsync", "TCP", "873", "Remote access & files"),
        # Mail
        ("smtp", "SMTP", "TCP", "25", "Mail"),
        ("submission", "Mail submission", "TCP", "587", "Mail"),
        ("smtps", "SMTP over TLS", "TCP", "465", "Mail"),
        ("imaps", "IMAP over TLS", "TCP", "993", "Mail"),
        ("pop3s", "POP3 over TLS", "TCP", "995", "Mail"),
        # VPN
        ("wireguard", "WireGuard", "UDP", "51820", "VPN"),
        ("openvpn", "OpenVPN", "UDP", "1194", "VPN"),
        ("ipsec", "IPsec (IKE + NAT-T)", "UDP", "500,4500", "VPN"),
        # Smart home
        ("ha", "Home Assistant", "TCP", "8123", "Smart home"),
        ("mqtt", "MQTT", "TCP", "1883", "Smart home"),
        ("mqtts", "MQTT over TLS", "TCP", "8883", "Smart home"),
        ("esphome", "ESPHome native API", "TCP", "6053", "Smart home"),
        ("homekit", "HomeKit (HAP)", "TCP", "51827", "Smart home"),
        ("matter", "Matter", "UDP", "5540", "Smart home"),
        ("coap", "CoAP", "UDP", "5683", "Smart home"),
        ("hue", "Philips Hue bridge", "TCP", "80,443", "Smart home"),
        ("tuya", "Tuya local", "TCP", "6668", "Smart home"),
        ("tuya-disc", "Tuya discovery", "UDP", "6666-6667", "Smart home"),
        ("kasa", "TP-Link Kasa / Tapo local", "TCP", "9999", "Smart home"),
        ("modbus", "Modbus TCP", "TCP", "502", "Smart home"),
        # Media
        ("airplay", "AirPlay", "TCP", "7000,7100", "Media"),
        ("cast", "Chromecast / Google Cast", "TCP", "8008-8009", "Media"),
        ("sonos", "Sonos", "TCP", "1400", "Media"),
        ("spotify", "Spotify Connect", "TCP", "4070", "Media"),
        ("plex", "Plex", "TCP", "32400", "Media"),
        ("rtsp", "RTSP (camera streams)", "TCP", "554", "Media"),
        ("onvif", "ONVIF (camera control)", "TCP", "2020", "Media"),
        ("sip", "SIP (VoIP)", "TCP/UDP", "5060", "Media"),
        ("rtp", "RTP (VoIP audio)", "UDP", "10000-20000", "Media"),
        # Printing
        ("ipp", "IPP printing", "TCP", "631", "Printing"),
        ("jetdirect", "Raw printing (JetDirect)", "TCP", "9100", "Printing"),
        ("lpd", "LPD printing", "TCP", "515", "Printing"),
        # Network management
        ("snmp", "SNMP", "UDP", "161", "Network management"),
        ("snmp-trap", "SNMP traps", "UDP", "162", "Network management"),
        ("syslog", "Syslog", "UDP", "514", "Network management"),
        ("radius", "RADIUS", "UDP", "1812-1813", "Network management"),
        ("ldap", "LDAP", "TCP", "389", "Network management"),
        ("ldaps", "LDAP over TLS", "TCP", "636", "Network management"),
        ("kerberos", "Kerberos", "TCP/UDP", "88", "Network management"),
        ("unifi-inform", "UniFi device inform", "TCP", "8080", "Network management"),
        ("unifi-stun", "UniFi STUN", "UDP", "3478", "Network management"),
        # Databases
        ("mysql", "MySQL / MariaDB", "TCP", "3306", "Databases"),
        ("postgres", "PostgreSQL", "TCP", "5432", "Databases"),
        ("mssql", "Microsoft SQL Server", "TCP", "1433", "Databases"),
        ("redis", "Redis", "TCP", "6379", "Databases"),
        ("mongodb", "MongoDB", "TCP", "27017", "Databases"),
        ("influxdb", "InfluxDB", "TCP", "8086", "Databases"),
        # Games & other
        ("xbox", "Xbox Live", "UDP", "3074", "Games"),
        ("psn", "PlayStation Network", "TCP", "3478-3480", "Games"),
        ("steam", "Steam", "UDP", "27000-27100", "Games"),
    ]
]
SERVICE_BY_ID = {s["id"]: s for s in SERVICES}

PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"]

# Starting points; each fills the rule list, which can then be edited.
TEMPLATES: list[dict] = [
    {
        "id": "guest",
        "name": "Guest: internet only",
        "description": "Addresses, DNS and the web; nothing local.",
        "rules": [
            {"action": "allow", "service": "dhcp", "dest": {"kind": "any"}},
            {"action": "allow", "service": "dns", "dest": {"kind": "gateway"}},
            {"action": "allow", "service": "ntp", "dest": {"kind": "internet"}},
            {"action": "block", "service": "any", "dest": {"kind": "local"}},
            {"action": "allow", "service": "any", "dest": {"kind": "internet"}},
        ],
    },
    {
        "id": "iot",
        "name": "IoT: Home Assistant + internet basics",
        "description": "Talks to Home Assistant, gets time and DNS; nothing else local.",
        "rules": [
            {"action": "allow", "service": "dhcp", "dest": {"kind": "any"}},
            {"action": "allow", "service": "dns", "dest": {"kind": "gateway"}},
            {"action": "allow", "service": "ntp", "dest": {"kind": "internet"}},
            {"action": "allow", "service": "any", "dest": {"kind": "ha"}},
            {"action": "allow", "service": "https", "dest": {"kind": "internet"}},
        ],
    },
    {
        "id": "isolated",
        "name": "Isolated: internet only, no local devices",
        "description": "Like guest but with no local DNS (uses the internet).",
        "rules": [
            {"action": "allow", "service": "dhcp", "dest": {"kind": "any"}},
            {"action": "block", "service": "any", "dest": {"kind": "local"}},
            {"action": "allow", "service": "any", "dest": {"kind": "internet"}},
        ],
    },
    {"id": "open", "name": "No rules (VLAN only)", "description": "Today's behaviour: the gateway firewall decides.", "rules": []},
]

DEST_KINDS = {
    "any": "anywhere",
    "internet": "the internet (not local addresses)",
    "local": "any local address",
    "gateway": "the gateway",
    "ha": "Home Assistant",
    "network": "a network",
    "cidr": "an address or range",
}

# Cirrus's built-in service ports (Unified Access > Policy groups > Service ports), as read from Cirrus on
# 2026-11-25. Used when the live list can't be read; the live list also includes ports the user added.
CIRRUS_DEFAULT_PORTS: list[dict] = [
    {"protocol": p, "name": n, "startPort": a, "endPort": None}
    for p, n, a in [
        ("TCP", "IRC (6666)", 6666), ("TCP", "NNTP (119)", 119), ("TCP", "IPX (213)", 213), ("TCP", "IRC (6668)", 6668),
        ("TCP", "NNTP-SSL (563)", 563), ("TCP", "Lotus ccmail (3264)", 3264), ("TCP", "Finger (79)", 79),
        ("TCP", "WinFrame-ICA (1494)", 1494), ("TCP", "America On-Line (5190)", 5190), ("TCP", "POP2 (109)", 109),
        ("TCP", "Lotus Notes (1352)", 1352), ("TCP", "Gnutella Service (6346)", 6346), ("TCP", "News (2009)", 2009),
        ("TCP", "BGP (179)", 179), ("TCP", "NetBIOS Session Service (139)", 139), ("TCP", "IMAP (143)", 143),
        ("TCP", "Microsoft SQL Server 6.0 (1433)", 1433), ("TCP", "Oracle SQL Net (1525)", 1525), ("TCP", "IRC (6667)", 6667),
        ("TCP", "TELNET (23)", 23), ("TCP", "IRC (6669)", 6669), ("TCP", "LDAP (389)", 389), ("TCP", "Kerberos (750)", 750),
        ("TCP", "Oracle SQL Net (1521)", 1521), ("TCP", "HTTP (80)", 80), ("TCP", "HylaFAX (4559)", 4559), ("TCP", "SMTP (25)", 25),
        ("TCP", "LDAP-SSL (636)", 636), ("TCP", "Napster (8875)", 8875), ("TCP", "NetBIOS Name Service (137)", 137),
        ("TCP", "HTTP-alt (8080)", 8080), ("TCP", "Ident (113)", 113), ("TCP", "POP3 over SSL (995)", 995), ("TCP", "IRC (6665)", 6665),
        ("TCP", "POP3 (110)", 110), ("TCP", "NetBIOS Datagram Service (138)", 138), ("TCP", "SMTP over SSL (465)", 465),
        ("TCP", "DNS (53)", 53), ("TCP", "VDOLive (7000)", 7000), ("TCP", "Novell Netware (396)", 396), ("TCP", "FTP (21)", 21),
        ("TCP", "Real Time Streaming Protocol (554)", 554), ("TCP", "HTTP-SSL (443)", 443), ("TCP", "Gnutella Router (6347)", 6347),
        ("UDP", "NetBIOS Datagram (138)", 138), ("UDP", "StreamWorks (1558)", 1558), ("UDP", "NetBIOS Name Service (137)", 137),
        ("UDP", "Bootp client (68)", 68), ("UDP", "SNMP Trap (162)", 162), ("UDP", "NetBIOS Session (139)", 139),
        ("UDP", "RADIUS (1812)", 1812), ("UDP", "DNS (53)", 53), ("UDP", "RIP Routing Information Protocol (520)", 520),
        ("UDP", "InterNet Phone (22555)", 22555), ("UDP", "Bootp server (67)", 67), ("UDP", "TFTP (69)", 69),
        ("UDP", "RADIUS Accounting (1813)", 1813), ("UDP", "NTP Network Time protocol (123)", 123), ("UDP", "TACACS (49)", 49),
        ("UDP", "SNMP (161)", 161),
    ]
]
IN_CIRRUS = "In Cirrus"
MORE_CIRRUS = "More Cirrus services"
NEW_SUFFIX = " (added to Cirrus when used)"


def _port_index(ports: list[dict]) -> dict[tuple[str, int, int], str]:
    """(protocol, start, end) -> Cirrus service port name."""
    out: dict[tuple[str, int, int], str] = {}
    for p in ports or []:
        try:
            a = int(p["startPort"])
            b = int(p.get("endPort") or a)
        except (KeyError, TypeError, ValueError):
            continue
        out.setdefault((str(p.get("protocol") or "").upper(), a, b), p.get("name") or f"{a}")
    return out


def _parts(svc: dict) -> list[tuple[str, int, int]]:
    protos = ["TCP", "UDP"] if svc["proto"] == "TCP/UDP" else [svc["proto"]] if svc["proto"] in ("TCP", "UDP") else []
    return [(p, a, b) for p in protos for a, b in (_ports(svc["ports"]) or [])]


def catalogue(ports: list[dict]) -> list[dict]:
    """The designer's service list: Cirrus's own service ports first (our friendly entries when every port they
    need already exists in Cirrus, then the rest of Cirrus's list), then our entries that would add new ports."""
    idx = _port_index(ports)
    used: set[tuple[str, int, int]] = set()
    have, new = [], []
    for s in SERVICES:
        parts = _parts(s)
        missing = [p for p in parts if p not in idx]
        if s["proto"] == "ICMP" or not missing:
            used.update(parts)
            have.append({**s, "group": IN_CIRRUS, "in_cirrus": True, "cirrus_names": [idx[p] for p in parts]})
        else:
            new.append({**s, "group": s["group"] + NEW_SUFFIX, "in_cirrus": False,
                        "adds": [f"{p} {a}" if a == b else f"{p} {a}-{b}" for p, a, b in missing]})
    more = []
    for (proto, a, b), pname in idx.items():
        if (proto, a, b) in used:
            continue
        more.append({"id": f"cp:{proto}:{a}-{b}", "name": re.sub(r"\s*\([\d\-]+\)$", "", pname) or pname, "proto": proto,
                     "ports": str(a) if a == b else f"{a}-{b}", "group": MORE_CIRRUS, "in_cirrus": True, "cirrus_names": [pname]})
    more.sort(key=lambda x: x["name"].lower())
    return have + more + new


NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
NAME_MAX = 32  # Cirrus doesn't publish a limit; AOS policy names are kept short to be safe


def service_search(iana: dict[str, str], query: str, limit: int = 25, services: list[dict] | None = None) -> list[dict]:
    """Catalogue entries (Cirrus's and ours) plus IANA registry ports matching a name or port number."""
    q = (query or "").strip().lower()
    if not q:
        return []
    def rank(name: str, ports: str) -> int:
        n = name.lower()
        return 0 if q == ports or n == q else 1 if n.startswith(q) else 2 if re.search(rf"\b{re.escape(q)}", n) else 3

    out = sorted((s for s in (services or SERVICES) if q in s["name"].lower() or q == s["ports"] or q in s["id"]),
                 key=lambda s: rank(s["name"], s["ports"]))
    hits = []
    for port, name in iana.items():
        if (q == port or q in (name or "").lower()) and not any(s["ports"] == port for s in out):
            hits.append({"id": f"iana:{port}", "name": f"{name} (IANA)", "proto": "TCP", "ports": port, "group": "IANA registry", "in_cirrus": False})
    hits.sort(key=lambda h: (rank(h["name"][:-7], h["ports"]), int(h["ports"])))
    return (out + hits)[:limit]


def _ports(text: str) -> list[tuple[int, int]] | None:
    """'80,443' / '67-68' / '22' -> [(80,80),(443,443)] ; None when invalid."""
    out = []
    for part in str(text or "").replace(" ", "").split(","):
        if not part:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            return None
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= b <= 65535):
            return None
        out.append((a, b))
    return out


def _service(rule: dict, iana: dict[str, str], extra: dict[str, dict] | None = None) -> dict | None:
    sid = rule.get("service") or "any"
    if sid == "any":
        return {"id": "any", "name": "anything", "proto": "", "ports": ""}
    if sid == "custom":
        c = rule.get("custom") or {}
        proto = str(c.get("proto") or "TCP").upper()
        return {"id": "custom", "name": c.get("name") or "", "proto": proto, "ports": str(c.get("ports") or "")}
    if sid.startswith("iana:"):
        port = sid[5:]
        proto = str((rule.get("custom") or {}).get("proto") or "TCP/UDP").upper()
        return {"id": sid, "name": iana.get(port, f"port {port}"), "proto": proto, "ports": port}
    return SERVICE_BY_ID.get(sid) or (extra or {}).get(sid)


def _svc_label(s: dict) -> str:
    if s["id"] == "any":
        return "anything"
    if s["proto"] == "ICMP":
        return s["name"]
    if not s["name"]:
        return f"{s['proto']} {s['ports']}"
    return f"{s['name']} ({s['proto']} {s['ports']})" if s["ports"] else s["name"]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:12] or "rule"


def _mask(net: ipaddress.IPv4Network) -> tuple[str, str]:
    return str(net.network_address), str(net.netmask)


def build_preview(design: dict, ctx: dict) -> dict:
    """design: {name, vlan, targets:[target ids], rules:[{action, service, custom, dest:{kind, network_id, cidr}}],
               default_deny (default true: block everything the rules don't allow, like a firewall)}
    ctx: {org_id, networks, targets:[{id, kind, name, group_id|device_mac, device_sn, site_id, devices?}], unps:[names],
          vlans:[ints], ha_ip, iana}
    Returns {ok, errors, warnings, notes, summary, requests}. Sends nothing."""
    errors: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []
    iana = ctx.get("iana") or {}
    org = ctx.get("org_id") or "{orgId}"
    base = f"/ov/v1/organizations/{org}/network-configuration"
    cirrus_ports = ctx.get("service_ports") or CIRRUS_DEFAULT_PORTS
    port_idx = _port_index(cirrus_ports)
    extra = {s["id"]: s for s in catalogue(cirrus_ports) if s["id"].startswith("cp:")}
    nets = {n["id"]: n for n in ctx.get("networks") or []}

    name = str(design.get("name") or "").strip()
    if not name:
        errors.append("Give the UNP a name.")
    elif not NAME_RE.match(name):
        errors.append("Use letters, numbers, '-', '_' or '.' in the name (no spaces).")
    elif len(name) > NAME_MAX:
        warnings.append(f"The name is longer than {NAME_MAX} characters; switches may truncate or reject it.")
    if name and name.lower() in {u.lower() for u in ctx.get("unps") or []}:
        errors.append(f"A UNP called {name} already exists in Cirrus.")

    vlan = design.get("vlan")
    try:
        vlan = int(vlan) if vlan not in (None, "", "ssid") else None
    except (TypeError, ValueError):
        errors.append("The VLAN must be a number.")
        vlan = None
    if vlan is not None and not 1 <= vlan <= 4094:
        errors.append("The VLAN must be between 1 and 4094.")
    # Several networks can share a VLAN number (an ISP's WAN VLAN, say): prefer the one with a private subnet.
    cands = [n for n in nets.values() if vlan and n.get("vlan") == vlan]
    cands.sort(key=lambda n: (not ipaddress.IPv4Network(n["cidr"]).is_private if n.get("cidr") else True, not n.get("gateway")))
    vnet = cands[0] if cands else None
    if len(cands) > 1:
        warnings.append(f"VLAN {vlan} is used by more than one gateway network ({', '.join(n['name'] + ' ' + n['cidr'] for n in cands)}). "
                        f"Rules aimed at 'the gateway' use {vnet['name']} ({vnet.get('gateway') or 'no gateway'}); check that's the right one.")
    if vlan and not vnet:
        warnings.append(f"No network on the gateway uses VLAN {vlan}: devices would get no address unless something else serves it.")
    if vlan and vlan not in set(ctx.get("vlans") or []):
        warnings.append(f"VLAN {vlan} isn't configured on your switches in Cirrus yet; it must exist (and be tagged towards the APs and the gateway) first.")

    by_id = {t["id"]: t for t in ctx.get("targets") or []}
    targets = [by_id[t] for t in design.get("targets") or [] if t in by_id]
    if not targets:
        errors.append("Pick at least one switch or AP group to apply it to.")
    if vlan is None and any(t["kind"] != "AP group" for t in targets):
        errors.append("A switch or device group assignment needs a VLAN (only AP groups can leave it to the SSID).")
    for t in targets:
        if t.get("devices") == 0:
            warnings.append(f"{t['kind']} '{t['name']}' has no devices in it, so this assignment would not reach any switch or AP.")
    if vlan is None and targets:
        notes.append("No VLAN: on AP groups devices stay on their SSID's VLAN (Cirrus stores this as VLAN 0).")

    # ---- rules -> policies
    gw_ip = (vnet or {}).get("gateway")
    ha_ip = ctx.get("ha_ip")
    summary: list[str] = []
    policies: list[dict] = []
    rules = design.get("rules") or []
    local_blocked = False
    for i, rule in enumerate(rules, 1):
        svc = _service(rule, iana, extra)
        if not svc:
            errors.append(f"Rule {i}: unknown service.")
            continue
        if svc["proto"] not in ("", "ICMP") and svc["id"] != "any":
            if svc["proto"] not in ("TCP", "UDP", "TCP/UDP"):
                errors.append(f"Rule {i}: protocol must be TCP, UDP or TCP/UDP.")
                continue
            if _ports(svc["ports"]) is None or not svc["ports"]:
                errors.append(f"Rule {i}: ports must look like 22, 67-68 or 80,443.")
                continue
        action = "Accept" if rule.get("action") == "allow" else "Drop"
        dest = rule.get("dest") or {"kind": "any"}
        kind = dest.get("kind") or "any"
        dests: list[tuple[str, ipaddress.IPv4Network | None]] = []  # (label, network or None = anywhere)
        label = DEST_KINDS.get(kind, kind)
        if kind == "any":
            dests = [("anywhere", None)]
        elif kind == "local":
            dests = [(r, ipaddress.IPv4Network(r)) for r in PRIVATE_RANGES]
        elif kind == "internet":
            # An ACL can't say "not local": block the same service to local ranges first, then allow it anywhere.
            dests = [("anywhere", None)]
        elif kind == "gateway":
            if not gw_ip:
                errors.append(f"Rule {i}: the gateway's address isn't known (pick a VLAN that has a gateway network).")
                continue
            dests = [(f"the gateway {gw_ip}", ipaddress.IPv4Network(f"{gw_ip}/32"))]
        elif kind == "ha":
            if not ha_ip:
                errors.append(f"Rule {i}: Home Assistant's address isn't known.")
                continue
            dests = [(f"Home Assistant {ha_ip}", ipaddress.IPv4Network(f"{ha_ip}/32"))]
        elif kind == "network":
            n = nets.get(dest.get("network_id"))
            if not n:
                errors.append(f"Rule {i}: pick a network.")
                continue
            dests = [(f"{n['name']} {n['cidr']}", ipaddress.IPv4Network(n["cidr"]))]
            label = f"{n['name']} ({n['cidr']})"
        elif kind == "cidr":
            try:
                net = ipaddress.IPv4Network(str(dest.get("cidr") or "").strip(), strict=False)
            except ValueError:
                errors.append(f"Rule {i}: '{dest.get('cidr')}' isn't an address or range like 192.168.1.10 or 10.0.0.0/8.")
                continue
            dests = [(str(net), net)]
            label = str(net)
        summary.append(f"{i}. {'Allow' if action == 'Accept' else 'Block'} {_svc_label(svc)} to {label}")
        protos = ["TCP", "UDP"] if svc["proto"] == "TCP/UDP" else [svc["proto"]] if svc["proto"] else [None]
        ranges = (_ports(svc["ports"]) or [None]) if svc["proto"] in ("TCP", "UDP", "TCP/UDP") else [None]
        combos = [(p, r) for p in protos for r in ranges]  # a condition holds one protocol and one port range
        if kind == "local" and svc["id"] == "any" and action == "Drop":
            local_blocked = True
        if kind == "internet" and not local_blocked:  # an earlier "block anything local" already covers it
            for net in PRIVATE_RANGES:
                for proto, rng in combos:
                    policies.append(_policy(name, len(policies) + 1, svc, proto, rng, "Drop", ipaddress.IPv4Network(net),
                                            f"rule {i}: keep {_svc_label(svc)} off local addresses"))
        for _lbl, net in dests:
            for proto, rng in combos:
                policies.append(_policy(name, len(policies) + 1, svc, proto, rng, action, net, f"rule {i}"))

    warnings.extend(_shadowed(rules, gw_ip, ha_ip, nets, iana, extra))
    ends_blocked = bool(rules) and _is_block_all(rules[-1])
    default_deny = design.get("default_deny", True) is not False
    if not rules:
        notes.append("No access rules: the UNP only picks the VLAN, as your UNPs do today. The gateway firewall decides the rest.")
    elif default_deny and not ends_blocked and any(_allows_all(r) for r in rules):
        notes.append("A rule already allows anything to the internet, so nothing would be left for 'Block everything else' to block; no deny rule is added.")
    elif default_deny and not ends_blocked:
        # Like a firewall's implicit deny: switches allow unmatched traffic, so the deny has to be a real last rule.
        any_svc = {"id": "custom", "name": "deny all", "proto": "", "ports": ""}
        policies.append(_policy(name, len(policies) + 1, any_svc, None, None, "Drop", None, "block everything else (implicit deny)"))
        summary.append(f"{len(rules) + 1}. Then block everything else (implicit deny)")
    elif not default_deny and not ends_blocked:
        notes.append("Anything not matched by a rule is allowed (the switches' default). Turn on 'Block everything else' for an allow-list.")
    if rules and (default_deny or ends_blocked):
        allows = [r for r in rules if r.get("action") == "allow"]
        if not any(r.get("service") in ("dhcp", "any") and (r.get("dest") or {}).get("kind", "any") in ("any", "internet") for r in allows):
            warnings.append("Everything else is blocked but no rule allows DHCP to anywhere, so devices won't get an address.")
        if not any(r.get("service") in ("dns", "dot", "any") for r in allows):
            warnings.append("Everything else is blocked but no rule allows DNS, so devices can't look up names.")
    if len(policies) > 60:
        warnings.append(f"{len(policies)} switch rules: large lists use more ACL space on the switches and APs.")

    # OmniSwitch applies the matching rule with the highest precedence, so number them counting down from the
    # first rule; every switch rule gets its own number (equal numbers leave the order to the switch).
    total = len(policies)
    rule_prec: dict[str, list[int]] = {}  # design rule number ("deny" for the implicit deny) -> [highest, lowest]
    for idx, p in enumerate(policies):
        prec = (total - idx) * 10
        p["policy"]["precedence"] = prec
        m = re.match(r"rule (\d+)", p["why"])
        key = m.group(1) if m else "deny"
        lo_hi = rule_prec.setdefault(key, [prec, prec])
        lo_hi[0], lo_hi[1] = max(lo_hi[0], prec), min(lo_hi[1], prec)

    # Every port range uses Cirrus's own service port when one matches; otherwise a new one is created first,
    # named the way Cirrus's own form names them ("MQTT (1883)", "Plex (32400)", "DHCP (67-68)").
    new_ports: dict[tuple[str, int, int], dict] = {}
    for p in policies:
        svc_name = p.pop("svc_name")
        l4 = p["policy"]["condition"].get("l4Services") or {}
        rng = l4.get("dstPortRange")
        if not rng:
            continue
        a, b = (int(x) for x in rng.split(":"))
        key = (l4["protocol"], a, b)
        if key not in port_idx and key not in new_ports:
            label = re.sub(r"\s*\(.*\)$", "", svc_name).strip() or "Custom"
            new_ports[key] = {"name": f"{label} ({a})" if a == b else f"{label} ({a}-{b})", "protocol": key[0],
                              "startPort": a, "endPort": None if a == b else b}
        l4["dstPortName"] = port_idx.get(key) or new_ports[key]["name"]
    if new_ports:
        notes.append(f"{len(new_ports)} service port(s) aren't in Cirrus yet and would be added: "
                     + ", ".join(f"{v['name']} {v['protocol']}" for v in new_ports.values()) + ".")

    assignment = _assignment(targets, vlan)
    plist = f"{name}-rules" if name else "-rules"
    requests: list[dict] = []
    for v in new_ports.values():
        # Cirrus's web app uses /api/organizations/... (not the documented /ov/v1) for service ports.
        requests.append({"method": "POST", "path": f"/organizations/{org}/network-configuration/service-ports",
                         "purpose": f"Add the service port {v['name']} to Cirrus", "body": v})
    pa = _policy_assignment(targets)
    for p in policies:
        requests.append({"method": "POST", "path": f"{base}/unified-policies", "purpose": f"Switch rule: {p.pop('why')}",
                         "body": {"policy": p["policy"]}})  # hand-built policies carry no assignment of their own
    if policies:
        requests.append({"method": "POST", "path": f"{base}/unified-policy-lists", "purpose": "Group the rules into one policy list",
                         "body": {"policyList": {"name": plist, "policies": [p["policy"]["name"] for p in policies]}, "assignment": pa}})
    # Matches the "Test" UNP built by hand: an existing list referenced by name with its policy names.
    arp = {"arpName": name, "useExistingPolicyList": bool(policies), "useExistingAclAndQos": False,
           "useExistingLocationPolicy": True, "useExistingPeriodPolicy": True}
    if policies:
        arp["policyList"] = {"name": plist, "policies": [p["policy"]["name"] for p in policies]}
    requests.append({"method": "POST", "path": f"{base}/arps", "purpose": "Create the UNP (Access Role Profile) and map its VLAN on each target",
                     "body": {"arp": arp, "assignment": assignment}})
    notes.append("Request shapes are checked against a UNP, policy list and policies built by hand in Cirrus; the POST bodies themselves are untested until a write step exists.")
    notes.append("Changes reach the switches at their next rediscovery, which can take up to an hour.")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "summary": summary,
        "network": vnet and {k: vnet.get(k) for k in ("name", "cidr", "gateway")},
        "policy_count": len(policies),
        "rule_precedence": rule_prec,
        "requests": requests if not errors else [],
    }


def _dest_nets(rule: dict, gw_ip: str | None, ha_ip: str | None, nets: dict) -> list | str | None:
    """A rule's destinations: "any", "internet", a list of networks, or None if unknown."""
    d = rule.get("dest") or {"kind": "any"}
    k = d.get("kind") or "any"
    try:
        if k in ("any", "internet"):
            return k
        if k == "local":
            return [ipaddress.IPv4Network(r) for r in PRIVATE_RANGES]
        if k == "gateway" and gw_ip:
            return [ipaddress.IPv4Network(f"{gw_ip}/32")]
        if k == "ha" and ha_ip:
            return [ipaddress.IPv4Network(f"{ha_ip}/32")]
        if k == "network" and d.get("network_id") in nets:
            return [ipaddress.IPv4Network(nets[d["network_id"]]["cidr"])]
        if k == "cidr":
            return [ipaddress.IPv4Network(str(d.get("cidr") or "").strip(), strict=False)]
    except ValueError:
        return None
    return None


def _is_block_all(rule: dict) -> bool:
    return rule.get("action") != "allow" and (rule.get("service") or "any") == "any" and (rule.get("dest") or {}).get("kind", "any") == "any"


def _allows_all(rule: dict) -> bool:
    """An allow of anything to anywhere or to the internet: nothing reaches a later catch-all deny."""
    return rule.get("action") == "allow" and (rule.get("service") or "any") == "any" and (rule.get("dest") or {}).get("kind", "any") in ("any", "internet")


def _shadowed(rules: list[dict], gw_ip, ha_ip, nets: dict, iana: dict, extra: dict | None = None) -> list[str]:
    """Rules that can never match because an earlier 'anything' rule already catches all their traffic."""
    out = []
    for j, later in enumerate(rules):
        ld = _dest_nets(later, gw_ip, ha_ip, nets)
        if ld is None:
            continue
        svc = _service(later, iana, extra)
        what = _svc_label(svc) if svc else "its service"
        seen_nets: list = []  # destinations already decided for all traffic by earlier rules
        seen_internet = False
        for i, early in enumerate(rules[:j]):
            if (early.get("service") or "any") != "any":
                continue
            ed = _dest_nets(early, gw_ip, ha_ip, nets)
            covered = (
                ed == "any"
                or (ed == "internet" and ld == "internet")
                or (isinstance(ed, list) and isinstance(ld, list) and all(any(n.subnet_of(e) for e in ed) for n in ld))
            )
            if covered:
                verb = "allows" if early.get("action") == "allow" else "blocks"
                out.append(f"Rule {j + 1} ({what}) never matches: rule {i + 1} already {verb} all of that traffic. Move it above rule {i + 1}.")
                break
            if ed == "internet":
                seen_internet = True
            elif isinstance(ed, list):
                seen_nets.extend(ed)
            local_done = all(any(ipaddress.IPv4Network(r).subnet_of(e) for e in seen_nets) for r in PRIVATE_RANGES)
            if ld == "any" and seen_internet and local_done:
                out.append(f"Rule {j + 1} ({what}) never matches: the rules above it already decide all local and internet traffic. Move it higher.")
                break
    return out


def _policy(unp: str, n: int, svc: dict, proto: str | None, rng: tuple[int, int] | None, action: str,
            dst: ipaddress.IPv4Network | None, why: str) -> dict:
    cond: dict[str, Any] = {}
    if dst is not None and dst.prefixlen:
        addr, mask = _mask(dst)
        cond["l3Ips"] = {"dstIpAddress": addr, "dstMask": mask}
    if svc["proto"] == "ICMP":
        cond["l4Services"] = {"protocol": "ICMP"}
    elif proto:
        cond["l4Services"] = {"protocol": proto}
        if rng:
            a, b = rng
            cond["l4Services"]["dstPortRange"] = f"{a}:{b}"  # Cirrus stores "22:22" even for one port
    if not cond:
        # "Anything to anywhere": Cirrus stores it as 0.0.0.0/0 both ways (from a hand-built "Drop everything").
        cond["l3Ips"] = {"srcIpAddress": "0.0.0.0", "srcMask": "0.0.0.0", "dstIpAddress": "0.0.0.0", "dstMask": "0.0.0.0"}
    pol = {
        "name": f"{unp}-{n:02d}-{_slug(svc['name'] if svc['id'] == 'custom' and svc['name'] else svc['id'])}"[:NAME_MAX],
        "condition": cond,
        # Shapes match policies hand-built in Cirrus ("Block SSH" and "Allow ICMP"): action.qos with DROP/ACCEPT,
        # YES/IGNORE flags. Cirrus leaves reflexive at IGNORE for allow rules too, so the designer does the same.
        "action": {"qos": {"disposition": action.upper(), "priority": 0}},
        "advancedOptions": {"enabled": "YES", "reflexive": "IGNORE",
                            "logMatches": "NO", "save": "YES", "sendTrap": "IGNORE", "defaultList": "NO"},
        "validityPeriod": {"type": "ALL_THE_TIME"},
    }
    return {"policy": pol, "why": why, "svc_name": svc["name"] if svc["name"] else f"{proto or ''} port".strip()}


def _assignment(targets: list[dict], vlan: int | None) -> dict:
    # Only the fields the API spec lists for a write (site and serial are read-side extras).
    mapping = {"mappingType": "Vlan", "useExistingTunnel": False, "vlans": [str(vlan or 0)]}
    groups = [{"deviceGroupId": t["group_id"], "vlanTunnelMapping": mapping} for t in targets if t.get("group_id")]
    devices = [{"deviceMac": t["device_mac"], "vlanTunnelMapping": mapping} for t in targets if t.get("device_mac")]
    mode = "DEVICE_GROUP_AND_DEVICE" if groups and devices else "DEVICE_GROUP" if groups else "DEVICE_MAC"
    return {"deviceGroups": groups, "devices": devices, "mode": mode}


def _policy_assignment(targets: list[dict]) -> dict:
    a = _assignment(targets, None)
    for x in (*a["deviceGroups"], *a["devices"]):
        x.pop("vlanTunnelMapping", None)
    return a
