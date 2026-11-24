"""The UniFi gateway's firewall, decoded for display (read-only).

Two models exist:
  * zone-based (UniFi Network 9+): networks sit in zones; ordered policies apply between a source and a
    destination zone. Summarised as a zone x zone matrix plus the rules behind each cell.
  * the older rule sets (LAN_IN, WAN_IN, ...): listed per rule set.
Plus traffic rules (the simple app / device blocks) and port forwards, since they also decide what gets through.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .mac_table import norm_mac

ZONE_KEY_NAMES = {
    "internal": "Internal",
    "external": "External",
    "gateway": "Gateway",
    "vpn": "VPN",
    "hotspot": "Hotspot",
    "dmz": "DMZ",
}
PROTO = {"all": "any protocol", "tcp_udp": "TCP/UDP", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6"}


def _s(v: Any) -> str:
    return str(v).strip() if v not in (None, "") else ""


def _net_index(networks: list[dict]) -> dict[str, dict]:
    out = {}
    for n in networks or []:
        nid = n.get("_id")
        if not nid:
            continue
        out[nid] = {
            "id": nid,
            "name": n.get("name") or nid,
            "vlan": n.get("vlan") if n.get("vlan_enabled") or n.get("vlan") else None,
            "cidr": _cidr(n.get("ip_subnet")),
            "purpose": n.get("purpose"),
        }
    return out


def _cidr(subnet: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Interface(str(subnet)).network) if subnet else None
    except ValueError:
        return None


def _group_index(groups: list[dict]) -> dict[str, dict]:
    return {
        g["_id"]: {"name": g.get("name") or g["_id"], "type": g.get("group_type"), "members": g.get("group_members") or []}
        for g in groups or []
        if g.get("_id")
    }


def _ports(end: dict, groups: dict[str, dict]) -> str:
    kind = (end.get("port_matching_type") or "ANY").upper()
    if kind == "SPECIFIC" and end.get("port"):
        txt = f"port {end['port']}"
    elif kind == "OBJECT" and end.get("port_group_id"):
        g = groups.get(end["port_group_id"]) or {}
        txt = f"ports {g.get('name') or 'group'}" + (f" ({', '.join(map(str, g['members']))})" if g.get("members") else "")
    else:
        return ""
    return ("not " if end.get("match_opposite_ports") else "") + txt


def _end_text(end: dict, nets: dict[str, dict], groups: dict[str, dict], names: dict[str, str]) -> str:
    """What one side of a zone policy matches, in words (the zone itself is shown separately)."""
    end = end or {}
    target = (end.get("matching_target") or "ANY").upper()
    neg = "not " if end.get("match_opposite_ips") or end.get("match_opposite_networks") else ""
    if target == "ANY":
        what = "anything"
    elif target == "IP":
        if (end.get("matching_target_type") or "").upper() == "OBJECT" and end.get("ip_group_id"):
            g = groups.get(end["ip_group_id"]) or {}
            what = f"{g.get('name') or 'address group'}" + (f" ({', '.join(map(str, g['members'][:6]))}{'…' if len(g['members']) > 6 else ''})" if g.get("members") else "")
        else:
            what = ", ".join(map(str, end.get("ips") or [])) or "addresses"
    elif target == "NETWORK":
        what = ", ".join((nets.get(i) or {}).get("name", i) for i in end.get("network_ids") or []) or "networks"
    elif target in ("CLIENT", "MAC"):
        macs = end.get("client_macs") or end.get("macs") or []
        what = ", ".join(names.get(norm_mac(m) or "", m) for m in macs) or "devices"
    elif target == "REGION":
        what = "countries " + ", ".join(end.get("regions") or [])
    elif target in ("DOMAIN", "WEB"):
        what = ", ".join(end.get("web_domains") or []) or "web domains"
    elif target == "APP":
        what = f"{len(end.get('app_ids') or [])} apps"
    elif target == "APP_CATEGORY":
        what = f"{len(end.get('app_category_ids') or [])} app categories"
    else:
        what = target.lower().replace("_", " ")
    ports = _ports(end, groups)
    return f"{neg}{what}{' · ' + ports if ports else ''}"


def _is_catch_all(p: dict) -> bool:
    src, dst = p.get("source") or {}, p.get("destination") or {}
    return (
        (src.get("matching_target") or "ANY").upper() == "ANY"
        and (dst.get("matching_target") or "ANY").upper() == "ANY"
        and (src.get("port_matching_type") or "ANY").upper() == "ANY"
        and (dst.get("port_matching_type") or "ANY").upper() == "ANY"
        and (p.get("protocol") or "all") == "all"
    )


def _state(p: dict) -> str:
    t = (p.get("connection_state_type") or "ALL").upper()
    if t == "RESPOND_ONLY":
        return "return traffic only"
    if t == "CUSTOM":
        return "states " + ", ".join(s.lower() for s in p.get("connection_states") or [])
    return ""


def parse_zone_policies(raw: dict, networks: list[dict], names: dict[str, str]) -> dict:
    nets = _net_index(networks)
    groups = _group_index(raw.get("groups"))
    zones = []
    zone_of_net: dict[str, str] = {}
    for z in raw.get("zones") or []:
        zid = z.get("_id")
        if not zid:
            continue
        zn = [nets[i] for i in z.get("network_ids") or [] if i in nets]
        for n in zn:
            zone_of_net[n["id"]] = zid
        zones.append(
            {
                "id": zid,
                "name": z.get("name") or ZONE_KEY_NAMES.get(z.get("zone_key"), zid),
                "key": z.get("zone_key"),
                "builtin": bool(z.get("default_zone") or z.get("zone_key")),
                "networks": zn,
            }
        )
    zname = {z["id"]: z["name"] for z in zones}
    policies = []
    for p in raw.get("policies") or []:
        src, dst = p.get("source") or {}, p.get("destination") or {}
        proto = p.get("protocol") or "all"
        policies.append(
            {
                "id": p.get("_id"),
                "name": p.get("name") or "(unnamed)",
                "description": _s(p.get("description")),
                "enabled": p.get("enabled", True) is not False,
                "action": (p.get("action") or "").upper() or "?",
                "index": p.get("index") if isinstance(p.get("index"), int) else 1_000_000,
                "predefined": bool(p.get("predefined")),
                "src_zone": src.get("zone_id"),
                "dst_zone": dst.get("zone_id"),
                "src": _end_text(src, nets, groups, names),
                "dst": _end_text(dst, nets, groups, names),
                "protocol": PROTO.get(proto, proto) if proto != "all" else "",
                "state": _state(p),
                "ip_version": p.get("ip_version"),
                "logging": bool(p.get("logging")),
                "schedule": ((p.get("schedule") or {}).get("mode") or "ALWAYS").upper(),
                "catch_all": _is_catch_all(p),
                "allow_return": bool(p.get("create_allow_respond")),
            }
        )
    policies.sort(key=lambda x: (x["src_zone"] or "", x["dst_zone"] or "", x["index"]))

    matrix: dict[str, dict[str, dict]] = {}
    for z1 in zones:
        row = {}
        for z2 in zones:
            rules = sorted(
                (p for p in policies if p["src_zone"] == z1["id"] and p["dst_zone"] == z2["id"] and p["enabled"]),
                key=lambda x: x["index"],
            )
            default = next((p for p in reversed(rules) if p["catch_all"] and not p["state"]), None)
            verdict = default["action"] if default else ("ALLOW" if any(r["action"] == "ALLOW" for r in rules) else "NONE")
            ret_only = any(p["catch_all"] and p["action"] == "ALLOW" and p["state"] == "return traffic only" for p in rules)
            exceptions = [p for p in rules if p is not default and p["action"] != verdict and not (p["catch_all"] and p["state"])]
            row[z2["id"]] = {
                "verdict": verdict,
                "return_only": ret_only and verdict != "ALLOW",
                "exceptions": len(exceptions),
                "custom": sum(1 for p in rules if not p["predefined"]),
                "rules": [p["id"] for p in rules],
            }
        matrix[z1["id"]] = row
    for p in policies:
        p["src_zone_name"] = zname.get(p["src_zone"], p["src_zone"])
        p["dst_zone_name"] = zname.get(p["dst_zone"], p["dst_zone"])
    return {"zones": zones, "policies": policies, "matrix": matrix, "zone_of_network": zone_of_net}


def parse_legacy_rules(raw: dict, networks: list[dict]) -> list[dict]:
    nets = _net_index(networks)
    groups = _group_index(raw.get("groups"))

    def side(r: dict, pre: str) -> str:
        bits = []
        if r.get(f"{pre}_networkconf_id"):
            n = nets.get(r[f"{pre}_networkconf_id"]) or {}
            kind = (r.get(f"{pre}_networkconf_type") or "NETv4").replace("ADDRv4", " gateway address").replace("NETv4", "")
            bits.append(f"{n.get('name', r[pre + '_networkconf_id'])}{kind}")
        if r.get(f"{pre}_address"):
            bits.append(str(r[f"{pre}_address"]))
        for gid in r.get(f"{pre}_firewallgroup_ids") or []:
            g = groups.get(gid) or {}
            bits.append(f"{g.get('name', gid)}" + (f" ({', '.join(map(str, g.get('members', [])[:6]))})" if g.get("members") else ""))
        if r.get(f"{pre}_port"):
            bits.append(f"port {r[pre + '_port']}")
        return ", ".join(bits) or "anything"

    out = []
    for r in raw.get("rules") or []:
        states = [s for s in ("new", "established", "related", "invalid") if r.get(f"state_{s}")]
        out.append(
            {
                "id": r.get("_id"),
                "name": r.get("name") or "(unnamed)",
                "ruleset": r.get("ruleset") or "?",
                "index": r.get("rule_index") or 0,
                "enabled": r.get("enabled", True) is not False,
                "action": (r.get("action") or "").upper(),
                "protocol": "" if (r.get("protocol") or "all") == "all" else str(r.get("protocol")).upper(),
                "src": side(r, "src"),
                "dst": side(r, "dst"),
                "state": ", ".join(states),
                "logging": bool(r.get("logging")),
            }
        )
    out.sort(key=lambda x: (x["ruleset"], x["index"]))
    return out


def parse_traffic_rules(raw: dict, networks: list[dict], names: dict[str, str]) -> list[dict]:
    nets = _net_index(networks)
    out = []
    for r in raw.get("traffic_rules") or []:
        targets = []
        for t in r.get("target_devices") or []:
            tt = (t.get("type") or "").upper()
            if tt == "ALL_CLIENTS":
                targets.append("all devices")
            elif tt == "NETWORK":
                targets.append((nets.get(t.get("network_id")) or {}).get("name", "a network"))
            elif tt == "CLIENT":
                targets.append(names.get(norm_mac(t.get("client_mac")) or "", t.get("client_mac") or "a device"))
        what = (r.get("matching_target") or "").upper()
        detail = {
            "INTERNET": "the internet",
            "DOMAIN": ", ".join(d.get("domain", "") for d in r.get("domains") or []) or "domains",
            "IP": ", ".join(i.get("ip_or_subnet", "") for i in r.get("ip_addresses") or []) or "addresses",
            "APP": f"{len(r.get('app_ids') or [])} apps",
            "APP_CATEGORY": f"{len(r.get('app_category_ids') or [])} app categories",
            "REGION": "countries " + ", ".join(r.get("regions") or []),
            "LOCAL_NETWORK": ", ".join((nets.get(i) or {}).get("name", i) for i in r.get("network_ids") or []) or "local networks",
        }.get(what, what.lower())
        out.append(
            {
                "id": r.get("_id"),
                "name": r.get("description") or "(unnamed)",
                "enabled": r.get("enabled", True) is not False,
                "action": (r.get("action") or "").upper(),
                "who": ", ".join(targets) or "–",
                "what": detail,
                "schedule": ((r.get("schedule") or {}).get("mode") or "ALWAYS").upper(),
            }
        )
    return out


def parse_port_forwards(raw: dict) -> list[dict]:
    return [
        {
            "id": f.get("_id"),
            "name": f.get("name") or "(unnamed)",
            "enabled": f.get("enabled", True) is not False,
            "wan_port": f.get("dst_port"),
            "to": f"{f.get('fwd') or '?'}:{f.get('fwd_port') or f.get('dst_port') or ''}",
            "protocol": (f.get("proto") or "tcp_udp").replace("_", "/").upper(),
            "from": f.get("src") if f.get("src") not in (None, "", "any") else "anywhere",
        }
        for f in raw.get("port_forwards") or []
    ]


def build(raw: dict | None, networks: list[dict], known: list[dict], clients: dict[str, dict]) -> dict:
    """Everything the card's Firewall view shows."""
    if not raw:
        return {}
    names: dict[str, str] = {}
    for k in known or []:
        m = norm_mac(k.get("mac"))
        if m and (k.get("name") or k.get("hostname")):
            names[m] = k.get("name") or k.get("hostname")
    for m, c in (clients or {}).items():
        if m and m not in names and (c.get("name") or c.get("hostname")):
            names[m] = c.get("name") or c.get("hostname")
    out: dict = {"errors": raw.get("errors") or {}}
    if raw.get("zones") and raw.get("policies"):
        out["model"] = "zones"
        out.update(parse_zone_policies(raw, networks, names))
    elif raw.get("rules") is not None and "rules" not in (raw.get("errors") or {}):
        out["model"] = "legacy"
    else:
        out["model"] = None
    rules = parse_legacy_rules(raw, networks)
    if rules:
        out["rules"] = rules
    out["traffic_rules"] = parse_traffic_rules(raw, networks, names)
    out["port_forwards"] = parse_port_forwards(raw)
    return out


def network_reach(fw: dict, network_id: str) -> list[dict]:
    """For one UniFi network: what its zone may reach, per destination zone (used by the UNP view)."""
    if not fw or fw.get("model") != "zones":
        return []
    zid = (fw.get("zone_of_network") or {}).get(network_id)
    if not zid:
        return []
    row = (fw.get("matrix") or {}).get(zid) or {}
    return [
        {"zone": z["name"], "zone_id": z["id"], **row.get(z["id"], {})}
        for z in fw.get("zones") or []
        if z["id"] != zid or len(z.get("networks") or []) > 1
    ]
