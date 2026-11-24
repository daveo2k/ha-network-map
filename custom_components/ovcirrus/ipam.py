"""IP address management view: every subnet with its DHCP pool, reservations and what is using each address.

Read-only. Networks come from the UniFi gateway (subnet, VLAN, DHCP range) and, for routed VLANs UniFi does
not know, from the switches' IP interfaces in Cirrus. Addresses in use are pooled from every source the
integration already reads (UniFi clients and reservations, Cirrus sessions, switch ARP, manual devices, the
network devices themselves).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from .mac_table import norm_mac

# Subnets up to this many hosts get a full address list (so the card can show the free ones).
ENUMERATE_MAX = 1024


@dataclass
class Sighting:
    ip: str
    mac: str | None
    source: str  # "UniFi", "Cirrus", "UPAM", "ARP", "Manual", "Device", "Interface"
    online: bool = True
    name: str | None = None


@dataclass
class Reservation:
    ip: str
    mac: str
    name: str | None = None
    network_id: str | None = None


@dataclass
class Network:
    id: str
    name: str
    vlan: int | None
    net: ipaddress.IPv4Network
    gateway: str | None
    pool: tuple[str, str] | None  # DHCP start, stop
    source: str  # "UniFi" or "Cirrus"
    dhcp: bool = False
    extra: dict = field(default_factory=dict)


def _ip(value: Any) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(value).strip())
    except (ValueError, TypeError):
        return None


def parse_unifi_networks(rows: list[dict]) -> list[Network]:
    """UniFi networkconf -> networks that have an IPv4 subnet (WAN and VPN entries are skipped)."""
    out: list[Network] = []
    for row in rows or []:
        if row.get("purpose") in ("wan", "remote-user-vpn", "site-vpn", "vpn-client") or not row.get("ip_subnet"):
            continue
        if row.get("enabled") is False:
            continue
        try:
            iface = ipaddress.IPv4Interface(row["ip_subnet"])
        except ValueError:
            continue
        mode = row.get("dhcp_mode") or ("ENABLED" if row.get("dhcpd_enabled") else None)
        dhcp = str(mode or "").upper() in ("ENABLED", "SERVER", "TRUE") or bool(row.get("dhcpd_enabled"))
        start, stop = _ip(row.get("dhcpd_start")), _ip(row.get("dhcpd_stop"))
        vlan = row.get("vlan") if row.get("vlan_enabled", True) else None
        try:
            vlan = int(vlan) if vlan not in (None, "") else None
        except (TypeError, ValueError):
            vlan = None
        out.append(
            Network(
                id=str(row.get("_id") or row.get("name")),
                name=row.get("name") or str(iface.network),
                vlan=vlan if vlan else (1 if row.get("purpose") == "corporate" and not row.get("vlan_enabled") else None),
                net=iface.network,
                gateway=str(iface.ip) if iface.ip != iface.network.network_address else None,
                pool=(str(start), str(stop)) if dhcp and start and stop else None,
                source="UniFi",
                dhcp=dhcp,
            )
        )
    return out


def parse_cirrus_interfaces(rows: list[dict], vlans: dict[str, dict]) -> list[Network]:
    """Switch IP interfaces (one per routed VLAN) -> networks, for subnets the gateway does not serve."""
    out: list[Network] = []
    for row in rows or []:
        addr, mask = row.get("ipInterfaceAddress"), row.get("ipInterfaceMask")
        if not addr or not mask:
            continue
        try:
            iface = ipaddress.IPv4Interface(f"{addr}/{mask}")
        except ValueError:
            continue
        if iface.network.prefixlen >= 31 or iface.network.prefixlen == 0 or iface.ip.is_loopback or iface.ip.is_unspecified:
            continue
        vlan = row.get("ipInterfaceVlanID")
        try:
            vlan = int(vlan) if vlan not in (None, "") else None
        except (TypeError, ValueError):
            vlan = None
        name = (vlans.get(str(vlan)) or {}).get("name") if vlan else None
        out.append(
            Network(
                id=f"if-{iface.network}",
                name=name or row.get("ipInterfaceName") or str(iface.network),
                vlan=vlan,
                net=iface.network,
                gateway=str(iface.ip),
                pool=None,
                source="Cirrus",
                extra={"switch": row.get("name")},
            )
        )
    return out


def merge_networks(unifi: list[Network], cirrus: list[Network], vlans: dict[str, dict] | None = None) -> list[Network]:
    """UniFi wins for a subnet both know; the switch's interface address is kept as extra info.

    The gateway's own LAN is untagged on its side (UniFi calls it VLAN 1) while the switches carry it on a real
    VLAN: a Cirrus VLAN with the same name as the network gives the id the rest of the network uses.
    """
    by_name = {str(v.get("name") or "").strip().lower(): int(k) for k, v in (vlans or {}).items() if str(k).isdigit()}
    for n in unifi:
        if n.vlan in (None, 1) and by_name.get(n.name.strip().lower()):
            n.vlan = by_name[n.name.strip().lower()]
    seen = {n.net: n for n in unifi}
    out = list(unifi)
    for n in cirrus:
        if n.net in seen:
            seen[n.net].extra.setdefault("switch_ip", n.gateway)
            if seen[n.net].vlan is None:
                seen[n.net].vlan = n.vlan
            continue
        seen[n.net] = n
        out.append(n)
    return sorted(out, key=lambda n: (n.vlan if n.vlan is not None else 0, int(n.net.network_address)))


def _in_pool(ip: ipaddress.IPv4Address, pool: tuple[str, str] | None) -> bool:
    if not pool:
        return False
    return ipaddress.IPv4Address(pool[0]) <= ip <= ipaddress.IPv4Address(pool[1])


def build_ipam(
    networks: list[Network],
    sightings: list[Sighting],
    reservations: list[Reservation],
    names: dict[str, str] | None = None,
) -> dict:
    """Per network: pool usage and one row per address that is reserved or in use."""
    names = names or {}
    rows_by_net: dict[str, dict[str, dict]] = {n.id: {} for n in networks}
    unmatched: dict[str, dict] = {}

    def net_for(ip: ipaddress.IPv4Address) -> Network | None:
        best = None
        for n in networks:
            if ip in n.net and (best is None or n.net.prefixlen > best.net.prefixlen):
                best = n
        return best

    def row(ip_s: str) -> dict | None:
        ip = _ip(ip_s)
        if ip is None or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return None
        n = net_for(ip)
        table = rows_by_net[n.id] if n else unmatched
        r = table.get(str(ip))
        if r is None:
            r = table[str(ip)] = {
                "ip": str(ip),
                "macs": {},  # mac -> {"sources": [...], "online": bool, "name": str}
                "reserved_for": None,
                "reserved_name": None,
                "in_pool": _in_pool(ip, n.pool) if n else False,
                "gateway": bool(n and (n.gateway == str(ip) or n.extra.get("switch_ip") == str(ip))),
            }
        return r

    for n in networks:  # the gateway and the switch's own address are always listed
        for gw in (n.gateway, n.extra.get("switch_ip")):
            if gw:
                row(gw)
    for s in sightings:
        r = row(s.ip)
        if r is None:
            continue
        mac = norm_mac(s.mac) or ""
        m = r["macs"].setdefault(mac, {"sources": [], "online": False, "name": None})
        if s.source not in m["sources"]:
            m["sources"].append(s.source)
        m["online"] = m["online"] or s.online
        m["name"] = m["name"] or s.name
    for res in reservations:
        r = row(res.ip)
        if r is None:
            continue
        r["reserved_for"] = norm_mac(res.mac)
        r["reserved_name"] = res.name

    def finish(r: dict, n: Network | None) -> dict:
        macs = {k: v for k, v in r["macs"].items() if k}
        online_macs = [k for k, v in macs.items() if v["online"]]
        reserved = r["reserved_for"]
        # The device using the address: the reserved MAC if seen, else the online one, else any.
        mac = reserved if reserved in macs else (online_macs[0] if online_macs else (next(iter(macs), None) or reserved))
        info = macs.get(mac or "", {}) if mac else {}
        conflict = None
        if len(online_macs) > 1:
            conflict = f"in use by {len(online_macs)} devices: " + ", ".join(online_macs)
        elif reserved and online_macs and online_macs[0] != reserved:
            conflict = f"reserved for {reserved} but in use by {online_macs[0]}"
        if r["gateway"]:
            state = "gateway"
        elif reserved:
            state = "reserved"
        elif r["in_pool"]:
            state = "dhcp"
        else:
            state = "static"
        sources = sorted({src for v in r["macs"].values() for src in v["sources"]} | ({"Reservation"} if reserved else set()))
        note = None
        if reserved and r["in_pool"]:
            note = "reservation inside the DHCP pool"
        return {
            "ip": r["ip"],
            "mac": mac,
            "name": names.get(mac or "") or info.get("name") or r["reserved_name"]
            or ("Gateway" if n and r["ip"] == n.gateway else "Switch" if r["gateway"] else None),
            "state": state,
            "online": bool(info.get("online")),
            "in_pool": r["in_pool"],
            "reserved_for": reserved,
            "sources": sources,
            "conflict": conflict,
            "note": note,
        }

    result_nets = []
    for n in networks:
        rows = sorted((finish(r, n) for r in rows_by_net[n.id].values()), key=lambda x: int(ipaddress.IPv4Address(x["ip"])))
        pool_size = (
            int(ipaddress.IPv4Address(n.pool[1])) - int(ipaddress.IPv4Address(n.pool[0])) + 1 if n.pool else 0
        )
        pool_used = sum(1 for x in rows if x["in_pool"] and (x["online"] or x["reserved_for"]))
        hosts = max(0, n.net.num_addresses - 2) if n.net.prefixlen < 31 else n.net.num_addresses
        result_nets.append(
            {
                "id": n.id,
                "name": n.name,
                "vlan": n.vlan,
                "cidr": str(n.net),
                "gateway": n.gateway,
                "switch_ip": n.extra.get("switch_ip") or (n.gateway if n.source == "Cirrus" else None),
                "source": n.source,
                "dhcp": n.dhcp,
                "pool": list(n.pool) if n.pool else None,
                "hosts": hosts,
                "enumerable": hosts <= ENUMERATE_MAX,
                "pool_size": pool_size,
                "pool_used": pool_used,
                "pool_free": max(0, pool_size - pool_used),
                "pool_pct": round(100 * pool_used / pool_size, 1) if pool_size else None,
                "reserved": sum(1 for x in rows if x["reserved_for"]),
                "in_use": sum(1 for x in rows if x["online"]),
                "conflicts": sum(1 for x in rows if x["conflict"]),
                "addresses": rows,
            }
        )
    other = sorted((finish(r, None) for r in unmatched.values()), key=lambda x: int(ipaddress.IPv4Address(x["ip"])))
    return {"networks": result_nets, "other": [x for x in other if ipaddress.IPv4Address(x["ip"]).is_private]}
