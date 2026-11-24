"""Device registration: name + MAC -> a fixed address from the gateway's DHCP and a Cirrus UNP.

PREVIEW ONLY. Nothing here talks to the UCG or Cirrus: it works out, from data the integration has already read,
what a registration would change (the exact requests it would send) and anything that would go wrong, so it can
be checked before the write step exists.

A registration would:
  1. UniFi: create (or update) the client entry for the MAC with a fixed IP on the chosen network
     (a DHCP reservation: the device still uses DHCP but always gets this address).
  2. Cirrus: create (or update) a Company Property for the MAC bound to the chosen Access Role Profile (UNP),
     so whenever it authenticates it lands in that UNP (VLAN and ACLs).
  3. Cirrus: if the device is online now, a RADIUS CoA so the new UNP applies at once instead of at reconnect.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .mac_table import norm_mac

FREE_LIST_MAX = 256  # free addresses offered per network


def _ip(value: Any) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(value).strip())
    except (ValueError, TypeError):
        return None


def free_addresses(net: dict, limit: int = FREE_LIST_MAX) -> dict:
    """Free addresses of one IPAM network: in the DHCP pool first, then the rest of the subnet.

    "Free" = no device seen on it, not reserved, not the gateway or switch. (A device that is switched off and
    has no reservation is not known here, so a ping before using an address outside the pool is still wise.)
    """
    try:
        subnet = ipaddress.IPv4Network(net["cidr"])
    except (KeyError, ValueError):
        return {"pool": [], "other": []}
    if subnet.num_addresses > 4096:
        return {"pool": [], "other": []}
    used = {a["ip"] for a in net.get("addresses") or []}
    pool = net.get("pool")
    lo, hi = (_ip(pool[0]), _ip(pool[1])) if pool else (None, None)
    in_pool, other = [], []
    for host in subnet.hosts():
        s = str(host)
        if s in used:
            continue
        if lo and hi and lo <= host <= hi:
            if len(in_pool) < limit:
                in_pool.append(s)
        elif len(other) < limit:
            other.append(s)
        if len(in_pool) >= limit and len(other) >= limit:
            break
    return {"pool": in_pool, "other": other}


def options(ipam: dict, unps: dict[str, dict]) -> dict:
    """What the registration form offers: networks (with free addresses) and UNPs."""
    nets = []
    for n in (ipam or {}).get("networks") or []:
        if n.get("source") != "UniFi":
            continue  # reservations are made on the gateway, so only its networks can be used
        free = free_addresses(n)
        nets.append(
            {
                "id": n["id"],
                "name": n["name"],
                "vlan": n.get("vlan"),
                "cidr": n["cidr"],
                "gateway": n.get("gateway"),
                "pool": n.get("pool"),
                "dhcp": n.get("dhcp"),
                "free_pool": free["pool"],
                "free_other": free["other"],
            }
        )
    unp_list = [
        {"name": u["name"], "vlans": sorted(set(u.get("vlans") or []) | set(u.get("seen_vlans") or [])), "policy_list": u.get("policy_list")}
        for u in sorted((unps or {}).values(), key=lambda x: x["name"].lower())
    ]
    return {"networks": nets, "unps": unp_list}


def _find_address(ipam: dict, network_id: str, ip: str) -> dict | None:
    for n in (ipam or {}).get("networks") or []:
        if n["id"] == network_id:
            return next((a for a in n.get("addresses") or [] if a["ip"] == ip), None)
    return None


def _ping_check(ping: dict | None, ip: str, mac: str | None, own_ip: str | None, errors: list, warnings: list, notes: list) -> None:
    """Fold a live ping / ARP check of the chosen address into the preview."""
    if not ping:
        return
    if ping.get("error"):
        notes.append(f"Could not ping {ip} to check it is free: {ping['error']}")
        return
    hit = (ping.get("in_use") or {}).get(ip)
    if hit:
        if hit.get("mac") and mac and norm_mac(hit["mac"]) == mac:
            notes.append(f"{ip} answered a ping, and it is this device.")
        elif hit.get("mac"):
            errors.append(f"{ip} is in use right now: something with MAC {hit['mac']} answers on it.")
        elif own_ip == ip:
            notes.append(f"{ip} answered a ping (this device is using it now).")
        else:
            warnings.append(
                f"{ip} answered a ping, so something is using it now although neither UniFi nor Cirrus lists it "
                "(perhaps a device with a static address). Pick another address unless you know it is this device."
            )
        return
    ctl = ping.get("control") or {}
    if ctl.get("tried") and not ctl.get("answered"):
        notes.append(
            f"{ip} did not answer a ping, but nor did any address known to be up on this network, so pings from "
            "Home Assistant are probably blocked there: the check proves nothing. "
            "Allow ICMP (ping) from the Home Assistant host to this network in the gateway's firewall."
        )
    else:
        notes.append(f"{ip} did not answer a ping from Home Assistant (a device that drops pings would not either).")


def _cp_mac(row: dict) -> str | None:
    return norm_mac(row.get("deviceMac") or row.get("mac"))


def build_preview(
    req: dict,
    *,
    ipam: dict,
    unps: dict[str, dict],
    known: list[dict],
    online: dict[str, dict],
    sessions: dict[str, dict],
    company_props: list[dict] | None,
    company_props_error: str | None,
    unifi_site: str | None,
    ping: dict | None = None,
) -> dict:
    """The changes a registration would make, plus errors (would refuse) and warnings / notes."""
    errors: list[str] = []
    warnings: list[str] = []
    notes: list[str] = []
    changes: list[dict] = []

    name = (req.get("name") or "").strip()
    mac = norm_mac(req.get("mac"))
    unp = (req.get("unp") or "").strip() or None
    if not name:
        errors.append("Give the device a name.")
    if not mac:
        errors.append("The MAC address is not valid (expected 6 hex pairs, e.g. 60:74:F4:EA:F6:8E).")
    elif int(mac.split(":")[0], 16) & 1:
        errors.append("That is a multicast MAC address, not a device.")
    elif int(mac.split(":")[0], 16) & 2:
        warnings.append(
            "This is a randomised (private) MAC. If the device changes it (phones often do per network or over time) "
            "the reservation and UNP stop matching; turn off private addressing for this network on the device."
        )

    net = next((n for n in (ipam or {}).get("networks") or [] if n["id"] == req.get("network_id")), None)
    if not net:
        errors.append("Pick a network.")
    elif net.get("source") != "UniFi":
        errors.append("Reservations are made on the UniFi gateway, and it does not serve that network.")
    ip = _ip(req.get("ip")) if req.get("ip") else None
    if net and req.get("ip") and not ip:
        errors.append("The IP address is not valid.")
    if net and ip:
        subnet = ipaddress.IPv4Network(net["cidr"])
        if ip not in subnet:
            errors.append(f"{ip} is not in {net['name']} ({net['cidr']}).")
        elif ip in (subnet.network_address, subnet.broadcast_address):
            errors.append(f"{ip} is the network or broadcast address of {net['cidr']}.")
        elif str(ip) in (net.get("gateway"), net.get("switch_ip")):
            errors.append(f"{ip} is the gateway / switch address of {net['name']}.")
        else:
            row = _find_address(ipam, net["id"], str(ip))
            if row and row.get("reserved_for") and row["reserved_for"] != mac:
                errors.append(f"{ip} is already reserved for {row.get('name') or row['reserved_for']} ({row['reserved_for']}).")
            elif row and row.get("online") and row.get("mac") and row["mac"] != mac:
                errors.append(f"{ip} is in use right now by {row.get('name') or row['mac']} ({row['mac']}).")
            elif row and row.get("mac") and row["mac"] != mac:
                warnings.append(f"{ip} was last seen used by {row.get('name') or row['mac']} ({row['mac']}), which is offline now.")
            _ping_check(ping, str(ip), mac, (online or {}).get(mac or "", {}).get("ip"), errors, warnings, notes)
            pool = net.get("pool")
            if pool and _ip(pool[0]) <= ip <= _ip(pool[1]):
                notes.append(f"{ip} is inside the DHCP pool ({pool[0]} – {pool[1]}); the gateway will not give it to anything else once reserved.")
            elif pool:
                notes.append(f"{ip} is outside the DHCP pool, so it can only ever be handed out by this reservation.")
    if net and not ip:
        errors.append("Pick an IP address.")

    unp_info = (unps or {}).get(unp) if unp else None
    if unp and not unp_info:
        errors.append(f"There is no UNP (Access Role Profile) called {unp} in Cirrus.")
    if net and unp_info:
        vlans = sorted(set(unp_info.get("vlans") or []) | set(unp_info.get("seen_vlans") or []))
        if vlans and net.get("vlan") not in vlans:
            warnings.append(
                f"UNP {unp} puts devices on VLAN {', '.join(map(str, vlans))}, but {net['name']} is VLAN {net.get('vlan')}. "
                "The device would be given a VLAN where this address does not work."
            )
        elif not vlans:
            notes.append(f"Cirrus does not say which VLAN UNP {unp} uses, so it cannot be checked against {net['name']}.")

    # ---- 1. UniFi reservation
    existing = next((k for k in known or [] if norm_mac(k.get("mac")) == mac), None) if mac else None
    now = (online or {}).get(mac or "") or {}
    if mac and net and ip:
        body = {"name": name, "use_fixedip": True, "fixed_ip": str(ip), "network_id": net["id"]}
        site = unifi_site or "default"
        details = []
        if existing:
            if existing.get("use_fixedip") and existing.get("fixed_ip"):
                if existing.get("fixed_ip") == str(ip) and existing.get("network_id") == net["id"]:
                    details.append(f"Already reserved at {ip}; only the name is set.")
                else:
                    details.append(f"Moves the existing reservation from {existing.get('fixed_ip')} to {ip}.")
            if existing.get("name") and existing.get("name") != name:
                details.append(f"Renames it from “{existing['name']}” to “{name}”.")
            changes.append(
                {
                    "system": "UniFi",
                    "action": "update",
                    "title": f"Reserve {ip} for {name} on {net['name']}",
                    "details": details or ["Updates the client UniFi already knows for this MAC."],
                    "request": {"method": "PUT", "path": f"/proxy/network/api/s/{site}/rest/user/{existing.get('_id')}", "body": body},
                }
            )
        else:
            changes.append(
                {
                    "system": "UniFi",
                    "action": "create",
                    "title": f"Reserve {ip} for {name} on {net['name']}",
                    "details": ["Adds the MAC to UniFi's known clients with a fixed IP."],
                    "request": {"method": "POST", "path": f"/proxy/network/api/s/{site}/rest/user", "body": {"mac": mac.lower(), **body}},
                }
            )
        cur_ip = now.get("ip")
        if cur_ip and cur_ip != str(ip):
            notes.append(f"{name} is online now at {cur_ip}; it moves to {ip} when it next renews its DHCP lease or reconnects.")

    # ---- 2. Cirrus company property (binds the MAC to the UNP)
    if mac and unp_info:
        cp = None
        if company_props is not None:
            cp = next((r for r in company_props if _cp_mac(r) == mac), None)
        elif company_props_error:
            warnings.append(f"Could not read Cirrus company properties ({company_props_error}); the write step would check again.")
        body = {"deviceName": name, "arpName": unp}
        if cp:
            old = cp.get("arpName")
            changes.append(
                {
                    "system": "Cirrus",
                    "action": "update",
                    "title": f"Put {name} in UNP {unp}",
                    "details": [f"Updates its company property (UNP now {old or 'none'})." if old != unp else "Already in this UNP; only the name is set."],
                    "request": {
                        "method": "PATCH",
                        "path": f"/api/ov/v1/organizations/{{org}}/am/accounts/company-properties/{cp.get('id') or cp.get('_id')}",
                        "body": body,
                    },
                }
            )
        else:
            changes.append(
                {
                    "system": "Cirrus",
                    "action": "create",
                    "title": f"Put {name} in UNP {unp}",
                    "details": ["Adds a company property for the MAC, bound to the UNP: it lands there whenever it authenticates."],
                    "request": {
                        "method": "POST",
                        "path": "/api/ov/v1/organizations/{org}/am/accounts/company-properties",
                        "body": {"deviceMac": mac, **body},
                    },
                }
            )
        # ---- 3. CoA so it applies now
        sess = (sessions or {}).get(mac)
        if sess and sess.get("unp") != unp:
            vlan_txt = f" (VLAN {sess['vlan']})" if sess.get("vlan") else ""
            changes.append(
                {
                    "system": "Cirrus",
                    "action": "coa",
                    "title": f"Move {name} into {unp} now",
                    "details": [f"It is online in UNP {sess.get('unp') or 'none'}{vlan_txt}; a RADIUS CoA re-authorises it straight away."],
                    "request": {
                        "method": "POST",
                        "path": "/api/ov/v1/organizations/{org}/am/access-records/online/radius-coa",
                        "body": {"macs": [mac], "accessRoleProfile": unp},
                    },
                }
            )
        elif sess:
            notes.append(f"{name} is online and already in UNP {unp}.")
        else:
            notes.append(f"{name} is not online through Cirrus authentication now; the UNP applies the next time it connects.")
    elif mac and not unp:
        notes.append("No UNP chosen: Cirrus is left as it is (the device keeps whatever access it gets today).")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "notes": notes,
        "changes": changes if not errors else [],
        "device": {"name": name, "mac": mac, "ip": str(ip) if ip else None, "network": net["name"] if net else None, "unp": unp},
    }
