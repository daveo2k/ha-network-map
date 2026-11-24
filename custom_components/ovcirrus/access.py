"""Unified access (UPAM / UNP) and alerts from Cirrus, shaped for the map. Read-only."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .mac_table import norm_mac


def _vlan_id(v: Any) -> int | None:
    if isinstance(v, dict):
        v = v.get("vlanId", v.get("vlan", v.get("id")))
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_unps(rows: list[dict]) -> dict[str, dict]:
    """Access Role Profiles -> {name: {"name", "policy_list", "vlans", "status"}}.

    The VLAN an ARP maps to is set per assignment (group, site or device), so all of them are collected.
    """
    out: dict[str, dict] = {}
    for row in rows or []:
        name = row.get("arpName") or row.get("name")
        if not name:
            continue
        vlans: set[int] = set()
        for a in row.get("assignments") or []:
            for v in ((a or {}).get("vlanTunnelMapping") or {}).get("vlans") or []:
                vid = _vlan_id(v)
                if vid:
                    vlans.add(vid)
        in_use = {
            (u or {}).get("deviceGroupId"): [t for t in (u or {}).get("inUseTypes") or [] if t]
            for u in row.get("inUseAssignments") or []
        }
        assigned, assignments = [], []
        for a in row.get("assignments") or []:
            a = a or {}
            if a.get("device"):
                kind, target = "Switch", str(a["device"].get("friendlyName") or a["device"].get("serialNumber") or "?")
            elif a.get("group"):
                kind, target = "AP group", str(a["group"].get("name") or "?")
            elif a.get("site"):
                kind, target = "Site", str(a["site"].get("name") or "?")
            else:
                continue
            assigned.append(f"{kind} {target}")
            m = a.get("vlanTunnelMapping")
            entry = {"kind": kind, "target": target, "status": a.get("configStatus")}
            if isinstance(m, dict):
                vids = [v for v in (_vlan_id(x) for x in m.get("vlans") or []) if v]
                mtype = m.get("mappingType") or ""
                entry["mapping"] = mtype or None
                entry["vlans"] = vids
                # On AP groups VLAN "0" (or none) means no mapping: the device stays on its SSID's VLAN.
                entry["ssid_vlan"] = mtype in ("", "Vlan", "NoMapping") and not vids
            if kind == "AP group":
                entry["in_use"] = in_use.get((a.get("group") or {}).get("id"), [])
            assignments.append(entry)
        bw = row.get("bandwidthControl") or {}
        cp = (row.get("captivePortal") or {}).get("captivePortalType")
        out[name] = {
            "name": name,
            "assigned": assigned,
            "assignments": assignments,
            "detailed": bool(row.get("_detailed")),
            "captive_portal": cp if cp and cp != "NONE" else None,
            "bandwidth": {k: bw[k] for k in ("upstreamBandwidth", "downstreamBandwidth") if bw.get(k)} or None,
            "policy_list": (row.get("policyList") or {}).get("name"),
            "vlans": sorted(vlans),
            "seen_vlans": [],
            "status": row.get("configStatus"),
            "clients": 0,
        }
    return out


def _epoch(value: Any) -> float | None:
    """Cirrus timestamps come as epoch seconds, epoch milliseconds or ISO strings."""
    if value in (None, ""):
        return None
    try:
        num = float(value)
        return num / 1000 if num > 1e11 else num
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def parse_sessions(rows: list[dict]) -> dict[str, dict]:
    """UPAM online authentication records -> {MAC: session} (the newest session per MAC)."""
    out: dict[str, dict] = {}
    for r in rows or []:
        mac = norm_mac(r.get("deviceMac"))
        if not mac:
            continue
        s = {
            "unp": r.get("finalAccessRoleProfile") or None,
            "vlan": _vlan_id(r.get("finalDynamicVlanId")),
            "policy": r.get("accessPolicy") or None,
            "auth": " / ".join(x for x in (r.get("authType"), r.get("authMethod")) if x) or None,
            "result": r.get("authResult") or None,
            "network": r.get("networkType") or None,
            "ssid": r.get("ssid") or None,
            "nas_ip": r.get("nasIpAddress") or r.get("nasSourceIp") or None,
            "user": r.get("username") or None,
            "ip": r.get("deviceIpv4") or None,
            "since": _epoch(r.get("sessionStart")),
        }
        old = out.get(mac)
        if old is None or (s["since"] or 0) >= (old["since"] or 0):
            out[mac] = s
    return out


def add_seen_vlans(unps: dict[str, dict], sessions: dict[str, dict]) -> None:
    """Fill in which VLANs each UNP actually put clients on, and how many clients it has now."""
    for s in sessions.values():
        name = s.get("unp")
        if not name:
            continue
        u = unps.setdefault(
            name, {"name": name, "policy_list": None, "vlans": [], "seen_vlans": [], "status": None, "clients": 0}
        )
        u["clients"] += 1
        if s.get("vlan") and s["vlan"] not in u["seen_vlans"]:
            u["seen_vlans"] = sorted([*u["seen_vlans"], s["vlan"]])


SEVERITY_ORDER = {"critical": 0, "major": 1, "high": 1, "minor": 2, "medium": 2, "warning": 3, "low": 3, "info": 4}


def parse_alerts(rows: list[dict]) -> list[dict]:
    """Cirrus alerts -> compact dicts, newest first."""
    out = []
    for r in rows or []:
        aid = r.get("id")
        if not aid:
            continue
        sev = (r.get("severity") or "").lower() or None
        out.append(
            {
                "id": str(aid),
                "severity": sev,
                "rank": SEVERITY_ORDER.get(sev or "", 5),
                "type": r.get("alertType") or r.get("description") or r.get("code"),
                "reason": r.get("reason") or r.get("description"),
                "device": r.get("deviceName") or r.get("friendlyName") or r.get("deviceIp") or r.get("deviceMac"),
                "device_mac": norm_mac(r.get("deviceMac")),
                "client_mac": norm_mac(r.get("staMac")),
                "ssid": r.get("ssid") or None,
                "site_id": r.get("siteId"),
                "site": r.get("siteName"),
                "source": r.get("source"),
                "time": _epoch(r.get("issuedAt") or r.get("createdAt")),
                "acknowledged": bool(r.get("isAcknowledged")),
            }
        )
    out.sort(key=lambda a: -(a["time"] or 0))
    return out
