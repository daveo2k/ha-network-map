"""Check whether addresses are really free: ping them from the Home Assistant host and read its ARP table.

Read-only (it only sends ICMP echo requests). Limits worth knowing:
  * A device whose firewall drops pings (Windows, many phones) does not answer. On the HA host's own subnets the
    ARP table still catches it, because the ping makes the host ask for its MAC first.
  * Across VLANs it depends on the gateway's firewall letting ICMP from HA through. The sweep pings a few known
    online addresses as a control, so the result says when a silent answer means nothing.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import sys

_LOGGER = logging.getLogger(__name__)

CONCURRENCY = 64
TIMEOUT = 1.0
ARP_FILE = "/proc/net/arp"


async def _icmplib(hosts: list[str], timeout: float) -> dict[str, bool] | None:
    try:
        from icmplib import async_multiping  # shipped with HA's ping integration; not always installed
    except ImportError:
        return None
    for privileged in (True, False):
        try:
            res = await async_multiping(
                hosts, count=2, interval=0.2, timeout=timeout, concurrent_tasks=CONCURRENCY, privileged=privileged
            )
            return {h.address: h.is_alive for h in res}
        except Exception as err:  # noqa: BLE001 - permission errors differ by platform
            _LOGGER.debug("icmplib (privileged=%s) failed: %s", privileged, err)
    return None


async def _ping_cmd(hosts: list[str], timeout: float) -> dict[str, bool] | None:
    exe = shutil.which("ping")
    if not exe:
        return None
    wait = ["-W", str(int(timeout * 1000))] if sys.platform == "darwin" else ["-W", str(max(1, round(timeout)))]
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(ip: str) -> bool:
        async with sem:
            for _ in range(2):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        exe, "-c", "1", *wait, ip, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                    )
                    if await asyncio.wait_for(proc.wait(), timeout + 2) == 0:
                        return True
                except (OSError, asyncio.TimeoutError):
                    return False
            return False

    results = await asyncio.gather(*(one(h) for h in hosts))
    return dict(zip(hosts, results))


def read_arp() -> dict[str, str]:
    """IP -> MAC from the host's ARP table (complete entries only). Empty where there is no /proc."""
    out: dict[str, str] = {}
    try:
        with open(ARP_FILE, encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "0x2" and parts[3] != "00:00:00:00:00:00":
                    out[parts[0]] = parts[3].upper()
    except OSError:
        pass
    return out


async def ping_many(hosts: list[str], timeout: float = TIMEOUT) -> tuple[dict[str, bool], str]:
    """Ping each host (2 tries). Returns ({ip: answered}, method used)."""
    hosts = [str(ipaddress.IPv4Address(h)) for h in hosts]
    if not hosts:
        return {}, "none"
    res = await _icmplib(hosts, timeout)
    if res is not None:
        return res, "icmplib"
    res = await _ping_cmd(hosts, timeout)
    if res is not None:
        return res, "ping"
    raise RuntimeError("Home Assistant cannot send pings here (no icmplib and no ping command).")


async def probe(hosts: list[str], controls: list[str]) -> dict:
    """Ping hosts plus controls (addresses known to be online). An address is in use when it answers or the
    ARP table has a MAC for it after the ping."""
    answered, method = await ping_many(list(dict.fromkeys([*hosts, *controls])))
    arp = await asyncio.get_running_loop().run_in_executor(None, read_arp)
    in_use = {}
    for ip in hosts:
        if answered.get(ip) or ip in arp:
            in_use[ip] = {"ping": bool(answered.get(ip)), "mac": arp.get(ip)}
    ctl = [c for c in controls if c not in hosts]
    return {
        "method": method,
        "checked": len(hosts),
        "in_use": in_use,
        "control": {"tried": len(ctl), "answered": sum(1 for c in ctl if answered.get(c) or c in arp)},
    }
