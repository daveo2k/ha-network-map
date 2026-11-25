"""Data coordinator for OmniVista Cirrus."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .access import add_seen_vlans, parse_alerts, parse_sessions, parse_unps
from .api import CirrusApiError, CirrusAuthError, CirrusClient, CirrusError, CirrusForbiddenError
from .assets import AssetCache
from .history import RateHistory
from .const import (
    CONF_DISCOVERY_INTERVAL,
    CONF_DNS_MODE,
    CONF_DNS_PREFER,
    CONF_DNS_SERVERS,
    CONF_DNS_SHORT,
    CONF_MANUAL_DEVICES,
    CONF_ORG_ID,
    CONF_SCAN_INTERVAL,
    CONF_SITE_IDS,
    CONF_SSH_ARP,
    CONF_SSH_ENABLED,
    CONF_SSH_HOSTS,
    CONF_SSH_INTERVAL,
    CONF_SSH_KEY_PATH,
    CONF_SSH_KNOWN_HOSTS,
    CONF_SSH_PORT,
    CONF_SSH_USERNAME,
    PHOTOS_URL,
    CONF_RATE_FINE_HOURS,
    CONF_RATE_INTERVAL,
    CONF_RATE_LONG_DAYS,
    CONF_RATE_PERSIST,
    DEFAULT_RATE_FINE_HOURS,
    DEFAULT_RATE_INTERVAL,
    DEFAULT_RATE_LONG_DAYS,
    CONF_UNIFI_ENABLED,
    CONF_UNIFI_HOST,
    CONF_UNIFI_PASSWORD,
    CONF_UNIFI_SITE,
    CONF_UNIFI_USERNAME,
    CONF_UNIFI_VERIFY_SSL,
    DEFAULT_DISCOVERY_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SSH_INTERVAL,
    DEFAULT_SSH_PORT,
    DOMAIN,
    EVENT_ALERT,
    EVENT_NEW_CLIENT,
    TOPOLOGY_INTERVAL,
)
from homeassistant.helpers import issue_registry as ir

from .discovery import discover, full_scan
from .dns import ReverseResolver, parse_servers
from .identify import HaDevice, identify, is_private_mac
from .ipam import Reservation, Sighting, build_ipam, merge_networks, parse_cirrus_interfaces, parse_unifi_networks
from . import firewall, probe, registration
from .mac_table import SshError, SwitchTables, fetch_switch_tables, norm_mac
from .store import EntryStore
from .topology import MapExtras, build_site_map, model_slug, walk_nodes
from .unifi import UnifiClient, UnifiError

_LOGGER = logging.getLogger(__name__)


def _iot_profiles(rows: list[dict]) -> dict[str, dict]:
    """Cirrus IoT inventory rows -> {MAC: profile}. A MAC can have a row per place it was seen; the best
    scored category wins and the DHCP options and looked-up hosts are merged."""

    def hosts(v: Any) -> list[str]:
        v = (v or "").strip().strip("[]")
        return [h.strip().strip("'\"") for h in v.split(",") if h.strip().strip("'\"")]

    out: dict[str, dict] = {}
    for r in sorted(rows, key=lambda r: str(r.get("updated_at") or "")):
        mac = norm_mac(r.get("endpoint_mac"))
        if not mac:
            continue
        p = out.setdefault(mac, {"category": None, "score": 0, "name": None, "manufacturer": None, "opt55": None,
                                 "opt60": None, "hosts": [], "user_agents": [], "seen_on": [], "updated": None})
        try:
            score = int(r.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        if r.get("category_hierarchy") and score >= (p["score"] or 0):
            p["category"], p["score"], p["name"] = r["category_hierarchy"], score, r.get("endpoint_name") or None
        man = r.get("manufacturer")
        if man and man.lower() != "private":
            p["manufacturer"] = man
        for key, src in (("opt55", "prof_opt55"), ("opt60", "prof_opt60")):
            if r.get(src):
                p[key] = r[src]
        for h in hosts(r.get("prof_hosts")):
            if h not in p["hosts"]:
                p["hosts"].append(h)
        for h in hosts(r.get("prof_user_agents")):
            if h not in p["user_agents"]:
                p["user_agents"].append(h)
        where = " · ".join(x for x in (r.get("device_name"), r.get("nwcontext_port_description") or r.get("nwcontext_port")) if x)
        if where and where not in p["seen_on"]:
            p["seen_on"].insert(0, where)  # newest first
        p["updated"] = r.get("updated_at") or p["updated"]
    return out


@dataclass
class CirrusData:
    """Snapshot of everything fetched in one refresh."""

    sites: dict[str, dict] = field(default_factory=dict)
    devices: dict[str, dict] = field(default_factory=dict)  # serial -> device
    clients: dict[str, dict] = field(default_factory=dict)  # MAC -> wireless session
    topology: dict[str, dict] = field(default_factory=dict)  # site_id -> raw topology
    node_status: dict[str, str] = field(default_factory=dict)  # MAC -> online/offline
    lldp: dict[str, list] = field(default_factory=dict)  # switch serial -> lldp entries
    ports: dict[str, list] = field(default_factory=dict)  # switch serial -> port status
    port_vlans: dict[str, dict] = field(default_factory=dict)  # serial -> port -> {"untagged", "tagged"}
    vlans: dict[str, dict] = field(default_factory=dict)  # VLAN id -> {"name", "up"}
    dns_names: dict[str, str] = field(default_factory=dict)  # ip -> PTR name
    radios: dict[str, list] = field(default_factory=dict)  # AP serial -> [radio dicts]
    rf_profiles: dict[str, str] = field(default_factory=dict)  # AP serial -> RF profile name
    switch_tables: dict[str, SwitchTables] = field(default_factory=dict)
    ssh_errors: dict[str, str] = field(default_factory=dict)
    unifi: dict = field(default_factory=dict)  # {"wan": {...}, "clients": {mac: {...}}}
    unifi_error: str | None = None
    unifi_networks: list = field(default_factory=list)  # UniFi networkconf rows
    unifi_known: list = field(default_factory=list)  # UniFi rest/user rows (incl. fixed-IP reservations)
    ip_interfaces: list = field(default_factory=list)  # switch IP interfaces from Cirrus
    unps: dict[str, dict] = field(default_factory=dict)  # Access Role Profile name -> summary
    sessions: dict[str, dict] = field(default_factory=dict)  # MAC -> UPAM online session
    access_error: str | None = None  # why UNP data is missing (e.g. no UPAM rights)
    alerts: list = field(default_factory=list)  # Cirrus alerts, newest first
    alerts_error: str | None = None
    alerts_raw: dict = field(default_factory=dict)  # alert id -> the record as Cirrus sent it (for the details view)
    ipam: dict = field(default_factory=dict)  # see ipam.build_ipam
    iot: dict = field(default_factory=dict)  # MAC -> Cirrus IoT inventory profile (see _iot_profiles)
    unifi_firewall: dict = field(default_factory=dict)  # raw UniFi firewall parts (see UnifiClient.firewall)
    firewall: dict = field(default_factory=dict)  # see firewall.build
    maps: dict[str, dict] = field(default_factory=dict)  # site_id -> card tree


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_port_vlans(rows: list[dict]) -> dict[str, dict]:
    """Cirrus ports-vlan-list -> {port: {"untagged": [ids], "tagged": [ids]}} (active VLANs only)."""
    result: dict[str, dict] = {}
    for row in rows or []:
        port = row.get("slot")
        if not port:
            continue
        untagged = [v["vlanNumber"] for v in row.get("untaggedVlans") or [] if v.get("vlanNumber") is not None]
        tagged = [
            v["vlanNumber"]
            for v in row.get("taggedVlans") or []
            if v.get("vlanNumber") is not None and v.get("status") != "inactive"
        ]
        if not untagged and row.get("defaultVlan") is not None:
            untagged = [row["defaultVlan"]]
        result[port] = {"untagged": untagged, "tagged": sorted(set(tagged))}
    return result


def parse_ssh_hosts(value: Any) -> dict[str, str]:
    """SSH addresses per switch serial.

    Current format: {serial: host} from the setup form ('' means do not SSH to that switch).
    Older format: 'SERIAL=host' lines; a bare address applies to every switch ('*').
    """
    if isinstance(value, dict):
        return {str(k): str(v or "").strip() for k, v in value.items()}
    result: dict[str, str] = {}
    for part in (value or "").replace("\n", ",").split(","):
        part = part.strip()
        if "=" in part:
            serial, host = part.split("=", 1)
            if serial.strip() and host.strip():
                result[serial.strip()] = host.strip()
        elif part:
            result["*"] = part
    return result


class CirrusCoordinator(DataUpdateCoordinator[CirrusData]):
    """Polls Cirrus (plus switches over SSH, the UniFi gateway and DNS, when enabled)."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: CirrusClient,
        assets: AssetCache,
        store: EntryStore,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
        )
        self.client = client
        self.assets = assets
        self.store = store
        self.org_id: str = entry.data[CONF_ORG_ID]
        self._topology_at = 0.0
        self._ssh_at = 0.0
        self._unifi_cfg_at = 0.0
        self._sessions_ok = False  # at least one successful read, so a failure can fall back to it
        self._alerts_ok = False
        self._alerts_warned = False  # warn once, then keep failures at debug level
        self._alert_defs: tuple[float, list] | None = None  # (fetched at, alert definitions)
        self._cache = CirrusData()
        self._scanning: set[str] = set()
        opts = entry.options
        mode = opts.get(CONF_DNS_MODE, "off")
        self.resolver: ReverseResolver | None = (
            ReverseResolver(mode, parse_servers(opts.get(CONF_DNS_SERVERS))) if mode in ("system", "server") else None
        )
        self.unifi: UnifiClient | None = (
            UnifiClient(
                opts.get(CONF_UNIFI_HOST, ""),
                opts.get(CONF_UNIFI_USERNAME, ""),
                entry.data.get(CONF_UNIFI_PASSWORD) or opts.get(CONF_UNIFI_PASSWORD, ""),
                opts.get(CONF_UNIFI_SITE, "default"),
                bool(opts.get(CONF_UNIFI_VERIFY_SSL, False)),
            )
            if opts.get(CONF_UNIFI_ENABLED) and opts.get(CONF_UNIFI_HOST)
            else None
        )

        self.rate_interval = int(opts.get(CONF_RATE_INTERVAL, DEFAULT_RATE_INTERVAL))
        self.rates = RateHistory(
            fine_seconds=int(float(opts.get(CONF_RATE_FINE_HOURS, DEFAULT_RATE_FINE_HOURS)) * 3600),
            long_seconds=int(float(opts.get(CONF_RATE_LONG_DAYS, DEFAULT_RATE_LONG_DAYS)) * 86400),
        )
        self._rates_unsub = None
        self._rates_busy = False
        self._rate_store: Store | None = (
            Store(hass, 1, f"{DOMAIN}.rates.{entry.entry_id}") if opts.get(CONF_RATE_PERSIST, True) else None
        )
        self._rate_save_pending = False

    RATE_SAVE_DELAY = 300  # write the saved history at most every 5 minutes (and when HA stops)

    async def start_rate_history(self) -> None:
        """Read the gateway's port rates into the history every sample interval (UniFi only)."""
        if not self.unifi or self._rates_unsub:
            return
        if self._rate_store:
            try:
                self.rates.load(await self._rate_store.async_load())
            except Exception as err:  # a damaged file must not stop the integration
                _LOGGER.warning("Could not read the saved bandwidth history: %s", err)
        else:  # saving turned off: drop any history saved earlier
            await Store(self.hass, 1, f"{DOMAIN}.rates.{self.config_entry.entry_id}").async_remove()
        self._rates_unsub = async_track_time_interval(
            self.hass, self._poll_rates, timedelta(seconds=max(5, self.rate_interval))
        )

    def _rate_data(self) -> dict:
        self._rate_save_pending = False
        return self.rates.to_dict()

    async def _poll_rates(self, _now=None) -> None:
        if self._rates_busy or not self.unifi:
            return
        self._rates_busy = True
        try:
            ports = await self.unifi.gateway_ports()
        except UnifiError as err:
            _LOGGER.debug("UniFi rate poll failed: %s", err)
            return
        finally:
            self._rates_busy = False
        for p in ports:
            key = p.get("ifname") or str(p.get("idx"))
            self.rates.names[key] = {"name": p.get("name"), "role": p.get("role"), "speed": p.get("speed"), "up": p.get("up")}
            if p.get("up"):
                self.rates.add(key, p.get("rx"), p.get("tx"))
        if self._rate_store and not self._rate_save_pending:
            self._rate_save_pending = True
            self._rate_store.async_delay_save(self._rate_data, self.RATE_SAVE_DELAY)

    @property
    def site_ids(self) -> list[str]:
        return list(self.config_entry.data.get(CONF_SITE_IDS) or [])

    @property
    def manual_devices(self) -> list[dict]:
        """Devices added from the map or the options (older options entries are still honoured)."""
        stored = {d.get("id"): d for d in self.store.manual}
        for dev in self.config_entry.options.get(CONF_MANUAL_DEVICES) or []:
            stored.setdefault(dev.get("id"), dev)
        return list(stored.values())

    def services_view(self) -> dict[str, dict]:
        """Scan results with your port names applied."""
        view: dict[str, dict] = {}
        for ip, result in self.store.services.items():
            services = []
            for svc in result.get("services") or []:
                label, scope = self.store.port_label(ip, svc["port"])
                if label:
                    svc = {**svc, "service": label, "label_scope": scope, "unknown": False, "labelled": True}
                services.append(svc)
            view[ip] = {**result, "services": services}
        return view

    async def async_shutdown(self) -> None:
        if self._rates_unsub:
            self._rates_unsub()
            self._rates_unsub = None
        if self._rate_store and self.unifi:
            await self._rate_store.async_save(self._rate_data())
        await super().async_shutdown()
        if self.unifi:
            await self.unifi.close()
        await self.store.async_save()

    async def _async_update_data(self) -> CirrusData:
        try:
            return await self._update()
        except CirrusAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except CirrusApiError as err:
            raise UpdateFailed(str(err)) from err

    # ---------------------------------------------------------------- fetch
    async def _update(self) -> CirrusData:
        data = CirrusData()
        prev = self._cache
        now = time.monotonic()

        sites = await self.client.get_sites(self.org_id)
        wanted = set(self.site_ids) or {s["id"] for s in sites}
        data.sites = {s["id"]: s for s in sites if s["id"] in wanted}

        devices = await self.client.get_devices(self.org_id)
        data.devices = {
            d["serialNumber"]: d
            for d in devices
            if d.get("serialNumber") and (d.get("site") or {}).get("id") in data.sites
        }
        clients = await self.client.get_wireless_clients(self.org_id, list(data.sites))
        data.clients = {
            norm_mac(c.get("clientMac")) or c.get("clientMac"): c for c in clients if not c.get("terminated")
        }

        if now - self._topology_at > TOPOLOGY_INTERVAL or not prev.topology:
            await self._update_topology(data, prev)
            self._topology_at = now
        else:
            data.topology, data.lldp, data.ports = prev.topology, prev.lldp, prev.ports
            data.port_vlans, data.vlans = prev.port_vlans, prev.vlans
            data.ip_interfaces, data.unps = prev.ip_interfaces, {k: dict(v) for k, v in prev.unps.items()}
            data.iot = prev.iot

        for topo in data.topology.values():
            for node in topo.get("nodes") or []:
                mac = norm_mac(node.get("macAddress"))
                if mac:
                    reach = (node.get("reachable") or "").lower()
                    data.node_status[mac] = {"on": "online", "off": "offline"}.get(reach, "unknown")

        await self._update_radios(data, prev)
        await self._update_access(data, prev)
        await self._update_ssh(data, prev, now)
        await self._update_unifi(data, prev, now)
        if self.resolver:
            data.dns_names = await self._resolve_names(data)

        self.assets.ensure_oui()
        data.maps = self._build_maps(data)
        data.ipam = self._build_ipam(data)
        data.firewall = self._build_firewall(data)
        self._observe(data)
        self._alert_events(data)
        self._schedule_discovery(data)
        self._cache = data
        return data

    async def _update_topology(self, data: CirrusData, prev: CirrusData) -> None:
        switches = [s for s, d in data.devices.items() if d.get("deviceFamily") == "AOS"]
        topo_results, lldp_results, port_results, vlan_results, vlan_list = await asyncio.gather(
            asyncio.gather(*(self.client.get_topology(self.org_id, s) for s in data.sites), return_exceptions=True),
            asyncio.gather(*(self.client.get_lldp(self.org_id, s) for s in switches), return_exceptions=True),
            asyncio.gather(*(self.client.get_ports(self.org_id, s) for s in switches), return_exceptions=True),
            asyncio.gather(*(self.client.get_port_vlans(self.org_id, s) for s in switches), return_exceptions=True),
            self.client.get_vlans(self.org_id, list(data.sites)),
            return_exceptions=True,
        )
        for serial, res in zip(switches, vlan_results if isinstance(vlan_results, list) else []):
            data.port_vlans[serial] = prev.port_vlans.get(serial, {}) if isinstance(res, Exception) else parse_port_vlans(res)
        if isinstance(vlan_list, Exception):
            _LOGGER.debug("VLAN list failed: %s", vlan_list)
            data.vlans = prev.vlans
        else:
            data.vlans = {
                str(v["vlanId"]): {
                    "name": v.get("description") or f"VLAN {v['vlanId']}",
                    "up": bool((v.get("operStatus") or {}).get("enabled")),
                }
                for v in vlan_list
                if v.get("vlanId") is not None
            }
        for sid, res in zip(data.sites, topo_results):
            if isinstance(res, Exception):
                _LOGGER.warning("Topology fetch failed for site %s: %s", sid, res)
                if sid in prev.topology:
                    data.topology[sid] = prev.topology[sid]
            else:
                data.topology[sid] = res
        for serial, res in zip(switches, lldp_results):
            data.lldp[serial] = prev.lldp.get(serial, []) if isinstance(res, Exception) else res
        for serial, res in zip(switches, port_results):
            data.ports[serial] = prev.ports.get(serial, []) if isinstance(res, Exception) else res
        try:
            data.ip_interfaces = await self.client.get_ip_interfaces(self.org_id, list(data.sites))
        except CirrusError as err:  # optional extra: never a reason to ask for new credentials
            _LOGGER.debug("IP interfaces failed: %s", err)
            data.ip_interfaces = prev.ip_interfaces
        try:
            data.unps = parse_unps(await self._arps_with_assignments())
        except CirrusError as err:  # optional: needs UPAM rights
            _LOGGER.debug("Access Role Profiles failed: %s", err)
            data.unps = {k: {**v, "clients": 0, "seen_vlans": []} for k, v in prev.unps.items()}

        try:
            data.iot = _iot_profiles(await self.client.get_iot_inventory(self.org_id, list(data.sites)))
        except CirrusError as err:  # optional: needs rights to the IoT inventory
            _LOGGER.debug("IoT inventory failed: %s", err)
            data.iot = prev.iot

    async def _arps_with_assignments(self) -> list[dict]:
        """The ARP list, with each ARP's assignments replaced by the detailed ones (which carry the VLAN per
        switch / AP group). Read-only GETs; an ARP whose detail fails keeps the list's assignments."""
        rows = await self.client.get_access_role_profiles(self.org_id)
        ids = [r.get("id") for r in rows]
        sem = asyncio.Semaphore(4)

        async def one(arp_id):
            if arp_id is None:
                return None
            async with sem:
                return await self.client.get_access_role_profile(self.org_id, arp_id)

        details = await asyncio.gather(*(one(i) for i in ids), return_exceptions=True)
        for row, det in zip(rows, details):
            if isinstance(det, Exception):
                _LOGGER.debug("ARP %s detail failed: %s", row.get("id"), det)
            elif isinstance(det, dict) and isinstance(det.get("assignments"), list):
                row["assignments"] = det["assignments"]
                row["inUseAssignments"] = det.get("inUseAssignments") or []
                row["_detailed"] = True
        return rows

    async def _update_access(self, data: CirrusData, prev: CirrusData) -> None:
        """UPAM sessions (which UNP each client is in) and alerts. Optional: needs the rights to read them."""
        for u in data.unps.values():
            u["clients"], u["seen_vlans"] = 0, []
        sessions, alerts = await asyncio.gather(
            self.client.get_auth_sessions(self.org_id),
            self.client.get_alerts(self.org_id, list(data.sites)),
            return_exceptions=True,
        )
        if isinstance(sessions, CirrusForbiddenError):
            data.access_error = "The Cirrus application's user may not read UPAM authentication records"
        elif isinstance(sessions, Exception):
            _LOGGER.debug("UPAM sessions failed: %s", sessions)
            data.sessions, data.access_error = prev.sessions, prev.access_error
            if not self._sessions_ok:
                data.access_error = f"Could not read UPAM sessions from Cirrus: {sessions}"
        else:
            data.sessions = parse_sessions(sessions)
            self._sessions_ok = True
        add_seen_vlans(data.unps, data.sessions)
        if isinstance(alerts, CirrusForbiddenError):
            data.alerts_error = "The Cirrus application's user may not read alerts. Give it read access to alerts in Cirrus to see them here."
        elif isinstance(alerts, Exception):
            (_LOGGER.debug if self._alerts_warned else _LOGGER.warning)("Cirrus alerts read failed: %s", alerts)
            self._alerts_warned = True
            data.alerts, data.alerts_error, data.alerts_raw = prev.alerts, prev.alerts_error, prev.alerts_raw
            if not self._alerts_ok:  # nothing good to show: say so rather than "no alerts"
                data.alerts_error = f"Could not read alerts from Cirrus: {alerts}"
        else:
            data.alerts = parse_alerts(alerts)
            data.alerts_raw = {str(r["id"]): r for r in alerts or [] if isinstance(r, dict) and r.get("id")}
            self._alerts_ok = True

    async def _update_radios(self, data: CirrusData, prev: CirrusData) -> None:
        aps = {s: d for s, d in data.devices.items() if d.get("deviceFamily") == "AP" and d.get("macAddress")}
        sem = asyncio.Semaphore(8)

        async def one(serial: str, dev: dict):
            async with sem:
                return serial, await self.client.get_rf_details(self.org_id, dev["macAddress"])

        results = await asyncio.gather(*(one(s, d) for s, d in aps.items()), return_exceptions=True)
        for (serial, _), res in zip(aps.items(), results):
            if isinstance(res, Exception):
                _LOGGER.debug("RF details failed for %s: %s", serial, res)
                data.radios[serial] = prev.radios.get(serial, [])
                if serial in prev.rf_profiles:
                    data.rf_profiles[serial] = prev.rf_profiles[serial]
                continue
            rf = res[1] or {}
            data.radios[serial] = sorted(rf.get("radios") or [], key=lambda r: r.get("radio") or "")
            if rf.get("rfProfileName"):
                data.rf_profiles[serial] = rf["rfProfileName"]

    async def _update_ssh(self, data: CirrusData, prev: CirrusData, now: float) -> None:
        opts = self.config_entry.options
        if not opts.get(CONF_SSH_ENABLED):
            return
        interval = opts.get(CONF_SSH_INTERVAL, DEFAULT_SSH_INTERVAL)
        if now - self._ssh_at < interval and prev.switch_tables:
            data.switch_tables, data.ssh_errors = prev.switch_tables, prev.ssh_errors
            return
        overrides = parse_ssh_hosts(opts.get(CONF_SSH_HOSTS))
        targets = {}
        for serial, dev in data.devices.items():
            if dev.get("deviceFamily") != "AOS":
                continue
            host = overrides[serial] if serial in overrides else overrides.get("*") or dev.get("ipAddress")
            if host:  # an empty address in the form means "skip this switch"
                targets[serial] = host

        async def one(serial: str, host: str):
            return serial, await fetch_switch_tables(
                host,
                opts.get(CONF_SSH_USERNAME, ""),
                opts.get(CONF_SSH_KEY_PATH) or None,
                opts.get(CONF_SSH_KNOWN_HOSTS) or None,
                int(opts.get(CONF_SSH_PORT, DEFAULT_SSH_PORT)),
                bool(opts.get(CONF_SSH_ARP, True)),
            )

        results = await asyncio.gather(*(one(s, h) for s, h in targets.items()), return_exceptions=True)
        for (serial, host), res in zip(targets.items(), results):
            if isinstance(res, Exception):
                msg = str(res) if isinstance(res, SshError) else f"{host}: {res!r}"
                data.ssh_errors[serial] = msg
                _LOGGER.warning("MAC table read failed for %s: %s", serial, msg)
                if serial in prev.switch_tables:
                    data.switch_tables[serial] = prev.switch_tables[serial]
            else:
                data.switch_tables[serial] = res[1]
        self._ssh_at = now

    async def _update_unifi(self, data: CirrusData, prev: CirrusData, now: float) -> None:
        if not self.unifi:
            return
        data.unifi_networks, data.unifi_known = prev.unifi_networks, prev.unifi_known
        data.unifi_firewall = prev.unifi_firewall
        try:
            snap = await self.unifi.snapshot()
        except UnifiError as err:
            data.unifi, data.unifi_error = prev.unifi, str(err)
            _LOGGER.warning("UniFi gateway read failed: %s", err)
            return
        if now - self._unifi_cfg_at > TOPOLOGY_INTERVAL or not prev.unifi_networks:
            # Networks and reservations change rarely: read them with the topology.
            try:
                data.unifi_networks = await self.unifi.networks()
                data.unifi_known = await self.unifi.known_clients()
                self._unifi_cfg_at = now
            except UnifiError as err:
                _LOGGER.debug("UniFi networks / known clients failed: %s", err)
            try:
                data.unifi_firewall = await self.unifi.firewall()
            except UnifiError as err:
                data.unifi_firewall = {"errors": {"all": str(err)}}
        data.unifi = {
            "wan": snap["wan"],
            "gateway": snap.get("gateway"),
            "clients": {
                norm_mac(c.get("mac")): c for c in snap["clients"] if norm_mac(c.get("mac"))
            },
        }

    async def _resolve_names(self, data: CirrusData) -> dict[str, str]:
        ips: set[str] = {c.get("clientIp") for c in data.clients.values() if c.get("clientIp")}
        for tables in data.switch_tables.values():
            ips.update(tables.arp.values())
        for topo in data.topology.values():
            for node in topo.get("nodes") or []:
                for addr in node.get("managementAddresses") or []:
                    if addr.get("address"):
                        ips.add(addr["address"])
        ips.update(d.get("ipAddress") for d in data.devices.values() if d.get("ipAddress"))
        ips.update(c.get("ip") for c in (data.unifi.get("clients") or {}).values() if c.get("ip"))
        ips.update(m.get("ip") for m in self.manual_devices if m.get("ip"))
        try:
            return await self.resolver.resolve_many(ips)
        except Exception as err:  # noqa: BLE001 - DNS must never break polling
            _LOGGER.debug("Reverse DNS failed: %s", err)
            return {}

    # ---------------------------------------------------------------- identity
    def _ha_devices(self) -> dict[str, HaDevice]:
        """MAC -> what other HA integrations know about the device."""
        result: dict[str, HaDevice] = {}
        registry = dr.async_get(self.hass)
        # Walk devices per config entry: works on every supported HA version and gives the
        # owning integration directly, without the deprecated registry.devices mapping or
        # DeviceEntry.config_entries.
        for entry in self.hass.config_entries.async_entries():
            if entry.domain == DOMAIN:
                continue
            for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
                macs = [norm_mac(v) for t, v in device.connections if t == dr.CONNECTION_NETWORK_MAC]
                macs = [m for m in macs if m]
                if not macs:
                    continue
                info = HaDevice(
                    name=device.name_by_user or device.name,
                    manufacturer=device.manufacturer,
                    model=device.model,
                    domain=entry.domain,
                )
                for mac in macs:
                    result.setdefault(mac, info)
        return result

    def _identities(self, data: CirrusData, ha: dict[str, HaDevice]) -> dict[str, dict]:
        unifi_clients = data.unifi.get("clients") or {}
        candidates: dict[str, dict] = {}
        for mac, c in data.clients.items():
            candidates[mac] = {"hostname": c.get("deviceName"), "os": c.get("osType"), "type": c.get("deviceType")}
        for tables in data.switch_tables.values():
            for entry in tables.macs:
                candidates.setdefault(entry.mac, {})
        for mac in unifi_clients:
            candidates.setdefault(mac, {})
        for dev in self.manual_devices:
            mac = norm_mac(dev.get("mac"))
            if mac:
                candidates.setdefault(mac, {})

        identities: dict[str, dict] = {}
        for mac, info in candidates.items():
            uc = unifi_clients.get(mac) or {}
            override = self.store.overrides.get(mac) or {}
            hostname = info.get("hostname") or uc.get("hostname")
            oui = None if is_private_mac(mac) else self.assets.vendor(mac)
            prof = data.iot.get(mac) or {}
            ident = identify(
                mac,
                hostname,
                oui_vendor=oui,
                cirrus_os=info.get("os"),
                cirrus_type=info.get("type"),
                ha=ha.get(mac),
                unifi_vendor=uc.get("oui"),
                override_type=override.get("type"),
                profile=prof,
            )
            if uc.get("name"):
                ident.sources.append("UniFi")
            identities[mac] = {
                "name": override.get("name") or uc.get("name"),  # user-set names win
                "hostname": hostname,
                "ip": uc.get("ip") or uc.get("last_ip"),
                "label": ident.describe(),
                "type": ident.type,
                "type_label": ident.type_label,
                "icon": ident.icon,
                "vendor": ident.vendor,
                "brand": ident.brand,
                "model": ident.model,
                "private_mac": ident.private_mac,
                "logo": self.assets.logo(ident.logo_sources),
                "sources": list(dict.fromkeys(ident.sources)),
                "overridden": bool(override),
                "profile": prof or None,
            }
        return identities

    def _device_images(self, data: CirrusData) -> tuple[dict[str, str], dict[str, dict]]:
        """Model slug -> image URL (your files > bundled > NetBox) and NetBox port layouts."""
        images = dict(self.hass.data.get(DOMAIN, {}).get("images", {}))
        layouts: dict[str, dict] = {}
        models = {(d.get("modelName"), "Alcatel-Lucent") for d in data.devices.values() if d.get("deviceFamily") == "AOS"}
        gw_model = (data.unifi.get("wan") or {}).get("gateway_model")
        if gw_model:
            models.add((gw_model, "Ubiquiti"))
        for model, vendor in models:
            if not model:
                continue
            slug = model_slug(model)
            if slug not in images:
                url = self.assets.netbox_image(vendor, model)
                if url:
                    images[slug] = url
            if vendor == "Alcatel-Lucent":
                ports = self.assets.netbox_ports(vendor, model)
                if ports:
                    layouts[slug] = ports
        return images, layouts

    # ---------------------------------------------------------------- map
    def _build_maps(self, data: CirrusData) -> dict[str, dict]:
        ha = self._ha_devices()
        ha_names = {mac: d.name for mac, d in ha.items() if d.name}
        identities = self._identities(data, ha)
        images, layouts = self._device_images(data)
        opts = self.config_entry.options
        extras = MapExtras(
            identities=identities,
            manual=self.manual_devices,
            services=self.services_view(),
            wan=(data.unifi.get("wan") or None),
            gateway=(data.unifi.get("gateway") or None),
            port_layouts=layouts,
            port_vlans=data.port_vlans,
            vlans=data.vlans,
            radios={norm_mac(data.devices[s].get("macAddress")): r for s, r in data.radios.items()},
            rf_profiles={norm_mac(data.devices[s].get("macAddress")): p for s, p in data.rf_profiles.items()},
            entry_id=self.config_entry.entry_id,
            unifi_ips={m: c.get("ip") for m, c in (data.unifi.get("clients") or {}).items() if c.get("ip")},
        )
        maps: dict[str, dict] = {}
        for sid, site in data.sites.items():
            try:
                maps[sid] = build_site_map(
                    site,
                    list(data.devices.values()),
                    data.topology.get(sid) or {},
                    data.lldp,
                    list(data.clients.values()),
                    data.switch_tables,
                    ha_names,
                    ports_by_serial=data.ports,
                    dns_names=data.dns_names,
                    prefer_dns=bool(opts.get(CONF_DNS_PREFER, False)),
                    dns_short=bool(opts.get(CONF_DNS_SHORT, True)),
                    images=images,
                    extras=extras,
                )
                self._apply_photos(maps[sid])
                self._apply_access(maps[sid], data)
                maps[sid]["ssh_errors"] = list(data.ssh_errors.values())
                maps[sid]["positions"] = dict(self.store.positions.get(sid, {}))
                maps[sid]["switches"] = [
                    {"serial": s, "name": d.get("name") or s}
                    for s, d in data.devices.items()
                    if d.get("deviceFamily") == "AOS" and (d.get("site") or {}).get("id") == sid
                ]
                if data.unifi_error:
                    maps[sid]["unifi_error"] = data.unifi_error
            except Exception:  # noqa: BLE001 - never let the map break polling
                _LOGGER.exception("Failed to build network map for site %s", sid)
        return maps

    def _apply_access(self, site_map: dict, data: CirrusData) -> None:
        """Mark each client with the UNP (Access Role Profile) UPAM gave it, and list the site's UNPs."""
        counts: dict[str, int] = {}
        for node in walk_nodes(site_map["root"]):
            s = data.sessions.get(node.get("mac") or "")
            if not s or node.get("kind") in ("internet", "gateway", "switch", "ap"):
                continue
            if s.get("unp"):
                node["unp"] = s["unp"]
                counts[s["unp"]] = counts.get(s["unp"], 0) + 1
            rows = [
                ("Access role (UNP)", s.get("unp")),
                ("UNP VLAN", s.get("vlan")),
                ("Policy list", (data.unps.get(s.get("unp") or "") or {}).get("policy_list")),
                ("Access policy", s.get("policy")),
                ("Authentication", s.get("auth")),
                ("Auth user", s.get("user")),
            ]
            node["details"] = [*node.get("details", []), *[[k, str(v)] for k, v in rows if v not in (None, "")]]
        site_map["unps"] = [
            {**{k: u[k] for k in ("name", "policy_list", "vlans", "seen_vlans", "status")}, "clients": counts.get(name, 0)}
            for name, u in sorted(data.unps.items())
        ]
        if data.access_error:
            site_map["access_error"] = data.access_error

    def _build_firewall(self, data: CirrusData) -> dict:
        try:
            return firewall.build(
                data.unifi_firewall, data.unifi_networks, data.unifi_known, (data.unifi or {}).get("clients") or {}
            )
        except Exception:  # noqa: BLE001 - a firewall format we do not understand must not break the map
            _LOGGER.exception("Could not decode the UniFi firewall")
            return {"errors": {"decode": "Could not decode the gateway's firewall (see the log)."}}

    def unp_details(self) -> list[dict]:
        """Each UNP with where it is assigned, its VLANs, the gateway network on each and that network's
        firewall zone (for the UNPs view). Read-only."""
        if not self.data:
            return []
        nets = (self.data.ipam or {}).get("networks") or []
        zone_of = (self.data.firewall or {}).get("zone_of_network") or {}
        zname = {z["id"]: z["name"] for z in (self.data.firewall or {}).get("zones") or []}
        counts: dict[str, int] = {}
        seen_nets: dict[str, set[str]] = {}  # UNP -> network ids its online devices have addresses in
        wifi_vlans: dict[str, set[int]] = {}  # UNP -> VLANs its wireless clients are on
        uclients = (self.data.unifi or {}).get("clients") or {}
        parsed = []
        for n in nets:
            try:
                parsed.append((ipaddress.IPv4Network(n["cidr"]), n))
            except (KeyError, ValueError):
                continue
        for mac, s in (self.data.sessions or {}).items():
            if not s.get("unp"):
                continue
            counts[s["unp"]] = counts.get(s["unp"], 0) + 1
            ip = (uclients.get(mac) or {}).get("ip") or s.get("ip")
            try:
                addr = ipaddress.IPv4Address(str(ip)) if ip else None
            except ValueError:
                addr = None
            if addr:
                hit = next((n for net, n in parsed if addr in net), None)
                if hit:
                    seen_nets.setdefault(s["unp"], set()).add(hit["id"])
            wv = _int((self.data.clients.get(mac) or {}).get("vlanId"))
            if wv and wv > 1:
                wifi_vlans.setdefault(s["unp"], set()).add(wv)
        out = []
        for name, u in sorted(self.data.unps.items(), key=lambda kv: kv[0].lower()):
            vl = set(u.get("vlans") or []) | set(u.get("seen_vlans") or []) | wifi_vlans.get(name, set())
            on, ids = [], set()
            for n in nets:
                by_vlan = n.get("vlan") in vl
                by_ip = n["id"] in seen_nets.get(name, set())
                if not (by_vlan or by_ip) or n["id"] in ids:
                    continue
                ids.add(n["id"])
                if n.get("vlan") is not None:
                    vl.add(n["vlan"])
                zid = zone_of.get(n["id"]) if n.get("source") == "UniFi" else None
                on.append({"vlan": n.get("vlan"), "network": n["name"], "network_id": n["id"], "cidr": n["cidr"],
                           "source": n.get("source"), "zone_id": zid, "zone": zname.get(zid),
                           "how": "Cirrus VLAN" if by_vlan else "addresses of its online devices"})
            vl = sorted(vl)
            out.append({**{k: u.get(k) for k in ("name", "policy_list", "status", "assigned", "assignments", "detailed", "captive_portal", "bandwidth")},
                        "vlans": vl, "networks": on, "clients": counts.get(name, 0)})
        return out

    def ssid_details(self) -> list[dict]:
        """Each SSID as its connected clients show it: the VLAN(s) they are on (tagged, or untagged on the AP
        port's native VLAN), the network that is, and which UNPs they are in. A wireless device whose UNP sets
        no VLAN (or with no UNP) gets the SSID's own VLAN. Read-only."""
        if not self.data:
            return []
        nets = (self.data.ipam or {}).get("networks") or []
        parsed = []
        for n in nets:
            try:
                parsed.append((ipaddress.IPv4Network(n["cidr"]), n))
            except (KeyError, ValueError):
                continue
        zone_of = (self.data.firewall or {}).get("zone_of_network") or {}
        zname = {z["id"]: z["name"] for z in (self.data.firewall or {}).get("zones") or []}
        uclients = (self.data.unifi or {}).get("clients") or {}
        by: dict[str, dict] = {}
        for mac, c in (self.data.clients or {}).items():
            ssid = c.get("ssid")
            if not ssid:
                continue
            row = by.setdefault(ssid, {"ssid": ssid, "clients": 0, "vlans": {}, "unps": {}, "nets": {}})
            row["clients"] += 1
            v = _int(c.get("vlanId"))
            key = str(v) if v and v > 1 else "untagged"
            row["vlans"][key] = row["vlans"].get(key, 0) + 1
            unp = ((self.data.sessions or {}).get(mac) or {}).get("unp") or "(none)"
            row["unps"][unp] = row["unps"].get(unp, 0) + 1
            ip = c.get("clientIp") or (uclients.get(mac) or {}).get("ip")
            try:
                addr = ipaddress.IPv4Address(str(ip)) if ip else None
            except ValueError:
                addr = None
            hit = next((n for net, n in parsed if addr and addr in net), None)
            if hit:
                nid = hit["id"]
                if nid not in row["nets"]:
                    zid = zone_of.get(nid) if hit.get("source") == "UniFi" else None
                    row["nets"][nid] = {"network": hit["name"], "vlan": hit.get("vlan"), "cidr": hit["cidr"],
                                        "zone_id": zid, "zone": zname.get(zid), "clients": 0}
                row["nets"][nid]["clients"] += 1
        out = []
        for row in sorted(by.values(), key=lambda r: r["ssid"].lower()):
            out.append({**row, "nets": sorted(row["nets"].values(), key=lambda n: -n["clients"])})
        return out

    def _build_ipam(self, data: CirrusData) -> dict:
        """Subnets, DHCP pools, reservations and every address in use (see ipam.py)."""
        try:
            networks = merge_networks(
                parse_unifi_networks(data.unifi_networks), parse_cirrus_interfaces(data.ip_interfaces, data.vlans), data.vlans
            )
        except Exception:  # noqa: BLE001 - never let IPAM break polling
            _LOGGER.exception("Could not read the network list for the address view")
            return {}
        if not networks:
            return {}
        names: dict[str, str] = {}
        sightings: list[Sighting] = []
        for site_map in data.maps.values():
            for node in walk_nodes(site_map["root"]):
                mac = norm_mac(node.get("mac"))
                if mac and node.get("name"):
                    names.setdefault(mac, node["name"])
                if node.get("kind") == "manual" and node.get("ip"):
                    sightings.append(Sighting(node["ip"], mac, "Manual", node.get("status") != "offline", node.get("name")))
        for dev in data.devices.values():
            if dev.get("ipAddress"):
                online = data.node_status.get(norm_mac(dev.get("macAddress")) or "") != "offline"
                sightings.append(Sighting(dev["ipAddress"], dev.get("macAddress"), "Device", online, dev.get("name")))
        for c in data.clients.values():
            if c.get("clientIp"):
                sightings.append(Sighting(c["clientIp"], c.get("clientMac"), "Cirrus"))
        for mac, s in data.sessions.items():
            if s.get("ip"):
                sightings.append(Sighting(s["ip"], mac, "UPAM"))
        for tables in data.switch_tables.values():
            for mac, ip in tables.arp.items():
                sightings.append(Sighting(ip, mac, "ARP"))
        for c in (data.unifi.get("clients") or {}).values():
            if c.get("ip"):
                sightings.append(Sighting(c["ip"], c.get("mac"), "UniFi", True, c.get("name") or c.get("hostname")))
        reservations = [
            Reservation(u["fixed_ip"], u["mac"], u.get("name") or u.get("hostname"), u.get("network_id"))
            for u in data.unifi_known
            if u.get("use_fixedip") and u.get("fixed_ip") and u.get("mac")
        ]
        try:
            return build_ipam(networks, sightings, reservations, names)
        except Exception:  # noqa: BLE001 - never let IPAM break polling
            _LOGGER.exception("Failed to build the address view")
            return {}

    def _alert_events(self, data: CirrusData) -> None:
        """Fire ovcirrus_alert once for each new, unacknowledged Cirrus alert (none on the very first read)."""
        fresh = self.store.observe_alerts([a["id"] for a in data.alerts])
        for alert in data.alerts:
            if alert["id"] in fresh and not alert["acknowledged"]:
                self.hass.bus.async_fire(
                    EVENT_ALERT,
                    {"entry_id": self.config_entry.entry_id, **{k: v for k, v in alert.items() if k != "rank"}},
                )

    def _observe(self, data: CirrusData) -> None:
        """New-device detection over everything placed on the maps."""
        seen: dict[str, dict] = {}
        for site_map in data.maps.values():
            for node in walk_nodes(site_map["root"]):
                mac = node.get("mac")
                if mac and node.get("kind") in ("wireless", "wired", "manual"):
                    seen[mac] = {
                        "name": node["name"],
                        "hostname": node.get("hostname"),
                        "vendor": node.get("vendor"),
                        "ip": node.get("ip"),
                        "where": node.get("where"),
                        "type": node.get("type_label"),
                        "site": site_map.get("site_name"),
                    }
        for new in self.store.observe(seen):
            _LOGGER.info("New device on the network: %s", new)
            self.hass.bus.async_fire(EVENT_NEW_CLIENT, {"entry_id": self.config_entry.entry_id, **new})
        for site_map in data.maps.values():
            for node in walk_nodes(site_map["root"]):
                if node.get("mac") and self.store.is_new(node["mac"]):
                    node["is_new"] = True
            site_map["summary"]["new_devices"] = len(self.store.recent_new())

    def registration_options(self) -> dict:
        """Networks with free addresses and the UNPs, for the registration form."""
        if not self.data:
            return {"networks": [], "unps": []}
        return registration.options(self.data.ipam, self.data.unps)

    def _ipam_net(self, network_id: str | None) -> dict | None:
        return next((n for n in (self.data.ipam or {}).get("networks") or [] if n["id"] == network_id), None) if self.data else None

    @staticmethod
    def _controls(net: dict) -> list[str]:
        """Addresses in a network known to be up right now (gateway + a few online devices): if none of them
        answer a ping either, silence from a free address proves nothing."""
        online = [a["ip"] for a in net.get("addresses") or [] if a.get("online")]
        return [x for x in [net.get("gateway"), *online[:6]] if x]

    async def async_ping_sweep(self, network_id: str) -> dict:
        """Ping every address the registration form offers as free in a network (read-only)."""
        net = self._ipam_net(network_id)
        if not net:
            raise ValueError("Unknown network")
        free = registration.free_addresses(net)
        res = await probe.probe([*free["pool"], *free["other"]], self._controls(net))
        res["network_id"] = network_id
        return res

    async def async_registration_preview(self, req: dict) -> dict:
        """What registering a device would change. Reads only (company properties are fetched fresh)."""
        if not self.data:
            return {"ok": False, "errors": ["No data from Cirrus yet."], "warnings": [], "notes": [], "changes": []}
        props, props_error = None, None
        try:
            props = await self.client.get_company_properties(self.org_id)
        except CirrusError as err:
            props_error = str(err)
        online = {
            mac: {"ip": c.get("ip"), "name": c.get("name") or c.get("hostname")}
            for mac, c in ((self.data.unifi or {}).get("clients") or {}).items()
        }
        ping = None
        net = self._ipam_net(req.get("network_id"))
        if net and req.get("ip") and net.get("source") == "UniFi":
            try:
                ping = await probe.probe([str(req["ip"]).strip()], self._controls(net))
            except (RuntimeError, ValueError) as err:
                ping = {"error": str(err)}
        return registration.build_preview(
            req,
            ping=ping,
            ipam=self.data.ipam,
            unps=self.data.unps,
            known=self.data.unifi_known,
            online=online,
            sessions=self.data.sessions,
            company_props=props,
            company_props_error=props_error,
            unifi_site=getattr(self.unifi, "site", None) if self.unifi else None,
        )

    async def async_alert_details(self, alert_id: str) -> dict:
        """More about one alert for the card's details panel, fetched when it is opened. Read-only GETs:
        every field Cirrus sent for it, its category from the alert definitions, and the client's other alerts
        over the last 30 days."""
        raw = (self.data.alerts_raw if self.data else {}).get(str(alert_id))
        if raw is None:
            raise ValueError("That alert is no longer in the list from Cirrus.")
        out: dict = {"id": str(alert_id), "fields": {}, "category": None, "definition": None,
                     "client_history": None, "client_total": None, "errors": {}}
        for k, v in raw.items():
            if v in (None, "", [], {}) or isinstance(v, (dict, list)):
                continue
            out["fields"][k] = v
        now = time.monotonic()
        if self._alert_defs is None or now - self._alert_defs[0] > 3600:
            try:
                self._alert_defs = (now, await self.client.get_alert_definitions(self.org_id))
            except CirrusError as err:
                out["errors"]["definitions"] = str(err)
        if self._alert_defs:
            tid, name = raw.get("alertTypeId"), raw.get("alertType")
            d = next((d for d in self._alert_defs[1] if tid and tid in (d.get("alertTypeId"), d.get("id"))), None) or \
                next((d for d in self._alert_defs[1] if name and d.get("name") == name), None)
            if d:
                out["category"] = d.get("category")
                out["definition"] = {k: d.get(k) for k in ("name", "category", "severity", "isEnabled")}
        sta = raw.get("staMac")
        if sta:
            try:
                rows, out["client_total"] = await self.client.get_client_alerts(self.org_id, sta.upper())
                hist = parse_alerts(rows)
                out["client_history"] = [
                    {k: h.get(k) for k in ("id", "time", "severity", "type", "reason", "device", "ssid", "acknowledged")}
                    for h in hist
                ]
            except CirrusError as err:
                out["errors"]["client_history"] = str(err)
        return out

    async def async_acknowledge_alerts(
        self, ids: list[str] | None = None, alert_type: str | None = None, client_mac: str | None = None
    ) -> int:
        """Acknowledge unacknowledged alerts in Cirrus: the given ids, or every one matching the filters
        (all of them when nothing is given). Returns how many were acknowledged."""
        if not self.data:
            return 0
        wanted = set(ids or [])
        mac = norm_mac(client_mac) if client_mac else None
        targets = [
            a
            for a in self.data.alerts
            if not a["acknowledged"]
            and (not wanted or a["id"] in wanted)
            and (not alert_type or (a.get("type") or "").lower() == alert_type.lower())
            and (not mac or a.get("client_mac") == mac)
        ]
        if not targets:
            return 0
        await self.client.acknowledge_alerts(self.org_id, [a["id"] for a in targets])
        for a in targets:
            a["acknowledged"] = True
        self.async_set_updated_data(self.data)
        return len(targets)

    def rebuild(self) -> None:
        """Re-render maps from cached data (after an override, scan result or new asset)."""
        if not self.data:
            return
        self.data.maps = self._build_maps(self.data)
        self.data.ipam = self._build_ipam(self.data)
        self.data.firewall = self._build_firewall(self.data)
        self._observe(self.data)
        self.async_set_updated_data(self.data)

    def _apply_photos(self, site_map: dict) -> None:
        """Your uploaded pictures, by MAC (so they follow a client between Wi-Fi and cable) or map id."""
        photos = self.store.photos
        for node in walk_nodes(site_map["root"]):
            if node.get("kind") in ("internet", "ap", "switch", "gateway"):
                continue
            key = norm_mac(node.get("mac")) or node.get("id")
            node["photo_key"] = key
            p = photos.get(key or "") or photos.get(node.get("id") or "")
            if p:
                node["photo"] = f"{PHOTOS_URL}/{p['file']}?v={p.get('v', 0)}"

    # ---------------------------------------------------------------- discovery
    def _schedule_discovery(self, data: CirrusData) -> None:
        if not self.hass.data.setdefault(DOMAIN, {}).get("nmap_issue_cleared"):
            ir.async_delete_issue(self.hass, DOMAIN, "nmap_missing")  # left over from versions that used nmap
            self.hass.data[DOMAIN]["nmap_issue_cleared"] = True
        hours = float(self.config_entry.options.get(CONF_DISCOVERY_INTERVAL, DEFAULT_DISCOVERY_INTERVAL))
        for dev in self.manual_devices:
            ip = dev.get("ip")
            if not dev.get("discover") or not ip or ip in self._scanning:
                continue
            last = (self.store.services.get(ip) or {}).get("ts", 0)
            if time.time() - last > hours * 3600:
                mode = "full" if dev.get("scan") == "full" else "quick"
                self.hass.async_create_background_task(self.async_discover(ip, mode), f"ovcirrus discover {ip}")

    async def async_discover(self, ip: str, mode: str = "quick") -> dict:
        if ip in self._scanning:
            return self.services_view().get(ip) or {}
        self._scanning.add(ip)
        try:
            mine = {int(p) for p in self.store.port_labels.get("*", {}) if str(p).isdigit()}
            result = await (full_scan(ip, mine) if mode == "full" else discover(ip, mine))
            self.store.set_services(ip, result)
            self.rebuild()
            return self.services_view().get(ip, result)
        finally:
            self._scanning.discard(ip)

    def wired_count(self, data: CirrusData | None = None) -> int:
        data = data or self.data
        return sum(m["summary"]["wired_clients"] for m in data.maps.values())


def device_status(data: CirrusData, device: dict[str, Any]) -> str:
    mac = norm_mac(device.get("macAddress"))
    return data.node_status.get(mac or "", "unknown")
