"""Async client for the OmniVista Cirrus REST API."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

PAGE_SIZE = 200
TIMEOUT = aiohttp.ClientTimeout(total=45)


class CirrusError(Exception):
    """Base error."""


class CirrusAuthError(CirrusError):
    """Credentials rejected."""


class CirrusApiError(CirrusError):
    """Request failed."""


class CirrusForbiddenError(CirrusApiError):
    """The application's user may not read this (e.g. no UPAM rights). Not a login problem."""


class CirrusClient:
    """Minimal OmniVista Cirrus API client."""

    def __init__(
        self, session: aiohttp.ClientSession, host: str, app_id: str, app_secret: str
    ) -> None:
        self._session = session
        self._host = host.strip().removeprefix("https://").rstrip("/")
        self._base = f"https://{self._host}/api"
        self._app_id = app_id
        self._app_secret = app_secret
        self._token: str | None = None
        self._token_expiry = 0.0
        self._auth_lock = asyncio.Lock()

    @property
    def _headers(self) -> dict[str, str]:
        # Cirrus rejects requests without these (csrf_missing_validation_headers).
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": f"https://{self._host}",
            "Referer": f"https://{self._host}/",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def authenticate(self) -> None:
        """Obtain a bearer token."""
        async with self._auth_lock:
            self._token = None
            try:
                async with self._session.post(
                    f"{self._base}/ov/v1/applications/authenticate",
                    json={"appId": self._app_id, "appSecret": self._app_secret},
                    headers=self._headers,
                    timeout=TIMEOUT,
                ) as resp:
                    body = await _read_json(resp)
                    if resp.status in (400, 401, 403):
                        raise CirrusAuthError(_err_text(resp.status, body))
                    if resp.status != 200 or not isinstance(body, dict):
                        raise CirrusApiError(_err_text(resp.status, body))
            except aiohttp.ClientError as err:
                raise CirrusApiError(f"Cannot reach {self._host}: {err}") from err
            token = body.get("access_token")
            if not token:
                raise CirrusAuthError("No access_token in response")
            self._token = token
            # Refresh an hour early (tokens last ~15 days).
            self._token_expiry = time.monotonic() + int(body.get("expires_in", 3600)) - 3600

    async def _get(self, path: str, params: dict[str, Any] | None = None, optional: bool = False) -> Any:
        """GET one resource. With optional=True a 403 raises CirrusForbiddenError instead of an auth failure,
        so a feature the account cannot read is skipped without failing the whole integration."""
        if not self._token or time.monotonic() > self._token_expiry:
            await self.authenticate()
        query = _encode_params(params or {})
        for attempt in (1, 2):
            try:
                async with self._session.get(
                    f"{self._base}{path}", params=query, headers=self._headers, timeout=TIMEOUT
                ) as resp:
                    body = await _read_json(resp)
                    if resp.status == 403 and optional:
                        raise CirrusForbiddenError(f"{path}: {_err_text(resp.status, body)}")
                    if resp.status in (401, 403) and attempt == 1:
                        await self.authenticate()
                        continue
                    if resp.status in (401, 403):
                        raise CirrusAuthError(_err_text(resp.status, body))
                    if resp.status != 200:
                        raise CirrusApiError(f"{path}: {_err_text(resp.status, body)}")
                    return body.get("data") if isinstance(body, dict) else body
            except aiohttp.ClientError as err:
                raise CirrusApiError(f"{path}: {err}") from err
        raise CirrusApiError(f"{path}: retry exhausted")

    async def _put(self, path: str, body: dict) -> Any:
        """PUT a change. A 403 means the application's user may not make it (CirrusForbiddenError), never reauth
        in a loop: one retry after a fresh token, as for reads."""
        if not self._token or time.monotonic() > self._token_expiry:
            await self.authenticate()
        for attempt in (1, 2):
            try:
                async with self._session.put(
                    f"{self._base}{path}", json=body, headers=self._headers, timeout=TIMEOUT
                ) as resp:
                    data = await _read_json(resp)
                    if resp.status == 401 and attempt == 1:
                        await self.authenticate()
                        continue
                    if resp.status == 403:
                        raise CirrusForbiddenError(f"{path}: {_err_text(resp.status, data)}")
                    if resp.status not in (200, 201, 204):
                        raise CirrusApiError(f"{path}: {_err_text(resp.status, data)}")
                    return data.get("data") if isinstance(data, dict) else data
            except aiohttp.ClientError as err:
                raise CirrusApiError(f"{path}: {err}") from err
        raise CirrusApiError(f"{path}: retry exhausted")

    async def acknowledge_alerts(self, org_id: str, ids: list[str]) -> None:
        """Acknowledge alerts in Cirrus by id (the same as Acknowledge in the Cirrus Alerts page)."""
        for i in range(0, len(ids), 100):
            await self._put(f"/ov/v1/organizations/{org_id}/alerts/acknowledge", {"ids": ids[i : i + 100]})

    async def get_organizations(self) -> list[dict]:
        return await self._get("/ov/v1/organizations") or []

    async def get_sites(self, org_id: str) -> list[dict]:
        return await self._get(f"/ov/v1/organizations/{org_id}/sites") or []

    async def get_devices(self, org_id: str) -> list[dict]:
        return await self._get(f"/ov/v1/organizations/{org_id}/sites/devices") or []

    async def get_topology(self, org_id: str, site_id: str) -> dict:
        return (
            await self._get(
                f"/ov/v1/organizations/{org_id}/sites/{site_id}/topology",
                {"scope": "site", "scopeId[]": [site_id]},
            )
            or {}
        )

    async def get_lldp(self, org_id: str, serial: str) -> list[dict]:
        return (
            await self._get(
                f"/ov/v1/organizations/{org_id}/lan-analytics/switch/lldp",
                {"serialNumber": serial},
            )
            or []
        )

    async def get_ports(self, org_id: str, serial: str) -> list[dict]:
        data = await self._get(
            f"/ov/v1/organizations/{org_id}/lan-analytics/switch/ports-list",
            {"serialNumber": serial},
        )
        return (data or {}).get("ports") or [] if isinstance(data, dict) else []

    async def get_port_vlans(self, org_id: str, serial: str) -> list[dict]:
        # The server requires serialNumber although the spec documents serials[]; send both.
        return (
            await self._get(
                f"/ov/v1/organizations/{org_id}/lan-analytics/switch/ports-vlan-list",
                {"serialNumber": serial, "serials[]": [serial]},
            )
            or []
        )

    async def get_vlans(self, org_id: str, site_ids: list[str]) -> list[dict]:
        vlans: list[dict] = []
        offset = 0
        while True:
            page = await self._get(
                f"/ov/v1/organizations/{org_id}/vlan",
                {"limit": 100, "offset": offset, "filters": "{}", "sort": "[]", "scope": "site", "scopeId[]": site_ids},
            ) or {}
            rows = page.get("result") or [] if isinstance(page, dict) else []
            vlans.extend(rows)
            if len(rows) < 100 or offset > 4000:
                return vlans
            offset += 100

    async def get_rf_details(self, org_id: str, ap_mac: str) -> dict:
        """Live radio state of one AP: band, channel, width, TX power, utilisation, noise floor."""
        return await self._get(f"/ov/v1/organizations/{org_id}/wlan-analytics/access-points/rf-details/{ap_mac}") or {}

    async def get_ip_interfaces(self, org_id: str, site_ids: list[str]) -> list[dict]:
        """Layer-3 interfaces of managed switches (one per routed VLAN, loopback, EMP...)."""
        result: list[dict] = []
        offset = 0
        while True:
            page = await self._get(
                f"/ov/v1/organizations/{org_id}/ipInterface",
                {"limit": 100, "offset": offset, "filters": "{}", "sort": "[]", "scope": "site", "scopeId[]": site_ids},
            ) or {}
            rows = page.get("ipInterfaces") or [] if isinstance(page, dict) else []
            result.extend(rows)
            if len(rows) < 100 or offset > 5000:
                return result
            offset += 100

    async def get_wireless_clients(self, org_id: str, site_ids: list[str]) -> list[dict]:
        clients: list[dict] = []
        offset = 0
        while True:
            page = await self._get(
                f"/ov/v1/organizations/{org_id}/wlan-analytics/sessions/wireless/current",
                {
                    "scope": "site",
                    "scopeId[]": site_ids,
                    "limit": PAGE_SIZE,
                    "offset": offset,
                    "filters": "{}",
                    "sort": "[]",
                },
            )
            page = page or []
            clients.extend(page)
            if len(page) < PAGE_SIZE or offset > 20000:
                return clients
            offset += PAGE_SIZE

    # ---- Unified access (UPAM / UNP). Read-only; these need an account that can see UPAM.
    async def get_access_role_profiles(self, org_id: str) -> list[dict]:
        """Access Role Profiles (UNPs), with their policy list and per-assignment VLAN mapping."""
        return await self._get(f"/ov/v1/organizations/{org_id}/network-configuration/arps", optional=True) or []

    async def get_access_role_profile(self, org_id: str, arp_id: Any) -> dict:
        """One Access Role Profile with its assignments. Unlike the list, each assignment here carries its
        VLAN/tunnel mapping (vlanTunnelMapping) and the response says which group assignments SSIDs use."""
        return await self._get(
            f"/ov/v1/organizations/{org_id}/network-configuration/arps/id/{arp_id}", optional=True
        ) or {}

    async def get_auth_sessions(self, org_id: str) -> list[dict]:
        """Current UPAM authentication sessions: MAC, final Access Role Profile, VLAN, policy, NAS."""
        rows: list[dict] = []
        offset = 0
        while True:
            page = await self._get(
                f"/ov/v1/organizations/{org_id}/am/access-records/authentication-online-records",
                {"limit": PAGE_SIZE, "offset": offset},
                optional=True,
            ) or {}
            batch = (page.get("list") or []) if isinstance(page, dict) else (page if isinstance(page, list) else [])
            rows.extend(batch)
            if len(batch) < PAGE_SIZE or offset > 20000:
                return rows
            offset += PAGE_SIZE

    async def get_company_properties(self, org_id: str) -> list[dict]:
        """UPAM company properties (MAC -> device name, Access Role Profile). Read-only."""
        rows: list[dict] = []
        offset = 0
        while True:
            page = await self._get(
                f"/ov/v1/organizations/{org_id}/am/accounts/company-properties",
                {"limit": PAGE_SIZE, "offset": offset},
                optional=True,
            ) or {}
            if isinstance(page, list):
                batch = page
            elif isinstance(page, dict):
                batch = page.get("list") or page.get("result") or page.get("data") or []
            else:
                batch = []
            rows.extend(batch)
            if len(batch) < PAGE_SIZE or offset > 20000:
                return rows
            offset += PAGE_SIZE

    async def get_alerts(self, org_id: str, site_ids: list[str], days: int = 7) -> list[dict]:
        """Alerts for the chosen sites from the last few days (acknowledged ones included).

        Uses alertsummary, which is what the Cirrus web UI reads. With period "None" it returns one record per
        alert (id, device, client MAC, SSID, reason); startDate/endDate (ISO 8601 with milliseconds) and period
        are required, otherwise the server answers HTTP 400.
        """
        now = datetime.now(timezone.utc)
        iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"  # noqa: E731
        rows: list[dict] = []
        offset = 0
        while True:
            data = await self._get(
                f"/ov/v1/organizations/{org_id}/alerts/alertsummary",
                {
                    "startDate": iso(now - timedelta(days=days)),
                    "endDate": iso(now),
                    "scope": "site",
                    "scopeId[]": site_ids,
                    "offset": offset,
                    "limit": 300,
                    "period": "None",
                },
                optional=True,
            )
            if isinstance(data, list):
                batch = data
            elif isinstance(data, dict):
                batch = data.get("result") or data.get("list") or []
            else:
                batch = []
            rows.extend(batch)
            if len(batch) < 300 or offset >= 1800:
                return rows
            offset += 300


def _encode_params(params: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in params.items():
        if isinstance(value, (list, tuple)):
            out.extend((key, str(v)) for v in value)
        elif isinstance(value, (dict,)):
            out.append((key, json.dumps(value)))
        else:
            out.append((key, str(value)))
    return out


async def _read_json(resp: aiohttp.ClientResponse) -> Any:
    try:
        return await resp.json(content_type=None)
    except (ValueError, aiohttp.ContentTypeError):
        return (await resp.text())[:300]


def _err_text(status: int, body: Any) -> str:
    if isinstance(body, dict):
        detail = body.get("errorDetailsCode") or body.get("errorMsg") or body.get("message")
        return f"HTTP {status}: {detail}"
    return f"HTTP {status}: {body}"
