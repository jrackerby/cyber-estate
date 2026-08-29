"""HTTP client for the nmap-scanner agent.

THE AGENT'S RESPONSE IS A CONTRACT, AND THIS FILE IS THE ONLY PLACE THAT KNOWS
ITS SHAPE. Everything downstream receives a validated `Inventory`, so a change
to the wire format is a change to one file.

FAILURE MODES ARE DISTINGUISHED, NEVER COLLAPSED. "cannot reach the scanner",
"the token is wrong", "the agent speaks a version I do not" and "no scan has
run yet" are four different situations needing four different actions, and an
integration that reports all of them as "unavailable" tells the operator
nothing. In particular an unreachable scanner must never surface as an empty
inventory: zero hosts is a claim about the network, and we have not measured
the network.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from .const import REQUEST_TIMEOUT, SUPPORTED_SCHEMA_VERSION

_LOGGER = logging.getLogger(__name__)


class NetworkInventoryError(Exception):
    """Base error."""


class CannotConnect(NetworkInventoryError):
    """The agent could not be reached."""


class InvalidAuth(NetworkInventoryError):
    """The agent rejected the token."""


class NoInventoryYet(NetworkInventoryError):
    """The agent is up but no scan has completed.

    Deliberately NOT an empty result. An agent that has never seen a scan and a
    network with nothing on it are different facts.
    """


class UnsupportedSchema(NetworkInventoryError):
    """The agent speaks a payload version this client does not."""

    def __init__(self, got: Any) -> None:
        super().__init__(
            f"agent reports schema_version {got!r}, this integration supports "
            f"{SUPPORTED_SCHEMA_VERSION}"
        )
        self.got = got


@dataclass(slots=True)
class Inventory:
    """One validated snapshot of the agent's view of the network."""

    schema_version: int
    generated_at: int
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def host_count(self) -> int:
        return len(self.hosts)


class NetworkInventoryClient:
    """Talks to one agent."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        token: str,
        use_tls: bool = False,
        verify_ssl: bool = True,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._token = token
        self._scheme = "https" if use_tls else "http"
        self._verify_ssl = verify_ssl
        # Kept across refreshes so a poll between scans costs headers only.
        # Reset whenever a response fails validation, so a bad payload can
        # never be "confirmed" unchanged by a later 304.
        self._etag: str | None = None
        self._cached: Inventory | None = None

    @property
    def base_url(self) -> str:
        return f"{self._scheme}://{self._host}:{self._port}"

    async def async_get_inventory(self) -> Inventory:
        """Fetch and validate the inventory."""
        headers = {"Authorization": f"Bearer {self._token}"}
        if self._etag and self._cached is not None:
            headers["If-None-Match"] = self._etag

        url = f"{self.base_url}/api/v1/inventory"
        try:
            async with self._session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=self._verify_ssl if self._scheme == "https" else None,
            ) as resp:
                if resp.status == 401:
                    raise InvalidAuth
                if resp.status == 503:
                    raise NoInventoryYet
                if resp.status == 304:
                    # Only reachable when a cached inventory exists -- the
                    # If-None-Match header is not sent otherwise, so this
                    # cannot return a None the caller would have to guard.
                    return self._cached  # type: ignore[return-value]
                if resp.status != 200:
                    raise CannotConnect(f"HTTP {resp.status} from {url}")

                etag = resp.headers.get("ETag")
                payload = await resp.json(content_type=None)
        except InvalidAuth:
            raise
        except (NoInventoryYet, UnsupportedSchema):
            raise
        except asyncio.TimeoutError as err:
            raise CannotConnect(f"timeout after {REQUEST_TIMEOUT}s") from err
        except aiohttp.ClientError as err:
            raise CannotConnect(str(err)) from err
        except ValueError as err:  # malformed JSON
            self._etag = None
            raise CannotConnect(f"agent returned invalid JSON: {err}") from err

        inventory = self._validate(payload)
        # Cache only AFTER validation. Storing first would let a later 304
        # re-serve a payload this client already judged unusable.
        self._etag = etag
        self._cached = inventory
        return inventory

    def _validate(self, payload: Any) -> Inventory:
        if not isinstance(payload, dict):
            self._etag = None
            raise CannotConnect("agent response was not a JSON object")

        version = payload.get("schema_version")
        if version != SUPPORTED_SCHEMA_VERSION:
            self._etag = None
            raise UnsupportedSchema(version)

        hosts = payload.get("hosts")
        if hosts is None:
            raise NoInventoryYet
        if not isinstance(hosts, dict):
            self._etag = None
            raise CannotConnect("agent returned a non-object `hosts`")

        generated_at = payload.get("generated_at")
        if not isinstance(generated_at, int):
            # Freshness is the one field a monitoring integration cannot infer.
            # Without it there is no way to tell a live feed from a frozen one,
            # so a missing timestamp is a protocol error rather than a default.
            self._etag = None
            raise CannotConnect("agent omitted a numeric `generated_at`")

        return Inventory(
            schema_version=version,
            generated_at=generated_at,
            hosts=hosts,
        )

    async def _request(self, method: str, path: str, json_body=None):
        """One place for the non-inventory calls. Returns the decoded body.

        Deliberately separate from async_get_inventory, which carries ETag
        state and a cached payload that none of these share.
        """
        url = f"{self.base_url}{path}"
        try:
            async with self._session.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                json=json_body,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=self._verify_ssl if self._scheme == "https" else None,
            ) as resp:
                if resp.status == 401:
                    raise InvalidAuth
                if resp.status not in (200, 202):
                    body = await resp.text()
                    raise CannotConnect(f"HTTP {resp.status} from {url}: {body[:200]}")
                return await resp.json(content_type=None)
        except InvalidAuth:
            raise
        except asyncio.TimeoutError as err:
            raise CannotConnect(f"timeout after {REQUEST_TIMEOUT}s") from err
        except aiohttp.ClientError as err:
            raise CannotConnect(str(err)) from err
        except ValueError as err:
            raise CannotConnect(f"agent returned invalid JSON: {err}") from err

    async def async_get_status(self) -> dict:
        """Per-profile timer and scan state.

        Returns {} rather than raising if the agent is too old to serve
        /status. The inventory is the reason this integration exists; losing
        the control surface must not take the data down with it.
        """
        try:
            payload = await self._request("GET", "/api/v1/status")
        except CannotConnect as err:
            _LOGGER.debug("status unavailable: %s", err)
            return {}
        if not isinstance(payload, dict):
            return {}
        profiles = payload.get("profiles")
        return profiles if isinstance(profiles, dict) else {}

    async def async_request_scan(self, profile: str) -> None:
        """Ask the agent to start a scan. Returns once QUEUED, not finished."""
        await self._request("POST", "/api/v1/scan", {"profile": profile})

    async def async_set_schedule(self, profile: str, enabled: bool) -> None:
        """Enable or disable a profile's timer."""
        await self._request(
            "POST", "/api/v1/schedule", {"profile": profile, "enabled": enabled}
        )

    async def async_verify(self) -> None:
        """Prove the agent answers and the token works. Used by the config flow.

        Deliberately fetches the real endpoint rather than a health check: a
        health endpoint that answers while the inventory route is broken would
        let setup succeed and every refresh afterwards fail.
        """
        try:
            await self.async_get_inventory()
        except NoInventoryYet:
            # The agent and the credential are both good; the scanner simply
            # has not produced a scan yet. That is a valid setup -- refusing it
            # would block configuring a freshly installed scanner.
            return
