"""Persistent inventory for locally-run scans.

WHY THIS EXISTS AT ALL. With the scanner on its own box, `inventory.json` was
the agent's business and this integration only ever read it. Scanning from
Home Assistant makes the inventory OUR state, and it is state that must not be
lost: `first_seen` is unrecoverable -- once forgotten, a host that has been on
the network for a year looks brand new, which is exactly the signal the
unknown-host detector exists to raise.

WRITTEN THROUGH HOME ASSISTANT'S OWN STORE, not to a file of our choosing, so
it lands in `.storage` with the same atomic-write and delayed-save behaviour as
every other integration. A half-written inventory after a power cut would be
indistinguishable from an empty network.

SAVES ARE DEBOUNCED, DELIBERATELY. A discovery sweep touches every record's
`last_seen`, and writing megabytes on each hourly sweep is a real cost on the
SD-backed hosts in this fleet. `async_delay_save` collapses a burst into one
write; the delay is short enough that a restart loses at most one sweep, which
costs a timestamp rather than a host.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .parse import merge_inventory, now_iso, prune

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
SAVE_DELAY = 30


class InventoryStore:
    """The set of hosts this integration has ever seen, and their history."""

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        self._hass = hass
        # Keyed by entry so two scanners on one instance cannot overwrite each
        # other's history -- the failure would look like hosts vanishing.
        self._store: Store = Store(
            hass, STORAGE_VERSION, f"network_inventory.{entry_id}"
        )
        self._hosts: dict[str, dict[str, Any]] = {}
        self._last_scan: str | None = None
        self._last_port_scan: str | None = None
        self._loaded = False

    @property
    def hosts(self) -> dict[str, dict[str, Any]]:
        return self._hosts

    @property
    def host_count(self) -> int:
        return len(self._hosts)

    @property
    def last_scan(self) -> str | None:
        return self._last_scan

    @property
    def last_port_scan(self) -> str | None:
        """When any host last had its PORTS observed.

        Tracked separately from `last_scan` because a liveness sweep refreshes
        the inventory without looking at a single port. Reporting only the
        first would show a healthy feed while service data silently aged out.
        """
        return self._last_port_scan

    async def async_load(self) -> None:
        """Read persisted state. Safe to call once per entry setup."""
        if self._loaded:
            return
        data = await self._store.async_load()
        if data:
            self._hosts = data.get("hosts", {})
            self._last_scan = data.get("last_scan")
            self._last_port_scan = data.get("last_port_scan")
        self._loaded = True
        _LOGGER.debug("loaded %d hosts from storage", len(self._hosts))

    def _data_to_save(self) -> dict[str, Any]:
        return {
            "hosts": self._hosts,
            "last_scan": self._last_scan,
            "last_port_scan": self._last_port_scan,
        }

    def apply_scan(
        self,
        hosts: dict[str, dict[str, Any]],
        complete: bool = True,
        stale_days: int | None = None,
    ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
        """Fold one scan in. Returns (new_keys, changed, pruned).

        A PARTIAL SCAN IS MERGED BUT NEVER PRUNES. Absence of a host in a scan
        that was interrupted says nothing about that host, and letting it age
        toward deletion would let a single timeout begin quietly forgetting the
        network.
        """
        ts = now_iso()
        self._hosts, new_keys, changed = merge_inventory(self._hosts, hosts, ts=ts)
        self._last_scan = ts
        if any(h.get("ports_scanned") for h in hosts.values()):
            self._last_port_scan = ts

        pruned: list[str] = []
        if complete and stale_days:
            pruned = prune(self._hosts, stale_days)

        self._store.async_delay_save(self._data_to_save, SAVE_DELAY)
        return new_keys, changed, pruned

    async def async_remove(self) -> None:
        """Delete persisted state. Called when the config entry is removed."""
        await self._store.async_remove()
