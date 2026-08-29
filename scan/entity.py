"""Shared entity bases: one for scanned endpoints, one for the scanner itself.

TWO KINDS OF DEVICE, AND THEY MUST NOT BE CONFLATED. The scanner is a service
this integration talks to; an endpoint is something the scanner FOUND. Putting
scan buttons on an endpoint, or an IP sensor on the scanner, would make the
device page lie about what the thing is.

ENDPOINT IDENTITY IS THE MAC, AND ONLY THE MAC. An IP moves with the lease, a
hostname is often absent and frequently duplicated, and the scanner's own key
is an implementation detail of the agent. The MAC is the one identifier that
belongs to the hardware, and using anything else means a device silently
becomes a different device.

`identifiers` AND `connections` ARE BOTH SET, DELIBERATELY, AND THEY DO
DIFFERENT JOBS. `identifiers` is this integration's own handle and is what
makes the device stable across restarts. `connections` states the MAC as a
network fact, which is what surfaces it in the UI and what any future
cross-integration matching would key on. Measured on this estate: Home
Assistant does NOT merge device records across config entries on a matching
connection -- an endpoint that another integration already knows will appear
twice. That duplication is accepted here as an explicit decision, not an
oversight; this integration's job is to describe what is on the wire.
"""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ..const import DOMAIN  # real top-level domain, see scan/const.py's note
from .coordinator import NetworkInventoryCoordinator


def pretty_mac(mac: str) -> str:
    """12 hex chars -> aa:bb:cc:dd:ee:ff, the form the registry stores."""
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


class ScannerEntity(CoordinatorEntity[NetworkInventoryCoordinator]):
    """An entity belonging to the scanner service itself."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: NetworkInventoryCoordinator,
        entry_id: str,
        title: str,
        host: str | None,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry_id}_{description.key}"
        # `host` IS ABSENT IN LOCAL MODE, and that is not a missing value to be
        # defaulted -- there is no remote agent to link to, because the scanner
        # is this instance. A configuration_url of "http://None" would render
        # as a live link to nowhere on the device page.
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry_id)},
            name=title,
            manufacturer="nmap",
            model="Scanner agent" if host else "Local scanner",
            configuration_url=f"http://{host}" if host else None,
        )


class EndpointEntity(CoordinatorEntity[NetworkInventoryCoordinator]):
    """An entity belonging to one scanned network endpoint."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: NetworkInventoryCoordinator,
        entry_id: str,
        mac: str,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._mac = mac
        # UNIQUE ID IS THE MAC, NOT THE ENTRY. Re-adding the integration then
        # keeps the same entities rather than orphaning every one of them and
        # starting the history again.
        self._attr_unique_id = f"{mac}_{description.key}"

        host = self._host or {}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)},
            connections={(CONNECTION_NETWORK_MAC, pretty_mac(mac))},
            # Hostname if the scan resolved one, else the address, else the MAC.
            # Never blank: a nameless row in the device list cannot be acted on.
            name=host.get("hostname") or host.get("ip") or pretty_mac(mac),
            manufacturer=host.get("vendor") or None,
            via_device=(DOMAIN, entry_id),
        )

    @property
    def _host(self) -> dict[str, Any] | None:
        """This endpoint's record in the latest scan, or None if it is gone."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.endpoints.get(self._mac)

    @property
    def available(self) -> bool:
        """Available only while the endpoint is still in the inventory.

        TWO DIFFERENT ABSENCES, AND BOTH MUST READ UNAVAILABLE RATHER THAN
        STALE. The coordinator failing means we did not measure the network;
        the endpoint being gone means we measured and it was not there. Neither
        justifies continuing to publish its last known IP as though it were
        current -- a device that left the network yesterday would otherwise
        keep showing an address that now belongs to something else.
        """
        return super().available and self._host is not None
