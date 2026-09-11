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
cross-integration matching would key on. Measured on this network: Home
Assistant does NOT merge device records across config entries on a matching
connection -- an endpoint that another integration already knows will appear
twice. That duplication is accepted here as an explicit decision, not an
oversight; this integration's job is to describe what is on the wire.
"""

from __future__ import annotations

from typing import Any

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from ..const import DOMAIN  # real top-level domain, see scan/const.py's note
from .coordinator import NetworkInventoryCoordinator


def pretty_mac(mac: str) -> str:
    """12 hex chars -> aa:bb:cc:dd:ee:ff, the form the registry stores."""
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def scanner_device_info(entry_id: str, title: str, host: str | None) -> DeviceInfo:
    """The scanner's own device, described in ONE place.

    Read by two code paths -- `ScannerEntity`, which is what actually puts
    scan buttons and the schedule switch on the device page, and
    `async_register_scanner_device`, which registers the same device up front
    so an endpoint has something to point `via_device_id` at before any
    platform is forwarded. Two literals here would drift and the drift would
    show up as a duplicate device, so both callers take this.
    """
    return DeviceInfo(
        identifiers={(DOMAIN, entry_id)},
        name=title,
        manufacturer="nmap",
        model="Scanner agent" if host else "Local scanner",
        # `host` IS ABSENT IN LOCAL MODE, and that is not a missing value to
        # be defaulted -- there is no remote agent to link to, because the
        # scanner is this instance. A configuration_url of "http://None"
        # would render as a live link to nowhere on the device page.
        configuration_url=f"http://{host}" if host else None,
    )


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
        self._attr_device_info = scanner_device_info(entry_id, title, host)


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
        )
        # via_device_id TAKES A REGISTRY ID, NOT AN IDENTIFIER TUPLE, AND THE
        # TWO FAIL DIFFERENTLY. The deprecated `via_device=(DOMAIN, entry_id)`
        # this replaces resolved the tuple itself and, when nothing matched,
        # logged and carried on unlinked. `via_device_id` instead RAISES
        # DeviceInfoError on an id the registry does not hold, so a value that
        # used to degrade to "no parent link" now aborts the entity. Hence the
        # explicit branch: resolve, and only claim a parent when there is one.
        #
        # `async_register_scanner_device` has already created this device by
        # the time any endpoint is constructed -- it runs in async_setup_entry
        # before the platforms are forwarded -- so the miss branch is the
        # genuinely-absent case, not a startup race.
        scanner = dr.async_get(self.coordinator.hass).async_get_device_by_identifier(
            (DOMAIN, entry_id), entry_id
        )
        if scanner is not None:
            self._attr_device_info["via_device_id"] = scanner.id

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
