"""The cyber_estate integration -- KAN-344 merge of estate_feeds, nvd_estate
and network_inventory under one config entry. See const.py for the full
merge rationale.

SETUP ORDER AND ITS CONSEQUENCE. feeds and cve coordinators NEVER raise --
both follow the "an unreadable source is a disposition, not a setup
failure" rule the standalone integrations were built on. scan CAN raise
ConfigEntryNotReady (missing nmap binary). Because all three now share one
config entry, a scan setup failure retries the WHOLE entry, including the
always-succeeding feeds/cve halves -- a real behaviour change from three
independent integrations, accepted because nmap already works on this host
today (the standalone network_inventory integration is loaded) and a
merged entry has one setup lifecycle by construction.
"""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntry

from .const import DOMAIN, PLATFORMS
from .cve.coordinator import NvdEstateCoordinator
from .feeds.coordinator import EstateFeedsCoordinator
from .scan import (
    async_remove_scan_device,
    async_remove_scan_entry,
    async_setup_scan,
    async_unload_scan,
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up all three subsystems under one entry."""
    feeds_coordinator = EstateFeedsCoordinator(hass)
    # async_refresh(), not async_config_entry_first_refresh(): the coordinator
    # never raises UpdateFailed (see feeds/coordinator.py), so the retry
    # machinery async_config_entry_first_refresh adds is dead weight here --
    # same reasoning the standalone estate_feeds integration documented.
    await feeds_coordinator.async_refresh()

    cve_coordinator = NvdEstateCoordinator(hass, entry)
    await cve_coordinator.async_config_entry_first_refresh()

    scan_coordinator = await async_setup_scan(hass, entry)

    entry.runtime_data = {
        "feeds": feeds_coordinator,
        "cve": cve_coordinator,
        "scan": scan_coordinator,
    }
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # KAN-294: a saved acknowledged-MACs change should not sit until the
    # next scheduled tick before unknown_hosts reflects it -- an explicit
    # refresh, not a reload. Reloading would re-run agent/local setup
    # (binary lookup, agent handshake) for a change that touched neither.
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await entry.runtime_data["scan"].async_refresh()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        async_unload_scan(hass)
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Forget scan's stored inventory when the entry itself is removed.

    Only on REMOVAL, never on unload -- see scan/__init__.py's
    async_remove_scan_entry docstring. feeds and cve carry no persisted
    state of their own to clean up.
    """
    await async_remove_scan_entry(hass, entry)


async def async_remove_config_entry_device(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device: DeviceEntry,
) -> bool:
    """Route device-removal requests to the owning subsystem.

    scan's devices (the scanner itself and every discovered endpoint) carry
    the REAL top-level DOMAIN in their identifiers (see scan/entity.py) and
    have real removability logic -- see async_remove_scan_device's
    docstring for why an endpoint that is still being seen refuses.

    feeds' and cve's own devices carry their LOCAL namespace strings
    ("estate_feeds", "nvd_estate") instead, precisely so they are
    distinguishable here. Neither is removable: both are single fixed
    devices that exist for the life of the entry, matching the standalone
    integrations' behaviour, which never implemented this hook at all (no
    hook means HA refuses removal by default).
    """
    if any(i[0] == DOMAIN for i in device.identifiers):
        scan_coordinator = entry.runtime_data["scan"]
        return await async_remove_scan_device(hass, entry, device, scan_coordinator)
    return False
