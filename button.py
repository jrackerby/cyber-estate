"""Button platform dispatcher for cyber_estate. Only scan has buttons."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .runtime import scan_coordinator_of
from .scan.button_entities import setup_scan_buttons


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    setup_scan_buttons(hass, entry, scan_coordinator_of(entry), async_add_entities)
