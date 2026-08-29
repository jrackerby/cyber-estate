"""Button platform dispatcher for cyber_estate. Only scan has buttons."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .scan.button_entities import setup_scan_buttons


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    setup_scan_buttons(hass, entry, entry.runtime_data["scan"], async_add_entities)
