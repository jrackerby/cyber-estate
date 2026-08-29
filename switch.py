"""Switch platform dispatcher for cyber_estate. Only scan has switches."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .scan.switch_entities import setup_scan_switches


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    setup_scan_switches(hass, entry, entry.runtime_data["scan"], async_add_entities)
