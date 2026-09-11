"""Sensor platform dispatcher for cyber_estate.

MERGE NOTE. Each subsystem's entity classes live unchanged in their own
subpackage (feeds/entities.py, cve/entities.py, scan/entities.py) -- this
file only resolves entry.runtime_data's three coordinators and hands each
to its subsystem's own setup. feeds and cve return a static list (both
build a fixed, known set of sensors up front); scan manages its own
ongoing async_add_entities calls as new endpoints/services are discovered
on the network, so it is called directly rather than collected into a list.
"""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .cve.entities import build_cve_sensors
from .feeds.entities import build_feed_sensors
from .runtime import scan_coordinator_of
from .scan.entities import setup_scan_sensors


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data = entry.runtime_data
    static_entities = [
        *build_feed_sensors(data["feeds"]),
        *build_cve_sensors(data["cve"]),
    ]
    async_add_entities(static_entities)
    setup_scan_sensors(hass, entry, scan_coordinator_of(entry), async_add_entities)
