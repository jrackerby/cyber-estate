"""Switches: enable or disable each scan profile's schedule.

THE SWITCH IS THE TIMER'S INSTALL STATE, NOT WHETHER A SCAN IS RUNNING. Those
are different questions and conflating them would make the control lie in both
directions -- off during a manual scan, on while a scan is in progress. Whether
a scan is currently running is reported as an attribute instead.

UNAVAILABLE WHEN THE AGENT'S STATUS CANNOT BE READ, rather than defaulting to
off. A schedule switch that shows a confident position it did not measure is
worse than one that admits it does not know: the whole point of the control is
to tell you whether scanning is going to happen.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import NetworkInventoryError
from .const import CONF_HOST, PROFILES
from .entity import ScannerEntity
from .helpers import schedule_followup_refresh


def setup_scan_switches(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one schedule switch per profile. MERGE NOTE: coordinator
    now passed in, see entities.py's setup_scan_sensors docstring."""
    async_add_entities(
        ScheduleSwitch(
            coordinator,
            entry.entry_id,
            entry.title,
            # .get, not [] -- local mode has no agent host at all.
            entry.data.get(CONF_HOST),
            SwitchEntityDescription(
                key=f"schedule_{profile}",
                translation_key=f"schedule_{profile}",
                icon="mdi:calendar-clock",
                entity_category=EntityCategory.CONFIG,
            ),
            profile,
        )
        for profile in PROFILES
    )


class ScheduleSwitch(ScannerEntity, SwitchEntity):
    """Whether one profile's systemd timer is enabled."""

    def __init__(self, coordinator, entry_id, title, host, description, profile):
        super().__init__(coordinator, entry_id, title, host, description)
        self._profile = profile

    @property
    def _status(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        if data is None:
            return None
        return (data.profiles or {}).get(self._profile)

    @property
    def available(self) -> bool:
        """Only available while the agent's status is actually readable."""
        return super().available and self._status is not None

    @property
    def is_on(self) -> bool | None:
        status = self._status
        if status is None:
            return None
        return bool(status.get("timer_enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        status = self._status
        if status is None:
            return None
        return {
            # Reported as the agent gave them: systemd's own formatting, which
            # is unambiguous about timezone. Parsing them into datetimes here
            # would only add a way to be wrong.
            "next_run": status.get("next_run"),
            "last_run": status.get("last_run"),
            "scanning": status.get("scanning"),
            "last_result": status.get("last_result"),
        }

    async def _set(self, enabled: bool) -> None:
        try:
            # Through the COORDINATOR: local mode has no client, and the two
            # modes must present one control surface.
            await self.coordinator.async_set_schedule(self._profile, enabled)
        except NetworkInventoryError as err:
            verb = "enable" if enabled else "disable"
            raise HomeAssistantError(
                f"could not {verb} the {self._profile} schedule: {err}"
            ) from err
        # NOT optimistically flipped. The far side is a marker file consumed by
        # a privileged unit; reporting the new position before it has been read
        # back would show a schedule change that may not have happened.
        schedule_followup_refresh(self.hass, self.coordinator)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)
