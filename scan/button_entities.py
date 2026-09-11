"""Buttons: start a scan on demand.

A PRESS IS A REQUEST, NOT A RESULT. The agent queues the scan and answers 202;
the scan itself starts moments later and runs for as long as it runs. Nothing
here waits for it, and nothing here reports success -- pressing the button
means "asked", and `scan in progress` on the matching switch is where you see
that it actually started. Blocking the press until the scan finished would tie
up the UI for the length of a deep scan.

THE PROFILE LIST IS PINNED, NOT DISCOVERED. It mirrors the agent's own
allowlist. Offering a button the agent will reject is worse than offering
none: a control that looks live and does nothing teaches people the whole
surface is unreliable.
"""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import NetworkInventoryError
from .const import CONF_HOST, PROFILES
from .entity import ScannerEntity
from .helpers import schedule_followup_refresh
from .options import InvalidScanRequest
from .scanner import ScanError

# EVERY WAY A SCAN REQUEST CAN LEGITIMATELY FAIL, in both modes. Caught as one
# tuple rather than as a bare `Exception` so a genuine programming error still
# surfaces as a traceback instead of being reported to the user as a scan that
# could not be queued.
SCAN_REQUEST_ERRORS = (NetworkInventoryError, ScanError, InvalidScanRequest)


def setup_scan_buttons(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one scan button per profile. MERGE NOTE: coordinator now
    passed in, see entities.py's setup_scan_sensors docstring."""
    async_add_entities(
        ScanButton(
            coordinator,
            entry.entry_id,
            entry.title,
            # .get, not [] -- local mode has no agent host at all.
            entry.data.get(CONF_HOST),
            ButtonEntityDescription(
                key=f"scan_{profile}",
                translation_key=f"scan_{profile}",
                icon="mdi:radar",
                entity_category=EntityCategory.CONFIG,
            ),
            profile,
        )
        for profile in PROFILES
    )


class ScanButton(ScannerEntity, ButtonEntity):
    """Ask the agent to run one scan profile now."""

    def __init__(self, coordinator, entry_id, title, host, description, profile):
        super().__init__(coordinator, entry_id, title, host, description)
        self._profile = profile

    async def async_press(self) -> None:
        """Queue the scan, then look again shortly.

        The agent's answer only says the request was accepted -- the scan is
        started by a separate privileged unit a moment later. Refreshing
        immediately would read the state from before it started, so the
        follow-up is delayed enough for the transition to have happened.
        """
        try:
            # Through the COORDINATOR, not through a client. In local mode
            # there is no client, and a control that raises AttributeError in
            # one of two supported modes is a fork wearing a method call.
            await self.coordinator.async_request_scan(self._profile)
        except SCAN_REQUEST_ERRORS as err:
            # Surfaced to the user rather than swallowed: a button that
            # silently fails is indistinguishable from one that worked.
            raise HomeAssistantError(
                f"could not queue a {self._profile} scan: {err}"
            ) from err
        schedule_followup_refresh(self.hass, self.coordinator)
