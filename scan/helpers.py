"""Small shared helpers for the control entities."""

from __future__ import annotations

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_call_later

# How long to wait after a control call before looking at the result.
#
# EVERY CONTROL ON THIS INTEGRATION IS ASYNCHRONOUS ON THE FAR SIDE. The agent
# is unprivileged and cannot start a unit; it drops a marker file that a
# root-owned systemd path unit picks up. So an immediate refresh reads the
# state from BEFORE the action took effect and the entity snaps back to its old
# value -- which looks exactly like the command having failed.
#
# Measured on this network: the marker is consumed in under a second. Three
# seconds clears that with room to spare while staying well inside the window
# where a user is still looking at the control they pressed.
FOLLOWUP_DELAY = 3


@callback
def schedule_followup_refresh(hass: HomeAssistant, coordinator) -> None:
    """Re-read the agent shortly, without blocking the caller.

    Deliberately not an `await asyncio.sleep()` in the entity method: that
    holds the service call open and makes the UI wait on something it does not
    need to wait for.
    """

    async def _refresh(_now) -> None:
        await coordinator.async_request_refresh()

    async_call_later(hass, FOLLOWUP_DELAY, _refresh)
