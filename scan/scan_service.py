"""The custom-scan service: plain-English options, no remembered flags.

WHY A SERVICE AND NOT A SCRIPT PLUS HELPERS. LAW section 7 rules that a script
reaching glass through a generic runner is banned, and that an affordance
belongs to the card that owns the concept. A service with named boolean fields
keeps the option vocabulary in ONE place: Home Assistant renders each field
from `services.yaml` with its own label and description, so the checkboxes in
Developer Tools, in the automation editor and on the dashboard card are all the
same list, and none of them can drift from what the builder actually accepts.

THE SCHEMA IS GENERATED FROM `options.SCAN_OPTIONS`, never written out twice.
A hand-maintained copy would eventually offer a box that the builder rejects --
a control that looks live and does nothing, which is the specific failure the
vocabulary exists to prevent.

THE SERVICE RETURNS A RESPONSE, and that is load-bearing rather than a
courtesy. A scan is slow and its effect is diffuse: without a response the only
way to find out what happened is to go looking at entities afterwards and infer
it. The response says what was run, in the words it was asked for, and what
changed.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr

from ..const import DOMAIN  # real top-level domain -- see scan/const.py's note
from ..runtime import scan_coordinators
from .options import (
    OPTION_KEYS,
    InvalidScanRequest,
    describe,
    worst_cost,
)
from .scanner import ScanBusy, ScanError

_LOGGER = logging.getLogger(__name__)

SERVICE_CUSTOM_SCAN = "custom_scan"
SERVICE_SCAN_DEVICE = "scan_device"

ATTR_TARGETS = "targets"
ATTR_DEVICE_ID = "device_id"

# One boolean per option, straight from the vocabulary. `vol.Optional` with a
# False default rather than required, so an automation naming three options
# does not have to spell out the other seven as false.
_OPTION_SCHEMA = {vol.Optional(key, default=False): cv.boolean for key in OPTION_KEYS}

CUSTOM_SCAN_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_TARGETS): vol.Any(cv.string, [cv.string]),
        **_OPTION_SCHEMA,
    }
)

SCAN_DEVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_DEVICE_ID): vol.Any(cv.string, [cv.string]),
        **_OPTION_SCHEMA,
    }
)


def _local_coordinators(hass: HomeAssistant) -> list[Any]:
    """Every loaded entry that can actually run a scan here.

    THE LOOKUP ITSELF LIVES IN `..runtime` AND IS TESTED THERE. This function
    is the HA-shaped half -- asking the registry which entries exist -- and
    nothing more. GH-707: the version that inlined the lookup read
    `entry.runtime_data` as if it were still one coordinator, so it matched
    nothing on any configuration and both services refused every call.
    """
    return scan_coordinators(hass.config_entries.async_entries(DOMAIN))


def _one_coordinator(hass: HomeAssistant):
    coordinators = _local_coordinators(hass)
    if not coordinators:
        raise HomeAssistantError(
            # NAMES THE DOMAIN THAT CAN ACTUALLY EXIST. This message used to
            # say "network_inventory", a domain retired at the KAN-344 merge,
            # and GH-707 was read as a missing config entry for exactly that
            # long -- an entry under that name cannot be created, so it can
            # never be found missing. A message that sends the reader
            # somewhere unreachable is worse than a bare failure.
            "no cyber_estate entry is set up to scan from Home Assistant; "
            "custom scans need an entry whose mode is local"
        )
    if len(coordinators) > 1:
        # REFUSED RATHER THAN GUESSED. Picking the first would silently scan
        # the wrong network, and the result would look entirely plausible.
        raise HomeAssistantError(
            "more than one local cyber_estate entry is configured; "
            "custom scans cannot tell which network you mean"
        )
    return coordinators[0]


def _chosen(call: ServiceCall) -> list[str]:
    return [key for key in OPTION_KEYS if call.data.get(key)]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


async def _async_custom_scan(call: ServiceCall) -> dict[str, Any]:
    hass = call.hass
    coordinator = _one_coordinator(hass)
    keys = _chosen(call)
    targets = _as_list(call.data.get(ATTR_TARGETS)) or None

    return await _run(coordinator, targets, keys, "custom scan")


async def _async_scan_device(call: ServiceCall) -> dict[str, Any]:
    """Scan the host behind one device, chosen from the device picker.

    THE ADDRESS IS RESOLVED FROM THE INVENTORY, NOT TYPED. This is the answer
    to the 03:15 blind spot: a device that is awake now can be scanned now,
    without anyone having to know or look up its current address -- which
    changes with the lease and is exactly the thing nobody remembers.
    """
    hass = call.hass
    coordinator = _one_coordinator(hass)
    registry = dr.async_get(hass)

    addresses: list[str] = []
    unresolved: list[str] = []
    for device_id in _as_list(call.data[ATTR_DEVICE_ID]):
        device = registry.async_get(device_id)
        if device is None:
            unresolved.append(device_id)
            continue
        address = _address_for(coordinator, device)
        if address:
            addresses.append(address)
        else:
            unresolved.append(device.name_by_user or device.name or device_id)

    if not addresses:
        raise HomeAssistantError(
            "none of the selected devices have a known address in the "
            f"inventory: {', '.join(unresolved) or 'no devices given'}"
        )

    result = await _run(coordinator, addresses, _chosen(call), "device scan")
    # SURFACED, never dropped. A partial success that reports only its
    # successes reads as a complete one.
    result["not_scanned"] = unresolved
    return result


def _address_for(coordinator, device) -> str | None:
    """This device's current address according to the latest scan."""
    view = coordinator.data
    if view is None:
        return None
    ours = {i[1] for i in device.identifiers if i[0] == DOMAIN}
    endpoints = view.endpoints
    for mac in ours:
        host = endpoints.get(mac)
        if host and host.get("ip"):
            return host["ip"]
    # Fall back to the MAC recorded as a network connection, so a device this
    # integration did not create can still be scanned.
    for conn_type, conn_value in device.connections:
        if conn_type != dr.CONNECTION_NETWORK_MAC:
            continue
        from .join import normalise_mac

        host = endpoints.get(normalise_mac(conn_value) or "")
        if host and host.get("ip"):
            return host["ip"]
    return None


async def _run(coordinator, targets, keys, label) -> dict[str, Any]:
    try:
        summary = describe(keys)
        result = await coordinator.async_run_custom_scan(
            targets=targets, option_keys=keys, label=label
        )
    except ScanBusy as err:
        raise HomeAssistantError(str(err)) from err
    except InvalidScanRequest as err:
        raise HomeAssistantError(f"this scan cannot be run: {err}") from err
    except ScanError as err:
        raise HomeAssistantError(f"the scan failed: {err}") from err

    return {
        "did": summary,
        "cost": worst_cost(keys),
        "targets": targets or coordinator.targets,
        "options": keys,
        "hosts_seen": result.host_count,
        "seconds": round(result.duration, 1),
        # REPORTED, ALWAYS. A scan that was cut short still returns the hosts
        # it saw, and a caller that cannot tell it was truncated will read the
        # missing ones as gone.
        "complete": result.complete,
    }


def async_register_services(hass: HomeAssistant) -> None:
    """Register once, however many entries exist."""
    if hass.services.has_service(DOMAIN, SERVICE_CUSTOM_SCAN):
        return
    hass.services.async_register(
        DOMAIN,
        SERVICE_CUSTOM_SCAN,
        _async_custom_scan,
        schema=CUSTOM_SCAN_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SCAN_DEVICE,
        _async_scan_device,
        schema=SCAN_DEVICE_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )


def async_unregister_services(hass: HomeAssistant) -> None:
    """Remove the services when the last entry goes away.

    Guarded on there being no local coordinators LEFT, not on this entry being
    unloaded: with two entries configured, unloading one would otherwise take
    the service away from the other.
    """
    if _local_coordinators(hass):
        return
    hass.services.async_remove(DOMAIN, SERVICE_CUSTOM_SCAN)
    hass.services.async_remove(DOMAIN, SERVICE_SCAN_DEVICE)
