"""Sensors for the network inventory integration.

TWO POPULATIONS, ON TWO KINDS OF DEVICE.

ROLLUPS live on the scanner device: counts and freshness for the network as a
whole. They are what a dashboard reads and what gets trended.

PER-ENDPOINT SENSORS live on the endpoint's own device: address, operating
system, last seen. This file previously said "rolled up, never one entity per
host" and that is no longer true -- an inventory whose detail is reachable only
inside a capped attribute blob is not an inventory you can click into, filter,
or point an automation at. The cost is real and was accepted deliberately: the
entity count becomes a function of the size of the network.

That cost is bounded by scanning ONE segment. Every host on an L2 segment
answers ARP, so every endpoint has a MAC and therefore a stable identity;
the churn that would make this unbearable is the churn of hosts that come and
go, and those age out of the scanner's own inventory rather than accumulating
here forever.

TWO TIMESTAMPS, NOT ONE. `last_scan` moves whenever any sweep runs; the
liveness sweep is typically hourly. `last_port_scan` moves only when a profile
that actually enumerates ports runs, which is typically nightly. If the deeper
profile stops, the first keeps ticking and everything looks healthy -- so the
second exists specifically to make that failure visible. They are exposed as
timestamps rather than as an "age in seconds" so they change only when a scan
lands, instead of writing a new history row on every poll.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.core import callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from ..const import DOMAIN  # real top-level domain -- see scan/const.py's note
from .const import CONF_HOST, MAX_DETAIL, MAX_STATE_LEN, OS_UNDETERMINED
from .entity import EndpointEntity
from .coordinator import InventoryView, NetworkInventoryCoordinator
from .services_view import (
    host_was_port_scanned,
    reading_for,
    service_slug,
    services_for_host,
)
from .ssh_probe import (
    STATE_NEVER_SCANNED as SSH_NEVER_SCANNED,
    STATE_NO_SSH as SSH_NO_SSH,
    host_runs_ssh,
)


@dataclass(frozen=True, kw_only=True)
class NetworkInventorySensorDescription(SensorEntityDescription):
    """Describes one rolled-up sensor."""

    value_fn: Callable[[InventoryView], Any]
    attr_fn: Callable[[InventoryView], dict[str, Any]] | None = None


def _unknown_attrs(view: InventoryView) -> dict[str, Any]:
    """Detail for the unknown-host count.

    CAPPED, AND THE CAP IS DECLARED. A truncated list that does not say it is
    truncated reads as a complete one, and the operator would act on a shorter
    list than the count beside it.

    ACKNOWLEDGED HOSTS ARE LISTED HERE, NEVER SILENTLY SUBTRACTED.
    "we decided this one is fine" and "this one never appeared" must not
    collapse into the same zero -- an acknowledged host stays visible on
    this entity, in its own bucket, even though it no longer counts toward
    the state (`unknown_count`, which is `unmatched` only).
    """
    return {
        "hosts": view.unmatched[:MAX_DETAIL],
        "detail_capped_at": MAX_DETAIL,
        "detail_truncated": len(view.unmatched) > MAX_DETAIL,
        # Reported alongside the answer, never separately: an unknown-host
        # count means nothing without knowing how many hosts could not be
        # checked at all.
        "matched": view.matched,
        "unjoinable_no_mac": view.unjoinable,
        "acknowledged_count": view.acknowledged_count,
        "acknowledged": view.acknowledged[:MAX_DETAIL],
    }


def _coverage_attrs(view: InventoryView) -> dict[str, Any]:
    return {
        "hosts_with_port_data": view.hosts_with_port_data,
        "hosts_total": view.inventory.host_count,
    }


SENSORS: tuple[NetworkInventorySensorDescription, ...] = (
    NetworkInventorySensorDescription(
        key="unknown_hosts",
        translation_key="unknown_hosts",
        icon="mdi:help-network",
        native_unit_of_measurement="hosts",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: v.unknown_count,
        attr_fn=_unknown_attrs,
    ),
    NetworkInventorySensorDescription(
        key="hosts_tracked",
        translation_key="hosts_tracked",
        icon="mdi:lan",
        native_unit_of_measurement="hosts",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: v.inventory.host_count,
    ),
    NetworkInventorySensorDescription(
        key="hosts_up",
        translation_key="hosts_up",
        icon="mdi:lan-connect",
        native_unit_of_measurement="hosts",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: v.hosts_up,
    ),
    NetworkInventorySensorDescription(
        key="exposed_services",
        translation_key="exposed_services",
        icon="mdi:door-open",
        native_unit_of_measurement="services",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: v.exposed_services,
        attr_fn=_coverage_attrs,
    ),
    NetworkInventorySensorDescription(
        key="never_port_scanned",
        translation_key="never_port_scanned",
        icon="mdi:radar",
        native_unit_of_measurement="hosts",
        state_class=SensorStateClass.MEASUREMENT,
        # THE SIZE OF THIS INSTRUMENT'S BLIND SPOT, published as a first-class
        # number rather than left to be derived by subtraction. Every service
        # answer is silent about exactly these hosts, and an operator should
        # not have to compute how many that is.
        value_fn=lambda v: v.hosts_never_port_scanned,
    ),
    NetworkInventorySensorDescription(
        key="service_census",
        translation_key="service_census",
        icon="mdi:format-list-bulleted",
        native_unit_of_measurement="services",
        # A count at a point in time, like every other rollup here. Declared so
        # this one is not the odd sensor out with no trend.
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: v.service_census["distinct_services"],
        # The whole estate in one entity: which services run where, how many
        # hosts each is on, and how much of the network is unproven. Capped
        # nowhere, because the distinct-service count is bounded by what nmap
        # can name rather than by the size of the network -- 19 here.
        attr_fn=lambda v: v.service_census,
    ),
    NetworkInventorySensorDescription(
        key="last_scan",
        translation_key="last_scan",
        icon="mdi:radar",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: datetime.fromtimestamp(
            v.inventory.generated_at, tz=timezone.utc
        ),
    ),
    NetworkInventorySensorDescription(
        key="last_port_scan",
        translation_key="last_port_scan",
        icon="mdi:clock-alert-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda v: v.newest_port_scan,
    ),
)


@dataclass(frozen=True, kw_only=True)
class EndpointSensorDescription(SensorEntityDescription):
    """Describes one per-endpoint sensor. `value_fn` receives the host record."""

    value_fn: Callable[[dict[str, Any]], Any]


def _os_value(host: dict[str, Any]) -> str:
    """The fingerprinted OS, or an explicit statement that there is not one.

    NEVER BLANK. An empty state is indistinguishable from a sensor that failed
    to read, and "nmap looked and could not tell" is a different fact from "no
    scan has run". Truncated with a marker if nmap returned a long alternatives
    list, because Home Assistant refuses a state over 255 characters and a
    silently dropped state would leave the sensor unknown.
    """
    value = (host.get("os") or "").strip()
    if not value:
        return OS_UNDETERMINED
    if len(value) > MAX_STATE_LEN:
        return value[: MAX_STATE_LEN - 1] + "\u2026"
    return value


def _open_ports_value(host: dict[str, Any]) -> Any:
    """How many ports are open, or None if nobody has looked.

    NONE, NOT ZERO, for an unscanned host. Zero is a measurement -- "we checked
    and nothing is open" -- and publishing it for a host nobody has scanned
    puts a confident, wrong number on 37 of this network's 78 hosts.
    """
    if not host_was_port_scanned(host):
        return None
    return host.get("open_port_count", 0)


ENDPOINT_SENSORS: tuple[EndpointSensorDescription, ...] = (
    EndpointSensorDescription(
        key="ip_address",
        translation_key="ip_address",
        icon="mdi:ip-network",
        value_fn=lambda h: h.get("ip"),
    ),
    EndpointSensorDescription(
        key="operating_system",
        translation_key="operating_system",
        icon="mdi:penguin",
        value_fn=_os_value,
    ),
    EndpointSensorDescription(
        key="last_seen",
        translation_key="last_seen",
        icon="mdi:clock-check-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda h: dt_util.parse_datetime(h.get("last_seen") or ""),
    ),
    EndpointSensorDescription(
        key="open_ports",
        translation_key="open_ports",
        icon="mdi:door-open",
        native_unit_of_measurement="ports",
        # MEASUREMENT IS NOT OPTIONAL HERE, AND NOT ONLY BECAUSE IT IS CORRECT.
        # These entity ids were previously owned by the scanner's own MQTT
        # discovery, which published "Open ports" per host WITH
        # state_class: measurement -- so Home Assistant holds long-term
        # statistics for them. Reclaiming the ids without the class raised a
        # repair per host offering to DELETE that history. A count of open
        # ports at a point in time is a measurement on its own merits; the
        # prior art just makes dropping it destructive as well as wrong.
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_open_ports_value,
    ),
    EndpointSensorDescription(
        key="last_port_scan",
        translation_key="last_port_scan",
        icon="mdi:clock-alert-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        # THE PER-HOST COVERAGE READING. Unknown here is the honest state for a
        # host that has never been port-scanned, and it is what makes the
        # estate's blind spot visible device by device rather than only as an
        # aggregate nobody drills into.
        value_fn=lambda h: dt_util.parse_datetime(h.get("ports_scanned_at") or ""),
    ),
)


def setup_scan_sensors(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: "NetworkInventoryCoordinator",
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the scanner rollups, then track endpoints as they appear.

    MERGE NOTE: was this platform's own async_setup_entry, resolving
    `coordinator = entry.runtime_data` itself. entry.runtime_data is now a
    dict of all three subsystems' coordinators under cyber_estate, so the
    top-level sensor.py resolves it once and passes it in directly.
    """
    async_add_entities(
        NetworkInventorySensor(coordinator, entry, description) for description in SENSORS
    )

    # ENDPOINTS ARE DISCOVERED, NOT ENUMERATED ONCE. A host that joins the
    # network after setup must get entities without the user reloading the
    # integration, so the listener stays for the life of the entry. `seen`
    # holds every MAC ever added and is never pruned: an endpoint that leaves
    # keeps its entities (reading unavailable) rather than being deleted, and
    # re-adding it on its return must not create a second copy.
    seen: set[str] = set()
    # (mac, service) pairs that already have an entity. NEVER PRUNED, for the
    # same reason `seen` is not: a service that closes keeps its sensor so the
    # closure is visible and alertable, and a service that comes back must not
    # get a second copy.
    seen_services: set[tuple[str, str]] = set()

    @callback
    def _add_new_endpoints() -> None:
        data = coordinator.data
        if data is None:
            return

        new: list[SensorEntity] = []

        fresh = [mac for mac in data.endpoints if mac not in seen]
        if fresh:
            seen.update(fresh)
            for mac in fresh:
                new.extend(
                    EndpointSensor(coordinator, entry.entry_id, mac, description)
                    for description in ENDPOINT_SENSORS
                )
                new.append(SshAccessSensor(coordinator, entry.entry_id, mac))

        # SERVICES ARE DISCOVERED SEPARATELY FROM HOSTS, and on every refresh
        # rather than only when a host first appears. A host known for months
        # gains an entity the first time a scan finds a new service on it --
        # which is precisely the event worth noticing.
        for mac, host in data.endpoints.items():
            for name in services_for_host(host):
                pair = (mac, name)
                if pair in seen_services:
                    continue
                seen_services.add(pair)
                new.append(ServiceSensor(coordinator, entry.entry_id, mac, name))

        if new:
            async_add_entities(new)

    _add_new_endpoints()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_endpoints))


class EndpointSensor(EndpointEntity, SensorEntity):
    """One reading about one scanned endpoint."""

    entity_description: EndpointSensorDescription

    @property
    def native_value(self) -> Any:
        host = self._host
        if host is None:
            # Unavailable already covers this; returning None rather than a
            # stale value means nothing here can outlive the observation.
            return None
        return self.entity_description.value_fn(host)


class ServiceSensor(EndpointEntity, SensorEntity):
    """One service on one endpoint: `open`, `closed` or `never_scanned`.

    THIS IS THE ENTITY THE WHOLE FEATURE EXISTS FOR. Its entity id ends in the
    service name -- `sensor.kiosk01` -- so Home Assistant's own search
    for "ssh" returns every host running it, with no template and no knowledge
    of which port it happens to be on.

    ONCE CREATED IT IS NEVER REMOVED, even when the service closes. A host that
    used to run ssh and now does not is a fact worth keeping and worth
    alerting on; deleting the entity would make that change invisible and take
    its history with it.
    """

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["open", "closed", "never_scanned"]

    def __init__(self, coordinator, entry_id, mac, service_name) -> None:
        super().__init__(
            coordinator,
            entry_id,
            mac,
            SensorEntityDescription(
                key=f"service_{service_slug(service_name)}",
                # NAMED FOR THE SERVICE ITSELF, uppercased, so the device page
                # reads "SSH" and the entity id reads `..._ssh`. Not translated:
                # a service name is a protocol identifier, and localising it
                # would break the search this exists to serve.
                name=service_name.upper(),
                icon=_service_icon(service_name),
            ),
        )
        self._service = service_name

    @property
    def available(self) -> bool:
        """Available even when never scanned.

        The reading `never_scanned` IS the information. Marking it unavailable
        would hide the coverage gap behind the same grey as a broken feed,
        which is the failure this state was introduced to prevent.
        """
        return super().available

    @property
    def native_value(self) -> Any:
        host = self._host
        if host is None:
            return None
        return reading_for(host, self._service).state

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        host = self._host
        if host is None:
            return None
        reading = reading_for(host, self._service)
        return {
            "service": self._service,
            "ports": reading.ports,
            "protocols": reading.protos,
            "product": reading.product,
            "version": reading.version,
            "extra_info": reading.extrainfo,
            # The identified build, or None. NOT defaulted to the service name:
            # "we know it is ssh" and "it is OpenSSH 10.0p2" are different
            # facts, and a vulnerability match needs to tell them apart.
            "identified_as": reading.descriptor,
            "last_port_scan": host.get("ports_scanned_at"),
        }


class SshAccessSensor(EndpointEntity, SensorEntity):
    """Whether Home Assistant itself can SSH into this endpoint.

    THE ANSWER IS ONLY MEANINGFUL BECAUSE THE PROBE RUNS HERE. "Is the public
    key installed" is a property of a (client, key, user, host) tuple, not of
    the host, so this entity is specifically about Home Assistant's own
    ability to connect -- not about whether anyone can.
    """

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = [
        "authorized",
        "refused",
        "host_key_changed",
        "unreachable",
        "no_ssh",
        "never_scanned",
    ]

    def __init__(self, coordinator, entry_id, mac) -> None:
        super().__init__(
            coordinator,
            entry_id,
            mac,
            SensorEntityDescription(
                key="ssh_access",
                translation_key="ssh_access",
                icon="mdi:key-chain",
            ),
        )

    @property
    def native_value(self) -> Any:
        host = self._host
        if host is None:
            return None

        # DERIVED FROM THE HOST RECORD FIRST, probe result second. Whether a
        # host runs ssh at all is knowable without probing, and reporting a
        # stale probe result for a host that has since stopped offering ssh
        # would outlive the observation it came from.
        runs = host_runs_ssh(host)
        if runs is None:
            return SSH_NEVER_SCANNED
        if runs is False:
            return SSH_NO_SSH

        result = (self.coordinator.data.ssh or {}).get(self._mac)
        if result is None:
            # Offers ssh, but no probe has completed. Unknown is honest here --
            # inventing `unreachable` would report a failure that never happened.
            return None
        return result.state

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        host = self._host
        if host is None:
            return None
        result = (self.coordinator.data.ssh or {}).get(self._mac)
        return {
            "user": result.user if result else None,
            "detail": result.detail if result else None,
            "ssh_ports": sorted(
                p for r in [services_for_host(host).get("ssh")] if r for p in r.ports
            ),
            "last_port_scan": host.get("ports_scanned_at"),
        }


def _service_icon(name: str) -> str:
    """A glyph that follows FUNCTION, not the vendor's protocol name."""
    return {
        "ssh": "mdi:console-network",
        "http": "mdi:web",
        "https": "mdi:web",
        "domain": "mdi:dns",
        "rtsp": "mdi:cctv",
        "printer": "mdi:printer",
        "jetdirect": "mdi:printer",
        "vnc": "mdi:monitor-share",
        "upnp": "mdi:lan",
        "tcpwrapped": "mdi:help-network",
        "unknown": "mdi:help-network",
    }.get(name, "mdi:lan-connect")


class NetworkInventorySensor(CoordinatorEntity[NetworkInventoryCoordinator], SensorEntity):
    """One rolled-up reading."""

    _attr_has_entity_name = True
    entity_description: NetworkInventorySensorDescription

    def __init__(
        self,
        coordinator: NetworkInventoryCoordinator,
        entry: ConfigEntry,
        description: NetworkInventorySensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        # HOST IS ABSENT IN LOCAL MODE. There is no remote agent to link to,
        # so the link is omitted rather than pointed at "http://None".
        host = entry.data.get(CONF_HOST)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="nmap",
            model="Scanner agent" if host else "Local scanner",
            configuration_url=f"http://{host}" if host else None,
        )

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attr_fn is None:
            return None
        return self.entity_description.attr_fn(self.coordinator.data)
