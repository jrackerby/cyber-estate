"""Turning a host record into per-service readings. Pure and HA-free.

THE QUESTION THIS FILE ANSWERS is "show me every device running ssh", and the
whole difficulty is in the devices it must NOT answer for. Of 78 tracked hosts
on this estate, 41 carry port data; the nightly scan only port-scans what is
awake at 03:15, so phones and tablets are systematically never looked at. A
two-state sensor would render all 37 of those as "not running ssh", which is
not a cautious answer -- it is a wrong one, delivered confidently, about the
devices most likely to be interesting.

SO EVERY READING IS THREE-STATE. `open` and `closed` are observations;
`never_scanned` is the absence of one. They are different kinds of fact and
the sensor must never collapse them, exactly as `absent` and `unreachable` are
kept apart elsewhere in this estate.

SERVICES ARE KEYED BY NAME, NOT BY PORT. A host serving http on 80 and 8080 is
one answer to "what runs http here", not two, and the ports travel as an
attribute. Keying by port would mean searching for a service required knowing
which port it happened to be on -- which is the thing nobody remembers, and
the reason this feature was asked for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Reported when a scan found the port open but could not name the service.
UNNAMED = "unknown"

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_NEVER_SCANNED = "never_scanned"

_SAFE = re.compile(r"[^a-z0-9]+")


def service_slug(name: str) -> str:
    """A service name as an entity-id fragment: `ms-wbt-server` -> `ms_wbt_server`."""
    return _SAFE.sub("_", (name or UNNAMED).strip().lower()).strip("_") or UNNAMED


@dataclass(slots=True)
class ServiceReading:
    """One service on one host, and everything known about it."""

    name: str
    state: str
    ports: list[int] = field(default_factory=list)
    protos: list[str] = field(default_factory=list)
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None

    @property
    def slug(self) -> str:
        return service_slug(self.name)

    @property
    def is_open(self) -> bool:
        return self.state == STATE_OPEN

    @property
    def descriptor(self) -> str | None:
        """'OpenSSH 10.0p2', or None when the scan never identified it.

        NOT defaulted to the service name. "we know it is ssh but not which
        ssh" and "it is OpenSSH 10.0p2" are different facts, and a consumer
        matching versions against a vulnerability feed must be able to tell
        that it has nothing to match rather than matching the word "ssh".
        """
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else None


def host_was_port_scanned(host: dict[str, Any]) -> bool:
    """Whether this host has EVER had its ports looked at.

    Reads `ports_scanned_at` rather than the emptiness of `ports`: a host that
    was scanned and had nothing open is a real observation, and it must not be
    confused with one nobody has scanned.
    """
    return bool(host.get("ports_scanned_at"))


def services_for_host(host: dict[str, Any]) -> dict[str, ServiceReading]:
    """Every service currently observed open on `host`, keyed by service name.

    Only OPEN services appear here -- a closed port has no service to describe.
    Producing `closed` readings is the job of `reading_for`, which needs the
    history of what this host used to run and therefore belongs one level up.
    """
    readings: dict[str, ServiceReading] = {}
    for port in host.get("ports") or []:
        name = (port.get("service") or UNNAMED).strip().lower() or UNNAMED
        reading = readings.get(name)
        if reading is None:
            reading = ServiceReading(name=name, state=STATE_OPEN)
            readings[name] = reading
        number = port.get("port")
        if isinstance(number, int) and number not in reading.ports:
            reading.ports.append(number)
        proto = port.get("proto")
        if proto and proto not in reading.protos:
            reading.protos.append(proto)
        # FIRST NAMED WINS, and it is recorded rather than merged. Two ports
        # answering the same service name can genuinely run different builds;
        # blending them would invent a version string that is true of neither.
        if reading.product is None and port.get("product"):
            reading.product = port["product"]
            reading.version = port.get("version")
            reading.extrainfo = port.get("extrainfo")
    for reading in readings.values():
        reading.ports.sort()
        reading.protos.sort()
    return readings


def reading_for(host: dict[str, Any], service_name: str) -> ServiceReading:
    """The current reading for one service on one host, including its absence.

    THE ORDER OF THESE THREE BRANCHES IS THE WHOLE POINT. Never-scanned is
    checked FIRST, so a host nobody has looked at can never fall through to
    `closed`. Only after we know a port scan happened is "not in the open list"
    allowed to mean the service is not running.
    """
    if not host_was_port_scanned(host):
        return ServiceReading(name=service_name, state=STATE_NEVER_SCANNED)

    current = services_for_host(host)
    found = current.get(service_name)
    if found is not None:
        return found

    return ServiceReading(name=service_name, state=STATE_CLOSED)


def census(hosts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Estate-wide roll-up: which services run where, and how much is unproven.

    THE UNPROVEN COUNT TRAVELS WITH THE ANSWER, never separately. "8 hosts run
    ssh" invites a conclusion about the other 70; "8 run ssh, 33 do not, and 37
    have never been port-scanned" invites the right one. Reporting the first
    number alone is the failure this whole feature was shaped to avoid.
    """
    by_service: dict[str, dict[str, Any]] = {}
    scanned = never = 0

    for host in hosts.values():
        if not host_was_port_scanned(host):
            never += 1
            continue
        scanned += 1
        for name, reading in services_for_host(host).items():
            row = by_service.setdefault(
                name, {"hosts": 0, "ports": set(), "versions": set()}
            )
            row["hosts"] += 1
            row["ports"].update(reading.ports)
            if reading.descriptor:
                row["versions"].add(reading.descriptor)

    services = {
        name: {
            "hosts": row["hosts"],
            "ports": sorted(row["ports"]),
            "versions": sorted(row["versions"]),
        }
        for name, row in sorted(
            by_service.items(), key=lambda kv: (-kv[1]["hosts"], kv[0])
        )
    }
    return {
        "services": services,
        "distinct_services": len(services),
        "hosts_port_scanned": scanned,
        "hosts_never_port_scanned": never,
        "coverage_pct": round(100 * scanned / (scanned + never), 1)
        if (scanned + never)
        else 0.0,
    }
