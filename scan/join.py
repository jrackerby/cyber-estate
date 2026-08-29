"""The scanned-hosts / known-devices join. Pure, and imports nothing from Home Assistant.

THIS MODULE IS DELIBERATELY HA-FREE so it can be tested directly. It decides
whether something on the network is accounted for, and a wrong answer here is
either a missed intruder or an alert that cries wolf until it is muted. Logic
with that failure mode has to be runnable in a test without booting anything.

MAC IS NORMALISED THROUGH ONE FUNCTION, APPLIED TO BOTH SIDES. The scanner
emits `AA:BB:CC:DD:EE:01`; a device registry may hold `88a29ee1ea23` or
`88-a2-9e-e1-ea-23`. Normalising only one side, or normalising each side with a
different helper, produces a join that silently matches nothing -- and a join
that matches nothing reports every host as unknown, which looks like a working
alarm rather than a broken comparison.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

_SEPARATORS = re.compile(r"[^0-9a-fA-F]")


def normalise_mac(value: str | None) -> str | None:
    """Return a MAC as 12 lowercase hex characters, or None if it is not one.

    Returns None rather than a best-effort string for anything that is not a
    48-bit address. A malformed value that normalised to *something* would join
    against other malformed values and manufacture matches.
    """
    if not value:
        return None
    stripped = _SEPARATORS.sub("", value).lower()
    if len(stripped) != 12:
        return None
    return stripped


@dataclass(slots=True)
class JoinResult:
    """What the join found. Counts and detail travel together."""

    matched: int = 0
    unmatched: list[dict[str, Any]] = field(default_factory=list)
    # KAN-294: a host Joel has looked at and decided is fine (a multi-NIC
    # device whose ARP-visible interface differs from the one the registry
    # knows -- the UDM Pro is the case that found this) is a DIFFERENT fact
    # from a host that never appeared. Collapsing the two into "matched"
    # would silently discard the "we decided this one is fine" record;
    # collapsing them into "unmatched" is the un-clearable reading this
    # ticket exists to fix. A separate bucket keeps both readable.
    acknowledged: list[dict[str, Any]] = field(default_factory=list)
    unjoinable: int = 0
    hosts_up: int = 0
    exposed_services: int = 0
    hosts_with_port_data: int = 0

    @property
    def unknown_count(self) -> int:
        return len(self.unmatched)

    @property
    def acknowledged_count(self) -> int:
        return len(self.acknowledged)

    @property
    def checked(self) -> int:
        """Hosts the join could actually decide about."""
        return self.matched + self.unknown_count + self.acknowledged_count


def join_hosts(
    hosts: dict[str, dict[str, Any]],
    known_macs: Iterable[str],
    acknowledged_macs: Iterable[str] = (),
) -> JoinResult:
    """Classify each scanned host against the MACs Home Assistant already knows.

    `known_macs` and `acknowledged_macs` are both passed through
    `normalise_mac` here rather than trusted as pre-normalised, so the
    caller cannot get the format wrong on either side.

    Acknowledgement is checked AFTER the known-MAC match, never instead of
    it: a host that is genuinely known should read `matched`, not
    `acknowledged` -- the two buckets answer different questions ("does HA
    already have a device for this" vs. "did a person decide this specific
    unaccounted-for host is fine") and a host cannot honestly answer both.
    """
    known = {m for m in (normalise_mac(v) for v in known_macs) if m}
    acked = {m for m in (normalise_mac(v) for v in acknowledged_macs) if m}

    result = JoinResult()

    for host in hosts.values():
        if host.get("status") == "up":
            result.hosts_up += 1

        ports = host.get("ports") or []
        result.exposed_services += len(ports)
        if ports:
            result.hosts_with_port_data += 1

        mac = normalise_mac(host.get("mac"))
        if mac is None:
            # No usable MAC, so this host cannot be decided either way. Counted
            # on its own: folding it into `unmatched` would raise an alert for
            # every routed host on another segment, and folding it into
            # `matched` would hide a real unknown behind a routing detail.
            result.unjoinable += 1
            continue

        if mac in known:
            result.matched += 1
            continue

        entry = {
            "mac": host.get("mac"),
            "ip": host.get("ip"),
            "hostname": host.get("hostname"),
            "vendor": host.get("vendor"),
            "os": host.get("os"),
            "open_ports": host.get("port_list") or [],
        }
        if mac in acked:
            result.acknowledged.append(entry)
        else:
            result.unmatched.append(entry)

    # Deterministic order so an attribute cap always drops the same tail, and
    # so the reported list does not churn between refreshes from dict ordering.
    result.unmatched.sort(key=lambda h: (h["ip"] or "", h["mac"] or ""))
    result.acknowledged.sort(key=lambda h: (h["ip"] or "", h["mac"] or ""))
    return result
