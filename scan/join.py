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
        is_up = host.get("status") == "up"
        if is_up:
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
            # UNCONDITIONAL, NOT LIVENESS-GATED. KAN-294's whole point is that
            # "we decided this one is fine" must never be silently subtracted
            # -- an acknowledgement is a standing human decision about a
            # device, not a live security read, so it stays listed whether or
            # not that device happens to answer THIS scan.
            result.acknowledged.append(entry)
        elif is_up:
            result.unmatched.append(entry)
        # NOT LIVE, NOT LISTED as unknown otherwise (Joel, 2026-09-05: "If the
        # device isn't live on the network, it should not be shown as
        # unknown"). `hosts` is the persisted inventory (KAN-294's
        # "unknown_hosts can reach zero" already relies on it never shrinking
        # on its own), so a device seen once and gone stays in it with
        # `status` no longer "up" -- without this gate it would sit in
        # `unmatched` forever, unresolvable by anyone because there is
        # nothing on the network left to investigate. A visibility gate, not
        # a deletion: the entry reappears the moment the host answers a scan
        # again, matched or not.

    # Deterministic order so an attribute cap always drops the same tail, and
    # so the reported list does not churn between refreshes from dict ordering.
    result.unmatched.sort(key=lambda h: (h["ip"] or "", h["mac"] or ""))
    result.acknowledged.sort(key=lambda h: (h["ip"] or "", h["mac"] or ""))
    return result


def _self_test():
    fails = []

    def eq(got, want, label):
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    hosts = {
        "1": {"mac": "AA:AA:AA:AA:AA:01", "ip": "10.0.0.1", "status": "up"},
        "2": {"mac": "AA:AA:AA:AA:AA:02", "ip": "10.0.0.2", "status": "up"},
        # Seen before, not answering THIS scan (GH-537, Joel: "If the device
        # isn't live on the network, it should not be shown as unknown").
        "3": {"mac": "AA:AA:AA:AA:AA:03", "ip": "10.0.0.3", "status": "down"},
        # Acknowledged AND currently offline -- must still show (KAN-294).
        "4": {"mac": "AA:AA:AA:AA:AA:04", "ip": "10.0.0.4", "status": "down"},
        # No MAC at all.
        "5": {"ip": "10.0.0.5", "status": "up"},
    }
    known = ["AA:AA:AA:AA:AA:01"]
    acked = ["AA:AA:AA:AA:AA:04"]

    r = join_hosts(hosts, known, acked)
    eq(r.matched, 1, "host 1 matched a known MAC")
    eq([h["mac"] for h in r.unmatched], ["AA:AA:AA:AA:AA:02"],
       "only the LIVE, unmatched, unacknowledged host is listed as unknown")
    eq(len(r.acknowledged), 1,
       "acknowledged host stays listed even though it is currently offline")
    eq(r.unjoinable, 1, "host with no MAC counted separately, never as unknown")
    eq(r.hosts_up, 3, "hosts_up counts every up host regardless of join bucket")

    # PROOF THIS HARNESS CAN FAIL (LAW section 4), by mutation:
    #   `elif is_up:` replaced with unconditional `else:`
    #       -> "only the LIVE, unmatched..." fails, host 3 reappears
    # Re-run that way after changing this comparison; a green self-test on
    # unmutated code proves nothing on its own.
    return fails


if __name__ == "__main__":
    import sys

    problems = _self_test()
    if problems:
        print("join.py SELF-TEST FAILED")
        for p in problems:
            print("  " + p)
        sys.exit(1)
    print("join.py self-test: all assertions passed")
