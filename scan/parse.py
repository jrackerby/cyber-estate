"""nmap XML -> host records, and the merge that keeps them across scans.

PURE, AND IMPORTS NOTHING FROM HOME ASSISTANT, for the same reason `join.py`
does not: this is the layer that decides what the network looks like, and logic
whose failure mode is "the inventory quietly forgets something" has to be
runnable in a test without booting anything.

THE CENTRAL DISTINCTION IN THIS FILE IS *NOT OBSERVED* VERSUS *NOT THERE*, and
every function here exists to keep those apart. A liveness sweep emits no
<ports> element at all; reading that as "nothing is open" is what let an hourly
sweep erase a nightly scan's service data, and it is the same class of error as
a missing entity rendering as `off`. Three separate fields carry the
distinction -- `ports_scanned`, `ports_scanned_at` and, downstream, the
three-state service sensors -- because collapsing it at any one of those layers
puts a confident "no SSH here" on a host nobody has ever port-scanned.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

_NON_KEY = re.compile(r"[^a-z0-9_]")


def now_iso() -> str:
    """UTC, seconds resolution. One clock for every timestamp this module writes."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slug(value: str) -> str:
    """A record key: lowercase, separators stripped."""
    return _NON_KEY.sub("", value.lower().replace(":", "").replace(".", "_"))


def host_key(mac: str | None, ipv4: str | None, ipv6: str | None = None) -> str:
    """MAC where there is one, address otherwise.

    MAC IS PREFERRED BECAUSE IT IS THE ONLY STABLE ONE. An IP-derived identity
    changes every time DHCP moves the lease, which silently replaces a device
    rather than updating it. The `ip_` prefix marks the fallback so a consumer
    can tell a real identity from a provisional one.
    """
    if mac:
        return slug(mac)
    return "ip_" + slug(ipv4 or ipv6 or "unknown")


def parse_scan(xml_text: str, ip_mac: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """Return {key: host record} for every host in one nmap XML document.

    `ip_mac` is an optional {ip: mac} map for addresses nmap could not learn
    itself. It is applied HERE rather than afterwards because the record's key
    is derived from the MAC -- filling one in later would leave the host keyed
    by IP and defeat the point of having it.
    """
    root = ET.fromstring(xml_text)
    hosts: dict[str, dict[str, Any]] = {}

    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"

        ipv4 = ipv6 = mac = vendor = None
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ipv4 = addr.get("addr")
            elif atype == "ipv6":
                ipv6 = addr.get("addr")
            elif atype == "mac":
                mac = (addr.get("addr") or "").upper() or None
                vendor = addr.get("vendor")

        hostname = None
        hn = host.find("hostnames")
        if hn is not None:
            first = hn.find("hostname")
            if first is not None:
                hostname = first.get("name")

        os_name = os_family = None
        os_accuracy = None
        osel = host.find("os")
        if osel is not None:
            match = osel.find("osmatch")
            if match is not None:
                os_name = match.get("name")
                os_accuracy = int(match.get("accuracy", 0))
                osclass = match.find("osclass")
                if osclass is not None:
                    os_family = osclass.get("osfamily")

        # DID THIS SCAN LOOK AT PORTS AT ALL? Discriminated on the XML's own
        # structure -- the presence of a <ports> element -- rather than on the
        # profile name that produced it, so a profile added later cannot get
        # this wrong by forgetting to declare itself.
        ports: list[dict[str, Any]] = []
        pel = host.find("ports")
        ports_scanned = pel is not None
        if pel is not None:
            for port in pel.findall("port"):
                pstate = port.find("state")
                if pstate is None or pstate.get("state") != "open":
                    continue
                entry: dict[str, Any] = {
                    "port": int(port.get("portid")),
                    "proto": port.get("protocol"),
                }
                svc = port.find("service")
                if svc is not None:
                    entry["service"] = svc.get("name")
                    if svc.get("product"):
                        entry["product"] = svc.get("product")
                    if svc.get("version"):
                        entry["version"] = svc.get("version")
                    if svc.get("extrainfo"):
                        entry["extrainfo"] = svc.get("extrainfo")
                ports.append(entry)
        ports.sort(key=lambda p: (p["proto"], p["port"]))

        # ENRICH BEFORE KEYING. See host_key(): the key derives from the MAC.
        mac_source = "arp" if mac else None
        if not mac and ipv4 and ip_mac:
            supplied = ip_mac.get(ipv4)
            if supplied:
                mac = supplied.upper()
                # Recorded, never blended. An ARP reply is this host answering
                # now; a controller record is a third party's belief about who
                # holds the address and can be stale across a reassignment.
                mac_source = "unifi"

        key = host_key(mac, ipv4, ipv6)
        hosts[key] = {
            "key": key,
            "mac": mac,
            "mac_source": mac_source,
            "ip": ipv4,
            "ipv6": ipv6,
            "hostname": hostname,
            "vendor": vendor,
            "os": os_name,
            "os_family": os_family,
            "os_accuracy": os_accuracy,
            "status": state,
            "ports": ports,
            "open_port_count": len(ports),
            "port_list": [f"{p['proto']}/{p['port']}" for p in ports],
            "ports_scanned": ports_scanned,
            "ports_scanned_at": None,
        }

    return hosts


def merge_inventory(
    inv: dict[str, dict[str, Any]],
    hosts: dict[str, dict[str, Any]],
    ts: str | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Fold one scan into the persistent inventory.

    Returns (inventory, new_keys, changed). `inv` is mutated and returned.

    A SCAN THAT DID NOT LOOK AT PORTS ASSERTS NOTHING ABOUT THEM: the previous
    observation is carried forward and NO delta is computed. Computing one
    would report every port on every host as closed after each liveness sweep
    and re-opened after each service scan -- a mass false delta, twice a day,
    on the one field that exists to signal a real change.
    """
    ts = ts or now_iso()
    new_keys: list[str] = []
    changed: list[dict[str, Any]] = []

    for key, host in hosts.items():
        prev = inv.get(key)
        if prev is None:
            host["first_seen"] = ts
            new_keys.append(key)
        else:
            host["first_seen"] = prev.get("first_seen", ts)
            if host["ports_scanned"]:
                prev_ports = set(prev.get("port_list", []))
                curr_ports = set(host["port_list"])
                opened = sorted(curr_ports - prev_ports)
                closed = sorted(prev_ports - curr_ports)
                # A host seen for the first time WITH ports is not a change;
                # only a host we had a previous port observation for can be.
                if (opened or closed) and prev.get("ports_scanned_at"):
                    changed.append(
                        {
                            "key": key,
                            "ip": host["ip"],
                            "hostname": host["hostname"],
                            "opened": opened,
                            "closed": closed,
                        }
                    )
            else:
                host["ports"] = prev.get("ports", [])
                host["port_list"] = prev.get("port_list", [])
                host["open_port_count"] = prev.get("open_port_count", 0)
                host["ports_scanned_at"] = prev.get("ports_scanned_at")

            # Preserve the last known fingerprint when this profile did not
            # take one. Guarded on the field being absent rather than applied
            # unconditionally, so a genuinely changed value still lands.
            if not host["os"] and prev.get("os"):
                host["os"] = prev["os"]
                host["os_family"] = prev.get("os_family")
                host["os_accuracy"] = prev.get("os_accuracy")
            if not host["vendor"] and prev.get("vendor"):
                host["vendor"] = prev["vendor"]

        # Port data carries its OWN age. Without this, ports carried forward
        # from last night read exactly like ports measured this minute and a
        # consumer cannot gate on freshness.
        if host["ports_scanned"]:
            host["ports_scanned_at"] = ts
        host["last_seen"] = ts
        inv[key] = host

    _retire_ip_keyed_duplicates(inv, hosts)
    return inv, new_keys, changed


def _retire_ip_keyed_duplicates(
    inv: dict[str, dict[str, Any]], hosts: dict[str, dict[str, Any]]
) -> None:
    """Drop the `ip_`-keyed predecessor of any host that now has a MAC.

    Those records do not disappear on their own -- pruning only drops them
    after the stale window -- so without this each enriched host appears TWICE
    for a month, once under each key, and every count derived from the
    inventory is inflated by exactly the hosts the enrichment was meant to fix.
    """
    for host in hosts.values():
        if not host.get("mac") or not host.get("ip"):
            continue
        legacy = "ip_" + slug(host["ip"])
        if legacy != host["key"] and legacy in inv:
            # The identity changed; the history did not.
            first = inv[legacy].get("first_seen")
            current = inv[host["key"]].get("first_seen", first)
            if first and current and first < current:
                inv[host["key"]]["first_seen"] = first
            del inv[legacy]


def prune(inv: dict[str, dict[str, Any]], stale_days: int) -> list[str]:
    """Forget hosts unseen for longer than the stale window. Mutates `inv`."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
    removed = []
    for key in list(inv):
        raw = inv[key].get("last_seen")
        try:
            last = datetime.fromisoformat(raw)
        except (TypeError, ValueError):
            # A record with no readable timestamp is kept, never dropped: we
            # cannot show it is stale, and deleting on an unreadable field
            # would silently destroy history on a parsing change.
            continue
        if last < cutoff:
            removed.append(key)
            del inv[key]
    return removed
