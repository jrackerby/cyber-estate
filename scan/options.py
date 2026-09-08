"""The scan-option vocabulary: plain English in, nmap arguments out.

THIS IS THE ONLY PLACE AN NMAP FLAG IS SPELLED. The service schema, the
translations, the dashboard card and the argv builder all derive from the
tuple below, so an option cannot exist in the UI without existing in the
builder, and cannot be added to the builder without acquiring a label someone
can read. The failure this prevents is a checkbox that looks live and does
nothing, which teaches people the whole surface is unreliable.

NO CALLER STRING EVER REACHES THE COMMAND LINE. A request names OPTION KEYS;
each key maps to a fixed, literal argument list written out here. An unknown
key is refused rather than passed through. This is the same property the
scanner LXC bought with a root-side filename allowlist, kept after the move
into Home Assistant, where it matters more rather than less: nmap runs here as
uid 0 with full capabilities, so argument injection would be arbitrary
privileged execution rather than merely an unexpected scan.

TARGETS ARE VALIDATED, NEVER INTERPOLATED. `--` terminates the option list and
every target is checked against a strict address/CIDR form before it is
appended, so a target can never be read as a flag.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True, kw_only=True)
class ScanOption:
    """One checkbox, and exactly what it does."""

    key: str
    label: str
    description: str
    args: tuple[str, ...] = ()
    # Roughly how much this multiplies scan time. Shown next to the label so a
    # choice that turns a 20-second scan into a 40-minute one says so BEFORE it
    # is made, rather than appearing to hang afterwards.
    cost: str = "low"
    # Options that cannot be combined. Declared both ways round by _validate.
    conflicts: tuple[str, ...] = field(default=())


SCAN_OPTIONS: tuple[ScanOption, ...] = (
    ScanOption(
        key="service_versions",
        label="Detect service names and versions",
        description=(
            "Ask each open port what it is running, e.g. 'OpenSSH 10.0p2' "
            "rather than just 'port 22 is open'. This is what makes a service "
            "searchable and what a vulnerability feed needs."
        ),
        args=("-sV", "--version-light"),
        cost="medium",
    ),
    ScanOption(
        key="os_detect",
        label="Identify the operating system",
        description=(
            "Guess each device's operating system from how it answers. "
            "Accurate for computers, often inconclusive for appliances."
        ),
        args=("-O", "--osscan-limit"),
        cost="medium",
    ),
    ScanOption(
        key="all_ports",
        label="Scan all 65,535 ports",
        description=(
            "Check every port instead of the 1,000 most common ones. Finds "
            "services on unusual ports; takes far longer."
        ),
        args=("-p-",),
        cost="very high",
    ),
    ScanOption(
        key="default_scripts",
        label="Run safe detection scripts",
        description=(
            "Run nmap's non-intrusive probes to collect extra detail, such as "
            "TLS certificates and HTTP titles. Read-only; nothing is changed "
            "on the target."
        ),
        args=("--script", "default,safe"),
        cost="high",
    ),
    ScanOption(
        key="udp_ports",
        label="Include common UDP services",
        description=(
            "Also check the 50 most common UDP ports, where DNS, mDNS and SNMP "
            "live. UDP has no handshake, so this is slow and less certain."
        ),
        args=("-sU",),
        cost="very high",
    ),
    ScanOption(
        key="skip_ping",
        label="Scan addresses that ignore ping",
        description=(
            "Treat every address as alive instead of skipping ones that do not "
            "answer a ping. Finds devices behind a firewall that drops pings; "
            "wastes time on addresses with nothing at all on them."
        ),
        args=("-Pn",),
        cost="high",
    ),
    ScanOption(
        key="traceroute",
        label="Trace the network path",
        description=(
            "Record the route packets take to each device. Useful for seeing "
            "which VLAN or gateway a device sits behind."
        ),
        args=("--traceroute",),
        cost="low",
    ),
    ScanOption(
        key="fast_timing",
        label="Scan faster, accept less certainty",
        description=(
            "Use aggressive timing. Finishes sooner but is more likely to miss "
            "a slow device or report a port as closed when it is filtered."
        ),
        args=("-T5",),
        cost="low",
        conflicts=("thorough_timing",),
    ),
    ScanOption(
        key="thorough_timing",
        label="Scan slower, retry more",
        description=(
            "Retry harder before giving up on a port. Use when results look "
            "inconsistent between scans, or on congested wireless."
        ),
        args=("-T2", "--max-retries", "4"),
        cost="high",
        conflicts=("fast_timing",),
    ),
)

OPTION_KEYS: tuple[str, ...] = tuple(o.key for o in SCAN_OPTIONS)
_BY_KEY: dict[str, ScanOption] = {o.key: o for o in SCAN_OPTIONS}

# Applied to every scan, whichever boxes are ticked.
#   -sS  SYN scan. Needs raw sockets; Home Assistant runs with them.
#   --open  report only open ports, so the XML stays proportional to what is
#           actually there rather than to the size of the port range.
#   -oX -   XML to stdout. Nothing is written to disk by nmap itself, so a
#           scan cannot fill the config volume.
BASE_ARGS: tuple[str, ...] = ("-sS", "--open", "-oX", "-")

# WHERE THE SCRIPT ENGINE LIVES, AND WHY IT IS NOT WHERE NMAP EXPECTS.
# Home Assistant's container ships nmap and its databases but NOT the NSE tree
# -- no `nse_main.lua`, no `nselib/`, no `scripts/`. The binary starts, `-sS`
# works, and then `-sV` dies with "could not locate nse_main.lua". That matters
# more than it sounds: `-sV` is the flag that turns "port 22 is open" into
# "OpenSSH 10.0p2", which is the entire point of a service inventory.
#
# `--datadir` points nmap at a tree under `/config`, which survives the
# container rebuild that an in-container install would not. Passed on EVERY
# scan rather than only the ones that need scripts, so the two cannot diverge.
DEFAULT_DATADIR = "/config/nmap-data"

# Used only when `all_ports` is not selected. Stated here rather than inline so
# the default port breadth is visible in the same place as the option that
# overrides it.
DEFAULT_PORT_ARGS: tuple[str, ...] = ("--top-ports", "1000")

# Neither fast nor thorough timing selected.
DEFAULT_TIMING_ARGS: tuple[str, ...] = ("-T4",)

# A liveness-only sweep. Deliberately NOT expressible through the checkboxes:
# it is the absence of port scanning rather than a modifier on it, and offering
# it as an option would let someone build a "scan" that cannot see any service.
DISCOVERY_ARGS: tuple[str, ...] = (
    "-sn", "-PE", "-PS22,80,443,3389", "-PA80,443", "-PU161", "-T4", "-oX", "-",
)

# The named profiles, expressed IN THE SAME VOCABULARY as the checkboxes, so
# "standard" and a hand-ticked equivalent produce identical arguments. A
# profile that drifted from its own description is a lie told by a preset.
PROFILES: dict[str, tuple[str, ...]] = {
    "discovery": (),  # special-cased: see DISCOVERY_ARGS
    "standard": ("service_versions", "os_detect"),
    "deep": ("service_versions", "all_ports", "default_scripts"),
}

_HOSTNAME = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                       r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


class InvalidScanRequest(ValueError):
    """A scan request that will not be run, with a reason a person can act on."""


def validate_target(target: str) -> str:
    """Return `target` if it is an address, a CIDR range or a hostname.

    REFUSES ANYTHING ELSE, including every string that could be read as an
    option. This is the check that lets targets be appended to an argument list
    at all; without it a target of `--script` would change what nmap does.
    """
    value = (target or "").strip()
    if not value:
        raise InvalidScanRequest("empty target")
    if value.startswith("-"):
        raise InvalidScanRequest(f"target may not begin with '-': {value!r}")

    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass

    # nmap's own octet-range form, e.g. 192.168.1.1-64
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}-\d{1,3}", value):
        return value

    if _HOSTNAME.fullmatch(value):
        return value

    raise InvalidScanRequest(
        f"not an address, range or hostname: {value!r}"
    )


def _validate_options(keys: list[str]) -> list[str]:
    unknown = [k for k in keys if k not in _BY_KEY]
    if unknown:
        raise InvalidScanRequest(
            f"unknown scan option(s): {', '.join(sorted(unknown))}"
        )
    chosen = set(keys)
    for key in keys:
        for other in _BY_KEY[key].conflicts:
            if other in chosen:
                raise InvalidScanRequest(
                    f"'{_BY_KEY[key].label}' and '{_BY_KEY[other].label}' "
                    "cannot both be selected"
                )
    # Deduplicated and ordered by the vocabulary, never by call order, so the
    # same request always builds a byte-identical command line.
    return [o.key for o in SCAN_OPTIONS if o.key in chosen]


def build_args(
    targets: list[str],
    option_keys: list[str] | None = None,
    exclude: list[str] | None = None,
    discovery_only: bool = False,
    datadir: str | None = None,
) -> list[str]:
    """Build a complete nmap argument list. Raises InvalidScanRequest.

    Every element is either a literal from this module or a target that has
    passed `validate_target`. Nothing else can appear.
    """
    if not targets:
        raise InvalidScanRequest("no targets given")
    clean_targets = [validate_target(t) for t in targets]
    clean_exclude = [validate_target(t) for t in (exclude or [])]

    # FIRST, so it is in effect before anything that needs it. nmap resolves
    # data files at startup, and a --datadir arriving after --script would be
    # applied but is needlessly fragile to argument-order changes later.
    args: list[str] = []
    if datadir:
        args.extend(["--datadir", datadir])

    if discovery_only:
        args.extend(DISCOVERY_ARGS)
    else:
        keys = _validate_options(list(option_keys or []))
        args.extend(BASE_ARGS)
        for key in keys:
            args.extend(_BY_KEY[key].args)
        if "all_ports" not in keys:
            args.extend(DEFAULT_PORT_ARGS)
        if not {"fast_timing", "thorough_timing"} & set(keys):
            args.extend(DEFAULT_TIMING_ARGS)

    if clean_exclude:
        args.extend(["--exclude", ",".join(clean_exclude)])

    # `--` ends the option list. Everything after it is a target, whatever it
    # looks like -- belt and braces alongside validate_target().
    args.append("--")
    args.extend(clean_targets)
    return args


def describe(option_keys: list[str]) -> str:
    """A one-line plain-English summary of what a scan will do.

    Returned to the caller of the scan service and logged, so what ran is
    recorded in the words the person chose it with rather than as a flag soup
    they would have to decode.
    """
    keys = _validate_options(list(option_keys or []))
    if not keys:
        return "Check which ports are open (top 1,000 ports)."
    return "Check which ports are open, then: " + "; ".join(
        _BY_KEY[k].label.lower() for k in keys
    ) + "."


def worst_cost(option_keys: list[str]) -> str:
    """The highest cost tier among the chosen options."""
    order = ["low", "medium", "high", "very high"]
    worst = "low"
    for key in _validate_options(list(option_keys or [])):
        if order.index(_BY_KEY[key].cost) > order.index(worst):
            worst = _BY_KEY[key].cost
    return worst
