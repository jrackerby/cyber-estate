#!/usr/bin/env python3
"""Tests for network_inventory's parse.py and options.py.

TWO FAILURE MODES ARE COVERED HERE AND BOTH ARE SILENT.

The first is the one that cost this network a night of service data: a liveness
sweep emits no <ports> element, and reading that as "nothing is open" erases
every port the previous scan found. Nothing throws, the inventory stays
well-formed, and the loss is only visible by noticing that a number went down.

The second is argument injection. nmap runs inside Home Assistant as uid 0 with
full capabilities, so a target or option that reaches the command line
unvalidated is arbitrary privileged execution -- and a scan that quietly ran
the wrong arguments still returns a clean XML document.

THE SELF-TEST AT THE END PROVES THESE CHECKS CAN FAIL. A gate
that has only ever seen good input has not been shown capable of reporting bad
input.

Run: python3 tools/test_network_inventory_scan.py
"""

from __future__ import annotations

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# network_inventory merged into cyber_estate's scan/ subpackage.
PKG = os.path.join(HERE, "..", "scan")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(PKG, filename))
    mod = importlib.util.module_from_spec(spec)
    # REGISTER BEFORE EXEC -- dataclasses resolves a class's module through
    # sys.modules, and a module loaded by spec alone raises AttributeError on
    # the first @dataclass rather than anywhere near the real cause.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


parse = load("ni_parse", "parse.py")
options = load("ni_options", "options.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def raises(label, fn, exc=options.InvalidScanRequest):
    global PASS, FAIL
    try:
        fn()
    except exc:
        PASS += 1
        print(f"  PASS  {label}")
        return
    except Exception as err:  # noqa: BLE001
        FAIL += 1
        print(f"  FAIL  {label}\n          raised {type(err).__name__}: {err}")
        return
    FAIL += 1
    print(f"  FAIL  {label}\n          no exception raised")


# --- fixtures --------------------------------------------------------------

PORTSCAN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.234" addrtype="ipv4"/>
    <address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi"/>
    <hostnames><hostname name="PI4KIOSK04"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="10.0p2"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95">
      <osclass osfamily="Linux"/>
    </osmatch></os>
  </host>
</nmaprun>
"""

# The same host, seen by a liveness sweep: NO <ports> element at all.
DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.234" addrtype="ipv4"/>
    <address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi"/>
  </host>
</nmaprun>
"""

# A host with the port range scanned and genuinely nothing open.
CLOSED_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.234" addrtype="ipv4"/>
    <address addr="DC:A6:32:11:22:33" addrtype="mac" vendor="Raspberry Pi"/>
    <ports><extraports state="closed" count="1000"/></ports>
  </host>
</nmaprun>
"""

KEY = "dca6321122 33".replace(" ", "")


print("\nparse_scan")
hosts = parse.parse_scan(PORTSCAN_XML)
check("one host parsed", len(hosts), 1)
h = hosts[KEY]
check("keyed by MAC", h["key"], KEY)
check("hostname read", h["hostname"], "PI4KIOSK04")
check("only OPEN ports kept", h["port_list"], ["tcp/22"])
check("service name", h["ports"][0]["service"], "ssh")
check("product carried", h["ports"][0]["product"], "OpenSSH")
check("version carried", h["ports"][0]["version"], "10.0p2")
check("os fingerprint", h["os"], "Linux 5.X")
check("ports were scanned", h["ports_scanned"], True)

disc = parse.parse_scan(DISCOVERY_XML)[KEY]
check("liveness sweep reports ports NOT scanned", disc["ports_scanned"], False)
closed = parse.parse_scan(CLOSED_XML)[KEY]
check("empty <ports> element IS a port scan", closed["ports_scanned"], True)
check("...and reports nothing open", closed["port_list"], [])

print("\nmerge_inventory -- the erasure regression")
inv = {}
inv, new, changed = parse.merge_inventory(inv, parse.parse_scan(PORTSCAN_XML), ts="T1")
check("first sighting is new", new, [KEY])
check("first sighting is not a change", changed, [])
check("ports stored", inv[KEY]["port_list"], ["tcp/22"])
check("port age stamped", inv[KEY]["ports_scanned_at"], "T1")

inv, new, changed = parse.merge_inventory(inv, parse.parse_scan(DISCOVERY_XML), ts="T2")
check("liveness sweep does NOT erase ports", inv[KEY]["port_list"], ["tcp/22"])
check("liveness sweep does NOT invent a delta", changed, [])
check("liveness sweep does NOT restamp port age", inv[KEY]["ports_scanned_at"], "T1")
check("liveness sweep DOES update last_seen", inv[KEY]["last_seen"], "T2")
check("os preserved across liveness sweep", inv[KEY]["os"], "Linux 5.X")
check("first_seen preserved", inv[KEY]["first_seen"], "T1")

inv, new, changed = parse.merge_inventory(inv, parse.parse_scan(CLOSED_XML), ts="T3")
check("a real port scan CAN close a port", inv[KEY]["port_list"], [])
check("...and that IS reported as a change",
      [(c["opened"], c["closed"]) for c in changed], [([], ["tcp/22"])])
check("port age restamped by a real scan", inv[KEY]["ports_scanned_at"], "T3")

print("\nbuild_args -- injection refusals")
check("plain scan",
      options.build_args(["192.0.2.0/24"]),
      ["-sS", "--open", "-oX", "-", "--top-ports", "1000", "-T4",
       "--", "192.0.2.0/24"])
check("versions + os",
      options.build_args(["10.0.0.1"], ["service_versions", "os_detect"]),
      ["-sS", "--open", "-oX", "-", "-sV", "--version-light", "-O",
       "--osscan-limit", "--top-ports", "1000", "-T4", "--", "10.0.0.1"])
check("all_ports replaces the top-ports default",
      "--top-ports" in options.build_args(["10.0.0.1"], ["all_ports"]), False)
check("option order is vocabulary order, not call order",
      options.build_args(["10.0.0.1"], ["os_detect", "service_versions"]),
      options.build_args(["10.0.0.1"], ["service_versions", "os_detect"]))
check("exclude list applied",
      "--exclude" in options.build_args(["10.0.0.0/24"], [], ["10.0.0.5"]), True)
check("discovery ignores port options",
      "-sn" in options.build_args(["10.0.0.0/24"], ["all_ports"], discovery_only=True),
      True)

print("\n--datadir -- without this, -sV silently stops working")
check("datadir leads the argument list",
      options.build_args(["10.0.0.1"], ["service_versions"],
                         datadir="/config/nmap-data")[:2],
      ["--datadir", "/config/nmap-data"])
check("datadir also applied to a discovery sweep",
      options.build_args(["10.0.0.0/24"], discovery_only=True,
                         datadir="/config/nmap-data")[:2],
      ["--datadir", "/config/nmap-data"])
check("no datadir given -> flag absent, not empty",
      "--datadir" in options.build_args(["10.0.0.1"]), False)
check("datadir does not disturb the rest of the line",
      options.build_args(["10.0.0.1"], ["service_versions"],
                         datadir="/d")[2:],
      options.build_args(["10.0.0.1"], ["service_versions"]))

raises("unknown option refused",
       lambda: options.build_args(["10.0.0.1"], ["rm_rf_slash"]))
raises("conflicting timing refused",
       lambda: options.build_args(["10.0.0.1"], ["fast_timing", "thorough_timing"]))
raises("flag-shaped target refused",
       lambda: options.build_args(["--script=evil"]))
raises("shell metacharacter target refused",
       lambda: options.build_args(["10.0.0.1; rm -rf /"]))
raises("space-separated injection refused",
       lambda: options.build_args(["10.0.0.1 --script evil"]))
raises("empty target refused", lambda: options.build_args([""]))
raises("no targets refused", lambda: options.build_args([]))
raises("bad exclude refused",
       lambda: options.build_args(["10.0.0.0/24"], [], ["--script"]))

check("hostname target accepted", options.validate_target("nas.local"), "nas.local")
check("octet range accepted",
      options.validate_target("192.0.2.1-64"), "192.0.2.1-64")

print("\ndescribe / cost")
check("empty description", options.describe([]),
      "Check which ports are open (top 1,000 ports).")
check("described in the words chosen",
      options.describe(["service_versions"]),
      "Check which ports are open, then: detect service names and versions.")
check("worst cost wins",
      options.worst_cost(["service_versions", "all_ports"]), "very high")

print("\nvocabulary integrity")
check("every option has a label", all(o.label for o in options.SCAN_OPTIONS), True)
check("every option has a description",
      all(len(o.description) > 20 for o in options.SCAN_OPTIONS), True)
check("keys unique", len(options.OPTION_KEYS), len(set(options.OPTION_KEYS)))
check("conflicts are symmetric",
      all(o.key in dict((x.key, x) for x in options.SCAN_OPTIONS)[c].conflicts
          for o in options.SCAN_OPTIONS for c in o.conflicts), True)
check("every profile names only real options",
      all(k in options.OPTION_KEYS
          for keys in options.PROFILES.values() for k in keys), True)

print("\nplatforms must not subscript mode-specific config")
# THE BUG THIS CATCHES SHIPPED. button, switch and sensor all did
# `entry.data[CONF_HOST]`, which exists only in agent mode, so every platform
# raised KeyError: 'host' the moment a local entry loaded -- and nothing in the
# pure test suite could see it, because the key is only absent at runtime in
# one of two modes. Platforms run in BOTH modes, so a subscript there is a
# latent crash by construction; `_setup_agent` in __init__.py is the one place
# entitled to use [] on agent-only keys, because it only runs in that mode.
# renamed inside the scan/ subpackage to avoid colliding with
# cyber_estate's own top-level button.py/switch.py/sensor.py dispatchers.
_PLATFORMS = [
    "button_entities.py", "switch_entities.py", "entities.py",
    "entity.py", "coordinator.py",
]
_offenders = []
for _name in _PLATFORMS:
    with open(os.path.join(PKG, _name)) as fh:
        for _i, _line in enumerate(fh, 1):
            _stripped = _line.split("#")[0]
            if "entry.data[" in _stripped or ".data[CONF_" in _stripped:
                _offenders.append(f"{_name}:{_i}")
check("no platform subscripts entry.data", _offenders, [])

print("\nevery measured sensor must declare a state class")
# WHY THIS GATE EXISTS. `open_ports` shipped with a unit and no state_class.
# Those entity ids were previously owned by the scanner's MQTT discovery, which
# DID declare measurement, so Home Assistant already held long-term statistics
# for them -- and raised one repair per host offering to delete that history.
# A unit without a state class is the signature, and it is invisible at runtime
# until the recorder notices. Checked on the source rather than by importing,
# because sensor.py imports Home Assistant and this suite must not.
# renamed from sensor.py to entities.py inside scan/, see
# _PLATFORMS' comment above.
_src = open(os.path.join(PKG, "entities.py")).read()
_blocks = _src.split("SensorDescription(")[1:]
_missing = []
for _b in _blocks:
    _body = _b.split("\n    ),")[0]
    if "native_unit_of_measurement" not in _body:
        continue
    if "state_class" not in _body:
        _key = "?"
        for _line in _body.splitlines():
            if _line.strip().startswith("key="):
                _key = _line.strip()
                break
        _missing.append(_key)
check("no sensor has a unit without a state class", _missing, [])
check("the gate actually inspected some descriptions",
      len(_blocks) > 3, True)

print("\nservices.yaml <-> options.py must not drift")
# Parsed WITHOUT pyyaml: it is not guaranteed present on the machine running
# these tests, and the shape here is regular enough that a targeted reader is
# more honest than pulling in a dependency for one file.
# services.yaml lives at the integration ROOT (cyber_estate/),
# not inside the scan/ subpackage -- HA only reads it from there.
_yaml_path = os.path.join(PKG, "..", "services.yaml")
with open(_yaml_path) as fh:
    _lines = fh.readlines()

_services: dict[str, list[str]] = {}
_current = None
_in_fields = False
for _line in _lines:
    if _line.startswith(("#", "\n")):
        continue
    if not _line.startswith(" "):
        _current = _line.split(":")[0].strip()
        _services[_current] = []
        _in_fields = False
    elif _line.strip() == "fields:":
        _in_fields = True
    elif _in_fields and _line.startswith("    ") and not _line.startswith("     "):
        _services[_current].append(_line.split(":")[0].strip())

_custom = set(_services.get("custom_scan", []))
_device = set(_services.get("scan_device", []))
_vocab = set(options.OPTION_KEYS)

check("custom_scan offers every option the builder accepts",
      sorted(_vocab - _custom), [])
check("custom_scan offers nothing the builder would reject",
      sorted(_custom - _vocab - {"targets"}), [])
check("scan_device offers every option too", sorted(_vocab - _device), [])
check("scan_device offers nothing extra",
      sorted(_device - _vocab - {"device_id"}), [])
check("both services were actually found in the yaml",
      sorted(_services), ["custom_scan", "scan_device"])
# PINS THE PARSER ITSELF. The comparisons above are set differences, so a
# reader that silently returned nothing would still make them pass in one
# direction; asserting the count means a broken parser cannot look clean.
check("parser read every field of custom_scan",
      len(_custom), len(options.OPTION_KEYS) + 1)  # + targets

# --- self-test: prove the checks above can actually fail --------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
raises("deliberately non-raising call", lambda: None)
detected = FAIL - _f
PASS, FAIL = _p, _f
if detected == 2:
    PASS += 1
    print("  PASS  self-test: both deliberate failures were detected")
else:
    FAIL += 1
    print(f"  FAIL  self-test: expected 2 detected failures, saw {detected}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
