#!/usr/bin/env python3
"""Tests for runtime.py -- which coordinator a scan service actually reaches.

WHY THIS SUITE EXISTS. Both of cyber_estate's scan services refused
every call, on every configuration, network-wide, from that merge until
this suite was written. The merge turned `entry.runtime_data` from one
coordinator into a dict of three; the service's lookup kept testing the
container itself with `hasattr(runtime_data, "async_run_custom_scan")`, which a
dict cannot satisfy for any input. Nothing caught it for two reasons worth
recording, because both are still true of everything this repo ships:

  1. THE SERVICES HAD NO CALLERS. Nothing on any board or in any automation
     invoked them, so a total failure produced no symptom anywhere. It surfaced
     only when jrackerby/ha-dashboards-monitoring#25 wired live buttons to them.
  2. hassfest NEVER IMPORTS THE CODE and the pure layer could not reach this
     lookup while it was inlined in a module that imports homeassistant and
     voluptuous at import time. A bug in the one line joining a service to its
     coordinator sat behind a fully green required-check set.

So the lookup moved to runtime.py, which imports nothing, and is tested here on
the object shape `__init__.py` actually writes -- not on a paraphrase of it.

Run: python3 tests/test_runtime_data_accessor.py
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")


def load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rt = load("ce_runtime", "runtime.py")

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}: got {got!r}, want {want!r}")


# --- stubs shaped like the real thing --------------------------------------
#
# LocalCoordinator DEFINES async_run_custom_scan; AgentCoordinator does not.
# That asymmetry is the mode discriminator the lookup relies on, so the stubs
# reproduce it rather than carrying a mode string the real code never reads.
class LocalLike:
    async def async_run_custom_scan(self, **kw):  # noqa: D102
        return {}


class AgentLike:
    pass


class Entry:
    """A config entry carrying whatever runtime_data it is given."""

    def __init__(self, runtime_data=Ellipsis):
        if runtime_data is not Ellipsis:
            self.runtime_data = runtime_data


def merged(scan):
    """Exactly the dict __init__.py writes, keys and all."""
    return {"feeds": object(), "cve": object(), rt.KEY_SCAN: scan}


# --- the regression: a merged entry in local mode IS reachable --------------
print("a local-mode merged entry is found (before the fix, it was not)")
local = LocalLike()
check("scan_coordinator_of digs the scan coordinator out of the dict",
      rt.scan_coordinator_of(Entry(merged(local))) is local, True)
check("scan_coordinators returns it",
      rt.scan_coordinators([Entry(merged(local))]) == [local], True)
check("the key indexed is the key __init__.py writes", rt.KEY_SCAN, "scan")

print("\nthe exact bug shape: the dict must never be duck-typed itself")
data = merged(local)
check("the runtime_data container has no scan method of its own",
      hasattr(data, "async_run_custom_scan"), False)
check("...yet the lookup still finds the coordinator inside it",
      rt.scan_coordinators([Entry(data)]) == [local], True)

# --- agent mode still refuses, and refuses for the real reason -------------
print("\nagent mode is still not a custom-scan target")
agent = AgentLike()
check("an agent entry yields no custom-scan coordinator",
      rt.scan_coordinators([Entry(merged(agent))]), [])
check("...but its coordinator is still reachable by key",
      rt.scan_coordinator_of(Entry(merged(agent))) is agent, True)

# --- entries that carry nothing ------------------------------------------
print("\nan entry with no runtime_data reads as 'cannot scan', never raises")
check("no runtime_data attribute at all", rt.scan_coordinator_of(Entry()), None)
check("runtime_data is None (unloaded)", rt.scan_coordinator_of(Entry(None)), None)
check("runtime_data is a bare coordinator (the pre-merge shape)",
      rt.scan_coordinator_of(Entry(LocalLike())), None)
check("an empty dict", rt.scan_coordinator_of(Entry({})), None)
check("a dict with feeds and cve but no scan",
      rt.scan_coordinator_of(Entry({"feeds": object(), "cve": object()})), None)
check("scan present but explicitly None",
      rt.scan_coordinator_of(Entry(merged(None))), None)

print("\nmixed and multiple entries")
check("two local entries both come back (the caller refuses the ambiguity)",
      len(rt.scan_coordinators([Entry(merged(LocalLike())), Entry(merged(LocalLike()))])), 2)
check("a local entry beside an unloaded one yields exactly one",
      rt.scan_coordinators([Entry(), Entry(merged(local))]) == [local], True)
check("no entries at all", rt.scan_coordinators([]), [])

# --- the accessor is the only door ---------------------------------------
#
# A source check, not a behaviour one: nothing else can assert that a FUTURE
# reader goes through runtime.py rather than re-inlining the index that broke.
print("\nnothing outside runtime.py duck-types runtime_data")
offenders = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in (".git", ".github", "tests", "tools", "__pycache__")]
    for fn in filenames:
        if not fn.endswith(".py") or fn == "runtime.py":
            continue
        path = os.path.join(dirpath, fn)
        src = open(path).read()
        # Strip comments and docstring prose: several files DOCUMENT the old
        # shape on purpose, and a file describing its own history must not
        # match the check that says the pattern is gone.
        code = re.sub(r"#.*", "", src)
        code = re.sub(r'"""(?:.|\n)*?"""', "", code)
        if re.search(r'hasattr\(\s*[\w.]*runtime_data', code):
            offenders.append(os.path.relpath(path, ROOT))
check("no module duck-types the runtime_data container", offenders, [])

svc = open(os.path.join(ROOT, "scan", "scan_service.py")).read()
svc_code = re.sub(r"#.*", "", re.sub(r'"""(?:.|\n)*?"""', "", svc))
check("scan_service.py imports the accessor",
      "from ..runtime import scan_coordinators" in svc_code, True)
check("scan_service.py no longer reads runtime_data itself",
      "runtime_data" in svc_code, False)

print("\nthe refusal names a domain that can actually exist")
check("no message sends the reader after a network_inventory entry",
      re.search(r"no network_inventory entry", svc), None)
check("the local-mode refusal names cyber_estate",
      "no cyber_estate entry is set up to scan" in svc, True)

# --- self-test: prove the checks above can actually fail -------------------
print("\nSELF-TEST (these MUST report a failure to prove the gate works)")
_p, _f = PASS, FAIL
check("deliberately wrong equality", 1, 2)
check("deliberately wrong identity", rt.scan_coordinator_of(Entry()) is local, True)
check("the old inlined lookup, run directly, finds nothing",
      [e for e in [Entry(merged(local))]
       if hasattr(getattr(e, "runtime_data", None), "async_run_custom_scan")] != [],
      True)
detected = FAIL - _f
PASS, FAIL = _p, _f
if detected == 3:
    PASS += 1
    print("  PASS  self-test: all three deliberate failures were detected")
    print("        (the third IS the bug: the pre-fix lookup, applied")
    print("         to a correctly configured local entry, returns nothing)")
else:
    FAIL += 1
    print(f"  FAIL  self-test: expected 3 detected failures, saw {detected}")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
