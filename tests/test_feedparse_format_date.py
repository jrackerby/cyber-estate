#!/usr/bin/env python3
"""format_date's stored identity must survive dateutil's deprecation.

WHAT THIS IS ABOUT. `feeds/feedparse.py`'s `format_date` produces a string that
becomes part of `entry_key` for feeds carrying neither guid nor link, and
`entry_key` is a STORED IDENTITY that acknowledgements are matched against. So
its output may not change -- a different string orphans every existing ack,
silently, with nothing to point at.

It used to reach a NAIVE datetime by letting dateutil fail to understand a zone
abbreviation, which emits UnknownTimezoneWarning and which dateutil says a
future release will turn into an EXCEPTION. The identity was therefore resting
on deprecated behaviour: on a dependency bump the module would start RAISING
for exactly the feeds it handles quietly today.

`_decline_abbreviations` reaches the same datetime by a supported route -- it
answers for every zone name, so dateutil never enters the guess-or-warn path.

THE ASSERTION IS EQUIVALENCE, NOT CORRECTNESS. This does not claim the naive
reading is right; the module's own docstring records why it is deliberate and
why changing it is an ack migration rather than a bug fix. It claims only that
the new route produces the OLD STRING, today and after the bump.

Run: python3 tools/test_feedparse_format_date.py
     (needs feedparser + python-dateutil; see tools/component_requirements.py)
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import time
import warnings
from datetime import timedelta

# Pinned before anything parses a date: the whole point is that the result must
# not depend on the host's zone, and a UTC process is the case that used to be
# wrong (measured on a UTC runner).
os.environ["TZ"] = "UTC"
try:
    time.tzset()
except AttributeError:  # non-POSIX
    pass

REPO = pathlib.Path(__file__).resolve().parent.parent
CANDIDATES = [
    REPO / "feeds" / "feedparse.py",
    pathlib.Path.home() / "repos" / "cyber-estate" / "feeds" / "feedparse.py",
]

MODULE_PATH = next((p for p in CANDIDATES if p.is_file()), None)
if MODULE_PATH is None:
    print("SKIP: feedparse.py not found in either the submodule or ~/repos/cyber-estate")
    print("      (feeds/feedparse.py not found in this repo)")
    raise SystemExit(0)

# Loaded BY FILE PATH, not through the package: importing cyber_estate would
# pull in __init__.py and its homeassistant imports, which this module's own
# docstring promises are not needed.
spec = importlib.util.spec_from_file_location("_feedparse_under_test", MODULE_PATH)
feedparse = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(feedparse)
except ModuleNotFoundError as exc:
    print(f"SKIP: {exc} -- feedparser/dateutil not installed in this interpreter")
    raise SystemExit(0)

from dateutil import parser as P  # noqa: E402
from dateutil.parser import UnknownTimezoneWarning  # noqa: E402

FMT = "%a, %d %b %Y %H:%M:%S %Z"

# Named zones inside _TZINFOS, named zones outside it, the zero-offset names
# dateutil resolves itself, numeric offsets, ISO-8601, and no zone at all.
SAMPLES = [
    "Thu, 06 Aug 2026 15:00:00 EDT",
    "Thu, 06 Aug 2026 15:00:00 EST",
    "Thu, 06 Aug 2026 15:00:00 PDT",
    "Thu, 06 Aug 2026 15:00:00 CST",
    "Thu, 06 Aug 2026 15:00:00 MST",
    "Thu, 06 Aug 2026 15:00:00 HST",
    "Thu, 06 Aug 2026 15:00:00 GMT",
    "Thu, 06 Aug 2026 15:00:00 UTC",
    "Thu, 06 Aug 2026 15:00:00 UT",
    "Thu, 06 Aug 2026 15:00:00 Z",
    "Thu, 06 Aug 2026 15:00:00 BST",
    "Thu, 06 Aug 2026 15:00:00 AEST",
    "Thu, 06 Aug 2026 15:00:00 IST",
    "Thu, 06 Aug 2026 15:00:00 +0000",
    "Thu, 06 Aug 2026 15:00:00 -0400",
    "Thu, 06 Aug 2026 15:00:00 +0530",
    "Thu, 06 Aug 2026 15:00:00",
    "2026-08-06T15:00:00Z",
    "2026-08-06T15:00:00-04:00",
    "2026-08-06 15:00:00 EST",
    "Mon, 01 Jan 2024 00:00:00 MST",
]

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ok   {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  FAIL {msg}", file=sys.stderr)


def legacy(value: str) -> str:
    """The form that shipped first -- the string acks were stored with."""
    return P.parse(value).strftime(FMT)


print(f"format_date identity  (module: {MODULE_PATH})")
print(f"process TZ={os.environ['TZ']} tzname={time.tzname}\n")

# 1. Byte-identical to the legacy form, today.
mismatches = []
for s in SAMPLES:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        want = legacy(s)
    got = feedparse.format_date(s, FMT)
    if got != want:
        mismatches.append((s, want, got))
if mismatches:
    for s, want, got in mismatches:
        bad(f"{s!r}: was {want!r}, now {got!r} -- this ORPHANS ACKS")
else:
    ok(f"byte-identical to the legacy form on all {len(SAMPLES)} shapes")

# 2. Emits no UnknownTimezoneWarning at all.
noisy = []
for s in SAMPLES:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        feedparse.format_date(s, FMT)
        if any(w.category is UnknownTimezoneWarning for w in caught):
            noisy.append(s)
if noisy:
    bad(f"{len(noisy)} shape(s) still warn, e.g. {noisy[0]!r} -- still on the deprecated path")
else:
    ok("no shape emits UnknownTimezoneWarning")

# 3. THE POINT: with the warning promoted to an error -- what dateutil says a
#    future release will do -- the output is unchanged and nothing raises.
broken = []
for s in SAMPLES:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        want = legacy(s)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UnknownTimezoneWarning)
        try:
            got = feedparse.format_date(s, FMT)
        except Exception as exc:  # noqa: BLE001
            got = f"<{type(exc).__name__}>"
    if got != want:
        broken.append((s, want, got))
if broken:
    for s, want, got in broken:
        bad(f"after the bump {s!r}: expected {want!r}, got {got!r}")
else:
    ok(f"identical with UnknownTimezoneWarning promoted to an error ({len(SAMPLES)} shapes)")

# 4. Self-test of the harness: the legacy form MUST break under that promotion,
#    or case 3 proves nothing -- a check that cannot fail is not evidence.
legacy_raised = 0
for s in SAMPLES:
    with warnings.catch_warnings():
        warnings.simplefilter("error", UnknownTimezoneWarning)
        try:
            legacy(s)
        except Exception:  # noqa: BLE001
            legacy_raised += 1
if legacy_raised > 0:
    ok(f"the legacy form raises on {legacy_raised}/{len(SAMPLES)} shapes under the same promotion")
else:
    bad("the legacy form did not raise -- case 3 proved nothing")

# 5. The ordering path keeps its own zone resolution, unchanged here.
entries = [
    {"id": "later-instant", "published": "Thu, 06 Aug 2026 15:00:00 EDT"},   # 19:00Z
    {"id": "earlier", "published": "Thu, 06 Aug 2026 18:00:00 GMT"},          # 18:00Z
]
picked = feedparse.latest_entry_key(entries, FMT)
if picked == "later-instant":
    ok("latest_entry_key still resolves EDT by offset, not by host zone")
else:
    bad(f"latest_entry_key picked {picked!r} -- ordering regressed")

# 6. A zero-offset named zone must still render UTC, not its own name.
if feedparse.format_date("Thu, 06 Aug 2026 15:00:00 GMT", FMT).endswith("UTC"):
    ok("a zero-offset named zone still renders %Z as UTC")
else:
    bad("GMT no longer renders as UTC -- zero-offset normalisation is broken")

print(f"\npassed={PASS} failed={FAIL}")
raise SystemExit(1 if FAIL else 0)
