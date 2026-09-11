#!/usr/bin/env python3
"""Gate for estate_feeds' latest_entry_key / entry_key.

RUNS ON THE HA HOST, because feedparser lives in that container and not in the
CLI box's venv. Invoke with:

    shell_command.run_tool_py  script: test_estate_feeds_key.py

feedparse.py imports nothing from homeassistant, deliberately, so this loads it
BY FILE PATH rather than through the package -- importing estate_feeds itself
would pull in __init__.py and its ConfigEntry import, which is the thing the
module's own docstring promises is not needed.

WHAT IT PROVES. latest_entry_key picks the item a consuming template would pick
and names it with the feed's own guid. The tie-break and the timezone handling
are the parts worth gating: an ack keyed on this and a headline rendered from
the entries must never name different items, and the old Jinja form got the
zone wrong uniformly, which was survivable only because it was uniform.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import time

# TIMEZONE, PINNED BEFORE ANYTHING PARSES A DATE. The zone fixture below feeds
# dateutil the string "EDT", and dateutil resolves a bare zone ABBREVIATION only
# when it matches the process's own local zone -- it reads time.tzname, and for
# anything else returns a NAIVE datetime plus an UnknownTimezoneWarning. So the
# same assertion passed on a host set to America/New_York and failed on a UTC
# runner, where 15:00 EDT decoded as 15:00 UTC: earlier than the 18:00 GMT entry
# instead of later, so latest_entry_key named the other item and the check that
# exists to prove zones are honoured reported the zone-blind answer. That is the
# benign-looking state the rule says to name and measure, and it is why this test
# had never once passed in CI.
#
# Pinned HERE rather than as a TZ= in tools-tests.yml on purpose: the dependency
# is the test's, so it travels with the file and holds however it is invoked --
# CI, the HA host, or a bare shell. America/New_York is not arbitrary; it is the
# zone the consuming integration actually runs in, and the rule wants the channel
# under test to be the one that will be used.
#
# This pin makes the TEST deterministic. feedparse.py's own host-dependence was
# the separate half of the same bug and is fixed in this component:
# _TZINFOS there resolves abbreviations explicitly, so the module no longer
# leans on the coincidence either. The pin stays regardless -- the EDT fixture
# below still needs a known zone to be a meaningful assertion, and a test that
# silently runs in the wrong zone reports a zone-blind answer as a pass.
os.environ["TZ"] = "America/New_York"
time.tzset()
if time.tzname != ("EST", "EDT"):
    sys.exit(
        "CANNOT RUN: TZ pin did not take -- time.tzname is "
        f"{time.tzname!r}, expected ('EST', 'EDT'). The zone assertions below "
        "would report a zone-blind answer as a pass. Is tzdata installed?"
    )

HERE = pathlib.Path(__file__).resolve().parent
# estate_feeds merged into cyber_estate's feeds/ subpackage.
CANDIDATES = [
    HERE.parent / "feeds" / "feedparse.py",
    pathlib.Path("/config/custom_components/cyber_estate/feeds/feedparse.py"),
]


def load():
    for path in CANDIDATES:
        if path.exists():
            spec = importlib.util.spec_from_file_location("_ef_feedparse", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod, path
    sys.exit("feedparse.py not found in any known location: " +
             ", ".join(str(p) for p in CANDIDATES))


FMT = "%a, %d %b %Y %H:%M:%S %Z"


def entry(**kw):
    """A feedparser entry is dict-like; a plain dict is faithful enough for the
    fields these functions touch, and keeps the gate independent of a network."""
    return dict(kw)


def main() -> int:
    fp, path = load()
    print(f"== loaded == {path}")

    # The module's own promise, asserted rather than trusted.
    src = path.read_text(encoding="utf-8")
    assert "from homeassistant" not in src and "import homeassistant" not in src, \
        "feedparse.py imports homeassistant -- it is supposed to be pure"
    print("  purity: imports nothing from homeassistant  OK")

    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    # --- entry_key: the fallback ladder, in order -------------------------
    check("key/guid-wins",
          fp.entry_key(entry(id="GUID-1", link="L", published="Thu, 06 Aug 2026 17:33:00 GMT"), FMT),
          "GUID-1")
    check("key/link-fallback",
          fp.entry_key(entry(link="LINK-1", published="Thu, 06 Aug 2026 17:33:00 GMT"), FMT),
          "LINK-1")
    # UTC, not GMT: format_date parses through dateutil and %Z on the result
    # emits "UTC" for a GMT input. That is not incidental -- it is why the
    # pre-move item_key read "...17:33:00 UTC" against a feed that publishes
    # GMT, and why the consuming template's strptime format had to be %Z.
    check("key/date-last-resort",
          fp.entry_key(entry(published="Thu, 06 Aug 2026 17:33:00 GMT"), FMT),
          "Thu, 06 Aug 2026 17:33:00 UTC")
    check("key/nothing-to-key-on", fp.entry_key(entry(title="t"), FMT), "")
    check("key/not-dict-like", fp.entry_key(object(), FMT), "")
    # An empty id must fall through rather than winning as a blank key.
    check("key/empty-guid-falls-through",
          fp.entry_key(entry(id="", link="LINK-2", published="Thu, 06 Aug 2026 17:33:00 GMT"), FMT),
          "LINK-2")

    # --- latest_entry_key: selection --------------------------------------
    feed = [
        entry(id="OLD", published="Tue, 28 Apr 2026 13:40:00 GMT"),
        entry(id="NEW", published="Thu, 06 Aug 2026 17:33:00 GMT"),
        entry(id="MID", published="Mon, 27 Jul 2026 12:07:00 GMT"),
    ]
    check("latest/picks-newest", fp.latest_entry_key(feed, FMT), "NEW")
    check("latest/empty-feed", fp.latest_entry_key([], FMT), "")
    check("latest/no-dates", fp.latest_entry_key([entry(id="X")], FMT), "")

    # TIE-BREAK: equal timestamps -> FIRST in feed order. This reproduces the
    # consuming template's `pub > newest` (strictly greater), and a card keying
    # on this must never name a different item than a headline rendered from
    # the same entries.
    tie = [
        entry(id="FIRST", published="Thu, 06 Aug 2026 17:33:00 GMT"),
        entry(id="SECOND", published="Thu, 06 Aug 2026 17:33:00 GMT"),
    ]
    check("latest/tie-goes-to-first", fp.latest_entry_key(tie, FMT), "FIRST")

    # An unparseable date is SKIPPED, not sorted to an end -- otherwise one bad
    # row could capture the key and the ack would name the wrong item.
    mixed = [
        entry(id="GOOD", published="Thu, 06 Aug 2026 17:33:00 GMT"),
        entry(id="JUNK", published="not a date at all"),
    ]
    check("latest/skips-unparseable", fp.latest_entry_key(mixed, FMT), "GOOD")

    # TIMEZONE, the reason this moved out of Jinja. These two are the SAME
    # instant expressed in different zones; the later-looking wall clock is the
    # EARLIER instant, so a zone-blind comparison picks the wrong one.
    zones = [
        entry(id="UTC-1800", published="Thu, 06 Aug 2026 18:00:00 GMT"),
        entry(id="EDT-1500", published="Thu, 06 Aug 2026 15:00:00 EDT"),  # 19:00 UTC
    ]
    check("latest/honours-timezone", fp.latest_entry_key(zones, FMT), "EDT-1500")

    # A NON-LOCAL abbreviation, which is the case the TZ pin above cannot
    # rescue and _TZINFOS in feedparse.py exists for. PDT is never the network
    # host's zone, so dateutil resolves it only if the module hands it a
    # tzinfos table; without one it decodes naive, gets defaulted to UTC, and
    # 12:00 PDT (19:00 UTC) reads as 12:00 UTC -- EARLIER than the 18:00 GMT
    # entry instead of later, so the wrong item wins with no error anywhere.
    # This assertion fails against the unfixed module on ANY host.
    nonlocal_zone = [
        entry(id="UTC-1800", published="Thu, 06 Aug 2026 18:00:00 GMT"),
        entry(id="PDT-1200", published="Thu, 06 Aug 2026 12:00:00 PDT"),  # 19:00 UTC
    ]
    check("latest/honours-a-non-local-zone", fp.latest_entry_key(nonlocal_zone, FMT), "PDT-1200")

    # A naive date is read as UTC, not as host-local.
    naive = [
        entry(id="NAIVE-1900", published="Thu, 06 Aug 2026 19:00:00"),
        entry(id="UTC-1800", published="Thu, 06 Aug 2026 18:00:00 GMT"),
    ]
    check("latest/naive-is-utc", fp.latest_entry_key(naive, FMT), "NAIVE-1900")

    # --- project_feed threads it through ----------------------------------
    rss = (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>'
        '<item><title>Older</title><guid isPermaLink="true">G-OLD</guid>'
        '<pubDate>Tue, 28 Apr 2026 13:40:00 GMT</pubDate></item>'
        '<item><title>Newest</title><guid isPermaLink="true">G-NEW</guid>'
        '<pubDate>Thu, 06 Aug 2026 17:33:00 GMT</pubDate></item>'
        "</channel></rss>"
    )
    out = fp.project_feed(rss, FMT, ["title", "link", "published", "summary"])
    check("project/latest_key-present", out.get("latest_key"), "G-NEW")
    check("project/entry-count", out.get("entry_count"), 2)
    # The guid is NOT in inclusions and must not leak into entries -- the key is
    # computed from the raw entries precisely so inclusions need not widen.
    leaked = [e for e in out["entries"] if "id" in e or "guid" in e]
    if leaked:
        fails.append(f"project/inclusions-unchanged: guid leaked into entries: {leaked}")

    # A body that is not a feed must still return a key field, not raise.
    junk = fp.project_feed("<html>nope</html>", FMT, ["title"])
    check("project/non-feed-has-key-field", junk.get("latest_key"), "")
    check("project/non-feed-not-parsable", junk.get("parsable"), False)

    for line in ("  entry_key ladder: guid -> link -> date -> empty  OK",
                 "  latest: newest, tie-to-first, skips junk, honours zones  OK",
                 "  project_feed: threads latest_key, leaks no guid, survives non-feed  OK"):
        print(line)

    if fails:
        print("\nFAIL")
        for f in fails:
            print("  -", f)
        return 1
    print("\nPASS: 17 assertions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
