"""Pure feed projection for estate_feeds.

THIS MODULE IMPORTS NOTHING FROM `homeassistant`, DELIBERATELY, and the parse
gate asserts it (Playbook 16.1). It takes bytes in and returns dicts out, so
it can be exercised on a plain python3 with no live state and no restart.

It also OWNS NO NETWORK. The caller fetches; this only projects. That split is
what makes the timeout enforceable -- a parser that fetches has to be trusted
to bound itself, and the old component was not.
"""

from __future__ import annotations

import io
from datetime import timedelta, timezone
from typing import Any

import feedparser
from dateutil import parser as _date_parser
from dateutil import tz as _tz

# ZONE ABBREVIATIONS, RESOLVED EXPLICITLY. dateutil resolves a bare abbreviation
# ONLY when it matches the running process's own local zone -- it compares
# against time.tzname -- and returns a NAIVE datetime plus an
# UnknownTimezoneWarning for anything else. latest_entry_key defaults a naive
# value to UTC, deliberately, for feeds that publish no zone at all. Those two
# behaviours combine into a silent bug: a feed publishing "15:00:00 EDT" on a
# host that is not in an EDT zone decodes naive and is then read as 15:00 UTC,
# four hours off, and ordering picks the wrong entry with no error anywhere.
# Measured on a UTC runner, where it made the suite's own zone assertion report
# the zone-blind answer.
#
# Resolving them here makes the parse independent of what host it runs on, which
# is the point -- the network's host is America/New_York today and CI is not.
# dateutil also warns that the naive-fallback path will RAISE in a future
# release, so this stops being merely wrong and starts being fatal.
_TZINFOS = {
    "UT": 0, "UTC": 0, "GMT": 0, "Z": 0,
    "EST": -5 * 3600, "EDT": -4 * 3600,
    "CST": -6 * 3600, "CDT": -5 * 3600,
    "MST": -7 * 3600, "MDT": -6 * 3600,
    "PST": -8 * 3600, "PDT": -7 * 3600,
    "AKST": -9 * 3600, "AKDT": -8 * 3600,
    "HST": -10 * 3600,
}

# The zero-offset names dateutil resolves BY ITSELF, rendering "%Z" as "UTC".
# format_date's tzinfos callable has to hand these back rather than decline
# them, or their stored identity would change. "UT" is not among them --
# dateutil leaves that one naive too, measured, not assumed.
_NATIVE_UTC_NAMES = frozenset({"UTC", "GMT", "Z"})

# Keys carrying a date that the old component reformatted before storing.
DATE_KEYS = ("published", "updated", "created", "expired")

# The old component skipped any key containing this substring -- feedparser
# emits `published_parsed` / `updated_parsed` struct_time objects that are not
# JSON-serialisable into a state attribute.
SKIP_SUBSTRING = "parsed"


def _decline_abbreviations(tzname: str, offset: int | None):
    """tzinfos callable that answers for EVERY zone name, resolving none of them.

    dateutil consults `tzinfos` only for zones it has not already resolved, and
    a callable that answers is never followed by the guess-or-warn path. So:

      * a numeric offset dateutil already parsed passes straight through;
      * the three zero-offset names it resolves natively return `tzutc()`, which
        is what it produces for them today (`%Z` -> "UTC");
      * every other abbreviation returns None, i.e. NAIVE -- which is also
        exactly what it produces today, but reached deliberately instead of by
        falling off a deprecated path.

    "UT" is deliberately not in the native set: dateutil does not resolve it
    either, so declining it is what reproduces today's output.
    """
    if offset is not None:
        return offset
    if tzname in _NATIVE_UTC_NAMES:
        return _tz.tzutc()
    return None


def format_date(value: str, date_format: str) -> str:
    """Reproduce the old component's date handling EXACTLY.

    dateutil.parser.parse() then strftime(date_format). Not
    email.utils.parsedate_to_datetime, and not feedparser's own
    `published_parsed` struct_time: both normalise the timezone, and %Z on a
    normalised value emits a different string than the consuming templates'
    strptime expects.

    DELIBERATELY NOT GIVEN `_TZINFOS`, unlike latest_entry_key's ordering
    parse. What this returns becomes part of entry_key when a feed has neither
    guid nor link, and entry_key is a STORED IDENTITY that acks are matched
    against. Resolving an abbreviation here would change %Z's output for those
    feeds and silently orphan every existing ack. The ordering bug that
    _TZINFOS fixes does not exist on this path: a wrong-but-stable string still
    matches itself. Changing it is an ack migration, not a bug fix.

    THAT RULING STANDS, AND THIS IS NOT A REVERSAL OF IT. What changed
    is only HOW the naive result is reached. The old form let dateutil fail to
    understand the abbreviation, which emits UnknownTimezoneWarning and which
    dateutil says a future release will turn into an EXCEPTION -- so the stored
    identity was resting on deprecated behaviour, and the module would have
    started raising on a dependency bump for exactly the feeds it currently
    handles quietly. Declining every abbreviation explicitly produces the same
    datetime by a supported route.

    Measured over 17 date shapes -- named zones in and out of `_TZINFOS`,
    numeric offsets, ISO-8601, and no zone at all -- the output is
    byte-identical to the old form today, emits no warning, and stays identical
    with UnknownTimezoneWarning promoted to an error. No ack migration.
    """
    parsed = _date_parser.parse(value, tzinfos=_decline_abbreviations)
    # dateutil labels a tz returned from tzinfos with the name it read, so
    # "GMT" would render "%Z" as "GMT" where it renders "UTC" today. Every
    # zero-offset zone normalises to tzutc() to keep that string stable.
    if parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0):
        parsed = parsed.replace(tzinfo=_tz.tzutc())
    return parsed.strftime(date_format)


def entry_key(entry: Any, date_format: str) -> str:
    """The stable identity of ONE entry, best available first.

    `id` is feedparser's mapping of RSS <guid> / Atom <id> -- the feed's own
    permalink for that item. CDC publishes it with isPermaLink="true" and it
    carries a stable content id, so it survives the item moving down the feed.
    `link` is the fallback for a feed that omits a guid.

    The formatted date is the LAST RESORT rather than an empty string: it is
    what the consuming template keyed on by itself before this existed, so a
    feed with neither id nor link stays ackable rather than silently losing
    the capability. Empty only when there is nothing at all to key on -- and
    an empty key must never match anything downstream.
    """
    if not hasattr(entry, "get"):
        return ""
    for attr in ("id", "link"):
        value = entry.get(attr)
        if value:
            return str(value)
    raw = entry.get("published")
    if raw:
        try:
            return format_date(raw, date_format)
        except Exception:  # noqa: BLE001
            return ""
    return ""


def latest_entry_key(raw_entries: list, date_format: str) -> str:
    """Identity of the NEWEST entry by published date, or "" if none has one.

    WHY IT IS COMPUTED HERE. The consumer used to do this in Jinja with
    strptime, and strptime returns a NAIVE datetime -- piping that through
    as_timestamp assumes the HA host's local zone, a fixed several-hour skew
    the consuming package documented and accepted. Here the date goes through
    the same dateutil parser format_date already uses, so the zone in the feed
    is honoured, and a naive value is read as UTC rather than as host-local
    because these are RFC-822 feeds.

    STRICTLY GREATER, so on equal timestamps the FIRST in feed order wins.
    That reproduces the consuming template's tie-break exactly; a card keying
    on this and a template rendering a headline must never name different
    items. Feed order is preserved by project_feed, so "first" is stable.

    An unparseable or absent date SKIPS the entry rather than sorting it to
    one end -- the same treatment project_entry gives, and it is counted there
    as unparsed_dates.
    """
    newest = None
    key = ""
    for entry in raw_entries:
        if not hasattr(entry, "get"):
            continue
        raw = entry.get("published")
        if not raw:
            continue
        try:
            when = _date_parser.parse(raw, tzinfos=_TZINFOS)
        except Exception:  # noqa: BLE001
            continue
        if when.tzinfo is None:
            # Genuinely zone-less now, rather than "carried a zone this process
            # did not recognise" -- which is what made this default a bug.
            when = when.replace(tzinfo=timezone.utc)
        if newest is None or when > newest:
            newest = when
            key = entry_key(entry, date_format)
    return key


def project_entry(
    entry: Any, date_format: str, inclusions: list[str]
) -> tuple[dict, bool]:
    """Project one feedparser entry to the stored dict shape.

    Returns (entry_dict, date_ok). A date that will not parse drops ONLY the
    date key and reports date_ok False -- the entry is kept and counted. The
    old component raised here, which took the whole update down and left the
    entity on its previous value with nothing saying why.
    """
    out: dict = {}
    date_ok = True
    for key, value in entry.items():
        if inclusions and key not in inclusions:
            continue
        if SKIP_SUBSTRING in key:
            continue
        if key in DATE_KEYS:
            try:
                value = format_date(value, date_format)
            except Exception:
                date_ok = False
                continue
        out[key] = value
    return out, date_ok


def project_feed(
    raw: bytes | str, date_format: str, inclusions: list[str]
) -> dict:
    """Parse an already-fetched body and project its entries.

    FEED ORDER IS PRESERVED -- do not sort here.

    CORRECTED 2026-08-08: the original justification for this was that
    `sensor.cdc_top_outbreak` read `entries[0]` as the top notice. THAT
    JUSTIFICATION IS VOID -- both that sensor and its CDC Travel Notices
    source were deleted the same day as a two-link dead chain. Neither
    surviving consumer is order-dependent: both iterate the whole list and
    select by parsed date. Order is preserved anyway, because reproducing the
    source document's order is the correct default and a future consumer may
    depend on it -- but it is no longer load-bearing, and this comment says so
    rather than leaving a stale reason to be trusted.

    Returns a dict carrying `entries`, `bozo`, `unparsed_dates` and `parsable`.
    It does NOT decide the disposition -- the caller owns that, because only
    the caller knows the HTTP status, and a 200 with an empty feed is a
    different fact from a 404 with an empty body (Playbook 16.15).
    """
    # WRAPPED, NOT PASSED RAW, AND THIS IS A BLOCKING-CALL FIX.
    # feedparser.parse() decides what it was handed by trying things in order,
    # and `open()` on the argument comes before "treat it as content". Handed
    # bytes, it therefore calls open() on the ENTIRE FEED DOCUMENT as though
    # it were a path -- a filesystem call, inside the event loop, on every
    # feed of every poll. HA's loop-blocking detector caught it in
    # system_log; nothing else would have, because the call fails harmlessly
    # and the parse then succeeds anyway.
    #
    # A file-like object skips that branch entirely: feedparser's own
    # _open_resource() starts with `if hasattr(x, 'read'): return x.read()`,
    # ahead of the open() attempt. Measured with builtins.open patched, the
    # bare form makes one open() call and the wrapped form makes none, for
    # identical parsed entries.
    #
    # BOTH INPUT TYPES ARE WRAPPED, AND str IS NOT OPTIONAL. The live feeds
    # hand this bytes, which is the only shape the first version of this fix
    # covered -- and io.BytesIO(str) raises TypeError, so a str caller went
    # from working to crashing. tests/test_estate_feeds_key.py
    # passes a str and caught it. A str also blocks: it takes the same open()
    # path, so leaving it unwrapped would have fixed half the defect.
    #
    # utf-8 IS FEEDPARSER'S OWN CHOICE, NOT A GUESS MADE HERE.
    # _open_resource() ends `if not isinstance(x, bytes): return
    # x.encode('utf-8')`, so encoding a str exactly reproduces the bytes it
    # would have built for itself. Anything else would risk handing the parser
    # a different byte sequence than it used to see.
    #
    # This does NOT touch the standing ruling. feedparser stays exactly what that
    # ruling made it -- an offline parser over content cyber_estate fetched
    # itself -- and no network path is added or restored here. Only the shape
    # of the argument changes.
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    parsed = feedparser.parse(io.BytesIO(data))
    raw_entries = list(getattr(parsed, "entries", []) or [])

    entries: list[dict] = []
    unparsed_dates = 0
    for entry in raw_entries:
        projected, date_ok = project_entry(entry, date_format, inclusions)
        if not date_ok:
            unparsed_dates += 1
        entries.append(projected)

    bozo = 1 if getattr(parsed, "bozo", 0) else 0
    version = getattr(parsed, "version", "") or ""

    # `parsable` means "this body was recognisably a feed". An empty entry
    # list with a real feed version is a QUIET FEED and is legitimate; an
    # empty entry list with no version and bozo set is a body that is not a
    # feed at all. Collapsing those two is the silent-zero defect.
    parsable = bool(version) or bool(entries)

    return {
        "entries": entries,
        "entry_count": len(entries),
        # Computed from the RAW entries, before the inclusions allowlist runs.
        # That is deliberate: `id` is not in any feed's inclusions and does not
        # need to be, so this adds a capability without widening what every
        # consumer sees. Widening inclusions was the alternative and is strictly
        # more surface for the same result.
        "latest_key": latest_entry_key(raw_entries, date_format),
        "bozo": bozo,
        "unparsed_dates": unparsed_dates,
        "version": version,
        "parsable": parsable,
    }
