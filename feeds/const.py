"""Constants and the feed registry for estate_feeds.

REPLACES the HACS component custom-components/sensor.feedparser, which was
killed 2026-08-08 (KAN-215). Three defects, none of them fixable in place
because the component is HACS-managed and an update reverts any edit:

  1. `update()` was SYNCHRONOUS and called `feedparser.parse(<url>)`, so the
     library did its own urllib fetch with NO timeout parameter available.
     The only bound was the process-wide socket default, which is unmeasured.
  2. `async_add_devices([...], True)` -- update_before_add=True -- put every
     one of those unbounded fetches on the STARTUP CRITICAL PATH. That is the
     `Timed out adding entities for domain sensor with platform feedparser
     after 500s` condition. 500s is a hard floor in HA core.
  3. A 404 through feedparser is a CLEAN ZERO, not an error (Playbook 16.15).
     Four dead NC feeds rendered a confident all-clear for an unknown period.
     PROVEN on the bench 2026-08-08: a dead cisa.gov path answers 404 with a
     47,347-byte HTML body, which feedparser reduces to entries == [].

The feedparser LIBRARY is retained, but only as a pure parser: it is handed
BYTES that this integration fetched itself, never a URL. It never touches the
network from inside this component.

TWO OF THE FOUR SURVIVING FEEDS WERE DELETED RATHER THAN MIGRATED, for
different reasons, both established by tree-wide sweeps with asserted
completeness (4,024 and 4,033 files listed, 0 zero-reads):

  - GDACS Alerts       `sensor.gdacs_alerts` had ZERO consumers. It had been
                       fetching hourly for nobody.
  - CDC Travel Notices a TWO-LINK DEAD CHAIN. Its only consumer was the
                       template sensor `sensor.cdc_top_outbreak`, and THAT
                       had zero consumers of its own. It was live and
                       non-zero at deletion -- "Level 2 - Zika in Indonesia",
                       severity 4 -- which is the point: a working sensor
                       publishing a real severity that nothing read.
                       `CDC Top Outbreak` was deleted from
                       packages/global_threats.yaml in the same pass. Keeping
                       the feed and dropping the consumer, or the reverse,
                       would have left a permanently-pinned sensor -- the
                       silent-constant defect of Current State 38.4.

Do not re-add either without a reader.
"""

from __future__ import annotations

# KAN-344 MERGE: was DOMAIN under the standalone estate_feeds integration.
# Renamed because this subpackage no longer owns a manifest/config entry of
# its own -- cyber_estate's top-level const.py now owns DOMAIN. Kept as
# text for unique_id prefixes and device-registry identifiers, where the
# old naming stays readable and stable across the migration; see
# feeds/entities.py.
FEEDS_NS = "estate_feeds"

# ONE cadence for every feed. Ruled 2026-08-08. The old per-feed 1h/6h split
# carried no rationale that survived the rewrite.
SCAN_INTERVAL_SECONDS = 3600

# THE WHOLE POINT. Every fetch is bounded in wall clock. Do not remove this
# and do not make it None -- an unbounded fetch is defect 1 above, restored.
FETCH_TIMEOUT = 15

# Dispositions. Playbook 16.3: `ok at zero` and `could not read` must be
# different values AT THE SOURCE. Only `ok` is healthy; every other value
# means the count is None rather than 0.
DISP_OK = "ok"
DISP_UNREACHABLE = "unreachable"      # transport: timeout, DNS, connection refused
DISP_HTTP_ERROR = "http_error"        # answered, but not 2xx -- the 404 case
DISP_UNPARSED = "unparsed"            # answered 2xx, body is not a feed

HEALTHY_DISPOSITIONS = (DISP_OK,)

# ---------------------------------------------------------------------------
# THE FEED REGISTRY IS ONE LIST. Adding a feed is one row.
#
# `name` IS LOAD-BEARING: entity_id is slugified from it, and these two
# entity_ids are the contract three downstream template blocks read. Renaming
# a row silently orphans its consumers.
#
# `date_format` IS ALSO LOAD-BEARING and is NOT cosmetic. The old component
# applied strftime(date_format) to published/updated/created/expired INSIDE
# its update(), so `entries[].published` is a PRE-FORMATTED STRING, and every
# consumer parses it back with a matching strptime format:
#
#   sensor.cdc_domestic_alerts  -> strptime(..., '%a, %d %b %Y %H:%M:%S %Z')
#   sensor.cisa_advisories      -> strptime(..., '%a, %d %b %Y %H:%M:%S')
#
# Change a date_format here and the consuming template stops parsing dates,
# which reads downstream as "no recent items" -- a silent all-clear.
#
# `inclusions` is also contract: the old component dropped every key not in
# this list, plus any key containing "parsed". Widening it is safe; narrowing
# it removes a key a consumer may read.
# ---------------------------------------------------------------------------
FEEDS = [
    {
        "key": "cdc_domestic_alerts",
        "name": "CDC Domestic Alerts",
        "url": "https://tools.cdc.gov/api/v2/resources/media/285676.rss",
        "date_format": "%a, %d %b %Y %H:%M:%S %Z",
        "inclusions": ["title", "link", "published", "summary"],
        # Consumer: sensor.cdc_domestic_24h (packages/global_threats.yaml).
        # Uses e.get('published') / e.get('title') -- entries MUST be real
        # dicts, not objects, or .get() fails.
    },
    {
        "key": "cisa_advisories",
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "date_format": "%a, %d %b %Y %H:%M:%S",
        "inclusions": ["title", "link", "published"],
        # TWO consumers, not one: sensor.cisa_new_24h (packages/misc.yaml,
        # friendly name "CISA New 7d") AND sensor.cisa_estate_7d
        # (packages/kev_estate.yaml). The second only surfaced in the
        # tree-wide sweep -- it is not in Current State 7.2's package list.
    },
]

FEED_KEYS = [f["key"] for f in FEEDS]
