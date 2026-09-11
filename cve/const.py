"""Constants and the asset->CPE map for nvd_estate.

THE ASSET TABLE BELOW IS THE ONE PINNED THING IN THIS INTEGRATION AND IT IS
THE WEAK LINK. Everything else here is discovered: versions come from the
device registry at runtime, affected ranges come from NVD at runtime, and the
comparison is a pure function in cpe.py. But NVD identifies products by CPE
name and Home Assistant identifies them by manufacturer/model strings, and
nothing structural connects the two. Somebody has to write "UDMPRO means
cpe:2.3:o:ui:unifi_dream_machine_firmware" down, and that somebody is this file.

This is the same shape as net_tiers.jinja's EXPECTED map, and it fails the same
way: a vendor renaming a model, or NVD renaming a CPE product, breaks the join
SILENTLY and the affected device simply stops being checked. That is why
UNMAPPED DEVICES ARE COUNTED AND REPORTED rather than skipped -- see
`sensor.nvd_estate_coverage`. A scan that keys on one pattern is not an audit
-- a scan keyed on one pattern is not an audit -- so this one states what it
misses.

ADDING A DEVICE CLASS: add a rule, then verify the CPE product actually exists
in NVD before trusting it. A typo'd CPE product matches nothing and reads
exactly like "no vulnerabilities", which is the false-clean this integration
exists to prevent. `tools/nvd_probe.py --cpe <product>` is the check.
"""

from __future__ import annotations

# MERGE NOTE: was DOMAIN under the standalone nvd_estate integration.
# Kept as text for unique_id prefixes and device-registry identifiers; see
# cve/entities.py. cyber_estate's top-level const.py now owns DOMAIN.
CVE_NS = "nvd_estate"

CONF_API_KEY = "api_key"

# NVD 2.0. The key is optional to the API but not to us in practice: 5 requests
# per 30s unauthenticated versus 50 authenticated, and this integration makes
# one request per tracked CPE product.
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# NVD asks for <= 120 days per query and the network cares about the actionable
# recent set. 90 days was inherited from the retired kev_estate.py so
# the two agreed while both existed; it is now this integration's own number.
WINDOW_DAYS = 90

# Polling. NVD data changes slowly and the network's versions change slowly;
# there is nothing here worth a tight loop, and the rate limit is real.
UPDATE_INTERVAL_HOURS = 6
REQUEST_TIMEOUT = 45

# Politeness delay between NVD calls, seconds. With a key the documented limit
# is 50 requests per rolling 30s; 0.7s between calls keeps us far under it even
# if the product list grows, and the whole refresh still finishes in seconds.
NVD_REQUEST_SPACING = 0.7

# ---------------------------------------------------------------------------
# ASSET RULES
#
# Each rule matches devices in the registry and yields one or more (cpe_vendor,
# cpe_product, version) triples. `match` keys are lowercased substring tests
# against the device's manufacturer and model. `extract` is an optional regex
# whose first group is the version; without it the whole sw_version is used.
#
# A device may yield SEVERAL products -- a kiosk Pi is both a Linux kernel and
# a Chromium install, and kiosk_pi deliberately packs both into one sw_version
# string ("<uname> / Chromium <version>") with a comment saying those two
# together are what KEV entries land on. That is why `extract` exists.
#
# `owner` NAMES THE ONLY INTEGRATION ENTITLED TO SUPPLY THIS RULE'S VERSION,
# and it is a correctness requirement rather than tidiness. The registry holds
# GHOST DEVICES: a device record can split in two, leaving a fragment owned by
# an integration that has no idea what the version string it inherited means.
# Three kiosks carried such a fragment -- owned by `unifi`, frozen at the
# Chromium build they ran on 2026-08-06 -- and it put 425 CVEs / 44 critical on
# the board against a browser installed nowhere. UniFi tracks MACs and traffic;
# it will never correct a Chromium version, so it is not a source of truth
# about one.
#
# DO NOT DISCRIMINATE ON THE SHAPE OF THE RECORD. Empty `identifiers` looks
# like the obvious tell and is NOT: the UDM Pro also carries empty identifiers,
# and filtering on that removes the network edge from the scan -- an asset that
# stops being scanned reads as clean, which is the unsafe direction. Ownership
# is the signal HA maintains and no integration can forge another's domain.
#
# Every owner below was MEASURED against the live registry on 2026-08-14, never
# guessed. A rule with no `owner` key is unconstrained, which is a defect to
# fix rather than a mode to rely on.
# ---------------------------------------------------------------------------

ASSET_RULES = [
    # --- Ubiquiti ----------------------------------------------------------
    # The gateway is the one that matters most: it is the network edge, and
    # the three UniFi OS KEV entries of 2026-06-23 land here. CPE product
    # verified against NVD 2026-08-11 for CVE-2026-34908/34909/34910.
    {
        "id": "unifi_gateway",
        "match": {"manufacturer": "ubiquiti", "model": "udmpro"},
        "owner": "unifi",
        "products": [("ui", "unifi_dream_machine_firmware", None)],
    },
    {
        "id": "unifi_network_application",
        "match": {"manufacturer": "ubiquiti", "model": "unifi network application"},
        "owner": "unifi",
        "products": [("ui", "unifi_network_application", None)],
    },
    # APs and switches share a firmware lineage but not a CPE product with the
    # gateway. Left UNMAPPED deliberately rather than guessed: an AP mapped to
    # the wrong CPE reads as clean forever. They surface in the coverage count.

    # --- Raspberry Pi kiosks ------------------------------------------------
    # Two products out of one sw_version. The kernel string carries a distro
    # suffix ("6.18.39+rpt-rpi-v8") which cpe.parse_version discards.
    {
        "id": "kiosk_pi",
        "match": {"manufacturer": "raspberry pi"},
        # THE RULE THIS OWNERSHIP CHECK EXISTS FOR. Measured 2026-08-14: seven
        # registry devices match "raspberry pi" and carry a version -- four
        # owned by `kiosk_pi` reading Chromium 151, three owned by `unifi`
        # reading Chromium 150. The three are ghosts and the browser they name
        # is installed nowhere.
        "owner": "kiosk_pi",
        "products": [
            ("linux", "linux_kernel", r"^([\d.]+)"),
            ("google", "chrome", r"Chromium\s+([\d.]+)"),
        ],
    },

    # --- Apple --------------------------------------------------------------
    # iPad7,1 is a terminal-iPadOS unit, already risk-accepted.
    # It is NOT accepted-by-ruling the way the Android tablets are, so it is
    # tracked and will report honestly.
    {
        "id": "ipad",
        "match": {"manufacturer": "apple", "model": "ipad"},
        "owner": "mobile_app",
        "products": [("apple", "ipados", None)],
    },
    {
        "id": "iphone",
        "match": {"manufacturer": "apple", "model": "iphone"},
        "owner": "mobile_app",
        "products": [("apple", "iphone_os", None)],
    },
    {
        "id": "appletv",
        "match": {"manufacturer": "apple", "model": "apple tv"},
        "owner": "apple_tv",
        "products": [("apple", "tvos", None)],
    },

    # --- Home Assistant itself ---------------------------------------------
    {
        "id": "ha_core",
        "match": {"manufacturer": "home assistant", "model": "home assistant core"},
        "owner": "hassio",
        "products": [("home-assistant", "home-assistant", None)],
    },

    # --- Printer ------------------------------------------------------------
    # ALL FOUR M477 SKUs are mapped, deliberately. The registry model string is
    # "HP Color LaserJet MFP M477fnw" and carries no SKU, while NVD splits this
    # printer into cf377a / cf378a / cf379a / m5h23a. Guessing one SKU risks
    # matching nothing, and matching nothing is indistinguishable from clean --
    # so this over-includes instead. Over-inclusion surfaces a CVE that may not
    # apply; under-inclusion hides one that does. Only one of those is safe.
    #
    # Its sw_version is a DATE CODE ("20201022"), not a dotted version, so no
    # NVD range comparison against it is meaningful. Expect unknown_version,
    # and that is the honest answer rather than a fabricated clean.
    {
        "id": "hp_laserjet_m477",
        "match": {"manufacturer": "hewlett-packard", "model": "m477"},
        "owner": "ipp",
        "products": [
            ("hp", "color_laserjet_pro_mfp_m477_cf377a_firmware", None),
            ("hp", "color_laserjet_pro_mfp_m477_cf378a_firmware", None),
            ("hp", "color_laserjet_pro_mfp_m477_cf379a_firmware", None),
            ("hp", "color_laserjet_pro_mfp_m477_m5h23a_firmware", None),
        ],
    },

    # --- Hue bridge ---------------------------------------------------------
    # The bridge is the only Hue device with a network attack surface worth
    # tracking; the bulbs are Zigbee endpoints behind it.
    #
    # THE CPE VENDOR IS `philips`, NOT `signify`. The registry says "Signify
    # Netherlands B.V." because that is who makes it today, and the obvious
    # guess `signify:hue_bridge_firmware` returns totalResults=0 from NVD --
    # which would have read as "the Hue bridge has no vulnerabilities" forever.
    # Verified 2026-08-11 against the NVD CPE dictionary. BSB002 is the v2
    # bridge, which is what a 1.78.x firmware string is.
    {
        "id": "hue_bridge",
        "match": {"manufacturer": "signify", "model": "hue bridge"},
        "owner": "hue",
        "products": [("philips", "hue_bridge_bsb002_firmware", None)],
    },
]

# ---------------------------------------------------------------------------
# RISK-ACCEPTED
#
# A ruling, not a config value. Anything here reports `accepted` and never
# `affected` -- it is deliberately excluded from the actionable count, WITH the
# reason carried on the entity so the acceptance is visible rather than a
# silent omission: a policy that declines a signal must say so.
# ---------------------------------------------------------------------------

ACCEPTED_RULES = [
    {
        "id": "android_tablets",
        "match": {"manufacturer": "lenovo"},
        "owner": "mobile_app",
        "reason": (
            "Android tablet patch status is formally risk-accepted "
            "Risk-accepted. Not a coverage gap and not a defect."
        ),
        # PRODUCTS ARE DECLARED EVEN THOUGH THE DEVICE IS ACCEPTED, so a CVE
        # against Android dispositions as `accepted` rather than `unmonitored`.
        # Those are different facts and must not collapse: `unmonitored` means
        # nothing here carries the product and a rule may be MISSING;
        # `accepted` means we know exactly what carries it and decided. Without
        # this, a real coverage hole and a deliberate decision read identically.
        #
        # The version is not compared and does not need to be right -- the
        # disposition is fixed by the ruling before any comparison happens.
        # sw_version on these is the MDM build ("1.60.1-emm"), not the Android
        # version, and the rule says not to raise Android OS version at
        # all unless asked directly.
        "products": [("google", "android", None)],
    },
]

# Vendor keywords used to decide whether a KEV entry is even worth joining.
# THIS IS NOW THE ONLY COPY. It was deliberately identical to kev_estate.py's
# ESTATE list, because two lists meaning the same thing drift; that script was
# retired with its sensor on 2026-08-14 and this list inherited the
# job. Microsoft stays excluded -- nothing here runs Windows.
KEV_VENDOR_KEYWORDS = [
    "ubiquiti",
    "apple",
    "google",
    "linux",
    "hewlett packard (hp)",
    "home assistant",
    "debian",
    "raspberry",
    "chromium",
    "android",
]
