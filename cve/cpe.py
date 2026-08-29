"""Version comparison and CVE disposition. PURE — imports nothing from HA.

This module decides whether an installed version is inside an NVD affected
range. Its failure mode is "tells you that you are patched when you are not",
which is the same class as household_state's resolver telling someone the wrong
thing under stress — so it follows the same rule LAW section 11 sets for that
resolver: it imports nothing from homeassistant, it is a set of pure functions,
and it can be tested without a running Home Assistant.

Run the self-test with:  python3 cpe.py

THE CENTRAL RULE, AND IT IS ASYMMETRIC. `patched` is a claim that licenses
inaction, so it gets the stricter standard (LAW section 1). Every path that
cannot establish a confident answer returns UNKNOWN_VERSION, never PATCHED.
A version we cannot parse, a range we cannot parse, an asset with no version
read — all of those are UNKNOWN_VERSION. Only an installed version that
successfully parsed AND fell outside every successfully-parsed affected range
returns PATCHED.

WHY NOT packaging.version. It is not in the HA container's dependency set that
we can rely on, and its PEP 440 semantics are wrong for firmware anyway:
"5.1.27.33981" and "151.0.7922.108" and "6.18.39+rpt-rpi-v8" are not Python
versions. A dotted-numeric comparator with explicit unknown handling is both
smaller and more honest about what it cannot do.
"""

from __future__ import annotations

import re

# Dispositions. These are DISTINCT VALUES AT THE SOURCE, per LAW section 11 --
# "ok at zero and could not read must be different values". A consumer must be
# able to render "we could not read this" without inventing a severity, and
# must never be able to collapse it into "not affected".
AFFECTED = "affected"
PATCHED = "patched"
UNKNOWN_VERSION = "unknown_version"
UNMONITORED = "unmonitored"
ACCEPTED = "accepted"

# Ordering for rollup: worst first. UNKNOWN_VERSION outranks PATCHED
# deliberately -- not knowing is worse than knowing you are fine.
SEVERITY_ORDER = [AFFECTED, UNKNOWN_VERSION, UNMONITORED, ACCEPTED, PATCHED]

# A version we are willing to compare. Leading digits, dot-separated, with an
# optional trailing non-numeric tail we discard ("+rpt-rpi-v8", "-generic").
# Anchored at the start: a string that does not BEGIN with a number is not a
# version we understand, and guessing is how you get a false `patched`.
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def parse_version(raw):
    """'6.18.39+rpt-rpi-v8' -> (6, 18, 39).  Unparseable -> None.

    None is the honest answer for 'unknown', 'unavailable', '', a marketing
    string, or anything not starting with a digit. Callers MUST treat None as
    UNKNOWN_VERSION and never as 'not in range'.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Firmware strings in this estate arrive as "5.1.27.33981" from the UniFi
    # device registry and "6.18.39+rpt-rpi-v8" from uname. kiosk_pi also packs
    # two versions into one sw_version field ("<uname> / Chromium <v>"), which
    # is why the caller splits before it gets here rather than this guessing.
    m = _VERSION_RE.match(s)
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:  # pragma: no cover - regex already constrains this
        return None


def _cmp(a, b):
    """Compare two version tuples, zero-padding the shorter.

    Padding with zero is what makes 5.1 == 5.1.0 and 5.1.27 > 5.1.12. It is
    also why this is not a plain tuple comparison: (5, 1) < (5, 1, 0) is False
    in Python but (5,1) vs (5,1,0) must compare EQUAL for version purposes.
    """
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version, node):
    """Is `version` inside this one cpeMatch range?

    Returns True / False / None, and None means CANNOT DECIDE. A node with no
    version bounds at all is the NVD way of saying "all versions of this
    product" -- that is a real True, not an unknown.

    NVD supplies up to four bounds and any combination may be absent:
        versionStartIncluding  >=      versionStartExcluding  >
        versionEndIncluding    <=      versionEndExcluding    <
    """
    if version is None:
        return None

    bounds = (
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    )

    saw_bound = False
    for key, ok in bounds:
        raw = node.get(key)
        if raw in (None, "", "-", "*"):
            continue
        bound = parse_version(raw)
        if bound is None:
            # A bound we cannot parse makes this node undecidable. Returning
            # False here would silently read as "not affected" -- the exact
            # false-negative this module exists to prevent.
            return None
        saw_bound = True
        if not ok(_cmp(version, bound)):
            return False

    if not saw_bound:
        # No bounds -> every version of this product is affected. NVD also
        # expresses a specific single version in the CPE string itself
        # (cpe:2.3:o:google:android:14.0:...), which the caller handles.
        return True

    return True


def disposition(version, nodes):
    """Disposition an installed version against a CVE's cpeMatch nodes.

    `nodes` are ONLY the nodes whose CPE product matched an asset we own --
    filtering by product is the caller's job, because that is estate knowledge
    and this module holds none.

    AFFECTED wins over everything: one node placing us in range is enough.
    UNKNOWN_VERSION beats PATCHED, so a CVE with one undecidable node and one
    clean node reports undecidable rather than clean.
    """
    if not nodes:
        return UNMONITORED
    if version is None:
        return UNKNOWN_VERSION

    saw_unknown = False
    for node in nodes:
        r = in_range(version, node)
        if r is True:
            return AFFECTED
        if r is None:
            saw_unknown = True
    return UNKNOWN_VERSION if saw_unknown else PATCHED


def severity_of(cve_obj):
    """Highest-confidence CVSS severity and score for a CVE. PURE.

    Prefers v3.1, then v3.0, then v2 -- the order the old
    network-security-card used, kept so a tile does not silently change
    meaning when this replaces those sensors.

    Returns (severity, score). ('UNRATED', None) when NVD carries no metric at
    all, which is a real state for a freshly-published CVE and must NOT be
    rendered as NONE -- "not scored yet" and "scored as harmless" are different
    facts, and only one of them is safe to ignore.
    """
    metrics = (cve_obj or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData") or {}
            sev = data.get("baseSeverity")
            if sev:
                return sev.upper(), data.get("baseScore")
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        data = arr[0].get("cvssData") or {}
        # v2 puts baseSeverity on the wrapper, not inside cvssData.
        sev = arr[0].get("baseSeverity") or data.get("baseSeverity")
        if sev:
            return sev.upper(), data.get("baseScore")
    return "UNRATED", None


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
            "UNRATED": 0, "NONE": 0}


def _rule_matches(rule_match, manufacturer, model):
    """Substring test on lowercased manufacturer and model."""
    want_mfr = rule_match.get("manufacturer")
    want_model = rule_match.get("model")
    if want_mfr and want_mfr not in manufacturer:
        return False
    if want_model and want_model not in model:
        return False
    return True


def _owner_ok(rule, owner_domain):
    """Is this integration entitled to supply this rule's version?

    A rule with no `owner` is unconstrained. An UNKNOWN owner (None) is also
    unconstrained, deliberately: the failure mode of guessing wrong here is a
    real asset silently leaving the scan, and an asset that stops being scanned
    reads as clean. Unconstrained over-includes, which is the safe direction.
    """
    want = rule.get("owner")
    if not want or owner_domain is None:
        return True
    return owner_domain == want


def classify_device(manufacturer, model, sw_version,
                    asset_rules, accepted_rules, owner_domain=None):
    """One device -> a (kind, payload) pair.

        ('accepted', {"reason": str, "products": [...]})
        ('mapped',   [(vendor, product, version_raw, version_tuple), ...])
        ('unmapped', reason_or_None)

    PURE, and here rather than in the coordinator for one reason: the offline
    harness that proves this join works must exercise THE SAME CODE the
    integration runs. A harness holding its own copy of the matching logic
    validates the copy, drifts from the original, and then reports green about
    code nobody runs.

    `products` is a list of (vendor, product, version_raw, version_tuple).
    ACCEPTED is checked first -- a risk-acceptance ruling outranks a CPE map.

    `owner_domain` IS THE DEVICE'S OWNING CONFIG-ENTRY DOMAIN, and matching it
    against the rule's `owner` is what keeps a GHOST device out of the asset
    list. The registry can split one machine into two records, leaving a
    fragment owned by an integration that inherited a version string it does
    not understand and will never update -- `unifi` holding a frozen Chromium
    build for a Raspberry Pi, for instance. Ownership is a signal Home
    Assistant maintains and no integration can forge another's domain, which is
    what LAW section 10 asks to discriminate on. Matching on the SHAPE of the
    record instead (empty `identifiers`) is wrong and dangerous: the UDM Pro
    has empty identifiers too.

    A rejected device returns `unmapped` WITH A REASON rather than vanishing.
    A scan that silently shrinks its own denominator is not an audit (LAW 5).
    """
    mfr = (manufacturer or "").strip().lower()
    mdl = (model or "").strip().lower()
    rejected = []

    for rule in accepted_rules or []:
        if _rule_matches(rule["match"], mfr, mdl):
            if not _owner_ok(rule, owner_domain):
                rejected.append((rule.get("id", "?"), rule.get("owner")))
                continue
            # An accepted rule MAY declare products. When it does, the caller
            # can still match a CVE to this device and disposition it ACCEPTED
            # rather than UNMONITORED -- "we decided" and "nothing here carries
            # this" are different facts (LAW section 11).
            products = []
            for vendor, product, extract in rule.get("products") or []:
                raw = str(sw_version)
                if extract:
                    m = re.search(extract, raw)
                    raw = m.group(1) if m else None
                products.append((vendor, product, raw, parse_version(raw)))
            return "accepted", {"reason": rule["reason"], "products": products}

    for rule in asset_rules or []:
        if not _rule_matches(rule["match"], mfr, mdl):
            continue
        if not _owner_ok(rule, owner_domain):
            rejected.append((rule.get("id", "?"), rule.get("owner")))
            continue
        products = []
        for vendor, product, extract in rule["products"]:
            raw = str(sw_version)
            if extract:
                m = re.search(extract, raw)
                # A rule asking for an extraction that does not match yields NO
                # version, never the whole string. Passing
                # "6.18.39+rpt-rpi-v8 / Chromium 151.0.7922.108" in as a
                # Chromium version would compare the KERNEL against Chrome's
                # ranges and call the result authoritative.
                raw = m.group(1) if m else None
            products.append((vendor, product, raw, parse_version(raw)))
        return "mapped", products

    if rejected:
        rule_id, want = rejected[0]
        return "unmapped", (
            f"matched rule {rule_id} but is owned by {owner_domain}, not "
            f"{want} -- version not authoritative (ghost registry entry)")
    return "unmapped", None


def nodes_for(cve_obj, vendor, product):
    """cpeMatch nodes from this CVE whose CPE names this vendor/product.

    PURE, and here rather than in the coordinator so it can be tested without
    Home Assistant installed -- it only walks a dict NVD handed us.

    `vulnerable: false` NODES ARE SKIPPED, AND THIS IS THE WHOLE BALLGAME.
    NVD expresses "product X running ON platform Y" as an operator=AND config
    with two nodes: the vulnerable product (vulnerable=true) and the platforms
    it runs on (vulnerable=false). CVE-2026-11645 is a Chromium V8 flaw and its
    configuration reads:

        config operator=AND
          node[0] vulnerable=True   google:chrome        < 149.0.7827.103
          node[1] vulnerable=False  apple:macos          (no bounds)
                  vulnerable=False  linux:linux_kernel   (no bounds)
                  vulnerable=False  microsoft:windows    (no bounds)

    Ignoring the flag made this function return the linux_kernel node, which
    carries no bounds, which in_range() correctly reads as "every version
    affected" -- and the estate's Pi kernels were reported AFFECTED by a Chrome
    bug. Caught by tools/nvd_probe.py --dryrun on 2026-08-11, before deploy.
    `vulnerable` is a structural signal NVD must keep true, which is what
    LAW section 10 says to discriminate on.

    NVD states an affected version in one of two ways and this handles both:
    range bounds on the match object, OR the version baked into the CPE string
    itself (cpe:2.3:o:google:android:14.0:...). The second form is converted to
    an exact-version pseudo-bound, because leaving it as a bare match would
    make in_range() see no bounds and answer "every version is affected" --
    turning a CVE against Android 14 into a CVE against all Android.
    """
    out = []
    for config in cve_obj.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                # Absent `vulnerable` is treated as NOT vulnerable. That is the
                # conservative direction for a false POSITIVE; the false
                # negative it could cause is bounded because NVD sets this flag
                # on every match it publishes.
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                if parts[3] != vendor or parts[4] != product:
                    continue
                exact = parts[5]
                if exact not in ("*", "-", ""):
                    out.append({
                        "versionStartIncluding": exact,
                        "versionEndIncluding": exact,
                    })
                else:
                    out.append(match)
    return out


def rollup(dispositions):
    """Worst disposition in a set. Empty -> PATCHED is WRONG, so: UNMONITORED.

    An empty set means nothing was evaluated, and "nothing was evaluated" must
    not render as "all clear" (LAW section 11 -- an unreadable source can never
    contribute 0).
    """
    if not dispositions:
        return UNMONITORED
    for level in SEVERITY_ORDER:
        if level in dispositions:
            return level
    return UNMONITORED  # pragma: no cover - SEVERITY_ORDER is exhaustive


# ---------------------------------------------------------------------------
# SELF-TEST. LAW section 4: every assertion set needs a self-test proving it
# CAN fail. The negative cases below are that proof -- they assert that this
# module REFUSES to say `patched`, which is the only failure that matters.
# ---------------------------------------------------------------------------

def _self_test():
    fails = []

    def eq(got, want, label):
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    # --- parsing ---
    eq(parse_version("5.1.27.33981"), (5, 1, 27, 33981), "parse udm")
    eq(parse_version("6.18.39+rpt-rpi-v8"), (6, 18, 39), "parse kernel suffix")
    eq(parse_version("151.0.7922.108"), (151, 0, 7922, 108), "parse chromium")
    eq(parse_version("unknown"), None, "parse unknown -> None")
    eq(parse_version("unavailable"), None, "parse unavailable -> None")
    eq(parse_version(""), None, "parse empty -> None")
    eq(parse_version(None), None, "parse None -> None")
    eq(parse_version("v2.1"), None, "parse leading-v -> None (no guessing)")

    # --- padding semantics ---
    eq(_cmp((5, 1), (5, 1, 0)), 0, "5.1 == 5.1.0")
    eq(_cmp((5, 1, 27), (5, 1, 12)), 1, "5.1.27 > 5.1.12")
    eq(_cmp((5, 1, 2), (5, 1, 12)), -1, "5.1.2 < 5.1.12 (not string order)")

    # --- the three real estate cases, from live data 2026-08-11 ---
    udm = parse_version("5.1.27.33981")
    unifi_node = {"versionEndExcluding": "5.1.12"}
    eq(disposition(udm, [unifi_node]), PATCHED, "UDM 5.1.27 vs <5.1.12")

    chrome = parse_version("151.0.7922.108")
    chrome_node = {"versionEndExcluding": "149.0.7827.103"}
    eq(disposition(chrome, [chrome_node]), PATCHED, "Chromium 151 vs <149")

    kern = parse_version("6.18.39+rpt-rpi-v8")
    kernel_nodes = [
        {"versionStartIncluding": "2.6.24", "versionEndExcluding": "4.9.301"},
        {"versionStartIncluding": "5.16", "versionEndExcluding": "5.16.6"},
    ]
    eq(disposition(kern, kernel_nodes), PATCHED, "kernel 6.18.39 vs <5.16.6")

    # --- and the same shapes when we ARE vulnerable (proves it can say so) ---
    eq(disposition(parse_version("5.1.11"), [unifi_node]), AFFECTED,
       "UDM 5.1.11 IS affected")
    eq(disposition(parse_version("5.16.3"), kernel_nodes), AFFECTED,
       "kernel 5.16.3 IS affected")
    eq(disposition(parse_version("2.6.24"), kernel_nodes), AFFECTED,
       "kernel at inclusive start IS affected")
    eq(disposition(parse_version("4.9.301"), kernel_nodes), PATCHED,
       "kernel at exclusive end is NOT affected")

    # --- the refusals: none of these may return PATCHED ---
    eq(disposition(None, [unifi_node]), UNKNOWN_VERSION,
       "no version read -> unknown, NOT patched")
    eq(disposition(parse_version("5.1.27"), [{"versionEndExcluding": "junk"}]),
       UNKNOWN_VERSION, "unparseable bound -> unknown, NOT patched")
    eq(disposition(udm, []), UNMONITORED, "no matching nodes -> unmonitored")
    eq(disposition(udm, [{"versionEndExcluding": "5.1.12"},
                         {"versionEndExcluding": "junk"}]),
       UNKNOWN_VERSION, "one bad node poisons a clean one -> unknown")
    eq(in_range(udm, {}), True, "no bounds at all -> all versions affected")

    # --- rollup ---
    eq(rollup({PATCHED, AFFECTED}), AFFECTED, "affected wins")
    eq(rollup({PATCHED, UNKNOWN_VERSION}), UNKNOWN_VERSION, "unknown beats patched")
    eq(rollup({PATCHED}), PATCHED, "all patched")
    eq(rollup(set()), UNMONITORED, "empty rollup is NOT patched")

    # --- classify_device: the kiosk double-extraction is the sharp case ---
    kiosk_rules = [{
        "id": "kiosk_pi",
        "match": {"manufacturer": "raspberry pi"},
        "products": [("linux", "linux_kernel", r"^([\d.]+)"),
                     ("google", "chrome", r"Chromium\s+([\d.]+)")],
    }]
    accept_rules = [{
        "id": "android", "match": {"manufacturer": "lenovo"}, "reason": "ruling",
    }]

    kind, payload = classify_device(
        "Raspberry Pi", "Raspberry Pi 4 Model B Rev 1.5",
        "6.18.39+rpt-rpi-v8 / Chromium 151.0.7922.108",
        kiosk_rules, accept_rules)
    eq(kind, "mapped", "kiosk classifies as mapped")
    eq(payload[0][:2], ("linux", "linux_kernel"), "kiosk product 1")
    eq(payload[0][3], (6, 18, 39), "kernel version extracted")
    eq(payload[1][:2], ("google", "chrome"), "kiosk product 2")
    eq(payload[1][3], (151, 0, 7922, 108), "chromium version extracted")

    # THE FAILURE THIS GUARDS: without the extract, Chromium would be handed
    # the kernel string and compared against Chrome's ranges.
    eq(payload[1][2], "151.0.7922.108", "chromium raw is not the kernel string")

    # An extraction that finds nothing yields None, never the whole string.
    kind, payload = classify_device(
        "Raspberry Pi", "Pi", "6.18.39+rpt-rpi-v8", kiosk_rules, accept_rules)
    eq(payload[1][2], None, "absent Chromium -> None, not the kernel string")
    eq(payload[1][3], None, "absent Chromium -> unparseable")
    eq(disposition(payload[1][3], [{"versionEndExcluding": "149.0"}]),
       UNKNOWN_VERSION, "absent Chromium dispositions unknown, NOT patched")

    # Acceptance outranks the CPE map.
    kind, payload = classify_device(
        "LENOVO", "Lenovo TB125FU", "1.60.1-emm", kiosk_rules, accept_rules)
    eq(kind, "accepted", "lenovo -> accepted by ruling")
    eq(payload["reason"], "ruling", "acceptance carries its reason")
    eq(payload["products"], [], "acceptance with no products declared")

    accept_with_products = [{
        "id": "android", "match": {"manufacturer": "lenovo"},
        "reason": "ruling", "products": [("google", "android", None)],
    }]
    kind, payload = classify_device(
        "LENOVO", "Lenovo TB125FU", "1.60.1-emm",
        kiosk_rules, accept_with_products)
    eq(kind, "accepted", "still accepted when products are declared")
    eq(payload["products"][0][:2], ("google", "android"),
       "accepted device still maps a product, so a CVE reads accepted "
       "rather than unmonitored")

    kind, payload = classify_device(
        "Sonos", "Beam", "18.6", kiosk_rules, accept_rules)
    eq(kind, "unmapped", "unknown vendor -> unmapped, not silently dropped")

    # --- OWNERSHIP: the ghost-device guard (KAN-286) ------------------------
    # A registry split leaves a fragment owned by an integration that inherited
    # a version string it does not understand and will never update. The
    # fragment must not become an asset; the real device must.
    owned_kiosk = [{
        "id": "kiosk_pi",
        "match": {"manufacturer": "raspberry pi"},
        "owner": "kiosk_pi",
        "products": [("google", "chrome", r"Chromium\s+([\d.]+)")],
    }]
    owned_gateway = [{
        "id": "unifi_gateway",
        "match": {"manufacturer": "ubiquiti", "model": "udmpro"},
        "owner": "unifi",
        "products": [("ui", "unifi_dream_machine_firmware", None)],
    }]

    kind, payload = classify_device(
        "Raspberry Pi", "Raspberry Pi 3 Model B Plus Rev 1.3",
        "6.18.39+rpt-rpi-v8 / Chromium 150.0.7871.181",
        owned_kiosk, [], owner_domain="unifi")
    eq(kind, "unmapped", "GHOST: pi owned by unifi is not a chromium source")
    eq("ghost registry entry" in (payload or ""), True,
       "ghost rejection states its reason, never a silent drop")

    kind, payload = classify_device(
        "Raspberry Pi", "Raspberry Pi 3 Model B Plus Rev 1.3",
        "6.18.39+rpt-rpi-v8 / Chromium 151.0.7922.108",
        owned_kiosk, [], owner_domain="kiosk_pi")
    eq(kind, "mapped", "REAL: pi owned by kiosk_pi still maps")
    # Guarded so a wrong `kind` reports as a clean assertion failure rather than
    # indexing into the rejection string and raising IndexError.
    eq(payload[0][2] if kind == "mapped" else None, "151.0.7922.108",
       "real kiosk keeps its chromium version")

    # THE TRAP, and the reason "empty identifiers" was rejected as the signal:
    # the UDM Pro is ALSO owned by unifi and has empty identifiers. Any guard
    # that drops it removes the network edge from the scan, and an asset that
    # stops being scanned reads as clean.
    kind, payload = classify_device(
        "Ubiquiti Networks", "UDMPRO", "5.1.27.33981",
        owned_gateway, [], owner_domain="unifi")
    eq(kind, "mapped", "TRAP: the UDM Pro is legitimately owned by unifi")
    eq(payload[0][1] if kind == "mapped" else None,
       "unifi_dream_machine_firmware", "gateway still mapped")

    # Unknown owner is UNCONSTRAINED -- over-include rather than drop a real
    # asset. This is the safe direction and it is deliberate.
    kind, payload = classify_device(
        "Raspberry Pi", "Pi", "6.18.39+rpt-rpi-v8 / Chromium 151.0.7922.108",
        owned_kiosk, [], owner_domain=None)
    eq(kind, "mapped", "unknown owner does not exclude a device")

    # Ownership applies to ACCEPTED rules too -- the tablets carry the same
    # split, with unifi holding an MDM build string and mobile_app the real
    # Android version.
    owned_accept = [{
        "id": "android_tablets", "match": {"manufacturer": "lenovo"},
        "owner": "mobile_app", "reason": "ruling",
        "products": [("google", "android", None)],
    }]
    kind, payload = classify_device(
        "LENOVO", "Lenovo TB125FU", "1.60.1-emm", [], owned_accept,
        owner_domain="unifi")
    eq(kind, "unmapped", "GHOST tablet: unifi is not an android version source")
    kind, payload = classify_device(
        "LENOVO", "Lenovo TB125FU", "33", [], owned_accept,
        owner_domain="mobile_app")
    eq(kind, "accepted", "REAL tablet still accepted by ruling")

    # --- severity_of: preference order and the UNRATED distinction ---------
    eq(severity_of({"metrics": {"cvssMetricV31": [
        {"cvssData": {"baseSeverity": "high", "baseScore": 8.8}}]}}),
       ("HIGH", 8.8), "v3.1 preferred and upper-cased")
    eq(severity_of({"metrics": {
        "cvssMetricV31": [{"cvssData": {"baseSeverity": "MEDIUM", "baseScore": 5.0}}],
        "cvssMetricV30": [{"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.9}}]}}),
       ("MEDIUM", 5.0), "v3.1 wins over v3.0")
    eq(severity_of({"metrics": {"cvssMetricV2": [
        {"baseSeverity": "LOW", "cvssData": {"baseScore": 2.1}}]}}),
       ("LOW", 2.1), "v2 severity lives on the wrapper, not cvssData")
    # THE ONE THAT MATTERS: no metric is UNRATED, never NONE. A freshly
    # published CVE with no CVSS yet must not render as harmless.
    eq(severity_of({"metrics": {}}), ("UNRATED", None), "no metrics -> UNRATED")
    eq(severity_of({}), ("UNRATED", None), "empty cve -> UNRATED")
    eq(severity_of(None), ("UNRATED", None), "None -> UNRATED")

    # --- REGRESSION: the platform-CPE false positive (CVE-2026-11645) -------
    # Verbatim shape of the real configuration, which reported the estate's Pi
    # kernels AFFECTED by a Chromium V8 bug until `vulnerable` was honoured.
    chrome_on_linux = {"configurations": [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "149.0.7827.103"},
        ]},
        {"operator": "OR", "cpeMatch": [
            {"vulnerable": False,
             "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"},
            {"vulnerable": False,
             "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
            {"vulnerable": False,
             "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
        ]},
    ]}]}
    eq(nodes_for(chrome_on_linux, "linux", "linux_kernel"), [],
       "platform CPE yields NO nodes -- a kernel is not affected by a Chrome bug")
    eq(disposition(parse_version("6.18.39+rpt-rpi-v8"),
                   nodes_for(chrome_on_linux, "linux", "linux_kernel")),
       UNMONITORED, "kernel vs a Chrome CVE is unmonitored, NOT affected")
    # and the real product still resolves correctly through the same CVE
    eq(disposition(parse_version("151.0.7922.108"),
                   nodes_for(chrome_on_linux, "google", "chrome")),
       PATCHED, "chrome 151 vs <149 is patched")
    eq(disposition(parse_version("148.0.1"),
                   nodes_for(chrome_on_linux, "google", "chrome")),
       AFFECTED, "chrome 148 IS affected -- the check can still fire")

    # --- nodes_for: the exact-version CPE form ---
    android_cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True,
         "criteria": "cpe:2.3:o:google:android:14.0:*:*:*:*:*:*:*"},
        {"vulnerable": True,
         "criteria": "cpe:2.3:o:google:android:15.0:*:*:*:*:*:*:*"},
        {"vulnerable": True,
         "criteria": "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "17.0"},
    ]}]}]}
    nodes = nodes_for(android_cve, "google", "android")
    eq(len(nodes), 2, "nodes_for filters to the named product")
    eq(disposition(parse_version("14.0"), nodes), AFFECTED, "android 14 affected")
    eq(disposition(parse_version("16.0"), nodes), PATCHED, "android 16 not affected")
    # The failure this prevents: a bare exact-version match read as "no bounds"
    # would make EVERY android version affected.
    eq(disposition(parse_version("99.0"), nodes), PATCHED,
       "exact-version CPE must not read as all-versions")

    # PROOF THIS HARNESS CAN FAIL (LAW section 4), by mutation rather than by
    # a self-referential check. Verified 2026-08-11 against two mutants:
    #
    #   versionEndExcluding treated as inclusive (`c <= 0`)
    #       -> "kernel at exclusive end is NOT affected" failed, exit 1
    #   unparseable bound skipped instead of returning None
    #       -> "unparseable bound -> unknown, NOT patched" failed, exit 1
    #       -> "one bad node poisons a clean one" failed, exit 1
    #
    # Both mutations are the false-`patched` class this module exists to
    # prevent, and both were caught. Re-run that way after changing any
    # comparison here; a green self-test on unmutated code proves nothing on
    # its own.
    #
    # The ownership assertion was proved the same way on 2026-08-14, and it
    # must fail in BOTH directions -- under-enforcing lets a ghost inflate the
    # board, over-enforcing drops a real asset and reads as clean:
    #
    #   _owner_ok always True (the pre-fix behaviour)
    #       -> "GHOST: pi owned by unifi is not a chromium source" failed
    #       -> "ghost rejection states its reason" failed
    #       -> "GHOST tablet: unifi is not an android version source" failed
    #   _owner_ok excludes any rule declaring an owner
    #       -> "TRAP: the UDM Pro is legitimately owned by unifi" failed
    #       -> "REAL: pi owned by kiosk_pi still maps" failed  (6 total)
    #   _owner_ok treats an UNKNOWN owner as a mismatch
    #       -> "unknown owner does not exclude a device" failed
    return fails


if __name__ == "__main__":
    import sys

    problems = _self_test()
    if problems:
        print("cpe.py SELF-TEST FAILED")
        for p in problems:
            print("  " + p)
        sys.exit(1)
    print("cpe.py self-test: all assertions passed")
