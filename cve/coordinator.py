"""Discovery, fetch and join for nvd_estate.

WHAT THIS DOES, IN ORDER
    1. Walk the device registry and turn manufacturer/model/sw_version into
       (cpe_vendor, cpe_product, installed_version) triples, using const.py's
       ASSET_RULES. Devices matched by ACCEPTED_RULES are recorded as accepted.
       A rule's version is taken ONLY from the integration that owns the device
       (`owner`), which keeps a ghost registry fragment from supplying a frozen
       version nothing runs. Devices with a sw_version and no rule -- or one
       whose ownership assertion failed -- are counted as UNMAPPED and reported
       WITH THE REASON. A scan that keys on one pattern is not an audit (LAW 5),
       so this one states what it misses instead of quietly shrinking its own
       denominator.
    2. Fetch the CISA KEV catalog and keep entries whose vendor/product/name
       matches an estate keyword. KEV is the high-signal source: every entry is
       confirmed actively exploited.
    3. Look each surviving KEV CVE up in NVD to get its cpeMatch ranges.
    4. Disposition every (cve, asset) pair through cpe.disposition().

SCOPE OF THIS VERSION, STATED SO THE HEADER STAYS TRUE. Two finding sets, kept
apart on purpose. `actionable` is KEV-DRIVEN ONLY -- actively-exploited
vulnerabilities joined to installed versions. `window_by_target` is the
recent-window sweep per tracked product, in _sweep_window below, which replaced
packages/network_security_cve.yaml's seven command_line sensors; that package
is retired and gone from the tree, and the API key it inlined went with it.

THE COORDINATOR NEVER RAISES UpdateFailed (LAW 11). Raising takes every entity
unavailable, which lets a dead layer read green -- exactly backwards for a
monitor. It always returns a dict, and the dict says which sources answered.

FAILURE IS NOT ZERO, AND IT IS NOT `patched` EITHER. If NVD cannot be reached,
findings are not emitted as clean; `sources` records the failure, integrity
goes degraded, and the actionable count is None rather than 0. An unreadable
source can never contribute 0 (LAW 11).

AUTH FAILURE DOES NOT BLOW UP THE ENTITIES. A 401/403 from NVD starts HA's
reauth flow so the key can be replaced from the UI -- which is the whole point
of this being an integration rather than seven inlined shell strings -- but it
does NOT raise ConfigEntryAuthFailed, because that would take every entity
unavailable and hide the reason. The data dict reports `unauthorized` and the
entities stay up saying so.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from . import cpe
from .const import (
    ACCEPTED_RULES,
    ASSET_RULES,
    CONF_API_KEY,
    CVE_NS,
    KEV_URL,
    KEV_VENDOR_KEYWORDS,
    NVD_CVE_URL,
    NVD_REQUEST_SPACING,
    REQUEST_TIMEOUT,
    UPDATE_INTERVAL_HOURS,
    WINDOW_DAYS,
)

_LOGGER = logging.getLogger(__name__)

# Per-product cap for the recent-window sweep. NVD allows 2000. This is a
# response-size limit, not a judgement about relevance -- linux_kernel alone
# carries 18832 CVEs all-time and several hundred in any 90-day window.
# WHATEVER IS DROPPED IS REPORTED in `truncated`, because a silent cap reads as
# "covered everything" when it did not (LAW 5).
MAX_PER_PRODUCT = 200


def _is_overdue(due_str, today):
    """Has CISA's KEV due date actually passed, or merely been set?

    GH-537 (found while explaining a critical rollup to Joel): entities.py
    used to count `f.get("due")` truthy as "overdue" -- that only checks a
    due date EXISTS, not that today is past it, so a KEV entry added
    yesterday with a two-week remediation window read as already overdue.
    A date we cannot parse is not overdue either -- guessing urgency from bad
    data is the same false-alarm shape LAW 5 exists to prevent.
    """
    if not due_str:
        return False
    try:
        return datetime.strptime(str(due_str), "%Y-%m-%d").date() < today
    except ValueError:
        return False


class NvdEstateCoordinator(DataUpdateCoordinator):
    """Joins what the estate runs to what NVD says is broken."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=CVE_NS,
            update_interval=timedelta(hours=UPDATE_INTERVAL_HOURS),
        )
        self.entry = entry
        self._session = async_get_clientsession(hass)
        self._reauth_started = False

    @property
    def _api_key(self):
        return self.entry.data.get(CONF_API_KEY)

    # -- discovery ---------------------------------------------------------

    def _owner_domain(self, device):
        """The config-entry domain that owns this device, or None.

        None means UNKNOWN, and cpe._owner_ok treats unknown as unconstrained
        on purpose -- over-including a device is recoverable, dropping a real
        asset from a security scan is not.
        """
        entry_id = getattr(device, "primary_config_entry", None)
        if not entry_id:
            # No primary. A single entry is unambiguous; several is a guess,
            # and a guess here would exclude on no evidence.
            entries = list(getattr(device, "config_entries", None) or [])
            entry_id = entries[0] if len(entries) == 1 else None
        if not entry_id:
            return None
        entry = self.hass.config_entries.async_get_entry(entry_id)
        return entry.domain if entry else None

    def _discover(self):
        """Device registry -> assets, accepted, unmapped.

        Versions are read PER DEVICE, never per model. Two kiosks of the same
        model can sit on different Chromium builds -- measured 2026-08-11, they
        did -- so collapsing by model would report one host's version for
        another's.

        THE VERSION MUST COME FROM THE INTEGRATION THAT OWNS THE DEVICE. The
        registry can split one machine into two records; the fragment keeps the
        version string it held at the split and its new owner never updates it.
        See cpe.classify_device and const.ASSET_RULES' `owner`.
        """
        reg = dr.async_get(self.hass)
        assets, accepted, unmapped = [], [], []

        # ITERATED, NOT .values() (GH-569). Deprecated mapping access on
        # device_registry.devices; breaks in HA 2027.9. Iterating yields
        # DeviceEntry directly. This site is NOT the one the ticket
        # named -- the log reported only scan/coordinator.py, and a fix
        # scoped to that one frame would have left this one live.
        for device in reg.devices:
            sw = device.sw_version
            if not sw:
                continue
            name = device.name_by_user or device.name or "?"

            kind, payload = cpe.classify_device(
                device.manufacturer, device.model, sw,
                ASSET_RULES, ACCEPTED_RULES,
                owner_domain=self._owner_domain(device),
            )

            if kind == "accepted":
                accepted.append({"device": name, "reason": payload["reason"]})
                # Declared products still enter the asset list, flagged, so a
                # CVE against them dispositions ACCEPTED instead of vanishing
                # into UNMONITORED.
                for vendor, product, raw, parsed in payload["products"]:
                    assets.append({
                        "device": name,
                        "vendor": vendor,
                        "product": product,
                        "version_raw": raw,
                        "version": parsed,
                        "accepted": True,
                        "reason": payload["reason"],
                    })
            elif kind == "mapped":
                for vendor, product, raw, parsed in payload:
                    assets.append({
                        "device": name,
                        "vendor": vendor,
                        "product": product,
                        "version_raw": raw,
                        "version": parsed,
                    })
            else:
                # `payload` carries a reason when the device matched a rule but
                # failed its ownership assertion. A rejected device is REPORTED,
                # never dropped (LAW 5).
                row = {
                    "device": name,
                    "manufacturer": device.manufacturer or "?",
                    "model": device.model or "?",
                }
                if payload:
                    row["reason"] = payload
                unmapped.append(row)

        return assets, accepted, unmapped

    @staticmethod
    def _version_conflicts(assets):
        """Same device name, same product, DIFFERENT versions.

        The registry can hold several entries for one physical machine. Three
        kiosks carried two each: kiosk_pi's own device (Chromium 151) and a
        GHOST fragment of the same hostname owned by unifi, frozen at Chromium
        150 -- which produced the largest finding on the board, against a
        browser build nothing runs.

        THE OWNERSHIP ASSERTION IN classify_device NOW REMOVES THAT CLASS
        BEFORE IT REACHES HERE, so this should read empty for the kiosks and
        the tablets. It is kept because it is the detector, not the fix: a
        conflict surviving the ownership check means two records that BOTH
        legitimately own a version disagree, which is a genuine finding and not
        something to tie-break.

        STILL RESOLVES NOTHING, deliberately. Picking the higher version guesses
        in the UNSAFE direction -- it assumes the best case and hides a stale
        host. Picking the lower invents work. Entity count remains a heuristic
        and is still not used. What LAW 10 asks for -- a signal the integration
        must keep true -- is the OWNING CONFIG-ENTRY DOMAIN, and that is applied
        upstream in classify_device rather than as a tie-breaker here.
        """
        seen = {}
        for a in assets:
            key = (a["device"], a["vendor"], a["product"])
            seen.setdefault(key, set()).add(a["version_raw"])
        return sorted(
            f"{dev} {vend}:{prod} -> {sorted(v for v in vers if v)}"
            for (dev, vend, prod), vers in seen.items()
            if len({v for v in vers if v}) > 1
        )

    # -- fetch -------------------------------------------------------------

    async def _get_json(self, url, params=None):
        """Return (data, error). error is None on success.

        Never raises. Every caller has to be able to tell "answered" from
        "did not answer", so a failure is a value here, not an exception.
        """
        headers = {"User-Agent": "nvd-estate/0.1"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        try:
            async with self._session.get(
                url, params=params, headers=headers,
                timeout=REQUEST_TIMEOUT,
            ) as resp:
                if resp.status in (401, 403):
                    return None, "unauthorized"
                if resp.status == 404:
                    return None, "not_found"
                if resp.status != 200:
                    return None, f"http_{resp.status}"
                return await resp.json(content_type=None), None
        except asyncio.TimeoutError:
            return None, "timeout"
        except Exception as err:  # noqa: BLE001 - a failure is a value here
            _LOGGER.debug("nvd_estate fetch failed for %s: %s", url, err)
            return None, type(err).__name__

    async def _fetch_kev(self):
        data, err = await self._get_json(KEV_URL)
        if err:
            return None, err
        return data.get("vulnerabilities") or [], None

    async def _fetch_cve(self, cve_id):
        data, err = await self._get_json(NVD_CVE_URL, {"cveId": cve_id})
        if err:
            return None, err
        items = data.get("vulnerabilities") or []
        return (items[0].get("cve") if items else None), None

    async def _fetch_window(self, vendor, product, version_raw, start, end):
        """CVEs in the window affecting THIS INSTALLED VERSION.

        THE VERSION GOES IN THE QUERY, and that is not an optimisation -- it is
        what makes the count trustworthy. A product-only query returns
        everything ever published against the product: linux_kernel came back
        1798 for a 90-day window, chrome 1734. Capped at 200 those are 11%
        samples, and LAW 5 is explicit that an ABSENCE from a truncated sweep
        is void. Measured 2026-08-11, that void was hiding real findings: the
        product-only chrome sample reported 200/200 patched, while the
        version-specific query for the installed 151.0.7922.71 returns 406
        CVEs, all genuinely affecting it (fixed in 151.0.7922.72).

        With the version in the match string the volume collapses to only what
        applies -- kernel 6.18.39 goes 1798 -> 57, the UDM Pro goes to 0 -- so
        `totalResults` IS the affected count rather than a floor.

        NVD's matching is the coarse filter; cpe.py remains the authority. The
        caller cross-checks a sample against our own comparator, because a
        count taken on trust from the thing being measured is not evidence
        (LAW 9).

        Returns (cve_objects_sample, total, error).
        """
        data, err = await self._get_json(NVD_CVE_URL, {
            "virtualMatchString": f"cpe:2.3:*:{vendor}:{product}:{version_raw}",
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": MAX_PER_PRODUCT,
        })
        if err:
            return None, 0, err
        items = data.get("vulnerabilities") or []
        return ([i.get("cve") for i in items if i.get("cve")],
                data.get("totalResults", len(items)), None)

    # -- join --------------------------------------------------------------

    async def _async_update_data(self):
        now = datetime.now(timezone.utc)
        assets, accepted, unmapped = self._discover()

        result = {
            "generated": now.isoformat(),
            "sources": {"kev": "ok", "nvd": "ok"},
            "coverage": {
                "mapped_devices": len({a["device"] for a in assets}),
                "accepted_devices": len(accepted),
                "unmapped_devices": len(unmapped),
                # Sample, not the whole list -- attributes have a size budget.
                "unmapped_sample": [
                    f"{u['manufacturer']} {u['model']}" for u in unmapped[:15]
                ],
                # Always present, never omitted when empty -- "the registry
                # agrees with itself" and "we did not check" are different.
                "version_conflicts": self._version_conflicts(assets),
                # Devices a rule DID match and ownership rejected -- a ghost
                # registry entry whose version is not authoritative. NOT
                # sampled: this list is small by construction and it is the
                # only place the exclusion is visible. `unmapped_sample`
                # truncates at 15 and carries no reason, so without this the
                # scan would decline a device silently, which is the half of
                # LAW 5 that says state what you missed.
                "ownership_rejected": [
                    f"{u['device']}: {u['reason']}"
                    for u in unmapped if u.get("reason")
                ],
            },
            "accepted": accepted,
            "findings": [],
            "counts": {},
            "actionable": None,
            "errors": [],
            "truncated": [],
        }

        if not assets:
            # No assets is a CONFIG problem, not an all-clear.
            result["sources"]["nvd"] = "no_assets"
            result["errors"].append("no devices matched ASSET_RULES")
            result["counts"] = {}
            return result

        kev_entries, kev_err = await self._fetch_kev()
        if kev_err:
            result["sources"]["kev"] = kev_err
            result["errors"].append(f"kev: {kev_err}")
            kev_entries = []

        cutoff = (now - timedelta(days=WINDOW_DAYS)).date()
        kev_ids = {}
        for entry in kev_entries:
            hay = " ".join([
                str(entry.get("vendorProject", "")),
                str(entry.get("product", "")),
                str(entry.get("vulnerabilityName", "")),
            ]).lower()
            if not any(k in hay for k in KEV_VENDOR_KEYWORDS):
                continue
            try:
                added = datetime.strptime(
                    entry.get("dateAdded", ""), "%Y-%m-%d").date()
            except ValueError:
                continue
            if added < cutoff:
                continue
            kev_ids[entry.get("cveID")] = entry

        # Look each KEV CVE up once, then disposition it against every asset.
        findings = []
        auth_failed = False
        for i, (cve_id, kev) in enumerate(sorted(kev_ids.items())):
            if i:
                await asyncio.sleep(NVD_REQUEST_SPACING)
            cve_obj, err = await self._fetch_cve(cve_id)
            if err == "unauthorized":
                auth_failed = True
                result["sources"]["nvd"] = "unauthorized"
                result["errors"].append("nvd: unauthorized")
                break
            if err or not cve_obj:
                result["errors"].append(f"nvd {cve_id}: {err or 'empty'}")
                # UNRESOLVED, not clean. It still appears as a finding so the
                # CVE cannot vanish just because the lookup failed.
                findings.append({
                    "cve": cve_id,
                    "device": None,
                    "product": None,
                    "version": None,
                    "disposition": cpe.UNKNOWN_VERSION,
                    "kev": True,
                    "note": f"NVD lookup failed ({err or 'empty'})",
                    "due": kev.get("dueDate"),
                    "overdue": _is_overdue(kev.get("dueDate"), now.date()),
                })
                continue

            matched_any = False
            for asset in assets:
                nodes = cpe.nodes_for(cve_obj, asset["vendor"], asset["product"])
                if not nodes:
                    continue
                matched_any = True
                # The ruling short-circuits the comparison: an accepted asset
                # is never dispositioned by version, so it can never read
                # `affected` and can never be silently re-litigated by a
                # version change.
                disp = (cpe.ACCEPTED if asset.get("accepted")
                        else cpe.disposition(asset["version"], nodes))
                findings.append({
                    "cve": cve_id,
                    "device": asset["device"],
                    "product": f"{asset['vendor']}:{asset['product']}",
                    "version": None if asset.get("accepted") else asset["version_raw"],
                    "disposition": disp,
                    "accepted_reason": asset.get("reason"),
                    "kev": True,
                    "ransomware": str(
                        kev.get("knownRansomwareCampaignUse", "")
                    ).lower() == "known",
                    "due": kev.get("dueDate"),
                    "overdue": _is_overdue(kev.get("dueDate"), now.date()),
                    "name": kev.get("vulnerabilityName"),
                    # GH-537 (Joel: "Can you add what the fixes are for the
                    # remaining CVE exposures?"). fixed_in is only ever the
                    # confidently-known NVD bound, never a guess -- None here
                    # means NVD has not published a clean fix boundary yet,
                    # which is itself worth surfacing rather than hiding.
                    "fixed_in": cpe.fixed_in(nodes) if disp == cpe.AFFECTED else None,
                    "remediation": kev.get("requiredAction"),
                })
            if not matched_any:
                # KEV says this vendor matters and no asset of ours carries the
                # product. That is UNMONITORED -- a coverage statement, not an
                # all-clear -- and it is how a missing ASSET_RULES row surfaces.
                findings.append({
                    "cve": cve_id,
                    "device": None,
                    "product": None,
                    "version": None,
                    "disposition": cpe.UNMONITORED,
                    "kev": True,
                    "due": kev.get("dueDate"),
                    "overdue": _is_overdue(kev.get("dueDate"), now.date()),
                    "name": kev.get("vulnerabilityName"),
                })

        if auth_failed:
            self._maybe_start_reauth()
            # Do NOT report counts computed from a partial run.
            result["findings"] = findings
            result["counts"] = {}
            result["actionable"] = None
            return result

        result["findings"] = findings
        counts = {}
        for f in findings:
            counts[f["disposition"]] = counts.get(f["disposition"], 0) + 1
        result["counts"] = counts

        # `actionable` stays None -- never 0 -- when a source did not answer.
        if result["sources"]["kev"] == "ok" and result["sources"]["nvd"] == "ok":
            result["actionable"] = counts.get(cpe.AFFECTED, 0)

        result["rollup"] = cpe.rollup({f["disposition"] for f in findings})

        # -- recent-window sweep, deliberately a SEPARATE number ------------
        #
        # This replaces what packages/network_security_cve.yaml's seven
        # command_line sensors did -- count CVEs per product in a rolling
        # window -- except dispositioned against installed versions instead of
        # merely counted.
        #
        # IT MUST NOT FEED `actionable`, AND THAT IS NOT TIDINESS. KEV means
        # CISA has confirmed active exploitation in the wild; a recent-window
        # CVE means it was published. A kernel CVE fixed in a point release the
        # Pis have not taken is genuinely `affected` and genuinely NOT the same
        # call to action as an exploited one. Merging them would let volume
        # bury the signal the wall tile exists to carry -- which is exactly the
        # defect the retired kev_estate.py described about the ICS advisory
        # feed IT replaced, and then committed in its own way by counting
        # vendors owned rather than versions held (KAN-151).
        await self._sweep_window(assets, now, result)
        return result

    async def _sweep_window(self, assets, now, result):
        """Disposition recently-published CVEs per tracked product."""
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        start = (now - timedelta(days=WINDOW_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%S.000")

        # One request per distinct (product, version). Kiosks sharing a kernel
        # share a query; kiosks on different Chromium builds do not, which is
        # the point -- one host being behind is exactly what this must catch.
        targets = sorted({
            (a["vendor"], a["product"], a["version_raw"])
            for a in assets
            if not a.get("accepted") and a["version_raw"]
        })

        by_target, disagreements = {}, []
        for i, (vendor, product, version_raw) in enumerate(targets):
            if i:
                await asyncio.sleep(NVD_REQUEST_SPACING)
            cves, total, err = await self._fetch_window(
                vendor, product, version_raw, start, end)
            if err:
                result["errors"].append(
                    f"window {vendor}:{product}:{version_raw}: {err}")
                result["sources"]["nvd_window"] = err
                continue

            if total > len(cves or []):
                # Only the DETAIL is capped now; `total` is the real count.
                result["truncated"].append(
                    f"{vendor}:{product}:{version_raw} detail "
                    f"{len(cves)}/{total}")

            # CROSS-CHECK: does our own comparator agree that the sample NVD
            # returned actually affects this version? A count taken on trust
            # from the source being measured is not evidence (LAW 9). A
            # disagreement is REPORTED, never silently resolved in either
            # direction -- whichever side is wrong, the operator needs to know
            # the number is not clean.
            parsed = cpe.parse_version(version_raw)
            crit = high = unrated = 0
            worst = []
            for cve_obj in (cves or []):
                nodes = cpe.nodes_for(cve_obj, vendor, product)
                if not nodes:
                    continue
                if cpe.disposition(parsed, nodes) != cpe.AFFECTED:
                    if len(disagreements) < 25:
                        disagreements.append(
                            f"{cve_obj.get('id')} {vendor}:{product}:"
                            f"{version_raw}")
                    continue
                sev, score = cpe.severity_of(cve_obj)
                if sev == "CRITICAL":
                    crit += 1
                elif sev == "HIGH":
                    high += 1
                elif sev == "UNRATED":
                    unrated += 1
                worst.append({
                    "id": cve_obj.get("id"),
                    "sev": sev,
                    "score": score,
                    "published": (cve_obj.get("published") or "")[:10],
                    # GH-537: same honest fixed_in as the KEV path above --
                    # None means NVD has not published a clean fix bound yet.
                    "fixed_in": cpe.fixed_in(nodes),
                })

            worst.sort(key=lambda c: (-cpe.SEV_RANK.get(c["sev"], 0),
                                      c["published"]), reverse=False)
            worst.sort(key=lambda c: cpe.SEV_RANK.get(c["sev"], 0),
                       reverse=True)

            by_target[f"{vendor}:{product}:{version_raw}"] = {
                "cves": total,
                # crit/high/unrated are counted over the SCORED SAMPLE, not
                # over `total`. When `sampled` < `cves` they are FLOORS, and
                # `sampled` is published beside them so nobody reads a floor as
                # a count (LAW 5).
                "sampled": len(worst),
                "crit": crit,
                "high": high,
                # Never folded into crit/high. A CVE NVD has not scored yet is
                # not a harmless one.
                "unrated": unrated,
                "worst": worst[:8],
            }

        devices_for = {}
        for a in assets:
            k = f"{a['vendor']}:{a['product']}:{a['version_raw']}"
            devices_for.setdefault(k, set()).add(a["device"])

        # Ordered worst-first by severity weight, then volume, so the first
        # row is the thing to fix rather than merely the noisiest.
        def _weight(item):
            return (item[1]["crit"] * 1000 + item[1]["high"] * 10
                    + min(item[1]["cves"], 9))

        result["window_by_target"] = {
            k: dict(v, devices=sorted(devices_for.get(k, [])))
            for k, v in sorted(by_target.items(), key=_weight, reverse=True)
            if v["cves"]
        }
        result["window_counts"] = {
            "targets_queried": len(targets),
            "targets_affected": sum(1 for v in by_target.values() if v["cves"]),
            "crit": sum(v["crit"] for v in by_target.values()),
            "high": sum(v["high"] for v in by_target.values()),
            "unrated": sum(v["unrated"] for v in by_target.values()),
            "cve_device_pairs": sum(
                v["cves"] * max(1, len(devices_for.get(k, [])))
                for k, v in by_target.items()),
            "disagreements": disagreements[:10],
        }
        # None, not 0, if any query failed -- a partial sweep is not a clean one.
        if result["sources"].get("nvd_window", "ok") != "ok":
            result["window_counts"]["targets_affected"] = None

    def _maybe_start_reauth(self):
        """Prompt for a new key once, without taking the entities down.

        ConfigEntryAuthFailed would be the idiomatic call here and it is
        deliberately NOT used: it marks every entity unavailable, so the one
        surface that could tell you the key expired goes blank at the moment it
        matters. The reauth flow is started directly instead and the data dict
        carries `unauthorized`, so the entities stay up and say why.
        """
        if self._reauth_started:
            return
        self._reauth_started = True
        self.entry.async_start_reauth(self.hass)
