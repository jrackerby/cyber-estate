"""Entities for nvd_estate.

FIVE SENSORS, AND THE SPLIT IS DELIBERATE.

    actionable   how many findings are AFFECTED -- the number that should
                 drive a wall tile, and the only one that can legitimately
                 read 0 as good news.
    integrity    whether the answer above can be trusted at all. This is a
                 DIFFERENT AUDIENCE, not a lower intensity (LAW 11): a
                 degraded integrity is an operator problem, and it must never
                 be collapsed into the actionable count.
    coverage     how many devices carry a version we do not check. The blind
                 spot, published rather than implied.
    recent_affected  findings that turned AFFECTED recently -- see
                 NvdRecentAffectedSensor for the exact window.
    rollup       worst disposition across every finding.

EVERY ENTITY OVERRIDES `available` TO TRUE. A monitor that disappears when its
subject does cannot report the subject being down (LAW 11), and the failure
this integration exists to prevent is precisely a security surface that reads
clean because it stopped working.

`actionable` IS None, NEVER 0, WHEN A SOURCE DID NOT ANSWER. It renders as
`unknown` rather than as a confident zero -- an unreadable source can never
contribute 0.
"""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import cpe
from .const import CVE_NS
from .coordinator import NvdEstateCoordinator

# KAN-344 MERGE: DOMAIN dropped, same reasoning as feeds/entities.py --
# the top-level sensor.py resolves the coordinator once for all three
# subsystems (entry.runtime_data is now a dict of coordinators, not one),
# so this module takes it as a parameter instead of doing its own lookup.
DOMAIN = CVE_NS  # unique_id / device-identifier prefix text only

# Attribute budget. A findings list of any real length blows past HA's
# recorder-friendly attribute size, so the detail is capped and the cap is
# STATED in an attribute rather than applied silently (LAW 5).
MAX_DETAIL = 25


def build_cve_sensors(coordinator: NvdEstateCoordinator) -> list:
    return [
        NvdActionableSensor(coordinator),
        NvdIntegritySensor(coordinator),
        NvdCoverageSensor(coordinator),
        NvdRollupSensor(coordinator),
        NvdRecentAffectedSensor(coordinator),
    ]


class _Base(CoordinatorEntity[NvdEstateCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: NvdEstateCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._key = key
        self._attr_unique_id = f"{DOMAIN}_{key}"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, DOMAIN)},
            name="NVD Estate",
            manufacturer="El Coronel Luz",
            model="Vulnerability applicability",
            entry_type="service",
        )

    @property
    def available(self) -> bool:
        """Always available -- see the module docstring. The integrity sensor
        is what reports a bad run, and it cannot do that from an unavailable
        state."""
        return True

    @property
    def _data(self):
        return self.coordinator.data or {}


class NvdActionableSensor(_Base):
    """Findings that are AFFECTED. The number worth acting on."""

    _attr_name = "Actionable vulnerabilities"
    _attr_icon = "mdi:shield-alert"
    _attr_native_unit_of_measurement = "findings"

    def __init__(self, coordinator):
        super().__init__(coordinator, "actionable")

    @property
    def native_value(self):
        # None -> `unknown` on the entity. Deliberately not 0.
        return self._data.get("actionable")

    @property
    def extra_state_attributes(self):
        data = self._data
        findings = data.get("findings") or []
        affected = [f for f in findings if f.get("disposition") == cpe.AFFECTED]
        unknown = [f for f in findings
                   if f.get("disposition") == cpe.UNKNOWN_VERSION]
        # GH-537: `f.get("due")` truthy only means CISA SET a due date, not
        # that it has passed -- a KEV entry added yesterday with a two-week
        # window is not overdue. Was double-counted into "past due" on this
        # wall tile before the coordinator started computing the real
        # comparison in `overdue`.
        overdue = [f for f in affected if f.get("overdue")]
        # GH-537 (Joel: "Can you add what the fixes are for the remaining CVE
        # exposures?"). One entry per CVE among the findings actually driving
        # this tile, not per (cve, device) -- every device sharing a CVE
        # shares its fix. fixed_in/remediation are already honest-or-None per
        # cpe.fixed_in()'s own rule; passed through unchanged, never guessed
        # here.
        fixes = {}
        for f in affected:
            cve_id = f.get("cve")
            if not cve_id or cve_id in fixes:
                continue
            if f.get("fixed_in") or f.get("remediation"):
                fixes[cve_id] = {
                    "fixed_in": f.get("fixed_in"),
                    "remediation": f.get("remediation"),
                }
        return {
            "counts": data.get("counts") or {},
            "affected": [
                f"{f['cve']} {f.get('product') or ''} "
                f"{f.get('device') or ''} {f.get('version') or ''}".strip()
                for f in affected[:MAX_DETAIL]
            ],
            "unknown_version": [
                f"{f['cve']} {f.get('product') or ''} "
                f"{f.get('device') or ''}".strip()
                for f in unknown[:MAX_DETAIL]
            ],
            "fixes": fixes,
            "ransomware_linked": sum(1 for f in affected if f.get("ransomware")),
            # GH-537: renamed from with_due_date, which counted a due date
            # EXISTING rather than having passed -- the old name was accurate
            # to what it measured, and what it measured was the wrong thing
            # for a tile the dashboard already labelled "past due".
            "overdue": len(overdue),
            "detail_capped_at": MAX_DETAIL,
            "detail_truncated": (
                len(affected) > MAX_DETAIL or len(unknown) > MAX_DETAIL
            ),
            "generated": data.get("generated"),
        }


class NvdIntegritySensor(_Base):
    """Can the actionable count be trusted. A different audience, not a
    lower severity."""

    _attr_name = "Integrity"
    _attr_icon = "mdi:heart-pulse"

    def __init__(self, coordinator):
        super().__init__(coordinator, "integrity")

    @property
    def native_value(self):
        data = self._data
        if not data:
            return "unknown"
        sources = data.get("sources") or {}
        if sources.get("nvd") == "unauthorized":
            return "unauthorized"
        if any(v != "ok" for v in sources.values()):
            return "degraded"
        if data.get("errors"):
            return "degraded"
        return "ok"

    @property
    def extra_state_attributes(self):
        data = self._data
        return {
            # Always present, never omitted when empty -- "nothing went wrong"
            # and "we did not look" are different facts (LAW 11).
            "sources": data.get("sources") or {},
            "errors": data.get("errors") or [],
            "truncated": data.get("truncated") or [],
            "generated": data.get("generated"),
        }


class NvdCoverageSensor(_Base):
    """Devices carrying a version that nothing checks."""

    _attr_name = "Unmapped devices"
    _attr_icon = "mdi:map-marker-question"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator):
        super().__init__(coordinator, "coverage")

    @property
    def native_value(self):
        cov = self._data.get("coverage") or {}
        return cov.get("unmapped_devices")

    @property
    def extra_state_attributes(self):
        cov = self._data.get("coverage") or {}
        accepted = self._data.get("accepted") or []
        return {
            "mapped_devices": cov.get("mapped_devices"),
            "accepted_devices": cov.get("accepted_devices"),
            "unmapped_sample": cov.get("unmapped_sample") or [],
            # The acceptance REASON travels with the count. A declined signal
            # has to say so on the entity (LAW 11).
            "accepted_reasons": sorted({a["reason"] for a in accepted}),
            # Registry entries that disagree with themselves about a version.
            # Deliberately NOT resolved by this integration -- see
            # coordinator._version_conflicts. A non-empty list means at least
            # one finding elsewhere is computed from a version nothing runs.
            "version_conflicts": cov.get("version_conflicts") or [],
            # Ghost registry entries this scan declined, with the reason. Also
            # always present: "nothing was declined" and "we did not check"
            # must not read identically (LAW 11).
            "ownership_rejected": cov.get("ownership_rejected") or [],
            "generated": self._data.get("generated"),
        }


class NvdRecentAffectedSensor(_Base):
    """Recently-published CVEs that affect an installed version.

    A DIFFERENT NUMBER FROM `actionable`, ON PURPOSE. This is the
    recently-published set; `actionable` is the actively-exploited set. A
    kernel CVE fixed in a point release the Pis have not taken belongs here and
    does not belong on a wall tile next to "something you own is being
    exploited right now". This is the replacement for what
    packages/network_security_cve.yaml's seven command_line sensors counted --
    same question, but dispositioned against installed versions rather than
    counted by vendor name.

    Expect this to be non-zero and to stay non-zero. That is the honest state
    of any estate running general-purpose operating systems, and it is why it
    is reported separately rather than folded into a number that is supposed to
    mean "act now".
    """

    _attr_name = "Recent affected"
    _attr_icon = "mdi:magnify-scan"
    _attr_native_unit_of_measurement = "findings"

    def __init__(self, coordinator):
        super().__init__(coordinator, "recent_affected")

    @property
    def native_value(self):
        """Installed versions with at least one recent CVE against them.

        Counting TARGETS, not CVEs. "406 chrome CVEs" and "1 browser that
        needs updating" are the same fact, and only the second one tells
        anybody what to do. The CVE totals are in `by_target`.
        """
        return (self._data.get("window_counts") or {}).get("targets_affected")

    @property
    def extra_state_attributes(self):
        data = self._data
        wc = data.get("window_counts") or {}
        by_target = data.get("window_by_target") or {}
        return {
            # product:version -> {cves, devices}. Ordered worst-first, so the
            # thing to update is the first line.
            "by_target": dict(list(by_target.items())[:MAX_DETAIL]),
            "targets_queried": wc.get("targets_queried"),
            "cve_device_pairs": wc.get("cve_device_pairs"),
            # Severity split over the SCORED SAMPLE. Each by_target row carries
            # its own `sampled` vs `cves` so a floor is never read as a count.
            "critical": wc.get("crit"),
            "high": wc.get("high"),
            # Kept separate from critical/high on purpose: a CVE NVD has not
            # scored yet is not a harmless one.
            "unrated": wc.get("unrated"),
            # Where OUR comparator disagreed with NVD's own version match on a
            # sampled CVE. Always present, never omitted when empty -- "we
            # agreed" and "we did not check" are different facts.
            "comparator_disagreements": wc.get("disagreements") or [],
            "detail_capped_at": MAX_DETAIL,
            # Detail-list caps only; the counts above are untruncated because
            # the version is in the query.
            "detail_truncated": data.get("truncated") or [],
            "generated": data.get("generated"),
        }


class NvdRollupSensor(_Base):
    """Worst disposition anywhere in the finding set."""

    _attr_name = "Worst disposition"
    _attr_icon = "mdi:gauge-full"

    def __init__(self, coordinator):
        super().__init__(coordinator, "rollup")

    @property
    def native_value(self):
        return self._data.get("rollup")

    @property
    def extra_state_attributes(self):
        return {
            "order_worst_first": cpe.SEVERITY_ORDER,
            "counts": self._data.get("counts") or {},
            "generated": self._data.get("generated"),
        }
