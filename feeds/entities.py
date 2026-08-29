"""Sensor platform for estate_feeds.

ENTITY IDs ARE THE CONTRACT. Each sensor must land on the exact entity_id the
retired feedparser platform used, because three downstream template blocks
read `state_attr('sensor.<id>', 'entries')`:

  sensor.cdc_domestic_alerts  -> sensor.cdc_domestic_24h
  sensor.cisa_advisories      -> sensor.cisa_new_24h AND sensor.cisa_estate_7d

CORRECTED 2026-08-08, ON GLASS. `_attr_has_entity_name = False` was NOT
sufficient. 0.1.0 relied on it to keep the device name out of the entity_id,
and the entities registered as `sensor.estate_feeds_cdc_domestic_alerts`
anyway -- HA still derived the object_id from device name + entity name. All
three consuming templates immediately rendered clean all-clears off a missing
entity: cisa_new_24h 0, parsed_entries 0/0, cdc_domestic_24h "No active
outbreak notices". Exactly the silent-zero defect this integration exists to
remove, reintroduced one layer up.

THE FIX IS AN EXPLICIT `self.entity_id`, ASSIGNED BELOW. Do not replace it
with a flag and an assumption about how HA derives object_ids -- that is the
thing that just failed. An explicit assignment cannot be quietly reinterpreted
by a core release.

THE LESSON, for the gate: the parse gate asserted `_attr_has_entity_name =
False` and passed, because that is the mechanism I believed in. The entity_id
only exists at runtime, so no static gate could have caught this. The check
that would have caught it is the post-setup assertion now in the deploy
sequence -- read the entity_ids back off the registry after adding the entry,
before trusting any consumer.
"""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DISP_OK, FEEDS, FEEDS_NS
from .coordinator import EstateFeedsCoordinator

# KAN-344 MERGE: DOMAIN dropped. Under the old standalone estate_feeds
# integration this module did its own hass.data[DOMAIN][entry.entry_id]
# lookup at platform setup. Merged into cyber_estate, the top-level
# sensor.py already resolved the coordinator once for all three
# subsystems -- a second lookup here would just be a second name for the
# same object. build_feed_sensors() takes it as a parameter instead.
DOMAIN = FEEDS_NS  # unique_id / device-identifier prefix text only, see below


def build_feed_sensors(coordinator: EstateFeedsCoordinator) -> list["FeedSensor"]:
    """One FeedSensor per registered feed.

    NOTE the absence of a second positional True on the old platform's
    async_add_entities. The retired standalone platform passed
    update_before_add=True, which put every unbounded fetch on the startup
    critical path -- KAN-215. The coordinator's first refresh already ran in
    cyber_estate's async_setup_entry, and it is bounded.
    """
    return [FeedSensor(coordinator, feed) for feed in FEEDS]


class FeedSensor(CoordinatorEntity, SensorEntity):
    """One registered feed."""

    _attr_has_entity_name = False
    _attr_icon = "mdi:rss"

    def __init__(self, coordinator: EstateFeedsCoordinator, feed: dict) -> None:
        super().__init__(coordinator)
        self._key = feed["key"]
        self._feed = feed
        self._attr_name = feed["name"]
        self._attr_unique_id = DOMAIN + "_" + feed["key"]

        # LOAD-BEARING. See the module docstring: the flag above is not
        # enough on its own. This pins the object_id to the retired
        # platform's, which three template blocks address by name.
        self.entity_id = "sensor." + feed["key"]

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, "estate_feeds")},
            name="Estate Feeds",
            manufacturer="Local",
            model="Bounded RSS collector",
            entry_type="service",
        )

    @property
    def available(self) -> bool:
        """ALWAYS TRUE, deliberately.

        A monitor that disappears when its subject does cannot report the
        subject being down. The health of the feed is carried in the
        `disposition` attribute, never in entity availability.
        """
        return True

    def _record(self) -> dict:
        data = self.coordinator.data or {}
        return data.get(self._key) or {}

    @property
    def native_value(self):
        """Entry count when healthy, None otherwise.

        Playbook 16.3: an unreadable source must not contribute a plausible
        zero. The retired platform returned 0 on a 404 and four dead feeds
        rendered a confident all-clear for an unknown period.
        """
        record = self._record()
        if record.get("disposition") != DISP_OK:
            return None
        return record.get("count")

    @property
    def extra_state_attributes(self) -> dict:
        """`entries` is the load-bearing key -- three templates read it."""
        record = self._record()
        return {
            "entries": record.get("entries", []),
            # The newest entry's own identity (RSS <guid> / Atom <id>, falling
            # back to link then to the formatted date). Consumers that need to
            # name WHICH item is current read this instead of re-deriving it by
            # looping `entries` and re-parsing dates in Jinja -- which is what
            # sensor.cdc_domestic_24h did, with a documented timezone skew.
            "latest_key": record.get("latest_key", ""),
            "disposition": record.get("disposition"),
            "detail": record.get("detail", ""),
            "stale": record.get("stale", False),
            "last_success": record.get("last_success"),
            "http_status": record.get("http_status"),
            "bozo": record.get("bozo"),
            "unparsed_dates": record.get("unparsed_dates"),
            "feed_url": record.get("feed_url", self._feed["url"]),
        }
