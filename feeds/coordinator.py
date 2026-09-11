"""Coordinator for estate_feeds.

THIS COORDINATOR NEVER RAISES `UpdateFailed`. Same rule as kiosk_pi 16.3 and
household_state 37.3: raising takes every entity unavailable, and attributes
on an unavailable entity vanish -- which is exactly how a broken collector
comes to read green. It always returns a dict.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    DISP_HTTP_ERROR,
    DISP_OK,
    DISP_UNPARSED,
    DISP_UNREACHABLE,
    FEEDS,
    FEEDS_NS,
    FETCH_TIMEOUT,
    SCAN_INTERVAL_SECONDS,
)
from .feedparse import project_feed

_LOGGER = logging.getLogger(__name__)


class EstateFeedsCoordinator(DataUpdateCoordinator):
    """Fetch every registered feed, bounded, and project it."""

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=FEEDS_NS,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        # Last GOOD projection per feed key. Retained so that a failed fetch
        # serves stale-but-real entries rather than an empty list. An empty
        # list downstream renders as "no advisories" -- a false all-clear,
        # which is the defect this integration exists to remove. Stale is
        # marked; silent is not acceptable.
        self._last_good: dict[str, dict] = {}

    async def _fetch_one(self, session, feed: dict) -> dict:
        """Fetch and project one feed. NEVER raises."""
        key = feed["key"]
        url = feed["url"]

        body = None
        status = None
        disposition = DISP_OK
        detail = ""

        try:
            async with asyncio.timeout(FETCH_TIMEOUT):
                async with session.get(url) as resp:
                    status = resp.status
                    body = await resp.read()
        except asyncio.TimeoutError:
            disposition = DISP_UNREACHABLE
            detail = "timed out after " + str(FETCH_TIMEOUT) + "s"
        except aiohttp.ClientError as err:
            disposition = DISP_UNREACHABLE
            detail = type(err).__name__ + ": " + str(err)
        except Exception as err:  # noqa: BLE001 - never raise out of a fetch
            disposition = DISP_UNREACHABLE
            detail = "unexpected " + type(err).__name__ + ": " + str(err)

        projected = None
        if disposition == DISP_OK:
            if status is None or status < 200 or status >= 300:
                # THE 404 CASE. feedparser would have returned entries == []
                # here and the consuming template would have rendered a clean
                # all-clear. It is an error and it is named as one.
                disposition = DISP_HTTP_ERROR
                detail = "HTTP " + str(status)
            else:
                try:
                    projected = project_feed(
                        body, feed["date_format"], feed["inclusions"]
                    )
                except Exception as err:  # noqa: BLE001
                    disposition = DISP_UNPARSED
                    detail = "parse failed: " + type(err).__name__ + ": " + str(err)
                else:
                    if not projected["parsable"]:
                        disposition = DISP_UNPARSED
                        detail = "body is not a recognisable feed"

        now = dt_util.utcnow()

        if disposition == DISP_OK and projected is not None:
            record = {
                "entries": projected["entries"],
                "count": projected["entry_count"],
                # identity of the newest entry, for anything that
                # needs to say WHICH item it is talking about. Never omitted --
                # the same reasoning as `disposition`, so a consumer can tell
                # "no key" from "attribute missing".
                "latest_key": projected["latest_key"],
                "disposition": DISP_OK,
                "detail": "",
                "http_status": status,
                "bozo": projected["bozo"],
                "unparsed_dates": projected["unparsed_dates"],
                "feed_version": projected["version"],
                "stale": False,
                "last_success": now.isoformat(),
                "feed_url": url,
            }
            self._last_good[key] = record
            return record

        prior = self._last_good.get(key)
        return {
            # Stale-but-real beats empty. If there is no prior, entries is
            # empty and `disposition` is the only thing that says why -- that
            # is unavoidable on a first-ever failure and is why disposition is
            # never omitted.
            "entries": prior["entries"] if prior else [],
            # Follows `entries`: a stale key describing stale entries is
            # coherent, a fresh-looking key over prior entries would not be.
            "latest_key": prior.get("latest_key", "") if prior else "",
            # COUNT IS None, NOT 0. Playbook 16.3: refuse to produce a number
            # at the point of reading rather than fixing it in an aggregator.
            "count": None,
            "disposition": disposition,
            "detail": detail,
            "http_status": status,
            "bozo": prior["bozo"] if prior else None,
            "unparsed_dates": prior["unparsed_dates"] if prior else None,
            "feed_version": prior["feed_version"] if prior else "",
            "stale": bool(prior),
            "last_success": prior["last_success"] if prior else None,
            "feed_url": url,
        }

    async def _async_update_data(self) -> dict:
        """Fetch every feed concurrently. ALWAYS returns a dict."""
        session = async_get_clientsession(self.hass)
        results = await asyncio.gather(
            *[self._fetch_one(session, feed) for feed in FEEDS],
            return_exceptions=True,
        )

        data: dict = {}
        for feed, result in zip(FEEDS, results):
            if isinstance(result, BaseException):
                # gather() should not surface anything -- _fetch_one catches
                # everything -- but a bug there must not take the whole
                # coordinator down with it.
                _LOGGER.error(
                    "estate_feeds: %s raised out of _fetch_one: %s",
                    feed["key"],
                    result,
                )
                data[feed["key"]] = {
                    "entries": [],
                    "count": None,
                    "latest_key": "",
                    "disposition": DISP_UNREACHABLE,
                    "detail": "collector fault: " + type(result).__name__,
                    "http_status": None,
                    "bozo": None,
                    "unparsed_dates": None,
                    "feed_version": "",
                    "stale": False,
                    "last_success": None,
                    "feed_url": feed["url"],
                }
            else:
                data[feed["key"]] = result

        unhealthy = [k for k, v in data.items() if v["disposition"] != DISP_OK]
        if unhealthy:
            _LOGGER.warning("estate_feeds: unhealthy feeds: %s", unhealthy)

        return data
