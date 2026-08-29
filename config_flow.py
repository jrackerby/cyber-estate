"""Config flow for cyber_estate -- KAN-344 merge of nvd_estate's API-key
step and network_inventory's local/agent scan setup into one sequential
flow, producing ONE config entry for all three subsystems.

ORDER IS DELIBERATE: the NVD key first, then the scan-mode menu. Both
halves' original validation is preserved verbatim (the same NVD probe
against a known CVE, the same nmap-binary / agent-connectivity checks) --
only the sequencing and the final async_create_entry are new.

REAUTH IS API-KEY ONLY. If the key stops working, cve/coordinator.py calls
entry.async_start_reauth(hass) itself (unchanged from the standalone
integration); async_step_reauth_confirm here updates just CONF_API_KEY via
data_updates, which merges into entry.data rather than replacing it, so a
reauth never touches the scan half of the entry.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN
from .cve.const import CONF_API_KEY, NVD_CVE_URL
from .scan.api import (
    CannotConnect,
    InvalidAuth,
    NetworkInventoryClient,
    UnsupportedSchema,
)
from .scan.const import (
    CONF_ACKNOWLEDGED_MACS,
    CONF_DATADIR,
    CONF_EXCLUDE,
    CONF_HOST,
    CONF_MODE,
    CONF_PORT,
    CONF_SSH_ENABLED,
    CONF_SSH_KEY,
    CONF_SSH_USERS,
    CONF_STALE_DAYS,
    CONF_TARGETS,
    CONF_TOKEN,
    CONF_USE_TLS,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SSH_KEY,
    DEFAULT_SSH_USERS,
    DEFAULT_STALE_DAYS,
    MIN_STALE_DAYS,
    MODE_AGENT,
    MODE_LOCAL,
)
from .scan.join import normalise_mac
from .scan.options import DEFAULT_DATADIR, InvalidScanRequest, validate_target
from .scan.scanner import find_nmap

_LOGGER = logging.getLogger(__name__)

# A cheap, always-present CVE. Any CVE id works; what is being tested is
# whether NVD accepts the key, not what it says about this vulnerability.
_PROBE_CVE = "CVE-2022-0492"

STEP_API_KEY = vol.Schema({vol.Required(CONF_API_KEY): str})

STEP_AGENT = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_TOKEN): str,
        vol.Optional(CONF_USE_TLS, default=False): bool,
        vol.Optional(CONF_VERIFY_SSL, default=True): bool,
    }
)

STEP_LOCAL = vol.Schema(
    {
        vol.Required(CONF_TARGETS): str,
        vol.Optional(CONF_EXCLUDE, default=""): str,
        vol.Optional(CONF_DATADIR, default=DEFAULT_DATADIR): str,
        vol.Optional(CONF_STALE_DAYS, default=DEFAULT_STALE_DAYS): vol.All(
            int, vol.Range(min=MIN_STALE_DAYS)
        ),
        vol.Optional(CONF_SSH_ENABLED, default=True): bool,
        vol.Optional(CONF_SSH_KEY, default=DEFAULT_SSH_KEY): str,
        vol.Optional(CONF_SSH_USERS, default=DEFAULT_SSH_USERS): str,
    }
)


async def _validate_nvd_key(hass, api_key) -> str | None:
    """Return None if the key works, else an error slug for the form.

    THE KEY IS VALIDATED BEFORE IT IS ACCEPTED. An unauthenticated NVD
    request still succeeds (5 requests/30s instead of 50), so a typo'd key
    does NOT announce itself by breaking -- it announces itself by
    rate-limiting hours later, under load, looking like an NVD outage.
    """
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            NVD_CVE_URL,
            params={"cveId": _PROBE_CVE},
            headers={"apiKey": api_key, "User-Agent": "cyber-estate/1.0"},
            timeout=30,
        ) as resp:
            if resp.status in (401, 403):
                return "invalid_auth"
            if resp.status != 200:
                return "cannot_connect"
            data = await resp.json(content_type=None)
    except Exception:  # noqa: BLE001 - any failure is a failed validation
        return "cannot_connect"

    # A 200 carrying no result for a CVE that certainly exists means we are
    # not talking to the API we think we are -- a captive portal or a proxy.
    if not (data.get("vulnerabilities") or []):
        return "cannot_connect"
    return None


class CyberEstateConfigFlow(ConfigFlow, domain=DOMAIN):
    """NVD key, then scan mode, then one combined entry."""

    VERSION = 1

    def __init__(self) -> None:
        self._api_key_data: dict[str, Any] = {}

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return CyberEstateOptionsFlow()

    # -- step 1: NVD API key -------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            # single_config_entry in manifest.json already enforces this;
            # kept as defense-in-depth, matching the pattern the merged
            # subsystems' own standalone flows used.
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

            err = await _validate_nvd_key(self.hass, user_input[CONF_API_KEY])
            if err:
                errors["base"] = err
            else:
                self._api_key_data = user_input
                return await self.async_step_scan_mode()

        return self.async_show_form(
            step_id="user", data_schema=STEP_API_KEY, errors=errors
        )

    # -- step 2: which end does the scanning -----------------------------

    async def async_step_scan_mode(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """THE TWO MODES NEED DISJOINT INFORMATION -- one wants an address
        and a token, the other wants subnets and a key path -- so a single
        form would show every field and mark most of them optional,
        leaving the operator to work out which half applies to them."""
        return self.async_show_menu(
            step_id="scan_mode", menu_options=[MODE_LOCAL, MODE_AGENT]
        )

    async def async_step_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Scan from Home Assistant itself."""
        errors: dict[str, str] = {}

        if user_input is not None:
            targets = [
                t.strip() for t in user_input[CONF_TARGETS].split(",") if t.strip()
            ]
            excludes = [
                t.strip()
                for t in (user_input.get(CONF_EXCLUDE) or "").split(",")
                if t.strip()
            ]
            # VALIDATED HERE, not at first scan. A target that nmap will
            # refuse should be refused while the person who typed it is
            # still looking at the field.
            try:
                if not targets:
                    raise InvalidScanRequest("no targets given")
                for value in targets + excludes:
                    validate_target(value)
            except InvalidScanRequest as err:
                _LOGGER.debug("rejected target: %s", err)
                errors[CONF_TARGETS] = "invalid_target"

            if not errors:
                binary = await self.hass.async_add_executor_job(find_nmap)
                if not binary:
                    errors["base"] = "no_nmap"

            if not errors:
                return self.async_create_entry(
                    title="Cyber Estate",
                    data={
                        **self._api_key_data,
                        **user_input,
                        CONF_MODE: MODE_LOCAL,
                    },
                )

        return self.async_show_form(
            step_id=MODE_LOCAL, data_schema=STEP_LOCAL, errors=errors
        )

    async def async_step_agent(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            port = user_input[CONF_PORT]

            client = NetworkInventoryClient(
                session=async_get_clientsession(self.hass),
                host=host,
                port=port,
                token=user_input[CONF_TOKEN],
                use_tls=user_input.get(CONF_USE_TLS, False),
                verify_ssl=user_input.get(CONF_VERIFY_SSL, True),
            )

            try:
                await client.async_verify()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except UnsupportedSchema as err:
                _LOGGER.error("Unsupported agent schema: %s", err)
                errors["base"] = "unsupported_schema"
            except CannotConnect as err:
                _LOGGER.debug("Cannot connect to agent: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001 - config flows must not crash
                _LOGGER.exception("Unexpected error verifying agent")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title="Cyber Estate",
                    data={
                        **self._api_key_data,
                        **user_input,
                        CONF_HOST: host,
                        CONF_MODE: MODE_AGENT,
                    },
                )

        return self.async_show_form(
            step_id=MODE_AGENT, data_schema=STEP_AGENT, errors=errors
        )

    # -- NVD key rotation / reauth ---------------------------------------

    async def async_step_reauth(self, entry_data) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            err = await _validate_nvd_key(self.hass, user_input[CONF_API_KEY])
            if err:
                errors["base"] = err
            else:
                # data_updates MERGES into entry.data -- the scan half of
                # the entry is untouched.
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates={CONF_API_KEY: user_input[CONF_API_KEY]},
                )

        return self.async_show_form(
            step_id="reauth_confirm", data_schema=STEP_API_KEY, errors=errors
        )


class CyberEstateOptionsFlow(OptionsFlow):
    """KAN-294: acknowledge a MAC `unknown_hosts` cannot otherwise clear.

    A single field in `entry.options`, deliberately not touching `entry.data`
    at all -- the scan-mode config (local vs. agent) is a different concern
    with its own reconfigure path, and an options flow that rewrote both
    would risk exactly the "resubmit everything or lose a field" trap a
    wholesale-data options flow creates elsewhere in this estate. Read live
    by the coordinator every refresh (`_acknowledged_macs()`), so acking a
    host takes effect on the next tick, no reload required.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        current = self.config_entry.options.get(CONF_ACKNOWLEDGED_MACS, [])

        if user_input is not None:
            raw = [
                t.strip()
                for t in user_input.get(CONF_ACKNOWLEDGED_MACS, "").split(",")
                if t.strip()
            ]
            normalised: list[str] = []
            bad: list[str] = []
            for value in raw:
                mac = normalise_mac(value)
                if mac is None:
                    bad.append(value)
                else:
                    normalised.append(mac)
            if bad:
                errors[CONF_ACKNOWLEDGED_MACS] = "invalid_mac"
            else:
                return self.async_create_entry(
                    data={CONF_ACKNOWLEDGED_MACS: normalised}
                )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_ACKNOWLEDGED_MACS, default=", ".join(current)
                    ): str,
                }
            ),
            errors=errors,
        )
