"""Constants for the network inventory integration.

NOTHING HERE MAY BE SPECIFIC TO ONE INSTALLATION. This integration is intended
for distribution, so every address, credential and interval is config-entry
data rather than a constant. A hard-coded host is the line that makes an
integration unpublishable, and it is always added "just for now".
"""

from __future__ import annotations

from datetime import timedelta

# KAN-344 MERGE: was DOMAIN under the standalone network_inventory
# integration. This subpackage no longer owns a manifest/config entry --
# cyber_estate's top-level const.py does. Files that need the REAL owning
# domain (service registration/lookup, device-registry identifiers checked
# by async_remove_config_entry_device) import DOMAIN from ..const instead.
# SCAN_NS is kept only as cosmetic naming text where nothing cross-checks
# it against a live domain.
SCAN_NS = "network_inventory"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_TOKEN = "token"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_TLS = "use_tls"

# WHICH END DOES THE SCANNING. One component, two modes, taken from config --
# never two components and never a fork. `agent` talks to a remote scanner over
# HTTP; `local` runs nmap in this container. Both are kept because the migration
# between them has to be reversible: the remote scanner holds the only copy of
# several months of `first_seen` history, and a one-way switch would make
# rolling back cost that history.
CONF_MODE = "mode"
MODE_AGENT = "agent"
MODE_LOCAL = "local"

# Local-mode scanning.
CONF_TARGETS = "targets"
CONF_EXCLUDE = "exclude"
CONF_DATADIR = "datadir"
CONF_STALE_DAYS = "stale_days"

# Local-mode SSH reachability probe.
CONF_SSH_ENABLED = "ssh_probe_enabled"
CONF_SSH_KEY = "ssh_key"
CONF_SSH_USERS = "ssh_users"

# KAN-294: options-flow field, mode-independent -- a MAC Joel has explicitly
# decided is accounted for (e.g. a multi-NIC device's ARP-visible interface),
# stored in entry.options so unknown_hosts can reach zero for a real,
# explained case without being silently filtered (see join.py's JoinResult).
CONF_ACKNOWLEDGED_MACS = "acknowledged_macs"

DEFAULT_PORT = 8765
DEFAULT_NAME = "Network Inventory"

# The estate's own conventions, offered as defaults so the common case is one
# confirmation rather than four lookups. Every one is overridable; none is
# hard-coded anywhere else (see the header).
DEFAULT_SSH_KEY = "/config/.ssh/kiosk_key"
DEFAULT_SSH_USERS = "kiosk, root"
DEFAULT_STALE_DAYS = 30

# How long a host may go unseen before its record is forgotten. Deliberately
# generous: a device switched off for a fortnight is normal, and forgetting it
# destroys `first_seen`, which cannot be recovered by scanning harder.
MIN_STALE_DAYS = 1

# The agent's API version this client speaks. The agent reports its own
# `schema_version` in every payload and the two are compared on every refresh,
# not merely at setup: an agent can be upgraded underneath a running Home
# Assistant, and a silent shape change is the failure mode this guards.
SUPPORTED_SCHEMA_VERSION = 1

# Scans are hourly at their most frequent, so polling faster only burns
# requests. The agent supports conditional GETs, so a poll between scans
# transfers nothing but headers.
UPDATE_INTERVAL = timedelta(minutes=10)

REQUEST_TIMEOUT = 30

# LOCAL MODE RUNS TWO DIFFERENT SWEEPS ON TWO DIFFERENT CLOCKS, and conflating
# them is the defect this estate already paid for once. A liveness sweep is
# cheap and answers "what is on the network"; a service scan is expensive and
# answers "what is it running". Running the cheap one often and the expensive
# one rarely is correct -- what is NOT correct is letting the cheap one's
# freshness stand in for the expensive one's, which is why they are timed,
# stamped and reported separately all the way up to the sensors.
LOCAL_DISCOVERY_INTERVAL = timedelta(hours=1)
LOCAL_SERVICE_INTERVAL = timedelta(hours=24)

# The coordinator's own tick in local mode. It does NOT scan on every tick; it
# checks whether either sweep is due. Short enough that an on-demand scan's
# results reach the entities promptly.
LOCAL_TICK = timedelta(minutes=5)

# The SSH probe runs against every host seen offering ssh. Kept well apart from
# the scan clocks: it is cheap, but it authenticates against real hosts, and
# doing that every five minutes would fill authentication logs estate-wide.
SSH_PROBE_INTERVAL = timedelta(hours=6)

# Scan profiles the agent will accept. Mirrored from the agent's own allowlist
# rather than discovered, because a button for a profile the agent rejects is a
# control that looks live and does nothing. The agent validates independently;
# this copy exists so the UI cannot offer an action that cannot succeed.
PROFILES: tuple[str, ...] = ("discovery", "standard", "deep")

# What an endpoint reports when nmap could not fingerprint it. A BLANK IS NOT
# ACCEPTABLE HERE: an empty state is indistinguishable from a sensor that
# failed to read, and "we looked and could not tell" is a different fact from
# "we do not know whether we looked".
OS_UNDETERMINED = "Undetermined"

# Home Assistant refuses a state longer than 255 characters, and an nmap
# osmatch string can run long when it lists alternatives. Truncated with a
# marker so a clipped value cannot read as a complete one.
MAX_STATE_LEN = 255

# Entity attributes are capped HERE rather than by asking the recorder to
# exclude the entity. Excluding stops history for the value as well as the
# detail, which quietly removes the ability to ask "how long has this been
# true" of the one number that matters. A cap keeps the trend and drops only
# the long tail.
MAX_DETAIL = 25

# How stale port data may get before the port-scanning profile is considered
# to have stopped running. The discovery sweep runs hourly and observes no
# ports at all; only the deeper profiles do, and those are typically nightly.
# Two days therefore clears one missed nightly run without hiding a dead one.
PORT_DATA_STALE_AFTER = timedelta(days=2)
