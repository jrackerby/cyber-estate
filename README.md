# Cyber Monitor

Security posture for your network, as one Home Assistant config entry.

It merges what used to be three independent integrations — advisory feeds,
CVE lookups and network scanning — into one. That merge is the reason the
setup path behaves the way it does:

- **feeds** and **cve** coordinators *never* raise. An unreadable source is a
  disposition the entities report, not a setup failure.
- **scan** *can* raise `ConfigEntryNotReady` — it needs the `nmap` binary.

Because all three now share a single config entry, a scan failure retries the
**whole** entry, including the two halves that always succeed. That is a real
behaviour change from three separate integrations and was accepted knowingly:
one entry has one setup lifecycle by construction.

## What it creates

Platforms: `button`, `sensor`, `switch`.

- **feeds** — advisory/alert feeds, timezone-correct. `feeds/feedparse.py`
  resolves feed timezone *abbreviations* from an explicit table rather than by
  matching the host's local zone, which is what dateutil does by default and
  which silently mis-ordered entries on any host outside the feed's zone.
- **cve** — NVD lookups against the inventory it builds.
- **scan** — nmap sweeps, unknown-host detection, MAC acknowledgement.

## Configuration

Config flow, single entry. Asks for the scan targets and the NVD API key;
optionally an exclude list, a data directory, stale-host thresholds, SSH
credentials for authenticated collection, TLS/verification flags, and a list of
already-acknowledged MACs.

**Options** (*Configure* on the entry) edit what is safe to change while it
runs, one concern per step: the networks to scan and the addresses to leave
alone, how often each local sweep runs, and the acknowledged MACs. Each step
saves on its own, takes effect on the scanner's next tick, and neither reloads
the integration nor touches the scan history — so a subnet can be added without
losing the date every device was first seen.

Scan scope and the sweep clocks apply to LOCAL mode only. With a separate
scanner agent, the targets live in that host's own `scan.sh` and the schedule in
its `nmap-scan@<profile>.timer` units; the agent's v1 API exposes no interval,
so those steps are not offered rather than offered and ignored.

Requires `feedparser` and `python-dateutil`, declared in the manifest and
installed by Home Assistant.

## Install

**Via HACS.** HACS → ⋮ → *Custom repositories* → `https://github.com/jrackerby/ha-cyber-monitor`,
category **Integration**. Install, restart Home Assistant, then add it under
*Settings → Devices & Services → Add Integration → "Cyber Monitor"*.

The integration lives at the repository **root**, not under
`custom_components/`. `hacs.json` declares `content_in_root: true`, so HACS
copies the root into `/config/custom_components/cyber_estate/`.

## Development

Issues and feature requests: **[jrackerby/ha-cyber-monitor/issues](https://github.com/jrackerby/ha-cyber-monitor/issues)**.

CI runs [hassfest](https://developers.home-assistant.io/blog/2020/04/16/hassfest)
and HACS validation on every push. hassfest scans `custom_components/*` and
takes no path argument, so `.github/workflows/validate.yml` stages this repo
into that layout before invoking it; the repo itself stays root-layout because
`hacs.json` declares `content_in_root: true`.

Pushing a `manifest.json` whose `version` has changed tags and publishes a
release automatically — that is the only supported way to cut one.
