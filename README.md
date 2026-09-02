# Cyber Estate

Security posture for the estate, as one Home Assistant config entry.

KAN-344 merged three previously independent integrations — `estate_feeds`,
`nvd_estate` and `network_inventory` — into this one. The merge is the reason
the setup path behaves the way it does:

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
  which silently mis-ordered entries on any host outside the feed's zone
  (GH-478).
- **cve** — NVD lookups against the estate's own inventory.
- **scan** — nmap sweeps, unknown-host detection, MAC acknowledgement.

## Configuration

Config flow, single entry. Asks for the scan targets and the NVD API key;
optionally an exclude list, a data directory, stale-host thresholds, SSH
credentials for authenticated collection, TLS/verification flags, and a list of
already-acknowledged MACs.

Requires `feedparser` and `python-dateutil`, declared in the manifest and
installed by Home Assistant.

## Install

**Via HACS.** HACS → ⋮ → *Custom repositories* → `https://github.com/jrackerby/cyber-estate`,
category **Integration**. Install, restart Home Assistant, then add it under
*Settings → Devices & Services → Add Integration → "Cyber Estate"*.

The integration lives at the repository **root**, not under
`custom_components/`. `hacs.json` declares `content_in_root: true`, so HACS
copies the root into `/config/custom_components/cyber_estate/`.

> **That path has two owners today.** `jrackerby/HA` also submodules this repo
> as `custom_components/cyber_estate` and writes the same directory on deploy. Until
> that cutover is settled (jrackerby/HA#483), a HACS install and a `git push ha
> master` will fight over it — install here only if you are not deploying this
> component from `jrackerby/HA`.

## Development

Issues and the work queue live in **[jrackerby/HA](https://github.com/jrackerby/HA/issues)**,
not here — one queue for the whole estate.

CI runs [hassfest](https://developers.home-assistant.io/blog/2020/04/16/hassfest)
and HACS validation on every push. hassfest scans `custom_components/*` and
takes no path argument, so `.github/workflows/validate.yml` stages this repo
into that layout before invoking it; the repo itself stays root-layout because
`jrackerby/HA` submodules it at that path.

Pushing a `manifest.json` whose `version` has changed tags and publishes a
release automatically — that is the only supported way to cut one.
