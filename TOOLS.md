# TOOLS

What the tooling does, refuses to do, and lies about, **for the instruments this
repository owns**. Every line is a claim with a timestamp: re-verify before
building a plan on one, and edit it when it stops being true. A capability is
not absent until validated absent.

Scope, so this file does not grow into a second copy of somebody else's:

- **Here**: instruments `cyber_estate` itself drives.
- **NOT here**: Home Assistant's own instrument surface — config entries,
  reloads, restarts, the recorder, the websocket API, `.storage`. Those belong
  to whichever repository owns the instrument, not to this one.
- **Never here**: a rule about how the work is done, rather than a fact about
  an instrument; a description of what currently exists, which goes stale
  faster than anything else in a file like this; and anything unresolved, which
  is an issue on this repository.

## nmap inside the HA core container
- **Present, privileged, NSE-STRIPPED**: `-sS`, `-sn`, `-O` work; `-sV` and `--script`
  fail (`nse_main.lua` missing). **`--datadir /config/nmap-data` restores both** from a
  copied NSE tree, and survives container rebuilds. A scan over 60s cannot run through
  `shell_command`; a custom component owning the subprocess can — which is what
  `scan/scanner.py` is, and why this trap sits in this repository rather than
  beside Home Assistant's own instruments.
