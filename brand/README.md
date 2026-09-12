# Brand marks

A padlock and a shield inside a house: the house says where this runs, the
shield says what it does, and the shield's two halves are the component's two
halves — circuit traces for *what is on the network*, a keyhole for *what is
protected*.

`source/logo-source.jpg` is the artwork **exactly as supplied**, and it is the
only thing here anyone should edit or replace. Every other file is derived from
it by `build.py` and committed, so the rasters are reproducible rather than
blobs nobody can diff.

## Files

| File | Size | Read by |
| --- | --- | --- |
| `source/logo-source.jpg` | 1024² | Nothing. It is the input. |
| `icon.png` | 256×256 | **The HACS brands check reads this exact path.** Also the size `home-assistant/brands` requires. |
| `icon@2x.png` | 512×512 | The `@2x` that `home-assistant/brands` requires beside it. |
| `logo.png` / `logo@2x.png` | 488×512, 976×1024 | This repository's README, and anywhere the full lockup is wanted. |
| `favicon.png` | 180² | Copied into `ha-dashboards-monitoring`'s `apps/cyber-security-monitor/public/`. Built here because the source lives here; that copy is the one the app serves. |

**The icon is the mark alone, without the wordmark.** HACS and the Home
Assistant sidebar both draw it small, and a 256px square asked to carry a
two-line wordmark renders the wordmark as grey mush.

## The white background is gone, and that cost the enclosed whites too

The source is a JPEG on a white page. `build.py` floods the background from the
border rather than treating white as transparent globally, because the artwork
draws in white as well — so a global rule cannot tell a matte from a keyline.

Every **enclosed** white then goes too: the inside of the shackle, the keyhole,
the trace nodes, the counters of the letters. All of them, not a chosen few. The
mark is two inks on a white page and a knockout keeps it that way on any page;
keeping the keyhole filled while the traces around it knock through is the one
result that is wrong on both grounds — a light page cannot tell the difference
either way, and a dark one shows a white keyhole floating in a shield whose own
outline has gone transparent.

The rim the original antialiased against white is solved rather than
thresholded: each such pixel is `a * ink + (1 - a) * white`, so its coverage
falls out by projection onto the nearest solid ink. Thresholding it away only
moves the halo one pixel inward.

The result is a single asset that reads on light and dark, so there is no
dark-mode variant and nothing to keep in sync.

## Palette

Taken from the artwork, not chosen: blue `#2AB7EC`, grey `#818181`. Note these
are **not** Home Assistant's own `#18BCF2` / `#44739E` — close, deliberately not
identical, and nothing here should be recoloured to match them.

## Home Assistant serves these itself. No `home-assistant/brands` PR is needed.

**This reverses what this file said when it was written**, which was that the
frontend reads only `brands.home-assistant.io` and the icon appears in the UI
only after a PR lands under `custom_integrations/cyber_estate/`. That was true
through HA 2026.2 and is not true now — the brands repository's own README
marks `custom_integrations` a **legacy folder** as of 2026.3.0.

Read out of `homeassistant/components/brands` rather than inferred:
`BrandsIntegrationView` serves `/api/brands/integration/{domain}/{image}` and
tries a custom integration's own files **first**, ahead of the CDN.

```python
if not integration.has_branding:
    return None
brand_dir = Path(integration.file_path) / "brand"
```

Three consequences worth knowing:

- **`has_branding` is `"brand" in self._top_level_files`** (`homeassistant/loader.py`).
  A directory named `brand`, and nothing else — no `manifest.json` key opts in,
  and none can opt out.
- **`ALLOWED_IMAGES` is exactly `icon.png`, `logo.png`, `icon@2x.png`,
  `logo@2x.png` and their `dark_` prefixes.** Anything else in this directory is
  never served; it is shipped weight and nothing more.
- **`content_in_root` puts this directory exactly where that code looks.** HACS
  installs the repository root to `custom_components/cyber_estate/`, so `brand/`
  lands at `custom_components/cyber_estate/brand/` — which is
  `Path(integration.file_path) / "brand"` verbatim.

So the same four files answer both readers:

- **HACS's brands check** reads `brand/icon.png` out of this repository at build
  time, which is what lets `.github/workflows/validate.yml` run that check
  instead of ignoring it.
- **The running instance** reads the same file off disk at request time.

`has_branding` is a `cached_property` and the custom-component set is cached at
load, so **a restart — not a reload — is what makes a newly added `brand/`
directory visible.** Shipping it is a release: HACS upgrades from releases, and
`release.yml` tags on a `manifest.json` version change.

## Rebuilding

Optional; every output is committed.

```sh
pip install pillow
python3 brand/build.py
```
