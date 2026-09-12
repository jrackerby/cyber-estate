# Brand marks

The mark is a Home Assistant house drawn around a security shield: the house
says where this runs, the shield says what it does. The shield splits the
component's two halves down the middle — routed circuit traces ending in nodes
for *what is on the network*, a keyhole for *what is being protected* — and a
short trace grounds the shield to the floor of the house rather than leaving it
floating inside it.

Everything here is **original artwork**, drawn as code in `generate.py` and
committed alongside the files it produces. It is not Home Assistant's logo and
is not derived from any third-party asset; the house silhouette and the two
brand colours are the deliberate visual reference to Home Assistant, nothing
more. Same MIT licence as the rest of the repository.

## Files

| File | Size | What it is for |
| --- | --- | --- |
| `icon.svg` | 512² | Source for both icons. |
| `icon.png` | 256×256 | **The HACS brands check reads this exact path.** Also the size `home-assistant/brands` requires. |
| `icon@2x.png` | 512×512 | The `@2x` that `home-assistant/brands` requires beside it. |
| `logo.svg` / `logo.png` / `logo@2x.png` | 512×140, 1024×280 | Horizontal lockup for light backgrounds. |
| `logo-dark.svg` / `logo-dark.png` / `logo-dark@2x.png` | same | Dark-background lockup. The slate word drops to near-white; **the light lockup's "Cyber" is unreadable on a dark ground**, which is the whole reason this variant exists. |

All PNGs are transparent RGBA.

## Palette

| Role | Hex |
| --- | --- |
| Home Assistant blue | `#18BCF2` |
| Home Assistant slate | `#44739E` |
| Keyline, traces, keyhole | `#ffffff` |
| Wordmark ink, dark variant | `#E7EEF5` |

## Two separate places a brand image is read from, and only one of them is here

- **HACS's brands check** reads `brand/icon.png` out of this repository —
  `content_in_root` in `hacs.json` is what puts it at the root rather than
  under a component directory. Committing this file is what lets
  `.github/workflows/validate.yml` stop ignoring that check.
- **The Home Assistant frontend** does not read this repository at all. It
  loads `https://brands.home-assistant.io/<domain>/icon.png`, so the icon shows
  up beside the integration in the UI only after a PR against
  `home-assistant/brands` lands `icon.png` and `icon@2x.png` under
  **`custom_integrations/cyber_estate/`** — the *domain*, which is
  `cyber_estate` and not the repository name. That PR has not been opened.

## Regenerating

Optional; every output is committed.

```sh
pip install fonttools pillow
python3 brand/generate.py --chrome /path/to/chromium   # or --svg-only
```

Wordmark glyphs are converted to paths, so the lockup does not depend on a font
being installed wherever it is rendered — an SVG logo carrying a live `<text>`
element is a different logo on every host that opens it.
