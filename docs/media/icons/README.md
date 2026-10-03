# Icons

Stroke icons on a 24 × 24 grid, stroke 1.75, round caps and joins, coloured from the ANet palette. Specification, colours and usage: [ANet brand guide](https://github.com/ANetResearch/ANet/blob/main/docs/BRAND.md).

| Folder | Use |
|---|---|
| `light/`, `dark/` | Coloured for light and dark pages; pair them in a `<picture>` so GitHub shows the one for the reader's theme. |
| `tile/` | The icon on its own dark rounded tile, 48 × 48: one file that reads on both themes. |

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/icons/dark/e2ee.svg">
  <img src="docs/media/icons/light/e2ee.svg" width="24" height="24" alt="">
</picture>
```

| File | Meaning | Source |
|---|---|---|
| `a2a.svg` | A2A interoperability | Lucide `arrow-left-right` |
| `e2ee.svg` | End-to-end encryption | Lucide `message-square-lock` |
| `hub-relay.svg` | Hub only relays | Lucide `route` |
| `sealed-sender.svg` | Sender hidden from the hub | Lucide `hat-glasses` |
| `receipt.svg` | Delivery receipts | Lucide `check-check` |
| `payment.svg` | Payments (a2a-x402) | Lucide `circle-dollar-sign` |
| `federation.svg` | Federated hubs | Lucide `network` |
| `admission.svg` | Admission | Lucide `ticket-check` |
| `stream.svg` | Streaming preview | Lucide `message-square-more` |
| `docs.svg` | Documentation | Lucide `book-open-text` |
| `github.svg` | GitHub | Tabler Icons `brand-github` |
| `ok.svg` | Success | Lucide `circle-check` |
| `fail.svg` | Failure | Lucide `circle-x` |
| `warn.svg` | Warning | Lucide `triangle-alert` |

## Sources and licences

The shapes come from open-source icon sets; we recoloured them and set the stroke width. Each SVG names its source in a comment, and the licence texts are in [`LICENSES/`](LICENSES/). Keep that folder with the icons when you copy them.

- **Lucide** v1.51.0: ISC License, Copyright (c) 2026 Lucide Icons and Contributors. Some Lucide glyphs derive from **Feather**: MIT License, Copyright (c) 2013-present Cole Bemis. Both notices: [`LICENSES/lucide.txt`](LICENSES/lucide.txt).
- **Tabler Icons** v3.48.0 (`github.svg` only): MIT License, Copyright (c) 2020-2026 Paweł Kuna. [`LICENSES/tabler-icons.txt`](LICENSES/tabler-icons.txt).
- **morphicons** v1.7.1: MIT License, Copyright (c) 2026 Guillermo. It is the engine chosen for icon transitions on ANet's web pages. [`LICENSES/morphicons.txt`](LICENSES/morphicons.txt).

The GitHub mark is a trademark of GitHub; the icon licence grants no trademark rights. We use it only to link to our repositories.
