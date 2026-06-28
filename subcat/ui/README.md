# subcat report UI

The screenshot-report front-end — React + Vite + Tailwind + [shadcn/ui](https://ui.shadcn.com)
(all MIT-licensed). It renders a gowitness-style gallery from a subcat scan.

End users do **not** need Node: the built single-file bundle is vendored at
`subcat/assets/report_ui.html` and loaded by `subcat/report.py`. You only need
this project to **change** the UI.

This folder is both the Vite project root and the source tree (flattened — the
`@` import alias resolves here).

## Develop

```bash
cd subcat/ui
npm install
npm run dev      # local dev server with hot reload
```

In dev there's no backend, so the app's API fetches fail — point it at a running
`subcat report serve` instance, or temporarily inject test data on `window`.

## Build & vendor (required for changes to take effect)

```bash
cd subcat/ui
npm run build                        # → subcat/ui/dist/index.html (single self-contained file)
cp dist/index.html ../assets/report_ui.html
```

`vite-plugin-singlefile` inlines all JS/CSS into one HTML file. It is served
verbatim by the report server at `/`, and the app consumes its JSON API:
`/api/scans`, `/api/scan/<id>`, `/scan/<id>/screenshots/<file>`, `/icons/<file>`.
Nothing is written to disk — the report is served live.

## Technology icons

`sync_icons.py` vendors the Wappalyzer icon set into `subcat/assets/icons/` and
regenerates `data/techIcons.json` (name → icon filename), aligned 1:1 with the
`icon` field in `subcat/fingerprints.json`:

```bash
python subcat/ui/sync_icons.py
```

## Data shape

See `lib/common.ts` (`Shot`, `ScanMeta`). It matches the JSON written by
`subcat/screenshot.py` (the per-scan `subcat_screenshots.json` index).
