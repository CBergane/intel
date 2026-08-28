# Self-hosted ransomware map assets

The ransomware map is deliberately independent of hosted map services. Browser
requests use only Django static assets and the ransomware live JSON endpoint.

## Geography

`static/intel/maps/world-countries-110m.geojson` is generated from
`world-atlas@2.0.2`'s `countries-110m.json`. That package redistributes Natural
Earth vector data version 4.1.0. The selected Admin 0 dataset is the quantized,
small-scale 1:110m edition; it is appropriate for a world overview and avoids a
street-map-sized payload.

- Natural Earth geography: public domain
- `world-atlas@2.0.2`: ISC
- `topojson-client@3.1.0`: ISC
- ISO identity metadata from `i18n-iso-countries@7.14.0`: MIT

The world-atlas redistribution notice is retained verbatim at
`static/intel/maps/WORLD-ATLAS-LICENSE.txt`; MapLibre and HTMX license texts are
likewise bundled beside their vendored static distributions.

The build converts the package's TopoJSON to GeoJSON, replaces numeric feature
IDs with stable ISO alpha-3 IDs where available, and emits the matching Python
country manifest at `intel/data/ransomware_map_countries.json`. Kosovo uses the
commonly used `XKX` user-assigned identifier. Natural Earth geometries without
an ISO identity keep an explicit `NE-*` identifier. No fuzzy matching is used.

Required map attribution is displayed below the map and in MapLibre's compact
attribution control:

> Map rendering: MapLibre GL JS 4.7.1. Geography: Natural Earth 4.1.0,
> 1:110m, public domain.

## Browser libraries

- `maplibre-gl@4.7.1`: BSD-3-Clause
- `htmx.org@1.9.12`: 0BSD

The exact package versions are locked in `package-lock.json`. The build copies
the distributable JavaScript, CSS, and license texts to `static/vendor/`.
PMTiles is intentionally not included: a local GeoJSON source is smaller and
simpler for the page's country-level interaction, and requires no tile protocol.

## Rebuilding

Run:

```sh
npm ci
npm run build
```

`npm run build:static` generates/copies the map assets; `npm run build:css`
rebuilds the tracked Tailwind artifact. Generated static assets are committed so
the production Python container can run `collectstatic` without Node.js. The
container build verifies the critical local files before collecting them.
