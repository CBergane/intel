import {copyFile, mkdir, readFile, writeFile} from "node:fs/promises";
import {createRequire} from "node:module";
import path from "node:path";
import {fileURLToPath} from "node:url";

import {feature as topojsonFeature} from "topojson-client";

const require = createRequire(import.meta.url);
const countries = require("i18n-iso-countries");
const englishLocale = require("i18n-iso-countries/langs/en.json");
countries.registerLocale(englishLocale);

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const staticMapDirectory = path.join(repositoryRoot, "static", "intel", "maps");
const countryDataDirectory = path.join(repositoryRoot, "intel", "data");
const maplibreDirectory = path.join(repositoryRoot, "static", "vendor", "maplibre");
const htmxDirectory = path.join(repositoryRoot, "static", "vendor", "htmx");

const displayNameOverrides = {
    COG: "Republic of the Congo",
    COD: "DR Congo",
    CZE: "Czechia",
    GBR: "United Kingdom",
    KOR: "South Korea",
    LAO: "Laos",
    MKD: "North Macedonia",
    PRK: "North Korea",
    RUS: "Russia",
    SWZ: "Eswatini",
    TUR: "Turkey",
    USA: "United States",
};

const nonIsoGeometryIds = {
    "N. Cyprus": "NE-NORTHERN-CYPRUS",
    Kosovo: "XKX",
    Somaliland: "NE-SOMALILAND",
};

const normalizedList = (values) => [
    ...new Set(
        values
            .flat()
            .filter((value) => typeof value === "string")
            .map((value) => value.trim())
            .filter(Boolean),
    ),
];

const topologyPath = path.join(
    repositoryRoot,
    "node_modules",
    "world-atlas",
    "countries-110m.json",
);
const topology = JSON.parse(await readFile(topologyPath, "utf8"));
const worldCountries = topojsonFeature(topology, topology.objects.countries);

const manifestCountries = worldCountries.features.map((countryFeature) => {
    const geometryName = String(countryFeature.properties?.name || "").trim();
    const rawNumericId = String(countryFeature.id ?? "").trim();
    const isoNumeric = /^\d+$/.test(rawNumericId)
        ? rawNumericId.padStart(3, "0")
        : "";
    const isoAlpha3 = isoNumeric ? countries.numericToAlpha3(isoNumeric) || "" : "";
    const isoAlpha2 = isoNumeric ? countries.numericToAlpha2(isoNumeric) || "" : "";
    const countryId =
        isoAlpha3 ||
        nonIsoGeometryIds[geometryName] ||
        `NE-${geometryName.toUpperCase().replace(/[^A-Z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
    const isoNames = isoAlpha2
        ? countries.getName(isoAlpha2, "en", {select: "all"}) || []
        : [];
    const displayName =
        displayNameOverrides[countryId] ||
        (isoAlpha2 ? countries.getName(isoAlpha2, "en") : "") ||
        geometryName;
    const aliases = normalizedList([displayName, geometryName, isoNames]);

    countryFeature.id = countryId;
    countryFeature.properties = {
        country_id: countryId,
        iso_a2: isoAlpha2,
        iso_a3: isoAlpha3,
        iso_n3: isoNumeric,
        name: displayName,
    };

    return {
        country_id: countryId,
        name: displayName,
        geometry_name: geometryName,
        iso_a2: isoAlpha2,
        iso_a3: isoAlpha3,
        iso_n3: isoNumeric,
        aliases,
    };
});

worldCountries.metadata = {
    source: "Natural Earth vector 4.1.0 via world-atlas 2.0.2",
    scale: "1:110m",
    license: "Public domain geography; world-atlas redistribution is ISC",
};

const manifest = {
    dataset: worldCountries.metadata,
    countries: manifestCountries.sort((left, right) =>
        left.name.localeCompare(right.name, "en"),
    ),
};

await Promise.all([
    mkdir(staticMapDirectory, {recursive: true}),
    mkdir(countryDataDirectory, {recursive: true}),
    mkdir(maplibreDirectory, {recursive: true}),
    mkdir(htmxDirectory, {recursive: true}),
]);

await Promise.all([
    writeFile(
        path.join(staticMapDirectory, "world-countries-110m.geojson"),
        `${JSON.stringify(worldCountries)}\n`,
        "utf8",
    ),
    writeFile(
        path.join(countryDataDirectory, "ransomware_map_countries.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
        "utf8",
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "maplibre-gl", "dist", "maplibre-gl.js"),
        path.join(maplibreDirectory, "maplibre-gl.js"),
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "maplibre-gl", "dist", "maplibre-gl.css"),
        path.join(maplibreDirectory, "maplibre-gl.css"),
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "maplibre-gl", "LICENSE.txt"),
        path.join(maplibreDirectory, "LICENSE.txt"),
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "world-atlas", "LICENSE"),
        path.join(staticMapDirectory, "WORLD-ATLAS-LICENSE.txt"),
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "htmx.org", "dist", "htmx.min.js"),
        path.join(htmxDirectory, "htmx.min.js"),
    ),
    copyFile(
        path.join(repositoryRoot, "node_modules", "htmx.org", "LICENSE"),
        path.join(htmxDirectory, "LICENSE.txt"),
    ),
]);

console.log(
    `Built ransomware map assets: ${worldCountries.features.length} country geometries, ` +
    "MapLibre GL JS 4.7.1, HTMX 1.9.12.",
);
