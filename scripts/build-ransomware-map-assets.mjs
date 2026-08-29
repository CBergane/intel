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

const coordinateEpsilon = 1e-9;
const representativeCountryIds = ["USA", "GBR", "DEU", "ITA", "MEX", "BRA", "IND"];
const expectedAntimeridianCountryIds = new Set(["FJI", "RUS", "ATA"]);
const normalizedAntimeridianCountryIds = new Set();

const coordinatesEqual = (left, right) =>
    Math.abs(left[0] - right[0]) <= coordinateEpsilon &&
    Math.abs(left[1] - right[1]) <= coordinateEpsilon;

const closeRing = (coordinates) => {
    if (!coordinates.length) return [];
    const closed = [...coordinates];
    if (!coordinatesEqual(closed[0], closed.at(-1))) {
        closed.push([...closed[0]]);
    }
    return closed;
};

const deduplicateAdjacentCoordinates = (coordinates) =>
    coordinates.filter(
        (coordinate, index) =>
            index === 0 || !coordinatesEqual(coordinate, coordinates[index - 1]),
    );

const signedRingArea = (ring) => {
    let area = 0;
    for (let index = 0; index < ring.length - 1; index += 1) {
        const current = ring[index];
        const next = ring[index + 1];
        area += current[0] * next[1] - next[0] * current[1];
    }
    return area / 2;
};

const unwrapRingLongitudes = (ring) => {
    const openRing = coordinatesEqual(ring[0], ring.at(-1)) ? ring.slice(0, -1) : [...ring];
    if (!openRing.length) return [];
    const unwrapped = [[...openRing[0]]];
    for (const coordinate of openRing.slice(1)) {
        let longitude = coordinate[0];
        const previousLongitude = unwrapped.at(-1)[0];
        while (longitude - previousLongitude > 180) longitude -= 360;
        while (longitude - previousLongitude < -180) longitude += 360;
        unwrapped.push([longitude, coordinate[1]]);
    }
    return unwrapped;
};

const clipCoordinatesAtLongitude = (coordinates, boundary, keepGreater) => {
    if (!coordinates.length) return [];
    const clipped = [];
    const isInside = (coordinate) =>
        keepGreater
            ? coordinate[0] >= boundary - coordinateEpsilon
            : coordinate[0] <= boundary + coordinateEpsilon;
    const intersection = (start, end) => {
        const deltaLongitude = end[0] - start[0];
        if (Math.abs(deltaLongitude) <= coordinateEpsilon) {
            return [boundary, end[1]];
        }
        const ratio = (boundary - start[0]) / deltaLongitude;
        return [boundary, start[1] + ratio * (end[1] - start[1])];
    };

    let previous = coordinates.at(-1);
    let previousInside = isInside(previous);
    for (const current of coordinates) {
        const currentInside = isInside(current);
        if (currentInside !== previousInside) {
            clipped.push(intersection(previous, current));
        }
        if (currentInside) clipped.push(current);
        previous = current;
        previousInside = currentInside;
    }
    return deduplicateAdjacentCoordinates(clipped);
};

const clipRingToLongitudeRange = (ring, minimumLongitude, maximumLongitude) => {
    const clippedMinimum = clipCoordinatesAtLongitude(ring, minimumLongitude, true);
    return clipCoordinatesAtLongitude(clippedMinimum, maximumLongitude, false);
};

const normalizeRingWinding = (ring, expectedAreaSign) => {
    const area = signedRingArea(ring);
    if (area === 0 || Math.sign(area) === expectedAreaSign) return ring;
    const openRing = ring.slice(0, -1).reverse();
    return closeRing(openRing);
};

const normalizeGeometryWinding = (geometry, countryName) => {
    const polygons = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
    const normalizedPolygons = polygons.flatMap((polygon) => {
        const [outerRing, ...holes] = polygon;
        if (Math.abs(signedRingArea(outerRing)) <= coordinateEpsilon) return [];
        const normalizedHoles = holes.map((ring) => {
            if (Math.abs(signedRingArea(ring)) <= coordinateEpsilon) {
                throw new Error(`Country ${countryName} has a zero-area polygon hole.`);
            }
            return normalizeRingWinding(ring, -1);
        });
        return [[normalizeRingWinding(outerRing, 1), ...normalizedHoles]];
    });
    if (!normalizedPolygons.length) {
        throw new Error(`Country ${countryName} has no non-degenerate polygon geometry.`);
    }
    return {
        type: normalizedPolygons.length === 1 ? "Polygon" : "MultiPolygon",
        coordinates:
            normalizedPolygons.length === 1 ? normalizedPolygons[0] : normalizedPolygons,
    };
};

const splitAntimeridianRing = (ring, countryName) => {
    const unwrapped = unwrapRingLongitudes(ring);
    const longitudes = unwrapped.map((coordinate) => coordinate[0]);
    const minimumLongitude = Math.min(...longitudes);
    const maximumLongitude = Math.max(...longitudes);
    let clippingRing = unwrapped;
    const longitudeRanges = [];

    if (maximumLongitude - minimumLongitude >= 360 - coordinateEpsilon) {
        // Antarctica follows the complete date-line boundary. Split it at the
        // prime meridian and close its polar cap through the South Pole so the
        // generated boundary cannot cross the coastline.
        clippingRing = [
            ...unwrapped,
            [maximumLongitude, -90],
            [minimumLongitude, -90],
        ];
        longitudeRanges.push([-180, 0, 0], [0, 180, 0]);
    } else {
        const firstWorld = Math.floor((minimumLongitude + 180) / 360);
        const lastWorld = Math.floor((maximumLongitude + 180 - coordinateEpsilon) / 360);
        for (let world = firstWorld; world <= lastWorld; world += 1) {
            longitudeRanges.push([-180 + 360 * world, 180 + 360 * world, world]);
        }
    }

    const splitRings = longitudeRanges.flatMap(([minimum, maximum, world]) => {
        const clipped = clipRingToLongitudeRange(clippingRing, minimum, maximum);
        if (clipped.length < 3) return [];
        const shifted = clipped.map(([longitude, latitude]) => [
            Math.max(-180, Math.min(180, longitude - 360 * world)),
            latitude,
        ]);
        const closed = closeRing(deduplicateAdjacentCoordinates(shifted));
        if (closed.length < 4 || Math.abs(signedRingArea(closed)) <= coordinateEpsilon) {
            return [];
        }
        return [closed];
    });

    if (splitRings.length < 2) {
        throw new Error(`Could not split antimeridian geometry for ${countryName}.`);
    }
    return splitRings;
};

const ringHasAntimeridianEdge = (ring) => {
    for (let index = 1; index < ring.length; index += 1) {
        if (Math.abs(ring[index][0] - ring[index - 1][0]) > 180 + coordinateEpsilon) {
            return true;
        }
    }
    return false;
};

const segmentOrientation = (start, end, point) =>
    (end[0] - start[0]) * (point[1] - start[1]) -
    (end[1] - start[1]) * (point[0] - start[0]);

const segmentsProperlyIntersect = (leftStart, leftEnd, rightStart, rightEnd) => {
    const leftToRightStart = segmentOrientation(leftStart, leftEnd, rightStart);
    const leftToRightEnd = segmentOrientation(leftStart, leftEnd, rightEnd);
    const rightToLeftStart = segmentOrientation(rightStart, rightEnd, leftStart);
    const rightToLeftEnd = segmentOrientation(rightStart, rightEnd, leftEnd);
    return (
        leftToRightStart * leftToRightEnd < -coordinateEpsilon &&
        rightToLeftStart * rightToLeftEnd < -coordinateEpsilon
    );
};

const ringHasProperSelfIntersection = (ring) => {
    for (let left = 0; left < ring.length - 1; left += 1) {
        for (let right = left + 2; right < ring.length - 1; right += 1) {
            if (left === 0 && right === ring.length - 2) continue;
            if (
                segmentsProperlyIntersect(
                    ring[left],
                    ring[left + 1],
                    ring[right],
                    ring[right + 1],
                )
            ) {
                return true;
            }
        }
    }
    return false;
};

const normalizeAntimeridianGeometry = (geometry, countryId) => {
    const polygons = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
    const normalizedPolygons = polygons.flatMap((polygon) => {
        const [outerRing, ...holes] = polygon;
        if (!ringHasAntimeridianEdge(outerRing)) return [polygon];
        normalizedAntimeridianCountryIds.add(countryId);
        if (holes.length) {
            throw new Error(
                `Antimeridian polygon with holes requires explicit handling: ${countryId}.`,
            );
        }
        return splitAntimeridianRing(outerRing, countryId).map((ring) => [ring]);
    });
    return {
        type: normalizedPolygons.length === 1 ? "Polygon" : "MultiPolygon",
        coordinates:
            normalizedPolygons.length === 1 ? normalizedPolygons[0] : normalizedPolygons,
    };
};

const validateWorldCountries = (featureCollection) => {
    const seenIds = new Set();
    for (const countryFeature of featureCollection.features) {
        const countryId = String(countryFeature.properties?.country_id || "").trim();
        if (!countryId || seenIds.has(countryId)) {
            throw new Error(`Country geometry has a missing or duplicate country_id: ${countryId}.`);
        }
        seenIds.add(countryId);
        if (countryFeature.id !== countryId) {
            throw new Error(`Feature ID does not match country_id for ${countryId}.`);
        }

        const polygons =
            countryFeature.geometry?.type === "Polygon"
                ? [countryFeature.geometry.coordinates]
                : countryFeature.geometry?.type === "MultiPolygon"
                  ? countryFeature.geometry.coordinates
                  : null;
        if (!polygons?.length) {
            throw new Error(`Country ${countryId} has no Polygon/MultiPolygon geometry.`);
        }
        for (const polygon of polygons) {
            if (!polygon.length) throw new Error(`Country ${countryId} has an empty polygon.`);
            for (const [ringIndex, ring] of polygon.entries()) {
                if (ring.length < 4 || !coordinatesEqual(ring[0], ring.at(-1))) {
                    throw new Error(`Country ${countryId} has an empty or unclosed polygon ring.`);
                }
                for (const coordinate of ring) {
                    if (
                        coordinate.length < 2 ||
                        !Number.isFinite(coordinate[0]) ||
                        !Number.isFinite(coordinate[1]) ||
                        coordinate[0] < -180 ||
                        coordinate[0] > 180 ||
                        coordinate[1] < -90 ||
                        coordinate[1] > 90
                    ) {
                        throw new Error(`Country ${countryId} has an invalid coordinate.`);
                    }
                }
                if (ringHasAntimeridianEdge(ring)) {
                    throw new Error(`Country ${countryId} has an unsplit antimeridian ring.`);
                }
                if (
                    expectedAntimeridianCountryIds.has(countryId) &&
                    ringHasProperSelfIntersection(ring)
                ) {
                    throw new Error(`Country ${countryId} has a self-intersecting repaired ring.`);
                }
                const area = signedRingArea(ring);
                if (
                    Math.abs(area) <= coordinateEpsilon ||
                    (ringIndex === 0 && area < 0) ||
                    (ringIndex > 0 && area > 0)
                ) {
                    throw new Error(`Country ${countryId} has invalid RFC 7946 ring winding.`);
                }
            }
        }
    }
    for (const countryId of representativeCountryIds) {
        if (!seenIds.has(countryId)) {
            throw new Error(`Representative country geometry is missing: ${countryId}.`);
        }
    }
    if (
        normalizedAntimeridianCountryIds.size !== expectedAntimeridianCountryIds.size ||
        [...expectedAntimeridianCountryIds].some(
            (countryId) => !normalizedAntimeridianCountryIds.has(countryId),
        )
    ) {
        throw new Error(
            `Unexpected antimeridian country set: ${[
                ...normalizedAntimeridianCountryIds,
            ].join(", ")}.`,
        );
    }
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
const maplibreSourcePath = path.join(
    repositoryRoot,
    "node_modules",
    "maplibre-gl",
    "dist",
    "maplibre-gl.js",
);
const maplibreSource = await readFile(maplibreSourcePath, "utf8");
const maplibreBrowserBundle = maplibreSource.replace(
    /(?:\r?\n)?\/\/# sourceMappingURL=maplibre-gl\.js\.map\s*$/u,
    "",
);
if (
    maplibreBrowserBundle.includes("sourceMappingURL") ||
    maplibreBrowserBundle.includes("maplibre-gl.js.map")
) {
    throw new Error("Generated MapLibre bundle still references its source map.");
}

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
    countryFeature.geometry = normalizeGeometryWinding(
        normalizeAntimeridianGeometry(countryFeature.geometry, countryId),
        displayName,
    );

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

validateWorldCountries(worldCountries);

worldCountries.metadata = {
    source: "Natural Earth vector 4.1.0 via world-atlas 2.0.2",
    scale: "1:110m",
    license: "Public domain geography; world-atlas redistribution is ISC",
    geometry_processing:
        "RFC 7946 ring winding; antimeridian-safe Fiji, Russia, and Antarctica polygons",
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
    writeFile(
        path.join(maplibreDirectory, "maplibre-gl.js"),
        maplibreBrowserBundle,
        "utf8",
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
