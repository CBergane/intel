(() => {
    "use strict";

    const pageElement = document.getElementById("ransomware-map-page");
    const mapElement = document.getElementById("ransomware-map-view");
    if (!pageElement) return;

    const fallbackElement = document.getElementById("ransomware-map-fallback");
    const countryDataElement = document.getElementById("ransomware-map-country-data");
    const latestVictimsElement = document.getElementById("ransomware-latest-victims");
    const topCountriesElement = document.getElementById("ransomware-top-countries");
    const topGroupsElement = document.getElementById("ransomware-top-groups");
    const styleUrl = mapElement?.dataset.styleUrl || "";
    const geographyUrl = mapElement?.dataset.geographyUrl || "";
    const liveUrl = pageElement.dataset.liveUrl || "";
    const pollInterval = Math.max(
        Number.parseInt(pageElement.dataset.liveInterval || "25000", 10) || 25000,
        10000,
    );
    let currentCursor = Math.max(
        Number.parseInt(pageElement.dataset.liveCursor || "0", 10) || 0,
        0,
    );
    let map = null;
    let mapReady = false;
    let popup = null;
    let hoveredCountryId = "";
    let pollTimer = null;
    let pollInFlight = false;
    let activeCountryIds = new Set();
    let countryActivity = new Map();

    const countrySourceId = "ransomware-world-countries";
    const countryFillLayerId = "ransomware-country-fill";

    const createElement = (tagName, className = "", text = "") => {
        const element = document.createElement(tagName);
        if (className) element.className = className;
        if (text !== "") element.textContent = String(text);
        return element;
    };

    const safeUrl = (value, {internal = false} = {}) => {
        try {
            const parsed = new URL(String(value || ""), window.location.origin);
            if (internal && parsed.origin !== window.location.origin) return "";
            if (!internal && !["http:", "https:"].includes(parsed.protocol)) return "";
            return parsed.href;
        } catch (_error) {
            return "";
        }
    };

    const createLink = (href, className, text, {internal = false} = {}) => {
        const link = createElement("a", className, text);
        link.href = safeUrl(href, {internal}) || "#";
        return link;
    };

    const showFallback = (message) => {
        if (!fallbackElement) return;
        fallbackElement.textContent = message;
        fallbackElement.classList.remove("hidden");
    };

    const hideFallback = () => fallbackElement?.classList.add("hidden");

    const pulseClass = (element, className) => {
        if (!element) return;
        element.classList.remove(className);
        void element.offsetWidth;
        element.classList.add(className);
    };

    const relativeTimeLabel = (isoValue) => {
        if (!isoValue) return "";
        const date = new Date(isoValue);
        if (Number.isNaN(date.getTime())) return "";
        const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
        if (seconds < 45) return "just now";
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    };

    const setText = (id, nextValue) => {
        const element = document.getElementById(id);
        if (!element) return;
        const textValue = String(nextValue);
        if (element.textContent.trim() !== textValue) {
            element.textContent = textValue;
            pulseClass(element, "ransomware-live-metric--changed");
        }
    };

    const setStatus = (label, tone) => {
        const element = document.getElementById("ransomware-live-status");
        if (!element) return;
        element.textContent = label;
        element.classList.remove(
            "text-sky-100",
            "text-amber-100",
            "text-rose-100",
            "bg-sky-500/10",
            "bg-amber-500/10",
            "bg-rose-500/10",
            "border-sky-500/20",
            "border-amber-500/25",
            "border-rose-500/25",
        );
        if (tone === "warn") {
            element.classList.add("text-amber-100", "bg-amber-500/10", "border-amber-500/25");
        } else if (tone === "error") {
            element.classList.add("text-rose-100", "bg-rose-500/10", "border-rose-500/25");
        } else {
            element.classList.add("text-sky-100", "bg-sky-500/10", "border-sky-500/20");
        }
    };

    const renderEmpty = (container, message) => {
        container.replaceChildren(createElement("p", "text-sm text-slate-400", message));
    };

    const renderLatestVictims = (records, newIds = new Set()) => {
        if (!latestVictimsElement) return;
        setText("ransomware-latest-victims-count", `${records.length} shown`);
        if (!records.length) {
            renderEmpty(
                latestVictimsElement,
                "No ransomware victims matched the current window and filters.",
            );
            return;
        }

        const fragment = document.createDocumentFragment();
        records.forEach((record) => {
            const article = createElement(
                "article",
                `rounded-xl border border-line/80 bg-slate-950/40 p-2.5 xl:p-3${
                    newIds.has(record.id) ? " ransomware-live-row--new" : ""
                }`,
            );
            article.append(
                createLink(
                    record.url,
                    "block truncate text-sm font-medium text-white transition hover:text-sky-200",
                    record.victim_name,
                ),
                createElement("p", "mt-1 text-[11px] text-slate-500", relativeTimeLabel(record.activity_at)),
            );

            const badges = createElement("div", "mt-2.5 flex flex-wrap gap-1.5 text-[11px]");
            if (record.group_name) {
                badges.append(
                    createLink(
                        record.group_url,
                        "rounded-md border border-rose-500/20 bg-rose-500/10 px-2 py-1 text-rose-200 transition hover:border-rose-400/40 hover:text-rose-100",
                        record.group_name,
                        {internal: true},
                    ),
                );
            }
            if (record.country_url) {
                badges.append(
                    createLink(
                        record.country_url,
                        "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-emerald-200 transition hover:border-emerald-400/40 hover:text-emerald-100",
                        record.country,
                        {internal: true},
                    ),
                );
            } else {
                badges.append(
                    createElement(
                        "span",
                        "rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-amber-200",
                        "Country pending",
                    ),
                );
            }
            article.append(badges);
            if (record.excerpt) {
                article.append(
                    createElement(
                        "p",
                        "mt-2.5 truncate text-[11px] leading-5 text-slate-400",
                        record.excerpt,
                    ),
                );
            }
            fragment.append(article);
        });
        latestVictimsElement.replaceChildren(fragment);
    };

    const renderTopCountries = (rows, pulseCountries = new Set()) => {
        if (!topCountriesElement) return;
        setText("ransomware-top-countries-count", `${rows.length} shown`);
        if (!rows.length) {
            renderEmpty(
                topCountriesElement,
                "Victims are present, but current records do not expose a recognized country.",
            );
            return;
        }

        const fragment = document.createDocumentFragment();
        rows.forEach((row) => {
            const link = createLink(
                row.url,
                `block rounded-xl border p-3 transition ${
                    row.is_selected
                        ? "border-cyan-400/40 bg-cyan-500/10"
                        : "border-line/80 bg-slate-950/40 hover:border-sky-400/30 hover:bg-slate-950/60"
                }${pulseCountries.has(row.country_key) ? " ransomware-live-row--bump" : ""}`,
                "",
                {internal: true},
            );
            const heading = createElement("div", "flex items-start justify-between gap-3");
            const identity = createElement("div", "min-w-0");
            identity.append(
                createElement("p", "truncate text-sm font-medium text-white", row.country),
                createElement(
                    "p",
                    "mt-1 text-[11px] text-slate-500",
                    `${row.group_count} groups${row.latest_group_name ? ` · latest ${row.latest_group_name}` : ""}`,
                ),
            );
            const count = createElement("div", "shrink-0 text-right");
            count.append(
                createElement(
                    "p",
                    `text-xl font-semibold ${row.is_selected ? "text-cyan-100" : "text-white"}`,
                    row.record_count,
                ),
                createElement("p", "text-[10px] uppercase tracking-[0.18em] text-slate-500", "victims"),
            );
            heading.append(identity, count);
            link.append(heading);
            if (row.latest_victim_name) {
                link.append(
                    createElement("p", "mt-2.5 truncate text-[11px] text-slate-300", row.latest_victim_name),
                );
            }
            fragment.append(link);
        });
        topCountriesElement.replaceChildren(fragment);
    };

    const renderTopGroups = (rows, pulseGroups = new Set()) => {
        if (!topGroupsElement) return;
        setText("ransomware-top-groups-count", `${rows.length} shown`);
        if (!rows.length) {
            renderEmpty(topGroupsElement, "No group activity matched the current ransomware filters.");
            return;
        }

        const fragment = document.createDocumentFragment();
        rows.forEach((row) => {
            const link = createLink(
                row.url,
                `block rounded-xl border border-line/80 bg-slate-950/35 p-3 transition hover:border-sky-400/30 hover:bg-slate-950/55${
                    pulseGroups.has(row.group_key) ? " ransomware-live-row--bump" : ""
                }`,
                "",
                {internal: true},
            );
            const heading = createElement("div", "flex items-start justify-between gap-3");
            const identity = createElement("div", "min-w-0");
            identity.append(
                createElement("p", "truncate text-sm font-medium text-white", row.group_name),
                createElement(
                    "p",
                    "mt-1 text-[11px] text-slate-500",
                    `${row.record_count} victims${row.country_count ? ` · ${row.country_count} countries` : ""}`,
                ),
            );
            heading.append(
                identity,
                createElement("span", "text-[11px] text-slate-400", relativeTimeLabel(row.latest_activity_at)),
            );
            link.append(heading);

            const badges = createElement("div", "mt-2.5 flex flex-wrap gap-1.5 text-[11px]");
            if (row.latest_victim_name) {
                badges.append(
                    createElement(
                        "span",
                        "rounded-md border border-line/80 bg-slate-900/70 px-2 py-1 text-slate-200",
                        row.latest_victim_name,
                    ),
                );
            }
            if (row.latest_country) {
                badges.append(
                    createElement(
                        "span",
                        "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-emerald-200",
                        row.latest_country,
                    ),
                );
            }
            link.append(badges);
            fragment.append(link);
        });
        topGroupsElement.replaceChildren(fragment);
    };

    const parseInitialCountryData = () => {
        if (!countryDataElement) return [];
        try {
            const parsed = JSON.parse(countryDataElement.textContent);
            return Array.isArray(parsed) ? parsed : [];
        } catch (_error) {
            showFallback("Local map activity data could not be read. Use the country list to continue.");
            return [];
        }
    };

    const buildPopupContent = (country) => {
        const content = createElement("div");
        content.append(
            createElement("p", "ransomware-map-popup__eyebrow", "Ransomware activity"),
            createElement("p", "ransomware-map-popup__title", country.name),
            createElement(
                "p",
                "ransomware-map-popup__meta",
                `${country.record_count} victim${country.record_count === 1 ? "" : "s"} · ${country.group_count} group${country.group_count === 1 ? "" : "s"}`,
            ),
        );
        if (country.latest_group_name) {
            content.append(
                createElement(
                    "p",
                    "ransomware-map-popup__meta",
                    `Latest group: ${country.latest_group_name}`,
                ),
            );
        }
        if (country.latest_victim_name) {
            content.append(
                createElement(
                    "p",
                    "ransomware-map-popup__meta",
                    `Latest victim: ${country.latest_victim_name}`,
                ),
            );
        }
        return content;
    };

    const countryIdForFeature = (feature) =>
        String(feature?.id || feature?.properties?.country_id || "");

    const setHoverCountry = (countryId) => {
        if (!mapReady || hoveredCountryId === countryId) return;
        if (hoveredCountryId) {
            map.setFeatureState(
                {source: countrySourceId, id: hoveredCountryId},
                {hovered: false},
            );
        }
        hoveredCountryId = countryId;
        if (hoveredCountryId) {
            map.setFeatureState(
                {source: countrySourceId, id: hoveredCountryId},
                {hovered: true},
            );
        }
    };

    const updateMapCountries = (rows, liveCountryIds = new Set()) => {
        const normalizedRows = Array.isArray(rows) ? rows : [];
        countryActivity = new Map(
            normalizedRows.map((country) => [String(country.country_id || country.country_key), country]),
        );
        setText(
            "ransomware-plotted-countries-count",
            normalizedRows.length
                ? `${normalizedRows.length} mapped countries`
                : "Local world ready, waiting on recognized geography",
        );

        if (!mapReady) return;
        activeCountryIds.forEach((countryId) => {
            map.setFeatureState(
                {source: countrySourceId, id: countryId},
                {record_count: 0, selected: false, live: false},
            );
        });
        const nextActiveCountryIds = new Set();
        normalizedRows.forEach((country) => {
            const countryId = String(country.country_id || country.country_key || "");
            if (!countryId) return;
            nextActiveCountryIds.add(countryId);
            map.setFeatureState(
                {source: countrySourceId, id: countryId},
                {
                    record_count: Number(country.record_count) || 0,
                    selected: Boolean(country.is_selected),
                    live: liveCountryIds.has(countryId),
                },
            );
        });
        activeCountryIds = nextActiveCountryIds;
    };

    const extendBoundsWithCoordinates = (bounds, coordinates) => {
        if (!Array.isArray(coordinates)) return;
        if (
            coordinates.length >= 2 &&
            typeof coordinates[0] === "number" &&
            typeof coordinates[1] === "number"
        ) {
            bounds.extend([coordinates[0], coordinates[1]]);
            return;
        }
        coordinates.forEach((part) => extendBoundsWithCoordinates(bounds, part));
    };

    const focusInitialGeography = () => {
        if (!mapReady) return;
        const selectedCountry = [...countryActivity.values()].find((country) => country.is_selected);
        if (!selectedCountry) {
            map.fitBounds([[-180, -72], [180, 84]], {
                padding: window.innerWidth < 640 ? 8 : 24,
                duration: 0,
            });
            return;
        }
        const features = map.querySourceFeatures(countrySourceId);
        const selectedFeature = features.find(
            (feature) => countryIdForFeature(feature) === selectedCountry.country_id,
        );
        if (!selectedFeature) return;
        const bounds = new maplibregl.LngLatBounds();
        extendBoundsWithCoordinates(bounds, selectedFeature.geometry?.coordinates);
        if (!bounds.isEmpty()) {
            map.fitBounds(bounds, {
                padding: window.innerWidth < 640 ? 42 : 76,
                maxZoom: 4.2,
                duration: 0,
            });
        }
    };

    const addCountryLayers = () => {
        map.addSource(countrySourceId, {
            type: "geojson",
            data: geographyUrl,
            attribution: "Natural Earth 4.1.0 · public domain",
        });
        map.addLayer({
            id: "ransomware-country-base",
            type: "fill",
            source: countrySourceId,
            paint: {
                "fill-color": "#0b1623",
                "fill-opacity": 0.78,
            },
        });
        map.addLayer({
            id: countryFillLayerId,
            type: "fill",
            source: countrySourceId,
            paint: {
                "fill-color": [
                    "interpolate",
                    ["linear"],
                    ["coalesce", ["feature-state", "record_count"], 0],
                    0, "#0b1623",
                    1, "#0e7490",
                    3, "#d97706",
                    8, "#ea580c",
                    20, "#dc2626",
                    50, "#991b1b",
                ],
                "fill-opacity": [
                    "case",
                    ["boolean", ["feature-state", "selected"], false], 0.88,
                    [">", ["coalesce", ["feature-state", "record_count"], 0], 0], 0.72,
                    0.18,
                ],
            },
        });
        map.addLayer({
            id: "ransomware-country-boundaries",
            type: "line",
            source: countrySourceId,
            paint: {
                "line-color": [
                    "case",
                    ["boolean", ["feature-state", "selected"], false], "#a5f3fc",
                    ["boolean", ["feature-state", "hovered"], false], "#67e8f9",
                    [">", ["coalesce", ["feature-state", "record_count"], 0], 0], "#7dd3fc",
                    "#27364a",
                ],
                "line-opacity": [
                    "case",
                    [">", ["coalesce", ["feature-state", "record_count"], 0], 0], 0.9,
                    0.64,
                ],
                "line-width": [
                    "case",
                    ["boolean", ["feature-state", "selected"], false], 2.6,
                    ["boolean", ["feature-state", "hovered"], false], 1.8,
                    [">", ["coalesce", ["feature-state", "record_count"], 0], 0], 1.1,
                    0.6,
                ],
            },
        });

        map.on("mousemove", countryFillLayerId, (event) => {
            const feature = event.features?.[0];
            const countryId = countryIdForFeature(feature);
            const activity = countryActivity.get(countryId);
            map.getCanvas().style.cursor = activity ? "pointer" : "";
            setHoverCountry(activity ? countryId : "");
            if (!activity) {
                popup?.remove();
                return;
            }
            popup
                .setLngLat(event.lngLat)
                .setDOMContent(buildPopupContent(activity))
                .addTo(map);
        });
        map.on("mouseleave", countryFillLayerId, () => {
            map.getCanvas().style.cursor = "";
            setHoverCountry("");
            popup?.remove();
        });
        map.on("click", countryFillLayerId, (event) => {
            const countryId = countryIdForFeature(event.features?.[0]);
            const destination = safeUrl(countryActivity.get(countryId)?.url, {internal: true});
            if (destination) window.location.assign(destination);
        });
    };

    const applySnapshot = (
        snapshot,
        newIds = new Set(),
        newCountryIds = new Set(),
        newGroupKeys = new Set(),
    ) => {
        if (!snapshot?.summary) return;
        renderLatestVictims(snapshot.latest_victims || [], newIds);
        renderTopCountries(snapshot.top_countries || [], newCountryIds);
        renderTopGroups(snapshot.top_groups || [], newGroupKeys);
        setText("ransomware-summary-victim-count", snapshot.summary.victim_count);
        setText("ransomware-summary-country-count", snapshot.summary.country_count);
        setText("ransomware-summary-group-count", snapshot.summary.group_count);
        setText("ransomware-summary-countryless-count", snapshot.summary.countryless_count);
        setText("ransomware-active-countries-count", `${snapshot.summary.country_count} active countries`);
        updateMapCountries(
            snapshot.map_country_data || snapshot.map_marker_data || [],
            newCountryIds,
        );
    };

    const startPolling = () => {
        if (!liveUrl || pollTimer) return;
        pollTimer = window.setInterval(() => {
            if (pollInFlight) return;
            pollInFlight = true;
            setStatus("Syncing", "warn");
            const separator = liveUrl.includes("?") ? "&" : "?";
            fetch(`${liveUrl}${separator}cursor=${encodeURIComponent(currentCursor)}`, {
                headers: {Accept: "application/json"},
            })
                .then((response) => {
                    if (!response.ok) throw new Error(`live-${response.status}`);
                    return response.json();
                })
                .then((payload) => {
                    const events = payload.events || [];
                    const newIds = new Set(events.map((event) => event.id));
                    const newCountryIds = new Set(
                        events.map((event) => event.country_key).filter(Boolean),
                    );
                    const newGroupKeys = new Set(
                        events.map((event) => event.group_key).filter(Boolean),
                    );
                    currentCursor = Math.max(currentCursor, Number(payload.cursor) || 0);
                    pageElement.dataset.liveCursor = String(currentCursor);
                    applySnapshot(payload.snapshot || {}, newIds, newCountryIds, newGroupKeys);
                    setStatus(newIds.size ? `${newIds.size} new` : "Live", "ok");
                })
                .catch(() => setStatus("Retrying", "error"))
                .finally(() => {
                    pollInFlight = false;
                });
        }, pollInterval);
    };

    const initialCountryData = parseInitialCountryData();
    countryActivity = new Map(
        initialCountryData.map((country) => [String(country.country_id || country.country_key), country]),
    );

    if (window.maplibregl && mapElement && styleUrl && geographyUrl) {
        popup = new maplibregl.Popup({
            closeButton: false,
            closeOnClick: false,
            offset: 12,
        });
        map = new maplibregl.Map({
            container: mapElement,
            style: styleUrl,
            center: [12, 18],
            zoom: window.innerWidth < 640 ? 0.3 : 0.9,
            minZoom: 0,
            maxZoom: 5.5,
            attributionControl: false,
            dragRotate: false,
            touchPitch: false,
            renderWorldCopies: false,
        });
        map.addControl(new maplibregl.AttributionControl({compact: true}), "bottom-right");
        map.addControl(new maplibregl.NavigationControl({showCompass: false}), "top-right");

        const failTimer = window.setTimeout(() => {
            if (!mapReady) {
                showFallback("The local map could not initialize. Use the country list to continue.");
            }
        }, 9000);

        map.once("load", () => {
            addCountryLayers();
            mapReady = true;
            window.clearTimeout(failTimer);
            hideFallback();
            updateMapCountries(initialCountryData);
            map.once("idle", focusInitialGeography);
        });
        map.on("error", (event) => {
            if (event?.error) {
                showFallback("A local map asset failed to load. Use the country list to continue.");
            }
        });
    } else if (mapElement) {
        showFallback("Interactive map engine unavailable. Use the country list to continue.");
    }

    startPolling();
    window.addEventListener("pagehide", () => {
        if (pollTimer) window.clearInterval(pollTimer);
        popup?.remove();
        map?.remove();
    }, {once: true});
})();
