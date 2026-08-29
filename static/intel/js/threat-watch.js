(() => {
    "use strict";

    const page = document.getElementById("threat-watch-page");
    if (!page) return;

    const surfaceMode = page.dataset.surfaceMode || "actors";
    const mapElement = document.getElementById("threat-watch-map-view");
    const mapFallback = document.getElementById("threat-watch-map-fallback");
    const countryDataElement = document.getElementById("threat-watch-country-data");
    const incomingList = document.getElementById("threat-watch-incoming-list");
    const actorSurface = document.getElementById("threat-watch-actor-surface");
    const topActors = document.getElementById("threat-watch-top-actors");
    const countryList = document.getElementById("threat-watch-country-list");
    const sourceCoverage = document.getElementById("threat-watch-source-coverage");
    const pollUrl = page.dataset.pollUrl || "";
    const pollInterval = Math.max(
        Number.parseInt(page.dataset.liveInterval || "25000", 10) || 25000,
        10000,
    );
    let cursor = Math.max(Number.parseInt(page.dataset.liveCursor || "0", 10) || 0, 0);
    let pollTimer = null;
    let pollInFlight = false;

    let map = null;
    let mapReady = false;
    let popup = null;
    let hoveredCountryId = "";
    let countryActivity = new Map();
    let appliedCountryIds = new Set();
    let geometryCountryIds = new Set();
    const countrySourceId = "threat-watch-world-countries";
    const countryFillLayerId = "threat-watch-country-fill";

    const createElement = (tagName, className = "", text = "") => {
        const element = document.createElement(tagName);
        if (className) element.className = className;
        if (text !== "") element.textContent = String(text);
        return element;
    };

    const safeInternalUrl = (value) => {
        try {
            const parsed = new URL(String(value || ""), window.location.origin);
            return parsed.origin === window.location.origin && ["http:", "https:"].includes(parsed.protocol)
                ? parsed.href
                : "";
        } catch (_error) {
            return "";
        }
    };

    const createInternalLink = (href, className = "") => {
        const link = createElement("a", className);
        link.href = safeInternalUrl(href) || "#";
        return link;
    };

    const relativeTime = (value) => {
        const timestamp = Date.parse(value || "");
        if (Number.isNaN(timestamp)) return "";
        const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
        if (seconds < 45) return "just now";
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    };

    const countLabel = (count, singular, plural = `${singular}s`) =>
        `${count} ${Number(count) === 1 ? singular : plural}`;

    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    };

    const renderEmpty = (container, message) => {
        if (!container) return;
        container.replaceChildren(createElement("p", "text-sm leading-6 text-slate-400", message));
    };

    const status = (text, tone = "ok") => {
        const element = document.getElementById("threat-watch-live-status");
        if (!element) return;
        element.textContent = text;
        element.classList.toggle("text-amber-100", tone === "warn");
        element.classList.toggle("text-rose-100", tone === "error");
        element.classList.toggle("text-cyan-100", tone === "ok");
    };

    const renderIncoming = (rows, newIds = new Set()) => {
        if (!incomingList) return;
        setText("threat-watch-incoming-count", `${rows.length} shown`);
        if (!rows.length) {
            renderEmpty(incomingList, "No incoming activity in the selected window.");
            return;
        }
        const fragment = document.createDocumentFragment();
        rows.forEach((row) => {
            const article = createElement(
                "article",
                `threat-watch-activity-row${row.is_watch_match ? " threat-watch-activity-row--matched" : ""}${newIds.has(row.id) ? " threat-watch-live-row--new" : ""}`,
            );
            article.dataset.hitId = String(row.id);
            const statusLine = createElement("div", "flex items-center justify-between gap-2");
            statusLine.append(
                createElement(
                    "span",
                    `text-[10px] font-semibold uppercase tracking-[0.16em] ${row.is_watch_match ? "text-cyan-200" : "text-slate-500"}`,
                    row.is_watch_match ? "Watch Match" : "Context",
                ),
            );
            const time = createElement("time", "shrink-0 text-[10px] text-slate-500", relativeTime(row.last_seen_at));
            time.dateTime = row.last_seen_at || row.detected_at || "";
            statusLine.append(time);
            article.append(statusLine);
            if (row.group_name) article.append(createElement("p", "mt-2 break-words text-sm font-semibold text-white", row.group_name));
            article.append(createElement("p", `mt-1 break-words text-sm leading-5 ${row.group_name ? "text-slate-300" : "font-medium text-white"}`, row.signal_title || row.title));
            const metadata = [row.source_name, row.signal_label, row.country].filter(Boolean).join(" · ");
            article.append(createElement("p", "mt-2 break-words text-[11px] leading-5 text-slate-500", metadata));
            if (row.excerpt) article.append(createElement("p", "mt-2 line-clamp-2 break-words text-xs leading-5 text-slate-400", row.excerpt));
            const rawLink = createInternalLink(row.raw_url, "mt-2 inline-flex text-[11px] text-sky-200 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70");
            rawLink.textContent = "Inspect raw context";
            article.append(rawLink);
            fragment.append(article);
        });
        incomingList.replaceChildren(fragment);
    };

    const actorRow = (row, {detailed = false} = {}) => {
        const link = createInternalLink(
            row.url,
            detailed
                ? `threat-watch-actor-row${row.watch_match_count ? " threat-watch-actor-row--matched" : ""}`
                : `block rounded-xl border p-3 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 ${row.country_match ? "border-cyan-500/30 bg-cyan-500/10" : row.watch_match_count ? "border-sky-500/25 bg-sky-500/5" : "border-line/80 bg-slate-950/35 hover:border-slate-600"}`,
        );
        if (detailed) {
            const bar = createElement("span", "threat-watch-actor-bar");
            bar.style.width = `${Math.min(100, Math.max(0, Number(row.activity_ratio) || 0))}%`;
            bar.setAttribute("aria-hidden", "true");
            link.append(bar);
        }
        const content = createElement("span", `${detailed ? "relative " : ""}flex min-w-0 items-start justify-between gap-3`);
        const identity = createElement("span", "min-w-0");
        identity.append(
            createElement("span", "block break-words text-sm font-semibold text-white", row.group_name),
            createElement(
                "span",
                "mt-1 block break-words text-[11px] leading-5 text-slate-400",
                `${countLabel(row.record_count, "record")} · ${countLabel(row.source_count, "source")}${row.watch_match_count ? ` · ${countLabel(row.watch_match_count, "watch match", "watch matches")}` : ""}`,
            ),
        );
        identity.append(createElement("span", "mt-1.5 block break-words text-[11px] text-slate-500", row.countries?.length ? `Observed: ${row.countries.join(", ")}` : "No geographic evidence"));
        const time = createElement("time", "shrink-0 text-[10px] text-slate-500", relativeTime(row.latest_activity_at));
        time.dateTime = row.latest_activity_at || "";
        content.append(identity, time);
        link.append(content);
        return link;
    };

    const renderActors = (rows) => {
        setText("threat-watch-actor-count", `${rows.length} shown`);
        if (actorSurface && surfaceMode === "actors") {
            if (rows.length) {
                const fragment = document.createDocumentFragment();
                rows.forEach((row) => fragment.append(actorRow(row, {detailed: true})));
                actorSurface.replaceChildren(fragment);
            } else {
                renderEmpty(actorSurface, "No actor identities matched the current filters.");
            }
        }
        if (!topActors) return;
        if (!rows.length) {
            renderEmpty(topActors, "No actor identities matched the current filters.");
            return;
        }
        const fragment = document.createDocumentFragment();
        rows.slice(0, 6).forEach((row) => fragment.append(actorRow(row)));
        topActors.replaceChildren(fragment);
    };

    const renderCountries = (rows) => {
        setText("threat-watch-country-count", `${rows.length} shown`);
        if (!countryList) return;
        if (!rows.length) {
            renderEmpty(countryList, "No recognized geographic evidence matches the current filters.");
            return;
        }
        const fragment = document.createDocumentFragment();
        rows.forEach((row) => {
            const link = createInternalLink(row.url, `rounded-xl border p-3 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 ${row.is_selected ? "border-cyan-400/40 bg-cyan-500/10" : "border-line/80 bg-slate-950/35 hover:border-sky-400/30"}`);
            const content = createElement("span", "flex items-start justify-between gap-3");
            const identity = createElement("span", "min-w-0");
            identity.append(
                createElement("span", "block break-words text-sm font-medium text-white", row.country),
                createElement(
                    "span",
                    "mt-1 block text-[11px] text-slate-500",
                    `${countLabel(row.record_count, "record")} · ${countLabel(row.group_count, "actor")} · ${countLabel(row.source_count, "source")}${row.watch_match_count ? ` · ${row.watch_match_count} matched` : ""}`,
                ),
            );
            content.append(identity, createElement("span", `shrink-0 text-lg font-semibold ${row.watch_match_count ? "text-cyan-100" : "text-slate-200"}`, row.record_count));
            link.append(content);
            fragment.append(link);
        });
        countryList.replaceChildren(fragment);
    };

    const renderSources = (rows) => {
        if (!sourceCoverage) return;
        if (!rows.length) {
            renderEmpty(sourceCoverage, "No source coverage in the selected window.");
            return;
        }
        const fragment = document.createDocumentFragment();
        rows.forEach((row) => {
            const link = createInternalLink(row.url, "block rounded-xl border border-line/80 bg-slate-950/35 p-3 transition hover:border-sky-400/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70");
            link.append(
                createElement("span", "block break-words text-sm font-medium text-white", row.source_name),
                createElement(
                    "span",
                    "mt-1 block text-[11px] leading-5 text-slate-400",
                    `${countLabel(row.record_count, "record")} · ${countLabel(row.group_count, "actor")} · ${countLabel(row.watch_match_count, "watch match", "watch matches")}`,
                ),
            );
            const coverage = row.incident_count
                ? `Geography coverage: ${row.mapped_incident_count} / ${row.incident_count} incidents (${row.geography_coverage_percent}%)`
                : "No incident denominator; actor evidence only";
            link.append(
                createElement("span", "mt-2 block text-[11px] text-slate-500", coverage),
                createElement("span", "mt-1 block text-[10px] text-slate-500", `Freshness: ${relativeTime(row.latest_activity_at)}`),
            );
            fragment.append(link);
        });
        sourceCoverage.replaceChildren(fragment);
    };

    const renderMatchedActors = (names) => {
        const container = document.getElementById("threat-watch-matched-top-actors");
        if (!container) return;
        const fragment = document.createDocumentFragment();
        names.forEach((name) => fragment.append(createElement("span", "rounded-md border border-cyan-500/20 bg-cyan-500/10 px-2 py-1 text-[11px] text-cyan-100", name)));
        container.replaceChildren(fragment);
    };

    const parseInitialCountries = () => {
        try {
            const rows = JSON.parse(countryDataElement?.textContent || "[]");
            return Array.isArray(rows) ? rows : [];
        } catch (_error) {
            return [];
        }
    };

    const recordCountExpression = () => ["to-number", ["coalesce", ["feature-state", "record_count"], 0], 0];
    const watchCountExpression = () => ["to-number", ["coalesce", ["feature-state", "watch_match_count"], 0], 0];
    const countryIdForFeature = (feature) => String(feature?.id || feature?.properties?.country_id || "");

    const buildPopup = (country) => {
        const content = createElement("div");
        content.append(
            createElement("p", "threat-watch-popup__eyebrow", "Observed evidence"),
            createElement("p", "threat-watch-popup__title", country.country),
            createElement("p", "threat-watch-popup__meta", `${country.record_count} records · ${country.incident_count} incidents`),
            createElement("p", "threat-watch-popup__meta", `${country.group_count} actors · ${country.source_count} sources`),
        );
        if (country.watch_match_count) content.append(createElement("p", "threat-watch-popup__meta", `${country.watch_match_count} watch matches`));
        return content;
    };

    const applyCountryState = () => {
        if (!mapReady) return;
        appliedCountryIds.forEach((countryId) => {
            map.setFeatureState({source: countrySourceId, id: countryId}, {record_count: 0, watch_match_count: 0, selected: false, live: false});
        });
        const nextApplied = new Set();
        countryActivity.forEach((country, countryId) => {
            if (!countryId) return;
            if (geometryCountryIds.has(countryId)) nextApplied.add(countryId);
            map.setFeatureState(
                {source: countrySourceId, id: countryId},
                {
                    record_count: Number(country.record_count) || 0,
                    watch_match_count: Number(country.watch_match_count) || 0,
                    selected: Boolean(country.is_selected),
                },
            );
        });
        appliedCountryIds = nextApplied;
    };

    const updateMapCountries = (rows) => {
        countryActivity = new Map(rows.map((row) => [String(row.country_id || row.country_key || ""), row]));
        setText("threat-watch-map-count", `${rows.length} active countries`);
        applyCountryState();
    };

    const setHoverCountry = (countryId) => {
        if (!mapReady || hoveredCountryId === countryId) return;
        if (hoveredCountryId) map.setFeatureState({source: countrySourceId, id: hoveredCountryId}, {hovered: false});
        hoveredCountryId = countryId;
        if (countryId) map.setFeatureState({source: countrySourceId, id: countryId}, {hovered: true});
    };

    const addCountryLayers = () => {
        map.addSource(countrySourceId, {
            type: "geojson",
            data: mapElement.dataset.geographyUrl,
            promoteId: "country_id",
            attribution: "Natural Earth 4.1.0 · public domain",
        });
        map.addLayer({
            id: countryFillLayerId,
            type: "fill",
            source: countrySourceId,
            paint: {
                "fill-color": ["interpolate", ["linear"], recordCountExpression(), 0, "#0b1623", 1, "#0e7490", 3, "#0891b2", 6, "#d97706", 12, "#ea580c", 24, "#b91c1c"],
                "fill-opacity": ["case", ["boolean", ["feature-state", "selected"], false], 0.92, [">", recordCountExpression(), 0], 0.8, 0.7],
            },
        });
        map.addLayer({
            id: "threat-watch-country-boundaries",
            type: "line",
            source: countrySourceId,
            paint: {
                "line-color": ["case", ["boolean", ["feature-state", "selected"], false], "#a5f3fc", [">", watchCountExpression(), 0], "#67e8f9", ["boolean", ["feature-state", "hovered"], false], "#7dd3fc", "#27364a"],
                "line-width": ["case", ["boolean", ["feature-state", "selected"], false], 2.7, [">", watchCountExpression(), 0], 1.8, ["boolean", ["feature-state", "hovered"], false], 1.5, 0.6],
                "line-opacity": ["case", [">", recordCountExpression(), 0], 0.95, 0.62],
            },
        });
        map.on("mousemove", countryFillLayerId, (event) => {
            const countryId = countryIdForFeature(event.features?.[0]);
            const activity = countryActivity.get(countryId);
            map.getCanvas().style.cursor = activity ? "pointer" : "";
            setHoverCountry(activity ? countryId : "");
            if (activity) popup.setLngLat(event.lngLat).setDOMContent(buildPopup(activity)).addTo(map);
            else popup.remove();
        });
        map.on("mouseleave", countryFillLayerId, () => {
            map.getCanvas().style.cursor = "";
            setHoverCountry("");
            popup.remove();
        });
        map.on("click", countryFillLayerId, (event) => {
            const destination = safeInternalUrl(countryActivity.get(countryIdForFeature(event.features?.[0]))?.url);
            if (destination) window.location.assign(destination);
        });
    };

    const sourceLoaded = () => Boolean(map?.getSource(countrySourceId) && map.isSourceLoaded(countrySourceId));
    const initializeLoadedSource = () => {
        if (mapReady || !sourceLoaded()) return false;
        geometryCountryIds = new Set(map.querySourceFeatures(countrySourceId).map(countryIdForFeature).filter(Boolean));
        mapReady = true;
        applyCountryState();
        mapFallback?.classList.add("hidden");
        map.fitBounds([[-180, -72], [180, 84]], {padding: window.innerWidth < 640 ? 8 : 24, duration: 0});
        return true;
    };

    const initializeMap = () => {
        if (surfaceMode !== "geography" || !mapElement || !window.maplibregl) return;
        const styleUrl = mapElement.dataset.styleUrl || "";
        if (!styleUrl || !mapElement.dataset.geographyUrl) return;
        popup = new maplibregl.Popup({closeButton: false, closeOnClick: false, offset: 12, className: "threat-watch-map-popup"});
        map = new maplibregl.Map({container: mapElement, style: styleUrl, center: [12, 18], zoom: window.innerWidth < 640 ? 0.25 : 0.9, minZoom: 0, maxZoom: 5.5, attributionControl: false, dragRotate: false, touchPitch: false, renderWorldCopies: false});
        map.addControl(new maplibregl.AttributionControl({compact: true}), "bottom-right");
        map.addControl(new maplibregl.NavigationControl({showCompass: false}), "top-right");
        const failureTimer = window.setTimeout(() => {
            if (!mapReady) mapFallback?.classList.remove("hidden");
        }, 9000);
        map.once("load", () => {
            const onSourceData = (event) => {
                if (event.sourceId !== countrySourceId) return;
                if (initializeLoadedSource()) {
                    map.off("sourcedata", onSourceData);
                    window.clearTimeout(failureTimer);
                }
            };
            map.on("sourcedata", onSourceData);
            addCountryLayers();
            if (initializeLoadedSource()) {
                map.off("sourcedata", onSourceData);
                window.clearTimeout(failureTimer);
            }
        });
        map.on("error", () => mapFallback?.classList.remove("hidden"));
    };

    const applySnapshot = (snapshot, newIds = new Set()) => {
        if (!snapshot?.map_metrics) return;
        setText("threat-watch-metric-records", snapshot.map_metrics.record_count);
        setText("threat-watch-metric-actors", snapshot.map_metrics.group_count);
        setText("threat-watch-metric-watch", snapshot.map_metrics.watch_match_count);
        setText("threat-watch-metric-countries", snapshot.map_metrics.country_count);
        setText("threat-watch-metric-sources", snapshot.map_metrics.source_count);
        setText("threat-watch-metric-geography-detail", `${snapshot.map_metrics.mapped_record_count} mapped records`);
        setText("threat-watch-matched-records", snapshot.matched_summary.record_count);
        setText("threat-watch-matched-incidents", snapshot.matched_summary.incident_count);
        setText("threat-watch-matched-actors", snapshot.matched_summary.group_count);
        setText("threat-watch-matched-sources", snapshot.matched_summary.source_count);
        renderMatchedActors(snapshot.matched_summary.top_actors || snapshot.matched_summary.top_groups || []);
        renderIncoming(snapshot.incoming_activity || [], newIds);
        renderActors(snapshot.top_actors || snapshot.top_groups || []);
        renderCountries(snapshot.top_countries || []);
        renderSources(snapshot.coverage_sources || []);
        updateMapCountries(snapshot.map_country_data || []);
        // Auto mode is deliberately stable for a live session. The server may
        // recommend a different mode after evidence changes; navigation/refresh
        // applies that recommendation without making the surface jump mid-triage.
    };

    const startPolling = () => {
        if (!pollUrl || pollTimer) return;
        pollTimer = window.setInterval(() => {
            if (pollInFlight || document.hidden) return;
            pollInFlight = true;
            status("Syncing", "warn");
            const url = new URL(pollUrl, window.location.origin);
            url.search = window.location.search;
            url.searchParams.set("cursor", String(cursor));
            fetch(url.href, {headers: {Accept: "application/json", "X-Requested-With": "XMLHttpRequest"}})
                .then((response) => {
                    if (!response.ok) throw new Error(`live-${response.status}`);
                    return response.json();
                })
                .then((payload) => {
                    const events = Array.isArray(payload.events) ? payload.events : [];
                    cursor = Math.max(cursor, Number(payload.cursor) || 0);
                    page.dataset.liveCursor = String(cursor);
                    applySnapshot(payload.snapshot || {}, new Set(events.map((event) => event.id)));
                    status(events.length ? `${events.length} new` : "Live · 25s");
                })
                .catch(() => status("Retrying", "error"))
                .finally(() => {
                    pollInFlight = false;
                });
        }, pollInterval);
    };

    const initialCountries = parseInitialCountries();
    countryActivity = new Map(initialCountries.map((row) => [String(row.country_id || row.country_key || ""), row]));
    initializeMap();
    startPolling();

    if (mapElement?.dataset.debugMap === "true") {
        window.getThreatWatchMapDiagnostics = () => ({
            sourceLoaded: sourceLoaded(),
            geometryFeatureCount: geometryCountryIds.size,
            activeFeatureCount: countryActivity.size,
            appliedFeatureCount: appliedCountryIds.size,
        });
    }

    window.addEventListener("pagehide", () => {
        if (pollTimer) window.clearInterval(pollTimer);
        popup?.remove();
        map?.remove();
    }, {once: true});
})();
