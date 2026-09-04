# BorealSec Intel Integration API v1

## Purpose and boundary

The internal Integration API provides a stable HTTP boundary for exporting deliberately selected BorealSec Intel data to server-to-server consumers. The intended flow is:

```text
BorealSec Intel -> Integration API v1 -> n8n -> Sixfold Archive
```

BorealSec Intel remains the authoritative collection, normalization, and evidence engine. n8n and Sixfold must consume this API and must never read the Intel PostgreSQL database directly.

The canonical API base path is `/api/v1/`. Version 1 uses Django's built-in JSON responses and does not use generic model serialization.

## Authentication and configuration

Every implemented data or health endpoint requires:

```text
Authorization: Bearer <token>
```

The token is configured with `INTEGRATION_API_TOKEN`. It must be generated and supplied out-of-band through the deployment environment, and must never be committed. If the setting is empty, authenticated endpoints fail closed with HTTP 503. Invalid credentials receive a generic HTTP 401 response and are never echoed.

Example using a shell environment variable:

```sh
curl \
  -H "Authorization: Bearer ${INTEGRATION_API_TOKEN}" \
  https://intel.borealsec.io/api/v1/health/
```

## Current endpoint

`GET /api/v1/health/` returns a small integration-health response and performs no Intel application-data queries:

```json
{
  "api_version": "1",
  "status": "ok",
  "service": "borealsec-intel"
}
```

The trailing slash is canonical. `/api/v1/health` returns a JSON 404 and is not redirected. Health is strictly GET-only; HEAD and unsafe methods return HTTP 405 with `Allow: GET`. Standard HTTP handling omits the response body for a HEAD request.

## Response contract

All v1 responses use UTF-8 JSON, include `"api_version": "1"`, and send `Cache-Control: no-store`.

Errors use this envelope:

```json
{
  "api_version": "1",
  "error": {
    "code": "unauthorized",
    "message": "Authentication required."
  }
}
```

The foundation defines JSON responses for HTTP 401 `unauthorized`, 404 `not_found`, 405 `method_not_allowed`, and 503 `service_unavailable`. Unknown paths below `/api/v1/` use the JSON 404 contract; normal website 404 handling is unchanged.

## Foundation scope and future direction

This slice exposes health only. It does not expose Intel items, sources, source health, ransomware, Nordic intelligence, Threat Watch, Dark/Tor records, configuration, or internal errors.

Planned resources, not yet implemented, are:

- `GET /api/v1/signals/`
- `GET /api/v1/signals/{id}/`
- `GET /api/v1/nordics/`
- `GET /api/v1/ransomware/`
- `GET /api/v1/changes/?cursor=<opaque>`

Incremental synchronization should eventually use an opaque cursor rather than caller-managed timestamps. A possible collection envelope is:

```json
{
  "api_version": "1",
  "results": [],
  "next_cursor": "opaque-value",
  "has_more": false
}
```

The endpoints above remain unimplemented. The publishable representation and cursor primitives described below are internal contracts for those future endpoints; they do not add HTTP routes.

## Publishable signal contract

One publishable signal has this complete v1 shape:

```json
{
  "schema_version": "1",
  "id": "intel:item:<stable-id>",
  "kind": "ransomware",
  "title": "Example title",
  "summary": "Normalized summary",
  "url": "https://public.example/item",
  "published_at": "2026-09-03T21:00:02Z",
  "observed_at": "2026-09-03T21:05:00Z",
  "classified_at": "2026-09-03T22:00:00Z",
  "priority": "P2",
  "score": 50,
  "classification": {
    "active_exploitation": false,
    "vulnerability": false,
    "threat_news": false,
    "ransomware": true,
    "nordic": true,
    "research": false
  },
  "entities": {
    "cves": [],
    "countries": [{"code": "SWE", "name": "Sweden"}],
    "ransomware_actor": "akira",
    "ransomware_victim": "Example AB"
  },
  "source": {
    "slug": "ransomware-live",
    "name": "ransomware.live"
  }
}
```

The field mappings are deliberate:

| Contract field | Authoritative Intel value |
| --- | --- |
| `schema_version` | Static publishable-signal schema version `1` |
| `id` | Namespaced `Item.stable_id`; the database primary key is not published |
| `kind` | `SignalProfile.primary_category` from `classify_item()` |
| `title` | Normalized `Item.title` |
| `summary` | Sanitized `Item.summary`, or `null` when blank |
| `url` | `Item.canonical_url`, or `null` when unavailable |
| `published_at` | `Item.published_at` in UTC; adapters use fetch time when the source provides no usable publication time |
| `observed_at` | `Item.created_at`, meaning the first time Intel persisted the item |
| `classified_at` | Explicit classifier evaluation time, supplied by the caller or defaulting to the current time |
| `priority`, `score` | Existing classifier output from `classify_item(item, now=classified_at)` |
| `classification` | Fixed boolean projection of the existing classifier outcomes |
| `entities.cves` | Classifier-normalized CVE identifiers, de-duplicated and sorted |
| `entities.countries` | Recognized `raw_payload.country` evidence normalized through the existing country manifest; currently zero or one country |
| ransomware actor/victim | Normalized fields retained by the authoritative `ransomware_live_victims` adapter only |
| `source` | `Source.slug` and `Source.name` only |

`intel:item:<stable-id>` is stable across repeated ingestion because `Item.stable_id` is unique, derived from existing deduplication identity, and assigned only when initially absent. The namespace keeps the identifier opaque as an API identity and avoids publishing a bare database primary key.

All timestamps are timezone-aware ISO-8601 UTC strings using `Z`; fractional seconds are retained when present. Required keys are always present. Unavailable singular values use `null`, while unavailable collections use `[]`. Classification keys have a fixed order, and entity collections are sorted deterministically.

`score` and `priority` are operational values at `classified_at`. They can legitimately change as classifier recency bands change; they are not historical first-observation scores. Determinism means that the same Item and the same `classified_at` produce the same DTO. A future collection endpoint must capture one evaluation timestamp at request start and pass it to every signal in that response.

Nordic relevance does not by itself assert that an item describes a specific country. A country entity is published only when recognized country metadata exists. Likewise, arbitrary `group`, `victim`, or similarly named upstream fields are not published outside the reviewed ransomware adapter.

The signal contract explicitly excludes bare database IDs, `external_id`, `raw_payload`, normalized-title hashes, classifier reasons/evidence strings, feed identity and configuration, source homepage/tags/enabled state, fetch health/errors, credentials, headers, and internal callback URLs. No generic Django serialization is used.

Dark/Tor models and content are excluded completely, including Dark sources, hits, documents, snapshots, onion URLs, watch expressions, proxy configuration, and raw Dark content. Any future Dark export requires a separate reviewed representation.

Future queryset callers should load `source` and `feed` with `select_related()` before building multiple signals. Building a signal from a preloaded Item performs no additional database queries.

## Incremental cursor contract

The internal change cursor is deterministically serialized, URL-safe, versioned, and signed with Django's `SECRET_KEY` facilities under an API-specific salt. It does not use `INTEGRATION_API_TOKEN`. Callers must store and return the cursor unchanged and must not parse or construct it. Invalid signatures, malformed state, and unsupported internal versions are rejected.

The proposed total ordering for a future changes feed is ascending `(Item.updated_at, Item.id)`. The timestamp captures both newly created records and subsequent model saves, while the primary key provides a deterministic tie-breaker. The cursor carries the position required to resume that ordering, but its internal payload is intentionally not part of the public API contract.

There are important limitations before `/api/v1/changes/` can be implemented robustly:

- `Item.updated_at` is not indexed.
- Current ingestion saves an existing Item when it is re-observed, even when its publishable content is unchanged. Therefore `updated_at` can produce harmless duplicate change events but cannot prove a material content change.
- Queryset-level updates can bypass Django's `auto_now` behavior.
- The current model has no persisted publishable-content fingerprint or change ledger, so it cannot reliably distinguish a new item, a substantive update, and a no-op re-observation for downstream change semantics.
- Time-dependent `score` and `priority` can change at a later `classified_at` without changing `Item.updated_at`; a future changes contract must decide how operational reclassification is synchronized.

A future changes slice should resolve the indexing and material-change semantics before exposing the endpoint. No schema changes are included in the contract slice.
