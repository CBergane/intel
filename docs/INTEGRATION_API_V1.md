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

Cursor construction and field-level resource schemas are intentionally deferred. Future endpoints must construct explicit publishable representations and must not serialize arbitrary model fields, raw payloads, or Dark intelligence data.
