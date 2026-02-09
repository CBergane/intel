# AI / Codex Working Agreement (Intel Dashboard)

## Goal
Build a public, read-only cybersecurity intel dashboard that aggregates high-signal sources (RSS + select JSON),
deduplicates and scores items, and presents them in a structured way (not an RSS dump).

## Non-goals
- No user accounts, org management, payments, or multi-tenancy in v1.
- No “scraping everything”. Prefer official feeds/APIs and an allowlist.
- No heavy ML/NLP pipeline in v1 (keep it deterministic + explainable).

## Product principles
1. High signal > high volume.
2. Everything is filterable (time, vendor, severity, exploited, tags).
3. Make freshness visible (timestamps + feed health).
4. Safe-by-default: treat all fetched content as untrusted.

## Engineering rules
1. Small diffs, reviewable commits.
2. Don’t introduce secrets into the repo.
3. Prefer config via `.env` + `.env.example`.
4. Add/adjust tests when changing parsing, scoring, or dedupe logic.
5. Avoid new dependencies unless necessary; if added, update requirements/lockfiles and docs.
6. Never render remote HTML as-is. Sanitize or store as text; always escape output.
7. Fetching rules:
   - Allowlist sources (no arbitrary URLs)
   - Strict timeouts, size limits, retries with backoff
   - Identify ourselves with a clear User-Agent
8. Data rules:
   - Store `raw` (for debugging) + `normalized` fields (for UI)
   - Deduplicate by canonical URL + normalized title hash
   - Keep a stable item id so updates don’t create duplicates
9. Ops rules:
   - Provide a “Feed Health” view (last success, error, lag)
   - Logging must not include secrets
10. Deliver with “What changed” + “How to test” in PR descriptions.
