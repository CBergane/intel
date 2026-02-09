# Backlog — Intel Dashboard

## Milestone 0 — Repo + baseline (1–2 pass)
- [ ] Create new Django project with the same conventions as the SIEM repo (Makefile, Podman/Docker, Tailwind pipeline).
- [ ] Add `.env.example` and settings split (dev/prod).
- [ ] Base layout (dark theme) + navigation skeleton:
  - Now
  - Exploited & Zero-day
  - Vendor advisories
  - Research & Writeups
  - Sweden / Nordics
  - Feed Health

## Milestone 1 — Data model + ingestion (MVP)
- [ ] Models:
  - Source (name, type=rss/json, url, tier, tags, enabled)
  - Item (title, url, published_at, source, summary, vendor, severity, exploited_flag, raw_payload, hash)
  - FetchRun (source, started_at, finished_at, ok, error, items_new, items_updated)
- [ ] Normalization:
  - Canonicalize URLs (strip common tracking params)
  - Normalize titles (trim, collapse whitespace)
  - Extract CVE IDs if present (simple regex)
- [ ] Deduplication strategy:
  - Unique on (canonical_url) OR fallback (source + title_hash + published_date_bucket)
- [ ] Ingestion job:
  - Management command `ingest_sources`
  - Optional Celery beat schedule (e.g., every 5–10 minutes)
- [ ] Source allowlist + limits:
  - timeout, max bytes, retry/backoff
  - explicit User-Agent header
- [ ] Seed initial Tier-1 sources (CERT-SE, CISA, MSRC, Cisco, Red Hat, Debian, SANS ISC, ZDI)

## Milestone 2 — Scoring + information architecture
- [ ] Scoring v1 (explainable):
  - +30 if “exploited/KEV/actively exploited” keywords
  - +20 if CVSS >= 9 (if present in feed text)
  - +15 if vendor is high-impact (Microsoft/Cisco/etc) and severity keywords exist
  - +10 if contains CVE
  - clamp score 0–100
- [ ] Topic clustering (lightweight):
  - Group by (CVE) else fuzzy title key (normalized title tokens)
  - Show “Topic” pages with related items
- [ ] UI filters:
  - time range, vendor, exploited flag, severity bucket, source tier
- [ ] “Now” page composition:
  - Breaking (last 24h, score >= threshold)
  - Exploited (flagged)
  - Vendors (top lists)
  - Trending topics (most items in last 48h)

## Milestone 3 — Feed Health + resilience
- [ ] Feed Health page:
  - per-source last_success, last_error, last_run_duration, lag
- [ ] Alerting hooks (optional):
  - webhook (Discord/Slack) for score >= 90 OR exploited=true
- [ ] Handle common feed failures:
  - 403/anti-bot: alternate headers and user-agent; log + mark degraded
  - backoff strategy and disable flapping feeds temporarily

## Milestone 4 — Deployment on Proxmox + Cloudflare Tunnel
- [ ] LXC template + provisioning steps (system deps, env, service)
- [ ] systemd service for gunicorn + celery (if used)
- [ ] Cloudflare Tunnel routing:
  - single tunnel with multiple ingress rules
  - catch-all rule returns 404
- [ ] Basic security hardening:
  - security headers
  - rate limit on any write endpoints (if any exist)
  - read-only public pages cached where safe

## Nice-to-have (after MVP)
- [ ] Add KEV JSON ingestion (not RSS) and enrich items with “Known Exploited” metadata.
- [ ] Add vendor-specific feeds (GitHub Security Advisories, npm/pypi advisories if relevant).
- [ ] Export: JSON/CSV for last N days.
- [ ] “Digest” page: daily/weekly summary view.
- [ ] Optional auth for “admin-only” views (Feed Health write controls), while keeping content public.

## Side quest — Subdomain naming cleanup
- [ ] Decide naming:
  - SIEM app: `reports.borealsec.io` (or `frc.borealsec.io`)
  - Intel dashboard: `intel.borealsec.io` (or `watch.borealsec.io`)
- [ ] Plan redirect + Cloudflare DNS/tunnel updates
