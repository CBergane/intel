# BorealSec Intel Dashboard

Public, read-only cybersecurity intelligence dashboard built with Django.

## Stack
- Django + Tailwind CSS
- Postgres-ready (defaults to sqlite in local dev if `DB_ENGINE` is empty)
- RSS/Atom/JSON ingestion via management commands

## Quickstart (Local)
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create env file:
   ```bash
   cp .env.example .env
   ```
4. Apply migrations:
   ```bash
   python manage.py migrate
   ```
5. (Optional) create superuser:
   ```bash
   python manage.py createsuperuser
   ```
6. Run server:
   ```bash
   python manage.py runserver
   ```

Main pages:
- `/`
- `/active`
- `/advisories`
- `/research`
- `/sweden`
- `/feed-health`
- `/sources`
- `/dark`
- `/about`

Superuser pages:
- Custom login: `/admin-login/`
- Custom admin panel: `/admin-panel/`
- Ops dashboard: `/ops/`
- Django admin fallback: `/boreal-admin/`

Ops actions are queued as background jobs (`OpsJob`) and do not execute inline in HTTP requests.
This avoids Gunicorn worker timeouts when ingest takes longer than request timeouts.

## Standard Ingestion Pipeline

### Commands
Seed tier-1 defaults (non-destructive for existing rows by default):
```bash
python manage.py seed_sources
```

Force full seed reconciliation (overwrites existing seeded rows):
```bash
python manage.py seed_sources --sync
```

Run ingest:
```bash
python manage.py ingest_sources
```

Run a single feed/source:
```bash
python manage.py ingest_sources --feed cert-se
```

Dry-run parse:
```bash
python manage.py ingest_sources --dry-run
```

Scoped backfill controls:
```bash
python manage.py ingest_sources --feed cisa --since-days 365 --max-items 5000
python manage.py ingest_sources --feed cisa --expanded
```

Prune stale items (keeps `FetchRun`):
```bash
python manage.py prune_items
python manage.py prune_items --dry-run
```

### Observability
Each `FetchRun` now records:
- `items_fetched`
- `items_stored`
- `items_new`
- `items_updated` (deduped/merged)
- `items_skipped_old`
- `items_skipped_invalid`
- `items_limited`

These counters are shown in:
- `/feed-health`
- `/ops/`

### Why intel may appear “missing”
- Feed-level limits (`max_items_per_run`, `max_age_days`) can skip old/high-volume entries.
- UI filters may hide results by source/query/time window.
- `/` is curated and balanced by design; use section pages for broader timelines.

## Feed/Source Operations (No Redeploy Needed)
Use `/admin-panel/` for day-to-day ops:
- Create/edit/disable/delete `Feed`
- Create/edit/disable/delete `Source`
- Edit feed URL, type (`rss`/`atom`/`json`), adapter key, limits, and expanded mode
- Manage dark sources in `/admin-panel/dark/` with guided source-type hints, quick test fetch, per-source ingest queueing, duplicate, and enable/disable

Use `/boreal-admin/` when you need lower-level model access and bulk/manual maintenance.

### Safety/validation
- Mutations are POST + CSRF protected.
- URL validation and range checks are enforced in forms.
- Seed defaults do not overwrite existing operator edits unless `--sync` is used.

## JSON Adapters
Standard ingest now supports adapter-based parsing:
- RSS/Atom: normalized through a shared entry layer
- JSON: normalized through adapter keys
- Included adapter: `cisa_kev` (CISA Known Exploited Vulnerabilities JSON)

Tier-1 source definitions live in:
- `intel/tier1_sources.py`

## Darkintel v2 (Isolated Pipeline)
Darkintel remains isolated from standard `Item` data.

Models:
- `DarkSource`
- `DarkFetchRun`
- `DarkDocument`
- `DarkHit`
- `DarkSnapshot`

Source types:
- `single_page`
- `index_page`
- `feed`

Guardrails:
- allowlist-only sources (superuser-managed)
- passive HTTP GET only
- no auth/forms/market interactions
- timeout/max-bytes/retries (global env defaults + optional per-source overrides in admin)
- sanitized rendering

Tor behavior:
- `.onion` URLs use Tor (`socks5h`)
- clearnet uses direct fetch unless `use_tor` is enabled per source

Command:
```bash
python manage.py ingest_dark
```

Views:
- Public dark dashboard: `/dark`
- Superuser dark admin: `/admin-panel/dark/`

## Environment Variables
Core:
- `INTEL_FETCH_TIMEOUT` (default `10`)
- `FEED_MAX_BYTES` (default `1500000`)
- `INTEL_FETCH_RETRIES` (default `3`)

Dark:
- `DARK_TOR_SOCKS_URL` (default `socks5h://127.0.0.1:9050`)
- `DARK_FETCH_TIMEOUT` (default `20`)
- `DARK_MAX_BYTES` (default `750000`)
- `DARK_FETCH_RETRIES` (default `3`)
- `DARK_INDEX_MAX_LINKS` (default `30`)

Static/admin:
- `WHITENOISE_ENABLED` (default `1`)

## Podman / Podman Compose Ops
Examples assume service name `web` (adjust to your compose file).

View logs:
```bash
podman compose logs -f web
```

Exec into container:
```bash
podman compose exec web bash
```

Run migrations:
```bash
podman compose exec web python manage.py migrate
```

Create superuser:
```bash
podman compose exec web python manage.py createsuperuser
```

Open Django admin:
- Navigate to `/boreal-admin/` and authenticate as superuser.

Trigger manual ingest:
```bash
podman compose exec web python manage.py ingest_sources
podman compose exec web python manage.py ingest_dark
```

### Timeout note
- Increasing Gunicorn `--timeout` may reduce timeout symptoms.
- It is not the real fix for ingest-triggered 500s.
- The primary fix is queued background ops jobs from `/ops/`.

## Deployment (minimal, systemd + gunicorn)
1. Set `DJANGO_ENV=prod` and Postgres env vars.
2. Install deps and run:
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```
3. Gunicorn systemd example:
   ```ini
   [Unit]
   Description=BorealSec Intel Gunicorn
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/srv/borealsec-intel
   EnvironmentFile=/srv/borealsec-intel/.env
   ExecStart=/srv/borealsec-intel/.venv/bin/gunicorn config.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 60
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

4. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now borealsec-intel.service
   ```

### Static Files in Production (/boreal-admin/ styling)
- The app uses WhiteNoise middleware in production when `WHITENOISE_ENABLED=1`.
- `collectstatic` must be run for admin CSS/JS:
  ```bash
  python manage.py collectstatic --noinput
  ```
- The provided `Containerfile` runs `collectstatic` during image build, so `/static/admin/...` is available in Podman/Gunicorn deployments.
- If admin appears unstyled, verify:
  1. `python manage.py collectstatic --noinput` completed successfully
  2. `/static/admin/css/base.css` is reachable through your proxy/tunnel
  3. `WHITENOISE_ENABLED=1` in runtime environment

### Dark Admin Workflow
- Use `/admin-panel/dark/` as the operational UI:
  - **New Dark Source** with source type guidance (`single_page` / `index_page` / `feed`)
  - **Test** action for fetch preview (title/excerpt/link count) without full ingest
  - **Run ingest** action queues a background dark ingest job for one source
  - **Duplicate** action for safe copy-and-adjust workflows
  - **Disable/Enable** toggles allowlist activation
- Use `/ops/` for full queued job output and history.

## Security Notes
- Keep `/admin-login/`, `/admin-panel/`, `/ops/`, and `/boreal-admin/` superuser-only.
- Keep admin interfaces behind trusted reverse proxy or internal/private access where possible.
- For internet exposure, enforce TLS and access controls at proxy/tunnel layer.
- In prod: set a strong `SECRET_KEY` and run:
  ```bash
  python manage.py check --deploy
  python -m pip_audit
  ```
