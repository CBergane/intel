# BorealSec Intel Dashboard

Public, read-only cybersecurity intelligence dashboard built with Django.

## Stack
- Django + Tailwind CSS
- Postgres-ready (defaults to sqlite in local dev if `DB_ENGINE` is empty)
- RSS/Atom ingestion via `ingest_sources` management command

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
5. (Optional) create admin user:
   ```bash
   python manage.py createsuperuser
   ```
6. Run server:
   ```bash
   python manage.py runserver
   ```

Dashboard pages:
- `/`
- `/active`
- `/advisories`
- `/research`
- `/sweden`
- `/feed-health`
- `/sources`
- `/about`
- `/ops/` (superuser only)
- `/admin-panel/` (superuser only)

Home dashboard (`/`) includes:
- High Signal (scored by CVE/keyword/section over last 7 days)
- Advisories, Research, Sweden blocks with per-source balancing
- Trending Sources (48h) and Trending CVEs (7d)
- Feed health mini-panel (ok/error/never + last ingest time)

## Tailwind
Templates are already Tailwind-compatible via CDN in `templates/base.html`.

Optional local build pipeline:
1. Install Node.js.
2. Install dev dependency:
   ```bash
   npm install
   ```
3. Build CSS:
   ```bash
   npm run build:css
   ```

## Ingestion
Seed Tier-1 sources/feeds (idempotent create + update):
```bash
python manage.py seed_sources
```
Tier-1 definitions live in `intel/tier1_sources.py`.

Run all enabled feeds:
```bash
python manage.py ingest_sources
```

Run one feed (id, source slug, or exact feed name):
```bash
python manage.py ingest_sources --feed cert-se
```

Dry-run parse without writing items:
```bash
python manage.py ingest_sources --dry-run
```

Per-feed guardrails:
- `Feed.max_items_per_run` (default `200`) caps processed entries each run.
- `Feed.max_age_days` (default `180`) skips entries older than this window.
- Entries without a published timestamp use fetch time as fallback for age checks.
- MSRC feeds default to `max_age_days=90` via migration.
- Global response-size cap is controlled by env `FEED_MAX_BYTES` (default `1500000`).

Admin auth routes:
- Login: `/admin-login/`
- Logout (POST only): `/logout/`

Prune stale items (keeps `FetchRun` history):
```bash
python manage.py prune_items
```

Dry-run prune:
```bash
python manage.py prune_items --dry-run
```

## Deployment (minimal, systemd + gunicorn)
1. Set `DJANGO_ENV=prod` and Postgres env vars.
2. Install production deps and run:
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```
3. Create a gunicorn systemd service (example):
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

## Pre-launch checklist
- Sync and curate feeds:
  ```bash
  python manage.py seed_sources
  ```
  This disables known broken feeds such as deprecated Debian/Red Hat URLs if they still exist in DB.
- Set a strong `SECRET_KEY` in environment for `DJANGO_ENV=prod` (required at startup).
- Run Django deployment checks:
  ```bash
  python manage.py check --deploy
  ```
- Run dependency audit:
  ```bash
  python -m pip_audit
  ```

## Optional scheduling notes
- Cron approach:
  ```bash
  */10 * * * * /srv/borealsec-intel/.venv/bin/python /srv/borealsec-intel/manage.py ingest_sources
  ```
- Celery approach:
  - Keep `ingest_sources` logic as reusable ingestion core.
  - Add celery beat task every 5-10 minutes if queue-based scheduling is needed.
