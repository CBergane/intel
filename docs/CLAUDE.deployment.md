# CLAUDE.deployment.md — Deployment & ops

## Stack
```
Proxmox host
  └── LXC container (Debian 12)
        ├── podman (rootless, user=appuser)
        │     ├── borealsec-intel (gunicorn, port 8000)
        │     └── tor daemon (optional — for dark intel)
        └── cloudflared (Cloudflare Tunnel agent)
```

## Cloudflare Tunnel
- No open inbound ports on the LXC or Proxmox host.
- Tunnel connects `intel.borealsec.io` → `localhost:8000`.
- Catch-all rule returns 404 for undefined routes.
- WAF rules: rate limit `/admin-login/` to 10 req/min per IP.

## Container build

```bash
# Build
podman build -t borealsec-intel:latest -f Containerfile .

# Run (dev)
podman run --rm -p 8000:8000 \
  --env-file .env \
  borealsec-intel:latest

# Run (prod — read .env from secret volume)
podman run -d --name intel \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  --secret intel-env,target=/run/secrets/env \
  borealsec-intel:latest
```

## Database

### SQLite (dev/small scale)
Default. File at `db.sqlite3` inside the container — **must be on a mounted volume** or data is lost on container restart.

```yaml
# podman-compose.yml
volumes:
  - ./data/db:/app/data
```
And set `DB_NAME=/app/data/db.sqlite3`.

### PostgreSQL (recommended for prod)
Set in `.env`:
```
DB_ENGINE=django.db.backends.postgresql
DB_NAME=intel
DB_USER=intel
DB_PASSWORD=<strong password>
DB_HOST=db
DB_PORT=5432
```

Run migrations after deploy:
```bash
podman exec intel python manage.py migrate --settings=config.settings.prod
```

## Production settings checklist

Add to `config/settings/prod.py`:
```python
from .base import *

DEBUG = False

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# HSTS — enable only after SSL confirmed working
# SECURE_HSTS_SECONDS = 31536000
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "django": {"handlers": ["console"], "level": "WARNING"},
        "intel": {"handlers": ["console"], "level": "INFO"},
    },
}
```

## Scheduled jobs (systemd timers — recommended over cron)

### Ingest feeds every 10 minutes
`/etc/systemd/system/intel-ingest.service`:
```ini
[Unit]
Description=borealsec-intel RSS ingest

[Service]
Type=oneshot
User=appuser
ExecStart=podman exec intel python manage.py ingest_sources --settings=config.settings.prod
```

`/etc/systemd/system/intel-ingest.timer`:
```ini
[Unit]
Description=Run intel ingest every 10 min

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now intel-ingest.timer
```

### Prune old items weekly
Same pattern, run `python manage.py prune_items` weekly.

### Dark intel ingest (separate timer — Tor required)
Same pattern, run `python manage.py ingest_dark` every 30–60 min.
The service should route through Tor SOCKS proxy (via `DARK_TOR_SOCKS_URL`).

## Backups

```bash
# SQLite
cp /app/data/db.sqlite3 /backup/intel-$(date +%Y%m%d).sqlite3

# PostgreSQL
pg_dump intel | gzip > /backup/intel-$(date +%Y%m%d).sql.gz
```

Automate with a systemd timer. Rotate backups older than 30 days.

## Monitoring / health

- `/ops/` dashboard (superuser-only) shows feed health and job status.
- Add an external uptime monitor (e.g. UptimeRobot) hitting the public `/` URL.
- Log rotation: podman logs are managed by journald; set `SystemMaxUse=500M` in `/etc/systemd/journald.conf`.

## Container security hardening

Add to Containerfile:
```dockerfile
# Drop capabilities
USER appuser

# Read-only root filesystem (requires volume mounts for db/staticfiles)
# Use: podman run --read-only ...

# No new privileges
# Add: --security-opt=no-new-privileges in run command
```

Podman run additions:
```bash
podman run \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --read-only \
  -v ./data:/app/data:Z \
  ...
```

## Update procedure

```bash
# 1. Pull latest code
git pull

# 2. Build new image
podman build -t borealsec-intel:latest .

# 3. Run migrations (zero-downtime if additive)
podman exec intel python manage.py migrate --settings=config.settings.prod

# 4. Restart container
podman stop intel
podman start intel

# 5. Verify
curl -s http://localhost:8000/ | grep -c "BorealSec"
```
