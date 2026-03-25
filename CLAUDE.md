# CLAUDE.md — borealsec-intel

## Quick navigation
- **Security rules** → `docs/CLAUDE.security.md`
- **Dark web intel** → `docs/CLAUDE.dark_intel.md`
- **Deployment / ops** → `docs/CLAUDE.deployment.md`

---

## Project snapshot

| Item | Value |
|------|-------|
| Stack | Django 5.x · HTMX · Tailwind CSS · PostgreSQL (SQLite in dev) |
| Container | Podman rootless · python:3.10-slim image |
| Infra | Proxmox LXC → Podman → Cloudflare Tunnel (no open ports) |
| App dir | `/app` inside container, mirrored by `borealsec-intel/` in the repo |
| Settings | `config/settings/{base,dev,prod}.py` loaded via `DJANGO_ENV` env var |
| Main Django app | `intel/` |

## Architecture overview

```
Cloudflare Tunnel
      │
   gunicorn (0.0.0.0:8000)
      │
   Django (config/)
      │
   ┌──┴────────────────┐
   │   intel/           │
   │   ├── models.py    │  Source, Feed, Item, FetchRun
   │   ├── dark_models  │  DarkSource, DarkFetchRun, DarkDocument, DarkSnapshot, DarkHit
   │   ├── ingestion.py │  RSS/JSON ingest pipeline
   │   ├── dark_utils   │  HTML extraction, keyword/regex matching
   │   └── views.py     │  Public dashboard, admin panel, ops, dark
   └───────────────────┘
```

## Coding rules (always apply)

1. **Never introduce secrets** into code or git. Use `.env` / env vars only.
2. **Never render remote HTML as-is.** Sanitize or store as escaped text.
3. **All mutating views must use POST + CSRF.** Logout is POST.
4. **All write routes are superuser-only**: `/admin-login/`, `/admin-panel/`, `/ops/`.
5. **Allowlist sources only** — no arbitrary URL fetching from user input.
6. **Strict fetch limits**: timeout, max_bytes, retries must come from settings or per-source overrides.
7. **Dark intel is isolated**: never mix `DarkHit` into the main `Item` feed. Separate views, separate models.
8. **Output escaping**: all template output must use Django's auto-escaping. Never use `| safe` on untrusted data.
9. **Tests required** for: any change to parsing, scoring, deduplication, or sanitization logic.
10. **Small commits**: one logical change per commit. Include "What changed" + "How to test".

## Working with Claude Code

### Starting a session
Always tell Claude which file/feature you're working on. The project has multiple independent subsystems (RSS intel, dark intel, ops, admin panel) — be explicit.

### Key commands
```bash
# Dev server
python manage.py runserver --settings=config.settings.dev

# Run tests
python manage.py test intel --settings=config.settings.dev

# Ingest feeds
python manage.py ingest_sources --settings=config.settings.dev

# Ingest dark intel
python manage.py ingest_dark --settings=config.settings.dev

# Podman build
podman build -t borealsec-intel -f Containerfile .

# Podman compose (dev)
podman-compose up
```

### Adding a new feature — checklist
- [ ] New model? → add migration, update admin.py, add to `__str__`
- [ ] New view? → add URL, check auth (superuser if mutating), add CSRF if POST
- [ ] New fetch logic? → must have timeout + max_bytes + retry, use `requests` not `urllib` raw
- [ ] New template? → extends `base.html`, never `| safe` on external data
- [ ] Tests? → `intel/tests/test_<feature>.py`

## Current state (what exists)

### RSS/JSON intel ✅ working
- `Source`, `Feed`, `Item`, `FetchRun` models
- `ingest_sources` management command
- Dashboard, item list, feed health views
- Admin panel (superuser-only)

### Dark web intel ⚠️ in development
- `DarkSource`, `DarkFetchRun`, `DarkDocument`, `DarkSnapshot`, `DarkHit` models
- `ingest_dark` management command (SOCKS5/Tor aware)
- Dark dashboard template exists, view wiring incomplete
- **See `docs/CLAUDE.dark_intel.md` for approach and next steps**

### Ops ✅ working
- `OpsJob` model
- Ops dashboard view

### Deployment ⚠️ not hardened for prod
- Containerfile exists, works for basic use
- Security headers not fully configured
- **See `docs/CLAUDE.deployment.md` for hardening checklist**
