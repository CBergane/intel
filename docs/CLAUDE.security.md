# CLAUDE.security.md — Security rules

## Django security baseline

### Settings that MUST be set in prod (`config/settings/prod.py`)
```python
DEBUG = False
SECRET_KEY = env("SECRET_KEY")          # min 50 chars, random
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS")
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SECURE_HSTS_SECONDS = 31536000          # 1 year — only after Cloudflare is confirmed
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### Content Security Policy (add django-csp or manual header middleware)
Minimum viable CSP for this app:
```
default-src 'self';
script-src 'self' 'unsafe-inline';     # tighten to nonce once stable
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self';
frame-ancestors 'none';
form-action 'self';
base-uri 'self';
```

Add as middleware or via Cloudflare Transform Rules.

---

## Authentication & authorization

### Rules
- All admin/write views: `@login_required` + `@user_passes_test(lambda u: u.is_superuser)`
- Use Django's built-in session auth. No JWT, no custom session handling.
- Login view: rate-limit attempts (django-ratelimit or nginx/Cloudflare).
- No "remember me" tokens stored outside session.
- POST-only logout with CSRF token.

### Adding a protected view — correct pattern
```python
from django.contrib.auth.decorators import login_required, user_passes_test

def superuser_required(view_func):
    decorated = login_required(user_passes_test(lambda u: u.is_superuser)(view_func))
    return decorated

@superuser_required
def my_admin_view(request):
    ...
```

---

## Input validation & output escaping

### Template rules
- NEVER use `{{ value | safe }}` on any data that came from an external feed or URL.
- NEVER use `mark_safe()` on external content.
- Store external HTML as plain text (strip tags before DB insert via `sanitize_summary()`).
- OK to use `| safe` only for hard-coded HTML strings you authored in Python.

### Form / query string inputs
- Always validate filter params against an explicit allowlist (e.g. severity choices, time ranges).
- Use Django ORM — no raw SQL interpolation with user input.
- Validate URL inputs with `URLValidator()` before any use in fetch logic.

### File / path handling
- Never accept user-supplied file paths.
- Static files served by WhiteNoise or Cloudflare — no user-uploaded media.

---

## Fetch security (RSS + dark intel)

### Source allowlist enforcement
```python
# CORRECT: only fetch from explicitly saved Source/DarkSource records
source = Source.objects.get(pk=pk, enabled=True)
response = requests.get(source.url, ...)

# WRONG: never do this
url = request.GET.get("url")
response = requests.get(url, ...)   # SSRF risk
```

### Required fetch kwargs
```python
{
    "headers": {"User-Agent": settings.INTEL_USER_AGENT},
    "timeout": source.effective_timeout_seconds(),
    "stream": True,
    "allow_redirects": True,
}
```

### Size enforcement (stream + chunk)
Always use `stream=True` and enforce `FEED_MAX_BYTES` / `DARK_MAX_BYTES` during chunk iteration. Already done in `ingest_dark.py` — follow the same pattern in any new fetch logic.

### SSRF mitigation
- Only fetch URLs stored in `Source.url` or `DarkSource.url` (admin-set, not user-set).
- Block fetches to `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` if you ever add user-submitted URLs (not current design).

---

## Dark web fetch security (additional rules)

See `docs/CLAUDE.dark_intel.md` for full dark intel rules.

- **Network isolation**: the container running `ingest_dark` should have egress restricted to `DARK_TOR_SOCKS_URL` only (set in podman-compose or systemd network namespace).
- **Tor-only for .onion**: already enforced in `_should_use_tor()` — don't remove this check.
- **No credentials in dark fetches**: no auth headers, no cookies, no form submissions.
- **Raw content stored with 4 KB cap**: already enforced (`raw=markup[:4000]`). Keep this limit.

---

## Secrets management

### What goes in `.env` (never in code)
- `SECRET_KEY`
- `DB_PASSWORD`
- `DARK_TOR_SOCKS_URL` (contains internal network address)
- Any API keys (if added later)

### What is safe in code / settings
- Default values for non-sensitive config (timeouts, byte limits, user agents)
- Feature flags that don't expose credentials

### Git safety
```
# .gitignore must include:
.env
*.sqlite3
db.sqlite3
```

---

## Dependency security

Run regularly (add to CI):
```bash
pip install pip-audit
pip-audit -r requirements.txt
```

Keep dependencies minimal. Before adding a new package:
1. Check PyPI for known CVEs.
2. Check last release date (abandoned packages are a risk).
3. Add to `requirements.txt` with pinned version.

---

## Rate limiting

### Current state: none in Django code
Mitigations in priority order:
1. **Cloudflare rate limiting** (WAF rules) — apply to `/admin-login/` and `/ops/`.
2. **`django-ratelimit`** — add to login view and any future write endpoints.
3. **gunicorn worker count** — already at 3 workers, limits concurrent abuse.

### Recommended additions (BACKLOG)
```python
# Example: rate limit login to 10 attempts / minute per IP
from django_ratelimit.decorators import ratelimit

@ratelimit(key="ip", rate="10/m", method="POST", block=True)
def admin_login(request):
    ...
```
