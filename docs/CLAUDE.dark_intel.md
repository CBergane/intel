# CLAUDE.dark_intel.md — Dark web intel approach

## Design philosophy

Dark intel monitoring is **passive, read-only, allowlist-only**.

- **No interaction**: only GET requests, no form submissions, no logins, no POST/PUT/DELETE.
- **No authentication to dark sites**: if a source requires credentials, it's out of scope.
- **No indiscriminate crawling**: only explicitly configured `DarkSource` records are fetched.
- **Keyword/regex matching drives signal**: raw HTML is stored briefly for debugging only (4 KB cap).
- **Isolation from RSS intel**: `DarkHit` never appears in the main `Item` feed.

---

## Current architecture

```
DarkSource (admin-configured)
    │
    ├── source_type = single_page  → fetch one URL
    ├── source_type = index_page   → fetch root, extract same-host links (≤ DARK_INDEX_MAX_LINKS)
    └── source_type = feed         → parse RSS/Atom, follow same-host entry links
         │
    _fetch_with_retries()
         │
    ┌────┴──────────────────────┐
    │  Tor SOCKS5 proxy         │  ← if .onion or source.use_tor = True
    │  socks5h://127.0.0.1:9050 │  ← DNS through Tor (socks5h)
    └───────────────────────────┘
         │
    _upsert_document_and_hits()
         │
    ├── DarkDocument (dedup by canonical_url per source)
    ├── DarkSnapshot (on content change)
    └── DarkHit (if keyword/regex matched)
```

---

## Network isolation — CRITICAL

The Podman container running `ingest_dark` MUST have restricted egress.

### Option A: Separate ingest container (recommended)
Add a second service to `podman-compose.yml`:

```yaml
services:
  web:
    build: .
    # ... existing web config

  dark-ingest:
    build: .
    command: ["python", "manage.py", "ingest_dark", "--settings=config.settings.prod"]
    environment:
      - DARK_TOR_SOCKS_URL=socks5h://tor:9050
    depends_on:
      - tor
    networks:
      - dark_net      # isolated network with only tor access
    restart: unless-stopped

  tor:
    image: docker.io/library/debian:slim
    # or use a dedicated tor image
    networks:
      - dark_net
      - internet
```

### Option B: Systemd network namespace (advanced)
Run `ingest_dark` in a network namespace that only routes through the Tor SOCKS proxy.

### Minimum requirement
At a minimum, document in `podman-compose.yml` that the dark-ingest service routes through Tor.

---

## Tor configuration

### socks5h vs socks5
Always use `socks5h://` — the `h` means DNS resolution happens on the Tor proxy side (inside Tor), not locally. This prevents DNS leaks.

Current setting: `DARK_TOR_SOCKS_URL=socks5h://127.0.0.1:9050` ✅

For podman-compose, use service name: `socks5h://tor:9050`

### Tor container / daemon
If running on the Proxmox LXC, install Tor as a system service:
```bash
apt-get install tor
# /etc/tor/torrc — default settings are fine for SOCKS proxy use
systemctl enable --now tor
```

Verify Tor is working:
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## Adding a new DarkSource

### Via Django admin panel (`/admin-panel/dark-sources/`)
Fields to set:
- `name` + `slug`: human-readable identifier
- `url`: the root URL to monitor (can be .onion or clearnet)
- `source_type`: `single_page` / `index_page` / `feed`
- `use_tor`: check if clearnet source should go through Tor anyway
- `watch_keywords`: comma-separated keywords (e.g. `borealsec, exploit, cve-2024`)
- `watch_regex`: one pattern per line (e.g. `CVE-\d{4}-\d+`)
- `timeout_seconds`, `max_bytes`, `fetch_retries`: override defaults

### Validation rules (enforced in admin)
- `.onion` URLs automatically use Tor regardless of `use_tor` flag.
- If URL pattern looks like an RSS feed but `source_type` is not `feed`, a warning is shown.
- If URL looks like a news/blog site, a warning suggests using standard intel feeds instead.

---

## DarkHit lifecycle

```
ingest_dark runs
    │
    ├── keyword/regex matches → DarkHit created (new content hash per document)
    ├── same content, same doc → DarkHit.last_seen_at updated
    └── no match → only DarkDocument + DarkSnapshot updated

DarkHit on dashboard
    │
    ├── sorted by detected_at DESC
    ├── filtered by dark_source, matched_keywords, date range
    └── linked to DarkDocument (for snapshot history)
```

---

## Dark dashboard — current state & next steps

### What exists
- `templates/intel/dark/dashboard.html` ✅
- `DarkHit`, `DarkDocument`, `DarkSnapshot` models ✅
- `DarkSource` admin form ✅

### What's missing / incomplete
- [ ] **Dark dashboard view** (`intel/views.py`) — needs wiring
- [ ] **URL registration** — `/dark/` route not yet in `intel/urls.py`
- [ ] **Pagination** on the dark dashboard
- [ ] **Filter by keyword match** on dark dashboard
- [ ] **Alert webhook** — send Discord/Slack notification on new `DarkHit`
- [ ] **Scheduled ingest** — `ingest_dark` should run on a cron or Podman systemd timer

### Prompt for Claude Code: wire dark dashboard view
```
Add a superuser-only dark dashboard view at /dark/ that shows:
- DarkHit list (paginated, 50/page), sorted by detected_at DESC
- Filter by: DarkSource slug (URL param ?source=), date range (?days=7/30/90)
- Each hit shows: source name, title, excerpt, matched_keywords, detected_at, link to DarkDocument
- The view must require @superuser_required (not just login_required)
- Template: templates/intel/dark/dashboard.html (extend and fill content block)
- Add URL to intel/urls.py and admin_urls.py (under /dark/ prefix)
- Add test in intel/tests/test_dark_dashboard.py covering:
  - Anonymous user → redirect to login
  - Non-superuser → 403
  - Superuser → 200 with hit list
  - Source filter works
```

---

## What NOT to do with dark intel

| ❌ Don't | Why |
|---------|-----|
| Store `.onion` login credentials | Out of scope, legal/ethical risk |
| Interact with marketplace checkout/cart pages | Active interaction, not passive monitoring |
| Follow off-host links | Crawling scope creep |
| Display raw HTML from dark sources in the UI | XSS risk, store as plain text only |
| Log full Tor circuit info | OPSEC — don't expose exit nodes in app logs |
| Run dark ingest without Tor when fetching .onion | Network error anyway, but add assertion |

---

## Security note on raw content

The `raw` field on `DarkSnapshot` and `DarkHit` stores the first 4 KB of raw markup. This is for debugging only:

1. Never render `raw` as HTML in any template (use `{{ hit.raw | escape }}` or don't show it at all).
2. In the admin panel, show `raw` as a `<pre>` block with escaping.
3. Consider adding a `show_raw` permission separate from superuser if raw content is exposed more broadly.
