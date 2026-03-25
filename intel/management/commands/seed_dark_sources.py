import sys

import requests
from django.core.management.base import BaseCommand

from intel.models import DarkSource

RANSOMWARE_LIVE_API = "https://api.ransomware.live/v2/groups"
RANSOMWATCH_MAX_BYTES = 2_000_000
RANSOMWATCH_TIMEOUT = 15

WATCH_GROUPS = {
    "ransomhub": {
        "display_name": "RansomHub Leaks",
        "watch_keywords": "sweden,sverige,stockholm,nordic,.se,gothenburg,malmö,göteborg",
        "tags": ["ransomware", "leaks", "priority"],
        "notes": "Source: joshhighet/ransomwatch + CISA AA24-242A",
    },
    "play": {
        "display_name": "Play Ransomware",
        "watch_keywords": "sweden,sverige,.se,nordic,stockholm",
        "tags": ["ransomware", "leaks"],
        "notes": "Source: joshhighet/ransomwatch + CISA AA23-352A",
    },
    "clop": {
        "display_name": "Cl0p Leaks",
        "watch_keywords": "sweden,sverige,.se,nordic,cleo",
        "tags": ["ransomware", "leaks"],
        "notes": "Source: joshhighet/ransomwatch",
    },
    "lockbit3": {
        "display_name": "LockBit 3.0",
        "watch_keywords": "sweden,sverige,.se,nordic",
        "tags": ["ransomware", "leaks"],
        "notes": "Source: joshhighet/ransomwatch + CISA AA23-325A",
        "enabled": False,  # Aktivera manuellt efter verifiering
    },
    "akira": {
        "display_name": "Akira Ransomware",
        "watch_keywords": "sweden,sverige,.se,nordic,stockholm",
        "tags": ["ransomware", "leaks"],
        "notes": "Source: joshhighet/ransomwatch + CISA AA24-109A",
    },
    "medusa": {
        "display_name": "Medusa Ransomware",
        "watch_keywords": "sweden,sverige,.se,nordic",
        "tags": ["ransomware", "leaks"],
        "notes": "Source: joshhighet/ransomwatch",
    },
}


def _truncate_fqdn(fqdn: str) -> str:
    """Show first 9 + '...' + last 7 chars so .onion suffix is visible."""
    if len(fqdn) <= 20:
        return fqdn
    return fqdn[:9] + "..." + fqdn[-7:]


def _pick_available_page(pages: list) -> dict | None:
    """Return first page dict where available=True, or None."""
    for page in pages:
        if isinstance(page, dict) and page.get("available"):
            return page
    return None


def _fetch_ransomwatch() -> list:
    """Fetch and return the ransomware.live groups list. Raises on error."""
    response = requests.get(
        RANSOMWARE_LIVE_API,
        timeout=RANSOMWATCH_TIMEOUT,
        stream=True,
        headers={"User-Agent": "borealsec-intel-bot/0.1"},
    )
    response.raise_for_status()

    size = 0
    chunks = []
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        size += len(chunk)
        if size > RANSOMWATCH_MAX_BYTES:
            raise ValueError(
                f"Ransomwatch API response exceeded max_bytes={RANSOMWATCH_MAX_BYTES}"
            )
        chunks.append(chunk)

    import json
    return json.loads(b"".join(chunks).decode("utf-8", errors="replace"))


class Command(BaseCommand):
    help = (
        "Seed DarkSource entries from ransomware.live community API. "
        "Creates or updates onion addresses for known ransomware leak sites."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be created/updated without writing to the database.",
        )

    def handle(self, *args, **options):
        dry_run = bool(options.get("dry_run"))

        self.stdout.write("Fetching ransomware.live API...")
        try:
            groups_list = _fetch_ransomwatch()
        except Exception as exc:
            self.stderr.write(f"Failed to fetch ransomware.live API: {exc}")
            sys.exit(1)

        if not isinstance(groups_list, list):
            self.stderr.write("Unexpected ransomware.live API response format (not a list).")
            sys.exit(1)

        self.stdout.write(f"Found {len(groups_list)} groups in ransomware.live.")

        # Build lookup: slug → group dict
        api_by_slug = {
            g["slug"]: g
            for g in groups_list
            if isinstance(g, dict) and g.get("slug")
        }

        created_count = 0
        updated_count = 0
        skipped_count = 0

        self.stdout.write("Processing WATCH_GROUPS:")

        for slug, cfg in WATCH_GROUPS.items():
            group = api_by_slug.get(slug)
            if group is None:
                self.stdout.write(f"  \u2717 {slug} \u2014 not found in API (skipped)")
                skipped_count += 1
                continue

            page = _pick_available_page(group.get("locations") or [])
            if page is None:
                self.stdout.write(f"  \u2717 {slug} \u2014 no available page (skipped)")
                skipped_count += 1
                continue

            fqdn = page["fqdn"]
            url = f"http://{fqdn}"

            # Safety: only accept well-formed onion URLs
            if not (url.startswith("http://") and fqdn.endswith(".onion")):
                self.stderr.write(
                    f"  \u2717 {slug} \u2014 invalid fqdn '{fqdn[:30]}' (skipped)"
                )
                skipped_count += 1
                continue

            enabled = cfg.get("enabled", True)
            display = _truncate_fqdn(fqdn)

            if dry_run:
                try:
                    existing = DarkSource.objects.get(slug=slug)
                    if existing.url != url:
                        self.stdout.write(
                            f"  [dry-run] would update {slug} url ({display})"
                        )
                    else:
                        self.stdout.write(
                            f"  [dry-run] {slug} already up-to-date"
                        )
                except DarkSource.DoesNotExist:
                    self.stdout.write(
                        f"  [dry-run] would create {slug} ({display})"
                    )
                continue

            source, source_created = DarkSource.objects.get_or_create(
                slug=slug,
                defaults={
                    "name": cfg["display_name"],
                    "url": url,
                    "source_type": DarkSource.SourceType.SINGLE_PAGE,
                    "enabled": enabled,
                    "use_tor": True,
                    "tags": cfg["tags"],
                    "watch_keywords": cfg["watch_keywords"],
                },
            )

            # Assert use_tor — never silently skip Tor for onion sources
            assert source.use_tor, (
                f"DarkSource {slug!r} has use_tor=False — onion sources must use Tor."
            )

            if source_created:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  \u2713 {cfg['display_name']} \u2014 created ({display})"
                    )
                )
                created_count += 1
            elif source.url != url:
                source.url = url
                source.save(update_fields=["url", "updated_at"])
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  \u2713 {cfg['display_name']} \u2014 url updated ({display})"
                    )
                )
                updated_count += 1
            else:
                self.stdout.write(
                    f"  \u2713 {cfg['display_name']} \u2014 already up-to-date"
                )

        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Done. Created: {created_count} / "
                    f"Updated: {updated_count} / "
                    f"Skipped: {skipped_count}"
                )
            )
        else:
            self.stdout.write("[dry-run] No database changes made.")
