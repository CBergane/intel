"""
Management command: check_hibp_domains

Queries the HaveIBeenPwned v3 API for breaches affecting monitored domains
and upserts one Item per domain breach (not per individual account address).

Usage:
    python manage.py check_hibp_domains [--domains example.com,example.se]

Settings required:
    HIBP_API_KEY   — API key from haveibeenpwned.com
    HIBP_DOMAINS   — comma-separated list of domains to check (fallback if --domains not given)
"""
import time

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from intel.ingestion import NormalizedEntry, upsert_normalized_item
from intel.models import Feed, Source
from intel.utils import canonicalize_url, normalize_title, sanitize_summary

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_HIBP_SOURCE_SLUG = "hibp"
_HIBP_FEED_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
_RATE_LIMIT_SLEEP = 1.5  # seconds between requests (HIBP free tier: 1 req/1.5 s)


class Command(BaseCommand):
    help = "Check HIBP for domain breaches and upsert one Item per breach per domain."

    def add_arguments(self, parser):
        parser.add_argument(
            "--domains",
            help="Comma-separated domains to check. Overrides HIBP_DOMAINS setting.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch and print results without writing items.",
        )

    def handle(self, *args, **options):
        api_key = getattr(settings, "HIBP_API_KEY", "")
        if not api_key:
            self.stderr.write(self.style.ERROR("HIBP_API_KEY is not configured. Aborting."))
            return

        if options.get("domains"):
            domains = [d.strip() for d in options["domains"].split(",") if d.strip()]
        else:
            domains = list(getattr(settings, "HIBP_DOMAINS", []))

        if not domains:
            self.stdout.write(self.style.WARNING("No domains configured. Use --domains or set HIBP_DOMAINS."))
            return

        feed = self._get_or_create_feed()

        total_new = 0
        total_updated = 0

        for i, domain in enumerate(domains):
            if i > 0:
                time.sleep(_RATE_LIMIT_SLEEP)

            try:
                breaches = self._fetch_domain_breaches(domain, api_key)
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f"[{domain}] fetch failed: {exc}"))
                continue

            if not breaches:
                self.stdout.write(f"[{domain}] no breaches found.")
                continue

            for breach in breaches:
                entry = self._breach_to_entry(domain, breach)
                if options["dry_run"]:
                    self.stdout.write(
                        self.style.WARNING(f"[dry-run] {domain}: {entry.title}")
                    )
                    continue

                item, created = upsert_normalized_item(feed, entry)
                if created:
                    total_new += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"[{domain}] NEW: {entry.title}")
                    )
                else:
                    total_updated += 1

        if not options["dry_run"]:
            self.stdout.write(
                self.style.SUCCESS(f"Done. new={total_new} updated={total_updated}")
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create_feed(self) -> Feed:
        source, _ = Source.objects.get_or_create(
            slug=_HIBP_SOURCE_SLUG,
            defaults={
                "name": "HaveIBeenPwned",
                "homepage": "https://haveibeenpwned.com",
                "tags": ["credential", "breach", "threat-intel"],
                "enabled": True,
            },
        )
        # Use a stable synthetic URL as the feed identifier
        feed_url = "https://haveibeenpwned.com/api/v3/breacheddomain/"
        feed, _ = Feed.objects.get_or_create(
            url=feed_url,
            defaults={
                "source": source,
                "name": "HIBP Domain Breach Check",
                "feed_type": Feed.FeedType.JSON,
                "adapter_key": "hibp_domain",
                "section": Feed.Section.ACTIVE,
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 500_000,
                "max_age_days": 3650,
                "max_items_per_run": 1000,
            },
        )
        return feed

    def _fetch_domain_breaches(self, domain: str, api_key: str) -> list[dict]:
        url = f"{_HIBP_BASE}/breacheddomain/{domain}"
        resp = requests.get(
            url,
            headers={
                "hibp-api-key": api_key,
                "User-Agent": getattr(settings, "INTEL_USER_AGENT", "borealsec-intel-bot/0.1"),
            },
            timeout=getattr(settings, "INTEL_FETCH_TIMEOUT", 10),
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        # HIBP returns {email: [breach_name, ...], ...}
        # Collect unique breach names; never log individual email addresses
        breach_names: set[str] = set()
        if isinstance(data, dict):
            for breach_list in data.values():
                if isinstance(breach_list, list):
                    breach_names.update(str(b) for b in breach_list)
        return [{"breach_name": name, "domain": domain} for name in sorted(breach_names)]

    def _breach_to_entry(self, domain: str, breach: dict) -> NormalizedEntry:
        breach_name = str(breach.get("breach_name") or "")
        title = normalize_title(f"{domain} found in {breach_name} breach")
        url = f"https://haveibeenpwned.com/PwnedWebsites#{breach_name}"
        canonical_url = canonicalize_url(url)
        external_id = f"{domain}:{breach_name}"
        summary = sanitize_summary(
            f"Domain {domain} has accounts in the {breach_name} breach. "
            "See HIBP for details. Individual addresses are not stored."
        )
        return NormalizedEntry(
            title=title,
            url=url,
            canonical_url=canonical_url,
            published_at=timezone.now(),
            summary=summary,
            raw_payload={"domain": domain, "breach_name": breach_name},
            external_id=external_id,
        )
