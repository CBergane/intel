import time
from datetime import timedelta

import feedparser
import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from intel.ingestion import parse_entry_datetime, upsert_item
from intel.models import Feed, FetchRun


class Command(BaseCommand):
    help = "Fetch enabled feeds and upsert deduplicated items."

    def add_arguments(self, parser):
        parser.add_argument(
            "--feed",
            help="Optional feed id, source slug, or exact feed name to ingest.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch and parse only, without writing items.",
        )

    def handle(self, *args, **options):
        feeds = Feed.objects.filter(enabled=True, source__enabled=True).select_related("source")

        feed_selector = options.get("feed")
        if feed_selector:
            if str(feed_selector).isdigit():
                feeds = feeds.filter(id=int(feed_selector))
            else:
                feeds = feeds.filter(
                    Q(source__slug=feed_selector) | Q(name__iexact=feed_selector)
                )

        if not feeds.exists():
            self.stdout.write(self.style.WARNING("No enabled feeds matched."))
            return

        total_new = 0
        total_updated = 0

        for feed in feeds:
            run = FetchRun.objects.create(feed=feed, started_at=timezone.now())
            started = time.monotonic()
            try:
                payload, status = self._fetch_with_retries(feed)
                run.http_status = status
                fetched_at = run.started_at

                if feed.feed_type == Feed.FeedType.JSON:
                    raise NotImplementedError(
                        "JSON ingestion is not implemented yet. Use rss/atom feeds for now."
                    )

                parsed = feedparser.parse(payload)
                if getattr(parsed, "bozo", False) and getattr(parsed, "entries", None) is None:
                    raise ValueError(f"Invalid feed payload: {parsed.bozo_exception}")

                items_new = 0
                items_updated = 0
                processed_entries = 0
                skipped_old = 0
                cutoff = fetched_at - timedelta(days=feed.max_age_days)

                for entry in parsed.entries:
                    if processed_entries >= feed.max_items_per_run:
                        break
                    processed_entries += 1

                    published_at = parse_entry_datetime(entry, fallback=fetched_at)
                    if published_at < cutoff:
                        skipped_old += 1
                        continue

                    if options["dry_run"]:
                        continue
                    _, created = upsert_item(feed, entry, published_at=published_at)
                    if created:
                        items_new += 1
                    else:
                        items_updated += 1

                run.ok = True
                run.items_new = items_new
                run.items_updated = items_updated
                run.finished_at = timezone.now()
                run.duration_ms = int((time.monotonic() - started) * 1000)
                run.save()

                feed.last_success_at = run.finished_at
                feed.last_error = ""
                feed.save(update_fields=["last_success_at", "last_error", "updated_at"])

                total_new += items_new
                total_updated += items_updated

                self.stdout.write(
                    self.style.SUCCESS(
                        f"[{feed.id}] {feed.name}: +{items_new} new / {items_updated} updated / "
                        f"{skipped_old} skipped-old / {processed_entries} processed"
                    )
                )
            except Exception as exc:
                run.ok = False
                run.error = str(exc)[:4000]
                run.finished_at = timezone.now()
                run.duration_ms = int((time.monotonic() - started) * 1000)
                run.save()

                feed.last_error = str(exc)[:2000]
                feed.save(update_fields=["last_error", "updated_at"])

                self.stderr.write(self.style.ERROR(f"[{feed.id}] {feed.name}: {exc}"))

        self.stdout.write(
            self.style.SUCCESS(
                f"Done. total_new={total_new}, total_updated={total_updated}"
            )
        )

    def _fetch_with_retries(self, feed):
        retries = max(settings.INTEL_FETCH_RETRIES, 1)
        last_error = None

        for attempt in range(1, retries + 1):
            try:
                return self._fetch_once(feed)
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(2 ** (attempt - 1))

        raise RuntimeError(
            f"Failed to fetch feed after {retries} attempt(s): {last_error}"
        )

    def _fetch_once(self, feed):
        timeout = max(1, min(feed.timeout_seconds, settings.INTEL_FETCH_TIMEOUT))
        max_bytes = max(1, min(feed.max_bytes, settings.INTEL_FETCH_MAX_BYTES))

        response = requests.get(
            feed.url,
            headers={
                "User-Agent": settings.INTEL_USER_AGENT,
                "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
            },
            timeout=timeout,
            stream=True,
        )
        response.raise_for_status()

        size = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"Feed response exceeded max_bytes={max_bytes}")
            chunks.append(chunk)

        return b"".join(chunks), response.status_code
