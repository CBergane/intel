import time
from datetime import timedelta

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from intel.ingestion import (
    is_valid_normalized_entry,
    parse_feed_payload,
    upsert_normalized_item,
)
from intel.models import Feed, FetchRun
from intel.notifications import (
    get_generic_intel_alert_context,
    send_generic_intel_alert,
    send_high_epss_alert,
    send_ransomware_victim_alert,
)


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
        parser.add_argument(
            "--since-days",
            type=int,
            help="Override age window for this run (use with --feed for scoped backfills).",
        )
        parser.add_argument(
            "--max-items",
            type=int,
            help="Override max items per feed for this run (use with --feed for scoped backfills).",
        )
        parser.add_argument(
            "--expanded",
            action="store_true",
            help="Use feed expanded collection settings for this run.",
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
        total_skipped_old = 0
        total_skipped_invalid = 0
        total_fetched = 0
        total_limited = 0

        for feed in feeds:
            run = FetchRun.objects.create(feed=feed, started_at=timezone.now())
            started = time.monotonic()
            try:
                payload, status = self._fetch_with_retries(feed)
                run.http_status = status
                fetched_at = run.started_at

                entries = parse_feed_payload(feed, payload, fetched_at=fetched_at)
                max_items, max_age_days = self._effective_limits(feed, options)
                cutoff = fetched_at - timedelta(days=max_age_days)

                run.items_fetched = len(entries)
                run.items_limited = max(0, len(entries) - max_items)

                items_new = 0
                items_updated = 0
                skipped_old = 0
                skipped_invalid = 0
                processed_entries = 0

                for entry in entries[:max_items]:
                    processed_entries += 1
                    if not is_valid_normalized_entry(entry, feed=feed):
                        skipped_invalid += 1
                        continue
                    if entry.published_at < cutoff:
                        skipped_old += 1
                        continue

                    if options["dry_run"]:
                        continue

                    item, created = upsert_normalized_item(feed, entry)
                    if created:
                        items_new += 1
                        if feed.adapter_key == "epss":
                            send_high_epss_alert(item)
                        elif feed.adapter_key == "ransomware_live_victims":
                            send_ransomware_victim_alert(item)
                        else:
                            generic_alert_context = get_generic_intel_alert_context(item)
                            if generic_alert_context:
                                send_generic_intel_alert(item, **generic_alert_context)
                    else:
                        items_updated += 1

                run.ok = True
                run.items_new = items_new
                run.items_updated = items_updated
                run.items_stored = items_new + items_updated
                run.items_deduped = items_updated
                run.items_skipped_old = skipped_old
                run.items_skipped_invalid = skipped_invalid
                run.finished_at = timezone.now()
                run.duration_ms = int((time.monotonic() - started) * 1000)
                run.save()

                feed.last_success_at = run.finished_at
                feed.last_error = ""
                feed.save(update_fields=["last_success_at", "last_error", "updated_at"])

                total_new += items_new
                total_updated += items_updated
                total_skipped_old += skipped_old
                total_skipped_invalid += skipped_invalid
                total_fetched += run.items_fetched
                total_limited += run.items_limited

                self.stdout.write(
                    self.style.SUCCESS(
                        f"[{feed.id}] {feed.name}: "
                        f"fetched={run.items_fetched} limited={run.items_limited} "
                        f"stored={run.items_stored} (new={items_new} deduped={items_updated}) "
                        f"skip_old={skipped_old} skip_invalid={skipped_invalid} "
                        f"processed={processed_entries} window={max_age_days}d"
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
                "Done. "
                f"fetched={total_fetched}, new={total_new}, deduped={total_updated}, "
                f"skipped_old={total_skipped_old}, skipped_invalid={total_skipped_invalid}, "
                f"limited={total_limited}"
            )
        )

    def _effective_limits(self, feed: Feed, options):
        since_override = options.get("since_days")
        max_items_override = options.get("max_items")
        use_expanded = options.get("expanded") or feed.expanded_collection

        if use_expanded:
            max_items = feed.expanded_max_items_per_run or max(feed.max_items_per_run, 1000)
            max_age_days = feed.expanded_max_age_days or max(feed.max_age_days, 365)
        else:
            max_items = feed.max_items_per_run
            max_age_days = feed.max_age_days

        if since_override is not None:
            max_age_days = max(1, since_override)
        if max_items_override is not None:
            max_items = max(1, max_items_override)

        return max_items, max_age_days

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
        max_bytes = max(1, min(feed.max_bytes, settings.FEED_MAX_BYTES))

        response = requests.get(
            feed.url,
            headers={
                "User-Agent": settings.INTEL_USER_AGENT,
                "Accept": (
                    "application/rss+xml, application/atom+xml, application/xml;q=0.9, "
                    "application/json;q=0.9, */*;q=0.8"
                ),
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
