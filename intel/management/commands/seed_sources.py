from django.core.management.base import BaseCommand

from intel.models import Feed, Source
from intel.tier1_sources import DISABLED_FEED_URLS, TIER1_SOURCES


class Command(BaseCommand):
    help = "Create or update Tier-1 sources and feeds idempotently."

    def handle(self, *args, **options):
        source_created = 0
        source_updated = 0
        feed_created = 0
        feed_updated = 0
        source_errors = 0
        feed_errors = 0
        disabled_broken_feeds = self._disable_broken_feeds()

        for source_data in TIER1_SOURCES:
            try:
                source, created, updated = self._upsert_source(source_data)
                if created:
                    source_created += 1
                elif updated:
                    source_updated += 1
            except Exception as exc:
                source_errors += 1
                self.stderr.write(
                    self.style.ERROR(
                        f"[source:{source_data['slug']}] upsert failed: {exc}"
                    )
                )
                continue

            for feed_data in source_data["feeds"]:
                try:
                    _, was_created, was_updated = self._upsert_feed(source, feed_data)
                    if was_created:
                        feed_created += 1
                    elif was_updated:
                        feed_updated += 1
                except Exception as exc:
                    feed_errors += 1
                    self.stderr.write(
                        self.style.ERROR(
                            f"[feed:{feed_data['url']}] upsert failed: {exc}"
                        )
                    )

        self.stdout.write(
            self.style.SUCCESS(
                "Seed complete. "
                f"sources_created={source_created}, "
                f"sources_updated={source_updated}, "
                f"feeds_created={feed_created}, "
                f"feeds_updated={feed_updated}, "
                f"source_errors={source_errors}, "
                f"feed_errors={feed_errors}, "
                f"disabled_broken_feeds={disabled_broken_feeds}"
            )
        )

    def _disable_broken_feeds(self):
        return Feed.objects.filter(url__in=DISABLED_FEED_URLS, enabled=True).update(
            enabled=False
        )

    def _upsert_source(self, source_data):
        seed_slug = source_data["slug"]
        seed_name = source_data["name"]
        desired = {
            "slug": seed_slug,
            "name": seed_name,
            "homepage": source_data.get("homepage", ""),
            "tags": source_data.get("tags", []),
            "enabled": source_data.get("enabled", True),
        }

        try:
            source = Source.objects.get(slug=seed_slug)
        except Source.DoesNotExist:
            try:
                source = Source.objects.get(name=seed_name)
            except Source.DoesNotExist:
                source = Source.objects.create(**desired)
                return source, True, False

        changed_fields = []
        for field, value in desired.items():
            if getattr(source, field) != value:
                setattr(source, field, value)
                changed_fields.append(field)

        if changed_fields:
            source.save(update_fields=[*changed_fields, "updated_at"])
            return source, False, True
        return source, False, False

    def _upsert_feed(self, source, feed_data):
        defaults = {
            "source": source,
            "name": feed_data["name"],
            "feed_type": feed_data.get("feed_type", Feed.FeedType.RSS),
            "section": feed_data["section"],
            "enabled": feed_data.get("enabled", True),
            "timeout_seconds": feed_data.get("timeout_seconds", 10),
            "max_bytes": feed_data.get("max_bytes", 1_500_000),
            "max_age_days": feed_data.get("max_age_days", 180),
            "max_items_per_run": feed_data.get("max_items_per_run", 200),
        }
        feed, created = Feed.objects.get_or_create(url=feed_data["url"], defaults=defaults)
        if created:
            return feed, True, False

        changed_fields = []
        for field, value in defaults.items():
            if getattr(feed, field) != value:
                setattr(feed, field, value)
                changed_fields.append(field)

        if changed_fields:
            feed.save(update_fields=[*changed_fields, "updated_at"])
            return feed, False, True
        return feed, False, False
