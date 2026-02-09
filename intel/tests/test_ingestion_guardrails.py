from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from intel.models import Feed, Item, Source


class IngestionGuardrailTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Guard Source", slug="guard-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Guard Feed",
            url="https://example.com/guard-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )

    def _run_ingest_with_entries(self, entries):
        parsed = SimpleNamespace(entries=entries, bozo=False)
        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(b"<rss/>", 200),
        ), patch(
            "intel.management.commands.ingest_sources.feedparser.parse",
            return_value=parsed,
        ):
            call_command("ingest_sources", feed=str(self.feed.id))

    def test_ingestion_respects_max_age_days(self):
        self.feed.max_age_days = 30
        self.feed.max_items_per_run = 200
        self.feed.save(update_fields=["max_age_days", "max_items_per_run", "updated_at"])

        now = timezone.now()
        entries = [
            {
                "title": "Too old",
                "link": "https://example.com/old",
                "summary": "old",
                "published": (now - timedelta(days=45)).isoformat(),
            },
            {
                "title": "Fresh",
                "link": "https://example.com/fresh",
                "summary": "fresh",
                "published": (now - timedelta(days=2)).isoformat(),
            },
            {
                "title": "No published date",
                "link": "https://example.com/no-date",
                "summary": "fallback to fetched_at",
            },
        ]

        self._run_ingest_with_entries(entries)

        self.assertEqual(Item.objects.count(), 2)
        self.assertFalse(Item.objects.filter(url="https://example.com/old").exists())
        self.assertTrue(Item.objects.filter(url="https://example.com/fresh").exists())
        self.assertTrue(Item.objects.filter(url="https://example.com/no-date").exists())

    def test_ingestion_respects_max_items_per_run(self):
        self.feed.max_age_days = 365
        self.feed.max_items_per_run = 2
        self.feed.save(update_fields=["max_age_days", "max_items_per_run", "updated_at"])

        now = timezone.now().isoformat()
        entries = [
            {
                "title": f"Item {idx}",
                "link": f"https://example.com/item-{idx}",
                "summary": "entry",
                "published": now,
            }
            for idx in range(5)
        ]

        self._run_ingest_with_entries(entries)

        self.assertEqual(Item.objects.count(), 2)
        self.assertEqual(
            list(Item.objects.order_by("id").values_list("url", flat=True)),
            ["https://example.com/item-0", "https://example.com/item-1"],
        )


class PruneItemsCommandTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Prune Source", slug="prune-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Prune Feed",
            url="https://example.com/prune-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            max_age_days=10,
        )

    def test_prune_items_dry_run_works(self):
        now = timezone.now()
        Item.objects.create(
            source=self.source,
            feed=self.feed,
            title="Old item",
            url="https://example.com/old-item",
            stable_id="",
            published_at=now - timedelta(days=41),
            summary="old",
        )
        Item.objects.create(
            source=self.source,
            feed=self.feed,
            title="Recent item",
            url="https://example.com/recent-item",
            stable_id="",
            published_at=now - timedelta(days=5),
            summary="recent",
        )

        output = StringIO()
        call_command("prune_items", "--dry-run", stdout=output)
        text = output.getvalue()

        self.assertEqual(Item.objects.count(), 2)
        self.assertIn("would_delete=1", text)
