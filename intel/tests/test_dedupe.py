from django.test import TestCase

from intel.ingestion import upsert_item
from intel.models import Feed, Item, Source


class DedupeTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Example Source", slug="example-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Example Feed",
            url="https://example.com/feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )

    def test_dedupe_by_canonical_url(self):
        first_entry = {
            "title": "Critical advisory",
            "link": "https://example.com/advisory?id=42&utm_source=rss",
            "summary": "<p>Initial <strong>summary</strong></p>",
            "published": "2026-02-08T10:00:00+00:00",
        }
        second_entry = {
            "title": "Critical advisory",
            "link": "https://example.com/advisory?utm_medium=email&id=42",
            "summary": "<p>Updated summary<script>alert(1)</script></p>",
            "published": "2026-02-08T11:00:00+00:00",
        }

        first_item, created_first = upsert_item(self.feed, first_entry)
        second_item, created_second = upsert_item(self.feed, second_entry)

        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(Item.objects.count(), 1)
        self.assertEqual(first_item.id, second_item.id)

        saved = Item.objects.get()
        self.assertEqual(saved.canonical_url, "https://example.com/advisory?id=42")
        self.assertEqual(saved.summary, "Updated summary")

    def test_dedupe_by_title_hash_when_url_missing(self):
        entry_a = {
            "title": "  Zero-day watch  ",
            "summary": "first",
            "published": "2026-02-08T01:00:00+00:00",
        }
        entry_b = {
            "title": "Zero-day   watch",
            "summary": "second",
            "published": "2026-02-08T23:00:00+00:00",
        }

        _, created_a = upsert_item(self.feed, entry_a)
        _, created_b = upsert_item(self.feed, entry_b)

        self.assertTrue(created_a)
        self.assertFalse(created_b)
        self.assertEqual(Item.objects.count(), 1)
