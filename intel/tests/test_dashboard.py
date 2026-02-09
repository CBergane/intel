from collections import Counter
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from intel.models import Feed, Item, Source


class DashboardViewTests(TestCase):
    def setUp(self):
        self._idx = 0

    def _create_feed(self, *, source_name, source_slug, section, tags=None):
        source = Source.objects.create(
            name=source_name,
            slug=source_slug,
            tags=tags or [],
        )
        feed = Feed.objects.create(
            source=source,
            name=f"{source_name} Feed",
            url=f"https://example.com/{source_slug}-{section}.xml",
            feed_type=Feed.FeedType.RSS,
            section=section,
        )
        return feed

    def _create_item(self, *, feed, title, summary="", age_hours=0, age_days=0):
        self._idx += 1
        return Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            summary=summary,
            url=f"https://example.com/item-{self._idx}",
            stable_id="",
            published_at=timezone.now() - timedelta(hours=age_hours, days=age_days),
        )

    def test_trending_cve_extraction_and_counting(self):
        feed = self._create_feed(
            source_name="Research Lab",
            source_slug="research-lab",
            section=Feed.Section.RESEARCH,
        )
        self._create_item(
            feed=feed,
            title="Investigation CVE-2026-1111",
            summary="CVE-2026-1111 and CVE-2026-2222",
            age_hours=2,
        )
        self._create_item(
            feed=feed,
            title="Patch cve-2026-1111 now",
            summary="",
            age_hours=3,
        )
        self._create_item(
            feed=feed,
            title="Old CVE-2026-9999 mention",
            summary="",
            age_days=10,
        )

        response = self.client.get("/")
        trending = dict(response.context["trending_cves"])

        self.assertEqual(trending["CVE-2026-1111"], 2)
        self.assertEqual(trending["CVE-2026-2222"], 1)
        self.assertNotIn("CVE-2026-9999", trending)

    def test_advisories_block_balances_per_source(self):
        feed_alpha = self._create_feed(
            source_name="Alpha Advisories",
            source_slug="alpha",
            section=Feed.Section.ADVISORIES,
        )
        feed_beta = self._create_feed(
            source_name="Beta Advisories",
            source_slug="beta",
            section=Feed.Section.ADVISORIES,
        )

        for idx in range(12):
            self._create_item(feed=feed_alpha, title=f"Alpha {idx}", age_hours=idx)
        for idx in range(5):
            self._create_item(feed=feed_beta, title=f"Beta {idx}", age_hours=24 + idx)

        response = self.client.get("/")
        advisories_items = response.context["advisories_items"]
        counts = Counter(item.source.slug for item in advisories_items)

        self.assertEqual(len(advisories_items), 13)
        self.assertEqual(counts["alpha"], 8)
        self.assertEqual(counts["beta"], 5)

    def test_high_signal_scoring_prefers_cve_and_keyword_items(self):
        feed = self._create_feed(
            source_name="Research Source",
            source_slug="research-source",
            section=Feed.Section.RESEARCH,
        )

        plain_title = "Routine update"
        keyword_title = "Exploit analysis"
        cve_title = "Patch for CVE-2026-5555"

        self._create_item(feed=feed, title=plain_title, summary="normal update", age_hours=0)
        self._create_item(
            feed=feed,
            title=keyword_title,
            summary="Actively exploited vulnerability in the wild",
            age_hours=1,
        )
        self._create_item(feed=feed, title=cve_title, summary="details", age_hours=2)

        response = self.client.get("/")
        top_titles = [item.title for item in response.context["high_signal_items"][:3]]

        self.assertEqual(top_titles[0], cve_title)
        self.assertEqual(top_titles[1], keyword_title)
        self.assertEqual(top_titles[2], plain_title)
