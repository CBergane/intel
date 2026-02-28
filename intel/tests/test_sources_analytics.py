from datetime import timedelta
from django.urls import reverse
from django.test import TestCase
from django.utils import timezone

from intel.models import Feed, FetchRun, Item, Source


class SourcesAnalyticsViewTests(TestCase):
    def setUp(self):
        now = timezone.now()

        self.source_alpha = Source.objects.create(
            name="Alpha Source",
            slug="alpha-source",
            homepage="https://example.com/" + ("very-long-path-" * 12),
            tags=["vendor", "sweden"],
        )
        self.source_beta = Source.objects.create(
            name="Beta Source",
            slug="beta-source",
            homepage="https://beta.example.org/security",
            tags=["research"],
        )

        self.alpha_feed_ok = Feed.objects.create(
            source=self.source_alpha,
            name="Alpha Feed OK",
            url="https://example.com/alpha-ok.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            enabled=True,
        )
        self.alpha_feed_err = Feed.objects.create(
            source=self.source_alpha,
            name="Alpha Feed Err",
            url="https://example.com/alpha-err.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.RESEARCH,
            enabled=True,
            last_error="Timeout",
        )
        self.beta_feed_never = Feed.objects.create(
            source=self.source_beta,
            name="Beta Feed Never",
            url="https://example.com/beta-never.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.RESEARCH,
            enabled=True,
        )

        FetchRun.objects.create(
            feed=self.alpha_feed_ok,
            started_at=now - timedelta(hours=2),
            finished_at=now - timedelta(hours=2),
            ok=True,
            http_status=200,
            items_new=3,
            items_updated=1,
        )
        FetchRun.objects.create(
            feed=self.alpha_feed_err,
            started_at=now - timedelta(hours=3),
            finished_at=now - timedelta(hours=3),
            ok=False,
            error="Fetch failed",
            http_status=500,
        )

        Item.objects.create(
            source=self.source_alpha,
            feed=self.alpha_feed_ok,
            title="Alpha fresh",
            summary="",
            url="https://example.com/a1",
            stable_id="",
            published_at=now - timedelta(hours=6),
        )
        Item.objects.create(
            source=self.source_alpha,
            feed=self.alpha_feed_ok,
            title="Alpha week",
            summary="",
            url="https://example.com/a2",
            stable_id="",
            published_at=now - timedelta(days=3),
        )
        Item.objects.create(
            source=self.source_alpha,
            feed=self.alpha_feed_ok,
            title="Alpha old",
            summary="",
            url="https://example.com/a3",
            stable_id="",
            published_at=now - timedelta(days=12),
        )

    def test_sources_page_renders_analytics_cards(self):
        response = self.client.get(reverse("sources"))
        self.assertEqual(response.status_code, 200)

        cards = {card["source"].slug: card for card in response.context["source_cards"]}
        alpha = cards["alpha-source"]
        beta = cards["beta-source"]

        self.assertEqual(alpha["new_24h"], 1)
        self.assertEqual(alpha["new_7d"], 2)
        self.assertEqual(alpha["item_count"], 3)
        self.assertEqual(alpha["status"], "Degraded")

        self.assertEqual(beta["new_24h"], 0)
        self.assertEqual(beta["new_7d"], 0)
        self.assertEqual(beta["item_count"], 0)
        self.assertEqual(beta["status"], "Never")

        self.assertContains(response, "Degraded")
        self.assertContains(response, "Never")
        self.assertContains(response, "New 24h")
        self.assertContains(response, "New 7d")
        self.assertContains(response, "Total")
        self.assertContains(response, "truncate overflow-hidden")
