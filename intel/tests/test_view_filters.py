from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, Item, Source


class ItemListFilterBehaviorTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Filter Source", slug="filter-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Filter Feed",
            url="https://example.com/filter-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )

    def _create_item(self, *, title: str, days_ago: int):
        now = timezone.now()
        return Item.objects.create(
            source=self.source,
            feed=self.feed,
            title=title,
            url=f"https://example.com/{title.replace(' ', '-').lower()}",
            stable_id="",
            published_at=now - timedelta(days=days_ago),
            summary=title,
        )

    def test_time_window_and_search_visibility_metrics(self):
        self._create_item(title="Alpha advisory", days_ago=1)
        self._create_item(title="Beta advisory", days_ago=2)
        self._create_item(title="Gamma old advisory", days_ago=20)

        response = self.client.get(
            reverse("advisories"),
            {"time": "7d", "q": "alpha"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["window_total"], 2)
        self.assertEqual(response.context["filtered_total"], 1)
        self.assertEqual(response.context["hidden_by_filters"], 1)
        self.assertContains(response, "hidden by current source/search filters")

    def test_q_search_matches_source_name(self):
        self._create_item(title="Alpha advisory", days_ago=1)

        other_source = Source.objects.create(name="Nordic Response Team", slug="nordic-response")
        other_feed = Feed.objects.create(
            source=other_source,
            name="Nordic Feed",
            url="https://example.com/nordic-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )
        Item.objects.create(
            source=other_source,
            feed=other_feed,
            title="Plain bulletin",
            url="https://example.com/plain-bulletin",
            stable_id="",
            published_at=timezone.now() - timedelta(days=1),
            summary="General update",
        )

        response = self.client.get(
            reverse("advisories"),
            {"time": "7d", "q": "Nordic Response Team"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Plain bulletin")
        self.assertNotContains(response, "Alpha advisory")
        self.assertEqual(response.context["filtered_total"], 1)

    def test_source_facets_follow_current_section_and_time_window(self):
        self._create_item(title="Fresh advisory", days_ago=1)
        self._create_item(title="Old advisory", days_ago=20)

        research_source = Source.objects.create(name="Research Source", slug="research-source")
        research_feed = Feed.objects.create(
            source=research_source,
            name="Research Feed",
            url="https://example.com/research-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.RESEARCH,
        )
        Item.objects.create(
            source=research_source,
            feed=research_feed,
            title="Research bulletin",
            url="https://example.com/research-bulletin",
            stable_id="",
            published_at=timezone.now() - timedelta(days=1),
            summary="Research bulletin",
        )

        response = self.client.get(reverse("advisories"), {"time": "7d"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [(row["slug"], row["count"]) for row in response.context["sources"]],
            [("filter-source", 1)],
        )
        self.assertContains(response, "Filter Source · 1")
        self.assertNotContains(response, "Research Source")

    def test_selected_source_is_preserved_when_it_has_zero_results(self):
        self._create_item(title="Current advisory", days_ago=1)

        old_source = Source.objects.create(name="Old Source", slug="old-source")
        old_feed = Feed.objects.create(
            source=old_source,
            name="Old Feed",
            url="https://example.com/old-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )
        Item.objects.create(
            source=old_source,
            feed=old_feed,
            title="Old advisory",
            url="https://example.com/old-advisory",
            stable_id="",
            published_at=timezone.now() - timedelta(days=30),
            summary="Old advisory",
        )

        response = self.client.get(
            reverse("advisories"),
            {"time": "7d", "source": "old-source"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["filtered_total"], 0)
        self.assertEqual(response.context["selected_source"], "old-source")
        self.assertEqual(response.context["selected_source_name"], "Old Source")
        self.assertIn(
            ("old-source", 0),
            [(row["slug"], row["count"]) for row in response.context["sources"]],
        )
        self.assertContains(response, "Old Source · 0")
