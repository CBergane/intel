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
