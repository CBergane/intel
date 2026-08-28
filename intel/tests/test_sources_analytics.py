from datetime import timedelta
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from intel import views
from intel.classification import classify_item
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

    def test_sources_page_groups_sources_by_section_with_recent_items(self):
        response = self.client.get(reverse("sources"))
        self.assertEqual(response.status_code, 200)

        section_groups = {group["key"]: group for group in response.context["section_groups"]}
        advisories = section_groups["advisories"]
        research = section_groups["research"]
        alpha = next(row for row in advisories["sources"] if row["source"].slug == "alpha-source")
        beta = next(row for row in research["sources"] if row["source"].slug == "beta-source")

        self.assertEqual(response.context["page_title"], "Sources")
        self.assertEqual(response.context["section_count"], 2)
        self.assertEqual(response.context["active_sources_7d_count"], 1)
        self.assertEqual(response.context["items_7d_count"], 2)

        self.assertEqual(advisories["source_count"], 1)
        self.assertEqual(advisories["new_24h"], 1)
        self.assertEqual(advisories["new_7d"], 2)
        self.assertEqual(alpha["new_24h"], 1)
        self.assertEqual(alpha["new_7d"], 2)
        self.assertEqual(alpha["item_count"], 3)
        self.assertEqual(alpha["status"], "OK")
        self.assertEqual(alpha["recent_items"][0].title, "Alpha fresh")
        self.assertEqual(alpha["open_url"], reverse("advisories") + "?source=alpha-source")

        self.assertEqual(research["source_count"], 2)
        self.assertEqual(beta["new_24h"], 0)
        self.assertEqual(beta["new_7d"], 0)
        self.assertEqual(beta["item_count"], 0)
        self.assertEqual(beta["status"], "Never")
        self.assertEqual(beta["recent_items"], [])
        self.assertEqual(beta["open_url"], reverse("research") + "?source=beta-source")

        self.assertContains(response, "Coverage, provenance, and recent intelligence by source.")
        self.assertContains(response, "Vulnerabilities")
        self.assertContains(response, "Browse source")
        self.assertContains(response, "Open Research")
        self.assertContains(response, "No recent items in the last 30 days for this source and section.")


class SourcesPreviewSelectionTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.source_alpha = Source.objects.create(
            name="Alpha Preview Source",
            slug="alpha-preview-source",
        )
        self.source_beta = Source.objects.create(
            name="Beta Preview Source",
            slug="beta-preview-source",
        )
        self.alpha_advisories = self._create_feed(
            self.source_alpha,
            "Alpha Advisories",
            "alpha-advisories",
            Feed.Section.ADVISORIES,
        )
        self.alpha_research = self._create_feed(
            self.source_alpha,
            "Alpha Research",
            "alpha-research",
            Feed.Section.RESEARCH,
        )
        self.beta_advisories = self._create_feed(
            self.source_beta,
            "Beta Advisories",
            "beta-advisories",
            Feed.Section.ADVISORIES,
        )
        self.beta_research = self._create_feed(
            self.source_beta,
            "Beta Research",
            "beta-research",
            Feed.Section.RESEARCH,
        )

    @staticmethod
    def _create_feed(source, name, slug, section):
        return Feed.objects.create(
            source=source,
            name=name,
            url=f"https://example.com/{slug}.xml",
            feed_type=Feed.FeedType.RSS,
            section=section,
            enabled=True,
        )

    def _create_item(self, feed, title, published_at):
        return Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            summary="Security intelligence preview",
            url=f"https://example.com/items/{title.lower().replace(' ', '-')}",
            stable_id=f"preview-{feed.id}-{title}",
            published_at=published_at,
        )

    @staticmethod
    def _rows_by_key(response):
        return {
            (row["source"].id, section["key"]): row
            for section in response.context["section_groups"]
            for row in section["sources"]
        }

    @staticmethod
    def _record_item_materialization():
        loaded_ids = []
        original_from_db = Item.from_db

        def record_from_db(db, field_names, values):
            instance = original_from_db(db, field_names, values)
            loaded_ids.append(instance.id)
            return instance

        return loaded_ids, patch.object(Item, "from_db", side_effect=record_from_db)

    def test_previews_are_top_three_per_source_section_with_deterministic_ties(self):
        newest = self._create_item(
            self.alpha_advisories,
            "Alpha newest",
            self.now - timedelta(minutes=10),
        )
        tie_time = self.now - timedelta(hours=1)
        tie_older_id = self._create_item(
            self.alpha_advisories,
            "Alpha tie lower id",
            tie_time,
        )
        tie_newer_id = self._create_item(
            self.alpha_advisories,
            "Alpha tie higher id",
            tie_time,
        )
        excluded_fourth = self._create_item(
            self.alpha_advisories,
            "Alpha fourth",
            self.now - timedelta(hours=2),
        )
        alpha_research_items = [
            self._create_item(
                self.alpha_research,
                "Alpha research newest",
                self.now - timedelta(hours=3),
            ),
            self._create_item(
                self.alpha_research,
                "Alpha research second",
                self.now - timedelta(hours=4),
            ),
        ]
        beta_items = [
            self._create_item(
                self.beta_advisories,
                f"Beta item {index}",
                self.now - timedelta(hours=5 + index),
            )
            for index in range(4)
        ]
        old_item = self._create_item(
            self.beta_research,
            "Beta outside window",
            self.now - timedelta(days=31),
        )

        expected_ids = {
            newest.id,
            tie_newer_id.id,
            tie_older_id.id,
        }
        expected_ids.update(item.id for item in alpha_research_items)
        expected_ids.update(item.id for item in beta_items[:3])
        loaded_ids, materialization_guard = self._record_item_materialization()
        with (
            materialization_guard,
            patch("intel.views.classify_item", wraps=classify_item) as classifier,
        ):
            response = self.client.get(reverse("sources"))

        self.assertEqual(response.status_code, 200)
        rows = self._rows_by_key(response)
        alpha_advisory_previews = rows[
            (self.source_alpha.id, Feed.Section.ADVISORIES)
        ]["recent_items"]
        self.assertEqual(
            [item.id for item in alpha_advisory_previews],
            [newest.id, tie_newer_id.id, tie_older_id.id],
        )
        self.assertNotIn(excluded_fourth.id, loaded_ids)
        self.assertEqual(
            [
                item.id
                for item in rows[
                    (self.source_alpha.id, Feed.Section.RESEARCH)
                ]["recent_items"]
            ],
            [item.id for item in alpha_research_items],
        )
        self.assertEqual(
            [
                item.id
                for item in rows[
                    (self.source_beta.id, Feed.Section.ADVISORIES)
                ]["recent_items"]
            ],
            [item.id for item in beta_items[:3]],
        )
        self.assertEqual(
            rows[(self.source_beta.id, Feed.Section.RESEARCH)]["recent_items"],
            [],
        )
        self.assertNotIn(old_item.id, loaded_ids)
        self.assertEqual(set(loaded_ids), expected_ids)
        self.assertEqual(len(loaded_ids), 8)
        self.assertEqual(classifier.call_count, 8)

    def test_preview_work_scales_with_groups_not_recent_item_count(self):
        feeds = (
            self.alpha_advisories,
            self.alpha_research,
            self.beta_advisories,
            self.beta_research,
        )
        items_per_group = 75
        items = []
        for feed in feeds:
            for index in range(items_per_group):
                items.append(
                    Item(
                        source=feed.source,
                        feed=feed,
                        title=f"Stress item {feed.id}-{index}",
                        normalized_title=f"Stress item {feed.id}-{index}",
                        title_hash=f"stress-hash-{feed.id}-{index}",
                        url=f"https://example.com/stress/{feed.id}/{index}",
                        canonical_url=f"https://example.com/stress/{feed.id}/{index}",
                        stable_id=f"stress-{feed.id}-{index}",
                        published_at=self.now - timedelta(minutes=index),
                        summary="Bounded preview classification test",
                    )
                )
        Item.objects.bulk_create(items)
        for feed in feeds:
            FetchRun.objects.create(
                feed=feed,
                started_at=self.now,
                finished_at=self.now,
                ok=True,
            )

        expected_preview_count = len(feeds) * 3
        loaded_ids, materialization_guard = self._record_item_materialization()
        original_destination = views._source_destination
        with (
            materialization_guard,
            patch("intel.views.classify_item", wraps=classify_item) as classifier,
            patch(
                "intel.views._source_destination",
                wraps=original_destination,
            ) as destination,
            CaptureQueriesContext(connection) as queries,
        ):
            response = self.client.get(reverse("sources"))

        preview_count = sum(
            len(row["recent_items"])
            for section in response.context["section_groups"]
            for row in section["sources"]
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Item.objects.count(), len(feeds) * items_per_group)
        self.assertEqual(preview_count, expected_preview_count)
        self.assertEqual(len(loaded_ids), expected_preview_count)
        self.assertEqual(classifier.call_count, expected_preview_count)
        self.assertEqual(destination.call_count, expected_preview_count + len(feeds))
        self.assertEqual(len(queries), 5)
