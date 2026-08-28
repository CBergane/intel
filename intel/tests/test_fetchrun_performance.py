from datetime import timedelta
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, FetchRun, Source


class FetchRunRequestPathPerformanceTests(TestCase):
    history_per_feed = 150

    def setUp(self):
        self.now = timezone.now()
        self.source = Source.objects.create(
            name="Performance Source",
            slug="performance-source",
        )
        self.ok_feed = self._create_feed("Latest OK", "latest-ok", enabled=True)
        self.error_feed = self._create_feed(
            "Latest Error",
            "latest-error",
            enabled=True,
            last_error="Latest visible failure",
        )
        self.never_feed = self._create_feed("Never Run", "never-run", enabled=True)
        self.disabled_feed = self._create_feed(
            "Disabled Feed",
            "disabled-feed",
            enabled=False,
        )

        history = []
        for index in range(self.history_per_feed):
            started_at = self.now - timedelta(days=2, minutes=index)
            for feed in (self.ok_feed, self.error_feed, self.disabled_feed):
                history.append(
                    FetchRun(
                        feed=feed,
                        started_at=started_at,
                        finished_at=started_at + timedelta(seconds=5),
                        ok=index % 2 == 0,
                        items_fetched=index + 1,
                        items_stored=index,
                    )
                )
        FetchRun.objects.bulk_create(history)

        tie_time = self.now - timedelta(minutes=1)
        self.ok_older_tie = FetchRun.objects.create(
            feed=self.ok_feed,
            started_at=tie_time,
            finished_at=tie_time + timedelta(seconds=3),
            ok=False,
            error="Superseded failure",
            items_fetched=10,
            items_stored=5,
        )
        self.ok_latest = FetchRun.objects.create(
            feed=self.ok_feed,
            started_at=tie_time,
            finished_at=tie_time + timedelta(seconds=4),
            ok=True,
            items_fetched=123,
            items_stored=120,
            items_skipped_old=2,
            items_skipped_invalid=1,
            items_limited=3,
        )
        self.error_older_tie = FetchRun.objects.create(
            feed=self.error_feed,
            started_at=tie_time,
            finished_at=tie_time + timedelta(seconds=3),
            ok=True,
            items_fetched=20,
            items_stored=20,
        )
        self.error_latest = FetchRun.objects.create(
            feed=self.error_feed,
            started_at=tie_time,
            finished_at=tie_time + timedelta(seconds=5),
            ok=False,
            error="Latest run failed",
            items_fetched=50,
            items_stored=4,
        )
        self.disabled_latest = FetchRun.objects.create(
            feed=self.disabled_feed,
            started_at=tie_time,
            finished_at=tie_time + timedelta(seconds=2),
            ok=True,
            items_fetched=40,
            items_stored=40,
        )

    def _create_feed(self, name, slug, *, enabled, last_error=""):
        return Feed.objects.create(
            source=self.source,
            name=name,
            url=f"https://example.com/{slug}.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            enabled=enabled,
            last_success_at=self.now if not last_error else None,
            last_error=last_error,
        )

    def _record_fetchrun_materialization(self):
        loaded_ids = []
        original_from_db = FetchRun.from_db

        def record_from_db(db, field_names, values):
            instance = original_from_db(db, field_names, values)
            loaded_ids.append(instance.id)
            return instance

        return loaded_ids, patch.object(
            FetchRun,
            "from_db",
            side_effect=record_from_db,
        )

    def test_dashboard_status_uses_only_latest_run_without_model_materialization(self):
        loaded_ids, materialization_guard = self._record_fetchrun_materialization()

        with materialization_guard, CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("now"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["feed_status_counts"], {"ok": 1, "error": 1, "never": 1})
        self.assertEqual(response.context["enabled_feed_count"], 3)
        self.assertEqual(
            response.context["last_ingest_finished_at"],
            self.error_latest.finished_at,
        )
        self.assertEqual(len(queries), 3)
        self.assertEqual(loaded_ids, [])

    def test_feed_health_loads_only_one_latest_run_per_feed(self):
        loaded_ids, materialization_guard = self._record_fetchrun_materialization()

        with materialization_guard, CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("feed-health"))

        latest_by_feed = response.context["latest_by_feed"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(queries), 2)
        self.assertEqual(
            set(loaded_ids),
            {self.ok_latest.id, self.error_latest.id, self.disabled_latest.id},
        )
        self.assertEqual(len(loaded_ids), 3)
        self.assertEqual(latest_by_feed[self.ok_feed.id].id, self.ok_latest.id)
        self.assertTrue(latest_by_feed[self.ok_feed.id].ok)
        self.assertEqual(latest_by_feed[self.error_feed.id].id, self.error_latest.id)
        self.assertFalse(latest_by_feed[self.error_feed.id].ok)
        self.assertNotIn(self.never_feed.id, latest_by_feed)
        self.assertContains(response, "123")
        self.assertContains(response, "Latest visible failure")
        self.assertContains(response, self.ok_feed.url)

    def test_sources_page_uses_the_same_bounded_latest_run_lookup(self):
        loaded_ids, materialization_guard = self._record_fetchrun_materialization()

        with materialization_guard, CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("sources"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(queries), 5)
        self.assertEqual(set(loaded_ids), {self.ok_latest.id, self.error_latest.id})
        self.assertEqual(len(loaded_ids), 2)
