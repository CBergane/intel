from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, FetchRun, Source


class OpsDashboardTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff_user = user_model.objects.create_user(
            username="opsstaff",
            password="test-pass-123",
            is_staff=True,
        )
        self.non_staff_user = user_model.objects.create_user(
            username="viewer",
            password="test-pass-123",
            is_staff=False,
        )
        self.url = reverse("ops-dashboard")

    def test_non_staff_cannot_access_ops_dashboard(self):
        self.client.force_login(self.non_staff_user)
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (302, 403))

    def test_staff_can_access_ops_dashboard(self):
        self.client.force_login(self.staff_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ops Dashboard")

    def test_actions_require_post_and_csrf(self):
        self.client.force_login(self.staff_user)

        with patch("intel.views.call_command") as mocked_call:
            response = self.client.get(f"{self.url}?action=seed")
            self.assertEqual(response.status_code, 200)
            mocked_call.assert_not_called()

            response = self.client.post(self.url, {"action": "seed"}, follow=True)
            self.assertEqual(response.status_code, 200)
            mocked_call.assert_called_once()

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.staff_user)
        forbidden = csrf_client.post(self.url, {"action": "seed"}, follow=True)
        self.assertEqual(forbidden.status_code, 403)

    def test_summary_counts_render_correctly(self):
        source = Source.objects.create(name="Ops Source", slug="ops-source")
        now = timezone.now()

        feed_ok = Feed.objects.create(
            source=source,
            name="Feed OK",
            url="https://example.com/feed-ok.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            enabled=True,
            last_success_at=now,
            last_error="",
        )
        feed_error = Feed.objects.create(
            source=source,
            name="Feed Error",
            url="https://example.com/feed-error.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.RESEARCH,
            enabled=True,
            last_success_at=now,
            last_error="Timeout",
        )
        Feed.objects.create(
            source=source,
            name="Feed Never",
            url="https://example.com/feed-never.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.SWEDEN,
            enabled=True,
            last_success_at=None,
            last_error="",
        )
        Feed.objects.create(
            source=source,
            name="Feed Disabled",
            url="https://example.com/feed-disabled.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.SWEDEN,
            enabled=False,
            last_success_at=None,
            last_error="broken",
        )

        FetchRun.objects.create(
            feed=feed_ok,
            started_at=now,
            finished_at=now,
            ok=True,
            http_status=200,
            items_new=4,
            items_updated=1,
        )
        FetchRun.objects.create(
            feed=feed_error,
            started_at=now,
            finished_at=now,
            ok=False,
            error="network error",
            http_status=500,
            items_new=0,
            items_updated=0,
        )

        self.client.force_login(self.staff_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["enabled_feeds_count"], 3)
        self.assertEqual(response.context["ok_count"], 1)
        self.assertEqual(response.context["error_count"], 1)
        self.assertEqual(response.context["never_run_count"], 1)
