from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, Source


class AdminSecurityTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="root",
            password="super-pass-123",
        )
        self.non_superuser = user_model.objects.create_user(
            username="staffer",
            password="staff-pass-123",
            is_staff=True,
        )

        self.ops_url = reverse("intel_admin:ops")
        self.panel_url = reverse("intel_admin:panel")
        self.login_url = reverse("intel_admin:login")

    def test_non_authenticated_user_cannot_access_panel_or_ops(self):
        ops_response = self.client.get(self.ops_url)
        panel_response = self.client.get(self.panel_url)

        self.assertEqual(ops_response.status_code, 302)
        self.assertEqual(panel_response.status_code, 302)
        self.assertIn(self.login_url, ops_response.url)
        self.assertIn(self.login_url, panel_response.url)

    def test_non_superuser_cannot_access_panel_or_ops(self):
        self.client.force_login(self.non_superuser)

        ops_response = self.client.get(self.ops_url)
        panel_response = self.client.get(self.panel_url)

        self.assertIn(ops_response.status_code, (302, 403))
        self.assertIn(panel_response.status_code, (302, 403))

    def test_login_rejects_non_superuser_even_with_valid_password(self):
        response = self.client.post(
            self.login_url,
            {"username": "staffer", "password": "staff-pass-123"},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid credentials.")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_blocks_open_redirect_next(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "root",
                "password": "super-pass-123",
                "next": "https://evil.example/phish",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, self.ops_url)


class AdminPanelFeedCrudTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="admin",
            password="admin-pass-123",
        )
        self.source = Source.objects.create(name="Panel Source", slug="panel-source")
        self.create_url = reverse("intel_admin:feed_create")
        self.panel_url = reverse("intel_admin:panel")

    def test_superuser_can_create_and_update_feed_with_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)

        create_get = client.get(self.create_url)
        self.assertEqual(create_get.status_code, 200)
        token = client.cookies["csrftoken"].value

        create_response = client.post(
            self.create_url,
            {
                "csrfmiddlewaretoken": token,
                "source": str(self.source.id),
                "name": "Managed Feed",
                "url": "https://example.com/managed.xml",
                "feed_type": Feed.FeedType.RSS,
                "section": Feed.Section.ADVISORIES,
                "enabled": "on",
                "priority": "100",
                "timeout_seconds": "10",
                "max_bytes": "1500000",
                "max_age_days": "120",
                "max_items_per_run": "150",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.panel_url)

        feed = Feed.objects.get(url="https://example.com/managed.xml")
        edit_url = reverse("intel_admin:feed_edit", kwargs={"feed_id": feed.id})
        delete_url = reverse("intel_admin:feed_delete", kwargs={"feed_id": feed.id})

        edit_get = client.get(edit_url)
        self.assertEqual(edit_get.status_code, 200)
        token = client.cookies["csrftoken"].value
        update_response = client.post(
            edit_url,
            {
                "csrfmiddlewaretoken": token,
                "source": str(self.source.id),
                "name": "Managed Feed Updated",
                "url": "https://example.com/managed-updated.xml",
                "feed_type": Feed.FeedType.RSS,
                "adapter_key": "",
                "section": Feed.Section.RESEARCH,
                "priority": "90",
                "timeout_seconds": "15",
                "max_bytes": "1500000",
                "max_age_days": "90",
                "max_items_per_run": "80",
            },
        )
        self.assertEqual(update_response.status_code, 302)
        self.assertEqual(update_response.url, self.panel_url)

        feed.refresh_from_db()
        self.assertEqual(feed.name, "Managed Feed Updated")
        self.assertEqual(feed.url, "https://example.com/managed-updated.xml")
        self.assertFalse(feed.enabled)
        self.assertEqual(feed.priority, 90)
        self.assertEqual(feed.section, Feed.Section.RESEARCH)
        self.assertEqual(feed.max_age_days, 90)
        self.assertEqual(feed.max_items_per_run, 80)

        token = client.cookies["csrftoken"].value
        delete_response = client.post(
            delete_url,
            {
                "csrfmiddlewaretoken": token,
                "next": self.panel_url,
            },
        )
        self.assertEqual(delete_response.status_code, 302)
        self.assertEqual(delete_response.url, self.panel_url)
        self.assertFalse(Feed.objects.filter(id=feed.id).exists())


class AdminPanelFeedListTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="panel-admin",
            password="panel-pass-123",
        )
        self.client.force_login(self.superuser)
        self.panel_url = reverse("intel_admin:panel")

        now = timezone.now()
        alpha = Source.objects.create(name="Alpha Source", slug="alpha-source")
        beta = Source.objects.create(name="Beta Source", slug="beta-source")
        gamma = Source.objects.create(name="Gamma Source", slug="gamma-source")

        self.ok_feed = Feed.objects.create(
            source=alpha,
            name="Alpha Advisory Feed",
            url="https://example.com/alpha-advisories.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            enabled=True,
            last_success_at=now,
            last_error="",
        )
        self.error_feed = Feed.objects.create(
            source=beta,
            name="Beta EPSS Feed",
            url="https://example.com/beta-epss.json",
            feed_type=Feed.FeedType.JSON,
            adapter_key="epss",
            section=Feed.Section.ACTIVE,
            enabled=False,
            last_success_at=now,
            last_error="Upstream response failed validation.",
        )
        self.never_feed = Feed.objects.create(
            source=gamma,
            name="Gamma Research Feed",
            url="https://example.com/gamma-research.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.RESEARCH,
            enabled=True,
        )

    def test_admin_panel_renders_for_superuser(self):
        response = self.client.get(self.panel_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Total Feeds")
        self.assertContains(response, self.ok_feed.name)
        self.assertContains(response, self.error_feed.name)
        self.assertContains(response, self.never_feed.name)

    def test_admin_panel_search_filters_feeds(self):
        response = self.client.get(self.panel_url, {"q": "epss"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.error_feed.name)
        self.assertNotContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.never_feed.name)

        response = self.client.get(self.panel_url, {"q": "Alpha Source"})

        self.assertContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.error_feed.name)
        self.assertNotContains(response, self.never_feed.name)

        response = self.client.get(self.panel_url, {"q": "Gamma Research Feed"})

        self.assertContains(response, self.never_feed.name)
        self.assertNotContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.error_feed.name)

        response = self.client.get(self.panel_url, {"q": "beta-epss.json"})

        self.assertContains(response, self.error_feed.name)
        self.assertNotContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.never_feed.name)

    def test_admin_panel_combined_filters_limit_feed_rows(self):
        response = self.client.get(
            self.panel_url,
            {
                "section": Feed.Section.ACTIVE,
                "enabled": "disabled",
                "status": "error",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.error_feed.name)
        self.assertNotContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.never_feed.name)

    def test_admin_panel_status_never_filter(self):
        response = self.client.get(self.panel_url, {"status": "never"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.never_feed.name)
        self.assertNotContains(response, self.ok_feed.name)
        self.assertNotContains(response, self.error_feed.name)
