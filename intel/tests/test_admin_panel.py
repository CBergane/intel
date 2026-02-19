from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

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
                "max_age_days": "120",
                "max_items_per_run": "150",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.panel_url)

        feed = Feed.objects.get(url="https://example.com/managed.xml")
        edit_url = reverse("intel_admin:feed_edit", kwargs={"feed_id": feed.id})

        edit_get = client.get(edit_url)
        self.assertEqual(edit_get.status_code, 200)
        token = client.cookies["csrftoken"].value
        update_response = client.post(
            edit_url,
            {
                "csrfmiddlewaretoken": token,
                "url": "https://example.com/managed-updated.xml",
                "section": Feed.Section.RESEARCH,
                "max_age_days": "90",
                "max_items_per_run": "80",
            },
        )
        self.assertEqual(update_response.status_code, 302)
        self.assertEqual(update_response.url, self.panel_url)

        feed.refresh_from_db()
        self.assertEqual(feed.url, "https://example.com/managed-updated.xml")
        self.assertFalse(feed.enabled)
        self.assertEqual(feed.section, Feed.Section.RESEARCH)
        self.assertEqual(feed.max_age_days, 90)
        self.assertEqual(feed.max_items_per_run, 80)
