import hashlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.dark_models import DarkHit, DarkSource

User = get_user_model()
DARK_URL = reverse("dark-dashboard")


def _make_source(slug="test-source", name="Test Source"):
    return DarkSource.objects.create(
        name=name,
        slug=slug,
        url="http://example.onion/",
    )


def _make_hit(source, title="Hit title", detected_offset_days=0):
    unique_hash = hashlib.md5(f"{source.slug}{title}".encode()).hexdigest()
    hit = DarkHit.objects.create(
        dark_source=source,
        title=title,
        url="http://example.onion/page",
        content_hash=unique_hash,
    )
    if detected_offset_days:
        DarkHit.objects.filter(pk=hit.pk).update(
            detected_at=timezone.now() - timedelta(days=detected_offset_days)
        )
        hit.refresh_from_db()
    return hit


class DarkDashboardAccessTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="root", password="super-pass-123"
        )
        self.regular_user = User.objects.create_user(
            username="staffer", password="staff-pass-123"
        )
        self.source = _make_source()
        _make_hit(self.source)

    def test_anonymous_redirects(self):
        response = self.client.get(DARK_URL)
        self.assertEqual(response.status_code, 302)

    def test_non_superuser_forbidden(self):
        self.client.force_login(self.regular_user)
        response = self.client.get(DARK_URL)
        self.assertEqual(response.status_code, 302)
        # redirect goes to login, not 200 or 403 — assert it's not the page
        self.assertNotEqual(response.status_code, 200)

    def test_superuser_gets_200(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_URL)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Hit title")

    def test_source_filter(self):
        other_source = _make_source(slug="other-source", name="Other Source")
        _make_hit(other_source, title="Other hit")

        self.client.force_login(self.superuser)
        response = self.client.get(DARK_URL + "?source=test-source")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Hit title")
        self.assertNotContains(response, "Other hit")

    def test_days_filter_excludes_old_hits(self):
        _make_hit(self.source, title="Old hit", detected_offset_days=60)

        self.client.force_login(self.superuser)
        response = self.client.get(DARK_URL + "?days=7")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Hit title")
        self.assertNotContains(response, "Old hit")

    def test_invalid_days_param_falls_back_to_30(self):
        # Should not crash with an unexpected days value
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_URL + "?days=999")
        self.assertEqual(response.status_code, 200)
