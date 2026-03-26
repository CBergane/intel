import hashlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.dark_models import DarkHit, DarkSource

User = get_user_model()
DARK_GROUPS_URL = reverse("dark-dashboard")
DARK_RECENT_URL = reverse("dark-recent-hits")


def _make_source(*, slug: str, name: str):
    return DarkSource.objects.create(
        name=name,
        slug=slug,
        url=f"https://{slug}.example.test/feed",
    )


def _make_hit(
    source,
    *,
    title: str,
    group_name: str = "",
    victim_name: str = "",
    country: str = "",
    record_type: str = "incident",
    detected_offset_days: int = 0,
):
    unique_hash = hashlib.md5(f"{source.slug}{title}{group_name}".encode()).hexdigest()
    hit = DarkHit.objects.create(
        dark_source=source,
        title=title,
        url=f"https://{source.slug}.example.test/item",
        content_hash=unique_hash,
        group_name=group_name,
        victim_name=victim_name,
        country=country,
        record_type=record_type,
    )
    if detected_offset_days:
        activity_at = timezone.now() - timedelta(days=detected_offset_days)
        DarkHit.objects.filter(pk=hit.pk).update(
            detected_at=activity_at,
            last_seen_at=activity_at,
        )
        hit.refresh_from_db()
    return hit


class DarkViewAccessTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="dark-root",
            password="dark-root-pass-123",
        )
        self.regular_user = User.objects.create_user(
            username="dark-staff",
            password="dark-staff-pass-123",
        )
        source = _make_source(slug="akira-source", name="Akira Source")
        _make_hit(source, title="Akira / Alpha", group_name="Akira", victim_name="Alpha")

    def test_anonymous_user_redirected_from_dark_pages(self):
        self.assertEqual(self.client.get(DARK_GROUPS_URL).status_code, 302)
        self.assertEqual(self.client.get(DARK_RECENT_URL).status_code, 302)

    def test_superuser_can_open_active_groups_and_recent_hits(self):
        self.client.force_login(self.superuser)

        groups_response = self.client.get(DARK_GROUPS_URL)
        recent_response = self.client.get(DARK_RECENT_URL)

        self.assertEqual(groups_response.status_code, 200)
        self.assertEqual(recent_response.status_code, 200)
        self.assertContains(groups_response, "Active Groups")
        self.assertContains(recent_response, "Recent Hits")

    def test_non_superuser_does_not_get_dark_pages(self):
        self.client.force_login(self.regular_user)
        self.assertNotEqual(self.client.get(DARK_GROUPS_URL).status_code, 200)
        self.assertNotEqual(self.client.get(DARK_RECENT_URL).status_code, 200)


class ActiveGroupsViewTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="dark-groups-root",
            password="dark-groups-pass-123",
        )
        self.source_a = _make_source(slug="akira-a", name="Akira Source A")
        self.source_b = _make_source(slug="akira-b", name="Akira Source B")
        self.source_c = _make_source(slug="play-a", name="Play Source")

        _make_hit(
            self.source_a,
            title="Alpha Manufacturing",
            group_name="Akira",
            victim_name="Alpha Manufacturing",
            country="Sweden",
            detected_offset_days=3,
        )
        _make_hit(
            self.source_b,
            title="Beta Retail",
            group_name="Akira",
            victim_name="Beta Retail",
            country="Norway",
        )
        _make_hit(
            self.source_c,
            title="Gamma Health",
            group_name="Play",
            victim_name="Gamma Health",
            country="Denmark",
            detected_offset_days=1,
        )

    def test_active_groups_view_aggregates_by_group_name(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Akira")
        self.assertContains(response, "Play")
        self.assertEqual(response.context["active_group_count"], 2)
        self.assertEqual(response.context["incident_count"], 3)

        rows = list(response.context["group_rows"].object_list)
        akira_row = next(row for row in rows if row["group_name"] == "Akira")
        self.assertEqual(akira_row["incident_count"], 2)
        self.assertEqual(akira_row["latest_victim_name"], "Beta Retail")
        self.assertEqual(akira_row["latest_country"], "Norway")
        self.assertEqual(akira_row["source_count"], 2)

    def test_active_groups_view_renders_secondary_recent_hits_link(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("dark-recent-hits"))
        self.assertContains(response, "Recent Signals")

    def test_recent_hits_view_keeps_raw_hits_available(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_RECENT_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Manufacturing")
        self.assertContains(response, "Beta Retail")
        self.assertContains(response, reverse("dark-dashboard"))
