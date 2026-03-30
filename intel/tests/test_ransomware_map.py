from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, Item, Source


RANSOMWARE_MAP_URL = reverse("ransomware-map")


class RansomwareMapViewTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Ransomware.live", slug="ransomware-live")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Victims",
            url="https://api.ransomware.live/victims.json",
            feed_type=Feed.FeedType.JSON,
            adapter_key="ransomware_live_victims",
            section=Feed.Section.ACTIVE,
        )
        self.other_source = Source.objects.create(name="Other Source", slug="other-source")
        self.other_feed = Feed.objects.create(
            source=self.other_source,
            name="Other Feed",
            url="https://example.com/other.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )
        self._idx = 0

    def _create_victim(
        self,
        *,
        victim: str,
        group: str,
        country: str = "",
        hours_ago: int = 0,
        days_ago: int = 0,
        summary: str = "",
    ):
        self._idx += 1
        published_at = timezone.now() - timedelta(hours=hours_ago, days=days_ago)
        return Item.objects.create(
            source=self.source,
            feed=self.feed,
            title=f"{group}: {victim}",
            url=f"https://www.ransomware.live/id/{self._idx}",
            stable_id="",
            published_at=published_at,
            summary=summary,
            raw_payload={
                "victim": victim,
                "group": group.lower(),
                "country": country,
                "discovered": published_at.isoformat(),
                "description": summary,
            },
        )

    def test_map_page_renders_with_svg_surface(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden")
        Item.objects.create(
            source=self.other_source,
            feed=self.other_feed,
            title="General bulletin",
            url="https://example.com/bulletin",
            stable_id="",
            published_at=timezone.now(),
        )

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["current_page"], "ransomware-map")
        self.assertContains(response, "Ransomware Incident Map")
        self.assertContains(response, 'id="ransomware-map-surface"')
        self.assertContains(response, "Nordic Mills")
        self.assertNotContains(response, "General bulletin")

    def test_map_page_renders_main_navigation_entry_with_active_state(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden")

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertGreaterEqual(response.content.decode().count('href="/ransomware/map/"'), 2)
        self.assertContains(response, "bg-rose-500/20 text-rose-100 ring-1 ring-rose-400/30")
        self.assertContains(response, "bg-rose-500/10 text-rose-100")

    def test_window_filtering_changes_victim_scope(self):
        self._create_victim(victim="Fresh Victim", group="Akira", country="Sweden", hours_ago=6)
        self._create_victim(victim="Older Victim", group="Qilin", country="Finland", days_ago=10)

        response_24h = self.client.get(RANSOMWARE_MAP_URL, {"window": "24h"})
        response_30d = self.client.get(RANSOMWARE_MAP_URL, {"window": "30d"})

        self.assertEqual(response_24h.context["summary"]["victim_count"], 1)
        self.assertEqual(response_30d.context["summary"]["victim_count"], 2)
        self.assertContains(response_30d, "Older Victim")
        self.assertNotContains(response_24h, "Older Victim")

    def test_country_aggregation_normalizes_aliases(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=3)
        self._create_victim(victim="Scandi Foods", group="Qilin", country="Sverige", hours_ago=4)

        response = self.client.get(RANSOMWARE_MAP_URL)

        top_country = response.context["top_countries"][0]
        self.assertEqual(top_country["country"], "Sweden")
        self.assertEqual(top_country["record_count"], 2)

    def test_group_aggregation_counts_countryless_victims(self):
        self._create_victim(victim="Mapped Victim", group="Akira", country="Sweden", hours_ago=2)
        self._create_victim(victim="Countryless Victim", group="Akira", hours_ago=1)
        self._create_victim(victim="Other Victim", group="Lockbit", country="United States", hours_ago=4)

        response = self.client.get(RANSOMWARE_MAP_URL)

        top_group = response.context["top_groups"][0]
        self.assertEqual(top_group["group_name"], "Akira")
        self.assertEqual(top_group["record_count"], 2)
        self.assertEqual(response.context["summary"]["countryless_count"], 1)

    def test_latest_victims_render_country_pending_when_geography_missing(self):
        self._create_victim(
            victim="No Geo Co",
            group="DragonForce",
            summary="Victim listing still useful without country.",
            hours_ago=1,
        )

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertEqual(response.context["latest_victims"][0]["victim_name"], "No Geo Co")
        self.assertContains(response, "Country pending")

    def test_selected_country_drilldown_filters_victim_lane_and_groups(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=1)
        self._create_victim(victim="Stockholm Labs", group="Qilin", country="Sverige", hours_ago=2)
        self._create_victim(victim="Texas Hosting", group="Lockbit", country="United States", hours_ago=3)

        response = self.client.get(RANSOMWARE_MAP_URL, {"country": "Sverige"})

        self.assertEqual(response.context["selected_country"], "Sweden")
        self.assertTrue(all(record["country"] == "Sweden" for record in response.context["latest_victims"]))
        self.assertEqual(
            {row["group_name"] for row in response.context["top_groups"]},
            {"Akira", "Qilin"},
        )

    def test_map_explains_when_victims_have_no_plot_ready_country(self):
        self._create_victim(victim="Countryless Victim", group="Akira", hours_ago=2)

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertContains(response, 'id="ransomware-map-surface"')
        self.assertContains(response, "Victim activity found, geography still sparse")
