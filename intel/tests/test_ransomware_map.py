import json
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, Item, Source
from intel.ransomware_countries import (
    RANSOMWARE_MAP_COUNTRIES,
    RANSOMWARE_MAP_DATASET,
    normalize_ransomware_country,
)


RANSOMWARE_MAP_URL = reverse("ransomware-map")
RANSOMWARE_MAP_LIVE_URL = reverse("ransomware-map-live")


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

    def test_map_page_uses_local_maplibre_and_country_geometry(self):
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
        self.assertContains(response, "Victim, group, and geography intelligence.")
        self.assertContains(response, 'id="ransomware-map-view"')
        self.assertContains(
            response,
            'data-style-url="/static/intel/maps/ransomware_map_style.json"',
        )
        self.assertContains(
            response,
            'data-geography-url="/static/intel/maps/world-countries-110m.geojson"',
        )
        self.assertContains(response, 'src="/static/vendor/maplibre/maplibre-gl.js"')
        self.assertContains(response, 'href="/static/vendor/maplibre/maplibre-gl.css"')
        self.assertContains(response, 'src="/static/intel/js/ransomware-map.js"')
        self.assertContains(response, "Natural Earth 4.1.0")
        self.assertContains(response, "Most affected countries")
        self.assertContains(response, "Nordic Mills")
        self.assertNotContains(response, "General bulletin")

    def test_map_runtime_configuration_has_no_external_map_infrastructure(self):
        response = self.client.get(RANSOMWARE_MAP_URL)
        rendered = response.content.decode()
        repository_root = Path(settings.BASE_DIR)
        checked_text = "\n".join(
            [
                rendered,
                (repository_root / "templates/intel/ransomware_map.html").read_text(
                    encoding="utf-8"
                ),
                (repository_root / "static/intel/maps/ransomware_map_style.json").read_text(
                    encoding="utf-8"
                ),
                (repository_root / "static/intel/js/ransomware-map.js").read_text(
                    encoding="utf-8"
                ),
            ]
        ).lower()

        for forbidden_host in (
            "unpkg.com",
            "basemaps.cartocdn.com",
            "api.mapbox.com",
            "mapbox.com",
        ):
            with self.subTest(forbidden_host=forbidden_host):
                self.assertNotIn(forbidden_host, checked_text)
        self.assertNotIn("pmtiles", rendered.lower())
        style = json.loads(
            (repository_root / "static/intel/maps/ransomware_map_style.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(style["sources"], {})

    def test_map_page_still_renders_useful_content_without_javascript(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden")

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertContains(response, 'id="ransomware-map-page"')
        self.assertContains(response, 'data-live-url="/ransomware/map/live/?window=7d"')
        self.assertContains(response, "JavaScript is required for the interactive map.")
        self.assertContains(response, "Nordic Mills")
        self.assertContains(response, "Sweden")

    def test_map_page_renders_main_navigation_entry_with_active_state(self):
        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertGreaterEqual(response.content.decode().count('href="/ransomware/map/"'), 2)
        self.assertEqual(response.content.decode().count('data-navigation-key="ransomware"'), 2)
        self.assertEqual(response.content.decode().count('aria-current="page"'), 2)

    def test_window_filtering_changes_victim_scope(self):
        self._create_victim(victim="Fresh Victim", group="Akira", country="Sweden", hours_ago=6)
        self._create_victim(victim="Older Victim", group="Qilin", country="Finland", days_ago=10)

        response_24h = self.client.get(RANSOMWARE_MAP_URL, {"window": "24h"})
        response_30d = self.client.get(RANSOMWARE_MAP_URL, {"window": "30d"})

        self.assertEqual(response_24h.context["summary"]["victim_count"], 1)
        self.assertEqual(response_30d.context["summary"]["victim_count"], 2)
        self.assertContains(response_30d, "Older Victim")
        self.assertNotContains(response_24h, "Older Victim")

    def test_explicit_country_aliases_normalize_deterministically(self):
        aliases = {
            "US": "USA",
            "USA": "USA",
            "United States": "USA",
            "United States of America": "USA",
            "UK": "GBR",
            "GB": "GBR",
            "GBR": "GBR",
            "United Kingdom": "GBR",
            "Russia": "RUS",
            "Russian Federation": "RUS",
            "South Korea": "KOR",
            "Republic of Korea": "KOR",
            "Czech Republic": "CZE",
            "Czechia": "CZE",
        }

        for alias, expected_country_id in aliases.items():
            with self.subTest(alias=alias):
                identity = normalize_ransomware_country(f"  {alias}  ")
                self.assertTrue(identity.recognized)
                self.assertEqual(identity.country_id, expected_country_id)

    def test_all_bundled_countries_are_normalized_from_geometry_identity(self):
        self.assertGreater(len(RANSOMWARE_MAP_COUNTRIES), 170)
        self.assertEqual(RANSOMWARE_MAP_DATASET["scale"], "1:110m")

        for country in RANSOMWARE_MAP_COUNTRIES:
            with self.subTest(country=country.display_name):
                self.assertEqual(
                    normalize_ransomware_country(country.display_name).country_id,
                    country.country_id,
                )
                self.assertEqual(
                    normalize_ransomware_country(country.country_id).country_id,
                    country.country_id,
                )

    def test_unknown_country_stays_unknown_instead_of_being_guessed(self):
        identity = normalize_ransomware_country("North Atlantis")
        self.assertFalse(identity.recognized)
        self.assertEqual(identity.display_name, "North Atlantis")

        self._create_victim(
            victim="Unknown Geography Co",
            group="Akira",
            country="North Atlantis",
        )
        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertEqual(response.context["map_country_data"], [])
        self.assertEqual(response.context["summary"]["countryless_count"], 1)
        self.assertEqual(response.context["latest_victims"][0]["country_url"], "")

    def test_recognized_country_no_longer_needs_manual_coordinates(self):
        from intel import views

        self.assertFalse(hasattr(views, "RANSOMWARE_MAP_COORDINATES"))
        self._create_victim(victim="Nairobi Works", group="Akira", country="Kenya")

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertEqual(response.context["map_country_data"][0]["country_id"], "KEN")
        self.assertEqual(response.context["map_country_data"][0]["name"], "Kenya")
        self.assertEqual(response.context["summary"]["countryless_count"], 0)

    def test_country_aggregation_normalizes_localized_aliases(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=3)
        self._create_victim(victim="Scandi Foods", group="Qilin", country="Sverige", hours_ago=4)

        response = self.client.get(RANSOMWARE_MAP_URL)

        top_country = response.context["top_countries"][0]
        self.assertEqual(top_country["country"], "Sweden")
        self.assertEqual(top_country["country_id"], "SWE")
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

    def test_latest_victims_render_country_pending_when_country_is_missing(self):
        self._create_victim(
            victim="No Geo Co",
            group="DragonForce",
            summary="Victim listing still useful without country.",
            hours_ago=1,
        )

        response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertEqual(response.context["latest_victims"][0]["victim_name"], "No Geo Co")
        self.assertContains(response, "Country pending")

    def test_group_country_and_window_filters_compose(self):
        self._create_victim(victim="Fresh Swedish", group="Akira", country="Sweden", hours_ago=1)
        self._create_victim(victim="Old Swedish", group="Akira", country="Sweden", days_ago=2)
        self._create_victim(victim="Fresh Finnish", group="Akira", country="Finland", hours_ago=2)
        self._create_victim(victim="Fresh Other Group", group="Qilin", country="Sweden", hours_ago=3)

        response = self.client.get(
            RANSOMWARE_MAP_URL,
            {"window": "24h", "group": "akira", "country": "Sverige"},
        )

        self.assertEqual(response.context["selected_group"], "akira")
        self.assertEqual(response.context["selected_country"], "Sweden")
        self.assertEqual(response.context["summary"]["victim_count"], 1)
        self.assertEqual(response.context["latest_victims"][0]["victim_name"], "Fresh Swedish")

    def test_selected_country_drilldown_agrees_across_panels_and_map(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=1)
        self._create_victim(victim="Stockholm Labs", group="Qilin", country="Sverige", hours_ago=2)
        self._create_victim(victim="Texas Hosting", group="Lockbit", country="United States", hours_ago=3)

        response = self.client.get(RANSOMWARE_MAP_URL, {"country": "Sverige"})

        self.assertEqual(response.context["selected_country"], "Sweden")
        self.assertTrue(response.context["selected_country_on_map"])
        self.assertEqual(
            {item["country_id"] for item in response.context["map_country_data"]},
            {"SWE"},
        )
        self.assertTrue(response.context["map_country_data"][0]["is_selected"])
        self.assertEqual(response.context["summary"], {
            "victim_count": 2,
            "country_count": 1,
            "group_count": 2,
            "countryless_count": 0,
        })
        self.assertTrue(
            all(record["country"] == "Sweden" for record in response.context["latest_victims"])
        )
        self.assertEqual([row["country"] for row in response.context["top_countries"]], ["Sweden"])
        self.assertEqual(
            {row["group_name"] for row in response.context["top_groups"]},
            {"Akira", "Qilin"},
        )

    def test_map_payload_counts_and_activity_values_match_analytics(self):
        for index in range(4):
            self._create_victim(
                victim=f"Swedish Victim {index}",
                group="Akira",
                country="Sweden",
                hours_ago=index,
            )
        self._create_victim(victim="US Victim", group="Qilin", country="US", hours_ago=5)
        self._create_victim(victim="Unknown Victim", group="Qilin", country="Unknown", hours_ago=6)

        response = self.client.get(RANSOMWARE_MAP_URL)
        country_data = response.context["map_country_data"]

        self.assertEqual(sum(row["record_count"] for row in country_data), 5)
        self.assertEqual(response.context["summary"]["victim_count"], 6)
        self.assertEqual(response.context["summary"]["country_count"], len(country_data))
        self.assertEqual(response.context["summary"]["countryless_count"], 1)
        self.assertEqual({row["country_id"] for row in country_data}, {"SWE", "USA"})
        self.assertTrue(all(1 <= row["intensity_level"] <= 4 for row in country_data))
        self.assertEqual(country_data[0]["intensity_level"], 4)

    def test_zero_country_and_zero_record_empty_states_are_intentional(self):
        empty_response = self.client.get(RANSOMWARE_MAP_URL)
        self.assertContains(empty_response, "No ransomware victims in current scope")
        self.assertEqual(empty_response.context["map_country_data"], [])

        self._create_victim(victim="Countryless Victim", group="Akira", hours_ago=2)
        countryless_response = self.client.get(RANSOMWARE_MAP_URL)
        self.assertContains(countryless_response, "Victim activity found, geography still sparse")
        self.assertContains(countryless_response, "without guessing a location")

    def test_live_endpoint_returns_country_polygon_snapshot(self):
        victim = self._create_victim(
            victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=1
        )

        response = self.client.get(RANSOMWARE_MAP_LIVE_URL, {"window": "7d"})
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["cursor"], victim.id)
        self.assertEqual(payload["events"][0]["country_key"], "SWE")
        self.assertEqual(payload["snapshot"]["summary"]["victim_count"], 1)
        self.assertEqual(payload["snapshot"]["map_country_data"][0]["country_id"], "SWE")
        self.assertEqual(payload["snapshot"]["map_country_data"][0]["record_count"], 1)
        self.assertEqual(
            payload["snapshot"]["map_marker_data"],
            payload["snapshot"]["map_country_data"],
        )

    def test_live_endpoint_respects_cursor_and_only_returns_new_events(self):
        self._create_victim(victim="Older One", group="Akira", country="Sweden", hours_ago=3)
        old_event = self._create_victim(
            victim="Older Two", group="Akira", country="Sweden", hours_ago=2
        )
        new_event = self._create_victim(
            victim="Fresh One", group="Akira", country="Sweden", hours_ago=1
        )

        response = self.client.get(
            RANSOMWARE_MAP_LIVE_URL,
            {"window": "7d", "cursor": old_event.id},
        )
        payload = response.json()

        self.assertEqual(payload["cursor"], new_event.id)
        self.assertEqual([event["id"] for event in payload["events"]], [new_event.id])
        self.assertEqual(payload["snapshot"]["latest_victims"][0]["victim_name"], "Fresh One")

    def test_live_endpoint_respects_group_country_and_window_filters(self):
        self._create_victim(victim="Nordic Mills", group="Akira", country="Sweden", hours_ago=1)
        self._create_victim(victim="Old Nordic", group="Akira", country="Sweden", days_ago=2)
        self._create_victim(victim="Helsinki Works", group="Akira", country="Finland", hours_ago=2)
        self._create_victim(victim="Stockholm Other", group="Lockbit", country="Sweden", hours_ago=3)

        response = self.client.get(
            RANSOMWARE_MAP_LIVE_URL,
            {"window": "24h", "group": "akira", "country": "Sverige"},
        )
        payload = response.json()

        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(payload["events"][0]["victim"], "Nordic Mills")
        self.assertEqual(payload["snapshot"]["summary"]["victim_count"], 1)
        self.assertEqual(
            {row["country_key"] for row in payload["snapshot"]["map_country_data"]},
            {"SWE"},
        )
        self.assertEqual(
            [row["group_name"] for row in payload["snapshot"]["top_groups"]],
            ["Akira"],
        )

    def test_json_script_escapes_source_controlled_values(self):
        self._create_victim(
            victim='Victim </script><script>alert("x")</script>',
            group="Akira",
            country="Sweden",
        )

        response = self.client.get(RANSOMWARE_MAP_URL)
        rendered = response.content.decode()

        self.assertNotIn('</script><script>alert("x")</script>', rendered)
        self.assertIn("\\u003C/script\\u003E", rendered)

    def test_threat_watch_affordance_remains_superuser_only(self):
        anonymous_response = self.client.get(RANSOMWARE_MAP_URL)
        self.assertNotContains(anonymous_response, "Threat Watch Map")
        self.assertEqual(self.client.get(reverse("dark-map")).status_code, 302)

        user = get_user_model().objects.create_superuser(
            username="operator",
            email="operator@example.com",
            password="not-used-by-force-login",
        )
        self.client.force_login(user)
        superuser_response = self.client.get(RANSOMWARE_MAP_URL)

        self.assertContains(superuser_response, "Threat Watch Map")
        self.assertContains(superuser_response, f'href="{reverse("dark-map")}"')
        self.assertEqual(self.client.get(reverse("dark-map")).status_code, 200)
