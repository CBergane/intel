import hashlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.dark_models import DarkHit, DarkSource

User = get_user_model()
DARK_GROUPS_URL = reverse("dark-dashboard")
DARK_MAP_URL = reverse("dark-map")
DARK_MAP_LIVE_URL = reverse("dark-map-live")
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
    is_watch_match: bool = False,
    detected_offset_days: int = 0,
    detected_offset_hours: int = 0,
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
        is_watch_match=is_watch_match,
        matched_keywords=["watch"] if is_watch_match else [],
    )
    if detected_offset_days or detected_offset_hours:
        activity_at = timezone.now() - timedelta(
            days=detected_offset_days,
            hours=detected_offset_hours,
        )
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
        self.assertEqual(self.client.get(DARK_MAP_URL).status_code, 302)
        self.assertEqual(self.client.get(DARK_RECENT_URL).status_code, 302)

    def test_superuser_can_open_active_groups_and_recent_hits(self):
        self.client.force_login(self.superuser)

        groups_response = self.client.get(DARK_GROUPS_URL)
        map_response = self.client.get(DARK_MAP_URL)
        recent_response = self.client.get(DARK_RECENT_URL)

        self.assertEqual(groups_response.status_code, 200)
        self.assertEqual(map_response.status_code, 200)
        self.assertEqual(recent_response.status_code, 200)
        self.assertContains(groups_response, "Active Groups")
        self.assertContains(map_response, "Threat Map")
        self.assertContains(recent_response, "Recent Hits")

    def test_non_superuser_does_not_get_dark_pages(self):
        self.client.force_login(self.regular_user)
        self.assertNotEqual(self.client.get(DARK_GROUPS_URL).status_code, 200)
        self.assertNotEqual(self.client.get(DARK_MAP_URL).status_code, 200)
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
        self.source_d = _make_source(slug="lockbit-a", name="LockBit Source")

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
            detected_offset_hours=8,
        )
        _make_hit(
            self.source_c,
            title="Gamma Health",
            group_name="Play",
            victim_name="Gamma Health",
            country="Denmark",
            detected_offset_hours=2,
        )
        _make_hit(
            self.source_d,
            title="Legacy Victim",
            group_name="LockBit",
            victim_name="Legacy Victim",
            country="Finland",
            detected_offset_days=10,
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
        self.assertEqual(rows[0]["group_name"], "Play")
        akira_row = next(row for row in rows if row["group_name"] == "Akira")
        self.assertEqual(akira_row["incident_count"], 2)
        self.assertEqual(akira_row["latest_victim_name"], "Beta Retail")
        self.assertEqual(akira_row["latest_country"], "Norway")
        self.assertEqual(akira_row["source_count"], 2)

    def test_active_groups_view_renders_summary_metrics(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Affected Countries")
        self.assertContains(response, "Sources Producing Hits")
        summary = response.context["summary_metrics"]
        self.assertEqual(summary["active_groups_24h"], 2)
        self.assertEqual(summary["active_groups_7d"], 2)
        self.assertEqual(summary["incident_count_24h"], 2)
        self.assertEqual(summary["incident_count_7d"], 3)
        self.assertEqual(summary["affected_country_count"], 3)
        self.assertEqual(summary["source_hit_count"], 3)

    def test_active_groups_view_renders_live_incidents_section(self):
        _make_hit(
            self.source_a,
            title="Black Basta Profile",
            group_name="Black Basta",
            record_type="group",
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("dark-recent-hits"))
        self.assertContains(response, "Live Incidents")
        live_incidents = response.context["live_incidents"]
        self.assertTrue(live_incidents)
        self.assertTrue(all(hit.record_type == "incident" for hit in live_incidents))
        self.assertFalse(any(hit.title == "Black Basta Profile" for hit in live_incidents))

    def test_group_cards_without_stored_group_name_still_appear_via_title_fallback(self):
        _make_hit(
            self.source_a,
            title="Black Basta",
            group_name="   ",
            record_type="group",
        )
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        rows = list(response.context["group_rows"].object_list)
        black_basta_row = next(row for row in rows if row["group_name"] == "Black Basta")
        self.assertEqual(black_basta_row["incident_count"], 1)

    def test_table_rows_without_explicit_group_name_still_appear_when_title_is_group(self):
        _make_hit(
            self.source_b,
            title="LockBit",
            group_name="",
            record_type="table_row",
        )
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        rows = list(response.context["group_rows"].object_list)
        lockbit_row = next(row for row in rows if row["group_name"] == "LockBit")
        self.assertEqual(lockbit_row["incident_count"], 1)

    def test_group_identity_is_normalized_for_grouping(self):
        _make_hit(
            self.source_a,
            title="Akira Follow-Up",
            group_name="  akira   ",
            victim_name="Delta Logistics",
        )
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.context["active_group_count"], 2)
        rows = list(response.context["group_rows"].object_list)
        akira_row = next(row for row in rows if row["group_name"] == "Akira")
        self.assertEqual(akira_row["incident_count"], 3)

    def test_blank_group_name_does_not_create_fake_group(self):
        _make_hit(
            self.source_a,
            title="Ungrouped Incident",
            group_name="   ",
            victim_name="Omega Corp",
            record_type="incident",
        )
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_GROUPS_URL)

        self.assertEqual(response.context["active_group_count"], 2)
        rows = list(response.context["group_rows"].object_list)
        self.assertFalse(any(row["group_name"] == "Ungrouped Incident" for row in rows))

    def test_dark_dashboard_window_filters_change_group_scope(self):
        self.client.force_login(self.superuser)

        response_24h = self.client.get(DARK_GROUPS_URL, {"window": "24h"})
        response_30d = self.client.get(DARK_GROUPS_URL, {"window": "30d"})

        self.assertEqual(response_24h.context["active_group_count"], 2)
        self.assertEqual(response_24h.context["summary_metrics"]["affected_country_count"], 2)
        self.assertEqual(response_30d.context["active_group_count"], 3)
        self.assertEqual(response_30d.context["summary_metrics"]["affected_country_count"], 4)

    def test_active_groups_match_filter_shows_only_watch_matched_records(self):
        _make_hit(
            self.source_a,
            title="Matched Alert",
            group_name="DragonForce",
            victim_name="Matched Alert",
            country="Sweden",
            is_watch_match=True,
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_GROUPS_URL, {"match": "matched"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["match_filter"], "matched")
        rows = list(response.context["group_rows"].object_list)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["group_name"], "DragonForce")
        self.assertEqual(rows[0]["watch_match_count"], 1)

    def test_recent_hits_view_keeps_raw_hits_available(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_RECENT_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Manufacturing")
        self.assertContains(response, "Beta Retail")
        self.assertContains(response, reverse("dark-dashboard"))

    def test_recent_hits_match_filter_hides_unmatched_context_records(self):
        _make_hit(
            self.source_a,
            title="Matched Context",
            group_name="DragonForce",
            victim_name="Matched Context",
            is_watch_match=True,
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_RECENT_URL, {"match": "matched"})

        self.assertContains(response, "Matched Context")
        self.assertNotContains(response, "Alpha Manufacturing")
        self.assertContains(response, "Watch Match")


class DarkMapViewTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="dark-map-root",
            password="dark-map-pass-123",
        )
        self.source_a = _make_source(slug="map-akira", name="Map Akira Source")
        self.source_b = _make_source(slug="map-play", name="Map Play Source")
        self.source_c = _make_source(slug="map-lockbit", name="Map LockBit Source")

        _make_hit(
            self.source_a,
            title="Alpha Manufacturing",
            group_name="Akira",
            victim_name="Alpha Manufacturing",
            country="Sweden",
            record_type="incident",
            detected_offset_hours=2,
        )
        _make_hit(
            self.source_a,
            title="Akira Profile",
            group_name="Akira",
            country="Sweden",
            record_type="group",
            detected_offset_hours=4,
        )
        _make_hit(
            self.source_b,
            title="Beta Retail",
            group_name="Akira",
            victim_name="Beta Retail",
            country="Sweden",
            record_type="incident",
            detected_offset_hours=9,
        )
        _make_hit(
            self.source_b,
            title="Gamma Health",
            group_name="Play",
            victim_name="Gamma Health",
            country="Norway",
            record_type="incident",
            detected_offset_hours=5,
        )
        _make_hit(
            self.source_c,
            title="Legacy Finland",
            group_name="LockBit",
            victim_name="Legacy Finland",
            country="Finland",
            record_type="incident",
            detected_offset_days=12,
        )

    def test_map_page_renders_country_panels(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Threat Map")
        self.assertContains(response, "Operational Threat Surface")
        self.assertContains(response, "Group / Context Intel")
        self.assertContains(response, "Incident / Country Intel")
        self.assertContains(response, "Incoming Activity")
        self.assertContains(response, "Matched Watch Context")
        self.assertContains(response, "Source Coverage")
        self.assertContains(response, "Plot-Ready Countries")
        self.assertContains(response, "Top Groups")
        self.assertContains(response, 'id="dark-threat-map"')
        self.assertContains(response, 'data-country-key="sweden"')
        self.assertContains(response, 'data-group-node="akira"')
        self.assertContains(response, 'data-country-connection="sweden"')
        self.assertContains(response, "Quick Country Filter")
        self.assertContains(response, 'data-poll-url="')
        self.assertContains(response, "Live polling every 25s")
        self.assertNotContains(response, "overflow-x-auto")
        self.assertNotContains(response, "min-w-[68rem]")
        self.assertFalse(response.context["group_first_mode"])

    def test_map_page_still_renders_without_js(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Manufacturing")
        self.assertContains(response, "Gamma Health")
        self.assertContains(response, 'id="dark-threat-map"')
        self.assertContains(response, 'id="dark-map-incoming-list"')

    def test_map_page_aggregates_countries_and_groups(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL)

        country_rows = response.context["country_rows"]
        self.assertEqual(country_rows[0]["country"], "Sweden")
        self.assertEqual(country_rows[0]["incident_count"], 2)
        self.assertEqual(country_rows[0]["record_count"], 3)

        top_groups = response.context["top_groups"]
        akira_row = next(row for row in top_groups if row["group_name"] == "Akira")
        self.assertEqual(akira_row["incident_count"], 3)
        self.assertIn("Sweden", akira_row["countries"])

    def test_map_page_window_filter_includes_older_country_only_in_30d(self):
        self.client.force_login(self.superuser)

        response_7d = self.client.get(DARK_MAP_URL, {"window": "7d"})
        response_30d = self.client.get(DARK_MAP_URL, {"window": "30d"})

        countries_7d = [row["country"] for row in response_7d.context["country_rows"]]
        countries_30d = [row["country"] for row in response_30d.context["country_rows"]]
        self.assertNotIn("Finland", countries_7d)
        self.assertIn("Finland", countries_30d)

    def test_map_page_uses_unmatched_incident_records_by_default(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["match_filter"], "all")
        self.assertGreater(response.context["map_metrics"]["incident_count"], 0)
        self.assertContains(response, "Sweden")

    def test_map_page_normalizes_country_aliases_for_aggregation_and_drilldown(self):
        _make_hit(
            self.source_a,
            title="Alias Sweden Incident",
            group_name="Akira",
            victim_name="Alias Sweden Incident",
            country="Sverige",
            record_type="incident",
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"country": "Sverige"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["selected_country"], "Sweden")
        sweden_row = next(
            row for row in response.context["country_rows"] if row["country"] == "Sweden"
        )
        self.assertEqual(sweden_row["incident_count"], 3)
        incoming_titles = [hit.title for hit in response.context["incoming_activity"]]
        self.assertIn("Alias Sweden Incident", incoming_titles)
        self.assertTrue(
            all((getattr(hit, "map_country", "") or hit.country) == "Sweden" for hit in response.context["incoming_activity"])
        )

    def test_map_country_drilldown_filters_incoming_activity_and_highlights_groups(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL, {"country": "Sweden"})

        self.assertEqual(response.context["selected_country"], "Sweden")
        incoming_activity = response.context["incoming_activity"]
        self.assertTrue(incoming_activity)
        self.assertTrue(
            all((getattr(hit, "map_country", "") or hit.country) == "Sweden" for hit in incoming_activity)
        )

        top_groups = response.context["top_groups"]
        akira_row = next(row for row in top_groups if row["group_name"] == "Akira")
        play_row = next(row for row in top_groups if row["group_name"] == "Play")
        self.assertTrue(akira_row["country_match"])
        self.assertFalse(play_row["country_match"])
        sweden_tile = next(
            tile for tile in response.context["map_tiles"] if tile["country_key"] == "sweden"
        )
        self.assertTrue(sweden_tile["is_selected"])
        self.assertContains(response, 'data-country-key="sweden"')
        self.assertContains(response, 'data-selected="true"')

    def test_map_incoming_activity_renders_group_and_incident_signals(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL)

        titles = [hit.title for hit in response.context["incoming_activity"]]
        self.assertIn("Alpha Manufacturing", titles)
        self.assertIn("Akira Profile", titles)
        self.assertIn("Gamma Health", titles)

    def test_map_match_filter_can_focus_on_watch_matched_records(self):
        _make_hit(
            self.source_a,
            title="Matched Sweden Incident",
            group_name="DragonForce",
            victim_name="Matched Sweden Incident",
            country="Sweden",
            is_watch_match=True,
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"match": "matched"})

        self.assertEqual(response.context["match_filter"], "matched")
        incoming_titles = [hit.title for hit in response.context["incoming_activity"]]
        self.assertEqual(incoming_titles, ["Matched Sweden Incident"])
        top_groups = response.context["top_groups"]
        self.assertEqual(len(top_groups), 1)
        self.assertEqual(top_groups[0]["group_name"], "DragonForce")

    def test_map_source_filter_limits_visual_map_and_incoming_activity(self):
        self.client.force_login(self.superuser)
        response = self.client.get(DARK_MAP_URL, {"source": self.source_b.slug})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["selected_source"], self.source_b.slug)
        self.assertEqual(response.context["map_metrics"]["country_count"], 2)
        countries = [row["country"] for row in response.context["country_rows"]]
        self.assertEqual(countries, ["Norway", "Sweden"])
        incoming_titles = [hit.title for hit in response.context["incoming_activity"]]
        self.assertEqual(incoming_titles, ["Gamma Health", "Beta Retail"])
        norway_tile = next(
            tile for tile in response.context["map_tiles"] if tile["country_key"] == "norway"
        )
        self.assertTrue(norway_tile["has_activity"])

    def test_map_empty_state_explains_group_only_source_selection(self):
        group_only_source = _make_source(slug="map-group-only", name="Map Group Only")
        _make_hit(
            group_only_source,
            title="Group Context",
            group_name="Context Crew",
            record_type="group",
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"source": group_only_source.slug})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["group_first_mode"])
        self.assertEqual(response.context["map_metrics"]["country_count"], 0)
        self.assertContains(response, "Group activity available, geography pending")
        self.assertContains(response, "Group-Led Mode")
        self.assertContains(response, "Incoming Activity")
        self.assertContains(response, "Source Coverage")
        self.assertContains(response, "Matched Watch Context")

    def test_map_empty_state_explains_missing_incident_country_values(self):
        countryless_source = _make_source(slug="map-countryless", name="Map Countryless")
        _make_hit(
            countryless_source,
            title="Countryless Incident",
            group_name="Akira",
            victim_name="Countryless Incident",
            country="",
            record_type="incident",
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"source": countryless_source.slug})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["group_first_mode"])
        self.assertEqual(response.context["map_metrics"]["country_count"], 0)
        self.assertContains(response, "Incident records found, but not plot-ready")
        self.assertContains(response, "Group activity and source coverage remain the strongest signals in this view")
        self.assertContains(response, "Incoming Activity")

    def test_map_empty_state_explains_placeholder_country_values_that_need_normalization(self):
        unknown_country_source = _make_source(slug="map-unknown-country", name="Map Unknown Country")
        _make_hit(
            unknown_country_source,
            title="Unknown Geography Incident",
            group_name="Akira",
            victim_name="Unknown Geography Incident",
            country="Unknown",
            record_type="incident",
            detected_offset_hours=1,
        )
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"source": unknown_country_source.slug})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["group_first_mode"])
        self.assertEqual(response.context["map_metrics"]["country_count"], 0)
        self.assertContains(response, "Country normalization still in progress")
        self.assertContains(response, "Group activity and source coverage remain actionable in the meantime")

    def test_map_links_preserve_filters_for_recent_hits_and_source_coverage(self):
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_URL, {"window": "24h", "source": self.source_b.slug})

        self.assertContains(response, f"{DARK_RECENT_URL}?window=24h&source={self.source_b.slug}")
        self.assertContains(response, f"{DARK_MAP_URL}?window=24h&source={self.source_b.slug}")

    def test_map_live_endpoint_returns_expected_shape(self):
        self.client.force_login(self.superuser)

        response = self.client.get(DARK_MAP_LIVE_URL)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("cursor", payload)
        self.assertIn("events", payload)
        self.assertIn("snapshot", payload)
        self.assertTrue(payload["events"])
        event = payload["events"][0]
        self.assertEqual(
            sorted(event.keys()),
            sorted(
                [
                    "animate_connection",
                    "animate_country",
                    "animate_group",
                    "country",
                    "country_key",
                    "detected_at",
                    "excerpt",
                    "group_key",
                    "group_name",
                    "id",
                    "is_watch_match",
                    "last_seen_at",
                    "raw_url",
                    "record_type",
                    "signal_label",
                    "signal_title",
                    "source_name",
                    "title",
                ]
            ),
        )
        self.assertIn("map_metrics", payload["snapshot"])
        self.assertIn("incoming_activity", payload["snapshot"])
        self.assertIn("top_groups", payload["snapshot"])
        self.assertIn("top_countries", payload["snapshot"])
        self.assertIn("map_tiles", payload["snapshot"])

    def test_map_live_endpoint_filters_new_events_by_cursor_and_window(self):
        self.client.force_login(self.superuser)
        initial_cursor = DarkHit.objects.order_by("-id").values_list("id", flat=True).first()
        _make_hit(
            self.source_a,
            title="Live Sweden Incident",
            group_name="Akira",
            victim_name="Live Sweden Incident",
            country="Sweden",
            record_type="incident",
        )

        response = self.client.get(DARK_MAP_LIVE_URL, {"window": "24h", "cursor": initial_cursor})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([event["title"] for event in payload["events"]], ["Live Sweden Incident"])
        self.assertNotIn("Legacy Finland", [event["title"] for event in payload["events"]])
        top_countries = [row["country"] for row in payload["snapshot"]["top_countries"]]
        self.assertNotIn("Finland", top_countries)

    def test_map_live_endpoint_does_not_fake_country_animation_for_countryless_records(self):
        countryless_source = _make_source(slug="map-live-countryless", name="Map Live Countryless")
        countryless_hit = _make_hit(
            countryless_source,
            title="Countryless Live Incident",
            group_name="Akira",
            victim_name="Countryless Live Incident",
            country="",
            record_type="incident",
        )
        self.client.force_login(self.superuser)

        response = self.client.get(
            DARK_MAP_LIVE_URL,
            {"source": countryless_source.slug, "cursor": countryless_hit.id - 1},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["events"]), 1)
        event = payload["events"][0]
        self.assertEqual(event["title"], "Countryless Live Incident")
        self.assertTrue(event["animate_group"])
        self.assertFalse(event["animate_country"])
        self.assertFalse(event["animate_connection"])
        self.assertEqual(event["country"], "")
        self.assertEqual(event["country_key"], "")
