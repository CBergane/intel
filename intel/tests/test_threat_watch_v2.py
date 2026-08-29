import hashlib
import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from intel.models import DarkFetchRun, DarkHit, DarkSource


User = get_user_model()
THREAT_WATCH_URL = reverse("dark-map")
THREAT_WATCH_LIVE_URL = reverse("dark-map-live")
REPO_ROOT = Path(__file__).resolve().parents[2]


class ThreatWatchV2Tests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="threat-watch-v2-root",
            password="threat-watch-v2-pass",
        )
        self.source = DarkSource.objects.create(
            name="Threat Watch Source",
            slug="threat-watch-source",
            url="https://threat-watch.example.test/feed",
        )
        self.client.force_login(self.superuser)
        self._hit_index = 0

    def _hit(
        self,
        *,
        title,
        actor="Actor One",
        country="",
        record_type="incident",
        matched=False,
        source=None,
    ):
        self._hit_index += 1
        source = source or self.source
        content_hash = hashlib.sha256(
            f"{source.pk}:{title}:{country}:{self._hit_index}".encode()
        ).hexdigest()
        return DarkHit.objects.create(
            dark_source=source,
            title=title,
            victim_name=title if record_type == "incident" else "",
            group_name=actor,
            country=country,
            record_type=record_type,
            url=f"https://threat-watch.example.test/{self._hit_index}",
            content_hash=content_hash,
            is_watch_match=matched,
            matched_keywords=["watch"] if matched else [],
        )

    def test_auto_uses_actor_mode_when_geography_is_sparse(self):
        self._hit(title="Sparse One", actor="Qilin", country="Sweden")
        self._hit(title="Sparse Two", actor="Qilin", country="Sweden")

        response = self.client.get(THREAT_WATCH_URL)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["surface_mode"], "actors")
        self.assertContains(response, "Actor-led view")
        self.assertContains(response, 'id="threat-watch-actor-surface"')
        self.assertNotContains(response, 'id="threat-watch-map-view"')

    def test_auto_uses_geography_mode_for_comparative_observed_evidence(self):
        countries = ["Sweden", "Norway", "Denmark", "Sweden", "Norway"]
        for index, country in enumerate(countries):
            self._hit(title=f"Mapped {index}", actor=f"Actor {index % 2}", country=country)

        response = self.client.get(THREAT_WATCH_URL)

        self.assertEqual(response.context["surface_mode"], "geography")
        self.assertContains(response, "Geography-led view")
        self.assertContains(response, 'id="threat-watch-map-view"')
        self.assertContains(response, "/static/vendor/maplibre/maplibre-gl.js")
        self.assertContains(response, "/static/intel/maps/world-countries-110m.geojson")
        self.assertContains(response, "no origin, destination, path, or continuous risk is inferred")

    def test_shared_country_identity_handles_aliases_without_guessing(self):
        self._hit(title="US", country="US")
        self._hit(title="UK", country="United Kingdom")
        self._hit(title="Germany", country="Deutschland")
        self._hit(title="Czechia", country="Czech Republic")
        self._hit(title="Unknown", country="Atlantis")

        response = self.client.get(THREAT_WATCH_URL)
        country_ids = {row["country_id"] for row in response.context["country_rows"]}

        self.assertEqual(country_ids, {"USA", "GBR", "DEU", "CZE"})
        self.assertEqual(response.context["map_metrics"]["unknown_geography_count"], 1)
        self.assertNotIn("Atlantis", {row["country"] for row in response.context["country_rows"]})

    def test_unknown_and_missing_geography_remain_pending(self):
        self._hit(title="Unknown", country="Atlantis")
        self._hit(title="Missing", country="")

        response = self.client.get(THREAT_WATCH_URL)

        self.assertEqual(response.context["surface_mode"], "actors")
        self.assertEqual(response.context["map_metrics"]["country_count"], 0)
        self.assertEqual(response.context["map_metrics"]["unknown_geography_count"], 1)
        self.assertEqual(response.context["map_metrics"]["missing_geography_count"], 1)
        self.assertContains(response, "Geography pending")
        self.assertNotContains(response, "Outside Current Map Coverage")
        self.assertNotContains(response, "<svg")

    def test_actor_ranking_and_watch_counts_are_deterministic(self):
        zulu = self._hit(title="Zulu activity", actor="Zulu", matched=True)
        alpha = self._hit(title="Alpha activity", actor="Alpha", matched=True)
        tie_time = timezone.now() - timedelta(minutes=3)
        DarkHit.objects.filter(pk__in=[zulu.pk, alpha.pk]).update(
            detected_at=tie_time,
            last_seen_at=tie_time,
        )

        response = self.client.get(THREAT_WATCH_URL)
        actors = response.context["top_actors"]

        self.assertEqual([row["group_name"] for row in actors], ["Alpha", "Zulu"])
        self.assertEqual([row["watch_match_count"] for row in actors], [1, 1])
        self.assertEqual(response.context["matched_summary"]["record_count"], 2)
        self.assertEqual(response.context["matched_summary"]["group_count"], 2)

    def test_source_coverage_uses_real_mapped_incident_ratio(self):
        self._hit(title="Mapped incident", actor="Akira", country="Sweden")
        self._hit(title="Countryless incident", actor="Akira", country="")
        self._hit(
            title="Actor profile",
            actor="Akira",
            country="Sweden",
            record_type="group",
        )

        response = self.client.get(THREAT_WATCH_URL)
        source_row = response.context["coverage_source_rows"][0]

        self.assertEqual(source_row["record_count"], 3)
        self.assertEqual(source_row["incident_count"], 2)
        self.assertEqual(source_row["mapped_incident_count"], 1)
        self.assertEqual(source_row["geography_coverage_percent"], 50)
        self.assertContains(response, "Geography coverage: 1 / 2 incidents (50%)")

    def test_filters_and_selected_country_remain_server_authoritative(self):
        other_source = DarkSource.objects.create(
            name="Other Threat Source",
            slug="other-threat-source",
            url="https://other-threat.example.test/feed",
        )
        self._hit(title="Matched Sweden", actor="Akira", country="Sweden", matched=True)
        self._hit(title="Unmatched Norway", actor="Play", country="Norway")
        self._hit(
            title="Other Sweden",
            actor="Qilin",
            country="Sweden",
            matched=True,
            source=other_source,
        )

        response = self.client.get(
            THREAT_WATCH_URL,
            {"window": "24h", "source": self.source.slug, "match": "matched", "country": "Sverige"},
        )

        self.assertEqual(response.context["window"], "24h")
        self.assertEqual(response.context["selected_source"], self.source.slug)
        self.assertEqual(response.context["match_filter"], "matched")
        self.assertEqual(response.context["selected_country"], "Sweden")
        self.assertEqual(response.context["selected_country_key"], "SWE")
        self.assertEqual([hit.title for hit in response.context["incoming_activity"]], ["Matched Sweden"])

    def test_live_snapshot_preserves_new_surface_contract(self):
        self._hit(title="Live Match", actor="Akira", country="Sweden", matched=True)

        response = self.client.get(THREAT_WATCH_LIVE_URL)
        snapshot = response.json()["snapshot"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(snapshot["surface_mode"], "actors")
        self.assertEqual(snapshot["top_actors"], snapshot["top_groups"])
        self.assertEqual(snapshot["map_country_data"][0]["country_id"], "SWE")
        self.assertEqual(snapshot["coverage_sources"][0]["geography_coverage_percent"], 100)

    def test_source_controlled_text_is_escaped(self):
        self._hit(
            title='<img src=x onerror="alert(1)">',
            actor="<script>alert(1)</script>",
            country="Sweden",
        )

        response = self.client.get(THREAT_WATCH_URL)

        self.assertNotContains(response, '<script>alert(1)</script>')
        self.assertNotContains(response, '<img src=x onerror="alert(1)">')
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertContains(response, "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;")

    def test_static_implementation_is_local_safe_and_has_no_svg_architecture(self):
        template = (REPO_ROOT / "templates" / "intel" / "dark" / "map.html").read_text(
            encoding="utf-8"
        )
        script = (REPO_ROOT / "static" / "intel" / "js" / "threat-watch.js").read_text(
            encoding="utf-8"
        )
        style = (REPO_ROOT / "static" / "intel" / "maps" / "ransomware_map_style.json").read_text(
            encoding="utf-8"
        )
        combined = f"{template}\n{script}\n{style}".lower()

        for forbidden in (
            "unpkg.com",
            "basemaps.cartocdn.com",
            "api.mapbox.com",
            "mapbox.com",
            "outside current map coverage",
            "data-country-connection",
            "data-group-node",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertNotIn("innerhtml", script.lower())
        self.assertNotIn("createelementns", script.lower())
        self.assertIn('promoteId: "country_id"', script)
        self.assertIn("map.isSourceLoaded(countrySourceId)", script)
        self.assertIn("textContent", script)

    def test_bundled_geometry_contains_representative_canonical_ids(self):
        geometry = json.loads(
            (REPO_ROOT / "static" / "intel" / "maps" / "world-countries-110m.geojson").read_text(
                encoding="utf-8"
            )
        )
        country_ids = {
            feature["properties"]["country_id"] for feature in geometry["features"]
        }
        self.assertTrue({"USA", "GBR", "DEU", "ITA", "MEX", "BRA", "IND"}.issubset(country_ids))


class ThreatWatchFetchRunPerformanceTests(TestCase):
    history_per_source = 100

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="threat-watch-performance-root",
            password="threat-watch-performance-pass",
        )
        self.client.force_login(self.superuser)
        self.now = timezone.now()
        self.sources = [
            DarkSource.objects.create(
                name=f"Performance Dark Source {index}",
                slug=f"performance-dark-source-{index}",
                url=f"https://performance-dark-{index}.example.test/feed",
            )
            for index in range(3)
        ]
        history = []
        for source in self.sources:
            for index in range(self.history_per_source):
                started_at = self.now - timedelta(days=2, minutes=index)
                history.append(
                    DarkFetchRun(
                        dark_source=source,
                        started_at=started_at,
                        finished_at=started_at + timedelta(seconds=2),
                        ok=index % 2 == 0,
                    )
                )
        DarkFetchRun.objects.bulk_create(history)
        tie_time = self.now - timedelta(minutes=1)
        self.latest_runs = []
        for source in self.sources:
            DarkFetchRun.objects.create(
                dark_source=source,
                started_at=tie_time,
                finished_at=tie_time + timedelta(seconds=2),
                ok=False,
                error="superseded",
            )
            self.latest_runs.append(
                DarkFetchRun.objects.create(
                    dark_source=source,
                    started_at=tie_time,
                    finished_at=tie_time + timedelta(seconds=3),
                    ok=True,
                )
            )

    def test_threat_watch_materializes_only_latest_dark_fetch_run_per_source(self):
        loaded_ids = []
        original_from_db = DarkFetchRun.from_db

        def record_from_db(db, field_names, values):
            instance = original_from_db(db, field_names, values)
            loaded_ids.append(instance.id)
            return instance

        with patch.object(DarkFetchRun, "from_db", side_effect=record_from_db), CaptureQueriesContext(
            connection
        ) as queries:
            response = self.client.get(THREAT_WATCH_URL)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(loaded_ids), {run.id for run in self.latest_runs})
        self.assertEqual(len(loaded_ids), len(self.sources))
        self.assertLessEqual(len(queries), 5)
