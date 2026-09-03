from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from intel.dark_utils import (
    _absolute_http_url,
    _fragment_url,
    extract_links,
    extract_profile_records,
    normalize_dark_country,
)
from intel.notifications import (
    build_dark_hit_alert_fingerprint,
    build_dark_hit_alert_identity,
)
from intel.models import DarkDocument, DarkFetchRun, DarkHit, DarkSource, OpsJob


class DummyResponse:
    def __init__(self, chunks, *, status_code=200, url="https://example.test/page"):
        self._chunks = chunks
        self.status_code = status_code
        self.url = url

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=8192):
        del chunk_size
        for chunk in self._chunks:
            yield chunk


class DarkSourceModelTests(TestCase):
    def test_dark_source_defaults_to_generic_extractor_profile(self):
        source = DarkSource.objects.create(
            name="Profile Default",
            slug="profile-default",
            url="https://example.test/default",
        )

        self.assertEqual(
            source.extractor_profile,
            DarkSource.ExtractorProfile.GENERIC_PAGE,
        )


class RansomDbCountryExtractionTests(SimpleTestCase):
    def _extract_record(self, country_markup: str):
        markup = f"""
        <article class="incident-card">
            <h3>Example Victim</h3>
            <p>Threat Group: Example Group</p>
            {country_markup}
            <p>Victim disclosure posted with extortion details.</p>
        </article>
        """
        records = extract_profile_records(
            markup,
            profile="incident_cards",
            base_url="https://www.ransom-db.com/live-updates",
        )
        self.assertEqual(len(records), 1)
        return records[0]

    def assertCountryEvidence(
        self,
        record,
        *,
        source_value: str,
        canonical_name: str,
        country_code: str,
        provenance: str,
    ):
        self.assertEqual(record.country, canonical_name)
        self.assertEqual(record.country_value, source_value)
        self.assertEqual(record.country_name, canonical_name)
        self.assertEqual(record.country_code, country_code)
        self.assertEqual(record.country_provenance, provenance)

    def test_same_line_country_label_is_extracted_and_validated(self):
        record = self._extract_record("<p>Country: Sweden</p>")

        self.assertCountryEvidence(
            record,
            source_value="Sweden",
            canonical_name="Sweden",
            country_code="SWE",
            provenance="labeled_text",
        )

    def test_adjacent_block_country_label_and_value_are_extracted(self):
        record = self._extract_record(
            """
            <div class="country-field">
                <div>Country</div>
                <div>Sweden</div>
            </div>
            """
        )

        self.assertCountryEvidence(
            record,
            source_value="Sweden",
            canonical_name="Sweden",
            country_code="SWE",
            provenance="labeled_text",
        )

    def test_current_ransomdb_split_span_schema_prefers_explicit_value(self):
        markup = """
        <div class="glass-card p-6">
            <div class="flex items-center gap-3">
                <img src="/assets/images/flags/us.png" alt="US" />
                <h3>Example Victim</h3>
            </div>
            <div class="flex items-center gap-2">
                <span>Threat Group:</span><span>Example Group</span>
            </div>
            <div class="flex items-center gap-2">
                <span>Country:</span><span>United States</span>
            </div>
            <p>Victim disclosure posted with extortion details.</p>
        </div>
        """

        records = extract_profile_records(markup, profile="incident_cards")

        self.assertEqual(len(records), 1)
        self.assertIn("/assets/images/flags/us.png", records[0].raw)
        self.assertCountryEvidence(
            records[0],
            source_value="United States",
            canonical_name="United States",
            country_code="USA",
            provenance="labeled_text",
        )

    def test_country_sibling_wins_over_parent_with_later_industry_field(self):
        cases = (
            ("Spain", "IT services", "Spain", "ESP"),
            ("South Africa", "Fleet management", "South Africa", "ZAF"),
            ("United States", "Dental care", "United States", "USA"),
        )

        for source_value, industry, canonical_name, country_code in cases:
            with self.subTest(country=source_value, industry=industry):
                record = self._extract_record(
                    f"""
                    <div class="grid grid-cols-2 gap-4">
                        <div class="flex items-center gap-2">
                            <span class="text-dark-text-secondary">Country:</span>
                            <span class="text-white font-medium"> {source_value} </span>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-dark-text-secondary">Industry:</span>
                            <span class="text-white font-medium"> {industry} </span>
                        </div>
                    </div>
                    """
                )

                self.assertCountryEvidence(
                    record,
                    source_value=source_value,
                    canonical_name=canonical_name,
                    country_code=country_code,
                    provenance="labeled_text",
                )

    def test_structurally_isolated_multi_country_value_remains_valid(self):
        record = self._extract_record(
            """
            <div class="country-field">
                <span>Country:</span>
                <span>Myanmar / United States</span>
            </div>
            """
        )

        self.assertCountryEvidence(
            record,
            source_value="Myanmar / United States",
            canonical_name="Myanmar",
            country_code="MMR",
            provenance="labeled_text",
        )

    def test_iso2_flag_in_country_context_is_extracted(self):
        record = self._extract_record(
            '<img src="/assets/images/flags/se.png" alt="SE" />'
        )

        self.assertCountryEvidence(
            record,
            source_value="SE",
            canonical_name="Sweden",
            country_code="SWE",
            provenance="flag_image",
        )

    def test_iso3_flag_in_country_context_is_extracted(self):
        record = self._extract_record(
            '<img class="country-flag" src="/images/swe.png" title="SWE" />'
        )

        self.assertCountryEvidence(
            record,
            source_value="SWE",
            canonical_name="Sweden",
            country_code="SWE",
            provenance="flag_image",
        )

    def test_country_data_attribute_is_extracted(self):
        record = self._extract_record('<div data-country-code="GBR"></div>')

        self.assertCountryEvidence(
            record,
            source_value="GBR",
            canonical_name="United Kingdom",
            country_code="GBR",
            provenance="data_attribute",
        )

    def test_flag_image_outside_country_context_is_not_extracted(self):
        record = self._extract_record(
            '<img class="company-logo" src="/assets/logos/us.png" alt="US" />'
        )

        self.assertCountryEvidence(
            record,
            source_value="",
            canonical_name="",
            country_code="",
            provenance="",
        )

    def test_country_like_prose_does_not_become_country(self):
        prose_samples = (
            "Country Motors S.A. distributes vehicles across the region.",
            "Country Honda announced a victim disclosure update.",
            "A U.S. healthcare technology firm reported the incident.",
            "Descriptive prose containing Country is not a labeled field.",
            "The victim operates from Atlanta, GA and serves regional clients.",
        )
        for prose in prose_samples:
            with self.subTest(prose=prose):
                record = self._extract_record(f"<p>{prose}</p>")
                self.assertEqual(record.country, "")
                self.assertEqual(record.country_code, "")

    def test_split_label_with_city_and_prose_is_rejected(self):
        record = self._extract_record(
            """
            <div class="metadata-row">
                <span>Country</span>
                <span>Atlanta, GA; U.S. healthcare technology firm with recent disclosures.</span>
            </div>
            """
        )

        self.assertEqual(record.country, "")
        self.assertEqual(record.country_code, "")

    def test_unknown_and_missing_country_remain_blank(self):
        unknown = self._extract_record("<p>Country: North Atlantis</p>")
        self.assertEqual(unknown.country, "")
        self.assertEqual(unknown.country_value, "North Atlantis")
        self.assertEqual(unknown.country_name, "")
        self.assertEqual(unknown.country_code, "")

        missing = self._extract_record("")
        self.assertEqual(missing.country, "")
        self.assertEqual(missing.country_value, "")
        self.assertEqual(missing.country_name, "")
        self.assertEqual(missing.country_code, "")

    def test_canonical_country_normalizer_accepts_iso2_iso3_and_names(self):
        cases = {
            "SE": ("Sweden", "SE"),
            "SWE": ("Sweden", "SE"),
            "Sweden": ("Sweden", "SE"),
            "US": ("United States", "US"),
            "USA": ("United States", "US"),
            "United States": ("United States", "US"),
            "GB": ("United Kingdom", "GB"),
            "GBR": ("United Kingdom", "GB"),
            "United Kingdom": ("United Kingdom", "GB"),
            "Slovakia": ("Slovakia", "SK"),
            "Thailand": ("Thailand", "TH"),
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_dark_country(value), expected)


class DarkAdminSecurityTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="dark-root",
            password="dark-root-pass-123",
        )
        self.non_superuser = user_model.objects.create_user(
            username="dark-staff",
            password="dark-staff-pass-123",
            is_staff=True,
        )
        self.source = DarkSource.objects.create(
            name="Dark Source",
            slug="dark-source",
            url="https://example.test/listing",
        )
        self.list_url = reverse("intel_admin:dark_sources")
        self.create_url = reverse("intel_admin:dark_source_create")
        self.edit_url = reverse(
            "intel_admin:dark_source_edit", kwargs={"source_id": self.source.id}
        )
        self.toggle_url = reverse(
            "intel_admin:dark_source_toggle", kwargs={"source_id": self.source.id}
        )
        self.ingest_url = reverse(
            "intel_admin:dark_source_ingest", kwargs={"source_id": self.source.id}
        )
        self.duplicate_url = reverse(
            "intel_admin:dark_source_duplicate", kwargs={"source_id": self.source.id}
        )
        self.test_url = reverse(
            "intel_admin:dark_source_test", kwargs={"source_id": self.source.id}
        )
        self.login_url = reverse("intel_admin:login")

    def test_reverse_names_resolve(self):
        self.assertEqual(self.list_url, "/admin-panel/dark/")
        self.assertEqual(self.create_url, "/admin-panel/dark/new/")
        self.assertEqual(self.edit_url, f"/admin-panel/dark/{self.source.id}/edit/")
        self.assertEqual(self.toggle_url, f"/admin-panel/dark/{self.source.id}/toggle/")
        self.assertEqual(self.ingest_url, f"/admin-panel/dark/{self.source.id}/ingest/")
        self.assertEqual(self.duplicate_url, f"/admin-panel/dark/{self.source.id}/duplicate/")
        self.assertEqual(self.test_url, f"/admin-panel/dark/{self.source.id}/test/")

    def test_unauthenticated_user_redirected_to_admin_login(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)

    def test_non_superuser_blocked_from_dark_admin(self):
        self.client.force_login(self.non_superuser)
        list_response = self.client.get(self.list_url)
        create_response = self.client.get(self.create_url)

        self.assertIn(list_response.status_code, (302, 403))
        self.assertIn(create_response.status_code, (302, 403))


class DarkAdminCrudTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="dark-admin",
            password="dark-admin-pass-123",
        )
        self.source = DarkSource.objects.create(
            name="Alpha Dark",
            slug="alpha-dark",
            homepage="https://alpha.example.com",
            url="https://alpha.example.com/page",
            tags=["onion"],
            watch_keywords="breach, leak",
            watch_regex=r"CVE-\d{4}-\d+",
            source_type=DarkSource.SourceType.SINGLE_PAGE,
            enabled=True,
        )
        self.list_url = reverse("intel_admin:dark_sources")
        self.create_url = reverse("intel_admin:dark_source_create")
        self.edit_url = reverse(
            "intel_admin:dark_source_edit", kwargs={"source_id": self.source.id}
        )
        self.toggle_url = reverse(
            "intel_admin:dark_source_toggle", kwargs={"source_id": self.source.id}
        )
        self.ingest_url = reverse(
            "intel_admin:dark_source_ingest", kwargs={"source_id": self.source.id}
        )
        self.duplicate_url = reverse(
            "intel_admin:dark_source_duplicate", kwargs={"source_id": self.source.id}
        )
        self.test_url = reverse(
            "intel_admin:dark_source_test", kwargs={"source_id": self.source.id}
        )

    def test_superuser_can_view_create_edit_and_toggle_dark_source(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)

        list_response = client.get(self.list_url)
        self.assertEqual(list_response.status_code, 200)
        self.assertContains(list_response, "Dark Admin")

        create_get = client.get(self.create_url)
        self.assertEqual(create_get.status_code, 200)
        token = client.cookies["csrftoken"].value
        create_response = client.post(
            self.create_url,
            {
                "csrfmiddlewaretoken": token,
                "name": "Beta Dark",
                "slug": "beta-dark",
                "homepage": "https://beta.example.com/home",
                "url": "https://beta.example.com/index",
                "source_type": DarkSource.SourceType.INDEX_PAGE,
                "extractor_profile": DarkSource.ExtractorProfile.INCIDENT_CARDS,
                "enabled": "on",
                "tags": "leaks, sweden",
                "watch_keywords": "Breach, Initial Access",
                "watch_regex": r"CVE-\d{4}-\d+",
                "use_tor": "on",
                "timeout_seconds": "12",
                "max_bytes": "650000",
                "fetch_retries": "2",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.list_url)

        created = DarkSource.objects.get(slug="beta-dark")
        self.assertEqual(created.tags, ["leaks", "sweden"])
        self.assertEqual(created.watch_keywords, "breach, initial access")
        self.assertEqual(created.source_type, DarkSource.SourceType.INDEX_PAGE)
        self.assertEqual(
            created.extractor_profile,
            DarkSource.ExtractorProfile.INCIDENT_CARDS,
        )
        self.assertTrue(created.use_tor)
        self.assertEqual(created.timeout_seconds, 12)
        self.assertEqual(created.max_bytes, 650000)
        self.assertEqual(created.fetch_retries, 2)

        edit_get = client.get(self.edit_url)
        self.assertEqual(edit_get.status_code, 200)
        token = client.cookies["csrftoken"].value
        edit_response = client.post(
            self.edit_url,
            {
                "csrfmiddlewaretoken": token,
                "name": "Alpha Dark Updated",
                "slug": "alpha-dark",
                "homepage": "https://alpha.example.com/reports",
                "url": "https://alpha.example.com/reports",
                "source_type": DarkSource.SourceType.FEED,
                "extractor_profile": DarkSource.ExtractorProfile.TABLE_ROWS,
                "tags": "onion, market",
                "watch_keywords": "Leak, Broker",
                "watch_regex": r"ransomware",
                "enabled": "on",
                "timeout_seconds": "9",
                "max_bytes": "720000",
                "fetch_retries": "4",
            },
        )
        self.assertEqual(edit_response.status_code, 302)
        self.assertEqual(edit_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertEqual(self.source.name, "Alpha Dark Updated")
        self.assertEqual(self.source.tags, ["onion", "market"])
        self.assertEqual(self.source.watch_keywords, "leak, broker")
        self.assertEqual(self.source.source_type, DarkSource.SourceType.FEED)
        self.assertEqual(
            self.source.extractor_profile,
            DarkSource.ExtractorProfile.TABLE_ROWS,
        )
        self.assertEqual(self.source.timeout_seconds, 9)
        self.assertEqual(self.source.max_bytes, 720000)
        self.assertEqual(self.source.fetch_retries, 4)

        toggle_get = client.get(self.toggle_url)
        self.assertEqual(toggle_get.status_code, 405)

        token = client.cookies["csrftoken"].value
        toggle_response = client.post(
            self.toggle_url,
            {
                "csrfmiddlewaretoken": token,
                "next": "https://evil.example/redirect",
            },
        )
        self.assertEqual(toggle_response.status_code, 302)
        self.assertEqual(toggle_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertFalse(self.source.enabled)

        self.source.enabled = True
        self.source.save(update_fields=["enabled", "updated_at"])
        token = client.cookies["csrftoken"].value
        with patch("intel.views.launch_ops_job_subprocess") as mocked_launch:
            ingest_response = client.post(
                self.ingest_url,
                {
                    "csrfmiddlewaretoken": token,
                    "next": self.list_url,
                },
            )
        self.assertEqual(ingest_response.status_code, 302)
        self.assertEqual(ingest_response.url, self.list_url)
        self.assertEqual(OpsJob.objects.filter(command_name="ingest_dark").count(), 1)
        job = OpsJob.objects.get(command_name="ingest_dark")
        self.assertEqual(job.command_args, ["--source", self.source.slug])
        mocked_launch.assert_called_once_with(job.id)

        token = client.cookies["csrftoken"].value
        duplicate_response = client.post(
            self.duplicate_url,
            {
                "csrfmiddlewaretoken": token,
            },
        )
        self.assertEqual(duplicate_response.status_code, 302)
        duplicated = DarkSource.objects.filter(slug__contains="copy").latest("id")
        self.assertFalse(duplicated.enabled)
        self.assertIn("copy", duplicated.slug)
        self.assertEqual(duplicated.extractor_profile, self.source.extractor_profile)

        token = client.cookies["csrftoken"].value
        with patch("intel.views._build_dark_source_preview") as mocked_preview:
            mocked_preview.return_value = {
                "source_name": self.source.name,
                "source_id": self.source.id,
                "http_status": 200,
                "final_url": self.source.url,
                "title": "Preview title",
                "excerpt": "Preview excerpt",
                "link_count": 1,
                "bytes_received": 123,
            }
            test_response = client.post(
                self.test_url,
                {
                    "csrfmiddlewaretoken": token,
                    "next": self.list_url,
                },
            )
        self.assertEqual(test_response.status_code, 302)
        self.assertEqual(test_response.url, self.list_url)
        preview = client.session.get("dark_source_test_preview")
        self.assertIsNotNone(preview)
        self.assertEqual(preview["title"], "Preview title")

    def test_csrf_enforced_for_dark_source_toggle(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        response = client.post(self.toggle_url, {"next": self.list_url})
        self.assertEqual(response.status_code, 403)

    def test_post_only_enforced_for_dark_quick_actions(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        self.assertEqual(client.get(self.ingest_url).status_code, 405)
        self.assertEqual(client.get(self.duplicate_url).status_code, 405)
        self.assertEqual(client.get(self.test_url).status_code, 405)

    def test_csrf_enforced_for_dark_quick_actions(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        self.assertEqual(client.post(self.ingest_url, {"next": self.list_url}).status_code, 403)
        self.assertEqual(client.post(self.duplicate_url, {}).status_code, 403)
        self.assertEqual(client.post(self.test_url, {"next": self.list_url}).status_code, 403)

    def test_dark_source_test_shows_failure_reason(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        client.get(self.list_url)
        token = client.cookies["csrftoken"].value
        with patch(
            "intel.views._build_dark_source_preview",
            side_effect=TimeoutError("timed out while connecting"),
        ):
            response = client.post(
                self.test_url,
                {"csrfmiddlewaretoken": token, "next": self.list_url},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Source Failed")
        self.assertContains(response, "Timeout while fetching source.")

    def test_dark_source_list_shows_standard_feed_suitability_warning(self):
        DarkSource.objects.create(
            name="News Site",
            slug="news-site",
            url="https://news.example.com/security/advisories",
            source_type=DarkSource.SourceType.INDEX_PAGE,
        )
        self.client.force_login(self.superuser)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Prefer standard intel feeds")


class DarkIngestionTests(TestCase):
    def setUp(self):
        self.source = DarkSource.objects.create(
            name="Gamma Dark",
            slug="gamma-dark",
            url="https://gamma.example.com/page",
            source_type=DarkSource.SourceType.SINGLE_PAGE,
            watch_keywords="breach, market",
        )

    def _ingest_markup(self, markup: str):
        response = DummyResponse([markup.encode("utf-8")], url=self.source.url)
        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

    @override_settings(DARK_MAX_BYTES=10, DARK_FETCH_RETRIES=1)
    def test_ingestion_respects_dark_max_bytes_and_records_error_run(self):
        response = DummyResponse([b"12345678", b"12345678"], url=self.source.url)

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ) as mocked_get:
            output = StringIO()
            call_command("ingest_dark", stdout=output, stderr=output)

        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertFalse(run.ok)
        self.assertIn("max_bytes=10", run.error)
        self.assertEqual(DarkHit.objects.count(), 0)
        self.assertNotIn("proxies", mocked_get.call_args.kwargs)

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_single_page_keyword_matching_creates_document_and_deduped_hit(self):
        html = (
            "<html><title>Breach market update</title>"
            "<body>New breach listing posted on the market today.</body></html>"
        )

        self._ingest_markup(html)
        self._ingest_markup(html)

        self.assertEqual(DarkFetchRun.objects.filter(dark_source=self.source).count(), 2)
        self.assertEqual(DarkDocument.objects.filter(dark_source=self.source).count(), 1)
        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 1)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertEqual(hit.title, "Breach market update")
        self.assertEqual(hit.matched_keywords, ["breach", "market"])

    @override_settings(DARK_FETCH_RETRIES=1, DARK_INDEX_MAX_LINKS=5)
    def test_index_page_discovers_internal_links_only(self):
        self.source.source_type = DarkSource.SourceType.INDEX_PAGE
        self.source.url = "https://gamma.example.com/index"
        self.source.watch_keywords = "ransomware"
        self.source.save(update_fields=["source_type", "url", "watch_keywords", "updated_at"])

        root_html = (
            '<html><body>'
            '<a href="/post-1">Post 1</a>'
            '<a href="https://gamma.example.com/post-2">Post 2</a>'
            '<a href="https://other.example.com/ignore">External</a>'
            "</body></html>"
        ).encode("utf-8")
        post_html = (
            "<html><title>Ransomware bulletin</title>"
            "<body>Ransomware operators active.</body></html>"
        ).encode("utf-8")

        def fake_get(url, **kwargs):
            if url == "https://gamma.example.com/index":
                return DummyResponse([root_html], url=url)
            if "post-" in url:
                return DummyResponse([post_html], url=url)
            return DummyResponse([b"<html></html>"], url=url)

        with patch("intel.management.commands.ingest_dark.requests.get", side_effect=fake_get):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertEqual(run.documents_discovered, 3)  # index + 2 internal links
        self.assertEqual(DarkDocument.objects.filter(dark_source=self.source).count(), 3)
        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 2)

    @override_settings(DARK_FETCH_RETRIES=1, DARK_TOR_SOCKS_URL="socks5h://tor:9050")
    def test_onion_proxy_selection(self):
        self.source.url = "http://examplehiddenservice.onion/list"
        self.source.save(update_fields=["url", "updated_at"])
        response = DummyResponse([b"<html><title>No hit</title></html>"], url=self.source.url)

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ) as mocked_get:
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        self.assertEqual(
            mocked_get.call_args.kwargs["proxies"],
            {
                "http": settings.DARK_TOR_SOCKS_URL,
                "https": settings.DARK_TOR_SOCKS_URL,
            },
        )

    def test_extract_links_same_host_only(self):
        markup = (
            '<a href="/a">A</a>'
            '<a href="https://gamma.example.com/b">B</a>'
            '<a href="https://other.example.com/c">C</a>'
        )
        links = extract_links(markup, base_url="https://gamma.example.com/index", max_links=10)
        self.assertEqual(
            links,
            ["https://gamma.example.com/a", "https://gamma.example.com/b"],
        )

    def test_extract_links_skips_malformed_bracket_urls_and_keeps_valid_sibling(self):
        for malformed_url in ("http://[", "http://]"):
            with self.subTest(malformed_url=malformed_url):
                markup = (
                    f'<a href="{malformed_url}">Malformed</a>'
                    '<a href="/valid-report">Valid</a>'
                    '<a href="https://other.example.com/external">External</a>'
                )

                links = extract_links(
                    markup,
                    base_url="https://gamma.example.com/index",
                    max_links=10,
                )

                self.assertEqual(links, ["https://gamma.example.com/valid-report"])

    def test_extract_links_rejects_malformed_base_url(self):
        for malformed_url in ("http://[", "http://]"):
            with self.subTest(malformed_url=malformed_url):
                self.assertEqual(
                    extract_links(
                        '<a href="/valid-report">Valid</a>',
                        base_url=malformed_url,
                        max_links=10,
                    ),
                    [],
                )

    def test_absolute_http_url_rejects_malformed_bracket_authorities(self):
        for malformed_url in ("http://[", "http://]"):
            with self.subTest(malformed_url=malformed_url):
                self.assertEqual(
                    _absolute_http_url(
                        malformed_url,
                        base_url="https://gamma.example.com/page",
                    ),
                    "",
                )

    def test_fragment_url_skips_malformed_candidate_and_uses_valid_sibling(self):
        for malformed_url in ("http://[", "http://]"):
            with self.subTest(malformed_url=malformed_url):
                fragment = (
                    f'<a href="{malformed_url}">Malformed record link</a>'
                    '<a href="/incidents/valid">Valid record link</a>'
                )

                self.assertEqual(
                    _fragment_url(fragment, "https://gamma.example.com/page"),
                    "https://gamma.example.com/incidents/valid",
                )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_incident_cards_survive_malformed_website_and_record_single_page_telemetry(self):
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(update_fields=["extractor_profile", "updated_at"])
        markup = """
        <html><title>Live Updates</title><body>
            <article class="incident-card">
                <h3>Malformed Link Corp</h3>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Industry: Manufacturing</p>
                <a href="/incidents/broken-website">Incident details</a>
                <p>Website: http://[</p>
                <p>Victim disclosure posted with extortion details and a response timeline.</p>
            </article>
            <article class="incident-card">
                <h3>Valid Sibling Corp</h3>
                <p>Threat Group: Play</p>
                <p>Country: Norway</p>
                <p>Industry: Retail</p>
                <a href="/incidents/valid-sibling">Incident details</a>
                <p>Website: https://valid-sibling.example</p>
                <p>Victim disclosure posted with extortion details and a response timeline.</p>
            </article>
        </body></html>
        """
        payload = markup.encode("utf-8")
        final_url = "https://gamma.example.com/final-live-updates"
        response = DummyResponse([payload], status_code=206, url=final_url)

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        run = DarkFetchRun.objects.get(dark_source=self.source)
        hits = {
            hit.title: hit for hit in DarkHit.objects.filter(dark_source=self.source)
        }
        self.assertTrue(run.ok)
        self.assertEqual(run.http_status, 206)
        self.assertEqual(run.final_url, final_url)
        self.assertEqual(run.bytes_received, len(payload))
        self.assertEqual(run.documents_fetched, 1)
        self.assertEqual(set(hits), {"Malformed Link Corp", "Valid Sibling Corp"})
        self.assertEqual(hits["Malformed Link Corp"].website_url, "")
        self.assertEqual(
            hits["Malformed Link Corp"].url,
            "https://gamma.example.com/incidents/broken-website",
        )
        self.assertEqual(
            hits["Valid Sibling Corp"].website_url,
            "https://valid-sibling.example",
        )

    def test_table_rows_survive_malformed_website_and_keep_valid_sibling(self):
        markup = """
        <table>
            <thead><tr><th>Group</th><th>Website</th><th>Notes</th></tr></thead>
            <tbody>
                <tr><td>Akira</td><td>http://]</td><td>Recent victim disclosures</td></tr>
                <tr><td>Play</td><td>https://play.example</td><td>Current extortion activity</td></tr>
            </tbody>
        </table>
        """

        records = extract_profile_records(
            markup,
            profile="table_rows",
            base_url="https://gamma.example.com/page",
        )

        records_by_title = {record.title: record for record in records}
        self.assertEqual(set(records_by_title), {"Akira", "Play"})
        self.assertEqual(records_by_title["Akira"].website_url, "")
        self.assertEqual(records_by_title["Play"].website_url, "https://play.example")

    @override_settings(DARK_FETCH_RETRIES=1, DARK_INDEX_MAX_LINKS=5)
    def test_index_discovery_skips_malformed_links_and_fetches_valid_sibling(self):
        self.source.source_type = DarkSource.SourceType.INDEX_PAGE
        self.source.url = "https://gamma.example.com/index"
        self.source.save(update_fields=["source_type", "url", "updated_at"])
        root_html = (
            '<a href="http://[">Malformed opening bracket</a>'
            '<a href="http://]">Malformed closing bracket</a>'
            '<a href="/valid-report">Valid report</a>'
        ).encode("utf-8")
        requested_urls = []

        def fake_get(url, **kwargs):
            del kwargs
            requested_urls.append(url)
            if url == self.source.url:
                return DummyResponse([root_html], url=url)
            if url == "https://gamma.example.com/valid-report":
                return DummyResponse(
                    [b"<html><title>Valid report</title><body>Current report details.</body></html>"],
                    url=url,
                )
            raise AssertionError(f"Unexpected URL fetched: {url}")

        with patch("intel.management.commands.ingest_dark.requests.get", side_effect=fake_get):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertTrue(run.ok)
        self.assertEqual(run.documents_discovered, 2)
        self.assertEqual(run.documents_fetched, 2)
        self.assertEqual(
            requested_urls,
            [self.source.url, self.source.url, "https://gamma.example.com/valid-report"],
        )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_INDEX_MAX_LINKS=5)
    def test_feed_discovery_skips_malformed_links_and_fetches_valid_sibling(self):
        self.source.source_type = DarkSource.SourceType.FEED
        self.source.url = "https://gamma.example.com/feed.xml"
        self.source.save(update_fields=["source_type", "url", "updated_at"])
        feed_markup = b"""
        <rss version="2.0"><channel><title>Gamma feed</title>
            <item><title>Malformed open</title><link>http://[</link></item>
            <item><title>Malformed close</title><link>http://]</link></item>
            <item><title>Valid report</title><link>https://gamma.example.com/valid-report</link></item>
            <item><title>External report</title><link>https://other.example.com/report</link></item>
        </channel></rss>
        """
        requested_urls = []

        def fake_get(url, **kwargs):
            del kwargs
            requested_urls.append(url)
            if url == self.source.url:
                return DummyResponse([feed_markup], url=url)
            if url == "https://gamma.example.com/valid-report":
                return DummyResponse(
                    [b"<html><title>Valid report</title><body>Current report details.</body></html>"],
                    url=url,
                )
            raise AssertionError(f"Unexpected URL fetched: {url}")

        with patch("intel.management.commands.ingest_dark.requests.get", side_effect=fake_get):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertTrue(run.ok)
        self.assertEqual(run.documents_discovered, 1)
        self.assertEqual(run.documents_fetched, 1)
        self.assertEqual(
            requested_urls,
            [self.source.url, "https://gamma.example.com/valid-report"],
        )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_INDEX_MAX_LINKS=5)
    def test_feed_discovery_returns_no_links_for_malformed_source_host(self):
        self.source.source_type = DarkSource.SourceType.FEED
        self.source.url = "http://["
        self.source.save(update_fields=["source_type", "url", "updated_at"])
        feed_markup = b"""
        <rss version="2.0"><channel><title>Gamma feed</title>
            <item><title>Report</title><link>https://other.example.com/report</link></item>
        </channel></rss>
        """
        response = DummyResponse([feed_markup], url=self.source.url)

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ) as mocked_get:
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertTrue(run.ok)
        self.assertEqual(run.documents_discovered, 0)
        self.assertEqual(run.documents_fetched, 0)
        self.assertEqual(run.bytes_received, len(feed_markup))
        mocked_get.assert_called_once()

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_extraction_removes_style_and_boilerplate_noise(self):
        self.source.watch_keywords = "breach"
        self.source.save(update_fields=["watch_keywords", "updated_at"])
        noisy_html = (
            "<html><head><style>.menu{display:none} body{font-family:sans-serif;}</style>"
            "<script>var x = 'noise';</script></head>"
            "<body><nav>Home Privacy Policy Subscribe</nav>"
            "<article><h1>Breach bulletin</h1>"
            "<p>Breach details for operators were published with indicators and timeline.</p>"
            "<p>Analysts confirmed the disclosure and scoped affected systems.</p>"
            "</article></body></html>"
        )

        self._ingest_markup(noisy_html)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertIn("Breach details for operators", hit.excerpt)
        self.assertNotIn("font-family", hit.excerpt.lower())
        self.assertNotIn("privacy policy", hit.excerpt.lower())

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_incident_cards_store_unmatched_records_and_aggregate_watch_matches(self):
        self.source.watch_keywords = "alphacorp, breach, negotiation, leak"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Live Updates</title><body>
            <section class="hero">Landing page for monitoring updates and general notices.</section>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Threat Group:   Akira   </p>
                <p>Country: Sweden</p>
                <p>Industry: Manufacturing</p>
                <p>Company Website: <a href="https://alphacorp.example">alphacorp.example</a></p>
                <p>Last Activity: 2026-03-20</p>
                <p>Breach negotiation leak posted with fresh victim details.</p>
                <a href="/live/alphacorp">Alpha entry</a>
            </div>
            <div class="incident-card">
                <h2>Beta Retail</h2>
                <p>Threat Group: Play</p>
                <p>Country: Norway</p>
                <p>Industry: Retail</p>
                <p>Website: https://beta.example</p>
                <p>Disclosure page updated for operator review.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = {
            hit.title: hit for hit in DarkHit.objects.filter(dark_source=self.source)
        }
        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertEqual(run.hits_new, 2)
        self.assertEqual(set(hits), {"AlphaCorp", "Beta Retail"})

        hit = hits["AlphaCorp"]
        self.assertTrue(hit.is_watch_match)
        self.assertEqual(
            hit.matched_keywords,
            ["alphacorp", "breach", "negotiation", "leak"],
        )
        self.assertEqual(hit.record_type, "incident")
        self.assertEqual(hit.group_name, "Akira")
        self.assertEqual(hit.victim_name, "AlphaCorp")
        self.assertEqual(hit.country, "Sweden")
        self.assertEqual(hit.industry, "Manufacturing")
        self.assertEqual(hit.website_url, "https://alphacorp.example")
        self.assertEqual(hit.last_activity_text, "2026-03-20")
        self.assertEqual(hit.url, "https://gamma.example.com/live/alphacorp")
        self.assertNotIn("landing page", hit.raw.lower())

        unmatched_hit = hits["Beta Retail"]
        self.assertFalse(unmatched_hit.is_watch_match)
        self.assertEqual(unmatched_hit.matched_keywords, [])
        self.assertEqual(unmatched_hit.matched_regex, [])
        self.assertEqual(unmatched_hit.record_type, "incident")
        self.assertEqual(unmatched_hit.group_name, "Play")
        self.assertEqual(unmatched_hit.country, "Norway")
        self.assertEqual(unmatched_hit.industry, "Retail")
        self.assertEqual(unmatched_hit.website_url, "https://beta.example")

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
        NOTIFICATIONS_ENABLED=True,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token",
    )
    def test_watch_matched_incident_records_still_send_discord_alerts(self):
        self.source.watch_keywords = "alphacorp"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """

        with patch("intel.notifications.requests.post") as mock_post:
            self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source, title="AlphaCorp")
        self.assertTrue(hit.is_watch_match)
        mock_post.assert_called_once()

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
        NOTIFICATIONS_ENABLED=True,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token",
    )
    def test_same_live_updates_record_does_not_realert_on_unchanged_reingest(self):
        self.source.watch_keywords = "alphacorp"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        first_markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>17 minutes ago</p>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """
        second_markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>1 hour ago</p>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """

        with patch("intel.notifications.requests.post") as mock_post:
            self._ingest_markup(first_markup)
            self._ingest_markup(second_markup)

        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 1)
        latest_run = DarkFetchRun.objects.filter(dark_source=self.source).latest("id")
        self.assertEqual(latest_run.hits_new, 0)
        self.assertEqual(latest_run.hits_updated, 1)
        mock_post.assert_called_once()

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
        NOTIFICATIONS_ENABLED=True,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token",
    )
    def test_equivalent_new_dark_hit_row_is_suppressed_by_alert_identity(self):
        self.source.watch_keywords = "alphacorp"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        previous_document = DarkDocument.objects.create(
            dark_source=self.source,
            url="https://gamma.example.com/older-page",
            canonical_url="https://gamma.example.com/older-page",
            title="Old listing",
            excerpt="AlphaCorp listing",
            content_hash="doc-hash-old",
        )
        previous_hit = DarkHit.objects.create(
            dark_source=self.source,
            dark_document=previous_document,
            title="AlphaCorp",
            excerpt="Threat Group: Akira Country: Sweden Victim disclosure updated.",
            url=self.source.url,
            content_hash="old-hit-hash",
            matched_keywords=["alphacorp"],
            matched_regex=[],
            is_watch_match=True,
            record_type="incident",
            victim_name="AlphaCorp",
            group_name="Akira",
            country="Sweden",
        )
        previous_hit.alert_identity_hash = build_dark_hit_alert_identity(
            source_id=self.source.id,
            record_type="incident",
            title="AlphaCorp",
            victim_name="AlphaCorp",
            group_name="Akira",
            url=self.source.url,
        )
        previous_hit.last_alert_fingerprint = build_dark_hit_alert_fingerprint(
            record_type="incident",
            title="AlphaCorp",
            excerpt="Threat Group: Akira Country: Sweden Victim disclosure updated.",
            victim_name="AlphaCorp",
            group_name="Akira",
            country="Sweden",
            url=self.source.url,
            matched_keywords=["alphacorp"],
            matched_regex=[],
        )
        previous_hit.last_alerted_at = timezone.now()
        previous_hit.save(
            update_fields=[
                "alert_identity_hash",
                "last_alert_fingerprint",
                "last_alerted_at",
            ]
        )

        markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """

        with patch("intel.notifications.requests.post") as mock_post:
            self._ingest_markup(markup)

        latest_hit = DarkHit.objects.filter(dark_source=self.source).latest("id")
        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 2)
        self.assertEqual(latest_hit.title, "AlphaCorp")
        self.assertEqual(latest_hit.last_alerted_at, previous_hit.last_alerted_at)
        self.assertEqual(latest_hit.last_alert_fingerprint, previous_hit.last_alert_fingerprint)
        mock_post.assert_not_called()

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_structured_matching_ignores_page_level_keyword_bleed(self):
        self.source.watch_keywords = "breach"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Live Updates</title><body>
            <section class="hero">
                Breach command center feed with breach coverage and breach statistics.
            </section>
            <div class="incident-card">
                <h2>Beta Retail</h2>
                <p>Threat Group: Play</p>
                <p>Country: Norway</p>
                <p>Industry: Retail</p>
                <p>Disclosure page updated for operator review.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source, title="Beta Retail")
        self.assertFalse(hit.is_watch_match)
        self.assertEqual(hit.matched_keywords, [])
        self.assertEqual(hit.matched_regex, [])

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
        NOTIFICATIONS_ENABLED=True,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token",
    )
    def test_changed_watch_matched_record_still_alerts_when_meaningful_fields_change(self):
        self.source.watch_keywords = "alphacorp"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        first_markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """
        second_markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Website: https://alphacorp.example</p>
                <p>Victim disclosure updated.</p>
            </div>
        </body></html>
        """

        with patch("intel.notifications.requests.post") as mock_post:
            self._ingest_markup(first_markup)
            self._ingest_markup(second_markup)

        hit = DarkHit.objects.get(dark_source=self.source, title="AlphaCorp")
        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 1)
        self.assertEqual(hit.website_url, "https://alphacorp.example")
        self.assertEqual(mock_post.call_count, 2)
        second_payload = mock_post.call_args.kwargs["json"]
        self.assertIn(
            {"name": "Why alerted", "value": "website changed", "inline": True},
            second_payload["embeds"][0]["fields"],
        )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_ransomdb_live_updates_cards_extract_normalized_incidents_only(self):
        self.source.watch_keywords = "living in green, fruktimporten"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Ransom-DB | Live Threat Command Center</title><body>
            <main class="space-y-6">
            <section class="rounded-xl border border-zinc-800 bg-zinc-950/70 p-6">
                <h1>Live Updates</h1>
                <p>Free Real-time feed of ransomware incidents with detailed victim information and threat group attribution.</p>
                <p>Showing last 10 results. Upgrade for more results.</p>
            </section>
            <section class="rounded-xl border border-amber-500/20 bg-amber-500/5 p-5">
                <h3>Registration Required</h3>
                <p>Sign in to unlock the full feed, search, and export tools.</p>
            </section>
            <div class="grid gap-4 md:grid-cols-2">
                <article class="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 shadow-sm">
                    <img src="/static/flags/cz.png" alt="CZ" />
                    <h3>Living in green, s. r. o.</h3>
                    <p>Mar 26, 2026</p>
                    <p>17 minutes ago</p>
                    <p>Threat Group: Qilin</p>
                    <p>Country: Czech Republic</p>
                    <p>Industry: Home Improvement &amp; Hardware Retail</p>
                    <p>Living in green, s. r. o. is a Czech company. Website: https://www.livingingreen.cz/</p>
                </article>
                <article class="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 shadow-sm">
                    <img src="/static/flags/se.png" alt="SE" />
                    <h3>Fruktimporten Stockholm</h3>
                    <p>Mar 26, 2026</p>
                    <p>1 hour ago</p>
                    <p>Threat Group: The_Gentelman</p>
                    <p>Country: Sverige</p>
                    <p>Industry: Wholesale of fruit and vegetables</p>
                    <p>Nordic produce distributor facing extortion pressure. Official website: https://www.fruktimporten.se/</p>
                </article>
            </div>
            <section class="rounded-xl border border-zinc-800 bg-zinc-950/60 p-5">
                <h3>Quick Links</h3>
                <p>Threat Groups</p>
                <p>API Access</p>
                <p>Blog</p>
            </section>
            </main>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source).order_by("title"))
        self.assertEqual(len(hits), 2)
        self.assertEqual(
            [hit.title for hit in hits],
            ["Fruktimporten Stockholm", "Living in green, s. r. o."],
        )

        stockholm = hits[0]
        self.assertEqual(stockholm.record_type, "incident")
        self.assertEqual(stockholm.victim_name, "Fruktimporten Stockholm")
        self.assertEqual(stockholm.group_name, "The_Gentelman")
        self.assertEqual(stockholm.country, "Sweden")
        self.assertEqual(
            normalize_dark_country(stockholm.country),
            ("Sweden", "SE"),
        )
        self.assertEqual(stockholm.industry, "Wholesale of fruit and vegetables")
        self.assertEqual(stockholm.website_url, "https://www.fruktimporten.se/")
        self.assertEqual(stockholm.url, self.source.url)

        living = hits[1]
        self.assertEqual(living.record_type, "incident")
        self.assertEqual(living.victim_name, "Living in green, s. r. o.")
        self.assertEqual(living.group_name, "Qilin")
        self.assertEqual(living.country, "Czechia")
        self.assertEqual(
            normalize_dark_country(living.country),
            ("Czechia", "CZ"),
        )
        self.assertEqual(living.industry, "Home Improvement & Hardware Retail")
        self.assertEqual(living.website_url, "https://www.livingingreen.cz/")

        raw_text = "\n".join(hit.raw.lower() for hit in hits)
        self.assertNotIn("live threat command center", raw_text)
        self.assertNotIn("registration required", raw_text)
        self.assertNotIn("showing 10 of", raw_text)
        self.assertNotIn("quick links", raw_text)

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_ransomdb_live_updates_rejects_weak_incident_cards_without_structured_fields(self):
        self.source.watch_keywords = "alphacorp"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Ransom-DB | Live Threat Command Center</title><body>
            <div class="incident-card">
                <h3>AlphaCorp</h3>
                <p>Threat Group: Akira</p>
                <p>Country: Sweden</p>
                <p>Industry: Manufacturing</p>
                <p>Website: https://alphacorp.example</p>
                <p>Victim page updated with extortion details.</p>
            </div>
            <div class="incident-card">
                <h3>Beta Retail</h3>
                <p>Brief note for analysts.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].title, "AlphaCorp")
        self.assertEqual(hits[0].group_name, "Akira")
        self.assertEqual(hits[0].country, "Sweden")
        self.assertEqual(hits[0].industry, "Manufacturing")
        self.assertEqual(hits[0].website_url, "https://alphacorp.example")

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_fragment_only_card_blocks_are_ignored(self):
        self.source.watch_keywords = "alphacorp, sweden, manufacturing, breach"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Victim Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <div class="country-card">Sweden</div>
                <div class="industry-card">Manufacturing</div>
                <p>Breach disclosure posted with negotiation notes and response timeline.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].title, "AlphaCorp")
        self.assertEqual(
            hits[0].matched_keywords,
            ["alphacorp", "sweden", "manufacturing", "breach"],
        )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_structured_record_without_link_falls_back_to_source_page_url(self):
        self.source.watch_keywords = "alphacorp, breach"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Live Updates</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <p>Group: Akira</p>
                <p>Company Website: <a href="https://alphacorp.example">alphacorp.example</a></p>
                <p>Breach post with operator note.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertEqual(hit.url, self.source.url)
        self.assertEqual(hit.website_url, "https://alphacorp.example")

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_group_cards_extract_normalized_fields(self):
        self.source.watch_keywords = "black basta"
        self.source.extractor_profile = DarkSource.ExtractorProfile.GROUP_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Threat Groups</title><body>
            <div class="intro">Trusted-source overview page.</div>
            <article class="group-card">
                <h2>Black Basta</h2>
                <p>Victims: 41</p>
                <p>Last Activity: 2026-03-22</p>
                <p>Windows-focused extortion operations with recent disclosures.</p>
            </article>
            <article class="group-card">
                <h2>Akira</h2>
                <p>Linux and VMware targeting noted this week.</p>
            </article>
        </body></html>
        """

        self._ingest_markup(markup)

        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 2)

        hit = DarkHit.objects.get(dark_source=self.source, title="Black Basta")
        self.assertEqual(hit.title, "Black Basta")
        self.assertTrue(hit.is_watch_match)
        self.assertEqual(hit.matched_keywords, ["black basta"])
        self.assertEqual(hit.record_type, "group")
        self.assertEqual(hit.group_name, "Black Basta")
        self.assertEqual(hit.victim_count, 41)
        self.assertEqual(hit.last_activity_text, "2026-03-22")
        self.assertIn("extortion operations", hit.excerpt)
        self.assertEqual(hit.url, self.source.url)

        akira = DarkHit.objects.get(dark_source=self.source, title="Akira")
        self.assertFalse(akira.is_watch_match)
        self.assertEqual(akira.matched_keywords, [])

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
    )
    def test_ransomdb_threat_groups_reject_timeline_and_loading_fragments(self):
        self.source.watch_keywords = "akira, dragonforce"
        self.source.extractor_profile = DarkSource.ExtractorProfile.GROUP_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Threat Groups</title><body>
            <article class="group-card">
                <h2>Loading...</h2>
                <p>Please wait while profile data loads.</p>
                <p>Recent disclosure placeholders remain visible.</p>
            </article>
            <article class="group-card">
                <h2>Recent Activity Timeline</h2>
                <p>Last Activity: 2026-03-22</p>
                <p>Timeline of recent disclosures and extortion updates.</p>
            </article>
            <article class="group-card">
                <h2>Last Activity: 2026-03-21</h2>
                <p>Victims: 12</p>
                <p>Metadata panel for sorting cards.</p>
            </article>
            <article class="group-card">
                <h2>Victim Count</h2>
                <p>41</p>
                <p>Sorting helper card for the timeline panel.</p>
            </article>
            <article class="group-card">
                <h2>Country: Sweden</h2>
                <p>Regional metadata label used by the activity timeline.</p>
            </article>
            <article class="group-card">
                <h2>Akira</h2>
                <p>Victims: 41</p>
                <p>Last Activity: 2026-03-22</p>
                <p>Recent extortion disclosures across manufacturing and retail.</p>
            </article>
            <article class="group-card">
                <h2>DragonForce</h2>
                <p>Victims: 12</p>
                <p>Last Activity: 2026-03-20</p>
                <p>Leak site posts and pressure tactics continue.</p>
            </article>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source).order_by("title"))
        self.assertEqual([hit.title for hit in hits], ["Akira", "DragonForce"])
        self.assertEqual(hits[0].group_name, "Akira")
        self.assertEqual(hits[1].group_name, "DragonForce")

    @override_settings(
        DARK_FETCH_RETRIES=1,
        DARK_MAX_BYTES=5000,
        NOTIFICATIONS_ENABLED=True,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token",
    )
    def test_group_cards_are_stored_without_sending_discord_alert(self):
        self.source.watch_keywords = "black basta"
        self.source.extractor_profile = DarkSource.ExtractorProfile.GROUP_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Threat Groups</title><body>
            <article class="group-card">
                <h2>Black Basta</h2>
                <p>Victims: 41</p>
                <p>Recent disclosures from this actor.</p>
            </article>
        </body></html>
        """

        with patch("intel.notifications.requests.post") as mock_post:
            self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertEqual(hit.record_type, "group")
        self.assertEqual(hit.group_name, "Black Basta")
        self.assertTrue(hit.is_watch_match)
        mock_post.assert_not_called()

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_partial_duplicate_card_records_are_pruned_in_favor_of_fuller_record(self):
        self.source.watch_keywords = "alphacorp, leak, timeline"
        self.source.extractor_profile = DarkSource.ExtractorProfile.INCIDENT_CARDS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Incident Stream</title><body>
            <div class="incident-card">
                <h2>AlphaCorp</h2>
                <div class="incident-item">
                    <h3>AlphaCorp</h3>
                    <p>Leak posted.</p>
                </div>
                <p>Leak posted with negotiation transcript and timeline for the response activity.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].title, "AlphaCorp")
        self.assertIn("timeline", hits[0].excerpt.lower())

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_table_rows_extract_multiple_structured_hits_from_one_page(self):
        self.source.watch_keywords = "akira, play"
        self.source.extractor_profile = DarkSource.ExtractorProfile.TABLE_ROWS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Group Summary</title><body>
            <section class="hero">Landing page with totals and charts.</section>
            <table>
                <thead><tr><th>Group</th><th>Victims</th><th>Country</th><th>Last Activity</th><th>Notes</th></tr></thead>
                <tbody>
                    <tr>
                        <td><a href="/groups/akira">Akira</a></td>
                        <td>41</td>
                        <td>Sweden</td>
                        <td>2026-03-24</td>
                        <td>Double extortion activity</td>
                    </tr>
                    <tr>
                        <td><a href="/groups/play">Play</a></td>
                        <td>18</td>
                        <td>Denmark</td>
                        <td>2026-03-23</td>
                        <td>Recent surge in disclosures</td>
                    </tr>
                </tbody>
            </table>
        </body></html>
        """

        self._ingest_markup(markup)

        run = DarkFetchRun.objects.get(dark_source=self.source)
        hits = list(DarkHit.objects.filter(dark_source=self.source).order_by("title"))
        self.assertEqual(DarkDocument.objects.filter(dark_source=self.source).count(), 1)
        self.assertEqual(run.hits_new, 2)
        self.assertEqual(len(hits), 2)
        self.assertEqual([hit.title for hit in hits], ["Akira", "Play"])
        self.assertEqual(hits[0].url, "https://gamma.example.com/groups/akira")
        self.assertEqual(hits[0].record_type, "group")
        self.assertEqual(hits[0].group_name, "Akira")
        self.assertEqual(hits[0].victim_count, 41)
        self.assertEqual(hits[0].country, "Sweden")
        self.assertEqual(hits[0].last_activity_text, "2026-03-24")

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_table_rows_with_name_header_populate_group_name_for_grouped_dashboard(self):
        self.source.watch_keywords = "akira"
        self.source.extractor_profile = DarkSource.ExtractorProfile.TABLE_ROWS
        self.source.save(
            update_fields=["watch_keywords", "extractor_profile", "updated_at"]
        )
        markup = """
        <html><title>Group Summary</title><body>
            <table>
                <thead><tr><th>Name</th><th>Victims</th><th>Country</th><th>Notes</th></tr></thead>
                <tbody>
                    <tr>
                        <td>Akira</td>
                        <td>41</td>
                        <td>Sweden</td>
                        <td>Recent disclosures</td>
                    </tr>
                    <tr>
                        <td>Play</td>
                        <td>18</td>
                        <td>Denmark</td>
                        <td>Older disclosures</td>
                    </tr>
                </tbody>
            </table>
        </body></html>
        """

        self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source, title="Akira")
        self.assertEqual(hit.group_name, "Akira")
        self.assertEqual(hit.record_type, "group")
