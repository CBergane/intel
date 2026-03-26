from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from intel.dark_utils import extract_links
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
    def test_incident_card_with_multiple_keyword_matches_creates_one_hit(self):
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
                <p>Breach negotiation leak posted with fresh victim details.</p>
                <a href="/live/alphacorp">Alpha entry</a>
            </div>
            <div class="incident-card">
                <h2>Beta Retail</h2>
                <p>Discussion thread without watched terms.</p>
            </div>
        </body></html>
        """

        self._ingest_markup(markup)

        hits = list(DarkHit.objects.filter(dark_source=self.source))
        run = DarkFetchRun.objects.get(dark_source=self.source)
        self.assertEqual(run.hits_new, 1)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit.title, "AlphaCorp")
        self.assertEqual(
            hit.matched_keywords,
            ["alphacorp", "breach", "negotiation", "leak"],
        )
        self.assertEqual(hit.url, "https://gamma.example.com/live/alphacorp")
        self.assertNotIn("landing page", hit.raw.lower())

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
                <p>Windows-focused extortion operations with recent disclosures.</p>
            </article>
            <article class="group-card">
                <h2>Akira</h2>
                <p>Linux and VMware targeting noted this week.</p>
            </article>
        </body></html>
        """

        self._ingest_markup(markup)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertEqual(hit.title, "Black Basta")
        self.assertEqual(hit.matched_keywords, ["black basta"])
        self.assertIn("extortion operations", hit.excerpt)
        self.assertEqual(hit.url, self.source.url)

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
                <thead><tr><th>Group</th><th>Victims</th><th>Notes</th></tr></thead>
                <tbody>
                    <tr>
                        <td><a href="/groups/akira">Akira</a></td>
                        <td>41</td>
                        <td>Double extortion activity</td>
                    </tr>
                    <tr>
                        <td><a href="/groups/play">Play</a></td>
                        <td>18</td>
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
