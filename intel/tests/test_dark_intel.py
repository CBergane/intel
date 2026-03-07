from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from intel.dark_utils import extract_links
from intel.models import DarkDocument, DarkFetchRun, DarkHit, DarkSource


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
        self.login_url = reverse("intel_admin:login")

    def test_reverse_names_resolve(self):
        self.assertEqual(self.list_url, "/admin-panel/dark/")
        self.assertEqual(self.create_url, "/admin-panel/dark/new/")
        self.assertEqual(self.edit_url, f"/admin-panel/dark/{self.source.id}/edit/")
        self.assertEqual(self.toggle_url, f"/admin-panel/dark/{self.source.id}/toggle/")

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
                "tags": "leaks, sweden",
                "watch_keywords": "Breach, Initial Access",
                "watch_regex": r"CVE-\d{4}-\d+",
                "use_tor": "on",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.list_url)

        created = DarkSource.objects.get(slug="beta-dark")
        self.assertEqual(created.tags, ["leaks", "sweden"])
        self.assertEqual(created.watch_keywords, "breach, initial access")
        self.assertEqual(created.source_type, DarkSource.SourceType.INDEX_PAGE)
        self.assertTrue(created.use_tor)

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
                "tags": "onion, market",
                "watch_keywords": "Leak, Broker",
                "watch_regex": r"ransomware",
                "enabled": "on",
            },
        )
        self.assertEqual(edit_response.status_code, 302)
        self.assertEqual(edit_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertEqual(self.source.name, "Alpha Dark Updated")
        self.assertEqual(self.source.tags, ["onion", "market"])
        self.assertEqual(self.source.watch_keywords, "leak, broker")
        self.assertEqual(self.source.source_type, DarkSource.SourceType.FEED)

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

    def test_csrf_enforced_for_dark_source_toggle(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        response = client.post(self.toggle_url, {"next": self.list_url})
        self.assertEqual(response.status_code, 403)


class DarkIngestionTests(TestCase):
    def setUp(self):
        self.source = DarkSource.objects.create(
            name="Gamma Dark",
            slug="gamma-dark",
            url="https://gamma.example.com/page",
            source_type=DarkSource.SourceType.SINGLE_PAGE,
            watch_keywords="breach, market",
        )

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
        ).encode("utf-8")
        response = DummyResponse([html], url=self.source.url)

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

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
