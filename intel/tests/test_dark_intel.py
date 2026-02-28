from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from intel.models import DarkFetchRun, DarkHit, DarkSource


class DummyResponse:
    def __init__(self, chunks, *, status_code=200):
        self._chunks = chunks
        self.status_code = status_code

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
            url="https://exampleonion.test/listing",
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
            url="https://alpha-dark.example.com/page",
            tags=["onion"],
            watch_keywords="breach, leak",
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
                "url": "https://beta-dark.example.com/index",
                "tags": "leaks, sweden",
                "watch_keywords": "Breach, Initial Access",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.list_url)

        created = DarkSource.objects.get(slug="beta-dark")
        self.assertEqual(created.tags, ["leaks", "sweden"])
        self.assertEqual(created.watch_keywords, "breach, initial access")

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
                "url": "https://alpha-dark.example.com/reports",
                "tags": "onion, market",
                "watch_keywords": "Leak, Broker",
                "enabled": "on",
            },
        )
        self.assertEqual(edit_response.status_code, 302)
        self.assertEqual(edit_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertEqual(self.source.name, "Alpha Dark Updated")
        self.assertEqual(self.source.tags, ["onion", "market"])
        self.assertEqual(self.source.watch_keywords, "leak, broker")

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
            url="https://gamma-dark.example.com/page",
            watch_keywords="breach, market",
        )

    @override_settings(DARK_MAX_BYTES=10, DARK_FETCH_RETRIES=1)
    def test_ingestion_respects_dark_max_bytes_and_records_error_run(self):
        response = DummyResponse([b"12345678", b"12345678"])

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
        self.assertEqual(
            mocked_get.call_args.kwargs["proxies"],
            {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"},
        )

    @override_settings(DARK_FETCH_RETRIES=1, DARK_MAX_BYTES=5000)
    def test_keyword_matching_creates_dark_hit_and_dedupes(self):
        html = (
            "<html><title>Breach market update</title>"
            "<body>New breach listing posted on the market today.</body></html>"
        ).encode("utf-8")
        response = DummyResponse([html])

        with patch(
            "intel.management.commands.ingest_dark.requests.get",
            return_value=response,
        ):
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())
            call_command("ingest_dark", stdout=StringIO(), stderr=StringIO())

        self.assertEqual(DarkFetchRun.objects.filter(dark_source=self.source).count(), 2)
        self.assertEqual(DarkHit.objects.filter(dark_source=self.source).count(), 1)

        hit = DarkHit.objects.get(dark_source=self.source)
        self.assertEqual(hit.title, "Breach market update")
        self.assertEqual(hit.matched_keywords, ["breach", "market"])
