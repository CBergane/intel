from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from intel.models import DarkSource, Source


class SourceAdminSecurityTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="source-root",
            password="source-root-pass-123",
        )
        self.non_superuser = user_model.objects.create_user(
            username="source-staff",
            password="source-staff-pass-123",
            is_staff=True,
        )
        self.list_url = reverse("intel_admin:sources")
        self.create_url = reverse("intel_admin:source_create")
        self.login_url = reverse("intel_admin:login")
        self.source = Source.objects.create(name="Managed Source", slug="managed-source")
        self.edit_url = reverse("intel_admin:source_edit", kwargs={"source_id": self.source.id})
        self.toggle_url = reverse(
            "intel_admin:source_toggle", kwargs={"source_id": self.source.id}
        )
        self.delete_url = reverse(
            "intel_admin:source_delete", kwargs={"source_id": self.source.id}
        )

    def test_reverse_names_resolve(self):
        self.assertEqual(self.list_url, "/admin-panel/sources/")
        self.assertEqual(self.create_url, "/admin-panel/sources/new/")
        self.assertEqual(self.edit_url, f"/admin-panel/sources/{self.source.id}/edit/")
        self.assertEqual(self.toggle_url, f"/admin-panel/sources/{self.source.id}/toggle/")
        self.assertEqual(self.delete_url, f"/admin-panel/sources/{self.source.id}/delete/")

    def test_unauthenticated_user_redirected_to_admin_login(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)

    def test_non_superuser_blocked_from_source_admin(self):
        self.client.force_login(self.non_superuser)
        list_response = self.client.get(self.list_url)
        create_response = self.client.get(self.create_url)

        self.assertIn(list_response.status_code, (302, 403))
        self.assertIn(create_response.status_code, (302, 403))


class SourceAdminCrudTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="source-admin",
            password="source-admin-pass-123",
        )
        self.source = Source.objects.create(
            name="Alpha Source",
            slug="alpha-source",
            homepage="https://alpha.example.com",
            tags=["vendor"],
            enabled=True,
        )
        self.list_url = reverse("intel_admin:sources")
        self.create_url = reverse("intel_admin:source_create")
        self.edit_url = reverse("intel_admin:source_edit", kwargs={"source_id": self.source.id})
        self.toggle_url = reverse(
            "intel_admin:source_toggle", kwargs={"source_id": self.source.id}
        )
        self.delete_url = reverse(
            "intel_admin:source_delete", kwargs={"source_id": self.source.id}
        )

    def test_superuser_can_view_sources_list(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Source Admin")
        self.assertContains(response, "Alpha Source")

    def test_superuser_can_create_edit_and_toggle_source_with_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)

        create_get = client.get(self.create_url)
        self.assertEqual(create_get.status_code, 200)
        token = client.cookies["csrftoken"].value

        create_response = client.post(
            self.create_url,
            {
                "csrfmiddlewaretoken": token,
                "name": "Beta Source",
                "slug": "beta-source",
                "homepage": "https://beta.example.com/path/that/is/quite/long",
                "tags": "research, sweden",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertEqual(create_response.url, self.list_url)

        created = Source.objects.get(slug="beta-source")
        self.assertEqual(created.tags, ["research", "sweden"])

        edit_get = client.get(self.edit_url)
        self.assertEqual(edit_get.status_code, 200)
        token = client.cookies["csrftoken"].value

        edit_response = client.post(
            self.edit_url,
            {
                "csrfmiddlewaretoken": token,
                "name": "Alpha Source Updated",
                "slug": "alpha-source",
                "homepage": "https://alpha.example.com/security",
                "tags": "vendor, critical",
                "enabled": "on",
            },
        )
        self.assertEqual(edit_response.status_code, 302)
        self.assertEqual(edit_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertEqual(self.source.name, "Alpha Source Updated")
        self.assertEqual(self.source.tags, ["vendor", "critical"])

        toggle_get = client.get(self.toggle_url)
        self.assertEqual(toggle_get.status_code, 405)

        token = client.cookies["csrftoken"].value
        toggle_response = client.post(
            self.toggle_url,
            {
                "csrfmiddlewaretoken": token,
                "next": self.list_url,
            },
        )
        self.assertEqual(toggle_response.status_code, 302)
        self.assertEqual(toggle_response.url, self.list_url)

        self.source.refresh_from_db()
        self.assertFalse(self.source.enabled)

        token = client.cookies["csrftoken"].value
        delete_response = client.post(
            self.delete_url,
            {
                "csrfmiddlewaretoken": token,
                "next": self.list_url,
            },
        )
        self.assertEqual(delete_response.status_code, 302)
        self.assertEqual(delete_response.url, self.list_url)
        self.assertFalse(Source.objects.filter(id=self.source.id).exists())

    def test_csrf_enforced_for_source_toggle(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        response = client.post(self.toggle_url, {"next": self.list_url})
        self.assertEqual(response.status_code, 403)


class DarkSourceAdminPanelTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="dark-admin",
            password="dark-admin-pass-123",
        )
        self.list_url = reverse("intel_admin:dark_sources")
        self.primary = DarkSource.objects.create(
            name="Alpha Leak Watch",
            slug="alpha-leak-watch",
            url="https://alpha.example.com/feed.xml",
            source_type=DarkSource.SourceType.FEED,
            extractor_profile=DarkSource.ExtractorProfile.GROUP_CARDS,
            enabled=True,
            use_tor=True,
            watch_keywords="breach, leak",
            watch_regex=r"CVE-\d{4}-\d+",
        )
        self.secondary = DarkSource.objects.create(
            name="Beta Onion Mirror",
            slug="beta-onion-mirror",
            url="http://betaexampleonion.onion/index",
            source_type=DarkSource.SourceType.INDEX_PAGE,
            extractor_profile=DarkSource.ExtractorProfile.TABLE_ROWS,
            enabled=False,
            use_tor=True,
            watch_keywords="",
            watch_regex="",
        )

    def test_superuser_can_view_dark_sources_list_with_summary_and_actions(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dark Admin")
        self.assertContains(response, "Total Dark Sources")
        self.assertContains(response, "Keyword Watches")
        self.assertContains(response, "Alpha Leak Watch")
        self.assertContains(response, "Beta Onion Mirror")
        self.assertContains(response, "Advanced details")
        self.assertContains(response, "Delete")
        self.assertContains(
            response, reverse("intel_admin:dark_source_edit", kwargs={"source_id": self.primary.id})
        )
        self.assertContains(
            response,
            reverse("intel_admin:dark_source_delete", kwargs={"source_id": self.primary.id}),
        )
        self.assertEqual(response.context["total_dark_sources_count"], 2)
        self.assertEqual(response.context["enabled_dark_sources_count"], 1)
        self.assertEqual(response.context["disabled_dark_sources_count"], 1)
        self.assertEqual(response.context["tor_enabled_sources_count"], 2)
        self.assertEqual(response.context["keyword_watch_sources_count"], 1)

    def test_dark_sources_list_surfaces_watch_and_network_badges(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "keywords 2")
        self.assertContains(response, "regex 1")
        self.assertContains(response, "tor")
        self.assertContains(response, "disabled")
        self.assertContains(response, "no watches")
        self.assertContains(response, "Group Cards")
        self.assertContains(response, "Table Rows")

    def test_superuser_can_delete_dark_source_with_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)

        list_response = client.get(self.list_url)
        self.assertEqual(list_response.status_code, 200)
        token = client.cookies["csrftoken"].value

        delete_response = client.post(
            reverse("intel_admin:dark_source_delete", kwargs={"source_id": self.primary.id}),
            {
                "csrfmiddlewaretoken": token,
                "next": self.list_url,
            },
        )

        self.assertEqual(delete_response.status_code, 302)
        self.assertEqual(delete_response.url, self.list_url)
        self.assertFalse(DarkSource.objects.filter(id=self.primary.id).exists())


class DarkSourceAdminFormTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="dark-form-admin",
            password="dark-form-admin-pass-123",
        )
        self.create_url = reverse("intel_admin:dark_source_create")
        self.source = DarkSource.objects.create(
            name="Gamma Intel Watch",
            slug="gamma-intel-watch",
            url="https://gamma.example.com/feed.xml",
            source_type=DarkSource.SourceType.FEED,
            extractor_profile=DarkSource.ExtractorProfile.INCIDENT_CARDS,
            enabled=True,
            use_tor=False,
            watch_keywords="breach, leak",
            watch_regex=r"CVE-\d{4}-\d+",
        )
        self.edit_url = reverse("intel_admin:dark_source_edit", kwargs={"source_id": self.source.id})

    def test_create_form_groups_fields_and_configures_operational_help(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.create_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Basic")
        self.assertContains(response, "Fetch Config")
        self.assertContains(response, "Matching / Watches")
        self.assertContains(response, "Notes / Tags / Suitability")
        self.assertContains(response, "Collection Quick Guide")
        self.assertEqual(
            [section["title"] for section in response.context["form_sections"]],
            ["Basic", "Fetch Config", "Matching / Watches", "Notes / Tags / Suitability"],
        )

        form = response.context["form"]
        self.assertEqual(form.fields["url"].label, "Fetch URL")
        self.assertEqual(form.fields["use_tor"].label, "Route Through Tor")
        self.assertEqual(form.fields["extractor_profile"].label, "Extractor Profile")
        self.assertEqual(
            form.fields["enabled"].help_text,
            "Turn off to keep the source configured without including it in ingest jobs.",
        )
        self.assertIn("incident_cards/group_cards", form.fields["extractor_profile"].help_text)
        self.assertEqual(
            form.fields["watch_keywords"].widget.attrs["placeholder"],
            "breach, leak, initial access",
        )
        self.assertEqual(form.fields["watch_keywords"].widget.attrs["rows"], 4)
        self.assertEqual(form.fields["watch_regex"].widget.attrs["rows"], 6)
        self.assertEqual(
            form.initial["extractor_profile"],
            DarkSource.ExtractorProfile.GENERIC_PAGE,
        )

    def test_edit_form_shows_consistent_footer_actions(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.edit_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Save Changes")
        self.assertContains(response, "Cancel")
        self.assertContains(response, "Delete")
        self.assertContains(
            response,
            reverse("intel_admin:dark_source_delete", kwargs={"source_id": self.source.id}),
        )
        self.assertContains(
            response,
            reverse("intel_admin:dark_source_test", kwargs={"source_id": self.source.id}),
        )
        self.assertContains(
            response,
            reverse("intel_admin:dark_source_ingest", kwargs={"source_id": self.source.id}),
        )

    def test_invalid_dark_source_form_shows_error_summary(self):
        self.client.force_login(self.superuser)
        response = self.client.post(
            self.create_url,
            {
                "name": "Delta Watch",
                "slug": "delta-watch",
                "url": "https://delta.example.com/feed.xml",
                "source_type": DarkSource.SourceType.FEED,
                "extractor_profile": DarkSource.ExtractorProfile.TABLE_ROWS,
                "timeout_seconds": "0",
                "max_bytes": "100",
                "fetch_retries": "0",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Check the highlighted fields.")
        self.assertContains(response, "Timeout must be between 1 and 120 seconds.")
        self.assertContains(response, "Max bytes must be between 1024 and 25000000.")
        self.assertContains(response, "Retries must be between 1 and 10.")

    def test_edit_form_preserves_selected_extractor_profile(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.edit_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["form"].initial["extractor_profile"],
            DarkSource.ExtractorProfile.INCIDENT_CARDS,
        )
