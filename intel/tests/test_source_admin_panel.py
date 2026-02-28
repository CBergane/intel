from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from intel.models import Source


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

    def test_reverse_names_resolve(self):
        self.assertEqual(self.list_url, "/admin-panel/sources/")
        self.assertEqual(self.create_url, "/admin-panel/sources/new/")
        self.assertEqual(self.edit_url, f"/admin-panel/sources/{self.source.id}/edit/")
        self.assertEqual(self.toggle_url, f"/admin-panel/sources/{self.source.id}/toggle/")

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

    def test_csrf_enforced_for_source_toggle(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.superuser)
        response = client.post(self.toggle_url, {"next": self.list_url})
        self.assertEqual(response.status_code, 403)
