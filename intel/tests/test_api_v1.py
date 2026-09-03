from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse


@override_settings(INTEGRATION_API_TOKEN="foundation-test-token")
class IntegrationApiV1Tests(SimpleTestCase):
    expected_unauthorized = {
        "api_version": "1",
        "error": {
            "code": "unauthorized",
            "message": "Authentication required.",
        },
    }

    def setUp(self):
        self.health_url = reverse("api_v1:health")
        self.authorization = "Bearer foundation-test-token"

    def assert_json_response(self, response, status):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.json()["api_version"], "1")

    def test_health_accepts_valid_bearer_token_without_data_queries(self):
        response = self.client.get(
            self.health_url,
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assert_json_response(response, 200)
        self.assertEqual(
            response.json(),
            {
                "api_version": "1",
                "status": "ok",
                "service": "borealsec-intel",
            },
        )
        self.assertFalse(response.cookies)

    def test_health_accepts_case_insensitive_bearer_scheme(self):
        response = self.client.get(
            self.health_url,
            HTTP_AUTHORIZATION="bearer foundation-test-token",
        )

        self.assert_json_response(response, 200)

    def test_missing_authorization_is_generic_json_unauthorized(self):
        response = self.client.get(self.health_url)

        self.assert_json_response(response, 401)
        self.assertEqual(response.json(), self.expected_unauthorized)
        self.assertEqual(response["WWW-Authenticate"], "Bearer")

    def test_wrong_token_is_rejected_exactly(self):
        for token in (
            "foundation-test-toke",
            "foundation-test-token-extra",
            "FOUNDATION-TEST-TOKEN",
        ):
            with self.subTest(token=token):
                response = self.client.get(
                    self.health_url,
                    HTTP_AUTHORIZATION=f"Bearer {token}",
                )

                self.assert_json_response(response, 401)
                self.assertEqual(response.json(), self.expected_unauthorized)

    def test_wrong_authorization_scheme_is_generic_json_unauthorized(self):
        response = self.client.get(
            self.health_url,
            HTTP_AUTHORIZATION="Basic foundation-test-token",
        )

        self.assert_json_response(response, 401)
        self.assertEqual(response.json(), self.expected_unauthorized)

    def test_malformed_bearer_values_are_rejected_without_echo(self):
        submitted_value = "submitted-secret-value"
        malformed_headers = (
            "Bearer",
            "Bearer ",
            f"Bearer  {submitted_value}",
            f"Bearer\t{submitted_value}",
            f"Bearer {submitted_value} extra",
            f"Bearer {submitted_value}-å",
        )
        for authorization in malformed_headers:
            with self.subTest(authorization=authorization):
                response = self.client.get(
                    self.health_url,
                    HTTP_AUTHORIZATION=authorization,
                )

                self.assert_json_response(response, 401)
                self.assertEqual(response.json(), self.expected_unauthorized)
                self.assertNotIn(submitted_value, response.content.decode())

    @override_settings(INTEGRATION_API_TOKEN="")
    def test_empty_configured_token_fails_closed(self):
        response = self.client.get(
            self.health_url,
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assert_json_response(response, 503)
        self.assertEqual(
            response.json(),
            {
                "api_version": "1",
                "error": {
                    "code": "service_unavailable",
                    "message": "API service unavailable.",
                },
            },
        )
        self.assertNotIn("token", response.content.decode().lower())
        self.assertNotIn("environment", response.content.decode().lower())

    def test_health_rejects_post_as_json_without_csrf_interception(self):
        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post(
            self.health_url,
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assert_json_response(response, 405)
        self.assertEqual(response["Allow"], "GET")
        self.assertEqual(
            response.json()["error"],
            {
                "code": "method_not_allowed",
                "message": "Method not allowed.",
            },
        )

    def test_health_rejects_head_deliberately(self):
        response = self.client.head(
            self.health_url,
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Allow"], "GET")
        self.assertEqual(response["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.content, b"")

    def test_unknown_api_endpoint_is_json_404(self):
        response = self.client.get("/api/v1/nope/")

        self.assert_json_response(response, 404)
        self.assertEqual(
            response.json()["error"],
            {
                "code": "not_found",
                "message": "API resource not found.",
            },
        )

    def test_missing_trailing_slash_is_json_404_without_redirect(self):
        response = self.client.get(
            "/api/v1/health",
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assert_json_response(response, 404)
        self.assertNotIn("Location", response)


class ExistingWebRoutingCompatibilityTests(TestCase):
    def test_ordinary_site_and_global_404_remain_html(self):
        response = self.client.get(reverse("about"))
        missing_response = self.client.get("/outside-api-nope/")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Type"].startswith("text/html"))
        self.assertEqual(missing_response.status_code, 404)
        self.assertTrue(missing_response["Content-Type"].startswith("text/html"))

    def test_existing_staff_login_and_redirect_behavior_is_unchanged(self):
        login_response = self.client.get(reverse("intel_admin:login"))
        ops_response = self.client.get(reverse("intel_admin:ops"))

        self.assertEqual(login_response.status_code, 200)
        self.assertEqual(ops_response.status_code, 302)
        self.assertIn(reverse("intel_admin:login"), ops_response.url)

    @override_settings(INTEGRATION_API_TOKEN="foundation-test-token")
    def test_authenticated_site_session_does_not_replace_api_bearer_auth(self):
        user = get_user_model().objects.create_superuser(
            username="api-foundation-admin",
            password="not-used-by-force-login",
        )
        self.client.force_login(user)

        response = self.client.get(reverse("api_v1:health"))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "unauthorized")
