from datetime import datetime, timedelta, timezone as datetime_timezone
from unittest.mock import patch
from urllib.parse import quote

from django.contrib.auth import get_user_model
from django.core import signing
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from intel.api_v1.contracts import build_publishable_signal
from intel.api_v1.cursors import (
    SNAPSHOT_CURSOR_SALT,
    encode_change_cursor,
    encode_snapshot_cursor,
)
from intel.api_v1.views import SIGNALS_DEFAULT_LIMIT, SIGNALS_MAX_LIMIT
from intel.models import Feed, Item, Source


CLASSIFIED_AT = datetime(2026, 9, 4, 8, 0, 0, tzinfo=datetime_timezone.utc)
PUBLISHED_AT = datetime(2026, 9, 3, 20, 0, 0, tzinfo=datetime_timezone.utc)
OBSERVED_AT = datetime(2026, 9, 3, 20, 5, 0, tzinfo=datetime_timezone.utc)


@override_settings(INTEGRATION_API_TOKEN="signals-test-token")
class SignalsEndpointTests(TestCase):
    def setUp(self):
        self.url = reverse("api_v1:signals")
        self.authorization = "Bearer signals-test-token"
        self.source = Source.objects.create(
            name="Signals Source",
            slug="signals-source",
            homepage="https://internal.example/source-config",
            tags=["news", "internal-tag"],
        )
        self.feed = Feed.objects.create(
            source=self.source,
            name="Internal Feed Configuration",
            url="https://internal.example/feed.xml",
            section=Feed.Section.ACTIVE,
            last_error="internal feed error",
        )
        self.item_index = 0

    def _make_item(self, *, published_at=None, title=None, raw_payload=None) -> Item:
        self.item_index += 1
        item = Item.objects.create(
            source=self.source,
            feed=self.feed,
            title=title or f"Signal {self.item_index:03d}",
            summary="Public normalized summary.",
            url=f"https://public.example/signals/{self.item_index}",
            published_at=published_at or PUBLISHED_AT,
            raw_payload=raw_payload or {},
            stable_id="",
        )
        Item.objects.filter(pk=item.pk).update(created_at=OBSERVED_AT)
        return Item.objects.select_related("source", "feed").get(pk=item.pk)

    def _get(self, data=None, *, authorization=None):
        header = self.authorization if authorization is None else authorization
        with patch("intel.api_v1.views.timezone.now", return_value=CLASSIFIED_AT):
            return self.client.get(
                self.url,
                data or {},
                HTTP_AUTHORIZATION=header,
            )

    def assert_api_response(self, response, status):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response.json()["api_version"], "1")

    def assert_invalid_request(self, response):
        self.assert_api_response(response, 400)
        self.assertEqual(
            response.json(),
            {
                "api_version": "1",
                "error": {
                    "code": "invalid_request",
                    "message": "Invalid request.",
                },
            },
        )

    def test_authenticated_get_returns_publishable_dto_envelope(self):
        item = self._make_item(
            title="CVE-2026-1001 actively exploited in the wild",
            raw_payload={"secret": "raw-secret-must-not-leak"},
        )

        response = self._get()

        self.assert_api_response(response, 200)
        payload = response.json()
        self.assertEqual(payload["classified_at"], "2026-09-04T08:00:00Z")
        self.assertEqual(
            payload["results"],
            [build_publishable_signal(item, classified_at=CLASSIFIED_AT)],
        )
        self.assertIsNone(payload["next_cursor"])
        self.assertFalse(payload["has_more"])
        serialized = response.content.decode()
        for excluded in (
            "raw_payload",
            "raw-secret-must-not-leak",
            "external_id",
            "title_hash",
            "internal-tag",
            "internal feed error",
            "source-config",
        ):
            self.assertNotIn(excluded, serialized)

    def test_request_uses_one_classification_time_for_every_result(self):
        for index in range(3):
            self._make_item(
                published_at=PUBLISHED_AT - timedelta(minutes=index),
            )

        with patch(
            "intel.api_v1.views.timezone.now",
            return_value=CLASSIFIED_AT,
        ) as mocked_now:
            response = self.client.get(
                self.url,
                HTTP_AUTHORIZATION=self.authorization,
            )

        self.assert_api_response(response, 200)
        payload = response.json()
        mocked_now.assert_called_once_with()
        self.assertEqual(
            {result["classified_at"] for result in payload["results"]},
            {payload["classified_at"]},
        )

    def test_missing_and_wrong_bearer_are_unauthorized(self):
        for authorization in ("", "Bearer wrong-token"):
            with self.subTest(authorization=authorization):
                response = self._get(authorization=authorization)

                self.assert_api_response(response, 401)
                self.assertEqual(response.json()["error"]["code"], "unauthorized")
                self.assertEqual(response["WWW-Authenticate"], "Bearer")

    @override_settings(INTEGRATION_API_TOKEN="")
    def test_empty_server_token_fails_closed(self):
        response = self._get()

        self.assert_api_response(response, 503)
        self.assertEqual(response.json()["error"]["code"], "service_unavailable")

    def test_default_and_maximum_page_sizes_are_bounded(self):
        for index in range(SIGNALS_MAX_LIMIT + 1):
            self._make_item(
                published_at=PUBLISHED_AT - timedelta(minutes=index),
            )

        default_response = self._get()
        maximum_response = self._get({"limit": str(SIGNALS_MAX_LIMIT + 500)})

        self.assertEqual(len(default_response.json()["results"]), SIGNALS_DEFAULT_LIMIT)
        self.assertTrue(default_response.json()["has_more"])
        self.assertEqual(len(maximum_response.json()["results"]), SIGNALS_MAX_LIMIT)
        self.assertTrue(maximum_response.json()["has_more"])

    def test_malformed_limit_and_unsupported_parameters_are_invalid(self):
        for data in (
            {"limit": ""},
            {"limit": "0"},
            {"limit": "-1"},
            {"limit": "1.5"},
            {"limit": "fifty"},
            {"nordic": "true"},
        ):
            with self.subTest(data=data):
                self.assert_invalid_request(self._get(data))

    def test_results_order_by_published_at_then_id_descending(self):
        older = self._make_item(
            title="Older",
            published_at=PUBLISHED_AT - timedelta(hours=1),
        )
        equal_first = self._make_item(title="Equal first", published_at=PUBLISHED_AT)
        equal_second = self._make_item(title="Equal second", published_at=PUBLISHED_AT)

        response = self._get()

        self.assertEqual(
            [result["id"] for result in response.json()["results"]],
            [
                f"intel:item:{equal_second.stable_id}",
                f"intel:item:{equal_first.stable_id}",
                f"intel:item:{older.stable_id}",
            ],
        )

    def test_cursor_pagination_has_no_duplicates_with_equal_timestamps(self):
        expected = []
        for index in range(5):
            item = self._make_item(
                published_at=PUBLISHED_AT if index < 3 else PUBLISHED_AT - timedelta(hours=1),
            )
            expected.append(item)
        expected.sort(key=lambda item: (item.published_at, item.id), reverse=True)

        first = self._get({"limit": "2"}).json()
        second = self._get({"limit": "2", "cursor": first["next_cursor"]}).json()
        third = self._get({"limit": "2", "cursor": second["next_cursor"]}).json()
        result_ids = [
            result["id"]
            for page in (first, second, third)
            for result in page["results"]
        ]

        self.assertEqual(
            result_ids,
            [f"intel:item:{item.stable_id}" for item in expected],
        )
        self.assertEqual(len(result_ids), len(set(result_ids)))
        self.assertTrue(first["has_more"])
        self.assertTrue(second["has_more"])
        self.assertFalse(third["has_more"])
        self.assertIsNone(third["next_cursor"])
        self.assertEqual(quote(first["next_cursor"], safe=""), first["next_cursor"])

    def test_malformed_tampered_change_and_unsupported_cursors_are_invalid(self):
        item = self._make_item()
        valid = encode_snapshot_cursor(published_at=item.published_at, item_id=item.id)
        encoded_payload, separator, signature = valid.partition(".")
        replacement = "A" if encoded_payload[0] != "A" else "B"
        tampered = replacement + encoded_payload[1:] + separator + signature
        unsupported = signing.Signer(
            salt=SNAPSHOT_CURSOR_SALT,
            sep=".",
        ).sign_object(
            {
                "v": 2,
                "p": "2026-09-03T20:00:00Z",
                "i": item.id,
            },
            compress=False,
        )
        change_cursor = encode_change_cursor(
            updated_at=OBSERVED_AT,
            item_id=item.id,
        )

        for cursor in ("not-a-cursor", tampered, unsupported, change_cursor):
            with self.subTest(cursor=cursor):
                self.assert_invalid_request(self._get({"cursor": cursor}))

    def test_cursor_does_not_replace_bearer_authentication(self):
        item = self._make_item()
        cursor = encode_snapshot_cursor(published_at=item.published_at, item_id=item.id)

        response = self._get({"cursor": cursor}, authorization="")

        self.assert_api_response(response, 401)
        self.assertEqual(response.json()["error"]["code"], "unauthorized")

    def test_post_is_json_405_without_csrf_interception(self):
        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post(
            self.url,
            HTTP_AUTHORIZATION=self.authorization,
        )

        self.assert_api_response(response, 405)
        self.assertEqual(response["Allow"], "GET")
        self.assertEqual(response.json()["error"]["code"], "method_not_allowed")

    def test_authenticated_session_does_not_replace_bearer_token(self):
        user = get_user_model().objects.create_superuser(
            username="signals-api-admin",
            password="not-used-by-force-login",
        )
        self.client.force_login(user)

        response = self._get(authorization="")

        self.assert_api_response(response, 401)

    def test_page_query_is_single_bounded_select_with_related_objects(self):
        for index in range(6):
            self._make_item(published_at=PUBLISHED_AT - timedelta(minutes=index))

        with patch("intel.api_v1.views.timezone.now", return_value=CLASSIFIED_AT):
            with self.assertNumQueries(1):
                response = self.client.get(
                    self.url,
                    {"limit": "5"},
                    HTTP_AUTHORIZATION=self.authorization,
                )

        self.assert_api_response(response, 200)
        self.assertEqual(len(response.json()["results"]), 5)
