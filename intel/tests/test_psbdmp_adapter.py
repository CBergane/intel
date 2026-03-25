import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings

from intel.ingestion import parse_json_payload
from intel.models import Feed, Item, Source


def _make_feed():
    source = Source.objects.create(
        name="Paste Monitor (psbdmp)",
        slug="psbdmp",
        homepage="https://psbdmp.ws",
    )
    return Feed.objects.create(
        source=source,
        name="psbdmp Credential Search",
        url="https://psbdmp.ws/api/v3/search/sweden+credentials",
        feed_type=Feed.FeedType.JSON,
        adapter_key="psbdmp",
        section=Feed.Section.ACTIVE,
        max_age_days=7,
        max_items_per_run=100,
    )


PASTE_A = {
    "id": "abc123",
    "tags": "password credentials email",
    "length": 500,
    "time": 1700000000,
}
PASTE_B = {
    "id": "def456",
    "tags": "sweden.se apikey secret",
    "length": 300,
    "time": 1700001000,
}
PASTE_UNRELATED = {
    "id": "ghi789",
    "tags": "funny cats memes",
    "length": 100,
    "time": 1700002000,
}

FETCHED_AT = datetime(2024, 1, 16, tzinfo=timezone.utc)


def _mock_response(data):
    mock = MagicMock()
    mock.raise_for_status.return_value = None
    mock.json.return_value = data
    return mock


class PsbdmpAdapterTests(TestCase):
    def setUp(self):
        self.feed = _make_feed()

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_initial_payload_parsed(self):
        """Pastes from the initial payload are returned."""
        payload = json.dumps([PASTE_A, PASTE_B]).encode()
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.return_value = _mock_response([])
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 2)
        ids = {e.external_id for e in entries}
        self.assertIn("abc123", ids)
        self.assertIn("def456", ids)

    @override_settings(PSBDMP_QUERIES="nordic breach")
    def test_psbdmp_additional_queries_fetched(self):
        """Additional queries from PSBDMP_QUERIES are fetched and merged."""
        initial_payload = json.dumps([PASTE_A]).encode()
        extra_paste = {"id": "extra999", "tags": "nordic breach leak", "length": 200, "time": 1700003000}
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.return_value = _mock_response([extra_paste])
            entries = parse_json_payload(self.feed, initial_payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 2)
        ids = {e.external_id for e in entries}
        self.assertIn("abc123", ids)
        self.assertIn("extra999", ids)

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_deduplication(self):
        """Same paste ID appearing in multiple sources is deduplicated."""
        payload = json.dumps([PASTE_A, PASTE_A]).encode()
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.return_value = _mock_response([PASTE_A])
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        # Only one entry for paste_id "abc123"
        ids = [e.external_id for e in entries]
        self.assertEqual(ids.count("abc123"), 1)

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_skips_missing_id(self):
        """Pastes without an id field are skipped."""
        payload = json.dumps([{"tags": "password", "time": 1700000000}]).encode()
        with patch("intel.ingestion.requests.get"):
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 0)

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_timestamp_parsed(self):
        """Unix timestamp in 'time' field is converted to UTC datetime."""
        payload = json.dumps([PASTE_A]).encode()
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.return_value = _mock_response([])
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 1)
        expected = datetime.fromtimestamp(1700000000, tz=timezone.utc)
        self.assertEqual(entries[0].published_at, expected)

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_fallback_timestamp(self):
        """Missing 'time' field falls back to fetched_at."""
        paste = {"id": "notime", "tags": "credentials", "length": 10}
        payload = json.dumps([paste]).encode()
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.return_value = _mock_response([])
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].published_at, FETCHED_AT)

    @override_settings(PSBDMP_QUERIES="fail query")
    def test_psbdmp_failed_query_does_not_raise(self):
        """A failed additional query is logged but does not abort the run."""
        payload = json.dumps([PASTE_A]).encode()
        with patch("intel.ingestion.requests.get") as mock_get:
            mock_get.side_effect = Exception("connection error")
            # Should not raise; initial payload still returns entries
            entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 1)

    @override_settings(PSBDMP_QUERIES="")
    def test_psbdmp_upsert_idempotent(self):
        """Running the adapter twice with same data does not create duplicate items."""
        from intel.ingestion import upsert_normalized_item

        payload = json.dumps([PASTE_A]).encode()
        for _ in range(2):
            with patch("intel.ingestion.requests.get") as mock_get:
                mock_get.return_value = _mock_response([])
                entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
            for entry in entries:
                upsert_normalized_item(self.feed, entry)

        self.assertEqual(Item.objects.filter(feed=self.feed).count(), 1)
