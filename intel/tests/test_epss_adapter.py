import json
from datetime import datetime, timezone

from django.test import TestCase, override_settings

from intel.ingestion import parse_json_payload
from intel.models import Feed, Item, Source


def _make_feed():
    source = Source.objects.create(
        name="FIRST.org EPSS",
        slug="epss",
        homepage="https://www.first.org/epss",
    )
    return Feed.objects.create(
        source=source,
        name="EPSS Top CVEs (7 days)",
        url="https://api.first.org/data/v1/epss?days=7&limit=200&order=!epss",
        feed_type=Feed.FeedType.JSON,
        adapter_key="epss",
        section=Feed.Section.ACTIVE,
        max_age_days=14,
        max_items_per_run=200,
    )


def _payload(*entries):
    return json.dumps({"data": list(entries)}).encode()


ENTRY_HIGH = {
    "cve": "CVE-2024-1234",
    "epss": "0.973",
    "percentile": "0.999",
    "date": "2024-01-15",
}
ENTRY_MED = {
    "cve": "CVE-2024-5678",
    "epss": "0.500",
    "percentile": "0.950",
    "date": "2024-01-14",
}
ENTRY_LOW = {
    "cve": "CVE-2024-9999",
    "epss": "0.050",
    "percentile": "0.200",
    "date": "2024-01-13",
}
FETCHED_AT = datetime(2024, 1, 16, tzinfo=timezone.utc)


class EPSSAdapterTests(TestCase):
    def setUp(self):
        self.feed = _make_feed()

    @override_settings(EPSS_MIN_SCORE=0.1)
    def test_epss_items_created(self):
        payload = _payload(ENTRY_HIGH, ENTRY_MED, ENTRY_LOW)
        # ENTRY_LOW (0.05) is below min_score=0.1, so only 2 entries returned
        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 2)

        from intel.ingestion import upsert_normalized_item
        for entry in entries:
            upsert_normalized_item(self.feed, entry)

        self.assertEqual(Item.objects.filter(feed=self.feed).count(), 2)

    @override_settings(EPSS_MIN_SCORE=0.1)
    def test_epss_low_score_filtered(self):
        payload = _payload(ENTRY_LOW)
        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 0)

    @override_settings(EPSS_MIN_SCORE=0.1)
    def test_epss_title_format(self):
        payload = _payload(ENTRY_HIGH)
        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].title, "CVE-2024-1234 \u2014 EPSS 97.3%")

    @override_settings(EPSS_MIN_SCORE=0.1)
    def test_epss_idempotent(self):
        from intel.ingestion import upsert_normalized_item
        payload = _payload(ENTRY_HIGH)

        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        for entry in entries:
            upsert_normalized_item(self.feed, entry)

        # Second run with identical data
        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)
        for entry in entries:
            upsert_normalized_item(self.feed, entry)

        self.assertEqual(Item.objects.filter(feed=self.feed).count(), 1)
