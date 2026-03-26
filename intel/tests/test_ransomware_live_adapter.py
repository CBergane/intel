import base64
import json
from datetime import datetime, timezone

from django.test import TestCase, override_settings

from intel.ingestion import parse_json_payload
from intel.models import Feed, Source


FETCHED_AT = datetime(2024, 1, 16, tzinfo=timezone.utc)


def _make_feed():
    source = Source.objects.create(
        name="ransomware.live",
        slug="ransomware-live",
        homepage="https://www.ransomware.live",
    )
    return Feed.objects.create(
        source=source,
        name="ransomware.live Victims",
        url="https://www.ransomware.live/api/victims",
        feed_type=Feed.FeedType.JSON,
        adapter_key="ransomware_live_victims",
        section=Feed.Section.ACTIVE,
        max_age_days=30,
        max_items_per_run=200,
    )


class RansomwareLiveAdapterTests(TestCase):
    def setUp(self):
        self.feed = _make_feed()

    @override_settings(RANSOMWARE_LIVE_NORDICS_ONLY=False)
    def test_canonical_url_uses_base64_id_path(self):
        payload = json.dumps(
            [
                {
                    "victim": "acme.se",
                    "group": "lockbit3",
                    "country": "SE",
                    "discovered": "2024-01-15T10:30:00+00:00",
                    "description": "Victim leak entry",
                }
            ]
        ).encode()

        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)

        self.assertEqual(len(entries), 1)
        expected_token = base64.b64encode(b"acme.se@lockbit3").decode("ascii")
        expected_url = f"https://www.ransomware.live/id/{expected_token}"
        self.assertEqual(entries[0].url, expected_url)
        self.assertEqual(entries[0].canonical_url, expected_url)

    @override_settings(RANSOMWARE_LIVE_NORDICS_ONLY=True)
    def test_nordic_filter_accepts_country_names_iso_codes_and_tld_fallback(self):
        payload = json.dumps(
            [
                {
                    "victim": "alpha.example",
                    "group": "akira",
                    "country": "Sweden",
                    "description": "Country name match",
                },
                {
                    "victim": "beta.example",
                    "group": "cl0p",
                    "country": "FI",
                    "description": "ISO code match",
                },
                {
                    "victim": "gamma.example.no",
                    "group": "lockbit",
                    "country": "",
                    "description": "TLD fallback match",
                },
                {
                    "victim": "delta.example.com",
                    "group": "play",
                    "country": "US",
                    "description": "Non-nordic victim",
                },
            ]
        ).encode()

        entries = parse_json_payload(self.feed, payload, fetched_at=FETCHED_AT)

        self.assertEqual(len(entries), 3)
        self.assertEqual(
            {entry.external_id for entry in entries},
            {
                "akira:alpha.example",
                "cl0p:beta.example",
                "lockbit:gamma.example.no",
            },
        )
