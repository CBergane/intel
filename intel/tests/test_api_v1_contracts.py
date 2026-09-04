from datetime import datetime, timezone as datetime_timezone
from urllib.parse import quote

from django.core import signing
from django.test import SimpleTestCase, TestCase

from intel.api_v1.contracts import build_publishable_signal
from intel.api_v1.cursors import (
    CHANGE_CURSOR_SALT,
    CHANGE_ORDERING_FIELDS,
    ChangeCursor,
    InvalidCursor,
    UnsupportedCursorVersion,
    decode_change_cursor,
    encode_change_cursor,
)
from intel.classification import classify_item
from intel.models import DarkHit, Feed, Item, Source


PUBLISHED_AT = datetime(2026, 9, 3, 21, 0, 2, tzinfo=datetime_timezone.utc)
OBSERVED_AT = datetime(2026, 9, 3, 21, 5, 0, tzinfo=datetime_timezone.utc)
CLASSIFIED_AT = datetime(2026, 9, 3, 22, 0, 0, tzinfo=datetime_timezone.utc)
UPDATED_AT = datetime(2026, 9, 3, 21, 10, 0, 123456, tzinfo=datetime_timezone.utc)


class PublishableSignalContractTests(TestCase):
    def setUp(self):
        self.item_index = 0

    def _make_item(
        self,
        *,
        title: str,
        summary: str = "",
        url: str = "",
        section: str = Feed.Section.ACTIVE,
        adapter_key: str = "",
        source_name: str = "Contract Source",
        source_slug: str = "contract-source",
        source_tags=None,
        raw_payload=None,
    ) -> Item:
        self.item_index += 1
        suffix = str(self.item_index)
        source = Source.objects.create(
            name=f"{source_name} {suffix}",
            slug=f"{source_slug}-{suffix}",
            homepage="https://internal-config.example/source",
            tags=source_tags or [],
            enabled=False,
        )
        feed = Feed.objects.create(
            source=source,
            name=f"Private Feed Configuration {suffix}",
            url=f"https://internal-config.example/feed-{suffix}.json",
            feed_type=Feed.FeedType.JSON if adapter_key else Feed.FeedType.RSS,
            adapter_key=adapter_key,
            section=section,
            enabled=False,
            last_error="private fetch error",
        )
        item = Item.objects.create(
            source=source,
            feed=feed,
            title=title,
            summary=summary,
            url=url,
            published_at=PUBLISHED_AT,
            raw_payload=raw_payload or {},
            stable_id="",
        )
        Item.objects.filter(pk=item.pk).update(
            created_at=OBSERVED_AT,
            updated_at=UPDATED_AT,
        )
        return Item.objects.select_related("source", "feed").get(pk=item.pk)

    def test_complete_ransomware_signal_shape_is_explicit(self):
        item = self._make_item(
            title="Akira: Example AB",
            summary="Victim disclosure.",
            url="https://EXAMPLE.com/victim?utm_source=feed&b=2&a=1",
            adapter_key="ransomware_live_victims",
            raw_payload={
                "group": "akira",
                "victim": "Example AB",
                "country": "Sweden",
                "internal_secret": "must-not-leak",
            },
        )

        with self.assertNumQueries(0):
            signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

        self.assertEqual(
            signal,
            {
                "schema_version": "1",
                "id": f"intel:item:{item.stable_id}",
                "kind": "ransomware",
                "title": "Akira: Example AB",
                "summary": "Victim disclosure.",
                "url": "https://example.com/victim?a=1&b=2",
                "published_at": "2026-09-03T21:00:02Z",
                "observed_at": "2026-09-03T21:05:00Z",
                "classified_at": "2026-09-03T22:00:00Z",
                "priority": "P2",
                "score": 50,
                "classification": {
                    "active_exploitation": False,
                    "vulnerability": False,
                    "threat_news": False,
                    "ransomware": True,
                    "nordic": True,
                    "research": False,
                },
                "entities": {
                    "cves": [],
                    "countries": [{"code": "SWE", "name": "Sweden"}],
                    "ransomware_actor": "akira",
                    "ransomware_victim": "Example AB",
                },
                "source": {
                    "slug": item.source.slug,
                    "name": item.source.name,
                },
            },
        )
        self.assertEqual(
            list(signal),
            [
                "schema_version",
                "id",
                "kind",
                "title",
                "summary",
                "url",
                "published_at",
                "observed_at",
                "classified_at",
                "priority",
                "score",
                "classification",
                "entities",
                "source",
            ],
        )

    def test_classification_fields_match_authoritative_classifier(self):
        items = (
            self._make_item(
                title="Security industry briefing",
                summary="An ordinary report about current technology developments.",
                source_tags=["news"],
            ),
            self._make_item(
                title="Critical CVE-2026-4004 vendor advisory",
                summary="A remote code execution vulnerability requires patching.",
                section=Feed.Section.ADVISORIES,
            ),
            self._make_item(
                title="CVE-2026-5005 - Example Gateway",
                adapter_key="cisa_kev",
            ),
            self._make_item(
                title="CERT-SE weekly security overview",
                section=Feed.Section.SWEDEN,
                source_name="CERT-SE",
                source_slug="cert-se",
                source_tags=["government", "sweden"],
            ),
            self._make_item(
                title="Qilin: Nordic Victim",
                adapter_key="ransomware_live_victims",
                raw_payload={"group": "qilin", "victim": "Nordic Victim"},
            ),
        )

        for item in items:
            with self.subTest(title=item.title):
                profile = classify_item(item, now=CLASSIFIED_AT)
                signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

                self.assertEqual(signal["kind"], profile.primary_category)
                self.assertEqual(signal["priority"], profile.priority)
                self.assertEqual(signal["score"], profile.score)
                self.assertEqual(
                    signal["classification"],
                    {
                        "active_exploitation": profile.active_exploitation,
                        "vulnerability": profile.vulnerability,
                        "threat_news": profile.threat_news,
                        "ransomware": profile.ransomware,
                        "nordic": profile.nordic_relevance,
                        "research": profile.research,
                    },
                )

    def test_cves_and_countries_are_normalized_and_deterministic(self):
        item = self._make_item(
            title="CVE-2026-9002 and cve-2025-1 with CVE-2026-9002",
            section=Feed.Section.ADVISORIES,
            raw_payload={"country": " Sverige "},
        )

        signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

        self.assertEqual(signal["entities"]["cves"], ["CVE-2025-1", "CVE-2026-9002"])
        self.assertEqual(
            signal["entities"]["countries"],
            [{"code": "SWE", "name": "Sweden"}],
        )

    def test_missing_optional_values_have_stable_null_and_empty_collection_policy(self):
        item = self._make_item(title="Uncategorized operational note")

        signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

        self.assertIsNone(signal["summary"])
        self.assertIsNone(signal["url"])
        self.assertEqual(signal["entities"]["cves"], [])
        self.assertEqual(signal["entities"]["countries"], [])
        self.assertIsNone(signal["entities"]["ransomware_actor"])
        self.assertIsNone(signal["entities"]["ransomware_victim"])

    def test_nordic_classification_does_not_invent_country_entity(self):
        item = self._make_item(
            title="CERT-SE weekly security overview",
            section=Feed.Section.SWEDEN,
            source_name="CERT-SE",
            source_slug="cert-se",
            source_tags=["government", "sweden"],
        )

        signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

        self.assertTrue(signal["classification"]["nordic"])
        self.assertEqual(signal["entities"]["countries"], [])

    def test_raw_payload_and_internal_source_or_feed_configuration_are_excluded(self):
        item = self._make_item(
            title="Public signal",
            raw_payload={
                "country": "Atlantis",
                "secret": "raw-secret-sentinel",
                "nested": {"private": True},
            },
            source_tags=["private-tag-sentinel"],
        )

        signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)
        serialized = repr(signal)

        self.assertEqual(set(signal["source"]), {"slug", "name"})
        self.assertNotIn("raw_payload", signal)
        self.assertNotIn("raw-secret-sentinel", serialized)
        self.assertNotIn("private-tag-sentinel", serialized)
        self.assertNotIn("internal-config.example", serialized)
        self.assertNotIn("private fetch error", serialized)
        self.assertNotIn("external_id", signal)
        self.assertNotIn("stable_id", signal)

    def test_non_ransomware_raw_actor_fields_are_not_published(self):
        item = self._make_item(
            title="Ordinary security report",
            raw_payload={"group": "not-authoritative", "victim": "not-authoritative"},
        )

        signal = build_publishable_signal(item, classified_at=CLASSIFIED_AT)

        self.assertIsNone(signal["entities"]["ransomware_actor"])
        self.assertIsNone(signal["entities"]["ransomware_victim"])

    def test_same_item_and_classification_time_are_deterministic(self):
        item = self._make_item(
            title="CVE-2026-7007 research analysis",
            section=Feed.Section.RESEARCH,
            source_tags=["research"],
        )

        self.assertEqual(
            build_publishable_signal(item, classified_at=CLASSIFIED_AT),
            build_publishable_signal(item, classified_at=CLASSIFIED_AT),
        )

    def test_later_classification_time_can_change_recency_score_and_priority(self):
        item = self._make_item(
            title="Akira: Example AB",
            adapter_key="ransomware_live_victims",
            raw_payload={
                "group": "akira",
                "victim": "Example AB",
                "country": "Sweden",
            },
        )
        later_classified_at = datetime(
            2026,
            9,
            7,
            22,
            0,
            tzinfo=datetime_timezone.utc,
        )

        initial = build_publishable_signal(item, classified_at=CLASSIFIED_AT)
        later = build_publishable_signal(item, classified_at=later_classified_at)

        self.assertEqual(initial["score"], 50)
        self.assertEqual(initial["priority"], "P2")
        self.assertEqual(later["score"], 43)
        self.assertEqual(later["priority"], "P3")
        self.assertEqual(initial["observed_at"], "2026-09-03T21:05:00Z")
        self.assertEqual(later["observed_at"], "2026-09-03T21:05:00Z")
        self.assertEqual(initial["classified_at"], "2026-09-03T22:00:00Z")
        self.assertEqual(later["classified_at"], "2026-09-07T22:00:00Z")

    def test_dark_model_cannot_enter_generic_signal_builder(self):
        with self.assertRaises(TypeError):
            build_publishable_signal(DarkHit())


class ChangeCursorContractTests(SimpleTestCase):
    def test_cursor_round_trip_is_deterministic(self):
        first = encode_change_cursor(updated_at=UPDATED_AT, item_id=42)
        second = encode_change_cursor(updated_at=UPDATED_AT, item_id=42)

        self.assertEqual(first, second)
        self.assertEqual(
            decode_change_cursor(first),
            ChangeCursor(updated_at=UPDATED_AT, item_id=42),
        )
        self.assertEqual(decode_change_cursor(first).ordering_key, (UPDATED_AT, 42))
        self.assertEqual(CHANGE_ORDERING_FIELDS, ("updated_at", "id"))

    def test_cursor_is_opaque_and_url_safe(self):
        cursor = encode_change_cursor(updated_at=UPDATED_AT, item_id=42)

        self.assertEqual(quote(cursor, safe=""), cursor)
        self.assertNotIn("2026-09-03", cursor)
        self.assertNotIn("updated_at", cursor)

    def test_malformed_cursor_is_rejected(self):
        for value in (None, "", "not-a-cursor", "one.two.three"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidCursor):
                    decode_change_cursor(value)

    def test_tampered_cursor_is_rejected(self):
        cursor = encode_change_cursor(updated_at=UPDATED_AT, item_id=42)
        encoded_payload, separator, signature = cursor.partition(".")
        replacement = "A" if encoded_payload[0] != "A" else "B"
        tampered = replacement + encoded_payload[1:] + separator + signature

        with self.assertRaises(InvalidCursor):
            decode_change_cursor(tampered)

    def test_unsupported_cursor_version_is_rejected(self):
        cursor = signing.Signer(salt=CHANGE_CURSOR_SALT, sep=".").sign_object(
            {
                "v": 2,
                "u": "2026-09-03T21:10:00.123456Z",
                "i": 42,
            },
            compress=False,
        )

        with self.assertRaises(UnsupportedCursorVersion):
            decode_change_cursor(cursor)

    def test_cursor_rejects_naive_timestamp_and_invalid_item_id(self):
        naive = datetime(2026, 9, 3, 21, 10)
        with self.assertRaises(ValueError):
            encode_change_cursor(updated_at=naive, item_id=42)
        for item_id in (0, -1, True, "42"):
            with self.subTest(item_id=item_id):
                with self.assertRaises(ValueError):
                    encode_change_cursor(updated_at=UPDATED_AT, item_id=item_id)
