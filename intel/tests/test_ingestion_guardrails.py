import json
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from intel.ingestion import normalize_syndication_entry
from intel.management.commands.ingest_sources import Command
from intel.models import Feed, FetchRun, Item, Source


class IngestionGuardrailTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Guard Source", slug="guard-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Guard Feed",
            url="https://example.com/guard-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )

    def _run_ingest_with_entries(self, entries):
        normalized = [
            normalize_syndication_entry(
                self.feed,
                entry,
                fallback_published_at=timezone.now(),
            )
            for entry in entries
        ]
        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(b"<rss/>", 200),
        ), patch(
            "intel.management.commands.ingest_sources.parse_feed_payload",
            return_value=normalized,
        ):
            call_command("ingest_sources", feed=str(self.feed.id))

    def test_ingestion_respects_max_age_days(self):
        self.feed.max_age_days = 30
        self.feed.max_items_per_run = 200
        self.feed.save(update_fields=["max_age_days", "max_items_per_run", "updated_at"])

        now = timezone.now()
        entries = [
            {
                "title": "Too old",
                "link": "https://example.com/old",
                "summary": "old",
                "published": (now - timedelta(days=45)).isoformat(),
            },
            {
                "title": "Fresh",
                "link": "https://example.com/fresh",
                "summary": "fresh",
                "published": (now - timedelta(days=2)).isoformat(),
            },
            {
                "title": "No published date",
                "link": "https://example.com/no-date",
                "summary": "fallback to fetched_at",
            },
        ]

        self._run_ingest_with_entries(entries)

        self.assertEqual(Item.objects.count(), 2)
        self.assertFalse(Item.objects.filter(url="https://example.com/old").exists())
        self.assertTrue(Item.objects.filter(url="https://example.com/fresh").exists())
        self.assertTrue(Item.objects.filter(url="https://example.com/no-date").exists())

        run = FetchRun.objects.get(feed=self.feed)
        self.assertEqual(run.items_skipped_old, 1)
        self.assertEqual(run.items_skipped_invalid, 0)
        self.assertEqual(run.items_stored, 2)

    def test_ingestion_respects_max_items_per_run(self):
        self.feed.max_age_days = 365
        self.feed.max_items_per_run = 2
        self.feed.save(update_fields=["max_age_days", "max_items_per_run", "updated_at"])

        now = timezone.now().isoformat()
        entries = [
            {
                "title": f"Item {idx}",
                "link": f"https://example.com/item-{idx}",
                "summary": "entry",
                "published": now,
            }
            for idx in range(5)
        ]

        self._run_ingest_with_entries(entries)

        self.assertEqual(Item.objects.count(), 2)
        self.assertEqual(
            list(Item.objects.order_by("id").values_list("url", flat=True)),
            ["https://example.com/item-0", "https://example.com/item-1"],
        )
        run = FetchRun.objects.get(feed=self.feed)
        self.assertEqual(run.items_fetched, 5)
        self.assertEqual(run.items_limited, 3)

    def test_missing_required_fields_are_skipped_invalid(self):
        entries = [
            {
                "title": "",
                "summary": "",
            },
            {
                "title": "Valid item",
                "link": "https://example.com/valid-item",
                "summary": "ok",
                "published": timezone.now().isoformat(),
            },
        ]
        self._run_ingest_with_entries(entries)

        self.assertEqual(Item.objects.count(), 1)
        run = FetchRun.objects.get(feed=self.feed)
        self.assertEqual(run.items_skipped_invalid, 1)
        self.assertEqual(run.items_stored, 1)

    @override_settings(FEED_MAX_BYTES=2_000_000)
    def test_fetch_once_respects_feed_max_bytes_setting(self):
        self.feed.max_bytes = 2_000_000
        self.feed.save(update_fields=["max_bytes", "updated_at"])

        chunk = b"a" * 800_000

        class DummyResponse:
            status_code = 200

            def raise_for_status(self):
                return None

            def iter_content(self, chunk_size=8192):
                del chunk_size
                yield chunk
                yield chunk

        with patch(
            "intel.management.commands.ingest_sources.requests.get",
            return_value=DummyResponse(),
        ):
            payload, status = Command()._fetch_once(self.feed)

        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 1_600_000)

    def test_json_cisa_kev_ingest(self):
        json_feed = Feed.objects.create(
            source=self.source,
            name="CISA KEV JSON",
            url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            feed_type=Feed.FeedType.JSON,
            adapter_key="cisa_kev",
            section=Feed.Section.ACTIVE,
            max_age_days=3650,
            max_items_per_run=10,
        )
        payload = {
            "dateReleased": "2026-03-01T00:00:00+00:00",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1111",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "dateAdded": "2026-03-02T00:00:00+00:00",
                    "requiredAction": "Apply patch",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2026-2222",
                    "vendorProject": "Beta",
                    "product": "Gateway",
                    "dateAdded": "2026-03-03T00:00:00+00:00",
                    "requiredAction": "Mitigate",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }

        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(json.dumps(payload).encode("utf-8"), 200),
        ):
            call_command("ingest_sources", feed=str(json_feed.id))

        self.assertEqual(Item.objects.filter(feed=json_feed).count(), 2)
        self.assertTrue(
            Item.objects.filter(feed=json_feed, external_id="CVE-2026-1111").exists()
        )
        self.assertTrue(
            Item.objects.filter(feed=json_feed, external_id="CVE-2026-2222").exists()
        )

    def test_rss_ingest_parses_real_payload(self):
        payload = b"""<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <title>Example Feed</title>
            <item>
              <title>Alert One</title>
              <link>https://example.com/alert-one</link>
              <pubDate>Sat, 07 Mar 2026 10:00:00 GMT</pubDate>
              <description>Alpha</description>
            </item>
            <item>
              <title>Alert Two</title>
              <link>https://example.com/alert-two</link>
              <pubDate>Sat, 07 Mar 2026 11:00:00 GMT</pubDate>
              <description>Beta</description>
            </item>
          </channel>
        </rss>"""

        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(payload, 200),
        ):
            call_command("ingest_sources", feed=str(self.feed.id))

        self.assertEqual(Item.objects.filter(feed=self.feed).count(), 2)
        self.assertTrue(Item.objects.filter(url="https://example.com/alert-one").exists())
        self.assertTrue(Item.objects.filter(url="https://example.com/alert-two").exists())

    def test_regular_high_signal_item_sends_generic_intel_alert(self):
        self.feed.section = Feed.Section.RESEARCH
        self.feed.save(update_fields=["section", "updated_at"])
        entries = [
            {
                "title": "Critical CVE-2026-4444 authentication bypass under attack",
                "link": "https://example.com/high-signal",
                "summary": "Urgent advisory for an actively exploited authentication bypass vulnerability.",
                "published": timezone.now().isoformat(),
            }
        ]
        normalized = [
            normalize_syndication_entry(
                self.feed,
                entry,
                fallback_published_at=timezone.now(),
            )
            for entry in entries
        ]

        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(b"<rss/>", 200),
        ), patch(
            "intel.management.commands.ingest_sources.parse_feed_payload",
            return_value=normalized,
        ), patch(
            "intel.management.commands.ingest_sources.send_generic_intel_alert"
        ) as mock_generic:
            call_command("ingest_sources", feed=str(self.feed.id))

        mock_generic.assert_called_once()
        alerted_item = mock_generic.call_args.args[0]
        self.assertEqual(alerted_item.title, "Critical CVE-2026-4444 authentication bypass under attack")
        self.assertEqual(
            mock_generic.call_args.kwargs["why_alerted"],
            "active exploitation",
        )

    def test_regular_low_signal_item_does_not_send_generic_intel_alert(self):
        self.feed.section = Feed.Section.RESEARCH
        self.feed.save(update_fields=["section", "updated_at"])
        entries = [
            {
                "title": "Platform maintenance release notes",
                "link": "https://example.com/release-notes",
                "summary": "Routine product update and version availability notice.",
                "published": timezone.now().isoformat(),
            }
        ]
        normalized = [
            normalize_syndication_entry(
                self.feed,
                entry,
                fallback_published_at=timezone.now(),
            )
            for entry in entries
        ]

        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(b"<rss/>", 200),
        ), patch(
            "intel.management.commands.ingest_sources.parse_feed_payload",
            return_value=normalized,
        ), patch(
            "intel.management.commands.ingest_sources.send_generic_intel_alert"
        ) as mock_generic:
            call_command("ingest_sources", feed=str(self.feed.id))

        mock_generic.assert_not_called()

    def test_epss_items_keep_specialized_alert_path_without_generic_alert(self):
        epss_feed = Feed.objects.create(
            source=self.source,
            name="EPSS Feed",
            url="https://example.com/epss.json",
            feed_type=Feed.FeedType.JSON,
            adapter_key="epss",
            section=Feed.Section.ACTIVE,
            max_age_days=365,
            max_items_per_run=10,
        )
        payload = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2026-9999",
                    "epss": "0.91",
                    "percentile": "0.999",
                    "date": "2026-03-01",
                }
            ],
        }

        with patch(
            "intel.management.commands.ingest_sources.Command._fetch_with_retries",
            return_value=(json.dumps(payload).encode("utf-8"), 200),
        ), patch(
            "intel.management.commands.ingest_sources.send_high_epss_alert"
        ) as mock_epss, patch(
            "intel.management.commands.ingest_sources.send_generic_intel_alert"
        ) as mock_generic:
            call_command("ingest_sources", feed=str(epss_feed.id))

        mock_epss.assert_called_once()
        mock_generic.assert_not_called()


class PruneItemsCommandTests(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name="Prune Source", slug="prune-source")
        self.feed = Feed.objects.create(
            source=self.source,
            name="Prune Feed",
            url="https://example.com/prune-feed.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            max_age_days=10,
        )

    def test_prune_items_dry_run_works(self):
        now = timezone.now()
        Item.objects.create(
            source=self.source,
            feed=self.feed,
            title="Old item",
            url="https://example.com/old-item",
            stable_id="",
            published_at=now - timedelta(days=41),
            summary="old",
        )
        Item.objects.create(
            source=self.source,
            feed=self.feed,
            title="Recent item",
            url="https://example.com/recent-item",
            stable_id="",
            published_at=now - timedelta(days=5),
            summary="recent",
        )

        output = StringIO()
        call_command("prune_items", "--dry-run", stdout=output)
        text = output.getvalue()

        self.assertEqual(Item.objects.count(), 2)
        self.assertIn("would_delete=1", text)
