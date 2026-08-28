from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from intel.models import Feed, Source
from intel.tier1_sources import DISABLED_FEED_URLS, TIER1_SOURCES


def _find_feed_config(source_slug: str):
    for source_cfg in TIER1_SOURCES:
        if source_cfg["slug"] != source_slug:
            continue
        return source_cfg["feeds"][0]
    raise AssertionError(f"No source config found for slug={source_slug}")


class SeedSourcesCommandTests(TestCase):
    def test_tier1_sources_use_current_feed_urls(self):
        red_hat = _find_feed_config("red-hat")
        epss = _find_feed_config("epss")
        leakix = _find_feed_config("leakix")
        ransomware_live = _find_feed_config("ransomware-live")

        self.assertEqual(
            red_hat["url"],
            "https://security.access.redhat.com/data/metrics/rhsa.rss",
        )
        self.assertEqual(
            epss["url"],
            "https://api.first.org/data/v1/epss?days=7&limit=200&sort=-epss",
        )
        self.assertEqual(leakix["url"], "https://leakix.net/rss/scope:public")
        self.assertFalse(leakix["enabled"])
        self.assertTrue(ransomware_live["discord_enabled"])
        self.assertEqual(
            ransomware_live["discord_min_priority"], Feed.DiscordPriority.P3
        )
        self.assertEqual(ransomware_live["discord_mode"], Feed.DiscordMode.DIGEST)

    def test_disabled_feed_urls_include_retired_or_invalid_endpoints(self):
        self.assertIn(
            "https://access.redhat.com/security/data/metrics/recently-released-rhsa.rss",
            DISABLED_FEED_URLS,
        )
        self.assertIn(
            "https://api.first.org/data/v1/epss?days=7&limit=200&order=!epss",
            DISABLED_FEED_URLS,
        )
        self.assertIn("https://leakix.net/rss/scope:public", DISABLED_FEED_URLS)

    def test_seed_sources_is_idempotent(self):
        expected_sources = len(TIER1_SOURCES)
        expected_feeds = sum(len(source["feeds"]) for source in TIER1_SOURCES)

        output_first = StringIO()
        call_command("seed_sources", stdout=output_first)

        self.assertEqual(Source.objects.count(), expected_sources)
        self.assertEqual(Feed.objects.count(), expected_feeds)
        ransomware_feed = Feed.objects.get(adapter_key="ransomware_live_victims")
        self.assertTrue(ransomware_feed.discord_enabled)
        self.assertEqual(
            ransomware_feed.discord_min_priority, Feed.DiscordPriority.P3
        )
        self.assertEqual(ransomware_feed.discord_mode, Feed.DiscordMode.DIGEST)
        normal_feeds = Feed.objects.exclude(adapter_key="ransomware_live_victims")
        self.assertFalse(normal_feeds.filter(discord_enabled=False).exists())
        self.assertFalse(
            normal_feeds.exclude(
                discord_min_priority=Feed.DiscordPriority.P3
            ).exists()
        )
        self.assertFalse(
            normal_feeds.exclude(discord_mode=Feed.DiscordMode.IMMEDIATE).exists()
        )

        output_second = StringIO()
        call_command("seed_sources", stdout=output_second)

        self.assertEqual(Source.objects.count(), expected_sources)
        self.assertEqual(Feed.objects.count(), expected_feeds)
        self.assertIn("sources_created=0", output_second.getvalue())
        self.assertIn("feeds_created=0", output_second.getvalue())

    def test_seed_sources_sync_updates_changed_feed_fields(self):
        call_command("seed_sources")

        feed = Feed.objects.select_related("source").get(source__slug="msrc")
        feed.section = Feed.Section.RESEARCH
        feed.enabled = False
        feed.timeout_seconds = 2
        feed.max_bytes = 512
        feed.max_age_days = 5
        feed.max_items_per_run = 5
        feed.discord_enabled = False
        feed.discord_min_priority = Feed.DiscordPriority.P1
        feed.discord_mode = Feed.DiscordMode.OFF
        feed.save(
            update_fields=[
                "section",
                "enabled",
                "timeout_seconds",
                "max_bytes",
                "max_age_days",
                "max_items_per_run",
                "discord_enabled",
                "discord_min_priority",
                "discord_mode",
                "updated_at",
            ]
        )

        # Default run preserves operator edits.
        call_command("seed_sources")
        feed.refresh_from_db()
        self.assertEqual(feed.section, Feed.Section.RESEARCH)
        self.assertFalse(feed.enabled)
        self.assertEqual(feed.timeout_seconds, 2)
        self.assertEqual(feed.max_bytes, 512)
        self.assertEqual(feed.max_age_days, 5)
        self.assertEqual(feed.max_items_per_run, 5)
        self.assertFalse(feed.discord_enabled)
        self.assertEqual(feed.discord_min_priority, Feed.DiscordPriority.P1)
        self.assertEqual(feed.discord_mode, Feed.DiscordMode.OFF)

        # --sync explicitly reconciles to tier defaults.
        call_command("seed_sources", "--sync")
        feed.refresh_from_db()

        expected = _find_feed_config("msrc")
        self.assertEqual(feed.section, expected["section"])
        self.assertEqual(feed.enabled, expected["enabled"])
        self.assertEqual(feed.timeout_seconds, expected["timeout_seconds"])
        self.assertEqual(feed.max_bytes, expected["max_bytes"])
        self.assertEqual(feed.max_age_days, expected["max_age_days"])
        self.assertEqual(feed.max_items_per_run, expected["max_items_per_run"])
        self.assertTrue(feed.discord_enabled)
        self.assertEqual(feed.discord_min_priority, Feed.DiscordPriority.P3)
        self.assertEqual(feed.discord_mode, Feed.DiscordMode.IMMEDIATE)

    def test_seed_sources_reconciles_manual_slug_mismatch(self):
        Source.objects.create(name="CERT-SE", slug="cert")

        call_command("seed_sources")

        cert = Source.objects.get(name="CERT-SE")
        self.assertEqual(cert.slug, "cert-se")
        self.assertEqual(Source.objects.filter(name="CERT-SE").count(), 1)
        self.assertFalse(Source.objects.filter(slug="cert").exists())

    def test_seed_sources_disables_known_broken_feed_urls(self):
        source = Source.objects.create(name="Legacy Source", slug="legacy-source")
        broken_url = next(iter(DISABLED_FEED_URLS))
        feed = Feed.objects.create(
            source=source,
            name="Legacy Broken Feed",
            url=broken_url,
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
            enabled=True,
        )

        call_command("seed_sources")
        feed.refresh_from_db()

        self.assertFalse(feed.enabled)
