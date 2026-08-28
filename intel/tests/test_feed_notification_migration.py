from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class FeedNotificationPolicyMigrationTests(TransactionTestCase):
    migrate_from = ("intel", "0011_darkhit_alert_state")
    migrate_to = (
        "intel",
        "0012_feed_discord_enabled_feed_discord_min_priority_and_more",
    )

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        Source = old_apps.get_model("intel", "Source")
        Feed = old_apps.get_model("intel", "Feed")

        source = Source.objects.create(name="Migration Source", slug="migration-source")
        Feed.objects.create(
            source=source,
            name="Existing Intel Feed",
            url="https://example.com/existing-intel.xml",
            feed_type="rss",
            adapter_key="",
            section="advisories",
        )
        Feed.objects.create(
            source=source,
            name="Existing Ransomware.live Feed",
            url="https://example.com/existing-ransomware.json",
            feed_type="json",
            adapter_key="ransomware_live_victims",
            section="active",
        )

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        self.apps = executor.loader.project_state([self.migrate_to]).apps

    def tearDown(self):
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
        super().tearDown()

    def test_existing_feeds_receive_predictable_notification_policy(self):
        Feed = self.apps.get_model("intel", "Feed")
        intel_feed = Feed.objects.get(name="Existing Intel Feed")
        ransomware_feed = Feed.objects.get(name="Existing Ransomware.live Feed")

        self.assertTrue(intel_feed.discord_enabled)
        self.assertEqual(intel_feed.discord_min_priority, "P3")
        self.assertEqual(intel_feed.discord_mode, "immediate")
        self.assertTrue(ransomware_feed.discord_enabled)
        self.assertEqual(ransomware_feed.discord_min_priority, "P3")
        self.assertEqual(ransomware_feed.discord_mode, "digest")
