import json
from dataclasses import replace
from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase, override_settings
from django.utils import timezone

from intel.dark_models import DarkHit, DarkSource
from intel.classification import classify_item
from intel.models import Feed, Item, Source
from intel.notifications import (
    build_dark_hit_alert_fingerprint,
    dark_hit_alert_reason,
    discord_priority_presentation,
    get_generic_intel_alert_context,
    send_dark_hit_alert,
    send_generic_intel_alert,
    send_high_epss_alert,
    send_ransomware_victim_alert,
    should_emit_dark_hit_alert,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dark_source(slug="test-onion", url="http://test.onion/"):
    return DarkSource.objects.create(
        name="Test Onion",
        slug=slug,
        url=url,
    )


def _make_dark_hit(
    source,
    title="Ransomware target found",
    excerpt="Some excerpt text",
    record_type="",
    matched_keywords=None,
    matched_regex=None,
    is_watch_match=True,
    victim_name="",
    group_name="",
    country="",
    industry="",
    website_url="",
    last_activity_text="",
):
    import hashlib
    content_hash = hashlib.md5(f"{source.slug}{title}".encode()).hexdigest()
    return DarkHit.objects.create(
        dark_source=source,
        title=title,
        excerpt=excerpt,
        url=source.url,
        content_hash=content_hash,
        matched_keywords=matched_keywords if matched_keywords is not None else ["ransomware", "credentials"],
        matched_regex=matched_regex if matched_regex is not None else [],
        is_watch_match=is_watch_match,
        record_type=record_type,
        victim_name=victim_name,
        group_name=group_name,
        country=country,
        industry=industry,
        website_url=website_url,
        last_activity_text=last_activity_text,
    )


def _make_item(title="CVE-2024-1234 \u2014 EPSS 85.0%", url="https://www.cve.org/CVERecord?id=CVE-2024-1234"):
    source = Source.objects.create(name="FIRST.org EPSS", slug="epss-test")
    feed = Feed.objects.create(
        source=source,
        name="EPSS Feed",
        url="https://api.first.org/data/v1/epss",
        feed_type=Feed.FeedType.JSON,
        adapter_key="epss",
        section=Feed.Section.ACTIVE,
        discord_enabled=True,
        discord_min_priority=Feed.DiscordPriority.P3,
        discord_mode=Feed.DiscordMode.IMMEDIATE,
        max_age_days=14,
        max_items_per_run=200,
    )
    return Item.objects.create(
        source=source,
        feed=feed,
        title=title,
        url=url,
        summary="EPSS score: 85.0% (percentile: 99.9%). High likelihood of exploitation.",
        published_at=timezone.now(),
    )


def _make_generic_item(
    *,
    section=Feed.Section.ADVISORIES,
    adapter_key="",
    source_name="Intel Source",
    source_slug="intel-source",
    title="Critical advisory for CVE-2026-1111",
    summary="Urgent remote code execution issue under active investigation.",
    url="https://example.com/high-signal",
    raw_payload=None,
    discord_enabled=True,
    discord_min_priority=Feed.DiscordPriority.P3,
    discord_mode=Feed.DiscordMode.IMMEDIATE,
):
    source = Source.objects.create(name=source_name, slug=source_slug)
    feed = Feed.objects.create(
        source=source,
        name=f"{source_name} Feed",
        url=f"https://example.com/{source_slug}.xml",
        feed_type=Feed.FeedType.RSS,
        adapter_key=adapter_key,
        section=section,
        discord_enabled=discord_enabled,
        discord_min_priority=discord_min_priority,
        discord_mode=discord_mode,
        max_age_days=14,
        max_items_per_run=200,
    )
    return Item.objects.create(
        source=source,
        feed=feed,
        title=title,
        url=url,
        summary=summary,
        raw_payload=raw_payload or {},
        published_at=timezone.now(),
    )


# ---------------------------------------------------------------------------
# Feed notification policy tests
# ---------------------------------------------------------------------------

class FeedNotificationPolicyTests(TestCase):
    def test_new_feed_defaults_to_explicitly_disabled_notifications(self):
        source = Source.objects.create(name="Manual Source", slug="manual-source")
        feed = Feed.objects.create(
            source=source,
            name="Manual Feed",
            url="https://example.com/manual.xml",
        )

        self.assertFalse(feed.discord_enabled)
        self.assertEqual(feed.discord_mode, Feed.DiscordMode.OFF)
        self.assertEqual(feed.discord_min_priority, Feed.DiscordPriority.P3)
        self.assertFalse(feed.allows_immediate_discord("P1"))


# ---------------------------------------------------------------------------
# Global notification kill switch tests
# ---------------------------------------------------------------------------

class NotificationKillSwitchTests(TestCase):
    @override_settings(
        NOTIFICATIONS_ENABLED=False,
        INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/token",
    )
    def test_generic_intel_alert_makes_no_request_when_notifications_disabled(self):
        item = _make_generic_item(section=Feed.Section.SWEDEN)
        context = get_generic_intel_alert_context(item)
        self.assertIsNotNone(context)

        with (
            patch("intel.notifications._intel_webhook") as mock_webhook,
            patch("intel.notifications.requests.post") as mock_post,
        ):
            send_generic_intel_alert(item, **context)

        mock_post.assert_not_called()
        mock_webhook.assert_not_called()

    @override_settings(
        NOTIFICATIONS_ENABLED=False,
        INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/epss/token",
        EPSS_ALERT_THRESHOLD=0.7,
    )
    def test_epss_alert_makes_no_request_when_notifications_disabled(self):
        item = _make_item(title="CVE-2024-1234 — EPSS 85.0%")

        with (
            patch("intel.notifications._intel_webhook") as mock_webhook,
            patch("intel.notifications.requests.post") as mock_post,
        ):
            send_high_epss_alert(item)

        mock_post.assert_not_called()
        mock_webhook.assert_not_called()

    @override_settings(
        NOTIFICATIONS_ENABLED=False,
        INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/ransomware/token",
    )
    def test_ransomware_alert_makes_no_request_when_notifications_disabled(self):
        item = _make_item(title="New ransomware victim")

        with (
            patch("intel.notifications._intel_webhook") as mock_webhook,
            patch("intel.notifications.requests.post") as mock_post,
        ):
            send_ransomware_victim_alert(item)

        mock_post.assert_not_called()
        mock_webhook.assert_not_called()

    @override_settings(
        NOTIFICATIONS_ENABLED=False,
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/dark/token",
    )
    def test_dark_watch_alert_makes_no_request_when_notifications_disabled(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, record_type="incident")

        with (
            patch("intel.notifications._dark_webhook") as mock_webhook,
            patch("intel.notifications.requests.post") as mock_post,
        ):
            send_dark_hit_alert(hit)

        mock_post.assert_not_called()
        mock_webhook.assert_not_called()


# ---------------------------------------------------------------------------
# DarkHit alert tests
# ---------------------------------------------------------------------------

@override_settings(NOTIFICATIONS_ENABLED=True)
class DarkHitAlertTests(TestCase):

    @override_settings(DARK_DISCORD_WEBHOOK="")
    def test_dark_hit_no_webhook(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source)
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_not_called()

    @override_settings(
        DARK_DISCORD_WEBHOOK="",
        INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/not-a-fallback",
    )
    def test_dark_hit_never_falls_back_to_intel_webhook(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, record_type="incident")

        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)

        mock_post.assert_not_called()

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_incident_dark_hit_sends_correct_payload(self):
        source = _make_dark_source()
        hit = _make_dark_hit(
            source,
            title="Breach data found",
            excerpt="Akira targeted the Swedish victim portal.",
            record_type="incident",
            matched_keywords=["akira", "swedish"],
            matched_regex=[r"victim"],
            victim_name="Nordic Victim",
            group_name="Akira",
            country="Sweden",
        )
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit, why_alerted="new finding")
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            sent_json = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
            embed = sent_json["embeds"][0]
            self.assertEqual(embed["title"], "Breach data found")
            self.assertIn(
                {"name": "Regex matched", "value": r"victim", "inline": True},
                embed["fields"],
            )
            self.assertIn(
                {"name": "Matched in", "value": "victim, group, details", "inline": True},
                embed["fields"],
            )
            self.assertIn(
                {"name": "Why alerted", "value": "new finding", "inline": True},
                embed["fields"],
            )

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_group_dark_hit_does_not_send_alert(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, title="Black Basta", record_type="group")
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_not_called()

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_unmatched_incident_dark_hit_does_not_send_alert(self):
        source = _make_dark_source()
        hit = _make_dark_hit(
            source,
            title="Context only",
            record_type="incident",
            matched_keywords=[],
            is_watch_match=False,
        )
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_not_called()

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_dark_hit_request_fails(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, record_type="incident")
        with patch(
            "intel.notifications.requests.post",
            side_effect=requests.RequestException("connection refused"),
        ):
            # Must not raise
            send_dark_hit_alert(hit)

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_dark_hit_onion_url_masked(self):
        source = _make_dark_source(url="http://abc123xyz.onion/secret-forum")
        hit = _make_dark_hit(source, record_type="incident")
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            sent_json = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
            payload_str = json.dumps(sent_json)
            self.assertNotIn(".onion", payload_str)

    def test_identical_recent_dark_hit_fingerprint_is_suppressed(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, record_type="incident")
        fingerprint = build_dark_hit_alert_fingerprint(
            record_type="incident",
            title=hit.title,
            excerpt=hit.excerpt,
            url=hit.url,
            matched_keywords=hit.matched_keywords,
            matched_regex=hit.matched_regex,
        )
        hit.last_alerted_at = timezone.now()
        hit.last_alert_fingerprint = fingerprint
        hit.save(update_fields=["last_alerted_at", "last_alert_fingerprint"])

        self.assertFalse(
            should_emit_dark_hit_alert(
                is_watch_match=True,
                record_type="incident",
                current_alert_fingerprint=fingerprint,
                previous_alert_hit=hit,
            )
        )

    def test_dark_hit_alert_reason_prefers_specific_keyword_change_reason(self):
        source = _make_dark_source()
        previous_hit = _make_dark_hit(
            source,
            record_type="incident",
            matched_keywords=["akira"],
            group_name="Akira",
            country="Sweden",
        )
        previous_hit.last_alerted_at = timezone.now()
        previous_hit.save(update_fields=["last_alerted_at"])

        reason = dark_hit_alert_reason(
            previous_hit,
            record_values={
                "group_name": "Akira",
                "country": "Sweden",
                "industry": "",
                "url": previous_hit.url,
                "victim_name": previous_hit.victim_name,
                "title": previous_hit.title,
                "website_url": previous_hit.website_url,
                "excerpt": previous_hit.excerpt,
            },
            keyword_matches=["akira", "sweden"],
            regex_matches=[],
        )

        self.assertEqual(reason, "Sweden keyword match")


# ---------------------------------------------------------------------------
# EPSS alert tests
# ---------------------------------------------------------------------------

@override_settings(NOTIFICATIONS_ENABLED=True)
class EPSSAlertTests(TestCase):

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/epss/token", EPSS_ALERT_THRESHOLD=0.7)
    def test_epss_above_threshold(self):
        item = _make_item(title="CVE-2024-1234 \u2014 EPSS 85.0%")
        with patch("intel.notifications.requests.post") as mock_post:
            send_high_epss_alert(item)
            mock_post.assert_called_once()

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/epss/token", EPSS_ALERT_THRESHOLD=0.7)
    def test_epss_below_threshold(self):
        item = _make_item(title="CVE-2024-5678 \u2014 EPSS 50.0%")
        with patch("intel.notifications.requests.post") as mock_post:
            send_high_epss_alert(item)
            mock_post.assert_not_called()

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/epss/token", EPSS_ALERT_THRESHOLD=0.7)
    def test_epss_no_match_in_title(self):
        item = _make_item(title="Something without EPSS score here")
        with patch("intel.notifications.requests.post") as mock_post:
            send_high_epss_alert(item)
            mock_post.assert_not_called()

    @override_settings(
        INTEL_DISCORD_WEBHOOK="",
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/dark/fallback",
        EPSS_ALERT_THRESHOLD=0.7,
    )
    def test_epss_never_falls_back_to_dark_webhook(self):
        item = _make_item(title="CVE-2024-9999 \u2014 EPSS 90.0%")
        with patch("intel.notifications.requests.post") as mock_post:
            send_high_epss_alert(item)
            mock_post.assert_not_called()


@override_settings(NOTIFICATIONS_ENABLED=True)
class GenericIntelAlertTests(TestCase):
    def test_generic_intel_alert_context_accepts_high_signal_active_item(self):
        item = _make_generic_item(
            section=Feed.Section.ACTIVE,
            title="VPN gateway targeted in the wild",
            summary="Authentication bypass is actively exploited in the wild.",
        )

        context = get_generic_intel_alert_context(item)

        self.assertIsNotNone(context)
        self.assertEqual(
            context["profile"].primary_reason,
            "Active exploitation in summary",
        )

    def test_generic_selection_consumes_classify_item_once(self):
        item = _make_generic_item(
            section=Feed.Section.ACTIVE,
            title="CISA warns vulnerability is actively exploited",
            summary="The vulnerability is actively exploited in the wild.",
        )

        with patch("intel.notifications.classify_item", wraps=classify_item) as mock_classify:
            context = get_generic_intel_alert_context(item)

        self.assertIsNotNone(context)
        mock_classify.assert_called_once_with(item)

    def test_generic_intel_alert_context_rejects_low_signal_release_notes(self):
        item = _make_generic_item(
            section=Feed.Section.RESEARCH,
            title="Platform maintenance release notes",
            summary="Routine product update and version availability notice.",
        )

        self.assertIsNone(get_generic_intel_alert_context(item))

    def test_feed_notification_switch_disables_generic_selection(self):
        item = _make_generic_item(
            section=Feed.Section.ACTIVE,
            title="CISA warns vulnerability is actively exploited",
            summary="The vulnerability is actively exploited in the wild.",
            discord_enabled=False,
        )

        self.assertIsNone(get_generic_intel_alert_context(item))

    def test_feed_minimum_priority_suppresses_lower_priority(self):
        item = _make_generic_item(section=Feed.Section.ACTIVE)
        item.feed.discord_min_priority = Feed.DiscordPriority.P2
        item.feed.save(update_fields=["discord_min_priority"])
        profile = replace(classify_item(item), priority="P3")

        with patch("intel.notifications.classify_item", return_value=profile):
            self.assertIsNone(get_generic_intel_alert_context(item))

        self.assertTrue(item.feed.allows_immediate_discord("P1"))
        self.assertTrue(item.feed.allows_immediate_discord("P2"))
        self.assertFalse(item.feed.allows_immediate_discord("P3"))
        self.assertFalse(item.feed.allows_immediate_discord("P4"))

    def test_immediate_mode_allows_eligible_generic_selection(self):
        item = _make_generic_item(section=Feed.Section.ACTIVE)
        profile = replace(classify_item(item), priority="P3")

        with patch("intel.notifications.classify_item", return_value=profile):
            self.assertIsNotNone(get_generic_intel_alert_context(item))

    def test_off_and_digest_modes_suppress_immediate_delivery(self):
        for mode in (Feed.DiscordMode.OFF, Feed.DiscordMode.DIGEST):
            with self.subTest(mode=mode):
                item = _make_generic_item(
                    section=Feed.Section.ACTIVE,
                    source_name=f"Intel {mode}",
                    source_slug=f"intel-{mode}",
                    url=f"https://example.com/{mode}",
                    discord_mode=mode,
                )
                self.assertIsNone(get_generic_intel_alert_context(item))

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/token")
    def test_send_generic_intel_alert_includes_summary_and_reason(self):
        item = _make_generic_item(
            section=Feed.Section.SWEDEN,
            title="CVE-2026-2222: Nordic CERT warns of credential theft campaign",
            summary="Swedish organizations are targeted in a credential theft campaign.",
            raw_payload={"country": "Sweden"},
        )

        context = get_generic_intel_alert_context(item)
        self.assertIsNotNone(context)

        with patch("intel.notifications.requests.post") as mock_post:
            send_generic_intel_alert(item, **context)

        mock_post.assert_called_once()
        sent_json = mock_post.call_args.kwargs.get("json") or mock_post.call_args.args[1]
        embed = sent_json["embeds"][0]
        profile = context["profile"]
        priority_label, expected_color = discord_priority_presentation(profile.priority)
        self.assertEqual(
            embed["title"],
            f"{profile.priority} {priority_label} intel: {item.title}",
        )
        self.assertEqual(embed["color"], expected_color)
        self.assertEqual(
            embed["description"],
            "Swedish organizations are targeted in a credential theft campaign.",
        )
        self.assertIn(
            {"name": "Why alerted", "value": profile.primary_reason, "inline": True},
            embed["fields"],
        )
        self.assertIn(
            {"name": "CVE", "value": "CVE-2026-2222", "inline": True},
            embed["fields"],
        )
        self.assertIn(
            {"name": "Country", "value": "Sweden", "inline": True},
            embed["fields"],
        )

    @override_settings(
        INTEL_DISCORD_WEBHOOK="",
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/dark/not-a-fallback",
    )
    def test_generic_intel_never_falls_back_to_dark_webhook(self):
        item = _make_generic_item(section=Feed.Section.SWEDEN)
        context = get_generic_intel_alert_context(item)
        self.assertIsNotNone(context)

        with patch("intel.notifications.requests.post") as mock_post:
            send_generic_intel_alert(item, **context)

        mock_post.assert_not_called()

    def test_priority_colors_are_deterministic(self):
        self.assertEqual(discord_priority_presentation("P1"), ("Critical", 0xDC2626))
        self.assertEqual(discord_priority_presentation("P2"), ("High", 0xF97316))
        self.assertEqual(discord_priority_presentation("P3"), ("Medium", 0xF59E0B))
        self.assertEqual(
            discord_priority_presentation("P4"),
            ("Low / informational", 0x3B82F6),
        )

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/secret-token")
    def test_non_2xx_response_is_safely_logged_without_webhook_secret(self):
        item = _make_generic_item(section=Feed.Section.SWEDEN)
        context = get_generic_intel_alert_context(item)
        self.assertIsNotNone(context)
        response = MagicMock(status_code=429)
        error = requests.HTTPError(
            "429 Client Error for url: https://discord.com/api/webhooks/intel/secret-token",
            response=response,
        )
        response.raise_for_status.side_effect = error

        with (
            self.assertLogs("intel.notifications", level="WARNING") as captured,
            patch("intel.notifications.requests.post", return_value=response),
        ):
            send_generic_intel_alert(item, **context)

        log_output = " ".join(captured.output)
        self.assertIn("HTTP status 429", log_output)
        self.assertNotIn("secret-token", log_output)

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/secret-token")
    def test_redirect_response_is_treated_as_delivery_failure(self):
        item = _make_generic_item(section=Feed.Section.SWEDEN)
        context = get_generic_intel_alert_context(item)
        self.assertIsNotNone(context)
        response = MagicMock(status_code=302)

        with (
            self.assertLogs("intel.notifications", level="WARNING") as captured,
            patch("intel.notifications.requests.post", return_value=response),
        ):
            send_generic_intel_alert(item, **context)

        self.assertIn("HTTP status 302", " ".join(captured.output))


@override_settings(NOTIFICATIONS_ENABLED=True)
class RansomwareAlertTests(TestCase):
    def _make_ransomware_item(self, *, mode=Feed.DiscordMode.IMMEDIATE):
        return _make_generic_item(
            adapter_key="ransomware_live_victims",
            source_name="Ransomware.live",
            source_slug=f"ransomware-live-{mode}",
            title="Acme AB listed by Akira",
            summary="Ransomware.live reports Acme AB as a new Akira victim.",
            raw_payload={"victim": "Acme AB", "group": "akira", "country": "SE"},
            discord_mode=mode,
        )

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/token")
    def test_explicit_immediate_policy_uses_specialized_ransomware_path(self):
        item = self._make_ransomware_item()

        with patch("intel.notifications.requests.post") as mock_post:
            send_ransomware_victim_alert(item)

        mock_post.assert_called_once()
        self.assertEqual(
            mock_post.call_args.args[0],
            "https://discord.com/api/webhooks/intel/token",
        )
        embed = mock_post.call_args.kwargs["json"]["embeds"][0]
        self.assertIn("Ransomware Victim", embed["title"])

    @override_settings(INTEL_DISCORD_WEBHOOK="https://discord.com/api/webhooks/intel/token")
    def test_digest_policy_does_not_immediately_send_ransomware_victim(self):
        item = self._make_ransomware_item(mode=Feed.DiscordMode.DIGEST)

        with patch("intel.notifications.requests.post") as mock_post:
            send_ransomware_victim_alert(item)

        mock_post.assert_not_called()

    @override_settings(
        INTEL_DISCORD_WEBHOOK="",
        DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/dark/not-a-fallback",
    )
    def test_ransomware_never_falls_back_to_dark_webhook(self):
        item = self._make_ransomware_item()

        with patch("intel.notifications.requests.post") as mock_post:
            send_ransomware_victim_alert(item)

        mock_post.assert_not_called()
