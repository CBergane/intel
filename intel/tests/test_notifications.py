import json
from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase, override_settings
from django.utils import timezone

from intel.dark_models import DarkHit, DarkSource
from intel.models import Feed, Item, Source
from intel.notifications import send_dark_hit_alert, send_high_epss_alert


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
):
    import hashlib
    content_hash = hashlib.md5(f"{source.slug}{title}".encode()).hexdigest()
    return DarkHit.objects.create(
        dark_source=source,
        title=title,
        excerpt=excerpt,
        url=source.url,
        content_hash=content_hash,
        matched_keywords=["ransomware", "credentials"],
        record_type=record_type,
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


# ---------------------------------------------------------------------------
# DarkHit alert tests
# ---------------------------------------------------------------------------

class DarkHitAlertTests(TestCase):

    @override_settings(DARK_DISCORD_WEBHOOK="")
    def test_dark_hit_no_webhook(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source)
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_not_called()

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_incident_dark_hit_sends_correct_payload(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, title="Breach data found", record_type="incident")
        with patch("intel.notifications.requests.post") as mock_post:
            send_dark_hit_alert(hit)
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            sent_json = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
            embed = sent_json["embeds"][0]
            self.assertEqual(embed["title"], "Breach data found")

    @override_settings(DARK_DISCORD_WEBHOOK="https://discord.com/api/webhooks/test/token")
    def test_group_dark_hit_does_not_send_alert(self):
        source = _make_dark_source()
        hit = _make_dark_hit(source, title="Black Basta", record_type="group")
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


# ---------------------------------------------------------------------------
# EPSS alert tests
# ---------------------------------------------------------------------------

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
    def test_intel_webhook_fallback(self):
        item = _make_item(title="CVE-2024-9999 \u2014 EPSS 90.0%")
        with patch("intel.notifications.requests.post") as mock_post:
            send_high_epss_alert(item)
            mock_post.assert_called_once()
            call_url = mock_post.call_args.args[0]
            self.assertIn("fallback", call_url)
