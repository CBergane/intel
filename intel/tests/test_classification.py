from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.classification import classify_item
from intel.models import Feed, Item, Source
from intel.notifications import get_generic_intel_alert_context


class SignalClassificationTests(TestCase):
    def setUp(self):
        self._index = 0

    def _make_item(
        self,
        *,
        title: str,
        summary: str = "",
        section: str = Feed.Section.ACTIVE,
        adapter_key: str = "",
        source_name: str = "Intel Source",
        source_slug: str = "intel-source",
        source_tags=None,
        raw_payload=None,
    ) -> Item:
        self._index += 1
        unique_slug = f"{source_slug}-{self._index}"
        source = Source.objects.create(
            name=f"{source_name} {self._index}",
            slug=unique_slug,
            tags=source_tags or [],
        )
        feed = Feed.objects.create(
            source=source,
            name=f"{source_name} Feed {self._index}",
            url=f"https://example.com/{unique_slug}.xml",
            feed_type=Feed.FeedType.JSON if adapter_key else Feed.FeedType.RSS,
            adapter_key=adapter_key,
            section=section,
        )
        return Item.objects.create(
            source=source,
            feed=feed,
            title=title,
            summary=summary,
            raw_payload=raw_payload or {},
            url=f"https://example.com/items/{self._index}",
            stable_id="",
            published_at=timezone.now(),
        )

    def test_active_feed_news_is_not_active_exploitation_without_evidence(self):
        item = self._make_item(
            source_name="Bleeping Computer",
            source_slug="bleeping-computer",
            source_tags=["news", "ransomware", "incident"],
            section=Feed.Section.ACTIVE,
            title="Windows adds a new account backup option",
            summary="A general security technology story with deployment details.",
        )

        profile = classify_item(item)

        self.assertFalse(profile.active_exploitation)
        self.assertTrue(profile.threat_news)
        self.assertFalse(profile.ransomware)
        self.assertEqual(profile.primary_category, "threat_news")
        self.assertNotIn("active_exploitation", profile.categories)
        self.assertEqual(profile.active_exploitation_evidence, "")
        self.assertEqual(profile.priority, "P4")

    def test_cisa_kev_is_authoritative_active_exploitation_evidence(self):
        item = self._make_item(
            source_name="CISA",
            source_slug="cisa",
            adapter_key="cisa_kev",
            title="CVE-2026-1001 - Example Vendor Gateway",
        )

        profile = classify_item(item)

        self.assertTrue(profile.active_exploitation)
        self.assertTrue(profile.vulnerability)
        self.assertEqual(profile.primary_category, "active_exploitation")
        self.assertIn("CISA KEV", profile.reasons)
        self.assertEqual(profile.active_exploitation_evidence, "authoritative")
        self.assertEqual(profile.priority, "P1")
        self.assertLessEqual(profile.score, 100)

    def test_explicit_in_the_wild_wording_is_active_exploitation_evidence(self):
        item = self._make_item(
            section=Feed.Section.ADVISORIES,
            title="Vendor confirms gateway attacks",
            summary="The vulnerability is actively exploited in the wild.",
        )

        profile = classify_item(item)

        self.assertTrue(profile.active_exploitation)
        self.assertIn("Active exploitation in summary", profile.reasons)
        self.assertEqual(profile.active_exploitation_evidence, "summary")
        self.assertEqual(profile.priority, "P2")

    def test_explicit_title_wording_is_active_exploitation_evidence(self):
        item = self._make_item(
            section=Feed.Section.ADVISORIES,
            title=(
                "CISA orders agencies to patch vulnerability actively exploited "
                "in the wild"
            ),
        )

        profile = classify_item(item)

        self.assertTrue(profile.active_exploitation)
        self.assertEqual(profile.active_exploitation_evidence, "title")
        self.assertIn("Active exploitation in title", profile.reasons)

    def test_actor_exploitation_wording_in_title_is_strong_evidence(self):
        item = self._make_item(
            title=(
                "State-supported cyber actors exploit industrial controllers "
                "across critical infrastructure"
            ),
        )

        profile = classify_item(item)

        self.assertTrue(profile.active_exploitation)
        self.assertEqual(profile.active_exploitation_evidence, "title")

    def test_critical_zero_day_rce_cve_is_not_exploitation_without_evidence(self):
        item = self._make_item(
            section=Feed.Section.ADVISORIES,
            title="Critical zero-day RCE in CVE-2026-2002",
            summary="CVSS 10 authentication bypass; apply the vendor patch.",
        )

        profile = classify_item(item)

        self.assertTrue(profile.vulnerability)
        self.assertTrue(profile.urgent)
        self.assertFalse(profile.active_exploitation)
        self.assertIn("CVE referenced", profile.reasons)
        self.assertEqual(profile.active_exploitation_evidence, "")
        self.assertEqual(profile.priority, "P3")

    def test_ransomware_live_victim_is_ransomware_but_not_active_exploitation(self):
        item = self._make_item(
            adapter_key="ransomware_live_victims",
            title="Akira: Example AB",
            raw_payload={
                "victim": "Example AB",
                "group": "akira",
                "country": "Sweden",
            },
        )

        profile = classify_item(item)

        self.assertTrue(profile.ransomware)
        self.assertFalse(profile.active_exploitation)
        self.assertEqual(profile.primary_category, "ransomware")
        self.assertIn("Ransomware.live victim", profile.reasons)
        self.assertEqual(profile.ransomware_evidence, "authoritative")

    def test_research_feed_is_research_without_implied_exploitation(self):
        item = self._make_item(
            section=Feed.Section.RESEARCH,
            source_tags=["research"],
            title="Analysis of phishing infrastructure trends",
        )

        profile = classify_item(item)

        self.assertTrue(profile.research)
        self.assertFalse(profile.active_exploitation)
        self.assertEqual(profile.primary_category, "research")

    def test_cert_se_item_is_nordic_without_implied_exploitation(self):
        item = self._make_item(
            section=Feed.Section.SWEDEN,
            source_name="CERT-SE",
            source_slug="cert-se",
            source_tags=["government", "sweden"],
            title="Veckans säkerhetsöversikt",
        )

        profile = classify_item(item)

        self.assertTrue(profile.nordic_relevance)
        self.assertFalse(profile.active_exploitation)
        self.assertEqual(profile.primary_category, "nordic")
        self.assertIn("Nordic source or metadata", profile.reasons)
        self.assertEqual(profile.nordic_evidence, "metadata")
        self.assertEqual(profile.priority, "P4")

    def test_epss_probability_text_is_not_observed_active_exploitation(self):
        item = self._make_item(
            adapter_key="epss",
            title="CVE-2026-3003 — EPSS 91.0%",
            summary=(
                "EPSS score: 91.0%. High likelihood of exploitation in the wild "
                "within 30 days."
            ),
        )

        profile = classify_item(item)

        self.assertTrue(profile.vulnerability)
        self.assertFalse(profile.active_exploitation)
        self.assertEqual(profile.active_exploitation_evidence, "")

    def test_negated_exploitation_wording_is_not_positive_evidence(self):
        summaries = (
            "The vulnerability is not exploited in the wild.",
            "The vulnerability is not known to be actively exploited.",
            "There is no evidence of exploitation in the wild.",
            "The issue has not been exploited in the wild.",
            "There is no known active exploitation.",
            "The activity was not observed in the wild.",
            "The vendor is not aware of exploitation in the wild.",
            "Active exploitation has not been observed.",
            "None are listed as actively exploited.",
            "The issue is no longer actively exploited.",
        )

        for summary in summaries:
            with self.subTest(summary=summary):
                item = self._make_item(
                    section=Feed.Section.ADVISORIES,
                    title="Critical CVE-2026-4004 vendor advisory",
                    summary=summary,
                )
                profile = classify_item(item)

                self.assertTrue(profile.vulnerability)
                self.assertFalse(profile.active_exploitation)
                self.assertEqual(profile.active_exploitation_evidence, "")

    def test_hardening_release_with_negated_exploitation_is_not_active(self):
        item = self._make_item(
            section=Feed.Section.ADVISORIES,
            source_name="Cisco",
            source_slug="cisco",
            source_tags=["vendor", "network"],
            title="Cisco Security Hardening Release: August 2026",
            summary=(
                "An internal security review found several vulnerabilities. "
                "These vulnerabilities are not known to be actively exploited. "
                "Cisco has released software updates."
            ),
        )

        profile = classify_item(item)

        self.assertFalse(profile.active_exploitation)
        self.assertTrue(profile.vulnerability)

    def test_pwn2own_announcement_ignores_historical_body_mentions(self):
        item = self._make_item(
            section=Feed.Section.RESEARCH,
            source_name="ZDI",
            source_slug="zdi",
            source_tags=["research", "threat-intel"],
            title="Announcing Pwn2Own Berlin for 2026",
            summary=(
                "The contest returns with new categories, targets, prizes, and rules. "
                + "Competitors can review the published contest details. " * 60
                + "Servers are targeted by ransomware crews. Last year's bugs were "
                "later exploited in the wild."
            ),
        )

        profile = classify_item(item)

        self.assertFalse(profile.active_exploitation)
        self.assertFalse(profile.ransomware)

    def test_security_roundup_ignores_single_covered_ransomware_item(self):
        item = self._make_item(
            section=Feed.Section.RESEARCH,
            source_name="ZDI",
            source_slug="zdi",
            source_tags=["research", "threat-intel"],
            title="The August 2026 Security Update Review",
            summary=(
                "This monthly review summarizes security patches from several vendors. "
                "One covered vulnerability is actively exploited in the wild. "
                + "The roundup covers the latest software updates and fixes. " * 60
                + "One privilege issue may be paired with code execution in ransomware."
            ),
        )

        profile = classify_item(item)

        self.assertFalse(profile.active_exploitation)
        self.assertFalse(profile.ransomware)

    def test_true_ransomware_article_title_remains_ransomware(self):
        item = self._make_item(
            section=Feed.Section.ACTIVE,
            source_tags=["news"],
            title="Ransomware campaign targets European hospitals",
            summary=(
                "The campaign encrypted hospital systems and published stolen data."
            ),
        )

        profile = classify_item(item)

        self.assertTrue(profile.ransomware)
        self.assertEqual(profile.ransomware_evidence, "title")
        self.assertIn("Ransomware or extortion in title", profile.reasons)

    def test_incidental_long_article_mentions_do_not_create_strong_signals(self):
        item = self._make_item(
            section=Feed.Section.ACTIVE,
            source_name="CISA",
            source_slug="cisa",
            source_tags=["government", "us"],
            title=(
                "Russian State-Supported Cyber Actors Conduct Phishing Campaign "
                "Targeting Users of Zimbra Collaboration Suite"
            ),
            summary=(
                "The advisory describes a phishing and espionage campaign targeting "
                "Zimbra users in several Western governments. "
                + "The report documents campaign tradecraft and mitigations. " * 30
                + "Authoring partners include agencies in Sweden, Denmark, and Finland. "
                "There is an absence of known financial extortion. Administrators can "
                "consult the Known Exploited Vulnerabilities Catalog and guidance on "
                "responding to active exploitation."
            ),
        )

        profile = classify_item(item)

        self.assertFalse(profile.active_exploitation)
        self.assertFalse(profile.ransomware)
        self.assertFalse(profile.nordic_relevance)

    def test_generic_notification_selection_consumes_central_classifier(self):
        item = self._make_item(
            section=Feed.Section.RESEARCH,
            title="VPN campaign investigation",
            summary="The flaw is exploited in the wild against internet-facing systems.",
        )
        item.feed.discord_enabled = True
        item.feed.discord_mode = Feed.DiscordMode.IMMEDIATE
        item.feed.save(update_fields=["discord_enabled", "discord_mode"])

        with patch(
            "intel.notifications.classify_item",
            wraps=classify_item,
        ) as mock_classify:
            context = get_generic_intel_alert_context(item)

        mock_classify.assert_called_once_with(item)
        self.assertEqual(
            context["profile"].primary_reason,
            "Active exploitation in summary",
        )


class ActiveViewClassificationTests(TestCase):
    def _make_item(
        self,
        *,
        source_slug: str,
        section: str,
        title: str,
        summary: str,
        source_tags=None,
    ) -> Item:
        source = Source.objects.create(
            name=source_slug.replace("-", " ").title(),
            slug=source_slug,
            tags=source_tags or [],
        )
        feed = Feed.objects.create(
            source=source,
            name=f"{source.name} Feed",
            url=f"https://example.com/{source_slug}.xml",
            feed_type=Feed.FeedType.RSS,
            section=section,
        )
        return Item.objects.create(
            source=source,
            feed=feed,
            title=title,
            summary=summary,
            url=f"https://example.com/{source_slug}/item",
            stable_id="",
            published_at=timezone.now(),
        )

    def test_active_view_excludes_active_section_news_without_exploitation_evidence(self):
        title = "Security company releases a new backup feature"
        self._make_item(
            source_slug="generic-active-news",
            source_tags=["news"],
            section=Feed.Section.ACTIVE,
            title=title,
            summary="General product and security industry news.",
        )

        response = self.client.get(reverse("active"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, title)
        self.assertEqual(response.context["filtered_total"], 0)

    def test_active_view_includes_evidence_from_non_active_feed(self):
        title = "Vendor confirms active exploitation of gateway flaw"
        self._make_item(
            source_slug="vendor-advisory",
            section=Feed.Section.ADVISORIES,
            title=title,
            summary="Attackers are actively exploiting the issue in the wild.",
        )

        response = self.client.get(reverse("active"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, title)
        self.assertEqual(response.context["filtered_total"], 1)
