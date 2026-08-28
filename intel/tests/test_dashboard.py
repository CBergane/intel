from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.classification import classify_item
from intel.models import Feed, Item, Source


class DashboardViewTests(TestCase):
    def setUp(self):
        self._idx = 0

    def _create_feed(
        self,
        *,
        source_name,
        source_slug,
        section,
        tags=None,
        adapter_key="",
        feed_type=Feed.FeedType.RSS,
    ):
        source = Source.objects.create(
            name=source_name,
            slug=source_slug,
            tags=tags or [],
        )
        return Feed.objects.create(
            source=source,
            name=f"{source_name} Feed",
            url=f"https://example.com/{source_slug}-{section}.xml",
            feed_type=feed_type,
            section=section,
            adapter_key=adapter_key,
        )

    def _create_item(
        self,
        *,
        feed,
        title,
        summary="",
        age_hours=0,
        age_days=0,
        published_at=None,
        raw_payload=None,
    ):
        self._idx += 1
        return Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            summary=summary,
            raw_payload=raw_payload or {},
            url=f"https://example.com/item-{self._idx}",
            stable_id="",
            published_at=published_at
            or (timezone.now() - timedelta(hours=age_hours, days=age_days)),
        )

    def test_now_renders_threat_pulse_from_authoritative_profiles(self):
        feed = self._create_feed(
            source_name="Exploit Desk",
            source_slug="exploit-desk",
            section=Feed.Section.ADVISORIES,
        )
        p1_item = self._create_item(
            feed=feed,
            title="Critical CVE-2026-7001 actively exploited in the wild",
            summary="Emergency remediation required.",
            age_hours=1,
        )
        p2_item = self._create_item(
            feed=feed,
            title="Service flaw actively exploited in the wild",
            age_hours=2,
        )

        response = self.client.get(reverse("now"))
        pulse = response.context["threat_pulse"]

        self.assertEqual(classify_item(p1_item).priority, "P1")
        self.assertEqual(classify_item(p2_item).priority, "P2")
        self.assertEqual(pulse["p1"], 1)
        self.assertEqual(pulse["p2"], 1)
        self.assertEqual(pulse["active"], 2)
        self.assertContains(response, "Threat Pulse")
        self.assertContains(response, 'data-dashboard-section="threat-pulse"', html=False)

    def test_priority_stream_uses_classifier_priority_and_deterministic_order(self):
        feed = self._create_feed(
            source_name="Priority Desk",
            source_slug="priority-desk",
            section=Feed.Section.ADVISORIES,
        )
        same_time = timezone.now() - timedelta(hours=1)
        older_p1 = self._create_item(
            feed=feed,
            title="CVE-2026-7101 actively exploited in the wild",
            published_at=same_time,
        )
        newer_id_p1 = self._create_item(
            feed=feed,
            title="CVE-2026-7102 actively exploited in the wild",
            published_at=same_time,
        )
        p2_item = self._create_item(
            feed=feed,
            title="Gateway flaw actively exploited in the wild",
            age_hours=2,
        )

        response = self.client.get(reverse("now"))
        priority_items = response.context["priority_items"]

        self.assertEqual(
            [item.id for item in priority_items],
            [newer_id_p1.id, older_p1.id, p2_item.id],
        )
        self.assertEqual([item.priority for item in priority_items], ["P1", "P1", "P2"])
        self.assertContains(response, 'data-priority="P1"', html=False)
        self.assertContains(response, "Critical")
        self.assertContains(response, "Active exploitation in title")

    def test_active_preview_uses_semantics_not_feed_section(self):
        active_feed = self._create_feed(
            source_name="Legacy Active Feed",
            source_slug="legacy-active",
            section=Feed.Section.ACTIVE,
        )
        research_feed = self._create_feed(
            source_name="Exploit Research",
            source_slug="exploit-research",
            section=Feed.Section.RESEARCH,
        )
        section_only = self._create_item(
            feed=active_feed,
            title="Routine platform maintenance release",
            age_days=8,
        )
        semantic_active = self._create_item(
            feed=research_feed,
            title="Gateway vulnerability actively exploited in the wild",
            age_days=8,
        )

        response = self.client.get(reverse("now"))
        active_ids = [item.id for item in response.context["active_items"]]

        self.assertFalse(classify_item(section_only).active_exploitation)
        self.assertTrue(classify_item(semantic_active).active_exploitation)
        self.assertEqual(active_ids, [semantic_active.id])
        self.assertContains(response, "Title evidence")
        self.assertNotContains(response, section_only.title)

    def test_ransomware_live_victim_is_ransomware_not_active_exploitation(self):
        feed = self._create_feed(
            source_name="Ransomware Live",
            source_slug="ransomware-live",
            section=Feed.Section.ACTIVE,
            adapter_key="ransomware_live_victims",
            feed_type=Feed.FeedType.JSON,
        )
        victim = self._create_item(
            feed=feed,
            title="Example Manufacturing claimed by Akira",
            summary="New victim listing.",
            age_hours=1,
        )

        response = self.client.get(reverse("now"))

        self.assertTrue(classify_item(victim).ransomware)
        self.assertFalse(classify_item(victim).active_exploitation)
        self.assertIn(victim.id, [item.id for item in response.context["ransomware_items"]])
        self.assertNotIn(victim.id, [item.id for item in response.context["active_items"]])

    def test_nordic_preview_uses_classifier_nordic_relevance(self):
        feed = self._create_feed(
            source_name="International Desk",
            source_slug="international-desk",
            section=Feed.Section.ADVISORIES,
        )
        item = self._create_item(
            feed=feed,
            title="Sweden agency issues new operational guidance",
            age_hours=2,
        )

        response = self.client.get(reverse("now"))

        self.assertTrue(classify_item(item).nordic_relevance)
        self.assertEqual([row.id for row in response.context["nordic_items"]], [item.id])

    def test_research_preview_uses_classifier_research_category(self):
        feed = self._create_feed(
            source_name="Analysis Lab",
            source_slug="analysis-lab",
            section=Feed.Section.RESEARCH,
        )
        item = self._create_item(
            feed=feed,
            title="Longitudinal protocol security analysis",
            age_hours=3,
        )

        response = self.client.get(reverse("now"))

        self.assertTrue(classify_item(item).research)
        self.assertEqual([row.id for row in response.context["research_items"]], [item.id])

    def test_intelligence_stream_contains_remaining_high_signal_items(self):
        feed = self._create_feed(
            source_name="Vendor Desk",
            source_slug="vendor-desk",
            section=Feed.Section.ADVISORIES,
        )
        item = self._create_item(
            feed=feed,
            title="Patch available for CVE-2026-7301",
            age_hours=4,
        )

        response = self.client.get(reverse("now"))

        self.assertTrue(classify_item(item).high_signal)
        self.assertEqual([row.id for row in response.context["intelligence_items"]], [item.id])
        self.assertContains(response, item.title)

    def test_dashboard_deduplicates_items_across_presentation_sections(self):
        feed = self._create_feed(
            source_name="Combined Signals",
            source_slug="combined-signals",
            section=Feed.Section.RESEARCH,
            tags=["sweden"],
        )
        self._create_item(
            feed=feed,
            title="Sweden ransomware campaign actively exploits CVE-2026-7401",
            age_hours=1,
        )
        self._create_item(
            feed=feed,
            title="Independent research methodology",
            age_hours=2,
        )

        response = self.client.get(reverse("now"))
        section_keys = (
            "priority_items",
            "active_items",
            "intelligence_items",
            "ransomware_items",
            "nordic_items",
            "research_items",
        )
        rendered_ids = [
            item.id
            for key in section_keys
            for item in response.context[key]
        ]

        self.assertEqual(len(rendered_ids), len(set(rendered_ids)))

    def test_empty_dashboard_has_meaningful_section_states(self):
        response = self.client.get(reverse("now"))

        self.assertContains(response, "No P1/P2 signals in the current window.")
        self.assertContains(response, "No confirmed active exploitation in the current window.")
        self.assertContains(response, "No ransomware activity in the current window.")
        self.assertContains(response, "No Nordic intelligence in the current window.")
        self.assertContains(response, "No recent research in the current window.")

    def test_dashboard_critical_links_and_source_destination_remain_available(self):
        feed = self._create_feed(
            source_name="Linked Exploit Desk",
            source_slug="linked-exploit-desk",
            section=Feed.Section.ACTIVE,
        )
        item = self._create_item(
            feed=feed,
            title="CVE-2026-7501 actively exploited in the wild",
            age_hours=1,
        )
        response = self.client.get(reverse("now"))
        source_url = f'{reverse("active")}?source=linked-exploit-desk'

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'href="{item.url}"', html=False)
        self.assertContains(response, f'href="{source_url}"', html=False)
        for route_name in ("active", "ransomware-map", "sweden", "research", "feed-health"):
            self.assertContains(response, f'href="{reverse(route_name)}"', html=False)

    def test_emerging_cves_are_counted_from_once_classified_attention_items(self):
        feed = self._create_feed(
            source_name="CVE Desk",
            source_slug="cve-desk",
            section=Feed.Section.ADVISORIES,
        )
        self._create_item(
            feed=feed,
            title="CVE-2026-7601 patch",
            summary="CVE-2026-7602 is also affected.",
            age_hours=1,
        )
        self._create_item(feed=feed, title="CVE-2026-7601 update", age_hours=2)
        self._create_item(feed=feed, title="CVE-2026-7999 old update", age_days=8)

        response = self.client.get(reverse("now"))

        self.assertEqual(
            response.context["emerging_cves"],
            [("CVE-2026-7601", 2), ("CVE-2026-7602", 1)],
        )

    def test_each_candidate_is_classified_once(self):
        feed = self._create_feed(
            source_name="Bounded Desk",
            source_slug="bounded-desk",
            section=Feed.Section.ADVISORIES,
        )
        for index in range(5):
            self._create_item(
                feed=feed,
                title=f"CVE-2026-77{index:02d} security update",
                age_hours=index,
            )

        with patch("intel.views.classify_item", wraps=classify_item) as classifier:
            response = self.client.get(reverse("now"))

        metrics = response.context["dashboard_metrics"]
        self.assertEqual(metrics["candidate_count"], 5)
        self.assertEqual(metrics["classification_calls"], 5)
        self.assertEqual(classifier.call_count, 5)

    def test_one_semantic_structure_orders_mobile_content_by_importance(self):
        response = self.client.get(reverse("now"))
        html = response.content.decode()
        section_order = (
            "threat-pulse",
            "priority",
            "active",
            "intelligence",
            "ransomware",
            "nordic",
            "research",
        )

        positions = [html.index(f'data-dashboard-section="{name}"') for name in section_order]
        self.assertEqual(positions, sorted(positions))
        for name in section_order:
            self.assertEqual(html.count(f'data-dashboard-section="{name}"'), 1)
        self.assertNotIn("data-mobile-section", html)
        self.assertNotIn("data-desktop-layout", html)

    def test_priority_marker_contains_level_label_and_signal_text(self):
        feed = self._create_feed(
            source_name="Critical Exploit Desk",
            source_slug="critical-exploit-desk",
            section=Feed.Section.ACTIVE,
        )
        self._create_item(
            feed=feed,
            title="Critical CVE-2026-7801 actively exploited in the wild",
            summary="Emergency remediation is required.",
            age_hours=1,
        )

        response = self.client.get(reverse("now"))

        self.assertContains(response, 'data-priority="P1"', html=False)
        self.assertContains(response, "Critical")
        self.assertContains(response, 'data-signal-category="active_exploitation"', html=False)
        self.assertContains(response, "Active exploitation")
