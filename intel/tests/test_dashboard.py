from collections import Counter
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.models import Feed, Item, Source


class DashboardViewTests(TestCase):
    def setUp(self):
        self._idx = 0

    def _create_feed(self, *, source_name, source_slug, section, tags=None):
        source = Source.objects.create(
            name=source_name,
            slug=source_slug,
            tags=tags or [],
        )
        feed = Feed.objects.create(
            source=source,
            name=f"{source_name} Feed",
            url=f"https://example.com/{source_slug}-{section}.xml",
            feed_type=Feed.FeedType.RSS,
            section=section,
        )
        return feed

    def _create_item(self, *, feed, title, summary="", age_hours=0, age_days=0, published_at=None):
        self._idx += 1
        return Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            summary=summary,
            url=f"https://example.com/item-{self._idx}",
            stable_id="",
            published_at=published_at or (timezone.now() - timedelta(hours=age_hours, days=age_days)),
        )

    def test_trending_cve_extraction_and_counting(self):
        feed = self._create_feed(
            source_name="Research Lab",
            source_slug="research-lab",
            section=Feed.Section.RESEARCH,
        )
        self._create_item(
            feed=feed,
            title="Investigation CVE-2026-1111",
            summary="CVE-2026-1111 and CVE-2026-2222",
            age_hours=2,
        )
        self._create_item(
            feed=feed,
            title="Patch cve-2026-1111 now",
            summary="",
            age_hours=3,
        )
        self._create_item(
            feed=feed,
            title="Old CVE-2026-9999 mention",
            summary="",
            age_days=10,
        )

        response = self.client.get("/")
        trending = dict(response.context["trending_cves"])

        self.assertEqual(trending["CVE-2026-1111"], 2)
        self.assertEqual(trending["CVE-2026-2222"], 1)
        self.assertNotIn("CVE-2026-9999", trending)

    def test_advisories_block_balances_per_source(self):
        feed_alpha = self._create_feed(
            source_name="Alpha Advisories",
            source_slug="alpha",
            section=Feed.Section.ADVISORIES,
        )
        feed_beta = self._create_feed(
            source_name="Beta Advisories",
            source_slug="beta",
            section=Feed.Section.ADVISORIES,
        )

        for idx in range(12):
            self._create_item(feed=feed_alpha, title=f"Alpha {idx}", age_hours=idx)
        for idx in range(5):
            self._create_item(feed=feed_beta, title=f"Beta {idx}", age_hours=24 + idx)

        response = self.client.get("/")
        advisories_items = response.context["advisories_items"]
        counts = Counter(item.source.slug for item in advisories_items)

        self.assertEqual(len(advisories_items), 13)
        self.assertEqual(counts["alpha"], 8)
        self.assertEqual(counts["beta"], 5)

    def test_high_signal_scoring_prefers_urgent_items_and_drops_routine_release_titles(self):
        feed = self._create_feed(
            source_name="Research Source",
            source_slug="research-source",
            section=Feed.Section.RESEARCH,
        )

        plain_title = "Platform maintenance release notes"
        keyword_title = "Exploit analysis"
        cve_title = "Patch for CVE-2026-5555"

        self._create_item(feed=feed, title=plain_title, summary="normal update", age_hours=0)
        self._create_item(
            feed=feed,
            title=keyword_title,
            summary="Actively exploited vulnerability in the wild",
            age_hours=1,
        )
        self._create_item(feed=feed, title=cve_title, summary="details", age_hours=2)

        response = self.client.get("/")
        top_titles = [item.title for item in response.context["high_signal_items"]]
        top_labels = {item.title: getattr(item, "signal_label", "") for item in response.context["high_signal_items"]}

        self.assertEqual(top_titles[0], keyword_title)
        self.assertIn(cve_title, top_titles)
        self.assertNotIn(plain_title, top_titles)
        self.assertEqual(top_labels[keyword_title], "Active exploitation")
        self.assertEqual(top_labels[cve_title], "CVE-driven")

    def test_high_signal_item_source_links_use_item_section(self):
        feed = self._create_feed(
            source_name="Bleeping Computer",
            source_slug="bleeping-computer",
            section=Feed.Section.ACTIVE,
        )
        self._create_item(
            feed=feed,
            title="Exploit campaign expands",
            summary="Actively exploited vulnerability in the wild",
            age_hours=1,
        )

        response = self.client.get("/")

        item = next(
            item for item in response.context["high_signal_items"] if item.source.slug == "bleeping-computer"
        )
        expected_url = reverse("active") + "?source=bleeping-computer"
        self.assertEqual(item.source_browse_url, expected_url)
        self.assertContains(response, f'href="{expected_url}"')

    def test_trending_sources_route_to_most_relevant_recent_section(self):
        active_feed = self._create_feed(
            source_name="Bleeping Computer",
            source_slug="bleeping-computer",
            section=Feed.Section.ACTIVE,
        )
        advisories_feed = Feed.objects.create(
            source=active_feed.source,
            name="Bleeping Computer Advisories",
            url="https://example.com/bleeping-computer-advisories.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )
        self._create_item(feed=active_feed, title="Fresh active item", age_hours=1)
        self._create_item(feed=advisories_feed, title="Older advisory item", age_hours=8)

        response = self.client.get("/")

        row = next(
            row for row in response.context["trending_sources"] if row["source__slug"] == "bleeping-computer"
        )
        expected_url = reverse("active") + "?source=bleeping-computer"
        self.assertEqual(row["open_url"], expected_url)
        self.assertContains(response, f'href="{expected_url}"')

    def test_trending_sources_fall_back_to_browse_overview_when_recent_sections_tie(self):
        active_feed = self._create_feed(
            source_name="Multi Section Source",
            source_slug="multi-section-source",
            section=Feed.Section.ACTIVE,
        )
        advisories_feed = Feed.objects.create(
            source=active_feed.source,
            name="Multi Section Advisories",
            url="https://example.com/multi-section-advisories.xml",
            feed_type=Feed.FeedType.RSS,
            section=Feed.Section.ADVISORIES,
        )
        same_time = timezone.now() - timedelta(hours=2)
        self._create_item(feed=active_feed, title="Same time active", published_at=same_time)
        self._create_item(feed=advisories_feed, title="Same time advisory", published_at=same_time)

        response = self.client.get("/")

        row = next(
            row for row in response.context["trending_sources"] if row["source__slug"] == "multi-section-source"
        )
        self.assertEqual(row["open_url"], reverse("sources"))

    def test_dashboard_front_page_cards_keep_front_page_layout_without_full_height_stretch(self):
        active_feed = self._create_feed(
            source_name="High Signal Source",
            source_slug="high-signal-source",
            section=Feed.Section.ACTIVE,
        )
        advisory_feed = self._create_feed(
            source_name="Vendor Advisories",
            source_slug="vendor-advisories",
            section=Feed.Section.ADVISORIES,
        )
        self._create_item(
            feed=active_feed,
            title="Actively exploited VPN zero-day under attack",
            summary="Urgent exploitation activity in the wild",
            age_hours=1,
        )
        self._create_item(
            feed=advisory_feed,
            title="Routine advisory update",
            summary="Stable maintenance release information",
            age_hours=2,
        )

        response = self.client.get("/")

        self.assertContains(response, 'data-card-layout="front-page"')
        self.assertContains(response, 'lg:grid-cols-3')
        self.assertContains(
            response,
            'data-card-layout="front-page" class="group w-full min-w-0 overflow-hidden rounded-xl border border-line/90 bg-slate-900/70 p-2 max-[320px]:p-1.5 sm:p-4 shadow-glow flex flex-col xl:p-5"',
            html=False,
        )
        self.assertNotContains(
            response,
            'data-card-layout="front-page" class="group min-w-0 overflow-hidden rounded-xl border border-line/90 bg-slate-900/70 p-3 shadow-glow sm:p-4 flex h-full flex-col',
            html=False,
        )

    def test_dashboard_includes_dedicated_active_preview_section(self):
        active_feed = self._create_feed(
            source_name="Exploit Tracker",
            source_slug="exploit-tracker",
            section=Feed.Section.ACTIVE,
        )
        advisory_feed = self._create_feed(
            source_name="Vendor Advisories",
            source_slug="vendor-advisories",
            section=Feed.Section.ADVISORIES,
        )
        self._create_item(
            feed=active_feed,
            title="Fresh active exploitation report",
            summary="Operational exploit activity",
            age_hours=1,
        )
        self._create_item(
            feed=advisory_feed,
            title="Routine advisory item",
            summary="General advisory note",
            age_hours=2,
        )

        response = self.client.get("/")

        self.assertEqual(len(response.context["active_items"]), 1)
        self.assertContains(response, 'id="active-block"', html=False)
        self.assertContains(response, "All active items")
        self.assertContains(response, "Fresh active exploitation report")
        self.assertContains(response, 'xl:grid-cols-3', html=False)
        self.assertContains(response, 'data-card-layout="dashboard-active-preview"')
        self.assertContains(
            response,
            'data-card-layout="dashboard-active-preview" class="group w-full min-w-0 overflow-hidden flex flex-col rounded-xl border border-line/80 bg-slate-900/65 px-3 py-3 max-[320px]:px-2.5 max-[320px]:py-2.5 shadow-[inset_0_1px_0_rgba(148,163,184,0.04)] md:min-h-[14rem] xl:min-h-[14.5rem]"',
            html=False,
        )

    def test_lower_preview_sections_render_two_compact_items_per_section(self):
        advisories_feed = self._create_feed(
            source_name="Advisory Desk",
            source_slug="advisory-desk",
            section=Feed.Section.ADVISORIES,
        )
        research_feed = self._create_feed(
            source_name="Research Desk",
            source_slug="research-desk",
            section=Feed.Section.RESEARCH,
        )
        sweden_feed = self._create_feed(
            source_name="Sweden Desk",
            source_slug="sweden-desk",
            section=Feed.Section.SWEDEN,
        )

        for idx in range(3):
            self._create_item(
                feed=advisories_feed,
                title=f"Advisory Preview {idx}",
                summary="Routine advisory preview",
                age_hours=idx,
            )
            self._create_item(
                feed=research_feed,
                title=f"Research Preview {idx}",
                summary="Routine research preview",
                age_hours=idx,
            )
            self._create_item(
                feed=sweden_feed,
                title=f"Sweden Preview {idx}",
                summary="Routine Sweden preview",
                age_hours=idx,
            )

        response = self.client.get("/")

        self.assertContains(response, "Advisory Preview 0")
        self.assertContains(response, "Advisory Preview 1")
        self.assertNotContains(response, "Advisory Preview 2")
        self.assertContains(response, "Research Preview 0")
        self.assertContains(response, "Research Preview 1")
        self.assertNotContains(response, "Research Preview 2")
        self.assertContains(response, "Sweden Preview 0")
        self.assertContains(response, "Sweden Preview 1")
        self.assertNotContains(response, "Sweden Preview 2")
        self.assertContains(response, 'data-card-layout="dashboard-preview"')
        self.assertContains(
            response,
            'data-card-layout="dashboard-preview" class="group w-full min-w-0 overflow-hidden flex flex-col rounded-xl border border-line/80 bg-slate-900/60 px-2.5 py-2.5 md:min-h-[11.5rem] sm:px-3 sm:py-3"',
            html=False,
        )

    def test_dashboard_mobile_layout_uses_compact_spacing_and_clamps(self):
        active_feed = self._create_feed(
            source_name="Mobile High Signal",
            source_slug="mobile-high-signal",
            section=Feed.Section.ACTIVE,
        )
        self._create_item(
            feed=active_feed,
            title="Critical authentication bypass exploited in the wild across exposed gateways",
            summary="Urgent exploitation activity with longer supporting context that should clamp on smaller screens.",
            age_hours=1,
        )

        response = self.client.get("/")

        self.assertContains(response, 'class="space-y-3 sm:space-y-5 xl:space-y-7"', html=False)
        self.assertContains(response, 'class="grid grid-cols-2 gap-2 max-[320px]:gap-1.5"', html=False)
        self.assertContains(response, '[-webkit-line-clamp:1] sm:[-webkit-line-clamp:3]', html=False)
        self.assertContains(response, 'mt-1 text-[12px] max-[320px]:text-[11px] leading-[1.1rem] sm:mt-2 sm:text-sm', html=False)
        self.assertContains(response, 'flex min-w-0 flex-wrap items-start gap-2', html=False)
        self.assertContains(response, 'class="inline-flex w-full max-w-full items-center justify-center rounded-lg bg-sky-500', html=False)
        self.assertContains(response, 'class="w-full max-w-full rounded-md border border-slate-700/80', html=False)

    def test_dashboard_mobile_sections_use_compact_high_signal_feed_health_and_trending_layouts(self):
        active_feed = self._create_feed(
            source_name="Mobile Signals",
            source_slug="mobile-signals",
            section=Feed.Section.ACTIVE,
        )
        for idx in range(4):
            self._create_item(
                feed=active_feed,
                title=f"High Signal Mobile {idx}",
                summary="Actively exploited vulnerability with mobile preview trimming.",
                age_hours=idx,
            )

        for idx in range(5):
            feed = self._create_feed(
                source_name=f"Trending Source {idx}",
                source_slug=f"trending-source-{idx}",
                section=Feed.Section.ADVISORIES,
            )
            self._create_item(
                feed=feed,
                title=f"Trending Item {idx}",
                summary="Recent source activity.",
                age_hours=idx,
            )

        response = self.client.get("/")

        self.assertContains(response, 'data-mobile-trim="high-signal-overflow"', html=False)
        self.assertContains(response, "Showing the top 3 curated items on mobile.")
        self.assertContains(response, 'data-mobile-layout="feed-health-compact"', html=False)
        self.assertContains(response, 'data-mobile-layout="trending-sources-compact"', html=False)
        self.assertContains(response, "Top 4 shown on mobile.")

    def test_dashboard_ultra_narrow_layout_uses_max_320_compaction(self):
        active_feed = self._create_feed(
            source_name="Ultra Mobile Source",
            source_slug="ultra-mobile-source",
            section=Feed.Section.ACTIVE,
        )
        for idx in range(4):
            self._create_item(
                feed=active_feed,
                title=f"Ultra Mobile High Signal {idx}",
                summary="Actively exploited vulnerability with ultra narrow trimming.",
                age_hours=idx,
            )

        for idx in range(4):
            advisory_feed = self._create_feed(
                source_name=f"Ultra Trending {idx}",
                source_slug=f"ultra-trending-{idx}",
                section=Feed.Section.ADVISORIES,
            )
            self._create_item(
                feed=advisory_feed,
                title=f"Ultra Trending Item {idx}",
                summary="Recent source activity.",
                age_hours=idx,
            )

        cve_feed = self._create_feed(
            source_name="Ultra CVE Source",
            source_slug="ultra-cve-source",
            section=Feed.Section.ADVISORIES,
        )
        for idx in range(4):
            self._create_item(
                feed=cve_feed,
                title=f"CVE-2026-100{idx} urgent advisory",
                summary="Critical CVE-driven item for ultra narrow mobile compaction.",
                age_hours=idx,
            )

        response = self.client.get("/")

        self.assertContains(response, 'max-[320px]:gap-1.5', html=False)
        self.assertContains(response, 'max-[320px]:text-lg', html=False)
        self.assertContains(response, 'data-ultra-mobile-trim="high-signal-extra"', html=False)
        self.assertContains(response, "Showing the top 2 curated items on very small screens.")
        self.assertContains(response, 'data-ultra-mobile-trim="active-extra"', html=False)
        self.assertContains(response, "Showing the top 2 active items on very small screens.")
        self.assertContains(response, 'data-mobile-layout="trending-cves-compact"', html=False)
        self.assertContains(response, 'data-ultra-mobile-trim="trending-cve-extra"', html=False)
        self.assertContains(response, "Top 3 CVEs shown on very small screens.")
        self.assertContains(response, 'data-ultra-mobile-trim="trending-source-extra"', html=False)
        self.assertContains(response, "Top 3 shown on very small screens.")
