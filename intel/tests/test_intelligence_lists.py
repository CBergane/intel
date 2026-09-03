from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from intel.classification import classify_item
from intel.models import Feed, Item, Source
from intel.views import LIST_CANDIDATE_LIMIT


class IntelligenceListViewTests(TestCase):
    def setUp(self):
        self._item_index = 0

    def _create_feed(
        self,
        *,
        name,
        slug,
        section=Feed.Section.ADVISORIES,
        tags=None,
    ):
        source = Source.objects.create(name=name, slug=slug, tags=tags or [])
        return Feed.objects.create(
            source=source,
            name=f"{name} Feed",
            url=f"https://example.com/{slug}.xml",
            feed_type=Feed.FeedType.RSS,
            section=section,
        )

    def _create_item(
        self,
        *,
        feed,
        title,
        summary="",
        age_hours=1,
        published_at=None,
        raw_payload=None,
    ):
        self._item_index += 1
        return Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            summary=summary,
            raw_payload=raw_payload or {},
            url=f"https://example.com/intelligence-{self._item_index}",
            stable_id="",
            published_at=published_at or timezone.now() - timedelta(hours=age_hours),
        )

    def test_active_page_uses_exploitation_semantics_not_active_feed_section(self):
        section_feed = self._create_feed(
            name="Legacy Active",
            slug="legacy-active-list",
            section=Feed.Section.ACTIVE,
        )
        research_feed = self._create_feed(
            name="Exploit Research",
            slug="exploit-research-list",
            section=Feed.Section.RESEARCH,
        )
        section_only = self._create_item(
            feed=section_feed,
            title="Routine platform maintenance release",
        )
        semantic_active = self._create_item(
            feed=research_feed,
            title="Gateway vulnerability actively exploited in the wild",
        )

        response = self.client.get(reverse("active"))
        result_ids = [item.id for item in response.context["page_obj"].object_list]

        self.assertFalse(classify_item(section_only).active_exploitation)
        self.assertTrue(classify_item(semantic_active).active_exploitation)
        self.assertEqual(result_ids, [semantic_active.id])
        self.assertContains(response, "Exploitation evidence · Title evidence")
        self.assertNotContains(response, section_only.title)

    def test_vulnerability_page_separates_vulnerability_from_exploitation(self):
        feed = self._create_feed(
            name="Vulnerability Research",
            slug="vulnerability-research-list",
            section=Feed.Section.RESEARCH,
        )
        vulnerability = self._create_item(
            feed=feed,
            title="Vendor patch available for CVE-2026-8101",
        )
        exploited = self._create_item(
            feed=feed,
            title="CVE-2026-8102 actively exploited in the wild",
        )
        neutral = self._create_item(feed=feed, title="Quarterly methodology review")

        response = self.client.get(reverse("advisories"))
        items = response.context["page_obj"].object_list

        self.assertTrue(classify_item(vulnerability).vulnerability)
        self.assertFalse(classify_item(vulnerability).active_exploitation)
        self.assertTrue(classify_item(exploited).active_exploitation)
        self.assertEqual({item.id for item in items}, {vulnerability.id, exploited.id})
        self.assertNotIn(neutral.id, [item.id for item in items])
        self.assertContains(response, "CVE-driven")
        self.assertContains(response, "Active exploitation")
        self.assertContains(response, "Confirmed exploitation · Title evidence")

    def test_threat_news_page_uses_classifier_news_semantics(self):
        news_feed = self._create_feed(
            name="Security Newsroom",
            slug="security-newsroom-list",
            section=Feed.Section.ACTIVE,
            tags=["news"],
        )
        generic_feed = self._create_feed(
            name="Generic Feed",
            slug="generic-list-feed",
            section=Feed.Section.ACTIVE,
        )
        news_item = self._create_item(feed=news_feed, title="Campaign activity update")
        generic_item = self._create_item(feed=generic_feed, title="General weekly update")

        response = self.client.get(reverse("threat-news"))

        self.assertTrue(classify_item(news_item).threat_news)
        self.assertFalse(classify_item(generic_item).threat_news)
        self.assertEqual(
            [item.id for item in response.context["page_obj"].object_list],
            [news_item.id],
        )
        self.assertContains(response, 'data-signal-category="threat_news"', html=False)

    def test_nordics_page_uses_classifier_nordic_relevance(self):
        nordic_feed = self._create_feed(
            name="CERT-SE",
            slug="cert-se",
            section=Feed.Section.ADVISORIES,
        )
        generic_feed = self._create_feed(
            name="Global Desk",
            slug="global-desk-list",
            section=Feed.Section.ADVISORIES,
        )
        nordic_item = self._create_item(feed=nordic_feed, title="Operational bulletin")
        generic_item = self._create_item(feed=generic_feed, title="Operational bulletin")

        response = self.client.get(reverse("sweden"))

        self.assertTrue(classify_item(nordic_item).nordic_relevance)
        self.assertFalse(classify_item(generic_item).nordic_relevance)
        self.assertEqual(
            [item.id for item in response.context["page_obj"].object_list],
            [nordic_item.id],
        )
        self.assertContains(response, "Nordic relevance · Source metadata")
        self.assertContains(response, "CERT-SE")

    def test_nordics_page_prefilters_before_global_candidate_limit(self):
        global_feed = self._create_feed(
            name="High Volume Global Desk",
            slug="high-volume-global-list",
        )
        nordic_feed = self._create_feed(
            name="CERT-SE",
            slug="cert-se",
            section=Feed.Section.SWEDEN,
        )
        now = timezone.now()
        Item.objects.bulk_create(
            [
                Item(
                    source=global_feed.source,
                    feed=global_feed,
                    title=f"Unrelated global bulletin {index}",
                    title_hash=f"global-list-{index}",
                    stable_id=f"global-list-{index}",
                    published_at=now - timedelta(seconds=index),
                )
                for index in range(LIST_CANDIDATE_LIMIT + 1)
            ]
        )
        nordic_item = self._create_item(
            feed=nordic_feed,
            title="CERT-SE weekly operational bulletin",
            published_at=now - timedelta(days=6),
        )

        with patch("intel.views.classify_item", wraps=classify_item) as classifier:
            response = self.client.get(reverse("sweden"), {"time": "7d"})

        self.assertEqual(
            [item.id for item in response.context["page_obj"].object_list],
            [nordic_item.id],
        )
        self.assertEqual(response.context["list_metrics"]["candidate_count"], 1)
        self.assertEqual(classifier.call_count, 1)
        self.assertFalse(response.context["candidate_limit_reached"])

    def test_nordics_prefilter_covers_non_section_evidence(self):
        country_feed = self._create_feed(
            name="International Country Desk",
            slug="international-country-list",
        )
        tagged_feed = self._create_feed(
            name="Tagged Agency Desk",
            slug="tagged-agency-list",
            tags=["government", "norway"],
        )
        summary_feed = self._create_feed(
            name="Regional Summary Desk",
            slug="regional-summary-list",
        )
        country_item = self._create_item(
            feed=country_feed,
            title="Regional organization activity update",
            raw_payload={"country": " Finland "},
        )
        tagged_item = self._create_item(
            feed=tagged_feed,
            title="Government security activity update",
        )
        summary_item = self._create_item(
            feed=summary_feed,
            title="Regional threat activity update",
            summary="The campaign affected organizations in Denmark.",
        )

        response = self.client.get(reverse("sweden"))

        profiles = {
            item.id: classify_item(item)
            for item in (country_item, tagged_item, summary_item)
        }
        self.assertEqual(profiles[country_item.id].nordic_evidence, "metadata")
        self.assertEqual(profiles[tagged_item.id].nordic_evidence, "metadata")
        self.assertEqual(profiles[summary_item.id].nordic_evidence, "summary")
        self.assertEqual(
            {item.id for item in response.context["page_obj"].object_list},
            {country_item.id, tagged_item.id, summary_item.id},
        )

    def test_research_page_uses_classifier_research_semantics(self):
        research_feed = self._create_feed(
            name="Analysis Group",
            slug="analysis-group-list",
            section=Feed.Section.ADVISORIES,
            tags=["research"],
        )
        generic_feed = self._create_feed(
            name="Bulletin Group",
            slug="bulletin-group-list",
            section=Feed.Section.ACTIVE,
        )
        research_item = self._create_item(
            feed=research_feed,
            title="Longitudinal protocol security analysis",
            summary="A detailed analytical review with practitioner observations.",
        )
        generic_item = self._create_item(feed=generic_feed, title="Routine bulletin")

        response = self.client.get(reverse("research"))

        self.assertTrue(classify_item(research_item).research)
        self.assertFalse(classify_item(generic_item).research)
        self.assertEqual(
            [item.id for item in response.context["page_obj"].object_list],
            [research_item.id],
        )
        self.assertContains(response, research_item.summary)
        self.assertContains(response, "Research source or feed")

    def test_shared_row_exposes_semantic_metadata_and_safe_links(self):
        feed = self._create_feed(
            name="Metadata Desk",
            slug="metadata-desk-list",
        )
        item = self._create_item(
            feed=feed,
            title="CVE-2026-8201 actively exploited in the wild",
            summary="A concise operational summary.",
        )

        response = self.client.get(reverse("active"))
        html = response.content.decode()

        self.assertEqual(html.count(f'data-intelligence-row="{item.id}"'), 1)
        self.assertContains(response, f'href="{item.url}"', html=False)
        self.assertContains(
            response,
            f'href="{reverse("advisories")}?q=CVE-2026-8201"',
            html=False,
        )
        self.assertContains(response, 'datetime="', html=False)
        self.assertContains(response, "P1")
        self.assertContains(response, "Critical")
        self.assertContains(response, item.source.name)
        self.assertContains(response, item.summary)

    def test_search_source_and_time_filters_continue_to_work(self):
        alpha_feed = self._create_feed(name="Alpha Vendor", slug="alpha-vendor-list")
        beta_feed = self._create_feed(name="Beta Vendor", slug="beta-vendor-list")
        alpha = self._create_item(feed=alpha_feed, title="CVE-2026-8301 Alpha issue")
        self._create_item(feed=beta_feed, title="CVE-2026-8302 Beta issue")
        self._create_item(
            feed=alpha_feed,
            title="CVE-2026-8303 Old Alpha issue",
            age_hours=24 * 20,
        )

        response = self.client.get(
            reverse("advisories"),
            {"q": "8301", "source": "alpha-vendor-list", "time": "7d"},
        )

        self.assertEqual(response.context["filtered_total"], 1)
        self.assertEqual(response.context["page_obj"].object_list[0].id, alpha.id)
        self.assertContains(response, "Source: Alpha Vendor")
        self.assertContains(response, "Time: 7d")

    def test_live_search_partial_updates_results_and_result_context(self):
        feed = self._create_feed(name="Live Filter", slug="live-filter-list")
        self._create_item(feed=feed, title="CVE-2026-8351 Alpha issue")
        self._create_item(feed=feed, title="CVE-2026-8352 Beta issue")

        response = self.client.get(
            reverse("advisories"),
            {"q": "Alpha", "time": "7d"},
            HTTP_HX_REQUEST="true",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["HX-Trigger"], '{"showToast": "1 results"}')
        self.assertContains(
            response,
            "Showing <strong>1</strong> signals",
            html=False,
        )
        self.assertContains(response, "Search: Alpha")
        self.assertContains(response, "CVE-2026-8351 Alpha issue")
        self.assertNotContains(response, 'data-page-header="true"', html=False)

    def test_pagination_preserves_filters_and_exposes_states(self):
        feed = self._create_feed(name="Paged Vendor", slug="paged-vendor-list")
        published_at = timezone.now() - timedelta(hours=1)
        for index in range(26):
            self._create_item(
                feed=feed,
                title=f"CVE-2026-{8400 + index} paged issue",
                published_at=published_at - timedelta(minutes=index),
            )

        first_page = self.client.get(
            reverse("advisories"),
            {"source": "paged-vendor-list", "time": "7d"},
        )
        second_page_url = (
            "?q=&source=paged-vendor-list&time=7d&page=2"
        )

        self.assertEqual(len(first_page.context["page_obj"].object_list), 25)
        self.assertContains(first_page, f'href="{second_page_url}"', html=False)
        self.assertContains(first_page, 'rel="next"', html=False)
        self.assertContains(first_page, 'aria-disabled="true"', html=False)

        second_page = self.client.get(
            reverse("advisories"),
            {"source": "paged-vendor-list", "time": "7d", "page": 2},
        )
        self.assertEqual(len(second_page.context["page_obj"].object_list), 1)
        self.assertContains(second_page, 'rel="prev"', html=False)
        self.assertContains(second_page, 'aria-current="page">2', html=False)

    def test_each_semantic_page_has_specific_empty_state(self):
        cases = (
            ("active", "No confirmed active exploitation in the current result set."),
            ("advisories", "No vulnerability intelligence matches the current filters."),
            ("threat-news", "No threat-news signals match the current filters."),
            ("sweden", "No Nordic-relevant intelligence matches the current filters."),
            ("research", "No research intelligence matches the current filters."),
        )

        for route_name, message in cases:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertContains(response, message)
                self.assertNotContains(response, "No data.")

    def test_candidate_classification_is_bounded_and_runs_once_per_item(self):
        feed = self._create_feed(name="Bounded List", slug="bounded-list")
        for index in range(4):
            self._create_item(feed=feed, title=f"CVE-2026-85{index:02d} update")

        with (
            patch("intel.views.LIST_CANDIDATE_LIMIT", 3),
            patch("intel.views.classify_item", wraps=classify_item) as classifier,
        ):
            response = self.client.get(reverse("advisories"))

        self.assertEqual(response.context["list_metrics"]["candidate_count"], 3)
        self.assertEqual(response.context["list_metrics"]["classification_calls"], 3)
        self.assertEqual(classifier.call_count, 3)
        self.assertTrue(response.context["candidate_limit_reached"])

    def test_representative_semantic_list_uses_one_item_query(self):
        feed = self._create_feed(name="Query Desk", slug="query-desk-list")
        self._create_item(feed=feed, title="CVE-2026-8601 actively exploited in the wild")

        with self.assertNumQueries(1):
            response = self.client.get(reverse("active"))

        self.assertEqual(response.status_code, 200)
