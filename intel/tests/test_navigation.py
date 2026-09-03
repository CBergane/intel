from pathlib import Path

from django.contrib.auth import get_user_model
from django.templatetags.static import static
from django.test import TestCase
from django.urls import reverse


REPO_ROOT = Path(__file__).resolve().parents[2]


class NavigationTemplateTests(TestCase):
    def test_shell_loads_compiled_assets_without_tailwind_cdn(self):
        response = self.client.get(reverse("about"))

        self.assertContains(response, f'href="{static("css/tailwind.css")}"', html=False)
        self.assertContains(response, f'src="{static("js/app-shell.js")}"', html=False)
        self.assertNotContains(response, "cdn.tailwindcss.com")

    def test_desktop_navigation_is_single_grouped_structure(self):
        response = self.client.get(reverse("about"))
        html = response.content.decode()

        self.assertEqual(html.count('data-primary-navigation="desktop"'), 1)
        self.assertEqual(html.count('id="desktop-primary-navigation"'), 1)
        for group_label in ("Overview", "Threats", "Intelligence", "Data"):
            self.assertGreaterEqual(html.count(f">{group_label}</h2>"), 2)

    def test_mobile_navigation_uses_same_logical_destinations(self):
        response = self.client.get(reverse("about"))
        html = response.content.decode()

        self.assertEqual(html.count('data-primary-navigation="mobile"'), 1)
        for key in (
            "now",
            "active",
            "vulnerabilities",
            "threat-news",
            "ransomware",
            "nordics",
            "research",
            "threat-watch",
            "sources",
            "feed-health",
            "about",
        ):
            self.assertEqual(html.count(f'data-navigation-key="{key}"'), 2)

    def test_navigation_uses_semantic_labels(self):
        response = self.client.get(reverse("about"))
        html = response.content.decode()

        for label in (
            "Active Exploitation",
            "Vulnerabilities",
            "Nordics",
            "Threat Watch",
        ):
            self.assertGreaterEqual(html.count(label), 2)
        for old_label in ("Active", "Advisories", "Sweden", "Dark"):
            self.assertNotIn(f">{old_label}<", html)

    def test_active_destination_has_aria_current_in_both_presentations(self):
        response = self.client.get(reverse("active"))
        html = response.content.decode()

        self.assertEqual(html.count('data-navigation-key="active"'), 2)
        self.assertEqual(html.count('aria-current="page"'), 2)
        self.assertEqual(response.context["active_navigation_item"]["key"], "active")

    def test_intelligence_list_destinations_keep_navigation_state(self):
        cases = (
            ("active", "active"),
            ("advisories", "vulnerabilities"),
            ("threat-news", "threat-news"),
            ("sweden", "nordics"),
            ("research", "research"),
        )

        for route_name, navigation_key in cases:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.context["active_navigation_item"]["key"],
                    navigation_key,
                )
                self.assertEqual(response.content.decode().count('aria-current="page"'), 2)

    def test_anonymous_threat_watch_is_restricted_and_not_linked(self):
        response = self.client.get(reverse("about"))
        html = response.content.decode()

        self.assertEqual(html.count('data-navigation-key="threat-watch"'), 2)
        self.assertEqual(html.count('aria-disabled="true"'), 2)
        self.assertEqual(html.count("Restricted"), 2)
        self.assertNotIn(f'href="{reverse("dark-dashboard")}"', html)
        self.assertEqual(self.client.get(reverse("dark-dashboard")).status_code, 302)

    def test_anonymous_utility_navigation_exposes_staff_login_only(self):
        response = self.client.get(reverse("about"))
        html = response.content.decode()

        self.assertEqual(html.count('data-staff-access="anonymous"'), 2)
        self.assertEqual(html.count(f'href="{reverse("intel_admin:login")}"'), 2)
        self.assertEqual(html.count("Staff login"), 2)
        self.assertNotIn('href="/signup', html)
        self.assertNotIn('href="/register', html)

    def test_superuser_navigation_links_and_activates_threat_watch(self):
        user = get_user_model().objects.create_superuser(
            username="navigation-admin",
            email="navigation@example.com",
            password="test-password",
        )
        self.client.force_login(user)

        public_response = self.client.get(reverse("about"))
        public_html = public_response.content.decode()
        self.assertEqual(public_html.count(f'href="{reverse("dark-dashboard")}"'), 2)
        self.assertNotIn('aria-disabled="true"', public_html)

        restricted_response = self.client.get(reverse("dark-dashboard"))
        restricted_html = restricted_response.content.decode()
        self.assertEqual(restricted_response.status_code, 200)
        self.assertEqual(restricted_html.count('aria-current="page"'), 2)
        self.assertEqual(
            restricted_response.context["active_navigation_item"]["key"],
            "threat-watch",
        )

    def test_superuser_utility_navigation_has_admin_ops_and_post_logout(self):
        user = get_user_model().objects.create_superuser(
            username="shell-admin",
            email="shell-admin@example.com",
            password="test-password",
        )
        self.client.force_login(user)

        response = self.client.get(reverse("about"))
        html = response.content.decode()

        self.assertEqual(html.count('data-staff-access="authenticated"'), 2)
        self.assertEqual(html.count(f'href="{reverse("intel_admin:panel")}"'), 2)
        self.assertEqual(html.count(f'href="{reverse("intel_admin:ops")}"'), 2)
        self.assertEqual(
            html.count(f'<form method="post" action="{reverse("intel_admin:logout")}"'),
            2,
        )
        self.assertEqual(html.count("Sign out"), 2)
        self.assertNotIn("Staff login", html)

    def test_mobile_controls_have_accessible_labels(self):
        response = self.client.get(reverse("about"))

        self.assertContains(response, 'aria-label="Open navigation"', html=False)
        self.assertContains(response, 'aria-expanded="false"', html=False)
        self.assertContains(response, 'aria-controls="mobile-nav-shell"', html=False)
        self.assertContains(response, 'id="mobile-nav-shell" class="mobile-nav-shell" aria-hidden="true"', html=False)
        self.assertContains(response, 'role="dialog"', html=False)
        self.assertContains(response, 'aria-modal="true"', html=False)
        self.assertContains(response, 'aria-label="Close navigation"', count=2, html=False)
        self.assertContains(response, 'aria-label="Primary navigation"', count=2, html=False)
        self.assertContains(response, "Skip to content")

    def test_mobile_topbar_identifies_current_section_and_page(self):
        response = self.client.get(reverse("active"))

        self.assertContains(response, 'class="app-mobile-brand__identity">BorealSec Intel</span>', html=False)
        self.assertContains(response, 'class="app-mobile-brand__context"', html=False)
        self.assertContains(response, "Threats")
        self.assertContains(response, "Active Exploitation")

    def test_mobile_drawer_script_supports_keyboard_and_scroll_lock(self):
        script = (REPO_ROOT / "static" / "js" / "app-shell.js").read_text(encoding="utf-8")
        stylesheet = (REPO_ROOT / "static" / "css" / "input.css").read_text(encoding="utf-8")

        self.assertIn('event.key === "Escape"', script)
        self.assertIn('toggle.setAttribute("aria-expanded", "true")', script)
        self.assertIn('document.body.classList.add("overflow-hidden")', script)
        self.assertIn('mobile-nav-shell[aria-hidden="false"]', stylesheet)

    def test_now_page_briefing_does_not_duplicate_global_navigation(self):
        response = self.client.get(reverse("now"))
        html = response.content.decode()

        self.assertEqual(html.count('data-primary-navigation="desktop"'), 1)
        self.assertEqual(html.count('data-primary-navigation="mobile"'), 1)
        self.assertEqual(html.count('data-dashboard-section="active"'), 1)
        self.assertNotIn('aria-label="Now page sections"', html)


class PageOrientationTests(TestCase):
    def test_public_major_pages_have_compact_orientation_headers(self):
        cases = (
            ("now", "Overview", "Now", "A current view of high-signal security activity."),
            (
                "active",
                "Threats",
                "Active Exploitation",
                "Confirmed or strongly evidenced exploitation activity.",
            ),
            (
                "advisories",
                "Threats",
                "Vulnerabilities",
                "Vendor and vulnerability intelligence.",
            ),
            (
                "threat-news",
                "Threats",
                "Threat News",
                "Security events, campaigns, and industry developments.",
            ),
            (
                "ransomware-map",
                "Intelligence",
                "Ransomware",
                "Victim, group, and geography intelligence.",
            ),
            (
                "sweden",
                "Intelligence",
                "Nordics",
                "Security intelligence with meaningful Nordic relevance.",
            ),
            (
                "research",
                "Intelligence",
                "Research",
                "Technical research, analysis, and practitioner writeups.",
            ),
            ("sources", "Data", "Sources", "Coverage, provenance, and recent intelligence by source."),
            ("feed-health", "Data", "Feed Health", "Freshness, ingest outcomes, and feed-level errors."),
            ("about", "System", "About", "Purpose, safeguards, and operating principles."),
        )

        for route_name, group, title, description in cases:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'data-page-header="true"', count=1, html=False)
                self.assertEqual(response.context["page_group"], group)
                self.assertEqual(response.context["page_title"], title)
                self.assertContains(response, description)

    def test_existing_public_routes_still_resolve(self):
        for route_name in (
            "now",
            "active",
            "advisories",
            "research",
            "sweden",
            "ransomware-map",
            "threat-news",
            "feed-health",
            "sources",
            "about",
        ):
            with self.subTest(route_name=route_name):
                self.assertEqual(self.client.get(reverse(route_name)).status_code, 200)
