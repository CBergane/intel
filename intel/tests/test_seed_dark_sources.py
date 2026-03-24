import json
from io import StringIO
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.test import TestCase

from intel.models import DarkSource

# ---------------------------------------------------------------------------
# Fake API responses
# ---------------------------------------------------------------------------

def _api_response(groups: list) -> MagicMock:
    """Return a mock requests.Response streaming the given groups list."""
    body = json.dumps(groups).encode()
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.iter_content.return_value = iter([body])
    return mock_resp


RANSOMHUB_PAGE = {
    "fqdn": "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",
    "available": True,
}
PLAY_PAGE = {
    "fqdn": "mbrlkbtq52qqbuqsl7fszefmbxsmrzlys4mvwftp5wkhfnikytbxbnad.onion",
    "available": True,
}

FULL_API = [
    {"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]},
    {"name": "Play", "slug": "play", "pages": [PLAY_PAGE]},
    {"name": "Akira", "slug": "akira", "pages": [
        {"fqdn": "akirafjeowji98234kasdfj.onion", "available": True}
    ]},
    {"name": "Medusa", "slug": "medusa", "pages": [
        {"fqdn": "medusawlmjuqnfra32nkpn.onion", "available": True}
    ]},
    {"name": "Cl0p", "slug": "clop", "pages": [
        {"fqdn": "clopbcv7boh4mhnxkjgifaa.onion", "available": True}
    ]},
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class SeedDarkSourcesCommandTests(TestCase):

    def _run(self, api_groups, *args, **kwargs):
        mock_resp = _api_response(api_groups)
        with patch(
            "intel.management.commands.seed_dark_sources.requests.get",
            return_value=mock_resp,
        ):
            out = StringIO()
            call_command("seed_dark_sources", *args, stdout=out, **kwargs)
            return out.getvalue()

    def test_creates_dark_sources(self):
        api = [
            {"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]},
            {"name": "Play", "slug": "play", "pages": [PLAY_PAGE]},
        ]
        self._run(api)

        self.assertTrue(DarkSource.objects.filter(slug="ransomhub").exists())
        self.assertTrue(DarkSource.objects.filter(slug="play").exists())
        self.assertEqual(DarkSource.objects.count(), 2)

    def test_created_sources_have_use_tor_true(self):
        api = [{"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]}]
        self._run(api)
        source = DarkSource.objects.get(slug="ransomhub")
        self.assertTrue(source.use_tor)

    def test_skips_unavailable_pages(self):
        api = [
            {
                "name": "RansomHub",
                "slug": "ransomhub",
                "pages": [
                    {"fqdn": "oldaddress.onion", "available": False},
                ],
            }
        ]
        self._run(api)
        self.assertFalse(DarkSource.objects.filter(slug="ransomhub").exists())

    def test_updates_url_if_changed(self):
        DarkSource.objects.create(
            name="RansomHub Leaks",
            slug="ransomhub",
            url="http://oldaddressxxxxxxxxxxxxxxx.onion",
            use_tor=True,
        )
        new_fqdn = RANSOMHUB_PAGE["fqdn"]
        api = [{"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]}]
        self._run(api)

        source = DarkSource.objects.get(slug="ransomhub")
        self.assertEqual(source.url, f"http://{new_fqdn}")

    def test_dry_run_creates_nothing(self):
        self._run(FULL_API, dry_run=True)
        self.assertEqual(DarkSource.objects.count(), 0)

    def test_api_failure_exits(self):
        with patch(
            "intel.management.commands.seed_dark_sources.requests.get",
            side_effect=Exception("connection refused"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                call_command("seed_dark_sources", stdout=StringIO(), stderr=StringIO())
            self.assertEqual(ctx.exception.code, 1)

    def test_skips_group_not_in_api(self):
        # lockbit3 is not in the API response → should be skipped
        api = [{"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]}]
        out = self._run(api)
        self.assertIn("not found in API", out)
        self.assertFalse(DarkSource.objects.filter(slug="lockbit3").exists())

    def test_onion_url_stored_correctly(self):
        api = [{"name": "RansomHub", "slug": "ransomhub", "pages": [RANSOMHUB_PAGE]}]
        self._run(api)
        source = DarkSource.objects.get(slug="ransomhub")
        self.assertTrue(source.url.startswith("http://"))
        self.assertTrue(source.url.endswith(".onion"))
