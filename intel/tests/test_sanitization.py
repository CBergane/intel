from django.test import SimpleTestCase

from intel.utils import sanitize_summary


class SanitizationTests(SimpleTestCase):
    def test_sanitize_summary_removes_remote_html(self):
        raw = (
            "<p>Hello <strong>world</strong></p>"
            "<script>alert('xss')</script>"
            "<style>body{display:none;}</style>"
        )
        self.assertEqual(sanitize_summary(raw), "Hello world")
