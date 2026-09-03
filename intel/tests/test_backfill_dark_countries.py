from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase

from intel.models import DarkHit, DarkSource


class BackfillDarkCountriesTests(TestCase):
    def setUp(self):
        self.source = DarkSource.objects.create(
            name="Ransom-DB Live Updates",
            slug="ransom-db-live-updates",
            url="https://www.ransom-db.com/live-updates",
            extractor_profile=DarkSource.ExtractorProfile.INCIDENT_CARDS,
        )

    def _raw_card(self, title: str, country_markup: str) -> str:
        return f"""
        <article class="incident-card">
            <h3>{title}</h3>
            <p>Threat Group: Example Group</p>
            {country_markup}
            <p>Victim disclosure posted with extortion details.</p>
        </article>
        """

    def _hit(
        self,
        title: str,
        *,
        country: str = "",
        raw: str = "",
        record_type: str = "incident",
    ) -> DarkHit:
        return DarkHit.objects.create(
            dark_source=self.source,
            title=title,
            victim_name=title,
            country=country,
            raw=raw,
            record_type=record_type,
            url=self.source.url,
            content_hash=(title.lower().replace(" ", "-") + "-hash")[:64],
        )

    def test_dry_run_is_default_and_apply_is_idempotent(self):
        blank = self._hit(
            "Blank Country",
            raw=self._raw_card("Blank Country", "<p>Country: Sweden</p>"),
        )
        false_positive = self._hit(
            "False Positive",
            country="Country Motors S.A. regional distributor",
            raw=self._raw_card(
                "False Positive",
                '<img src="/assets/images/flags/us.png" alt="US" />',
            ),
        )
        protected = self._hit(
            "Protected Country",
            country="Norway",
            raw=self._raw_card("Protected Country", "<p>Country: Canada</p>"),
        )
        rejected = self._hit(
            "Rejected Prose",
            country="Country Honda regional report",
            raw=self._raw_card(
                "Rejected Prose",
                "<p>Country Motors distributes vehicles across the region.</p>",
            ),
        )
        self._hit(
            "Group Record",
            raw=self._raw_card("Group Record", "<p>Country: Denmark</p>"),
            record_type="group",
        )

        stdout = StringIO()
        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            stdout=stdout,
        )

        self.assertIn("mode=dry-run", stdout.getvalue())
        self.assertIn(
            "scanned=4 candidates=3 reparsed=3 recognized=2 "
            "changed=2 unchanged=0 rejected=1",
            stdout.getvalue(),
        )
        blank.refresh_from_db()
        false_positive.refresh_from_db()
        self.assertEqual(blank.country, "")
        self.assertEqual(
            false_positive.country, "Country Motors S.A. regional distributor"
        )

        stdout = StringIO()
        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            apply=True,
            stdout=stdout,
        )

        self.assertIn("mode=apply", stdout.getvalue())
        self.assertIn("changed=2", stdout.getvalue())
        blank.refresh_from_db()
        false_positive.refresh_from_db()
        protected.refresh_from_db()
        rejected.refresh_from_db()
        self.assertEqual(blank.country, "Sweden")
        self.assertEqual(false_positive.country, "United States")
        self.assertEqual(protected.country, "Norway")
        self.assertEqual(rejected.country, "Country Honda regional report")

        stdout = StringIO()
        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            apply=True,
            stdout=stdout,
        )
        self.assertIn("changed=0", stdout.getvalue())

    def test_recognized_country_requires_explicit_opt_in_to_replace(self):
        hit = self._hit(
            "Recognized Country",
            country="Norway",
            raw=self._raw_card("Recognized Country", "<p>Country: Canada</p>"),
        )

        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            apply=True,
            stdout=StringIO(),
        )
        hit.refresh_from_db()
        self.assertEqual(hit.country, "Norway")

        stdout = StringIO()
        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            apply=True,
            include_recognized=True,
            stdout=stdout,
        )
        hit.refresh_from_db()
        self.assertEqual(hit.country, "Canada")
        self.assertIn("changed=1", stdout.getvalue())

    def test_dry_run_accepts_bounded_country_and_rejects_cross_field_value(self):
        clean = self._hit(
            "Nuvitia.com",
            raw=self._raw_card(
                "Nuvitia.com",
                """
                <div class="grid grid-cols-2 gap-4">
                    <div class="flex items-center gap-2">
                        <span class="text-dark-text-secondary">Country:</span>
                        <span class="text-white font-medium"> Spain </span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="text-dark-text-secondary">Industry:</span>
                        <span class="text-white font-medium"> IT services </span>
                    </div>
                </div>
                """,
            ),
        )
        unsafe = self._hit(
            "Altavista strategic partners",
            raw=self._raw_card(
                "Altavista strategic partners",
                "<p>Country: United States Industry: Advertising, Marketing &amp; PR</p>",
            ),
        )
        unsafe_multi = self._hit(
            "Parami university",
            raw=self._raw_card(
                "Parami university",
                "<p>Country: Myanmar / United States Industry: Higher Education</p>",
            ),
        )

        stdout = StringIO()
        call_command(
            "backfill_dark_countries",
            source=self.source.slug,
            stdout=stdout,
        )

        self.assertIn("mode=dry-run", stdout.getvalue())
        self.assertIn(
            "scanned=3 candidates=3 reparsed=3 recognized=1 "
            "changed=1 unchanged=0 rejected=2",
            stdout.getvalue(),
        )
        clean.refresh_from_db()
        unsafe.refresh_from_db()
        unsafe_multi.refresh_from_db()
        self.assertEqual(clean.country, "")
        self.assertEqual(unsafe.country, "")
        self.assertEqual(unsafe_multi.country, "")

    def test_source_must_exist_and_use_incident_cards(self):
        with self.assertRaisesMessage(CommandError, "was not found"):
            call_command(
                "backfill_dark_countries",
                source="missing-source",
                stdout=StringIO(),
            )

        generic_source = DarkSource.objects.create(
            name="Generic Source",
            slug="generic-source",
            url="https://example.test/",
        )
        with self.assertRaisesMessage(CommandError, "does not use the incident_cards"):
            call_command(
                "backfill_dark_countries",
                source=generic_source.slug,
                stdout=StringIO(),
            )
