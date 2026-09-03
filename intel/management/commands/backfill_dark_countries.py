from django.core.management.base import BaseCommand, CommandError

from intel.dark_utils import extract_profile_records
from intel.models import DarkHit, DarkSource
from intel.ransomware_countries import normalize_ransomware_country


def _matching_incident_record(hit, records):
    if len(records) == 1:
        return records[0]

    expected_names = {
        value.strip().casefold()
        for value in (hit.victim_name, hit.title)
        if value and value.strip()
    }
    matches = [
        record
        for record in records
        if record.record_type == "incident"
        and {
            value.strip().casefold()
            for value in (record.victim_name, record.title)
            if value and value.strip()
        }
        & expected_names
    ]
    return matches[0] if len(matches) == 1 else None


class Command(BaseCommand):
    help = (
        "Safely reparse stored incident-card raw markup for structured countries. "
        "Dry-run is the default; pass --apply to write changes."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--source",
            required=True,
            help="Exact DarkSource slug to backfill.",
        )
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument(
            "--dry-run",
            action="store_true",
            help="Report proposed changes without writing (the default mode).",
        )
        mode.add_argument(
            "--apply",
            action="store_true",
            help="Write recognized country values. Without this flag, report only.",
        )
        parser.add_argument(
            "--include-recognized",
            action="store_true",
            help=(
                "Also reparse rows whose current country is already recognized. "
                "Recognized rows are protected by default."
            ),
        )

    def handle(self, *args, **options):
        source_slug = options["source"].strip()
        apply_changes = bool(options["apply"])
        include_recognized = bool(options["include_recognized"])

        try:
            source = DarkSource.objects.get(slug=source_slug)
        except DarkSource.DoesNotExist as exc:
            raise CommandError(f"Dark source slug {source_slug!r} was not found.") from exc

        if source.extractor_profile != DarkSource.ExtractorProfile.INCIDENT_CARDS:
            raise CommandError(
                f"Dark source {source.slug!r} does not use the incident_cards profile."
            )

        counts = {
            "scanned": 0,
            "candidates": 0,
            "reparsed": 0,
            "recognized": 0,
            "changed": 0,
            "unchanged": 0,
            "rejected": 0,
        }
        hits = (
            DarkHit.objects.filter(dark_source=source, record_type="incident")
            .only("id", "title", "victim_name", "country", "url", "raw")
            .order_by("id")
        )
        for hit in hits.iterator(chunk_size=500):
            counts["scanned"] += 1
            current_identity = normalize_ransomware_country(hit.country)
            if current_identity.recognized and not include_recognized:
                continue

            counts["candidates"] += 1
            if not hit.raw:
                counts["rejected"] += 1
                continue

            counts["reparsed"] += 1
            records = extract_profile_records(
                hit.raw,
                profile=DarkSource.ExtractorProfile.INCIDENT_CARDS,
                base_url=hit.url or source.url,
            )
            record = _matching_incident_record(hit, records)
            if record is None or not record.country_code or not record.country:
                counts["rejected"] += 1
                continue

            reparsed_identity = normalize_ransomware_country(record.country)
            if not reparsed_identity.recognized:
                counts["rejected"] += 1
                continue
            counts["recognized"] += 1

            if (
                current_identity.recognized
                and current_identity.country_id == reparsed_identity.country_id
            ) or hit.country == record.country:
                counts["unchanged"] += 1
                continue

            counts["changed"] += 1
            if apply_changes:
                DarkHit.objects.filter(pk=hit.pk).update(country=record.country)

        mode = "apply" if apply_changes else "dry-run"
        report = " ".join(f"{name}={value}" for name, value in counts.items())
        self.stdout.write(f"mode={mode} source={source.slug} {report}")
