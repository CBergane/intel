from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from intel.models import Feed, Item


class Command(BaseCommand):
    help = (
        "Delete items older than each feed's max_age_days plus a 30-day safety buffer."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show how many items would be deleted without deleting.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()
        total = 0

        for feed in Feed.objects.all().order_by("id"):
            cutoff = now - timedelta(days=feed.max_age_days + 30)
            queryset = Item.objects.filter(feed=feed, published_at__lt=cutoff)
            count = queryset.count()
            if count == 0:
                continue

            total += count
            if dry_run:
                self.stdout.write(
                    f"[dry-run] [{feed.id}] {feed.name}: {count} would be deleted"
                )
            else:
                queryset.delete()
                self.stdout.write(f"[{feed.id}] {feed.name}: deleted {count}")

        if dry_run:
            self.stdout.write(self.style.SUCCESS(f"Dry-run complete. would_delete={total}"))
        else:
            self.stdout.write(self.style.SUCCESS(f"Prune complete. deleted={total}"))
