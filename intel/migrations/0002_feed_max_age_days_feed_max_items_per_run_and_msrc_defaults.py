from django.db import migrations, models
from django.db.models import Q


def set_msrc_feed_defaults(apps, schema_editor):
    Feed = apps.get_model("intel", "Feed")
    Source = apps.get_model("intel", "Source")

    msrc_source_ids = Source.objects.filter(
        Q(slug__iexact="msrc") | Q(name__icontains="msrc")
    ).values_list("id", flat=True)

    Feed.objects.filter(
        Q(source_id__in=msrc_source_ids) | Q(name__icontains="msrc")
    ).update(max_age_days=90, max_items_per_run=200)


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="feed",
            name="max_age_days",
            field=models.PositiveIntegerField(default=180),
        ),
        migrations.AddField(
            model_name="feed",
            name="max_items_per_run",
            field=models.PositiveIntegerField(default=200),
        ),
        migrations.RunPython(set_msrc_feed_defaults, migrations.RunPython.noop),
    ]
