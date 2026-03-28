from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0009_darkhit_structured_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="darkhit",
            name="is_watch_match",
            field=models.BooleanField(db_index=True, default=False),
        ),
    ]
