from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0010_darkhit_is_watch_match"),
    ]

    operations = [
        migrations.AddField(
            model_name="darkhit",
            name="alert_identity_hash",
            field=models.CharField(blank=True, db_index=True, max_length=64),
        ),
        migrations.AddField(
            model_name="darkhit",
            name="last_alert_fingerprint",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="darkhit",
            name="last_alerted_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
    ]
