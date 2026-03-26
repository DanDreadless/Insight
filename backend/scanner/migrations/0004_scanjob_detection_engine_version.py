from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_scanjob_content_hash_last_scanned_at_cached_from'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanjob',
            name='detection_engine_version',
            field=models.IntegerField(default=0),
        ),
    ]
