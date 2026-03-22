import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_alter_finding_ordering'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanjob',
            name='content_hash',
            field=models.CharField(blank=True, db_index=True, max_length=64),
        ),
        migrations.AddField(
            model_name='scanjob',
            name='last_scanned_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='scanjob',
            name='cached_from',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='cache_hits',
                to='scanner.scanjob',
            ),
        ),
    ]
