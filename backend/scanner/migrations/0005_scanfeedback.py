import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_scanjob_detection_engine_version'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanFeedback',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(max_length=2048)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('reason', models.CharField(
                    choices=[
                        ('false_positive', 'False Positive'),
                        ('missed_threat', 'Missed Threat'),
                        ('wrong_severity', 'Wrong Severity'),
                        ('other', 'Other'),
                    ],
                    max_length=20,
                )),
                ('note', models.TextField(blank=True)),
                ('actual_verdict', models.CharField(max_length=10)),
                ('expected_verdict', models.CharField(blank=True, max_length=10)),
                ('findings_snapshot', models.JSONField(default=list)),
                ('resolved', models.BooleanField(default=False)),
                ('submitter_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('scan', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='feedback',
                    to='scanner.scanjob',
                )),
            ],
            options={
                'ordering': ['-submitted_at'],
            },
        ),
    ]
