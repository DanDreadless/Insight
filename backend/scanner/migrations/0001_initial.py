import uuid
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='ScanJob',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=2048)),
                ('status', models.CharField(
                    choices=[
                        ('PENDING', 'Pending'),
                        ('RUNNING', 'Running'),
                        ('COMPLETE', 'Complete'),
                        ('FAILED', 'Failed'),
                    ],
                    default='PENDING',
                    max_length=10,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('error_message', models.TextField(blank=True)),
                ('submitter_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('verdict', models.CharField(
                    choices=[
                        ('MALICIOUS', 'Malicious'),
                        ('SUSPICIOUS', 'Suspicious'),
                        ('CLEAN', 'Clean'),
                        ('UNKNOWN', 'Unknown'),
                    ],
                    default='UNKNOWN',
                    max_length=10,
                )),
                ('scan_metadata', models.JSONField(default=dict)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scan', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='findings',
                    to='scanner.scanjob',
                )),
                ('severity', models.CharField(
                    choices=[
                        ('CRITICAL', 'Critical'),
                        ('HIGH', 'High'),
                        ('MEDIUM', 'Medium'),
                        ('LOW', 'Low'),
                        ('INFO', 'Info'),
                    ],
                    max_length=10,
                )),
                ('category', models.CharField(max_length=100)),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('evidence', models.TextField(blank=True)),
                ('resource_url', models.URLField(blank=True, max_length=2048)),
            ],
            options={
                'ordering': ['severity', 'category'],
            },
        ),
    ]
