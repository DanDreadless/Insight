import uuid
from django.db import models


class ScanJob(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        RUNNING = 'RUNNING', 'Running'
        COMPLETE = 'COMPLETE', 'Complete'
        FAILED = 'FAILED', 'Failed'

    class Verdict(models.TextChoices):
        MALICIOUS = 'MALICIOUS', 'Malicious'
        SUSPICIOUS = 'SUSPICIOUS', 'Suspicious'
        CLEAN = 'CLEAN', 'Clean'
        UNKNOWN = 'UNKNOWN', 'Unknown'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2048)
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    submitter_ip = models.GenericIPAddressField(null=True, blank=True)
    verdict = models.CharField(
        max_length=10,
        choices=Verdict.choices,
        default=Verdict.UNKNOWN,
    )
    scan_metadata = models.JSONField(default=dict)
    content_hash = models.CharField(max_length=64, blank=True, db_index=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    detection_engine_version = models.IntegerField(default=0)
    cached_from = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='cache_hits',
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'ScanJob({self.id}, {self.url}, {self.status})'


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = 'CRITICAL', 'Critical'
        HIGH = 'HIGH', 'High'
        MEDIUM = 'MEDIUM', 'Medium'
        LOW = 'LOW', 'Low'
        INFO = 'INFO', 'Info'

    _SEVERITY_ORDER = {
        'CRITICAL': 0,
        'HIGH': 1,
        'MEDIUM': 2,
        'LOW': 3,
        'INFO': 4,
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanJob, related_name='findings', on_delete=models.CASCADE)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    category = models.CharField(max_length=100)
    title = models.CharField(max_length=200)
    description = models.TextField()
    evidence = models.TextField(blank=True)
    resource_url = models.URLField(max_length=2048, blank=True)

    class Meta:
        ordering = []  # Ordering handled by ScanJobSerializer (severity-ranked, not alphabetical)

    @property
    def severity_order(self) -> int:
        return self._SEVERITY_ORDER.get(self.severity, 99)

    def __str__(self) -> str:
        return f'Finding({self.severity}, {self.title})'


class ScanFeedback(models.Model):
    class Reason(models.TextChoices):
        FALSE_POSITIVE = 'false_positive', 'False Positive'
        MISSED_THREAT = 'missed_threat', 'Missed Threat'
        WRONG_SEVERITY = 'wrong_severity', 'Wrong Severity'
        OTHER = 'other', 'Other'

    scan = models.ForeignKey(
        ScanJob,
        related_name='feedback',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    url = models.URLField(max_length=2048)
    submitted_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=20, choices=Reason.choices)
    note = models.TextField(blank=True)
    actual_verdict = models.CharField(max_length=10)
    expected_verdict = models.CharField(max_length=10, blank=True)
    findings_snapshot = models.JSONField(default=list)
    resolved = models.BooleanField(default=False)
    submitter_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self) -> str:
        return f'ScanFeedback({self.pk}, {self.reason}, {self.url[:60]})'
