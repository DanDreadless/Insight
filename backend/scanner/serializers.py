from urllib.parse import urlparse, unquote

from rest_framework import serializers

from .models import Finding, ScanJob


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = [
            'id',
            'severity',
            'category',
            'title',
            'description',
            'evidence',
            'resource_url',
        ]


_SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


class ScanJobSerializer(serializers.ModelSerializer):
    findings = serializers.SerializerMethodField()

    def get_findings(self, obj):
        # For cache-hit jobs, serve findings from the canonical source job
        source = obj.cached_from if obj.cached_from_id else obj
        ordered = sorted(
            source.findings.all(),
            key=lambda f: (_SEVERITY_RANK.get(f.severity, 4), f.category, f.title),
        )
        return FindingSerializer(ordered, many=True).data

    class Meta:
        model = ScanJob
        fields = [
            'id',
            'url',
            'status',
            'verdict',
            'created_at',
            'completed_at',
            'last_scanned_at',
            'findings',
            'scan_metadata',
            'error_message',
        ]


class ScanJobSummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for history list — no findings or scan_metadata."""
    findings_count = serializers.SerializerMethodField()

    def get_findings_count(self, obj):
        source = obj.cached_from if obj.cached_from_id else obj
        return source.findings.count()

    class Meta:
        model = ScanJob
        fields = ['id', 'url', 'status', 'verdict', 'created_at', 'completed_at', 'last_scanned_at', 'findings_count']


class ScanSubmitSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2048)

    def validate_url(self, value: str) -> str:
        value = value.strip()

        # Decode percent-encoded scheme (e.g. http%3A%2F%2Fexample.com → http://example.com).
        # Users sometimes paste URLs copied from encoded contexts (email clients, docs, etc.).
        lower = value.lower()
        if lower.startswith('http%3a') or lower.startswith('https%3a'):
            value = unquote(value)

        if len(value) > 2048:
            raise serializers.ValidationError('URL must not exceed 2048 characters.')

        parsed = urlparse(value)

        if parsed.scheme not in ('http', 'https'):
            raise serializers.ValidationError(
                'URL must use http or https scheme.'
            )

        hostname = parsed.hostname
        if not hostname:
            raise serializers.ValidationError('URL must include a valid hostname.')

        # Basic localhost / private-range rejection at serializer level
        _BLOCKED_HOSTNAMES = {
            'localhost',
            '0.0.0.0',
            '::1',
        }
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            raise serializers.ValidationError(
                'Scanning internal/loopback addresses is not permitted.'
            )

        # Reject bare IP private/loopback/link-local ranges at the serializer
        # level (deep check remains in validators.py after DNS resolution).
        # Using ipaddress covers all RFC1918 ranges correctly — the previous
        # prefix check missed 172.17–172.31 (the full 172.16.0.0/12 block).
        import ipaddress as _ipaddress
        try:
            _ip_obj = _ipaddress.ip_address(hostname)
            if not _ip_obj.is_global:
                raise serializers.ValidationError(
                    'Scanning private network addresses is not permitted.'
                )
        except ValueError:
            pass  # Not a raw IP — validators.py checks after DNS resolution

        return value
