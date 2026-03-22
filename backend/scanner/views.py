"""
Scanner API views.
"""
import json
import logging
import time

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.views import View
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ScanJob
from .serializers import ScanJobSerializer, ScanJobSummarySerializer, ScanSubmitSerializer
from .tasks import run_scan
from .modules.fetcher import fetch, FetchError

logger = logging.getLogger(__name__)


def _get_client_ip(request: HttpRequest) -> str:
    """
    Extract the real client IP address.

    By default (TRUSTED_PROXY_COUNT=0) always uses REMOTE_ADDR, which cannot
    be spoofed by the client.  Set TRUSTED_PROXY_COUNT=N in .env to peel N
    trusted proxy entries off the right of the X-Forwarded-For chain — use this
    only when the app sits behind a known, controlled reverse proxy (e.g. one
    Cloudflare hop → TRUSTED_PROXY_COUNT=1).

    Never trust the raw X-Forwarded-For header without proxy count configuration:
    it is entirely user-controllable and would allow per-IP rate-limit bypass.
    """
    proxy_count = getattr(settings, 'TRUSTED_PROXY_COUNT', 0)
    if proxy_count > 0:
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if xff:
            ips = [ip.strip() for ip in xff.split(',')]
            # The real client IP is at index -(proxy_count + 1) from the right.
            # e.g., with 1 trusted proxy: "client, proxy1" → take index 0.
            idx = max(0, len(ips) - proxy_count - 1)
            return ips[idx]
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


class HealthCheckView(APIView):
    throttle_scope = 'health'  # SEC-13: 60/minute per IP (see settings.py)

    def get(self, request: HttpRequest) -> Response:
        return Response({'status': 'ok'})


class ScanSubmitView(APIView):
    def post(self, request: HttpRequest) -> Response:
        serializer = ScanSubmitSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        url = serializer.validated_data['url']
        client_ip = _get_client_ip(request)

        # ---------------------------------------------------------------
        # Rate limiting: max N scans/hour per IP  (SEC-02 — atomic increment)
        #
        # cache.add() sets the key only if absent, preserving the existing TTL.
        # cache.incr() is a single atomic INCR in Redis — no TOCTOU race.
        # We increment BEFORE checking so concurrent requests each get a unique
        # count value and at most (rate_limit) of them can proceed.
        # ---------------------------------------------------------------
        rate_limit = getattr(settings, 'RATE_LIMIT_SCANS_PER_HOUR', 5)
        if rate_limit > 0:
            cache_key = f'scan_rate:{client_ip}'
            cache.add(cache_key, 0, timeout=3600)
            try:
                new_count = cache.incr(cache_key)
            except ValueError:
                # Key expired between add() and incr() — reset atomically.
                cache.set(cache_key, 1, timeout=3600)
                new_count = 1

            if new_count > rate_limit:
                logger.warning('Rate limit exceeded: ip=%s count=%s', client_ip, new_count)
                return Response(
                    {
                        'error': 'Rate limit exceeded.',
                        'detail': f'Maximum {rate_limit} scans per hour per IP address.',
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

        # ---------------------------------------------------------------
        # Create ScanJob and enqueue Celery task
        # ---------------------------------------------------------------
        job = ScanJob.objects.create(
            url=url,
            submitter_ip=client_ip,
            status=ScanJob.Status.PENDING,
        )

        run_scan.delay(str(job.id))

        logger.info('Scan queued: job=%s url=%s ip=%s', job.id, url, client_ip)

        return Response(
            {'id': str(job.id), 'status': job.status},
            status=status.HTTP_202_ACCEPTED,
        )


class ScanStatusView(APIView):
    throttle_scope = 'scan_status'  # SEC-06: 600/hour per IP (see settings.py)

    def get(self, request: HttpRequest, scan_id: str) -> Response:
        try:
            job = ScanJob.objects.prefetch_related('findings').get(id=scan_id)
        except (ScanJob.DoesNotExist, ValueError):
            return Response({'error': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ScanJobSerializer(job)
        data = serializer.data

        # Delete failed jobs after serialising — they have already communicated
        # their error via SSE; this cleans up any orphaned records where no SSE
        # connection was active when the scan failed.
        if job.status == ScanJob.Status.FAILED:
            job.delete()

        return Response(data)


class ScanStreamView(View):
    """
    Server-Sent Events stream for real-time scan progress.
    Polls the ScanJob every 2 seconds and emits status events.
    Plain Django View — not DRF APIView — so content negotiation does not
    interfere with the text/event-stream content type.
    """

    def get(self, request: HttpRequest, scan_id: str) -> HttpResponse:
        # SEC-06: manual rate limit for plain Django views (can't use DRF throttle_scope).
        # 120 SSE connections per IP per hour — each stream runs up to 4 minutes.
        client_ip = _get_client_ip(request)
        stream_rate_key = f'stream_rate:{client_ip}'
        cache.add(stream_rate_key, 0, timeout=3600)
        try:
            stream_count = cache.incr(stream_rate_key)
        except ValueError:
            cache.set(stream_rate_key, 1, timeout=3600)
            stream_count = 1
        if stream_count > 120:
            return JsonResponse({'error': 'Rate limit exceeded.'}, status=429)

        try:
            ScanJob.objects.get(id=scan_id)
        except (ScanJob.DoesNotExist, ValueError):
            return JsonResponse({'error': 'Scan not found.'}, status=404)

        def event_stream():
            max_polls = 120  # 120 * 2s = 4 minutes max stream
            polls = 0

            while polls < max_polls:
                try:
                    job = ScanJob.objects.prefetch_related('findings').get(id=scan_id)
                except ScanJob.DoesNotExist:
                    yield _sse_event('error', json.dumps({'error': 'Scan not found'}))
                    return

                if job.status in (ScanJob.Status.COMPLETE, ScanJob.Status.FAILED):
                    if job.status == ScanJob.Status.COMPLETE:
                        serializer = ScanJobSerializer(job)
                        yield _sse_event('complete', json.dumps(serializer.data))
                    else:
                        # Send full error details before deleting the job so the
                        # client has everything it needs without needing to poll.
                        yield _sse_event('error', json.dumps({
                            'status': 'FAILED',
                            'error_message': job.error_message,
                            'scan_metadata': job.scan_metadata,
                        }))
                        job.delete()
                    return

                # Still running — emit status update
                yield _sse_event('status_update', json.dumps({
                    'status': job.status,
                    'id': str(job.id),
                }))

                time.sleep(2)
                polls += 1

            # Timeout
            yield _sse_event('error', json.dumps({'error': 'Stream timed out waiting for scan completion'}))

        response = StreamingHttpResponse(
            event_stream(),
            content_type='text/event-stream',
        )
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'
        # CORS is handled by django-cors-headers middleware; do not override here
        return response


class ScanHistoryView(APIView):
    """
    GET /api/history/?q=<search>&page=<n>

    Returns a paginated list of completed (and failed) scans, newest first.
    Optional ?q= filters by URL substring (domain search).
    Page size: 20. Returns {count, page, total_pages, results}.
    """
    throttle_scope = 'scan_status'

    PAGE_SIZE = 20

    def get(self, request: HttpRequest) -> Response:
        q = request.GET.get('q', '').strip()
        try:
            page = max(1, int(request.GET.get('page', 1)))
        except (ValueError, TypeError):
            page = 1

        qs = ScanJob.objects.filter(
            cached_from__isnull=True,
        ).exclude(status=ScanJob.Status.PENDING).exclude(
            status=ScanJob.Status.RUNNING,
        ).order_by('-created_at')

        if q:
            qs = qs.filter(url__icontains=q)

        total = qs.count()
        total_pages = max(1, (total + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        page = min(page, total_pages)
        offset = (page - 1) * self.PAGE_SIZE
        results = qs[offset: offset + self.PAGE_SIZE]

        serializer = ScanJobSummarySerializer(results, many=True)
        return Response({
            'count': total,
            'page': page,
            'total_pages': total_pages,
            'results': serializer.data,
        })


def _sse_event(event_type: str, data: str) -> str:
    """Format a Server-Sent Events message."""
    # SEC-20: strip CR/LF from event_type to prevent SSE header injection.
    safe_type = event_type.replace('\r', '').replace('\n', '')
    return f'event: {safe_type}\ndata: {data}\n\n'


class ScanSourceView(APIView):
    """
    Re-fetch and return the raw source of a URL that was part of a completed scan.

    Only permits URLs that belong to the scan (the scanned URL itself or one of
    the external script URLs collected during analysis).  This prevents the
    endpoint being used as an open proxy.

    GET /api/scan/{scan_id}/source/?url=<url>
    Returns: text/plain
    """
    throttle_scope = 'scan_status'  # Reuse the same 600/hour bucket

    def get(self, request: HttpRequest, scan_id: str) -> HttpResponse:
        try:
            job = ScanJob.objects.get(id=scan_id)
        except (ScanJob.DoesNotExist, ValueError):
            return HttpResponse('Scan not found.', status=404, content_type='text/plain')

        if job.status != ScanJob.Status.COMPLETE:
            return HttpResponse('Scan not complete.', status=400, content_type='text/plain')

        requested_url = request.GET.get('url', '').strip()
        if not requested_url:
            # Default to the scanned URL
            requested_url = job.scan_metadata.get('final_url') or job.url

        # Build the allowlist of URLs that belong to this scan
        metadata = job.scan_metadata or {}
        allowed_urls = {
            job.url,
            metadata.get('final_url', ''),
        }
        for script_url in metadata.get('scripts_urls', []):
            if script_url:
                allowed_urls.add(script_url)

        if requested_url not in allowed_urls:
            return HttpResponse(
                'URL not in scan scope.',
                status=403,
                content_type='text/plain',
            )

        try:
            response = fetch(requested_url, max_size_bytes=5 * 1024 * 1024)
        except FetchError as exc:
            logger.warning('ScanSourceView fetch error: scan=%s url=%s err=%s', scan_id, requested_url, exc)
            return HttpResponse('Could not fetch source.', status=502, content_type='text/plain')
        except Exception as exc:
            logger.error('ScanSourceView unexpected error: scan=%s err=%s', scan_id, exc)
            return HttpResponse('Unexpected error.', status=500, content_type='text/plain')

        source = response.get('text', '')
        resp = HttpResponse(source, content_type='text/plain; charset=utf-8')
        resp['X-Content-Type-Options'] = 'nosniff'
        return resp
