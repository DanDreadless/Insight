"""
SSRF-safe HTTP fetcher (httpx, HTTP/2-first).

Every outbound request — including each redirect hop — is validated through
validate_url() before the connection is made. Response bodies are capped at
MAX_SIZE_BYTES (default 5 MB). Hard timeouts: connect=5s, read=10s.

Binary/download responses (Content-Disposition: attachment or non-text
Content-Type) are never stored in memory beyond a single chunk at a time —
they are stream-hashed (SHA-256) and discarded, so nothing ever touches disk
and RAM usage stays constant regardless of file size.

SSL handling: the public fetch() attempts the request with SSL verification
enabled.  If the server's certificate cannot be verified (expired, self-signed,
hostname mismatch), it retries without verification and sets ssl_cert_error=True
in the response so the caller can surface a finding.  Certificate issues are
reported independently by ssl_analyser.py via a direct TLS handshake.

HTTP/2: httpx negotiates HTTP/2 via ALPN on TLS connections and falls back to
HTTP/1.1 automatically.  Sites that throttle HTTP/1.1 (e.g. CDN-backed hosts
that prefer H2) respond significantly faster.
"""
import hashlib
import logging
import ssl
from typing import Optional
from urllib.parse import urljoin

import httpx

from scanner.validators import validate_url
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/133.0.0.0 Safari/537.36'
)
_DEFAULT_TIMEOUT = (5, 10)
# Some CDN-backed sites (e.g. sites that throttle HTTP/1.1 clients while
# preferring HTTP/2) can take 10–15 s before sending the first response byte.
# Use this longer timeout for the initial page fetch; keep _DEFAULT_TIMEOUT
# for external script fetches where a 30 s stall per script is unacceptable.
PAGE_FETCH_TIMEOUT = (10, 30)
_MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
_MAX_REDIRECTS = 10

_BINARY_CONTENT_TYPE_PREFIXES = (
    'application/octet-stream',
    'application/zip',
    'application/x-zip',
    'application/x-rar',
    'application/x-7z',
    'application/x-tar',
    'application/gzip',
    'application/x-bzip',
    'application/x-msdownload',
    'application/x-executable',
    'application/x-dosexec',
    'application/vnd.microsoft.portable-executable',
    'application/x-msdos-program',
    'application/pdf',
    'image/',
    'audio/',
    'video/',
)


def _is_download_response(headers: httpx.Headers) -> bool:
    disposition = headers.get('Content-Disposition', '')
    if 'attachment' in disposition.lower():
        return True
    content_type = headers.get('Content-Type', '').lower().split(';')[0].strip()
    return any(content_type.startswith(p) for p in _BINARY_CONTENT_TYPE_PREFIXES)


def _user_message_for_validation_error(exc_message: str) -> str | None:
    msg = exc_message.lower()
    if 'cannot resolve hostname' in msg or 'resolved to no addresses' in msg:
        return 'DNS lookup failed — the domain does not exist or could not be resolved.'
    return None


def _timeout(t: tuple[int, int]) -> httpx.Timeout:
    return httpx.Timeout(connect=t[0], read=t[1], write=t[0], pool=t[0])


def _is_ssl_cert_error(exc: httpx.ConnectError) -> bool:
    """Return True if the ConnectError was caused by SSL certificate verification."""
    cause = exc.__context__
    while cause is not None:
        if isinstance(cause, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        # httpcore wraps ssl errors; check string as last resort
        cause_str = str(cause).lower()
        if 'certificate' in cause_str and ('verify' in cause_str or 'expired' in cause_str or 'hostname' in cause_str):
            return True
        cause = cause.__context__
    # Check the exception message itself
    msg = str(exc).lower()
    return 'certificate' in msg and ('verify' in msg or 'expired' in msg or 'hostname' in msg or 'ssl' in msg)


class FetchError(Exception):
    """Raised for any error during SSRF-safe fetch.

    user_message is safe for display to end users — no internal IPs or traces.
    """
    def __init__(self, message: str, user_message: str | None = None):
        super().__init__(message)
        self.user_message = user_message or 'Could not fetch the target URL. The site may be unavailable, unreachable, or blocking automated requests.'


class HttpStatusError(FetchError):
    """Raised when the server returns a non-scannable HTTP status code."""
    def __init__(self, status_code: int, message: str):
        super().__init__(message, user_message=message)
        self.status_code = status_code


class SslVerificationError(FetchError):
    """
    Raised when SSL certificate verification fails on a hop.

    failing_url is the specific URL whose certificate could not be verified.
    """
    def __init__(self, message: str, failing_url: str = '', user_message: str | None = None):
        super().__init__(message, user_message=user_message)
        self.failing_url = failing_url


def fetch(
    url: str,
    timeout: tuple[int, int] = _DEFAULT_TIMEOUT,
    max_size_bytes: int = _MAX_SIZE_BYTES,
    max_redirects: int = _MAX_REDIRECTS,
) -> dict:
    """
    Fetch a URL safely with HTTP/2 support.

    Attempts with SSL verification enabled first.  If the server's certificate
    cannot be verified, retries without verification and sets ssl_cert_error=True
    and ssl_cert_error_url in the response dict.

    Returns a dict with:
        url                – final URL after redirects
        status_code        – HTTP status code
        headers            – response headers (dict)
        content            – raw bytes (capped at max_size_bytes)
        text               – decoded string
        redirect_chain     – list of intermediate URLs followed
        ssl_cert_error     – True if SSL verification was bypassed (optional key)
        ssl_cert_error_url – URL of the hop that failed cert verification (optional key)
    """
    _ssl_failing_url: str = ''
    try:
        return _fetch_core(url, timeout=timeout, max_size_bytes=max_size_bytes,
                           max_redirects=max_redirects, verify_ssl=True)
    except SslVerificationError as ssl_exc:
        _ssl_failing_url = ssl_exc.failing_url or url
        logger.info('SSL cert verification failed for %s — retrying without verification', _ssl_failing_url)

    result = _fetch_core(url, timeout=timeout, max_size_bytes=max_size_bytes,
                         max_redirects=max_redirects, verify_ssl=False)
    result['ssl_cert_error'] = True
    result['ssl_cert_error_url'] = _ssl_failing_url
    return result


def _fetch_core(
    url: str,
    timeout: tuple[int, int] = _DEFAULT_TIMEOUT,
    max_size_bytes: int = _MAX_SIZE_BYTES,
    max_redirects: int = _MAX_REDIRECTS,
    verify_ssl: bool = True,
) -> dict:
    """Core fetch implementation. Called by fetch() — do not call directly."""
    try:
        url = validate_url(url)
    except ValidationError as exc:
        raise FetchError(
            f'URL validation failed: {exc.message}',
            user_message=_user_message_for_validation_error(exc.message),
        ) from exc

    req_headers = {
        'User-Agent': _USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    }

    redirect_chain: list[str] = []
    current_url = url

    # http2=True: httpx negotiates H2 via ALPN and falls back to H1.1 automatically.
    # follow_redirects=False: we handle each hop manually for SSRF re-validation.
    with httpx.Client(
        http2=True,
        verify=verify_ssl,
        follow_redirects=False,
        timeout=_timeout(timeout),
    ) as client:
        try:
            for _ in range(max_redirects + 1):
                # SEC-03: Re-validate immediately before connecting (SSRF TOCTOU mitigation).
                try:
                    validate_url(current_url)
                except ValidationError as exc:
                    raise FetchError(
                        f'URL failed pre-connect SSRF re-validation: {exc.message}',
                        user_message=_user_message_for_validation_error(exc.message),
                    ) from exc

                try:
                    with client.stream('GET', current_url, headers=req_headers) as response:
                        logger.info('Fetched %s -> status=%s http_version=%s',
                                    current_url, response.status_code,
                                    getattr(response, 'http_version', '?'))

                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get('location', '')
                            if not location:
                                # No Location header — treat as final response; read body below
                                return _read_body(response, current_url, redirect_chain,
                                                  max_size_bytes, dict(response.headers))
                            next_url = urljoin(current_url, location)
                            try:
                                next_url = validate_url(next_url)
                            except ValidationError as exc:
                                raise FetchError(
                                    f'Redirect destination failed SSRF validation: {exc.message}'
                                ) from exc
                            redirect_chain.append(current_url)
                            current_url = next_url
                            # response context exits here, connection released
                            continue

                        # Final response — read body inside the stream context
                        return _read_body(response, current_url, redirect_chain,
                                          max_size_bytes, dict(response.headers))

                except httpx.TimeoutException as exc:
                    raise FetchError(
                        f'Request timed out for {current_url}',
                        user_message='Connection timed out — the server did not respond in time.',
                    ) from exc
                except httpx.ConnectError as exc:
                    if _is_ssl_cert_error(exc):
                        raise SslVerificationError(
                            f'SSL certificate verification failed for {current_url}: {exc}',
                            failing_url=current_url,
                            user_message="SSL/TLS error — the server's certificate could not be verified.",
                        ) from exc
                    exc_str = str(exc).lower()
                    if any(k in exc_str for k in ('getaddrinfo', 'name or service not known',
                                                   'nodename nor servname', 'nameresolution',
                                                   'nodename')):
                        user_msg = 'DNS lookup failed — the domain does not exist or could not be resolved.'
                    elif 'connection refused' in exc_str:
                        user_msg = 'Connection refused — the server is not accepting connections on this port.'
                    elif 'ssl' in exc_str or 'certificate' in exc_str:
                        user_msg = 'SSL/TLS error — could not establish a secure connection to the server.'
                    else:
                        user_msg = 'Could not connect to the server — the site may be offline or blocking automated requests.'
                    raise FetchError(
                        f'Connection error for {current_url}: {exc}',
                        user_message=user_msg,
                    ) from exc
                except httpx.HTTPError as exc:
                    raise FetchError(
                        f'Request failed for {current_url} [{type(exc).__name__}]: {exc}',
                        user_message='The request failed unexpectedly. The site may be offline or blocking automated requests.',
                    ) from exc

            raise FetchError(
                f'Too many redirects (max {max_redirects})',
                user_message=f'Too many redirects — the site redirected more than {max_redirects} times.',
            )

        except FetchError:
            raise
        except Exception as exc:
            raise FetchError(f'Unexpected error fetching {current_url}: {exc}') from exc


def _read_body(
    response: httpx.Response,
    current_url: str,
    redirect_chain: list[str],
    max_size_bytes: int,
    resp_headers: dict,
) -> dict:
    """Read the response body within an active httpx stream context."""
    if _is_download_response(response.headers):
        sha256 = hashlib.sha256()
        total = 0
        truncated = False
        for chunk in response.iter_bytes(chunk_size=65536):
            sha256.update(chunk)
            total += len(chunk)
            if total >= max_size_bytes:
                truncated = True
                for _ in response.iter_bytes(chunk_size=65536):
                    pass
                break

        logger.info(
            'Binary download detected at %s — SHA256=%s size_seen=%d truncated=%s',
            current_url, sha256.hexdigest(), total, truncated,
        )
        return {
            'url': current_url,
            'status_code': response.status_code,
            'headers': resp_headers,
            'content': b'',
            'text': '',
            'redirect_chain': redirect_chain,
            'is_download': True,
            'download_sha256': sha256.hexdigest(),
            'download_size_seen': total,
            'download_truncated': truncated,
            'download_content_type': resp_headers.get('Content-Type', ''),
            'download_filename': _extract_filename(resp_headers.get('Content-Disposition', '')),
        }

    content_chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes(chunk_size=65536):
        total += len(chunk)
        if total > max_size_bytes:
            content_chunks.append(chunk[: max_size_bytes - (total - len(chunk))])
            break
        content_chunks.append(chunk)

    raw_content = b''.join(content_chunks)
    encoding = response.encoding or 'utf-8'
    try:
        text = raw_content.decode(encoding, errors='replace')
    except (LookupError, UnicodeDecodeError):
        text = raw_content.decode('utf-8', errors='replace')

    return {
        'url': current_url,
        'status_code': response.status_code,
        'headers': resp_headers,
        'content': raw_content,
        'text': text,
        'redirect_chain': redirect_chain,
        'is_download': False,
    }


def _extract_filename(disposition: str) -> str:
    """Extract filename from Content-Disposition header value, or empty string."""
    for part in disposition.split(';'):
        part = part.strip()
        if part.lower().startswith('filename='):
            return part[9:].strip().strip('"\'')
    return ''
