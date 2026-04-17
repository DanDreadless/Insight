"""
SSRF-safe HTTP fetcher.

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
"""
import hashlib
import logging
from typing import Optional
from urllib.parse import urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter

from scanner.validators import validate_url
from django.core.exceptions import ValidationError

# Suppress the urllib3 InsecureRequestWarning that fires when verify=False is
# used during the SSL-fallback retry path.  The warning is noise here because
# the scanner intentionally retries without verification after a cert failure,
# and ssl_analyser.py reports the certificate issue as a finding independently.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Mimic a real browser UA so CDN/WAF bot-detection (Cloudflare et al.) does not
# block the passive fetch before we can analyse the page content.
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

# Content-Type prefixes/values that indicate binary/download content.
# These responses are stream-hashed only — no body is stored in memory.
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


def _is_download_response(headers: dict) -> bool:
    """
    Return True if the response should be treated as a file download rather
    than a web page.  Checks both Content-Disposition and Content-Type.
    """
    disposition = headers.get('Content-Disposition', '')
    if 'attachment' in disposition.lower():
        return True

    content_type = headers.get('Content-Type', '').lower().split(';')[0].strip()
    return any(content_type.startswith(p) for p in _BINARY_CONTENT_TYPE_PREFIXES)


def _user_message_for_validation_error(exc_message: str) -> str | None:
    """
    Map a ValidationError message to a safe user-facing string.
    Only DNS failures are surfaced specifically — SSRF-related rejections
    (blocked IP ranges, private hostnames) stay generic to avoid leaking
    internal network topology.
    """
    msg = exc_message.lower()
    if 'cannot resolve hostname' in msg or 'resolved to no addresses' in msg:
        return 'DNS lookup failed — the domain does not exist or could not be resolved.'
    # All other validation failures (blocked IP, invalid scheme, etc.) stay generic.
    return None


class FetchError(Exception):
    """Raised for any error during SSRF-safe fetch.

    user_message is a safe, human-readable explanation suitable for display to
    end users — it must not contain internal URLs, IP addresses, or stack traces.
    The main exception message is for server-side logging only.
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

    failing_url is the specific URL (hop) whose certificate could not be
    verified — used by fetch() to record which host had the cert issue and
    to run ssl_analyser on that hostname even if it is not the final URL.
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
    Fetch a URL safely.

    Attempts with SSL verification enabled first.  If the server's certificate
    cannot be verified, retries without verification and sets ssl_cert_error=True
    and ssl_cert_error_url in the response dict so tasks.py can surface a finding
    and run ssl_analyser on the failing hostname.

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
        # Capture before Python deletes the 'as' variable at end of except block.
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
    """
    Core fetch implementation.  Called by fetch() — do not call directly.
    verify_ssl=False is only used on the SSL-fallback retry path.
    """
    # Validate the initial URL before opening any connection
    try:
        url = validate_url(url)
    except ValidationError as exc:
        raise FetchError(
            f'URL validation failed: {exc.message}',
            user_message=_user_message_for_validation_error(exc.message),
        ) from exc

    session = requests.Session()
    # allow_redirects=False on every session.get() call below prevents requests
    # from auto-following redirects — we handle each hop manually so we can
    # re-validate the destination URL for SSRF before connecting.
    adapter = HTTPAdapter(max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    headers = {
        'User-Agent': _USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        # Sec-Fetch headers signal a top-level browser navigation — a strong
        # signal Cloudflare and other WAFs use to distinguish bots from browsers.
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    }

    redirect_chain: list[str] = []
    current_url = url
    response = None

    try:
        for _ in range(max_redirects + 1):
            # SEC-03: Re-validate immediately before connecting to shrink the
            # SSRF TOCTOU window to microseconds.  A DNS rebinding attack would
            # need to flip the DNS record between this call and the kernel's TCP
            # connect() — practically infeasible without TTL=0 and precise timing.
            # Full elimination requires IP-pinning at the urllib3 socket layer.
            try:
                validate_url(current_url)
            except ValidationError as exc:
                raise FetchError(
                    f'URL failed pre-connect SSRF re-validation: {exc.message}',
                    user_message=_user_message_for_validation_error(exc.message),
                ) from exc

            try:
                response = session.get(
                    current_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=verify_ssl,
                )
            except requests.exceptions.Timeout as exc:
                raise FetchError(
                    f'Request timed out for {current_url}',
                    user_message='Connection timed out — the server did not respond in time.',
                ) from exc
            except requests.exceptions.SSLError as exc:
                # Raised specifically for cert verification failures (expired,
                # self-signed, hostname mismatch).  Re-raise as SslVerificationError
                # so fetch() can retry with verify_ssl=False and record the failing URL.
                raise SslVerificationError(
                    f'SSL certificate verification failed for {current_url}: {exc}',
                    failing_url=current_url,
                    user_message='SSL/TLS error — the server\'s certificate could not be verified.',
                ) from exc
            except requests.exceptions.ConnectionError as exc:
                exc_str = str(exc).lower()
                if 'getaddrinfo failed' in exc_str or 'name or service not known' in exc_str or 'nodename nor servname' in exc_str or 'nameresolution' in exc_str.replace(' ', ''):
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
            except requests.exceptions.RequestException as exc:
                raise FetchError(
                    f'Request failed for {current_url} [{type(exc).__name__}]: {exc}',
                    user_message='The request failed unexpectedly. The site may be offline or blocking automated requests.',
                ) from exc

            logger.info('Fetched %s -> status=%s', current_url, response.status_code)

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                if not location:
                    break

                # Resolve relative redirect URLs
                next_url = urljoin(current_url, location)

                # SSRF-validate the redirect destination before following
                try:
                    next_url = validate_url(next_url)
                except ValidationError as exc:
                    raise FetchError(
                        f'Redirect destination failed SSRF validation: {exc.message}'
                    ) from exc

                redirect_chain.append(current_url)
                current_url = next_url
                response.close()
                continue

            # Not a redirect — read the body
            break
        else:
            raise FetchError(
                f'Too many redirects (max {max_redirects})',
                user_message=f'Too many redirects — the site redirected more than {max_redirects} times.',
            )

        resp_headers: dict[str, str] = dict(response.headers)

        # Binary/download response — stream-hash only, never accumulate in RAM
        if _is_download_response(resp_headers):
            sha256 = hashlib.sha256()
            total = 0
            truncated = False
            for chunk in response.iter_content(chunk_size=65536):
                sha256.update(chunk)
                total += len(chunk)
                if total >= max_size_bytes:
                    truncated = True
                    # Drain remaining response without storing it
                    for _ in response.iter_content(chunk_size=65536):
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

        # Text response — read body with size cap
        content_chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > max_size_bytes:
                content_chunks.append(chunk[: max_size_bytes - (total - len(chunk))])
                break
            content_chunks.append(chunk)

        raw_content = b''.join(content_chunks)

        # Decode text
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

    except FetchError:
        raise
    except Exception as exc:
        raise FetchError(f'Unexpected error fetching {current_url}: {exc}') from exc
    finally:
        session.close()


def _extract_filename(disposition: str) -> str:
    """Extract filename from Content-Disposition header value, or empty string."""
    for part in disposition.split(';'):
        part = part.strip()
        if part.lower().startswith('filename='):
            return part[9:].strip().strip('"\'')
    return ''
