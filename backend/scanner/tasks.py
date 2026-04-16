"""
Celery tasks for the scanner application.
"""
import hashlib
import logging
import os
import re
import time
from urllib.parse import urlparse

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone as django_timezone

from scanner.models import Finding, ScanJob
from scanner.validators import validate_url
from scanner.modules.fetcher import fetch, FetchError, HttpStatusError
from scanner.modules.resource_collector import collect_resources
from scanner.modules import (
    header_analyser,
    ssl_analyser,
    domain_intelligence,
    html_analyser,
    js_analyser,
    scorer,
    tech_detector,
)
from scanner.modules.robots_checker import check_robots
from scanner.modules.whois_lookup import lookup_whois
from scanner.modules.engine_version import get_engine_version
from scanner.modules.known_good_domains import is_known_good, is_site_builder_cdn, PLATFORM_INLINE_SKIP_BYTES

logger = logging.getLogger(__name__)


def _get_client_ip_from_url(url: str) -> str:
    """Extract hostname from URL for SSL analysis."""
    return urlparse(url).hostname or ''


# Script file extensions and Content-Types that indicate a directly-served
# script file rather than an HTML page.  When detected, the raw response body
# is passed straight to js_analyser so dropper/C2 patterns are caught even
# though there are no <script> tags to collect.
_SCRIPT_EXTENSIONS = frozenset({
    # POSIX / shell
    '.sh', '.bash', '.zsh', '.ksh', '.fish', '.csh', '.tcsh',
    # PowerShell
    '.ps1', '.psm1', '.psd1', '.pssc', '.cdxml',
    # Windows Script Host / scriptlets (common malspam and LOLBIN vectors)
    '.wsf',                         # Windows Script File (JScript/VBScript mix)
    '.wsc', '.sct',                 # COM scriptlets — regsvr32 squiblydoo
    '.jse',                         # JScript Encoded (obfuscated)
    '.vbs', '.vbe',                 # VBScript / VBScript Encoded
    '.hta',                         # HTML Application (runs with elevated trust)
    # Windows batch / registry / AutoRun (text-based execution vectors)
    '.bat', '.cmd',
    '.reg',                         # Windows Registry script
    '.inf',                         # AutoRun / Setup INF
    '.scf',                         # Shell Command File (credential harvesting via UNC)
    # XSL — wmic /format: LOLBIN execution vector
    '.xsl', '.xslt',
    # SVG — can embed JavaScript
    '.svg',
    # General scripting languages
    '.py',
    '.pl', '.pm',                   # Perl
    '.rb',                          # Ruby
    '.lua',                         # Lua (used in some C2/RAT frameworks)
    '.tcl',                         # Tcl
    '.awk',
    # JavaScript served directly
    '.js', '.mjs',
})

_SCRIPT_CONTENT_TYPES = frozenset({
    # Shell
    'text/x-shellscript', 'application/x-sh', 'application/x-shellscript',
    'application/x-csh', 'text/x-csh',
    # Python
    'text/x-python', 'application/x-python',
    # Perl / Ruby / Lua / Tcl
    'text/x-perl', 'application/x-perl',
    'text/x-ruby', 'application/x-ruby',
    'text/x-lua', 'application/x-lua',
    'text/x-tcl', 'application/x-tcl',
    # JavaScript
    'text/javascript', 'application/javascript', 'application/x-javascript',
    'text/jscript', 'application/x-jscript',
    # VBScript
    'text/vbscript', 'application/x-vbscript',
    # PowerShell
    'text/x-powershell', 'application/x-powershell',
    # Batch / Windows script
    'application/x-bat', 'application/x-wsf',
    # XSL
    'application/xslt+xml', 'text/xsl',
    # SVG (can contain embedded scripts)
    'image/svg+xml',
})


def _update_progress(job, step: int, total_steps: int, label: str, current_url: str = '', findings_count: int = 0) -> None:
    """Write incremental progress to scan_metadata so the SSE stream can surface it."""
    job.scan_metadata = {
        '_progress': {
            'step': step,
            'total_steps': total_steps,
            'label': label,
            'current_url': current_url,
            'findings_count': findings_count,
        }
    }
    job.save(update_fields=['scan_metadata'])


def _is_direct_script(url: str, headers: dict) -> bool:
    """
    Return True if the URL or Content-Type indicates a directly-served script
    file rather than an HTML page.  Used to route raw content through the JS
    analyser when there are no <script> tags to collect.
    """
    from pathlib import PurePosixPath
    suffix = PurePosixPath(urlparse(url).path).suffix.lower()
    if suffix in _SCRIPT_EXTENSIONS:
        return True
    ct = headers.get('Content-Type', headers.get('content-type', '')).lower().split(';')[0].strip()
    return ct in _SCRIPT_CONTENT_TYPES


# ---------------------------------------------------------------------------
# Carapace renderer flag → Insight finding conversion
# ---------------------------------------------------------------------------

# Codes produced as a side-effect of Carapace's sanitisation pipeline.
# They fire on almost every real page and carry no independent threat signal.
_CARAPACE_SKIP_CODES: frozenset[str] = frozenset({
    'BLOCKED_ELEMENT_SCRIPT',   # Carapace always strips <script> tags
    'BLOCKED_ELEMENT_IFRAME',   # Always stripped
    'BLOCKED_ELEMENT_OTHER',    # Always stripped
    'JAVASCRIPT_URL_STRIPPED',  # Very common; stripped as sanitisation
    'NETWORK_ATTEMPT_BLOCKED',  # All network is blocked by design
})

_CARAPACE_SEVERITY_MAP: dict[str, str] = {
    'critical': 'CRITICAL',
    'high':     'HIGH',
    'medium':   'MEDIUM',
    'low':      'LOW',
}

# (title, analyst-facing description) for each flag code.
_CARAPACE_FLAG_INFO: dict[str, tuple[str, str]] = {
    'DRIVE_BY_DOWNLOAD': (
        'Drive-by download blocked by renderer',
        'The Carapace renderer intercepted an automatic file download. The file body was never '
        'written to disk — only the filename, MIME type, and SHA-256 hash were recorded. '
        'Auto-downloading executables or archives is the primary delivery mechanism for '
        'drive-by malware attacks.',
    ),
    'JS_EVAL_DETECTED': (
        'Renderer: eval() call detected',
        'A call to eval() was found during render-phase static analysis. eval() executes '
        'arbitrary JavaScript from a string, making it the primary mechanism for hiding '
        'malicious payloads from static analysis tools.',
    ),
    'JS_FUNCTION_CONSTRUCTOR': (
        'Renderer: Function constructor detected',
        'new Function(code) was found during render-phase analysis. Like eval(), this '
        'constructs and executes arbitrary code from a string at runtime.',
    ),
    'BASE64_OBFUSCATION': (
        'Renderer: base64-encoded payload detected',
        'atob() decoding a string literal was detected. The decoded value is in the evidence '
        'field. Base64 encoding is commonly used to hide URLs, shell commands, and payload '
        'strings from text-based scanners.',
    ),
    'HEX_OBFUSCATION': (
        'Renderer: hex-escaped string obfuscation',
        'A string with a high density of \\xNN hex escape sequences was detected — a common '
        'technique for hiding URLs, shell commands, and payload strings from static scanners.',
    ),
    'INNER_HTML_MUTATION': (
        'Renderer: innerHTML assignment',
        'A script assigns to innerHTML or outerHTML, which can inject arbitrary HTML and event '
        'handlers into the DOM. Combined with other flags this indicates DOM-based XSS or '
        'injected payload delivery.',
    ),
    'WEBSOCKET_ATTEMPT': (
        'Renderer: WebSocket connection attempted',
        'A WebSocket was constructed in page scripts. WebSocket connections bypass HTTP proxy '
        'inspection and are a common channel for C2 (command-and-control) communication.',
    ),
    'TIMER_STRING_EXEC': (
        'Renderer: timer string execution',
        'setTimeout or setInterval was called with a string argument — functionally equivalent '
        'to eval(). Commonly used to delay payload execution and evade time-based sandbox analysis.',
    ),
    'REDIRECT_ATTEMPT': (
        'Renderer: JavaScript navigation redirect',
        'A script assigns a URL to window.location or similar. JavaScript redirects are '
        'commonly used in traffic distribution systems and phishing redirect chains.',
    ),
    'DOCUMENT_WRITE': (
        'Renderer: document.write() usage',
        'document.write() injects HTML directly into the page and can be used to insert '
        'hidden iframes, script tags, or redirect elements after the initial page load.',
    ),
    'COOKIE_ACCESS': (
        'Renderer: document.cookie write',
        'A script writes to document.cookie, potentially setting tracking, session-fixation, '
        'or data-exfiltration cookies.',
    ),
    'EVENT_HANDLER_STRIPPED': (
        'Renderer: inline event handler stripped',
        'An inline on* event handler attribute (e.g. onclick, onload) was removed by the '
        'HTML sanitiser. Inline handlers are used to execute scripts without a <script> tag.',
    ),
    'META_REDIRECT_STRIPPED': (
        'Renderer: meta refresh redirect stripped',
        'A <meta http-equiv="refresh"> redirect was removed during sanitisation. Meta '
        'refreshes are used to redirect visitors to phishing pages or malware delivery sites.',
    ),
    'SANDBOX_EVASION_WEBDRIVER': (
        'Sandbox evasion: webdriver detection probe',
        'A script reads navigator.webdriver — a property that is true in Selenium/WebDriver '
        'browsers and undefined in real user browsers. No legitimate website reads this. '
        'Scripts that check for it are designed to serve different content to security '
        'analysts than to real visitors, making this a strong indicator of intentionally '
        'evasive malware.',
    ),
    'SANDBOX_EVASION_HEADLESS_STRING': (
        'Sandbox evasion: headless browser identifier in script',
        'A string literal containing a known headless browser identifier was found in page '
        'scripts (e.g. "HeadlessChrome", "PhantomJS", "$cdc_"). These strings appear '
        'exclusively in anti-analysis code that checks for automation artifacts. Legitimate '
        'websites do not check for these identifiers.',
    ),
    'SANDBOX_EVASION_SCREEN_PROBE': (
        'Sandbox evasion: screen dimension probe',
        'A script accesses window.outerHeight or window.outerWidth — properties that return '
        '0 in headless environments. Checking these is a known technique for detecting '
        'automated analysis environments and serving clean content to scanners.',
    ),
    'SANDBOX_EVASION_PLUGINS_PROBE': (
        'Sandbox evasion: plugin list probe',
        'A script accesses navigator.plugins. Headless browsers have an empty plugins list; '
        'real browsers show installed extensions. Checking plugins.length is a common '
        'technique for distinguishing analysis environments from real users.',
    ),
}


def _carapace_flags_to_findings(flags: list[dict], url: str) -> list[dict]:
    """
    Convert Carapace threat report flags into Insight finding dicts.

    Sanitisation-behaviour codes (those that fire on nearly every real page
    as a natural side-effect of Carapace's JS/network blocking) are skipped.
    All remaining flags are surfaced under category='Renderer' so they are
    clearly distinguishable from Insight's own analysis findings.
    """
    findings: list[dict] = []
    for flag in flags:
        code = flag.get('code', '')
        if code in _CARAPACE_SKIP_CODES:
            continue
        severity = _CARAPACE_SEVERITY_MAP.get(flag.get('severity', 'low'), 'LOW')
        title, description = _CARAPACE_FLAG_INFO.get(
            code,
            (f'Renderer: {code}', f'Carapace renderer reported: {flag.get("detail", "")}'),
        )
        findings.append({
            'severity': severity,
            'category': 'Renderer',
            'title': title,
            'description': description,
            'evidence': flag.get('detail', ''),
            'resource_url': url,
        })
    return findings


def _detect_cloudflare_challenge(headers: dict, body: str) -> str | None:
    """
    Return a user-facing error message if the response is a Cloudflare challenge
    page that a passive scanner cannot complete, else None.

    Covers:
    - Turnstile (interactive widget requiring human interaction)
    - Managed challenge / JS challenge (requires browser JS execution)
    """
    server = headers.get('Server', headers.get('server', '')).lower()
    has_cf_ray = any(k.lower() == 'cf-ray' for k in headers)
    if 'cloudflare' not in server and not has_cf_ray:
        return None

    body_lower = body.lower()

    # Turnstile — interactive human-verification widget
    if 'cf-turnstile' in body_lower or '/cdn-cgi/turnstile/' in body_lower:
        return (
            'Cloudflare Turnstile challenge detected — this site requires interactive '
            'human verification that a passive scanner cannot complete. '
            'Use a browser-based tool (Burp Suite, browser DevTools) for further analysis.'
        )

    # Managed challenge / JS challenge — requires JavaScript execution
    if (
        'cf_challenge_form' in body_lower
        or '/cdn-cgi/challenge-platform/' in body_lower
        or 'window._cf_chl_opt' in body_lower
        or 'just a moment' in body_lower
    ):
        return (
            'Cloudflare browser challenge detected — this site requires JavaScript '
            'execution that a passive scanner cannot complete. '
            'Use a browser-based tool (Burp Suite, browser DevTools) for further analysis.'
        )

    return None


@shared_task(
    bind=True,
    name='scanner.tasks.run_scan',
    max_retries=0,
    soft_time_limit=getattr(settings, 'CELERY_TASK_SOFT_TIME_LIMIT', 60),
    time_limit=getattr(settings, 'CELERY_TASK_TIME_LIMIT', 90),
)
def run_scan(self, scan_job_id: str) -> dict:
    """
    Execute a full passive scan for a given ScanJob ID.

    Steps:
    1. Validate URL
    2. Fetch target page
    3. Collect resources
    4. Run all analysers
    5. Aggregate findings with context collapse check
    6. Persist results
    """
    # ----------------------------------------------------------------
    # Fetch the ScanJob record
    # ----------------------------------------------------------------
    try:
        job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        logger.error('ScanJob %s not found', scan_job_id)
        return {'error': 'ScanJob not found'}

    job.status = ScanJob.Status.RUNNING
    job.save(update_fields=['status'])

    current_engine_version = get_engine_version()
    scan_start = time.monotonic()
    all_findings: list[dict] = []
    _carapace: dict | None = None   # populated by Step 3c if Carapace is configured

    try:
        url = job.url

        # ----------------------------------------------------------------
        # Step 1: SSRF-validate URL (defence in depth — also done in view)
        # ----------------------------------------------------------------
        from django.core.exceptions import ValidationError
        try:
            url = validate_url(url)
        except ValidationError as exc:
            raise FetchError(f'URL validation failed: {exc.message}') from exc

        # ----------------------------------------------------------------
        # Step 2: Fetch target page (with scheme fallback)
        _update_progress(job, 1, 7, 'Fetching page', url, 0)
        # If the initial fetch fails, automatically retry with the alternate
        # scheme (https→http or http→https) before giving up.
        # ----------------------------------------------------------------
        logger.info('[scan:%s] Fetching %s', scan_job_id, url)
        scheme_fallback_from = None
        try:
            response = fetch(url)
        except FetchError as original_exc:
            original_scheme = urlparse(url).scheme
            if original_scheme == 'https':
                fallback_url = 'http' + url[len('https'):]
            else:
                fallback_url = 'https' + url[len('http'):]

            logger.info(
                '[scan:%s] Fetch failed (%s) — retrying with %s',
                scan_job_id, original_exc, fallback_url,
            )
            try:
                response = fetch(fallback_url)
                scheme_fallback_from = original_scheme
                url = fallback_url
            except FetchError:
                raise original_exc  # Both schemes failed — surface the original error

        final_url = response['url']
        html_content = response['text']
        response_headers = response['headers']
        status_code = response['status_code']

        # ----------------------------------------------------------------
        # Step 3: Check for non-scannable HTTP status codes
        # ----------------------------------------------------------------
        _HTTP_STATUS_DESCRIPTIONS = {
            400: 'Bad Request — the server could not understand the request.',
            401: 'Unauthorised — the site requires authentication to access.',
            403: 'Forbidden — the server refused to allow access to this resource.',
            404: 'Not Found — the URL does not exist on this server.',
            405: 'Method Not Allowed — the server rejected the request method.',
            406: 'Not Acceptable — the server cannot produce a response in the requested format.',
            407: 'Proxy Authentication Required.',
            408: 'Request Timeout — the server timed out waiting for the request.',
            410: 'Gone — this resource has been permanently removed.',
            429: 'Too Many Requests — the site is rate-limiting automated access.',
            451: 'Unavailable For Legal Reasons — access to this resource is restricted.',
            500: 'Internal Server Error — the target site encountered an unexpected error.',
            502: 'Bad Gateway — the server received an invalid response from an upstream server.',
            503: 'Service Unavailable — the target site is temporarily down or overloaded.',
            504: 'Gateway Timeout — the upstream server failed to respond in time.',
            521: 'Web Server Down — Cloudflare could not reach the origin server.',
            522: 'Connection Timed Out — Cloudflare could not complete a TCP connection to the origin.',
            523: 'Origin Unreachable — Cloudflare cannot reach the origin server.',
            524: 'A Timeout Occurred — Cloudflare timed out waiting for the origin.',
        }
        if status_code != 200 and not (200 <= status_code < 300):
            cf_message = _detect_cloudflare_challenge(response_headers, html_content)
            if cf_message:
                raise HttpStatusError(status_code, f'HTTP {status_code}: {cf_message}')
            description = _HTTP_STATUS_DESCRIPTIONS.get(
                status_code,
                f'The server returned an unexpected response that cannot be scanned.',
            )
            raise HttpStatusError(
                status_code,
                f'HTTP {status_code}: {description}',
            )

        # Cloudflare JS challenge pages sometimes return 200 — detect and
        # short-circuit before analysing the challenge page as real content.
        cf_message = _detect_cloudflare_challenge(response_headers, html_content)
        if cf_message:
            raise HttpStatusError(status_code, f'HTTP {status_code}: {cf_message}')

        # Note scheme fallback in findings so analysts know the scan used a
        # different scheme than submitted.  HTTPS→HTTP is LOW (plaintext
        # downgrade); HTTP→HTTPS is INFO (upgrade, no security concern).
        if scheme_fallback_from:
            fallback_severity = 'LOW' if scheme_fallback_from == 'https' else 'INFO'
            fallback_to = 'http' if scheme_fallback_from == 'https' else 'https'
            all_findings.append({
                'severity': fallback_severity,
                'category': 'Connectivity',
                'title': f'Scanned over {fallback_to.upper()} after {scheme_fallback_from.upper()} failed',
                'description': (
                    f'The submitted URL used {scheme_fallback_from.upper()} but the connection failed. '
                    f'The scan was retried and completed over {fallback_to.upper()}. '
                    + (
                        'All traffic between the scanner and the server was transmitted in plaintext.'
                        if scheme_fallback_from == 'https'
                        else 'The server accepted a secure connection despite the original HTTP submission.'
                    )
                ),
                'evidence': f'Submitted: {job.url}\nScanned:   {url}',
                'resource_url': url,
            })

        # ----------------------------------------------------------------
        # Step 3a-i: Cross-domain redirect detection
        # If the submitted URL redirected to a completely different registered
        # domain, flag it.  Phishing kits commonly redirect scanners to major
        # consumer sites (Google, Bing) while serving malicious content to
        # real visitors — cloaking.  When the redirect target is one of these
        # well-known consumer destinations, skip HTML/JS analysis to avoid
        # firing false positives on the target site's own code.
        # ----------------------------------------------------------------
        import tldextract as _tldextract
        _CLOAKING_REDIRECT_TARGETS: frozenset[str] = frozenset({
            'google.com', 'bing.com', 'yahoo.com', 'baidu.com', 'duckduckgo.com',
            'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'amazon.com', 'microsoft.com', 'apple.com', 'wikipedia.org',
        })
        _submitted_host = urlparse(url).hostname or ''
        _submitted_is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', _submitted_host))
        if _submitted_is_ip:
            all_findings.append({
                'severity': 'MEDIUM',
                'category': 'Domain',
                'title': 'Submitted URL uses a bare IP address',
                'description': (
                    f'The submitted URL targets a server by its raw IP address ({_submitted_host}) '
                    'rather than a registered domain name. Bare IP hosting is uncommon for legitimate '
                    'sites — it is frequently used by malware distribution infrastructure, phishing '
                    'kits, and C2 servers to avoid registering a traceable domain. Combined with an '
                    'obfuscated or hashed path, this is a strong indicator of malicious hosting.'
                ),
                'evidence': f'Submitted URL: {url}\nHost: {_submitted_host}',
                'resource_url': url,
            })
        _submitted_domain = _tldextract.extract(url).top_domain_under_public_suffix.lower()
        _final_domain_r = _tldextract.extract(final_url).top_domain_under_public_suffix.lower()
        _skip_content_analysis = False
        _cross_domain = (
            # Normal domain-to-domain redirect
            (_submitted_domain and _final_domain_r and _submitted_domain != _final_domain_r)
            # IP-to-domain redirect — tldextract returns '' for IP hosts so the
            # standard check would silently pass; handle it explicitly.
            or (_submitted_is_ip and _final_domain_r)
        )
        if _cross_domain:
            _redirect_to_cloaking_target = _final_domain_r in _CLOAKING_REDIRECT_TARGETS
            all_findings.append({
                'severity': 'HIGH',
                'category': 'Redirect',
                'title': 'Suspicious HTTP redirect to unrelated domain',
                'description': (
                    'The submitted URL redirected to a completely different registered domain. '
                    'Redirecting scanners and bots to an innocent page (e.g. Google) while '
                    'serving malicious content to real visitors is a well-known cloaking technique '
                    'used by phishing kits and malware distribution sites to evade automated detection.'
                    + (' The redirect destination is a major consumer site, which strongly '
                       'suggests active scanner evasion rather than a legitimate redirect.'
                       if _redirect_to_cloaking_target else '')
                ),
                'evidence': f'Submitted: {url}\nRedirected to: {final_url}',
                'resource_url': url,
            })
            if _redirect_to_cloaking_target:
                _skip_content_analysis = True

        # ----------------------------------------------------------------
        # Step 3a: Content hash — deduplicate unchanged pages
        # ----------------------------------------------------------------
        content_hash = hashlib.sha256(html_content.encode('utf-8', errors='replace')).hexdigest()
        cached_job = (
            ScanJob.objects
            .filter(
                url=job.url,
                content_hash=content_hash,
                status=ScanJob.Status.COMPLETE,
                cached_from__isnull=True,
                detection_engine_version=current_engine_version,
            )
            .exclude(id=job.id)
            .order_by('-completed_at')
            .first()
        )
        if cached_job:
            now = django_timezone.now()
            cached_job.last_scanned_at = now
            cached_job.save(update_fields=['last_scanned_at'])

            job.status = ScanJob.Status.COMPLETE
            job.verdict = cached_job.verdict
            job.completed_at = now
            job.last_scanned_at = now
            job.content_hash = content_hash
            job.scan_metadata = cached_job.scan_metadata
            job.cached_from = cached_job
            job.error_message = ''
            job.detection_engine_version = current_engine_version
            job.save(update_fields=[
                'status', 'verdict', 'completed_at', 'last_scanned_at',
                'content_hash', 'scan_metadata', 'cached_from', 'error_message',
                'detection_engine_version',
            ])
            logger.info('[scan:%s] Cache hit — reused results from job %s', scan_job_id, cached_job.id)
            return {'verdict': cached_job.verdict, 'cached': True}

        # ----------------------------------------------------------------
        # Step 3c: Visual screenshot via Carapace (best-effort)
        # Chromium-headless render with JS disabled — gives analysts a
        # pixel-perfect view of what a real visitor would see.
        # Runs after the cache check so cache hits reuse the existing
        # screenshot stored in the canonical job's scan_metadata.
        # Failures are swallowed — the scan continues without a screenshot.
        # ----------------------------------------------------------------
        from scanner.modules.carapace_client import capture_screenshot
        _update_progress(job, 2, 7, 'Capturing visual screenshot', final_url, 0)
        _carapace = capture_screenshot(final_url)
        if _carapace:
            logger.info(
                '[scan:%s] Carapace screenshot: risk=%d, flags=%d',
                scan_job_id, _carapace['carapace_risk'], len(_carapace.get('carapace_flags', [])),
            )
            renderer_findings = _carapace_flags_to_findings(
                _carapace.get('carapace_flags', []), final_url
            )
            if renderer_findings:
                logger.info(
                    '[scan:%s] Carapace contributed %d renderer finding(s)',
                    scan_job_id, len(renderer_findings),
                )
                all_findings.extend(renderer_findings)
        else:
            logger.info('[scan:%s] Carapace screenshot: unavailable', scan_job_id)

        # ----------------------------------------------------------------
        # Step 3b: robots.txt check
        # ----------------------------------------------------------------
        logger.info('[scan:%s] Step 3b: Checking robots.txt', scan_job_id)
        try:
            robots_findings = check_robots(final_url)
            for f in robots_findings:
                f.setdefault('resource_url', final_url)
            all_findings.extend(robots_findings)
        except Exception as exc:
            logger.warning('[scan:%s] robots.txt check error: %s', scan_job_id, exc)

        # ----------------------------------------------------------------
        # Step 4: Short-circuit for direct file downloads
        # ----------------------------------------------------------------
        if response.get('is_download'):
            sha256 = response['download_sha256']
            size = response['download_size_seen']
            truncated = response['download_truncated']
            content_type = response['download_content_type']
            filename = response.get('download_filename') or '(unknown)'

            size_str = f'{size / 1024:.1f} KB' if size < 1024 * 1024 else f'{size / (1024 * 1024):.1f} MB'
            trunc_note = ' (file larger than 5 MB — hash covers first 5 MB only)' if truncated else ''

            all_findings.append({
                'severity': 'MEDIUM',
                'category': 'Download',
                'title': 'URL serves a direct file download',
                'description': (
                    f'The URL responds with a file download rather than a web page. '
                    f'The file contents cannot be passively analysed — malicious payloads '
                    f'inside archives or executables are invisible to this scanner.'
                ),
                'evidence': (
                    f'Filename    : {filename}\n'
                    f'Content-Type: {content_type}\n'
                    f'Size seen   : {size_str}{trunc_note}\n'
                    f'SHA-256     : {sha256}'
                ),
                'resource_url': final_url,
            })

            all_findings.append({
                'severity': 'MEDIUM',
                'category': 'Download',
                'title': 'File integrity unverified — manual review required',
                'description': (
                    'This scanner cannot determine whether the downloaded file is safe. '
                    'Before opening or executing it, verify the file through independent means.'
                ),
                'evidence': (
                    f'Recommended actions:\n'
                    f'  1. Submit the SHA-256 hash to VirusTotal (virustotal.com) to check against AV engines\n'
                    f'  2. Compare the SHA-256 against the hash published by the official source\n'
                    f'  3. Open the file in an isolated sandbox (e.g. any.run, hybrid-analysis.com)\n'
                    f'  4. Do not execute on a production or personal machine until verified\n\n'
                    f'SHA-256 : {sha256}'
                ),
                'resource_url': final_url,
            })

            # Detect Content-Type / extension mismatch — a server claiming a
            # script file (by URL extension) is a binary type is a common
            # obfuscation technique to defeat content-based analysis tools.
            url_ext = os.path.splitext(urlparse(final_url).path)[1].lower()
            if url_ext in _SCRIPT_EXTENSIONS:
                all_findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Download',
                    'title': 'Script extension served with binary Content-Type',
                    'description': (
                        f'The URL path ends with {url_ext!r} (a script file extension) but the server '
                        f'declared Content-Type: {content_type!r}. Mismatching the declared type against '
                        f'the file extension is a common obfuscation technique used to bypass '
                        f'content-based analysis and endpoint security tools.'
                    ),
                    'evidence': (
                        f'URL extension : {url_ext}\n'
                        f'Content-Type  : {content_type}\n'
                        f'SHA-256       : {sha256}'
                    ),
                    'resource_url': final_url,
                })

            logger.info('[scan:%s] Download detected — SHA256=%s', scan_job_id, sha256)

            # Still run header, SSL and domain checks — they are independent of page content
            logger.info('[scan:%s] Analysing headers', scan_job_id)
            header_findings = header_analyser.analyse_headers(response_headers, final_url, status_code)
            for f in header_findings:
                f.setdefault('resource_url', final_url)
            all_findings.extend(header_findings)

            hostname = _get_client_ip_from_url(final_url)
            if hostname and urlparse(final_url).scheme == 'https':
                try:
                    ssl_port = urlparse(final_url).port or 443
                    ssl_findings = ssl_analyser.analyse_ssl(hostname, ssl_port)
                    for f in ssl_findings:
                        f.setdefault('resource_url', final_url)
                    all_findings.extend(ssl_findings)
                except Exception as exc:
                    logger.warning('[scan:%s] SSL analysis error: %s', scan_job_id, exc)

            domain_findings = domain_intelligence.analyse_domain(final_url)
            for f in domain_findings:
                f.setdefault('resource_url', final_url)
            all_findings.extend(domain_findings)

            # Skip to verdict
            all_findings = scorer.context_collapse_check(all_findings)
            all_findings = scorer.sort_findings(all_findings)

            finding_objects = [
                Finding(
                    scan=job,
                    severity=f.get('severity', 'INFO'),
                    category=f.get('category', 'General'),
                    title=f.get('title', '')[:200],
                    description=f.get('description', ''),
                    evidence=f.get('evidence', ''),
                    resource_url=f.get('resource_url', '')[:2048],
                )
                for f in all_findings
            ]
            Finding.objects.bulk_create(finding_objects)

            verdict = scorer.derive_verdict(all_findings)
            job.status = ScanJob.Status.COMPLETE
            job.verdict = verdict
            job.completed_at = django_timezone.now()
            job.scan_metadata = {
                'final_url': final_url,
                'redirect_chain': response.get('redirect_chain', []),
                'status_code': status_code,
                'is_download': True,
                'download_filename': filename,
                'download_content_type': content_type,
                'download_sha256': sha256,
                'download_size_seen': size,
                'download_truncated': truncated,
                'findings_count': len(all_findings),
                'engine_version': current_engine_version,
                'screenshot_b64': _carapace['screenshot_b64'] if _carapace else '',
                'screenshot_carapace_risk': _carapace['carapace_risk'] if _carapace else 0,
            }
            job.error_message = ''
            job.detection_engine_version = current_engine_version
            job.save(update_fields=['status', 'verdict', 'completed_at', 'scan_metadata', 'error_message', 'detection_engine_version'])
            return {'verdict': verdict, 'findings_count': len(all_findings)}

        # ----------------------------------------------------------------
        # Step 4: Collect resources (text/HTML responses only)
        # ----------------------------------------------------------------
        logger.info('[scan:%s] Collecting resources', scan_job_id)
        resources = collect_resources(html_content, final_url)

        # ----------------------------------------------------------------
        # Step 4a: WHOIS lookup + Technology detection
        # WHOIS runs first so nameserver records are available to the
        # tech detector for high-confidence CDN/hosting identification.
        # The progress label is written here (not at collect_resources above)
        # because the WHOIS query is the dominant wait time in this phase —
        # the user sees an accurate label for the ~5–10s it takes.
        # ----------------------------------------------------------------
        _update_progress(job, 3, 7, 'Resolving domain & detecting technologies', final_url, len(all_findings))
        logger.info('[scan:%s] WHOIS lookup for %s', scan_job_id, _get_client_ip_from_url(final_url))
        whois_data: dict | None = None
        try:
            whois_data = lookup_whois(_get_client_ip_from_url(final_url))
        except Exception as exc:
            logger.warning('[scan:%s] WHOIS lookup error: %s', scan_job_id, exc)

        logger.info('[scan:%s] Detecting technologies', scan_job_id)
        detected_technologies: list[dict] = []
        try:
            detected_technologies = tech_detector.detect_technologies(
                html_content, response_headers, resources, whois_data=whois_data
            )
        except Exception as exc:
            logger.warning('[scan:%s] Tech detection error: %s', scan_job_id, exc)

        # Merge Carapace's browser-grade tech detections into the list.
        # Carapace uses a spec-correct DOM parser and full attribute/class walk,
        # so it catches things BeautifulSoup-based detection can miss.
        if _carapace and _carapace.get('carapace_tech'):
            existing_names = {t['name'] for t in detected_technologies}
            for tech in _carapace['carapace_tech']:
                if tech.get('name') and tech['name'] not in existing_names:
                    detected_technologies.append(tech)
                    existing_names.add(tech['name'])
            logger.info(
                '[scan:%s] Tech stack after Carapace merge: %d technologies',
                scan_job_id, len(detected_technologies),
            )

        # ----------------------------------------------------------------
        # Step 4b: Header analysis
        # ----------------------------------------------------------------
        _update_progress(job, 4, 7, 'Analysing headers & SSL', final_url, len(all_findings))
        logger.info('[scan:%s] Analysing headers', scan_job_id)
        header_findings = header_analyser.analyse_headers(response_headers, final_url, status_code)
        for f in header_findings:
            f.setdefault('resource_url', final_url)
        all_findings.extend(header_findings)

        # ----------------------------------------------------------------
        # Step 4b: SSL analysis
        # ----------------------------------------------------------------
        hostname = _get_client_ip_from_url(final_url)
        if hostname and urlparse(final_url).scheme == 'https':
            logger.info('[scan:%s] Analysing SSL for %s', scan_job_id, hostname)
            try:
                ssl_port = urlparse(final_url).port or 443
                ssl_findings = ssl_analyser.analyse_ssl(hostname, ssl_port)
                for f in ssl_findings:
                    f.setdefault('resource_url', final_url)
                all_findings.extend(ssl_findings)
            except Exception as exc:
                logger.warning('[scan:%s] SSL analysis error: %s', scan_job_id, exc)
                all_findings.append({
                    'severity': 'INFO',
                    'category': 'SSL',
                    'title': 'SSL analysis could not be completed',
                    'description': str(exc),
                    'evidence': '',
                    'resource_url': final_url,
                })

        # ----------------------------------------------------------------
        # Step 4c: Domain intelligence
        # ----------------------------------------------------------------
        _update_progress(job, 5, 7, 'Analysing domain & HTML', final_url, len(all_findings))
        logger.info('[scan:%s] Analysing domain', scan_job_id)
        domain_findings = domain_intelligence.analyse_domain(final_url, whois_data=whois_data)
        for f in domain_findings:
            f.setdefault('resource_url', final_url)
        all_findings.extend(domain_findings)

        # ----------------------------------------------------------------
        # Step 4d: HTML analysis
        # ----------------------------------------------------------------
        if not _skip_content_analysis:
            logger.info('[scan:%s] Analysing HTML', scan_job_id)
            html_findings = html_analyser.analyse_html(html_content, final_url, resources)
            for f in html_findings:
                f.setdefault('resource_url', final_url)
            all_findings.extend(html_findings)
        else:
            logger.info('[scan:%s] Skipping HTML/JS analysis — redirect to known-good domain (cloaking)', scan_job_id)

        # ----------------------------------------------------------------
        # Step 4e: JavaScript analysis
        # ----------------------------------------------------------------
        max_resources = getattr(settings, 'MAX_SCAN_RESOURCES', 50)
        soft_limit = getattr(settings, 'SCAN_TIMEOUT_SECONDS', 60)
        # Reserve 15 s for result persistence and context-collapse scoring.
        # If elapsed time exceeds this budget, stop fetching more scripts and
        # proceed directly to verdict — partial results are better than SIGKILL.
        js_time_budget = soft_limit - 15

        scripts = [] if _skip_content_analysis else resources.get('scripts', [])

        # Platform-page detection: if every external script is known-good AND at
        # least one is from a site-builder CDN (e.g. Wix/parastorage.com), this
        # page's inline scripts are platform initialisation blobs, not user content.
        # Skip inline scripts above PLATFORM_INLINE_SKIP_BYTES to avoid analysing
        # Thunderbolt/React/i18n blobs — small inline scripts (<4 KB) are kept.
        _external_scripts_on_page = [s for s in scripts if not s.get('inline') and s.get('url')]
        _unknown_externals = [s for s in _external_scripts_on_page if not is_known_good(s['url'])]
        _is_platform_page = (
            not _unknown_externals
            and any(is_site_builder_cdn(s['url']) for s in _external_scripts_on_page if s.get('url'))
        )
        if _is_platform_page:
            _before = len(scripts)
            scripts = [
                s for s in scripts
                if not s.get('inline') or len(s.get('content', '')) <= PLATFORM_INLINE_SKIP_BYTES
            ]
            logger.info(
                '[scan:%s] Platform page detected — skipped %d large inline blobs',
                scan_job_id, _before - len(scripts),
            )

        processed = 0
        scripts_skipped_budget = 0
        scripts_total = len(scripts)

        _update_progress(job, 6, 7,f'Analysing scripts (0/{scripts_total})', final_url, len(all_findings))

        for script in scripts:
            if processed >= max_resources:
                break

            elapsed = time.monotonic() - scan_start
            if elapsed > js_time_budget:
                scripts_skipped_budget = len(scripts) - processed
                logger.warning(
                    '[scan:%s] JS time budget exhausted (%.1fs / %ds) — skipping %d remaining scripts',
                    scan_job_id, elapsed, js_time_budget, scripts_skipped_budget,
                )
                break

            if script.get('inline'):
                content = script.get('content', '')
                if content and content.strip():
                    _update_progress(job, 6, 7,f'Analysing script {processed + 1}/{scripts_total}', final_url, len(all_findings))
                    logger.info('[scan:%s] Analysing inline script', scan_job_id)
                    try:
                        js_findings = js_analyser.analyse_js(content, final_url)
                    except SoftTimeLimitExceeded:
                        logger.warning('[scan:%s] Soft time limit hit during inline script analysis', scan_job_id)
                        break
                    for f in js_findings:
                        f.setdefault('resource_url', final_url)
                    all_findings.extend(js_findings)
            else:
                script_url = script.get('url', '')
                if not script_url:
                    continue
                if is_known_good(script_url):
                    logger.info('[scan:%s] Skipping known-good script: %s', scan_job_id, script_url)
                    continue
                _update_progress(job, 6, 7,f'Analysing script {processed + 1}/{scripts_total}', script_url, len(all_findings))
                logger.info('[scan:%s] Fetching external script: %s', scan_job_id, script_url)
                try:
                    script_response = fetch(script_url, max_size_bytes=1 * 1024 * 1024)
                    js_content = script_response['text']
                    if js_content:
                        js_findings = js_analyser.analyse_js(js_content, script_url)
                        for f in js_findings:
                            f['resource_url'] = script_url
                        all_findings.extend(js_findings)
                except SoftTimeLimitExceeded:
                    logger.warning('[scan:%s] Soft time limit hit fetching/analysing %s', scan_job_id, script_url)
                    break
                except FetchError as exc:
                    logger.warning('[scan:%s] Could not fetch script %s: %s', scan_job_id, script_url, exc)
                except Exception as exc:
                    logger.warning('[scan:%s] Script analysis error for %s: %s', scan_job_id, script_url, exc)

            processed += 1

        # ----------------------------------------------------------------
        # Step 4f: Direct script analysis
        # If the response is a script file served directly (no HTML wrapper),
        # collect_resources() finds no <script> tags so the JS analyser never
        # runs.  Pass the raw body through it now to catch shell droppers,
        # PowerShell droppers, curl/wget C2 beacons, and similar patterns.
        # ----------------------------------------------------------------
        if _is_direct_script(final_url, response_headers) and html_content.strip():
            logger.info('[scan:%s] Direct script file — analysing raw content', scan_job_id)
            try:
                script_findings = js_analyser.analyse_js(html_content, final_url)
                for f in script_findings:
                    f.setdefault('resource_url', final_url)
                all_findings.extend(script_findings)
            except Exception as exc:
                logger.warning('[scan:%s] Direct script analysis error: %s', scan_job_id, exc)

        # ----------------------------------------------------------------
        # Step 5: Deduplicate, context collapse, sort
        # ----------------------------------------------------------------
        _update_progress(job, 7, 7, 'Finalising results', final_url, len(all_findings))
        all_findings = scorer.deduplicate_findings(all_findings)
        all_findings = scorer.context_collapse_check(all_findings)
        all_findings = scorer.sort_findings(all_findings)

        # ----------------------------------------------------------------
        # Step 6: Persist findings
        # ----------------------------------------------------------------
        finding_objects = []
        for f in all_findings:
            finding_objects.append(Finding(
                scan=job,
                severity=f.get('severity', 'INFO'),
                category=f.get('category', 'General'),
                title=f.get('title', 'Unnamed finding')[:200],
                description=f.get('description', ''),
                evidence=f.get('evidence', ''),
                resource_url=f.get('resource_url', '')[:2048],
            ))
        Finding.objects.bulk_create(finding_objects)

        # ----------------------------------------------------------------
        # Step 7: Derive verdict and update ScanJob
        # ----------------------------------------------------------------
        verdict = scorer.derive_verdict(all_findings)

        raw_links = resources.get('links', [])
        raw_scripts = [
            s['url'] for s in resources.get('scripts', [])
            if not s.get('inline', False) and s.get('url')
        ]
        raw_stylesheets = [
            s['url'] for s in resources.get('stylesheets', [])
            if not s.get('inline', False) and s.get('url')
        ]
        raw_iframes = [f['url'] for f in resources.get('iframes', []) if f.get('url')]
        raw_forms = [
            {
                'action': f.get('action', ''),
                'method': f.get('method', 'GET'),
                'input_count': len(f.get('inputs', [])),
            }
            for f in resources.get('forms', [])
        ]
        scan_metadata = {
            'final_url': final_url,
            'redirect_chain': response.get('redirect_chain', []),
            'status_code': status_code,
            'engine_version': current_engine_version,
            'scripts_count': len(resources.get('scripts', [])),
            'scripts_urls': raw_scripts[:100],
            'scripts_analysed': processed,
            'scripts_skipped_budget': scripts_skipped_budget,
            'stylesheets_count': len(resources.get('stylesheets', [])),
            'stylesheets_urls': raw_stylesheets[:100],
            'iframes_count': len(raw_iframes),
            'iframes_urls': raw_iframes[:50],
            'forms_count': len(raw_forms),
            'forms_list': raw_forms[:50],
            'external_domains': resources.get('external_domains', []),
            'links_count': len(raw_links),
            'links': raw_links[:200],
            'images_count': len(resources.get('images', [])),
            'has_base_tag': resources.get('base_href') is not None,
            'meta_refresh_count': len(resources.get('meta_refresh', [])),
            'findings_count': len(all_findings),
            'detected_technologies': detected_technologies,
            'whois_data': whois_data,
            # Carapace visual render — empty string means screenshot unavailable.
            'screenshot_b64': _carapace['screenshot_b64'] if _carapace else '',
            'screenshot_carapace_risk': _carapace['carapace_risk'] if _carapace else 0,
        }

        now = django_timezone.now()
        job.status = ScanJob.Status.COMPLETE
        job.verdict = verdict
        job.completed_at = now
        job.last_scanned_at = now
        job.content_hash = content_hash
        job.scan_metadata = scan_metadata
        job.error_message = ''
        job.detection_engine_version = current_engine_version
        job.save(update_fields=[
            'status', 'verdict', 'completed_at', 'last_scanned_at',
            'content_hash', 'scan_metadata', 'error_message',
            'detection_engine_version',
        ])

        logger.info(
            '[scan:%s] Complete — verdict=%s, findings=%d',
            scan_job_id, verdict, len(all_findings)
        )
        return {'verdict': verdict, 'findings_count': len(all_findings)}

    except SoftTimeLimitExceeded:
        logger.warning('[scan:%s] Soft time limit exceeded', scan_job_id)
        job.status = ScanJob.Status.FAILED
        job.error_message = 'Scan timed out. The target may be slow or unresponsive.'
        job.completed_at = django_timezone.now()
        job.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'error': 'timeout'}

    except HttpStatusError as exc:
        logger.warning('[scan:%s] HTTP %s: %s', scan_job_id, exc.status_code, exc)
        job.status = ScanJob.Status.FAILED
        job.error_message = str(exc)
        job.completed_at = django_timezone.now()
        # Preserve response headers so the frontend can inspect them
        try:
            # SEC-21: cap header count and value length before storing to prevent
            # a malicious server from bloating the database record.
            _MAX_HEADERS = 50
            _MAX_HEADER_VALUE = 1024
            job.scan_metadata = {
                'error_response_headers': {
                    k: str(v)[:_MAX_HEADER_VALUE]
                    for k, v in list(response_headers.items())[:_MAX_HEADERS]
                }
            }
        except NameError:
            pass
        job.save(update_fields=['status', 'error_message', 'completed_at', 'scan_metadata'])
        return {'error': 'http_status_error'}

    except FetchError as exc:
        # SEC-10: log full internal detail server-side; show only the safe
        # user_message to the client (no internal IPs, URLs, or stack traces).
        logger.error('[scan:%s] Fetch error: %s', scan_job_id, exc)
        job.status = ScanJob.Status.FAILED
        job.error_message = exc.user_message
        job.completed_at = django_timezone.now()
        job.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'error': 'fetch_error'}

    except Exception as exc:
        # SEC-08: never return exception type/message to clients — log only.
        logger.exception('[scan:%s] Unexpected error: %s', scan_job_id, exc)
        job.status = ScanJob.Status.FAILED
        job.error_message = 'An internal error occurred during scanning.'
        job.completed_at = django_timezone.now()
        job.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'error': 'internal_error'}
