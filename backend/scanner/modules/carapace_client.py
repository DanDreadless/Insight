"""
Carapace integration — safe visual screenshot service.

Calls the Carapace HTTP API (POST /render) to produce a pixel-perfect
Chromium-headless screenshot of a URL with JavaScript fully disabled and
network access blocked.  Returns the base64-encoded PNG and the Carapace
threat report summary.

Configuration (via environment variables):
    CARAPACE_URL               — base URL of the Carapace API server, e.g.
                                 http://carapace:8080.  If unset, all calls
                                 return None silently (screenshots disabled).
    CARAPACE_API_KEY           — optional API key sent in X-API-Key header.
    CARAPACE_SCREENSHOT_TIMEOUT — per-request timeout in seconds (default 20).
"""
import logging
import os

import requests as _requests

logger = logging.getLogger(__name__)

_CARAPACE_URL: str = os.getenv('CARAPACE_URL', '').rstrip('/')
_CARAPACE_API_KEY: str = os.getenv('CARAPACE_API_KEY', '')
_SCREENSHOT_TIMEOUT: int = int(os.getenv('CARAPACE_SCREENSHOT_TIMEOUT', '20'))

# ---------------------------------------------------------------------------
# Flag tables — shared by tasks.py and run_scan_test.py
# ---------------------------------------------------------------------------

CARAPACE_SKIP_CODES: frozenset[str] = frozenset({
    'BLOCKED_ELEMENT_SCRIPT',   # Carapace always strips <script> tags
    'BLOCKED_ELEMENT_IFRAME',   # Always stripped
    'BLOCKED_ELEMENT_OTHER',    # Always stripped
    'JAVASCRIPT_URL_STRIPPED',  # Very common; stripped as sanitisation
    'NETWORK_ATTEMPT_BLOCKED',  # All network is blocked by design
})

CARAPACE_SEVERITY_MAP: dict[str, str] = {
    'critical': 'CRITICAL',
    'high':     'HIGH',
    'medium':   'MEDIUM',
    'low':      'LOW',
}

# (title, analyst-facing description) for each flag code.
CARAPACE_FLAG_INFO: dict[str, tuple[str, str]] = {
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


def flags_to_findings(flags: list[dict], url: str) -> list[dict]:
    """Convert Carapace threat report flags into Insight finding dicts."""
    findings: list[dict] = []
    for flag in flags:
        code = flag.get('code', '')
        if code in CARAPACE_SKIP_CODES:
            continue
        severity = CARAPACE_SEVERITY_MAP.get(flag.get('severity', 'low'), 'LOW')
        title, description = CARAPACE_FLAG_INFO.get(
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


def capture_screenshot(url: str, width: int = 1280) -> dict | None:
    """
    Render *url* using Carapace and return::

        {
            'screenshot_b64': str,  # base64-encoded PNG; empty string on render failure
            'carapace_risk':  int,  # Carapace risk score 0–100
            'carapace_flags': list,
            'carapace_tech':  list,
        }

    Returns ``None`` if CARAPACE_URL is not configured or the API is unreachable.
    Failures are logged at WARNING level and never propagate.
    """
    if not _CARAPACE_URL:
        return None

    headers: dict[str, str] = {'Content-Type': 'application/json'}
    if _CARAPACE_API_KEY:
        headers['X-API-Key'] = _CARAPACE_API_KEY

    try:
        resp = _requests.post(
            f'{_CARAPACE_URL}/render',
            headers=headers,
            json={
                'url': url,
                'format': 'png',
                'width': width,
                'no_assets': False,
            },
            timeout=_SCREENSHOT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        threat = data.get('threat_report', {})
        return {
            'screenshot_b64': data.get('output') or '',
            'carapace_risk':  threat.get('risk_score', 0),
            'carapace_flags': threat.get('flags', []),
            'carapace_tech':  threat.get('tech_stack', []),
        }
    except _requests.exceptions.Timeout:
        logger.warning('Carapace screenshot timed out for %s', url)
        return None
    except Exception as exc:
        logger.warning('Carapace screenshot failed for %s: %s', url, exc)
        return None
