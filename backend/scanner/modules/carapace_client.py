"""
Carapace integration — safe visual screenshot and renderer-phase analysis.

Calls the Carapace HTTP API (POST /render) to produce a pixel-perfect
Chromium-headless screenshot of a URL with network access isolated via a
logging proxy.  JavaScript IS enabled in the renderer so that dynamic
overlays (ClickFix, SocGholish, ClearFake, drainers) render and are
detectable.  All outbound connections are blocked and logged — no data
leaves the machine.

Returns the base64-encoded PNG, the Carapace threat report, and a list of
URLs that JavaScript attempted to fetch at runtime (intercepted by the proxy).

Configuration (via environment variables):
    CARAPACE_URL               — base URL of the Carapace API server, e.g.
                                 http://carapace:8080.  If unset, all calls
                                 return None silently (screenshots disabled).
    CARAPACE_API_KEY           — optional API key sent in X-API-Key header.
    CARAPACE_SCREENSHOT_TIMEOUT — per-request timeout in seconds (default 30).
"""
import logging
import os

import requests as _requests

logger = logging.getLogger(__name__)

_CARAPACE_URL: str = os.getenv('CARAPACE_URL', '').rstrip('/')
_CARAPACE_API_KEY: str = os.getenv('CARAPACE_API_KEY', '')
_SCREENSHOT_TIMEOUT: int = int(os.getenv('CARAPACE_SCREENSHOT_TIMEOUT', '30'))

# ---------------------------------------------------------------------------
# Flag tables — shared by tasks.py and run_scan_test.py
# ---------------------------------------------------------------------------

CARAPACE_SKIP_CODES: frozenset[str] = frozenset({
    'BLOCKED_ELEMENT_SCRIPT',   # Carapace always strips <script> tags before static analysis
    'BLOCKED_ELEMENT_IFRAME',   # Always stripped
    'BLOCKED_ELEMENT_OTHER',    # Always stripped
    'JAVASCRIPT_URL_STRIPPED',  # Very common; stripped as sanitisation artefact
    'NETWORK_ATTEMPT_BLOCKED',  # Static-analysis detection of fetch/XHR in source code — too
                                # noisy on legitimate sites.  Runtime interceptions are surfaced
                                # via INTERCEPTED_REQUEST instead (higher confidence signal).
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
        'Renderer: Function constructor with visible body',
        'new Function("...") was found with a string-literal body — the actual code being '
        'constructed is shown in the evidence block. Inspect the body for network calls, '
        'document manipulation, or encoded payloads. Legitimate uses (template engines, '
        'polyfills) typically have short, readable bodies.',
    ),
    'JS_FUNCTION_CONSTRUCTOR_DYNAMIC': (
        'Renderer: Function constructor with dynamic body',
        'new Function(expr) was called with a non-literal argument — the body is assembled '
        'at runtime from a variable or expression that the static analyser cannot read. '
        'This pattern is common in template engines and framework compilers (Vue, Angular) '
        'and is not inherently malicious. It becomes high-confidence only when combined '
        'with obfuscation signals such as base64 decoding or hex-escaped strings.',
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
    'SANDBOX_EVASION_CHROME_RUNTIME': (
        'Sandbox evasion: chrome.runtime / window.chrome probe',
        'A script accesses window.chrome or chrome.runtime — properties that are undefined in '
        'headless Chromium despite the underlying engine being Chrome-based. No legitimate '
        'website reads these properties; they appear exclusively in anti-bot fingerprinting '
        'code designed to detect automated analysis environments and serve clean content to '
        'scanners while serving malicious content to real users.',
    ),
    'SANDBOX_EVASION_FOCUS_PROBE': (
        'Sandbox evasion: document focus probe',
        'A script calls document.hasFocus(), which always returns false in headless browsers '
        'because there is no user-visible window. This is used to detect automated analysis '
        'environments. No legitimate site functionality depends on this check in a way that '
        'would require it to be present in production page code.',
    ),
    'SANDBOX_EVASION_CANVAS_FINGERPRINT': (
        'Sandbox evasion: WebGL canvas fingerprinting',
        'A script accessed the WEBGL_debug_renderer_info extension or UNMASKED_RENDERER_WEBGL / '
        'UNMASKED_VENDOR_WEBGL constants to read GPU vendor and renderer strings. These differ '
        'between real browsers and headless Chromium, making this a reliable anti-analysis probe. '
        'Phishing kits (Tycoon2FA and derivatives) use WebGL fingerprinting to detect automated '
        'analysis environments and serve a clean page to scanners while serving the phishing '
        'form to real users. No legitimate page functionality requires these specific GPU '
        'identifier strings.',
    ),
    'CLIPBOARD_HIJACK': (
        'Clipboard hijack: JavaScript wrote to the system clipboard',
        'JavaScript on this page called navigator.clipboard.writeText() or registered a copy '
        'event handler with clipboardData.setData(), overwriting the visitor\'s clipboard without '
        'any user interaction. The intercepted payload is shown in the evidence block. This is the '
        'delivery mechanism for clipboard-injection attacks: the victim is prompted to paste the '
        'content into a terminal or Run dialog, executing an arbitrary command on their machine.',
    ),
    'CLIPBOARD_HIJACK_CLICKFIX': (
        'ClickFix clipboard hijack: shell command written to clipboard (CRITICAL)',
        'JavaScript on this page wrote a shell command directly to the visitor\'s clipboard via '
        'navigator.clipboard.writeText() or a copy event handler. The intercepted command is shown '
        'in the evidence block. This is the canonical ClickFix / paste-and-run attack: the page '
        'displays a fake CAPTCHA, verification prompt, or error dialog instructing the visitor to '
        'press Win+R and paste, or open a terminal and paste. The command then executes with user '
        'privileges — typically downloading and running a second-stage payload (PowerShell stager, '
        'Python dropper, or curl-piped script). The actual command the victim would paste is in '
        'the evidence block.',
    ),
    'CSS_OVERLAY_INJECTED': (
        'Fullscreen CSS overlay detected (ClickFix / SocGholish pattern)',
        'A CSS rule with position:fixed, full viewport width (100%/100vw), and full viewport '
        'height (100%/100vh) was found in the page. This structure creates a page-covering '
        'layer that blocks all legitimate content behind it. ClickFix campaigns use this to '
        'display a fake CAPTCHA or verification prompt that socially engineers the visitor into '
        'pasting a malicious shell command. SocGholish and ClearFake use it for fake browser '
        'update dialogs. Cookie banners and legitimate modals do not use full-height viewports.',
    ),
    'INTERCEPTED_REQUEST': (
        'JavaScript runtime network request(s) intercepted',
        'JavaScript on this page attempted to make one or more network requests at runtime '
        'that were not present in the static HTML. All requests were blocked (the renderer '
        'runs with full network isolation). The intercepted URLs are in the evidence block. '
        'Dynamic script loading from an unknown domain is the payload-delivery step of '
        'SocGholish and ClickFix campaigns. XHR/fetch calls to external domains indicate '
        'data exfiltration or C2 communication attempts.',
    ),
}


# Point weights matching Carapace's recalculate_score() in threat/mod.rs.
# Used to estimate how much of the risk_score is accounted for by reported findings.
_CARAPACE_SEVERITY_PTS: dict[str, int] = {
    'CRITICAL': 40,
    'HIGH':     20,
    'MEDIUM':   10,
    'LOW':       5,
}

# Human-readable labels for skip-code flags surfaced in the sanitisation summary.
_SKIP_CODE_LABELS: dict[str, str] = {
    'BLOCKED_ELEMENT_SCRIPT':  ('script tag stripped',        'script tags stripped'),
    'BLOCKED_ELEMENT_IFRAME':  ('iframe stripped',            'iframes stripped'),
    'BLOCKED_ELEMENT_OTHER':   ('element stripped',           'elements stripped'),
    'JAVASCRIPT_URL_STRIPPED': ('javascript: URL stripped',   'javascript: URLs stripped'),
    'NETWORK_ATTEMPT_BLOCKED': ('source-level network request detected', 'source-level network requests detected'),
}


def flags_to_findings(flags: list[dict], url: str, risk_score: int = 0) -> list[dict]:
    """Convert Carapace threat report flags into Insight finding dicts.

    risk_score — Carapace's internal risk score (0–100).  When provided, a gap
    between the score and the severity of reported findings surfaces a LOW finding
    so analysts can see that Carapace's internal scoring is higher than the visible
    flags alone would suggest.
    """
    findings: list[dict] = []
    skip_counts: dict[str, int] = {}

    for flag in flags:
        code = flag.get('code', '')
        if code in CARAPACE_SKIP_CODES:
            skip_counts[code] = skip_counts.get(code, 0) + 1
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

    # Surface skip-code sanitisation counts as a single INFO finding so analysts
    # can see how much activity Carapace stripped without being flooded by individual
    # low-signal entries.
    if skip_counts:
        parts = []
        for code in sorted(skip_counts):
            n = skip_counts[code]
            singular, plural = _SKIP_CODE_LABELS.get(code, (code, code))
            parts.append(f'{n} {singular if n == 1 else plural}')
        findings.append({
            'severity': 'INFO',
            'category': 'Renderer',
            'title': 'Carapace sanitisation activity',
            'description': (
                'The Carapace renderer stripped or blocked elements before static analysis. '
                'These are aggregated here rather than listed individually to avoid noise. '
                'Elevated script-tag or network-request counts on a simple page warrant '
                'closer inspection alongside other findings.'
            ),
            'evidence': '; '.join(parts),
            'resource_url': url,
        })

    # If Carapace's risk score is materially higher than what the reported findings
    # account for, the gap is driven by volume bonus from skip-code flags inside
    # recalculate_score().  Surface it so the score is not silently unexplained.
    if risk_score > 0:
        expected_pts = sum(
            _CARAPACE_SEVERITY_PTS.get(f['severity'], 0)
            for f in findings
            if f.get('category') == 'Renderer' and f['severity'] != 'INFO'
        )
        gap = risk_score - min(expected_pts, 100)
        if gap >= 15:
            findings.append({
                'severity': 'LOW',
                'category': 'Renderer',
                'title': 'Carapace elevated internal risk score',
                'description': (
                    'Carapace\'s internal risk score is higher than the reported findings '
                    'account for. The gap is typically caused by a high volume of sanitised '
                    'elements — script tags, iframes, or source-level network requests — that '
                    'each score below the reporting threshold but accumulate via Carapace\'s '
                    'per-code volume bonus. Review the sanitisation activity finding for counts.'
                ),
                'evidence': (
                    f'Carapace risk score: {risk_score}; '
                    f'estimated finding contribution: {min(expected_pts, 100)}; '
                    f'unexplained gap: {gap}'
                ),
                'resource_url': url,
            })

    return findings


def capture_screenshot(url: str, width: int = 1280, height: int = 1400) -> dict | None:
    """
    Render *url* using Carapace and return::

        {
            'screenshot_b64':        str,   # base64-encoded PNG; empty string on render failure
            'carapace_risk':         int,   # Carapace risk score 0–100
            'carapace_flags':        list,  # threat report flags
            'carapace_tech':         list,  # technology stack detections
            'carapace_intercepted':  list,  # URLs JS attempted to fetch at runtime
        }

    Returns ``None`` if CARAPACE_URL is not configured or the API is unreachable.
    Failures are logged at WARNING level and never propagate.

    Height defaults to 1400px (taller than the previous 800px default) to
    capture content injected below the fold — a common evasion technique.
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
                'height': height,
                'no_assets': False,
            },
            timeout=_SCREENSHOT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        threat = data.get('threat_report', {})
        return {
            'screenshot_b64':       data.get('output') or '',
            'carapace_risk':        threat.get('risk_score', 0),
            'carapace_flags':       threat.get('flags', []),
            'carapace_tech':        threat.get('tech_stack', []),
            'carapace_intercepted': threat.get('blocked_network', []),
        }
    except _requests.exceptions.Timeout:
        logger.warning('Carapace screenshot timed out for %s', url)
        return None
    except Exception as exc:
        logger.warning('Carapace screenshot failed for %s: %s', url, exc)
        return None
