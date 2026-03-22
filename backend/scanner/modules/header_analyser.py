"""
HTTP response header security analysis module.
"""
import re
from urllib.parse import urlparse


_DEPRECATED_SERVER_PATTERNS = re.compile(
    r'(?:'
    r'Apache/(?:1\.\d|2\.0|2\.2)|'
    r'nginx/0\.\d|'
    r'IIS/(?:6\.0|7\.0)|'
    r'PHP/(?:5\.\d|7\.0|7\.1)'
    r')',
    re.IGNORECASE,
)

_SERVER_VERSION_PATTERN = re.compile(
    r'(?:Apache|nginx|IIS|Microsoft-IIS|lighttpd|LiteSpeed|OpenResty)/[\d.]+',
    re.IGNORECASE,
)

_PHP_VERSION_PATTERN = re.compile(r'PHP/[\d.]+', re.IGNORECASE)


def _headers_lower(headers: dict) -> dict[str, str]:
    """Return a case-insensitive copy of headers dict with lowercased keys."""
    return {k.lower(): v for k, v in headers.items()}


def analyse_headers(headers: dict, url: str, status_code: int) -> list[dict]:
    """
    Analyse HTTP response headers for security issues.

    Returns list of finding dicts with keys:
        severity, category, title, description, evidence.
    """
    findings: list[dict] = []
    h = _headers_lower(headers)
    parsed = urlparse(url)
    is_https = parsed.scheme == 'https'

    # ------------------------------------------------------------------
    # 1. Content-Security-Policy
    # ------------------------------------------------------------------
    csp = h.get('content-security-policy', '')
    if not csp:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'Headers',
            'title': 'Missing Content-Security-Policy header',
            'description': (
                'No Content-Security-Policy header is set. CSP prevents cross-site scripting (XSS) '
                'by specifying allowed content sources.'
            ),
            'evidence': 'Content-Security-Policy header absent',
        })
    else:
        if "'unsafe-inline'" in csp:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': "CSP contains 'unsafe-inline' directive",
                'description': (
                    "The Content-Security-Policy header contains 'unsafe-inline', which allows inline "
                    "scripts/styles and largely defeats XSS protection."
                ),
                'evidence': f'CSP: {csp}',
            })
        if "'unsafe-eval'" in csp:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': "CSP contains 'unsafe-eval' directive",
                'description': (
                    "The Content-Security-Policy header allows eval() via 'unsafe-eval'. "
                    "This permits dynamic code execution and weakens XSS protection."
                ),
                'evidence': f'CSP: {csp}',
            })

    # ------------------------------------------------------------------
    # 2. X-Frame-Options
    # ------------------------------------------------------------------
    xfo = h.get('x-frame-options', '')
    if not xfo:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'Headers',
            'title': 'Missing X-Frame-Options header',
            'description': (
                'No X-Frame-Options header. The page may be embedded in an iframe by a third party, '
                'enabling clickjacking attacks.'
            ),
            'evidence': 'X-Frame-Options header absent',
        })
    else:
        xfo_upper = xfo.strip().upper()
        if xfo_upper not in ('DENY', 'SAMEORIGIN'):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Headers',
                'title': f'Weak X-Frame-Options value: {xfo}',
                'description': (
                    f'X-Frame-Options is set to "{xfo}" which does not effectively prevent framing. '
                    'Use DENY or SAMEORIGIN.'
                ),
                'evidence': f'X-Frame-Options: {xfo}',
            })

    # ------------------------------------------------------------------
    # 3. X-Content-Type-Options
    # ------------------------------------------------------------------
    xcto = h.get('x-content-type-options', '')
    if xcto.strip().lower() != 'nosniff':
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'Missing or incorrect X-Content-Type-Options header',
            'description': (
                'X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff responses, '
                'potentially executing scripts served with wrong content types.'
            ),
            'evidence': f'X-Content-Type-Options: {xcto!r}' if xcto else 'Header absent',
        })

    # ------------------------------------------------------------------
    # 4. Strict-Transport-Security (HSTS)
    # ------------------------------------------------------------------
    if is_https:
        hsts = h.get('strict-transport-security', '')
        if not hsts:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Headers',
                'title': 'Missing Strict-Transport-Security (HSTS) header',
                'description': (
                    'HTTPS site does not set HSTS. Without HSTS, users can be downgraded to HTTP '
                    'via man-in-the-middle attacks.'
                ),
                'evidence': 'Strict-Transport-Security header absent',
            })
        else:
            # Check max-age
            max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    findings.append({
                        'severity': 'LOW',
                        'category': 'Headers',
                        'title': f'HSTS max-age too low ({max_age}s)',
                        'description': (
                            f'HSTS max-age is {max_age} seconds (less than 1 year = 31536000s). '
                            'A short HSTS duration reduces protection.'
                        ),
                        'evidence': f'Strict-Transport-Security: {hsts}',
                    })

    # ------------------------------------------------------------------
    # 5. Referrer-Policy
    # ------------------------------------------------------------------
    if not h.get('referrer-policy'):
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'Missing Referrer-Policy header',
            'description': (
                'No Referrer-Policy header. The browser may send full URL referrers to third parties, '
                'leaking sensitive URL parameters.'
            ),
            'evidence': 'Referrer-Policy header absent',
        })

    # ------------------------------------------------------------------
    # 6. Permissions-Policy
    # ------------------------------------------------------------------
    if not h.get('permissions-policy') and not h.get('feature-policy'):
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'Missing Permissions-Policy header',
            'description': (
                'No Permissions-Policy (formerly Feature-Policy) header. '
                'This header controls access to browser features like camera, microphone, geolocation.'
            ),
            'evidence': 'Permissions-Policy header absent',
        })

    # ------------------------------------------------------------------
    # 7. Server version disclosure
    # ------------------------------------------------------------------
    server = h.get('server', '')
    if server:
        version_match = _SERVER_VERSION_PATTERN.search(server)
        if version_match:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': 'Server header discloses software version',
                'description': (
                    f'The Server header reveals the specific software version: "{server}". '
                    'Version disclosure aids attackers in targeting known CVEs.'
                ),
                'evidence': f'Server: {server}',
            })

    # ------------------------------------------------------------------
    # 8. X-Powered-By disclosure
    # ------------------------------------------------------------------
    xpb = h.get('x-powered-by', '')
    if xpb:
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'X-Powered-By header discloses technology stack',
            'description': (
                f'X-Powered-By: {xpb} reveals the backend framework/language. '
                'Helps attackers target known vulnerabilities.'
            ),
            'evidence': f'X-Powered-By: {xpb}',
        })

    # ------------------------------------------------------------------
    # 9. HTTP instead of HTTPS
    # ------------------------------------------------------------------
    if not is_https:
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': 'Site served over unencrypted HTTP',
            'description': (
                'The page is served over HTTP, not HTTPS. All data — including any credentials, '
                'session tokens, and form submissions — is transmitted in plaintext. '
                'All traffic is exposed to network interception.'
            ),
            'evidence': f'URL scheme: http | URL: {url}',
        })

    # ------------------------------------------------------------------
    # 10. Deprecated server software
    # ------------------------------------------------------------------
    full_server_info = f'{server} {h.get("x-powered-by", "")}'
    deprecated_match = _DEPRECATED_SERVER_PATTERNS.search(full_server_info)
    if deprecated_match:
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': f'Deprecated/end-of-life server software: {deprecated_match.group(0)}',
            'description': (
                f'Server headers indicate {deprecated_match.group(0)}, which is end-of-life '
                'and no longer receives security patches. Likely vulnerable to known exploits — '
                'indicates potentially compromised or abandoned infrastructure.'
            ),
            'evidence': f'Server: {server} | X-Powered-By: {h.get("x-powered-by", "N/A")}',
        })

    # ------------------------------------------------------------------
    # 11. Insecure cookie flags
    # ------------------------------------------------------------------
    set_cookie_headers: list[str] = []
    for key, val in headers.items():
        if key.lower() == 'set-cookie':
            set_cookie_headers.append(val)

    for cookie_val in set_cookie_headers:
        cookie_lower = cookie_val.lower()
        issues: list[str] = []

        if 'httponly' not in cookie_lower:
            issues.append('missing HttpOnly')
        if is_https and 'secure' not in cookie_lower:
            issues.append('missing Secure flag on HTTPS')
        if 'samesite' not in cookie_lower:
            issues.append('missing SameSite')

        if issues:
            # Extract cookie name (before first =)
            cookie_name = cookie_val.split('=')[0].strip()
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': f'Insecure cookie flags on "{cookie_name}"',
                'description': (
                    f'Cookie "{cookie_name}" has security issues: {", ".join(issues)}. '
                    'Missing HttpOnly allows JS access; missing Secure sends cookie over HTTP; '
                    'missing SameSite enables CSRF.'
                ),
                'evidence': f'Set-Cookie: {cookie_val}',
            })
            break  # One finding for cookie issues is sufficient

    # ------------------------------------------------------------------
    # 12. CORS misconfiguration
    # ------------------------------------------------------------------
    acao = h.get('access-control-allow-origin', '')
    acac = h.get('access-control-allow-credentials', '')
    if acao.strip() == '*' and acac.strip().lower() == 'true':
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': 'Dangerous CORS misconfiguration: wildcard + credentials',
            'description': (
                'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true '
                'is a critical CORS misconfiguration. Browsers reject this combination per spec, '
                'but it indicates a misconfigured server that may also have other CORS issues.'
            ),
            'evidence': f'Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}',
        })
    elif acao.strip() == '*':
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'CORS wildcard origin (Access-Control-Allow-Origin: *)',
            'description': (
                'All origins are allowed to read responses from this server. '
                'Acceptable for public APIs but not for authenticated endpoints.'
            ),
            'evidence': f'Access-Control-Allow-Origin: {acao}',
        })

    return findings
