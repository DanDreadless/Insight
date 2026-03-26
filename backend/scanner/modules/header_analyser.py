"""
HTTP response header security analysis module.

Severity philosophy (aligned with industry consensus):
  - CRITICAL/HIGH  : Active or directly exploitable risk to visitors
                     (HTTP in plaintext, EOL server software, CORS wildcard+credentials)
  - LOW            : Configuration weaknesses that increase attack surface
                     (cookie flags, version disclosure, weak HSTS duration)
  - INFO           : Missing best-practice defensive headers
                     (CSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy)
                     These represent configuration debt, not evidence of malice.
                     Their absence matters most when combined with other threat signals
                     — the context_collapse_check in scorer.py handles that.

Reference: Cobalt Vulnerability Wiki, OWASP, Invicti research, industry pentest standards.
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
    # INFO — absence is a configuration gap, not a threat signal.
    # CSP's value is as a second-line defence: it limits damage IF an
    # attacker has already achieved XSS injection. The site being un-CSP'd
    # does not mean it is compromised or malicious.
    # ------------------------------------------------------------------
    csp = h.get('content-security-policy', '')
    if not csp:
        findings.append({
            'severity': 'INFO',
            'category': 'Headers',
            'title': 'Missing Content-Security-Policy header',
            'description': (
                'No Content-Security-Policy header is set. CSP is a second-line browser defence '
                'that restricts which origins can load scripts, fonts, and other resources — '
                'limiting the impact of Cross-Site Scripting (XSS) if it were separately present. '
                'Its absence is a hardening gap, not an indicator of compromise. '
                'This finding carries more weight when combined with injected scripts or phishing '
                'form findings on this page.'
            ),
            'evidence': 'Content-Security-Policy header absent',
        })
    else:
        if "'unsafe-inline'" in csp:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': "CSP allows 'unsafe-inline' — XSS protection weakened",
                'description': (
                    "The Content-Security-Policy header contains 'unsafe-inline', permitting inline "
                    "scripts and styles. This largely defeats CSP's XSS protection because an attacker "
                    "who achieves script injection can execute code without loading an external resource. "
                    "On a compromised site, this makes injected malware more effective."
                ),
                'evidence': f'CSP: {csp}',
            })
        if "'unsafe-eval'" in csp:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': "CSP allows 'unsafe-eval' — dynamic code execution permitted",
                'description': (
                    "The Content-Security-Policy header allows eval() via 'unsafe-eval'. "
                    "This permits runtime JavaScript execution from strings — weakening CSP's protection "
                    "against eval-based obfuscation payloads. On a site with other threat signals, "
                    "this permissive directive enables obfuscated script execution."
                ),
                'evidence': f'CSP: {csp}',
            })

    # ------------------------------------------------------------------
    # 2. X-Frame-Options
    # INFO — absence allows framing; it does not mean framing is occurring.
    # Clickjacking requires an attacker to separately frame this page on
    # their own site — the missing header does not make this page dangerous.
    # ------------------------------------------------------------------
    xfo = h.get('x-frame-options', '')
    if not xfo:
        findings.append({
            'severity': 'INFO',
            'category': 'Headers',
            'title': 'Missing X-Frame-Options header',
            'description': (
                'No X-Frame-Options header is set. This means the page can be embedded in an iframe '
                'on any third-party site, making it theoretically susceptible to clickjacking. '
                'In practice, this finding only represents a risk if an attacker is actively targeting '
                'this page — its absence is a hardening gap, not evidence of a current attack. '
                'Modern browsers also respect CSP frame-ancestors as a more flexible alternative.'
            ),
            'evidence': 'X-Frame-Options header absent',
        })
    else:
        xfo_upper = xfo.strip().upper()
        if xfo_upper not in ('DENY', 'SAMEORIGIN'):
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': f'Weak X-Frame-Options value: {xfo}',
                'description': (
                    f'X-Frame-Options is set to "{xfo}", which does not effectively prevent framing. '
                    'Use DENY or SAMEORIGIN. The current value provides no meaningful clickjacking protection.'
                ),
                'evidence': f'X-Frame-Options: {xfo}',
            })

    # ------------------------------------------------------------------
    # 3. X-Content-Type-Options
    # LOW — MIME sniffing attacks require specific conditions; still worth noting.
    # ------------------------------------------------------------------
    xcto = h.get('x-content-type-options', '')
    if xcto.strip().lower() != 'nosniff':
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'Missing X-Content-Type-Options: nosniff',
            'description': (
                'X-Content-Type-Options: nosniff is not set. Without this header, some browsers may '
                'MIME-sniff responses and execute content served with incorrect content types '
                '(e.g., running a text/plain response as JavaScript). '
                'This is a low-impact hardening gap that eliminates a narrow attack class.'
            ),
            'evidence': f'X-Content-Type-Options: {xcto!r}' if xcto else 'Header absent',
        })

    # ------------------------------------------------------------------
    # 4. Strict-Transport-Security (HSTS)
    # LOW on HTTPS — meaningful security benefit but absence doesn't indicate malice.
    # An attacker would need to achieve an active MitM position to exploit this.
    # ------------------------------------------------------------------
    if is_https:
        hsts = h.get('strict-transport-security', '')
        if not hsts:
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': 'Missing Strict-Transport-Security (HSTS) header',
                'description': (
                    'This HTTPS site does not set HSTS. Without it, a network-level attacker '
                    '(public Wi-Fi, ISP interception) could strip HTTPS and redirect the user to '
                    'an HTTP version of the site — a "SSL stripping" attack. '
                    'This risk requires an active man-in-the-middle position; it is a hardening '
                    'gap rather than evidence that the site itself is malicious.'
                ),
                'evidence': 'Strict-Transport-Security header absent',
            })
        else:
            max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    findings.append({
                        'severity': 'LOW',
                        'category': 'Headers',
                        'title': f'HSTS max-age too low ({max_age}s — recommended: 31536000)',
                        'description': (
                            f'HSTS max-age is {max_age} seconds (less than the recommended 1 year = 31536000s). '
                            'A short HSTS duration means browsers will forget the HTTPS requirement sooner, '
                            'reducing the window of protection against SSL-stripping attacks on repeat visitors.'
                        ),
                        'evidence': f'Strict-Transport-Security: {hsts}',
                    })

    # ------------------------------------------------------------------
    # 5. Referrer-Policy
    # INFO — absence leaks referrer data to third parties, not a visitor threat.
    # ------------------------------------------------------------------
    if not h.get('referrer-policy'):
        findings.append({
            'severity': 'INFO',
            'category': 'Headers',
            'title': 'Missing Referrer-Policy header',
            'description': (
                'No Referrer-Policy is set. Browsers will send the full referrer URL when '
                'navigating to third-party links, potentially leaking sensitive URL parameters '
                '(tokens, session IDs, search terms) to external services. '
                'This is a privacy and configuration hygiene issue, not a direct threat to visitors.'
            ),
            'evidence': 'Referrer-Policy header absent',
        })

    # ------------------------------------------------------------------
    # 6. Permissions-Policy
    # INFO — almost no sites set this; absence is the norm, not a red flag.
    # ------------------------------------------------------------------
    if not h.get('permissions-policy') and not h.get('feature-policy'):
        findings.append({
            'severity': 'INFO',
            'category': 'Headers',
            'title': 'Missing Permissions-Policy header',
            'description': (
                'No Permissions-Policy (formerly Feature-Policy) header is set. '
                'This optional header restricts browser API access (camera, microphone, geolocation, '
                'USB, etc.) for the page and its embedded content. '
                'The vast majority of legitimate websites do not set this header. '
                'Its absence alone is not a threat indicator.'
            ),
            'evidence': 'Permissions-Policy header absent',
        })

    # ------------------------------------------------------------------
    # 7. Server version disclosure
    # LOW — aids reconnaissance; does not directly harm visitors.
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
                    f'The Server header reveals the exact software version: "{server}". '
                    'Version disclosure gives attackers a starting point for CVE lookups — '
                    'they can target known unpatched vulnerabilities for this specific version. '
                    'This is a reconnaissance-reduction finding; the disclosure itself does not harm visitors.'
                ),
                'evidence': f'Server: {server}',
            })

    # ------------------------------------------------------------------
    # 8. X-Powered-By disclosure
    # LOW — same as server version disclosure above.
    # ------------------------------------------------------------------
    xpb = h.get('x-powered-by', '')
    if xpb:
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'X-Powered-By header exposes backend technology',
            'description': (
                f'X-Powered-By: {xpb} reveals the backend framework or language. '
                'This helps attackers identify matching CVEs and default configuration weaknesses. '
                'This is a reconnaissance-reduction finding; it does not directly harm visitors.'
            ),
            'evidence': f'X-Powered-By: {xpb}',
        })

    # ------------------------------------------------------------------
    # 9. HTTP instead of HTTPS
    # HIGH — concrete, active risk to visitors. Credentials, session tokens,
    # and all page content transmitted in plaintext on every request.
    # This is the one transport-level finding that directly harms visitors.
    # ------------------------------------------------------------------
    if not is_https:
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': 'Site served over unencrypted HTTP',
            'description': (
                'The page is delivered over HTTP — all traffic between the visitor and this server '
                'is transmitted in plaintext. Any password, session token, or form submission '
                'can be read or modified by anyone on the same network path '
                '(coffee shop Wi-Fi, ISP, corporate proxy, nation-state interception). '
                'If this page contains a login form or sensitive content, visitor credentials '
                'are directly exposed on every connection.'
            ),
            'evidence': f'URL scheme: http | URL: {url}',
        })

    # ------------------------------------------------------------------
    # 10. Deprecated / end-of-life server software
    # HIGH — EOL software is unpatched and likely vulnerable to known exploits.
    # Combined with other signals this indicates compromised or abandoned infra.
    # ------------------------------------------------------------------
    full_server_info = f'{server} {h.get("x-powered-by", "")}'
    deprecated_match = _DEPRECATED_SERVER_PATTERNS.search(full_server_info)
    if deprecated_match:
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': f'End-of-life server software: {deprecated_match.group(0)}',
            'description': (
                f'Server headers reveal {deprecated_match.group(0)}, which is end-of-life '
                'and no longer receives security patches. EOL software carries unpatched CVEs '
                'that are publicly known and actively exploited. '
                'This indicates either an abandoned server or one that has been compromised and '
                'not updated by the attacker — either way, it is high risk for visitors and should '
                'be treated as potentially compromised infrastructure.'
            ),
            'evidence': f'Server: {server} | X-Powered-By: {h.get("x-powered-by", "N/A")}',
        })

    # ------------------------------------------------------------------
    # 11. Insecure cookie flags
    # LOW — increases attack surface; does not indicate active compromise.
    # ------------------------------------------------------------------
    set_cookie_headers: list[str] = []
    for key, val in headers.items():
        if key.lower() == 'set-cookie':
            set_cookie_headers.append(val)

    for cookie_val in set_cookie_headers:
        cookie_lower = cookie_val.lower()
        issues: list[str] = []

        if 'httponly' not in cookie_lower:
            issues.append('missing HttpOnly (JavaScript can read this cookie — enables XSS session theft)')
        if is_https and 'secure' not in cookie_lower:
            issues.append('missing Secure flag (cookie transmitted over HTTP if downgraded)')
        if 'samesite' not in cookie_lower:
            issues.append('missing SameSite (CSRF attacks can include this cookie in cross-origin requests)')

        if issues:
            cookie_name = cookie_val.split('=')[0].strip()
            findings.append({
                'severity': 'LOW',
                'category': 'Headers',
                'title': f'Insecure cookie flags on "{cookie_name}"',
                'description': (
                    f'Cookie "{cookie_name}" is missing security flags that reduce the impact of '
                    f'other attacks: {"; ".join(issues)}. '
                    'These flags are defence-in-depth measures — their absence amplifies the '
                    'damage from XSS or CSRF if those vulnerabilities are separately present.'
                ),
                'evidence': f'Set-Cookie: {cookie_val}',
            })
            break  # One finding for cookie issues is sufficient

    # ------------------------------------------------------------------
    # 12. CORS misconfiguration
    # HIGH (wildcard + credentials) — exploitable cross-origin data theft.
    # LOW (wildcard alone) — acceptable for public APIs.
    # ------------------------------------------------------------------
    acao = h.get('access-control-allow-origin', '')
    acac = h.get('access-control-allow-credentials', '')
    if acao.strip() == '*' and acac.strip().lower() == 'true':
        findings.append({
            'severity': 'HIGH',
            'category': 'Headers',
            'title': 'Critical CORS misconfiguration: wildcard + credentials',
            'description': (
                'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true '
                'is a dangerous CORS misconfiguration. While browsers reject this combination per the '
                'CORS specification, it signals a deeply misconfigured server that likely has other '
                'CORS issues. An attacker could craft a variation that successfully reads authenticated '
                'responses from any origin — enabling cross-origin session hijacking and data exfiltration.'
            ),
            'evidence': f'Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}',
        })
    elif acao.strip() == '*':
        findings.append({
            'severity': 'LOW',
            'category': 'Headers',
            'title': 'CORS: all origins allowed (Access-Control-Allow-Origin: *)',
            'description': (
                'Any origin can read responses from this server. '
                'This is standard and expected for public APIs and CDN-served assets. '
                'It becomes a risk only if combined with Access-Control-Allow-Credentials: true '
                'or if this endpoint serves authenticated/sensitive data.'
            ),
            'evidence': f'Access-Control-Allow-Origin: {acao}',
        })

    return findings
