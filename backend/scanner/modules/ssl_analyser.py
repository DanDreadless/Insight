"""
SSL/TLS certificate analysis module.
Uses Python's ssl module and pyOpenSSL to inspect certificate properties.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

import tldextract

logger = logging.getLogger(__name__)

_BRAND_NAMES = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
    'twitter', 'instagram', 'netflix', 'bank', 'chase', 'wellsfargo',
    'barclays', 'hsbc', 'lloyds', 'natwest', 'coinbase', 'binance',
    'steam', 'ebay', 'linkedin', 'dropbox', 'icloud', 'yahoo',
]

_BRAND_REAL_SLDS = {
    'paypal': ['paypal'],
    'google': ['google', 'googleapis', 'gstatic', 'googleusercontent'],
    'apple': ['apple', 'icloud', 'mzstatic'],
    'microsoft': ['microsoft', 'live', 'hotmail', 'msn', 'azure', 'windows'],
    'amazon': ['amazon', 'amazonaws'],
    'facebook': ['facebook', 'fb'],
    'twitter': ['twitter', 't'],
    'instagram': ['instagram'],
    'netflix': ['netflix'],
    'chase': ['chase'],
    'wellsfargo': ['wellsfargo'],
    'barclays': ['barclays'],
    'hsbc': ['hsbc'],
    'coinbase': ['coinbase'],
    'binance': ['binance'],
    'steam': ['steampowered', 'steamcommunity'],
    'ebay': ['ebay'],
    'linkedin': ['linkedin'],
    'dropbox': ['dropbox'],
    'icloud': ['icloud'],
    'yahoo': ['yahoo'],
}


def _is_brand_impersonating(hostname: str) -> bool:
    ext = tldextract.extract(hostname)
    sld = ext.domain.lower()
    subdomain = ext.subdomain.lower()

    sld_components = sld.split('-')
    subdomain_components = [p for p in subdomain.split('.') if p]
    for brand in _BRAND_NAMES:
        real_slds = _BRAND_REAL_SLDS.get(brand, [brand])
        # Subdomain: brand must be an exact dot-delimited component
        if brand in subdomain_components and sld not in real_slds:
            return True
        # SLD: brand must equal the full SLD or a hyphen-delimited component
        if (brand == sld or brand in sld_components) and sld not in real_slds:
            return True
    return False


def analyse_ssl(hostname: str, port: int = 443) -> list[dict]:
    """
    Analyse the SSL/TLS certificate for a given hostname.

    Returns list of finding dicts.
    Handles all connection errors gracefully.
    """
    findings: list[dict] = []

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # ------------------------------------------------------------------
    # Attempt connection and retrieve certificate
    # ------------------------------------------------------------------
    cert_dict: Optional[dict] = None
    peer_cert_bin: Optional[bytes] = None
    ssl_version_used: Optional[str] = None

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()
                peer_cert_bin = ssock.getpeercert(binary_form=True)
                ssl_version_used = ssock.version()
    except ssl.CertificateError as exc:
        findings.append({
            'severity': 'HIGH',
            'category': 'SSL',
            'title': 'SSL certificate error',
            'description': f'Certificate verification failed: {exc}',
            'evidence': str(exc),
        })
        # Try without verification to still inspect the cert
        context_noverify = ssl.create_default_context()
        context_noverify.check_hostname = False
        context_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context_noverify.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    peer_cert_bin = ssock.getpeercert(binary_form=True)
                    ssl_version_used = ssock.version()
        except Exception:
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        findings.append({
            'severity': 'INFO',
            'category': 'SSL',
            'title': 'SSL/TLS connection could not be established',
            'description': (
                f'Could not connect to {hostname}:{port} for SSL inspection: {exc}. '
                'This may indicate the service is HTTP-only, firewalled, or non-standard port.'
            ),
            'evidence': str(exc),
        })
        return findings
    except Exception as exc:
        findings.append({
            'severity': 'INFO',
            'category': 'SSL',
            'title': 'SSL inspection encountered an unexpected error',
            'description': f'SSL inspection failed for {hostname}: {type(exc).__name__}: {exc}',
            'evidence': str(exc),
        })
        return findings

    if not cert_dict:
        findings.append({
            'severity': 'INFO',
            'category': 'SSL',
            'title': 'Could not retrieve SSL certificate details',
            'description': f'SSL certificate data not available for {hostname}.',
            'evidence': '',
        })
        return findings

    # ------------------------------------------------------------------
    # Parse certificate fields
    # ------------------------------------------------------------------
    now = datetime.now(tz=timezone.utc)

    # notAfter / expiry
    not_after_str = cert_dict.get('notAfter', '')
    not_before_str = cert_dict.get('notBefore', '')
    issuer_tuples = cert_dict.get('issuer', ())
    subject_tuples = cert_dict.get('subject', ())

    def _flatten_rdn(rdn_sequence: tuple) -> dict[str, str]:
        result: dict[str, str] = {}
        for rdn in rdn_sequence:
            for attr in rdn:
                result[attr[0]] = attr[1]
        return result

    issuer = _flatten_rdn(issuer_tuples)
    subject = _flatten_rdn(subject_tuples)

    issuer_org = issuer.get('organizationName', '')
    issuer_cn = issuer.get('commonName', '')
    subject_cn = subject.get('commonName', '')

    # ------------------------------------------------------------------
    # 1. Certificate expiry
    # ------------------------------------------------------------------
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            days_remaining = (not_after - now).days

            if days_remaining < 0:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'SSL',
                    'title': f'SSL certificate has expired ({abs(days_remaining)} days ago)',
                    'description': (
                        f'The SSL certificate for {hostname} expired on {not_after_str}. '
                        'Expired certificates cause browser warnings and indicate neglected maintenance.'
                    ),
                    'evidence': f'notAfter: {not_after_str} | Days expired: {abs(days_remaining)}',
                })
            elif days_remaining < 30:
                findings.append({
                    'severity': 'LOW',
                    'category': 'SSL',
                    'title': f'SSL certificate expires soon ({days_remaining} days)',
                    'description': (
                        f'The SSL certificate for {hostname} expires on {not_after_str} '
                        f'({days_remaining} days remaining). Renew before expiry to avoid disruption.'
                    ),
                    'evidence': f'notAfter: {not_after_str} | Days remaining: {days_remaining}',
                })
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # 2. Self-signed certificate
    # ------------------------------------------------------------------
    if issuer_cn and subject_cn and issuer_cn == subject_cn:
        findings.append({
            'severity': 'HIGH',
            'category': 'SSL',
            'title': 'Self-signed SSL certificate',
            'description': (
                f'The certificate for {hostname} is self-signed (issuer CN == subject CN: "{issuer_cn}"). '
                'Self-signed certificates provide no trust chain and are easily forged.'
            ),
            'evidence': f'Issuer CN: {issuer_cn} | Subject CN: {subject_cn}',
        })
    elif issuer_org and subject.get('organizationName', '') and issuer_org == subject.get('organizationName', ''):
        # Issuer and subject orgs match — likely self-signed
        if 'let\'s encrypt' not in issuer_org.lower() and 'digicert' not in issuer_org.lower():
            findings.append({
                'severity': 'HIGH',
                'category': 'SSL',
                'title': 'Possible self-signed SSL certificate (issuer org == subject org)',
                'description': (
                    f'Issuer organization "{issuer_org}" matches subject organization. '
                    'May indicate a self-signed or internally-issued certificate.'
                ),
                'evidence': f'Issuer: {issuer} | Subject: {subject}',
            })

    # ------------------------------------------------------------------
    # 3. Hostname mismatch (checked via CertificateError above, but double-check SANs)
    # ------------------------------------------------------------------
    san_list: list[str] = []
    for san_type, san_val in cert_dict.get('subjectAltName', []):
        if san_type.lower() == 'dns':
            san_list.append(san_val.lower())

    if san_list:
        hostname_lower = hostname.lower()
        matched = False
        for san in san_list:
            if san == hostname_lower:
                matched = True
                break
            if san.startswith('*.'):
                wildcard_domain = san[2:]
                parts = hostname_lower.split('.')
                if len(parts) >= 2 and '.'.join(parts[1:]) == wildcard_domain:
                    matched = True
                    break
        if not matched:
            findings.append({
                'severity': 'HIGH',
                'category': 'SSL',
                'title': 'Certificate hostname mismatch',
                'description': (
                    f'The certificate SANs do not include "{hostname}". '
                    'This could indicate a misconfiguration or man-in-the-middle interception.'
                ),
                'evidence': f'Hostname: {hostname} | SANs: {", ".join(san_list)}',
            })

    # ------------------------------------------------------------------
    # 4. Let's Encrypt on brand-impersonating domain
    # ------------------------------------------------------------------
    is_le = 'let\'s encrypt' in issuer_org.lower() or 'let\'s encrypt' in issuer_cn.lower()
    if is_le and _is_brand_impersonating(hostname):
        findings.append({
            'severity': 'MEDIUM',
            'category': 'SSL',
            'title': "Let's Encrypt cert on brand-impersonating domain",
            'description': (
                f'The hostname "{hostname}" appears to impersonate a brand, and the certificate '
                'was issued by Let\'s Encrypt. LE provides no organisation validation — phishing '
                'sites routinely use LE for the "padlock" without legitimacy.'
            ),
            'evidence': f'Issuer: {issuer_cn} | Hostname: {hostname}',
        })

    # ------------------------------------------------------------------
    # 5. Deprecated TLS version
    # ------------------------------------------------------------------
    if ssl_version_used:
        # Exact match only — 'TLSv1.3'.startswith('TLSv1') is True, which is wrong.
        # TLS 1.2 and 1.3 are not deprecated; only 1.0, 1.1, SSLv2, SSLv3 are.
        deprecated_versions = {'TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2'}
        if ssl_version_used in deprecated_versions:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'SSL',
                'title': f'Deprecated TLS version in use: {ssl_version_used}',
                'description': (
                    f'Connection negotiated using {ssl_version_used}, which is deprecated and '
                    'vulnerable to known attacks (POODLE, BEAST, etc.). '
                    'Minimum TLS 1.2 (preferably TLS 1.3) should be enforced.'
                ),
                'evidence': f'Negotiated TLS version: {ssl_version_used}',
            })
    else:
        # Try deprecated TLS explicitly
        try:
            legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy_ctx.check_hostname = False
            legacy_ctx.verify_mode = ssl.CERT_NONE
            legacy_ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with legacy_ctx.wrap_socket(sock) as ssock:
                    legacy_version = ssock.version()
                    findings.append({
                        'severity': 'MEDIUM',
                        'category': 'SSL',
                        'title': f'Server accepts deprecated TLS {legacy_version}',
                        'description': (
                            f'The server accepted a connection using deprecated TLS {legacy_version}. '
                            'Deprecated TLS versions are vulnerable to known attacks.'
                        ),
                        'evidence': f'Server accepted TLS version: {legacy_version}',
                    })
        except (ssl.SSLError, AttributeError, OSError):
            pass  # Good — server rejected legacy TLS

    # ------------------------------------------------------------------
    # 6. Certificate age (INFO)
    # ------------------------------------------------------------------
    if not_before_str:
        try:
            not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            age_days = (now - not_before).days
            if 0 <= age_days < 7:
                findings.append({
                    'severity': 'INFO',
                    'category': 'SSL',
                    'title': f'Certificate issued very recently ({age_days} days ago)',
                    'description': (
                        f'SSL certificate was issued only {age_days} day(s) ago ({not_before_str}). '
                        'A freshly issued certificate is normal for new sites, but in combination with '
                        'other indicators may suggest a newly registered phishing domain.'
                    ),
                    'evidence': f'notBefore: {not_before_str} | Age: {age_days} days',
                })
        except ValueError:
            pass

    return findings
