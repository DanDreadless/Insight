import ipaddress
import socket
from urllib.parse import urlparse

from django.core.exceptions import ValidationError

BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('100.64.0.0/10'),  # CGNAT
]


def is_ip_safe(ip_str: str) -> bool:
    """Return True if the IP address is safe to connect to (not private/loopback/special)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False

    # Also block multicast, reserved, link-local
    if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
        return False

    return True


def validate_url(url: str) -> str:
    """
    Validate a URL for SSRF safety and return the normalised form.
    Raises django.core.exceptions.ValidationError on any failure.
    """
    if not url:
        raise ValidationError('URL must not be empty.')

    if len(url) > 2048:
        raise ValidationError('URL must not exceed 2048 characters.')

    parsed = urlparse(url)

    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(
            f'URL scheme "{parsed.scheme}" is not allowed. Only http and https are permitted.'
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError('URL must include a valid hostname.')

    # Reject obvious internal hostnames
    _BLOCKED_HOSTNAMES = {'localhost', '0.0.0.0', '::1', 'ip6-localhost', 'ip6-loopback'}
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValidationError(f'Hostname "{hostname}" is not permitted.')

    # If hostname is already a raw IP address, check it directly
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if not is_ip_safe(str(ip_obj)):
            raise ValidationError(
                f'IP address "{hostname}" is in a blocked range (private/loopback/link-local).'
            )
        # If the IP is safe, normalise and return
        normalised = url
        if parsed.port:
            normalised = url
        return normalised
    except ValueError:
        pass  # Not a raw IP — resolve it below

    # Resolve hostname to IP(s) and validate each
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValidationError(f'Cannot resolve hostname "{hostname}": {exc}') from exc

    if not addr_infos:
        raise ValidationError(f'Hostname "{hostname}" resolved to no addresses.')

    for addr_info in addr_infos:
        resolved_ip = addr_info[4][0]
        if not is_ip_safe(resolved_ip):
            raise ValidationError(
                f'Hostname "{hostname}" resolves to a blocked IP address: {resolved_ip}'
            )

    # Normalise: ensure scheme is lowercase
    normalised = parsed._replace(scheme=parsed.scheme.lower()).geturl()
    return normalised
