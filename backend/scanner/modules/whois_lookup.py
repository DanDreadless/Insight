"""
WHOIS data lookup module.

Fetches registration data for the scanned domain (registrar, dates,
country, nameservers) and returns a normalised dict for storage in
scan_metadata.  All failures are caught and return None so a WHOIS
lookup outage never breaks a scan.
"""
import logging
import socket
from datetime import datetime

logger = logging.getLogger(__name__)

_WHOIS_TIMEOUT = 10  # seconds


def lookup_whois(domain: str) -> dict | None:
    """
    Look up WHOIS data for *domain* (hostname, not full URL).

    Returns a normalised dict with string/list values, or None if the
    lookup fails, times out, or returns no useful data.
    """
    if not domain:
        return None

    # Strip any port suffix (e.g. "example.com:8080")
    domain = domain.split(':')[0].strip().lower()
    if not domain:
        return None

    try:
        import whois as _whois
    except ImportError:
        logger.warning('python-whois is not installed — skipping WHOIS lookup')
        return None

    # Apply a socket-level timeout so a slow WHOIS server doesn't stall
    # the Celery task.  socket.setdefaulttimeout is process-global but safe
    # here because we restore it in the finally block.
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_WHOIS_TIMEOUT)
        w = _whois.whois(domain)
    except Exception as exc:
        logger.warning('WHOIS lookup failed for %s: %s', domain, exc)
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)

    if not w:
        return None

    def _date_str(val) -> str | None:
        """Normalise a WHOIS date field to 'YYYY-MM-DD' string or None."""
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        if val is None:
            return None
        if isinstance(val, datetime):
            return val.strftime('%Y-%m-%d')
        s = str(val).strip()
        # Return just the date portion if there's a time component
        return s[:10] if s else None

    def _str_val(val) -> str | None:
        """Normalise a scalar WHOIS field."""
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        if val is None:
            return None
        s = str(val).strip()
        return s if s else None

    def _list_val(val, limit: int = 6) -> list[str]:
        """Normalise a list WHOIS field, deduplicating and lowercasing."""
        if val is None:
            return []
        items = val if isinstance(val, list) else [val]
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            if item is None:
                continue
            s = str(item).strip().lower().rstrip('.')
            if s and s not in seen:
                seen.add(s)
                result.append(s)
            if len(result) >= limit:
                break
        return result

    def _status_list(val) -> list[str]:
        """Normalise WHOIS status codes — strip the ICANN URL suffix."""
        raw = _list_val(val, limit=5)
        cleaned: list[str] = []
        for s in raw:
            # Many registrars append " https://icann.org/epp#..." to status codes
            status = s.split(' ')[0].split('https')[0].strip()
            if status:
                cleaned.append(status)
        return cleaned

    # Build the normalised record
    result: dict = {}

    domain_name = _str_val(w.domain_name)
    if domain_name:
        result['domain_name'] = domain_name.lower()

    registrar = _str_val(w.registrar)
    if registrar:
        result['registrar'] = registrar

    creation_date = _date_str(w.creation_date)
    if creation_date:
        result['creation_date'] = creation_date

    expiry_date = _date_str(w.expiration_date)
    if expiry_date:
        result['expiry_date'] = expiry_date

    updated_date = _date_str(w.updated_date)
    if updated_date:
        result['updated_date'] = updated_date

    country = _str_val(w.country)
    if country:
        result['registrant_country'] = country.upper()

    name_servers = _list_val(w.name_servers)
    if name_servers:
        result['name_servers'] = name_servers

    statuses = _status_list(w.status)
    if statuses:
        result['status'] = statuses

    # If we got nothing useful, treat it as a failed lookup
    if not result:
        return None

    return result
