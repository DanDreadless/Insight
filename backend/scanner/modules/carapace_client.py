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


def capture_screenshot(url: str, width: int = 1280) -> dict | None:
    """
    Render *url* using Carapace and return::

        {
            'screenshot_b64': str,  # base64-encoded PNG; empty string on render failure
            'carapace_risk':  int,  # Carapace risk score 0–100
        }

    Returns ``None`` if:
    - ``CARAPACE_URL`` is not configured (screenshots disabled)
    - The Carapace API is unreachable or returns an error

    Failures are logged at WARNING level and never propagate — the caller
    should treat ``None`` as "screenshot unavailable" and continue normally.
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
                'no_assets': False,   # fetch CSS + images for a realistic render
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
