"""
robots.txt compliance checker.

Fetches and parses the target domain's robots.txt, then checks whether the
scanned URL path is disallowed for the Insight scanner user-agent.

A single INFO finding is returned if the path is disallowed — the scan
proceeds regardless, since Insight is a passive security analysis tool, not a
web crawler, and honouring robots.txt would allow malicious sites to trivially
evade detection by adding a blanket Disallow rule.

Site operators can treat this finding as confirmation that their opt-out
directive was observed.
"""
import logging
import urllib.robotparser
from urllib.parse import urlparse

from scanner.modules.fetcher import fetch, FetchError

logger = logging.getLogger(__name__)

# Match the first token of the User-Agent sent by fetcher.py: 'Insight/1.0 ...'
_SCANNER_UA = 'Insight'


def check_robots(target_url: str) -> list[dict]:
    """
    Fetch and parse robots.txt for the target domain.

    Returns a list with one INFO finding if the scanned path is disallowed,
    or an empty list if access is permitted or robots.txt is absent/unreachable.
    """
    parsed = urlparse(target_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    try:
        response = fetch(robots_url)
    except FetchError as exc:
        logger.debug('robots.txt fetch failed for %s: %s', robots_url, exc)
        return []

    if response.get('status_code') != 200:
        return []

    robots_text = response.get('text', '').strip()
    if not robots_text:
        return []

    rp = urllib.robotparser.RobotFileParser()
    rp.parse(robots_text.splitlines())

    if rp.can_fetch(_SCANNER_UA, target_url):
        return []

    relevant = _extract_relevant_rules(robots_text, _SCANNER_UA)

    return [{
        'severity': 'INFO',
        'category': 'Robots',
        'title': 'robots.txt disallows automated access to this path',
        'description': (
            "The target site's robots.txt contains a Disallow rule covering the scanned URL. "
            "The scan proceeded — Insight is a passive security analysis tool, not a web crawler, "
            "and honouring robots.txt would allow malicious sites to trivially evade detection. "
            "Site operators can treat this finding as confirmation that their opt-out directive was observed."
        ),
        'evidence': (
            f"robots.txt: {robots_url}\n"
            f"Scanned path: {parsed.path or '/'}\n\n"
            f"Applicable rules:\n{relevant}"
        ),
        'resource_url': robots_url,
    }]


def _extract_relevant_rules(robots_text: str, ua: str) -> str:
    """
    Return the User-agent blocks from robots_text that apply to ``ua`` or ``*``,
    formatted as a string for display in the finding evidence block.
    """
    ua_lower = ua.lower()

    # Split the file into logical blocks (separated by blank lines / comments)
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in robots_text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            current.append(stripped)
        else:
            if current:
                blocks.append(current)
                current = []
    if current:
        blocks.append(current)

    matched: list[str] = []
    for block in blocks:
        agents = [
            l.split(':', 1)[1].strip().lower()
            for l in block
            if l.lower().startswith('user-agent:')
        ]
        if any(a in (ua_lower, '*') for a in agents):
            matched.extend(block)
            matched.append('')  # blank line between blocks

    return '\n'.join(matched).strip() or '(rules not extracted)'
