"""
HTML structure analysis module.
Detects phishing forms, hidden iframes, suspicious downloads, and security misconfigurations.
"""
import os
import re
import logging
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup, Comment

from scanner.modules.known_good_domains import is_known_good, is_payment_processor, is_cdn

logger = logging.getLogger(__name__)

_BRAND_KEYWORDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter',
    'instagram', 'bank', 'chase', 'wellsfargo', 'wells fargo', 'hsbc', 'barclays',
    'lloyds', 'natwest', 'halifax', 'santander', 'citibank', 'netflix', 'steam',
    'ebay', 'linkedin', 'dropbox', 'onedrive', 'icloud', 'yahoo', 'outlook',
    'office365', 'coinbase', 'binance', 'blockchain',
    'metamask', 'bitmart', 'myetherwallet', 'kucoin', 'blockfi',
    'ledger', 'trezor', 'trustwallet', 'opensea', 'uniswap',
    'roblox', 'discord', 'twitch', 'spotify',
]

# Maps a crypto wallet / exchange brand keyword to the set of registered
# domains that legitimately use that brand.  If the page title claims one
# of these brands but the page domain is not in the official set, it is
# almost certainly brand-impersonation phishing.
_CRYPTO_WALLET_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    'trezor':        frozenset({'trezor.io'}),
    'metamask':      frozenset({'metamask.io'}),
    'ledger':        frozenset({'ledger.com'}),
    'trustwallet':   frozenset({'trustwallet.com'}),
    'myetherwallet': frozenset({'myetherwallet.com'}),
    'phantom':       frozenset({'phantom.app'}),
    'coinbase':      frozenset({'coinbase.com'}),
    'uniswap':       frozenset({'uniswap.org'}),
    'opensea':       frozenset({'opensea.io'}),
    'kucoin':        frozenset({'kucoin.com'}),
    'binance':       frozenset({'binance.com'}),
    'blockfi':       frozenset({'blockfi.com'}),
}

# Extensions checked against the URL *path only* (never the hostname).
# .js excluded — it is a normal web asset analysed separately by js_analyser.
# .com excluded — it is a TLD and would produce false positives on every .com domain.
_EXECUTABLE_EXT_SET = frozenset({
    '.exe', '.msi', '.bat', '.cmd', '.vbs', '.ps1',
    '.dmg', '.pkg', '.apk', '.scr', '.pif', '.hta',
})

_FAKE_UPDATE_BROWSER_RE = re.compile(
    r'\b(?:chrome|chromium|firefox|mozilla|edge|safari|browser)\b',
    re.IGNORECASE,
)
_FAKE_UPDATE_ACTION_RE = re.compile(
    r'\b(?:update|upgrade|install|download|outdated|new\s+version|latest\s+version)\b',
    re.IGNORECASE,
)
_FAKE_UPDATE_EXEC_RE = re.compile(r'\.(?:exe|msi|dmg|pkg)\b', re.IGNORECASE)

_IPFS_GATEWAY_RE = re.compile(
    r'https?://(?:'
    r'[a-zA-Z0-9]+\.ipfs\.io/|'
    r'ipfs\.io/ipfs/|'
    r'cloudflare-ipfs\.com/|'
    r'gateway\.pinata\.cloud/|'
    r'ipfs\.infura\.io/|'
    r'dweb\.link/|'
    r'[a-zA-Z0-9]+\.ipfs\.dweb\.link/|'
    r'nftstorage\.link/|'
    r'w3s\.link/'
    r')',
    re.IGNORECASE,
)

_CLICKFIX_CAPTCHA_RE = re.compile(
    r'(?:'
    # Classic fake CAPTCHA framing
    r'verify\s+you(?:\'re|\s+are)\s+(?:human|not\s+a\s+robot)|'
    r'i(?:\'m|\s+am)\s+not\s+a\s+robot|'
    r'human\s+verif(?:y|ication)|'
    r'prove\s+you(?:\'re|\s+are)\s+human|'
    r'captcha\s+verif|'
    # "Click to fix" / ClickFix-branded variants
    r'click\s+(?:here\s+)?(?:to\s+)?fix\b|'
    r'click\s+fix\b|'
    # Browser / identity verification overlays
    r'browser\s+verif(?:y|ication)|'
    r'verify\s+your\s+(?:browser|identity|access)|'
    r'confirm\s+you(?:\'re|\s+are)\s+(?:human|not\s+a\s+robot)|'
    # "Action required" / error-page style prompts
    r'action\s+required.*(?:fix|resolve|continue)|'
    r'website\s+blocked.*(?:fix|restore|access)'
    r')',
    re.IGNORECASE,
)
_CLICKFIX_INSTRUCTION_RE = re.compile(
    r'(?:'
    # Win+R / Run dialog instructions
    r'press\s+(?:windows|win)\s*\+\s*r\b|'
    r'(?:use|hit)\s+(?:win(?:dows)?\s*\+\s*r|run\s+dialog)|'
    r'windows\s*\+\s*r\b|'
    r'open\s+run\s+dialog|'
    # Paste-into-terminal instructions
    r'paste\s+(?:into|in\s+the)\s+(?:run|command|terminal|powershell|cmd|search\s+bar)|'
    r'paste\s+(?:it\s+)?(?:and|then)\s+(?:run|execute|press\s+enter)|'
    r'copy\s+(?:and|then)\s+(?:run|execute|paste\s+(?:it\s+)?(?:in|into))|'
    # Explicit "run the following" framing
    r'run\s+the\s+following\s+(?:command|script|code|fix)|'
    r'type\s+the\s+following\s+(?:in|into)|'
    # Keyboard shortcuts / direct execution prompts
    r'press\s+ctrl\s*\+\s*v|'
    r'open\s+(?:powershell|terminal|command\s+prompt)'
    r')',
    re.IGNORECASE,
)

# Shell command indicators that are unambiguous when found in HTML attributes
# or hidden elements — PowerShell, mshta, cmd, and in-memory execution chains
# have no legitimate reason to appear in data-* attrs, onclick handlers, or
# display:none content.
_HTML_SHELL_RE = re.compile(
    r'(?:'
    r'powershell(?:\.exe)?(?=[\s\-;,\'"]|$)|'
    r'mshta(?:\.exe)?(?=[\s:;\'"(]|$)|'
    r'cmd(?:\.exe)?\s*/[cfkCFK]|'
    r'wscript(?:\.exe)?(?=[\s\'"(]|$)|'
    r'cscript(?:\.exe)?(?=[\s\'"(]|$)|'
    r'rundll32(?:\.exe)?(?=[\s\'"(]|$)|'
    r'regsvr32(?:\.exe)?(?=[\s\'"(]|$)|'
    r'\|\s*iex\b|'
    r';\s*iex\b|'
    r'&\s*iex\b|'
    r'\binvoke-expression\b|'
    r'\binvoke-restmethod\b|'
    r'\binvoke-webrequest\b'
    r')',
    re.IGNORECASE,
)

_HTML_EVENT_ATTRS: frozenset = frozenset({
    'onclick', 'onmouseover', 'onmouseout', 'onload', 'onsubmit',
    'onkeydown', 'onkeyup', 'onfocus', 'onblur', 'onchange',
    'onmouseenter', 'onmouseleave', 'ondblclick', 'oninput',
})

_SENSITIVE_COMMENT_KEYWORDS = re.compile(
    r'\b(?:password|api_key|apikey|token|secret|todo|fixme|hack|debug|'
    r'internal|private|credentials|passwd|pwd|auth)\b',
    re.IGNORECASE,
)


def _check_shell_commands_in_html(soup) -> list[dict]:
    """
    Detect PowerShell/cmd/mshta shell command strings stored in HTML attributes
    or hidden elements — the payload-storage half of the ClickFix technique.

    ClickFix attackers commonly keep the clipboard payload out of inline <script>
    blocks to evade JS-focused scanners.  Instead they store it as:
      - data-* attribute:  <button data-cmd="powershell -enc ...">
      - onclick handler:   <button onclick="clipboard.writeText(this.dataset.cmd)">
      - hidden element:    <div style="display:none">powershell ...</div>
      - hidden input:      <input type="hidden" value="powershell ...">

    No legitimate page embeds shell commands in these locations.
    """
    findings = []

    # 1. data-* attributes and inline event handlers
    for tag in soup.find_all(True):
        for attr_name, attr_val in tag.attrs.items():
            if not isinstance(attr_val, str):
                continue
            attr_lower = attr_name.lower()
            if attr_lower.startswith('data-') or attr_lower in _HTML_EVENT_ATTRS:
                m = _HTML_SHELL_RE.search(attr_val)
                if m:
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'HTML',
                        'title': 'Shell command in HTML attribute (ClickFix payload storage)',
                        'description': (
                            f'A shell command string ({m.group(0)!r}) was found inside an HTML '
                            f'{attr_name!r} attribute. This is a ClickFix payload-storage pattern: '
                            f'the malicious command is embedded in the DOM and passed to '
                            f'navigator.clipboard.writeText() when the user clicks a fake verification '
                            f'button. The visitor is then socially engineered to paste and execute it '
                            f'via Win+R or a terminal prompt. No legitimate page uses this pattern.'
                        ),
                        'evidence': f'[<{tag.name}> — {attr_name}]\n{attr_val[:600]}',
                    })
                    return findings  # One CRITICAL is enough

    # 2. Hidden element text / hidden input values
    for tag in soup.find_all(True):
        style = tag.get('style', '')
        is_hidden = (
            re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', style, re.IGNORECASE)
            or tag.get('type', '').lower() == 'hidden'
            or tag.name == 'template'
        )
        if not is_hidden:
            continue
        for candidate in (tag.get_text(strip=True), tag.get('value', '')):
            if not candidate:
                continue
            m = _HTML_SHELL_RE.search(candidate)
            if m:
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'HTML',
                    'title': 'Shell command in hidden HTML element (ClickFix payload storage)',
                    'description': (
                        f'A shell command string ({m.group(0)!r}) was found inside a hidden HTML '
                        f'element (display:none, visibility:hidden, or hidden input). '
                        f'This is the ClickFix payload-storage pattern: the command is concealed '
                        f'from the visible page and retrieved by a clipboard.writeText() call when '
                        f'the user interacts with a fake CAPTCHA or verification overlay. '
                        f'No legitimate page stores shell commands in hidden elements.'
                    ),
                    'evidence': f'[<{tag.name}> — hidden]\n{candidate[:600]}',
                })
                return findings

    return findings


def _path_extension(href: str) -> str:
    """Return lowercase file extension from the URL path only, ignoring hostname and query string."""
    try:
        _, ext = os.path.splitext(urlparse(href).path)
        return ext.lower()
    except Exception:
        return ''


def _registrable_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain


def _is_external(url: str, page_url: str) -> bool:
    page_dom = _registrable_domain(page_url)
    target_dom = _registrable_domain(url)
    return bool(target_dom) and target_dom != page_dom


def analyse_html(html: str, page_url: str, resources: dict) -> list[dict]:
    """
    Analyse HTML content for security issues.

    Returns list of finding dicts with keys:
        severity, category, title, description, evidence.
    """
    findings: list[dict] = []
    soup = BeautifulSoup(html, 'lxml')
    page_domain = _registrable_domain(page_url)
    page_scheme = urlparse(page_url).scheme

    # ------------------------------------------------------------------
    # 1. Phishing form detector
    # ------------------------------------------------------------------
    page_text = soup.get_text(separator=' ', strip=True).lower()
    # Use word-boundary matching to avoid compound-word false positives
    # (e.g. "bank" matching "snowbank").
    has_brand = any(re.search(r'\b' + re.escape(kw) + r'\b', page_text) for kw in _BRAND_KEYWORDS)
    title_tag = soup.find('title')
    page_title = title_tag.get_text().lower() if title_tag else ''
    has_brand_in_title = any(re.search(r'\b' + re.escape(kw) + r'\b', page_title) for kw in _BRAND_KEYWORDS)

    for form in resources.get('forms', []):
        action = form.get('action', '')
        if not action:
            continue
        action_domain = _registrable_domain(action)
        if action_domain and action_domain != page_domain:
            if is_payment_processor(action_domain):
                # Known payment processor — expected cross-domain form submission
                findings.append({
                    'severity': 'INFO',
                    'category': 'Phishing',
                    'title': 'Form submits to known payment processor',
                    'description': (
                        f'Form action points to "{action_domain}", a known payment processor. '
                        'Cross-domain submission to payment providers is expected and legitimate.'
                    ),
                    'evidence': f'action="{action}" | page domain: {page_domain}',
                })
            else:
                # Escalate to CRITICAL only if the page title contains a brand
                # keyword — the title is a reliable signal of active impersonation.
                # Body-text brand matches alone are weak (e.g. a hosting company
                # that mentions the word "bank" somewhere on their page).
                severity = 'CRITICAL' if has_brand_in_title else 'HIGH'
                findings.append({
                    'severity': severity,
                    'category': 'Phishing',
                    'title': 'Form submits credentials to external domain',
                    'description': (
                        f'A form on "{page_domain}" submits its data to "{action_domain}" — '
                        'a different domain. This is the core mechanism of a credential harvesting '
                        'attack: the visitor believes they are submitting to the site they are on, '
                        'but their input is sent directly to an attacker-controlled server. '
                        + ('The page title contains a brand keyword, confirming active brand '
                           'impersonation — victims are being deceived about which site they are on.'
                           if has_brand_in_title else
                           'Investigate whether this is a legitimate third-party form processor '
                           '(e.g., Typeform, Mailchimp) or an attacker\'s collection endpoint.')
                    ),
                    'evidence': f'action="{action}" | page domain: {page_domain} | action domain: {action_domain}',
                })

    # ------------------------------------------------------------------
    # 2. Hidden iframes
    # ------------------------------------------------------------------
    # Build the set of external script hostnames so we can suppress iframe
    # findings that come from the same CDN — a strong signal of TMS tracking
    # pixel infrastructure (e.g. Tealium) rather than an attack.
    _ext_script_hosts: set[str] = {
        urlparse(s['url']).hostname or ''
        for s in resources.get('scripts', [])
        if not s.get('inline', True) and s.get('url')
    }
    _ext_script_hosts.discard('')

    for iframe_info in resources.get('iframes', []):
        attrs = iframe_info.get('attrs', {})
        url = iframe_info.get('url', '')
        style = attrs.get('style', '').lower()
        width = str(attrs.get('width', '')).strip()
        height = str(attrs.get('height', '')).strip()

        is_hidden = any([
            'display:none' in style.replace(' ', ''),
            'visibility:hidden' in style.replace(' ', ''),
            'width:0' in style.replace(' ', ''),
            'height:0' in style.replace(' ', ''),
            width in ('0', '0px'),
            height in ('0', '0px'),
            'position:absolute' in style.replace(' ', '') and (
                'left:-' in style or 'top:-' in style
            ),
        ])

        if is_hidden:
            # Suppress if iframe src is from the same host as an external
            # script already loaded on the page.  Tag management systems
            # (Tealium, similar) load their tracking pixels from the same
            # CDN distribution as their wrapper script — this is not an attack.
            iframe_host = urlparse(url).hostname or ''
            if iframe_host and iframe_host in _ext_script_hosts:
                continue
            # SEC-19: escape attacker-controlled values so a crafted attribute
            # cannot make the evidence block appear to be a different finding.
            def _esc(s: str) -> str:
                return str(s).replace('"', '&quot;').replace('\n', ' ').replace('\r', ' ')
            tag_repr = f'<iframe src="{_esc(url)}" {" ".join(f"{k}=\"{_esc(v)}\"" for k, v in attrs.items())}>'
            findings.append({
                'severity': 'HIGH',
                'category': 'HTML',
                'title': 'Hidden iframe detected',
                'description': (
                    'An iframe is deliberately hidden using CSS or zero dimensions '
                    '(display:none, width=0, height=0, or negative off-screen positioning). '
                    'There is no legitimate reason to embed invisible cross-origin content on a page. '
                    'Hidden iframes are a well-documented attack primitive used to: '
                    '(1) load drive-by exploit pages that attack visitor browsers silently, '
                    '(2) pre-authenticate victims on third-party sites for clickjacking, or '
                    '(3) trigger automatic resource requests to attacker infrastructure. '
                    'In the context of other threat signals, this strongly indicates '
                    'a compromised page or purpose-built attack infrastructure.'
                ),
                'evidence': tag_repr,
            })

    # ------------------------------------------------------------------
    # 3. Base tag hijack
    # ------------------------------------------------------------------
    base_href = resources.get('base_href')
    if base_href:
        base_is_external = _is_external(base_href, page_url)
        severity = 'HIGH' if base_is_external else 'MEDIUM'
        findings.append({
            'severity': severity,
            'category': 'HTML',
            'title': 'Base tag present' + (' pointing to external domain' if base_is_external else ''),
            'description': (
                f'<base href="{base_href}"> changes the base URL for all relative links. '
                + ('The base href points to an external domain — this is a strong indicator of URL hijacking.'
                   if base_is_external else
                   'Verify that this base href is intentional and not attacker-injected.')
            ),
            'evidence': f'<base href="{base_href}">',
        })

    # ------------------------------------------------------------------
    # 4. Meta refresh redirect
    # ------------------------------------------------------------------
    for meta_info in resources.get('meta_refresh', []):
        delay = meta_info.get('delay', 999)
        refresh_url = meta_info.get('url', '')
        is_ext = _is_external(refresh_url, page_url) if refresh_url else False
        severity = 'HIGH' if (delay <= 2 and is_ext) else 'MEDIUM'
        findings.append({
            'severity': severity,
            'category': 'HTML',
            'title': f'Meta refresh redirect (delay={delay}s)',
            'description': (
                f'Page redirects after {delay} second(s) via <meta http-equiv="refresh">. '
                + ('Immediate redirect to external domain — classic phishing redirect technique.'
                   if delay <= 2 and is_ext else
                   'Meta refresh with short delay may disorient users or hide phishing content.')
            ),
            'evidence': f'delay={delay}, url="{refresh_url}"',
        })

    # ------------------------------------------------------------------
    # 5. Right-click disable in HTML
    # ------------------------------------------------------------------
    body = soup.find('body')
    if body:
        oncontextmenu = body.get('oncontextmenu', '')
        if 'return false' in oncontextmenu.lower():
            findings.append({
                'severity': 'MEDIUM',
                'category': 'HTML',
                'title': 'Right-click context menu disabled',
                'description': (
                    'The page disables the browser\'s right-click context menu via '
                    'oncontextmenu="return false". While some legitimate sites use this to '
                    'protect media assets, in conjunction with other suspicious signals it is '
                    'an anti-analysis technique: it prevents visitors from easily inspecting '
                    'links, viewing page source shortcuts, or accessing developer tools via '
                    'context menu — reducing the chance of casual detection of malicious content.'
                ),
                'evidence': f'oncontextmenu="{oncontextmenu}"',
            })

    # ------------------------------------------------------------------
    # 6. Disabled text selection
    # ------------------------------------------------------------------
    style_tags = soup.find_all('style')
    full_style = ' '.join(t.get_text() for t in style_tags)
    if 'user-select' in full_style.lower() and 'none' in full_style.lower():
        findings.append({
            'severity': 'LOW',
            'category': 'HTML',
            'title': 'Text selection disabled via CSS',
            'description': (
                'CSS user-select:none is applied to body or global scope, preventing text selection. '
                'Often paired with other anti-inspection techniques.'
            ),
            'evidence': 'user-select: none found in stylesheet',
        })

    for tag in soup.find_all(onselectstart=True):
        val = tag.get('onselectstart', '').lower()
        if 'return false' in val or 'false' in val:
            findings.append({
                'severity': 'LOW',
                'category': 'HTML',
                'title': 'Text selection blocked via onselectstart handler',
                'description': 'onselectstart handler prevents text selection on this element.',
                'evidence': f'onselectstart="{tag.get("onselectstart", "")}"',
            })
            break

    # ------------------------------------------------------------------
    # 7. Suspicious download links
    # Extension is checked against the URL path only — never the hostname —
    # to avoid false positives like `.com` in `example.com/page`.
    # Deduplicated by href: one finding per unique URL with an occurrence count.
    # ------------------------------------------------------------------
    download_link_counts: dict[str, int] = {}
    for tag in soup.find_all('a'):
        href = tag.get('href', '')
        if not href:
            continue
        ext = _path_extension(href)
        if ext in _EXECUTABLE_EXT_SET or tag.has_attr('download'):
            download_link_counts[href] = download_link_counts.get(href, 0) + 1

    for href, count in download_link_counts.items():
        ext = _path_extension(href)
        count_note = f' — link appears {count} times on this page' if count > 1 else ''
        ext_label = ext if ext else '(download attribute set)'
        findings.append({
            'severity': 'MEDIUM',
            'category': 'HTML',
            'title': f'Executable file download link: {ext_label}',
            'description': (
                f'A link on this page points to a file with an executable extension ({ext_label}). '
                'Malware delivery campaigns (SocGholish, ClearFake, ClickFix) frequently use '
                'download links to .exe, .msi, .ps1, .bat, and .hta files as the final payload '
                'delivery step — the visitor is told the file is a browser update, security tool, '
                'or required software. '
                'Evaluate whether the download is expected given the page\'s stated purpose.'
            ),
            'evidence': f'href="{href}"{count_note}',
        })

    # ------------------------------------------------------------------
    # 8. Inline script size anomaly
    # ------------------------------------------------------------------
    inline_scripts = [s for s in resources.get('scripts', []) if s.get('inline')]
    total_inline_script_size = sum(len(s.get('content', '')) for s in inline_scripts)
    full_html_len = len(html)
    script_tag_size = sum(
        len(str(tag)) for tag in soup.find_all('script')
    )
    non_script_size = max(full_html_len - script_tag_size, 1)
    if total_inline_script_size > 3 * non_script_size:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': 'Page is primarily an inline script delivery vehicle',
            'description': (
                f'Total inline JavaScript ({total_inline_script_size} bytes) is more than 3× '
                f'the structural HTML content ({non_script_size} bytes). '
                'Legitimate web pages serve content with scripting as enhancement; this ratio '
                'indicates the opposite — the "page" exists mainly to deliver script. '
                'This is a common characteristic of obfuscated attack pages: phishing kits, '
                'SocGholish injections, and cryptominer landing pages typically have a minimal '
                'HTML wrapper with large embedded payloads.'
            ),
            'evidence': f'Inline JS: {total_inline_script_size}B | Non-script HTML: {non_script_size}B | Ratio: {total_inline_script_size // max(non_script_size, 1)}×',
        })

    # ------------------------------------------------------------------
    # 9. noscript redirect
    # ------------------------------------------------------------------
    for noscript in soup.find_all('noscript'):
        content = noscript.get_text(separator=' ')
        if re.search(r'http[s]?://', content, re.IGNORECASE):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'HTML',
                'title': 'Noscript block contains external URL redirect',
                'description': (
                    '<noscript> tag contains a link or redirect to an external URL. '
                    'Used to redirect users with JavaScript disabled to alternative phishing pages.'
                ),
                'evidence': content,
            })
            break

    # ------------------------------------------------------------------
    # 10. External scripts without SRI
    # ------------------------------------------------------------------
    external_scripts_without_sri: list[str] = []
    known_good_without_sri: list[str] = []
    for tag in soup.find_all('script', src=True):
        src = tag.get('src', '')
        if src.startswith('http') and _is_external(src, page_url):
            if not tag.get('integrity'):
                if is_known_good(src):
                    known_good_without_sri.append(src)
                else:
                    external_scripts_without_sri.append(src)

    if external_scripts_without_sri:
        suppressed_note = (
            f'\n\n[{len(known_good_without_sri)} script(s) from known-good domains also lack SRI but were suppressed]'
            if known_good_without_sri else ''
        )
        script_list = '\n'.join(f'  <script src="{s}"> (no integrity attribute)' for s in external_scripts_without_sri)
        findings.append({
            'severity': 'LOW',
            'category': 'Security',
            'title': f'External scripts loaded without Subresource Integrity (SRI) — {len(external_scripts_without_sri)} found',
            'description': (
                'External scripts are included without an integrity attribute. '
                'If the CDN or external server is compromised, malicious code would execute unchecked.'
            ),
            'evidence': (
                f'[Scripts missing integrity= attribute ({len(external_scripts_without_sri)} total)]\n'
                + script_list
                + suppressed_note
            ),
        })
    elif known_good_without_sri:
        # All external scripts lacking SRI are from known-good domains — suppress finding
        pass

    # ------------------------------------------------------------------
    # 11. Password field without autocomplete
    # ------------------------------------------------------------------
    for pwd_input in soup.find_all('input', type=lambda t: t and t.lower() == 'password'):
        ac = pwd_input.get('autocomplete', '').lower()
        if ac not in ('off', 'new-password', 'current-password'):
            findings.append({
                'severity': 'LOW',
                'category': 'Security',
                'title': 'Password field missing autocomplete attribute',
                'description': (
                    'A password input field lacks autocomplete="off" or autocomplete="new-password". '
                    'This may allow browsers to autofill credentials on phishing pages.'
                ),
                'evidence': str(pwd_input),
            })
            break

    # ------------------------------------------------------------------
    # 12. Login form over HTTP
    # ------------------------------------------------------------------
    for form_info in resources.get('forms', []):
        action = form_info.get('action', '')
        inputs = form_info.get('inputs', [])
        has_password = any(i.get('type', '').lower() == 'password' for i in inputs)
        if has_password:
            action_scheme = urlparse(action).scheme if action else page_scheme
            if action_scheme == 'http' or page_scheme == 'http':
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Security',
                    'title': 'Login form transmitting credentials over HTTP',
                    'description': (
                        'A form with a password field is submitting over an unencrypted HTTP connection. '
                        'Credentials are exposed to network interception.'
                    ),
                    'evidence': f'form action="{action}" | page scheme: {page_scheme}',
                })
                break

    # ------------------------------------------------------------------
    # 13. Sensitive comment disclosure
    # ------------------------------------------------------------------
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        if _SENSITIVE_COMMENT_KEYWORDS.search(str(comment)):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Security',
                'title': 'Sensitive information in HTML comment',
                'description': (
                    'An HTML comment contains potentially sensitive keywords '
                    '(password, api_key, token, secret, etc.). '
                    'Sensitive data in comments may be visible to anyone viewing page source.'
                ),
                'evidence': str(comment),
            })
            if len([f for f in findings if f['title'].startswith('Sensitive')]) >= 3:
                break

    # ------------------------------------------------------------------
    # 14. Clickjacking overlay
    # ------------------------------------------------------------------
    # SEC-07: use sequential simple patterns instead of a single .*?/DOTALL
    # regex — the original was vulnerable to ReDoS on malformed style attributes.
    # Each sub-pattern is O(n); no backtracking across quantifiers.
    _pos_re = re.compile(r'position\s*:\s*(?:fixed|absolute)', re.IGNORECASE)
    _topleft_re = re.compile(r'(?:top|left)\s*:\s*0', re.IGNORECASE)
    _fullsize_re = re.compile(r'(?:width|height)\s*:\s*100%', re.IGNORECASE)
    _zindex_re = re.compile(r'z-index\s*:\s*(\d+)', re.IGNORECASE)

    for tag in soup.find_all(True):
        style = tag.get('style', '')
        if not style:
            continue
        if not _pos_re.search(style):
            continue
        if not _topleft_re.search(style):
            continue
        if not _fullsize_re.search(style):
            continue
        zm = _zindex_re.search(style)
        if not zm:
            continue
        z_index = int(zm.group(1))
        if z_index > 100:
            onclick = tag.get('onclick', '') or tag.get('onmousedown', '')
            if onclick or tag.name in ('div', 'span', 'a'):
                findings.append({
                    'severity': 'HIGH',
                    'category': 'HTML',
                    'title': 'Potential clickjacking overlay element',
                    'description': (
                        f'A full-viewport positioned element (z-index={z_index}) with click handling '
                        'was detected. This pattern is used for clickjacking attacks where an '
                        'invisible layer captures clicks intended for the page beneath it.'
                    ),
                    'evidence': (
                        f'[Element: <{tag.name}>, z-index={z_index}]\n'
                        f'style="{style}"\n'
                        + (f'\n[Click handler]\n{onclick[:300]}' if onclick else '')
                    ),
                })
                break

    # ------------------------------------------------------------------
    # 15. Fake browser update page (SocGholish / ClearFake)
    # ------------------------------------------------------------------
    page_text_lower = soup.get_text(separator=' ', strip=True)
    if (
        _FAKE_UPDATE_BROWSER_RE.search(page_text_lower)
        and _FAKE_UPDATE_ACTION_RE.search(page_text_lower)
    ):
        exec_links = [
            tag.get('href', '')
            for tag in soup.find_all('a', href=True)
            if _FAKE_UPDATE_EXEC_RE.search(urlparse(tag.get('href', '')).path)
        ]
        if exec_links:
            findings.append({
                'severity': 'HIGH',
                'category': 'HTML',
                'title': 'Fake browser update page (SocGholish/ClearFake pattern)',
                'description': (
                    'Page combines browser/update terminology with executable download links. '
                    'SocGholish and ClearFake campaigns inject fake browser update overlays into '
                    'compromised legitimate websites to deliver RATs, info-stealers, and ransomware loaders.'
                ),
                'evidence': (
                    'Browser/update keywords detected in page content.\n'
                    'Executable download links: ' + ', '.join(exec_links[:5])
                ),
            })

    # ------------------------------------------------------------------
    # 16. IPFS-hosted resources
    # ------------------------------------------------------------------
    ipfs_urls: list[str] = []
    ipfs_seen: set[str] = set()
    for script in resources.get('scripts', []):
        u = script.get('url', '')
        if _IPFS_GATEWAY_RE.search(u) and u not in ipfs_seen:
            ipfs_urls.append(u)
            ipfs_seen.add(u)
    for m in _IPFS_GATEWAY_RE.finditer(html):
        u = m.group(0)
        if u not in ipfs_seen:
            ipfs_urls.append(u)
            ipfs_seen.add(u)
    if ipfs_urls:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'HTML',
            'title': f'Resources loaded from IPFS gateway ({len(ipfs_urls)} found)',
            'description': (
                'This page loads content from IPFS (InterPlanetary File System) gateways. '
                'IPFS content is addressed by cryptographic hash and is immutable — it cannot be '
                'taken down by contacting a hosting provider or registrar, making it a preferred '
                'delivery infrastructure for threat actors who need takedown resistance. '
                'IPFS phishing domains increased 215% between January and August 2024 (Bolster AI). '
                'Common uses: phishing kits that survive domain seizures, crypto wallet drainer '
                'scripts, and malicious overlays on compromised pages. '
                'Legitimate sites have very limited reasons to load content from IPFS gateways '
                '(some NFT/Web3 platforms are the exception).'
            ),
            'evidence': '\n'.join(ipfs_urls[:10]),
        })

    # ------------------------------------------------------------------
    # 17. External script preload / prefetch (WordPress malware injection)
    # ------------------------------------------------------------------
    # Attackers injecting malware into WordPress sites commonly add
    # <link rel="preload" as="script"> or <link rel="prefetch"> hints
    # pointing to their malicious CDN, staging the payload before execution.
    # Legitimate preloads are almost always same-origin or well-known CDNs.
    preload_hrefs: list[str] = []
    for link_tag in soup.find_all('link', rel=True):
        rel_vals = link_tag.get('rel', [])
        if isinstance(rel_vals, str):
            rel_vals = [rel_vals]
        rel_vals = [r.lower() for r in rel_vals]
        href = link_tag.get('href', '')
        if not href or not href.startswith('http'):
            continue
        is_preload_script = (
            'preload' in rel_vals and link_tag.get('as', '').lower() == 'script'
        )
        is_prefetch_script = (
            'prefetch' in rel_vals
            and (
                _path_extension(href) in ('.js', '.mjs')
                or link_tag.get('as', '').lower() == 'script'
            )
        )
        if (is_preload_script or is_prefetch_script) and _is_external(href, page_url):
            if not is_known_good(href):
                preload_hrefs.append(href)
    if preload_hrefs:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'HTML',
            'title': f'External script preloaded from unknown domain ({len(preload_hrefs)} found)',
            'description': (
                'Page uses <link rel="preload" as="script"> or <link rel="prefetch"> to load '
                'JavaScript from an external domain not in the known-good list. '
                'This is a common WordPress malware injection pattern: attackers add preload '
                'hints for their malicious CDN to stage payloads before execution, and the hints '
                'persist in the HTML even when the corresponding <script> tag is rendered dynamically.'
            ),
            'evidence': '\n'.join(
                f'<link rel="preload" as="script" href="{h}">' for h in preload_hrefs[:5]
            ),
        })

    # ------------------------------------------------------------------
    # 18. External script from unknown domain (staged WordPress injection)
    # ------------------------------------------------------------------
    # Finds <script src="..."> tags loading from external domains not in the
    # known-good list.  When the same domain also appears in a
    # <link rel="dns-prefetch"> in the same page, the severity is HIGH —
    # the attacker pre-staged the connection, reducing latency for the
    # payload.  This is the exact pattern used in the cloudretouch.com
    # compromise: pacificbirdstudies.com was both dns-prefetched AND used
    # as the script src, with the tag disguised as bootstrap.bundle.min.js.
    #
    # Distinct from the SRI check (LOW for all missing SRI) — this check
    # specifically flags unknown external origins at a useful severity.

    dns_prefetch_domains: set[str] = set()
    for _link_tag in soup.find_all('link', rel=True):
        _rel = _link_tag.get('rel', [])
        if isinstance(_rel, str):
            _rel = [_rel]
        if 'dns-prefetch' in [r.lower() for r in _rel]:
            _href = _link_tag.get('href', '').strip()
            # dns-prefetch hrefs are usually protocol-relative (//domain.com)
            _href_norm = _href.lstrip('/')
            if _href_norm:
                if not _href_norm.startswith('http'):
                    _href_norm = 'https://' + _href_norm
                _dom = _registrable_domain(_href_norm)
                if _dom:
                    dns_prefetch_domains.add(_dom)

    injected_unknown_scripts: list[tuple[str, str]] = []  # (src_url, registrable_domain)
    for _tag in soup.find_all('script', src=True):
        _src = _tag.get('src', '')
        if not _src.startswith('http'):
            continue
        if not _is_external(_src, page_url):
            continue
        if is_known_good(_src):
            continue
        _src_dom = _registrable_domain(_src)
        if not _tag.get('integrity'):  # SRI check already fires LOW — only add this when no SRI
            injected_unknown_scripts.append((_src, _src_dom))

    if injected_unknown_scripts:
        pre_staged = [(u, d) for u, d in injected_unknown_scripts if d in dns_prefetch_domains]
        not_staged = [(u, d) for u, d in injected_unknown_scripts if d not in dns_prefetch_domains]

        if pre_staged:
            findings.append({
                'severity': 'HIGH',
                'category': 'HTML',
                'title': f'External script injection from unknown domain — DNS pre-staged ({len(pre_staged)} found)',
                'description': (
                    'Script(s) are loaded from external domains not in the known-good list, '
                    'and the same domain(s) are pre-staged via <link rel="dns-prefetch">. '
                    'Deliberately pre-fetching a malicious domain reduces load latency and is '
                    'a deliberate preparation step — characteristic of automated WordPress '
                    'compromise tools (WPCode injections, malicious plugin backdoors). '
                    'The combination of dns-prefetch + unknown script src is a strong indicator '
                    'of an injected malicious payload.'
                ),
                'evidence': '\n'.join(
                    f'<script src="{u}">  [same domain in dns-prefetch: {d}]'
                    for u, d in pre_staged[:5]
                ),
            })

        if not_staged:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'HTML',
                'title': f'External script from unknown domain ({len(not_staged)} found)',
                'description': (
                    'Script(s) are loaded from external domains not in the known-good list. '
                    'Unlike CDN or analytics scripts, these domains have no recognised legitimate '
                    'purpose. May be a legitimate third-party integration or a maliciously '
                    'injected script — investigate the source domain.'
                ),
                'evidence': '\n'.join(
                    f'<script src="{u}">'
                    for u, d in not_staged[:5]
                ),
            })

    # ------------------------------------------------------------------
    # 19. Shell commands in HTML attributes / hidden elements (ClickFix payload storage)
    # ------------------------------------------------------------------
    findings.extend(_check_shell_commands_in_html(soup))

    # ------------------------------------------------------------------
    # 21. Crypto wallet brand impersonation (SEO poisoning / fake wallet sites)
    # ------------------------------------------------------------------
    # Phishing pages targeting crypto wallet users often don't have a
    # credential form on the landing page — they use SEO poisoning to
    # appear in search results for "<Brand> login / download" and then
    # funnel victims to malicious downloads or seed-phrase harvest pages.
    # Detect when the page *title* claims a wallet brand but the domain
    # is not the official one.  Title is the strongest signal: attackers
    # explicitly set it for CTR in search results.
    for _brand, _official_domains in _CRYPTO_WALLET_OFFICIAL_DOMAINS.items():
        if re.search(r'\b' + re.escape(_brand) + r'\b', page_title, re.IGNORECASE):
            if page_domain not in _official_domains:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Phishing',
                    'title': f'Crypto wallet brand impersonation — {_brand.capitalize()}',
                    'description': (
                        f'The page title claims to be associated with {_brand.capitalize()} '
                        f'(official domain(s): {", ".join(sorted(_official_domains))}), '
                        f'but the actual domain is "{page_domain}". '
                        'This pattern is characteristic of SEO-poisoning phishing campaigns '
                        'that target crypto wallet users searching for official download or '
                        'login pages. Victims are typically served malicious wallet software '
                        'or redirected to seed-phrase harvesting pages.'
                    ),
                    'evidence': (
                        f'Page title: {page_title}\n'
                        f'Page domain: {page_domain}\n'
                        f'Official domain(s): {", ".join(sorted(_official_domains))}'
                    ),
                })
                break  # one finding per page is sufficient

    # ------------------------------------------------------------------
    # 20. Fake CAPTCHA / ClickFix social engineering UI text
    # ------------------------------------------------------------------
    full_page_text = soup.get_text(separator=' ', strip=True)
    captcha_m = _CLICKFIX_CAPTCHA_RE.search(full_page_text)
    instruction_m = _CLICKFIX_INSTRUCTION_RE.search(full_page_text)
    if captcha_m and instruction_m:
        # Suppress if a legitimate CAPTCHA iframe is present (reCAPTCHA, hCaptcha, Turnstile)
        has_legit_captcha = any(
            any(
                s in (tag.get('src', '') + tag.get('data-src', '')).lower()
                for s in ('recaptcha', 'hcaptcha', 'turnstile', 'captcha.com')
            )
            for tag in soup.find_all('iframe')
        )
        if not has_legit_captcha:
            findings.append({
                'severity': 'HIGH',
                'category': 'HTML',
                'title': 'Fake CAPTCHA / ClickFix social engineering page',
                'description': (
                    'Page presents a fake human-verification prompt combined with instructions to '
                    'execute system commands (Win+R, paste into terminal, etc.). '
                    'This is the ClickFix technique: a malicious command is written to the clipboard '
                    'and the user is instructed to run it, bypassing all browser security controls. '
                    'One of the most active initial-access techniques in 2024–2025 campaigns.'
                ),
                'evidence': (
                    f'[Fake verification text]\n{captcha_m.group(0)}\n\n'
                    f'[Execution instruction]\n{instruction_m.group(0)}'
                ),
            })

    return findings
