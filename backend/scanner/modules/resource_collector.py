"""
Parse fetched HTML and return all embedded resources.
"""
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup


def _get_registrable_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain


def collect_resources(html: str, base_url: str) -> dict:
    """
    Returns a dict containing all resources embedded in the HTML page.

    Keys:
        scripts        – list of {'url': str, 'inline': bool, 'content': str}
        stylesheets    – list of {'url': str, 'inline': bool, 'content': str}
        iframes        – list of {'url': str, 'attrs': dict}
        forms          – list of {'action': str, 'method': str, 'inputs': list}
        links          – list of str  (all href values)
        images         – list of str
        external_domains – list of unique external domains
        meta_refresh   – list of {'delay': int, 'url': str}
        base_href      – str or None
    """
    soup = BeautifulSoup(html, 'lxml')

    # Determine effective base URL (may be overridden by <base href>)
    base_tag = soup.find('base', href=True)
    base_href: str | None = None
    if base_tag:
        base_href = base_tag.get('href', '').strip()
        if base_href:
            effective_base = urljoin(base_url, base_href)
        else:
            effective_base = base_url
    else:
        effective_base = base_url

    page_domain = _get_registrable_domain(base_url)
    external_domains: set[str] = set()

    def resolve(href: str) -> str:
        if not href:
            return ''
        return urljoin(effective_base, href.strip())

    def is_external(url: str) -> bool:
        if not url:
            return False
        dom = _get_registrable_domain(url)
        return bool(dom) and dom != page_domain

    # --- Scripts ---
    scripts: list[dict] = []
    for tag in soup.find_all('script'):
        src = tag.get('src', '').strip()
        if src:
            resolved = resolve(src)
            scripts.append({'url': resolved, 'inline': False, 'content': ''})
            if is_external(resolved):
                external_domains.add(_get_registrable_domain(resolved))
        else:
            content = tag.get_text() or ''
            scripts.append({'url': base_url, 'inline': True, 'content': content})

    # --- Stylesheets ---
    stylesheets: list[dict] = []
    for tag in soup.find_all('link', rel=lambda r: r and 'stylesheet' in r):
        href = tag.get('href', '').strip()
        if href:
            resolved = resolve(href)
            stylesheets.append({'url': resolved, 'inline': False, 'content': ''})
            if is_external(resolved):
                external_domains.add(_get_registrable_domain(resolved))
    for tag in soup.find_all('style'):
        content = tag.get_text() or ''
        stylesheets.append({'url': base_url, 'inline': True, 'content': content})

    # --- Iframes ---
    iframes: list[dict] = []
    for tag in soup.find_all('iframe'):
        src = tag.get('src', '').strip()
        resolved = resolve(src) if src else ''
        attrs = {k: v for k, v in tag.attrs.items() if k != 'src'}
        iframes.append({'url': resolved, 'attrs': attrs})
        if resolved and is_external(resolved):
            external_domains.add(_get_registrable_domain(resolved))

    # --- Forms ---
    forms: list[dict] = []
    for tag in soup.find_all('form'):
        action = tag.get('action', '').strip()
        resolved_action = resolve(action) if action else base_url
        method = tag.get('method', 'get').upper()
        inputs = []
        for inp in tag.find_all(['input', 'select', 'textarea']):
            inputs.append({
                'name': inp.get('name', ''),
                'type': inp.get('type', 'text'),
                'autocomplete': inp.get('autocomplete', ''),
            })
        forms.append({'action': resolved_action, 'method': method, 'inputs': inputs})

    # --- Links ---
    links: list[str] = []
    for tag in soup.find_all('a', href=True):
        href = tag.get('href', '').strip()
        if href and not href.startswith(('mailto:', 'tel:', 'javascript:', 'data:')):
            resolved = resolve(href)
            links.append(resolved)
            if is_external(resolved):
                external_domains.add(_get_registrable_domain(resolved))

    # --- Images ---
    images: list[str] = []
    for tag in soup.find_all('img', src=True):
        src = tag.get('src', '').strip()
        if src:
            images.append(resolve(src))

    # --- Meta refresh ---
    meta_refresh: list[dict] = []
    for tag in soup.find_all('meta', attrs={'http-equiv': lambda v: v and v.lower() == 'refresh'}):
        content = tag.get('content', '')
        if content:
            parts = content.split(';', 1)
            try:
                delay = int(parts[0].strip())
            except ValueError:
                delay = 0
            refresh_url = ''
            if len(parts) > 1:
                url_part = parts[1].strip()
                if url_part.lower().startswith('url='):
                    refresh_url = resolve(url_part[4:].strip().strip("'\""))
                else:
                    refresh_url = resolve(url_part.strip().strip("'\""))
            meta_refresh.append({'delay': delay, 'url': refresh_url})

    return {
        'scripts': scripts,
        'stylesheets': stylesheets,
        'iframes': iframes,
        'forms': forms,
        'links': links,
        'images': images,
        'external_domains': sorted(external_domains),
        'meta_refresh': meta_refresh,
        'base_href': base_href,
    }
