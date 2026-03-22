"""
Technology detection module.

Analyses HTML content, HTTP response headers, cookies, and resource URLs to
identify the technology stack of a scanned page.

Returns a list of detected technologies:
    [{'name': str, 'category': str, 'version': str|None, 'confidence': str}, ...]

confidence: 'high'   — definitive signal (meta generator tag, version-specific attribute)
            'medium' — strong indicator (file name pattern, cookie name, URL fragment)

No external API calls are made. Detection is entirely content-based.
"""
import logging
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cookies_from_headers(headers: dict) -> dict[str, str]:
    """
    Parse Set-Cookie header(s) into a name→value map (lowercase names).

    requests combines multiple Set-Cookie values with ', ' into one header string,
    which is ambiguous (commas also appear in Expires= values).  We split on ';'
    first to isolate each cookie directive, then pick up name=value pairs at the
    start of each directive.
    """
    cookies: dict[str, str] = {}
    raw = headers.get('Set-Cookie', '')
    if not raw:
        return cookies
    # Each cookie directive ends at a semicolon; directives are separated by ', '
    # Split on ';' to get individual directives, then parse the first token of each.
    for directive in raw.split(';'):
        kv = directive.strip().split(',')[-1].strip()  # handle 'Expires=..., NextCookieName=...'
        if '=' in kv:
            name, _, value = kv.partition('=')
            name = name.strip().lower()
            if name and not name.startswith('expires') and not name.startswith('path') \
                    and not name.startswith('domain') and not name.startswith('max-age') \
                    and not name.startswith('samesite') and not name.startswith('secure') \
                    and not name.startswith('httponly'):
                cookies[name] = value.strip()
    return cookies


def _version_from_url(url: str, patterns: list[str]) -> str | None:
    """Try to extract a version string from a URL using regex patterns."""
    for pat in patterns:
        m = re.search(pat, url, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _any_url_matches(urls: list[str], patterns: list[str]) -> tuple[bool, str | None]:
    """Return (matched, version_or_None) if any URL matches any pattern."""
    for url in urls:
        for pat in patterns:
            m = re.search(pat, url, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else None
                return True, version
    return False, None


def _seen(results: list[dict], name: str) -> bool:
    return any(r['name'] == name for r in results)


def _add(results: list[dict], name: str, category: str,
         version: str | None = None, confidence: str = 'medium') -> None:
    if not _seen(results, name):
        entry: dict = {'name': name, 'category': category, 'confidence': confidence}
        if version:
            entry['version'] = version
        results.append(entry)


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_technologies(
    html: str,
    headers: dict,
    resources: dict,
) -> list[dict]:
    """
    Detect technologies used by a page from its HTML, headers, and resources.

    Parameters
    ----------
    html      : decoded page HTML
    headers   : HTTP response headers dict
    resources : output of resource_collector.collect_resources()
    """
    results: list[dict] = []

    try:
        soup = BeautifulSoup(html, 'lxml')
    except Exception:
        soup = BeautifulSoup(html, 'html.parser')

    # Pre-extract common sources for fast pattern matching
    script_srcs: list[str] = [
        s.get('url', '') for s in resources.get('scripts', [])
        if not s.get('inline') and s.get('url')
    ]
    stylesheet_hrefs: list[str] = [
        s.get('url', '') for s in resources.get('stylesheets', [])
        if not s.get('inline') and s.get('url')
    ]
    # Inline script/style content concatenated for pattern matching
    inline_js = '\n'.join(
        s.get('content', '') for s in resources.get('scripts', [])
        if s.get('inline') and s.get('content')
    )
    inline_css = '\n'.join(
        s.get('content', '') for s in resources.get('stylesheets', [])
        if s.get('inline') and s.get('content')
    )
    all_resource_urls = script_srcs + stylesheet_hrefs
    cookies = _cookies_from_headers(headers)
    server_header = headers.get('Server', '').lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    html_lower = html.lower()
    inline_js_lower = inline_js.lower()

    # -----------------------------------------------------------------------
    # Build tool / bundler
    # -----------------------------------------------------------------------
    _detect_build_tools(results, soup, html_lower, script_srcs, inline_js_lower)

    # -----------------------------------------------------------------------
    # CMS
    # -----------------------------------------------------------------------
    _detect_cms(results, soup, html_lower, script_srcs, stylesheet_hrefs, cookies)

    # -----------------------------------------------------------------------
    # JavaScript frameworks
    # -----------------------------------------------------------------------
    _detect_js_frameworks(results, soup, html_lower, script_srcs, inline_js_lower)

    # -----------------------------------------------------------------------
    # JavaScript libraries
    # -----------------------------------------------------------------------
    _detect_js_libraries(results, soup, html_lower, script_srcs, inline_js_lower)

    # -----------------------------------------------------------------------
    # CSS frameworks
    # -----------------------------------------------------------------------
    _detect_css_frameworks(results, soup, html_lower, stylesheet_hrefs, script_srcs, inline_css)

    # -----------------------------------------------------------------------
    # Analytics & tracking
    # -----------------------------------------------------------------------
    _detect_analytics(results, html_lower, script_srcs)

    # -----------------------------------------------------------------------
    # Backend / runtime (from cookies, headers, URL patterns)
    # -----------------------------------------------------------------------
    _detect_backend(results, headers, cookies, powered_by)

    # -----------------------------------------------------------------------
    # Web server
    # -----------------------------------------------------------------------
    _detect_server(results, server_header, headers)

    # -----------------------------------------------------------------------
    # CDN / delivery
    # -----------------------------------------------------------------------
    _detect_cdn(results, headers, all_resource_urls)

    # -----------------------------------------------------------------------
    # Security / bot-protection tools
    # -----------------------------------------------------------------------
    _detect_security(results, html_lower, script_srcs)

    # -----------------------------------------------------------------------
    # Payment processors
    # -----------------------------------------------------------------------
    _detect_payment(results, html_lower, script_srcs)

    logger.debug('tech_detector: detected %d technologies', len(results))
    return results


# ---------------------------------------------------------------------------
# CMS detection
# ---------------------------------------------------------------------------

def _detect_cms(
    results: list[dict],
    soup: BeautifulSoup,
    html_lower: str,
    script_srcs: list[str],
    stylesheet_hrefs: list[str],
    cookies: dict,
) -> None:
    # Meta generator tag — highest confidence for all CMS
    generator = ''
    gen_tag = soup.find('meta', attrs={'name': re.compile(r'^generator$', re.I)})
    if gen_tag and gen_tag.get('content'):
        generator = str(gen_tag['content'])

    # WordPress
    wp_version = None
    if re.search(r'wordpress', generator, re.I):
        m = re.search(r'WordPress\s+([\d.]+)', generator, re.I)
        wp_version = m.group(1) if m else None
        _add(results, 'WordPress', 'CMS', version=wp_version, confidence='high')
    elif (
        re.search(r'/wp-content/', html_lower)
        or re.search(r'/wp-includes/', html_lower)
        or any('/wp-content/' in u or '/wp-includes/' in u for u in script_srcs + stylesheet_hrefs)
        or any(k.startswith('wordpress_') or k.startswith('wp_') for k in cookies)
    ):
        _add(results, 'WordPress', 'CMS', confidence='high')

    # Drupal
    if re.search(r'drupal', generator, re.I):
        _add(results, 'Drupal', 'CMS', confidence='high')
    elif (
        re.search(r'drupal', html_lower)
        and (
            re.search(r'/sites/default/files/', html_lower)
            or re.search(r'Drupal\.settings', html_lower)
            or 'drupal' in ' '.join(cookies.keys())
        )
    ):
        _add(results, 'Drupal', 'CMS', confidence='medium')

    # Joomla
    if re.search(r'joomla', generator, re.I):
        _add(results, 'Joomla', 'CMS', confidence='high')
    elif (
        re.search(r'/media/jui/', html_lower)
        or re.search(r'/components/com_', html_lower)
        or 'joomla' in ' '.join(cookies.keys())
    ):
        _add(results, 'Joomla', 'CMS', confidence='medium')

    # Ghost
    if re.search(r'ghost', generator, re.I):
        _add(results, 'Ghost', 'CMS', confidence='high')
    elif re.search(r'ghost\.min\.js', html_lower) or re.search(r'/ghost/api/', html_lower):
        _add(results, 'Ghost', 'CMS', confidence='medium')

    # Shopify
    if (
        any('cdn.shopify.com' in u for u in script_srcs + stylesheet_hrefs)
        or re.search(r'Shopify\.shop', html_lower)
        or re.search(r'shopify\.js', html_lower)
    ):
        _add(results, 'Shopify', 'CMS', confidence='high')

    # Wix
    if any('wixstatic.com' in u for u in script_srcs + stylesheet_hrefs):
        _add(results, 'Wix', 'CMS', confidence='high')

    # Squarespace
    if any('squarespace.com' in u for u in script_srcs + stylesheet_hrefs):
        _add(results, 'Squarespace', 'CMS', confidence='high')

    # Webflow
    if (
        any('webflow.com' in u for u in script_srcs + stylesheet_hrefs)
        or re.search(r'Webflow\.require', html_lower)
    ):
        _add(results, 'Webflow', 'CMS', confidence='high')

    # HubSpot CMS
    if re.search(r'hs-scripts\.com|hubspot\.com/hs/(?:hsstatic|analytics)', html_lower):
        _add(results, 'HubSpot CMS', 'CMS', confidence='medium')


# ---------------------------------------------------------------------------
# Build tool / bundler detection
# ---------------------------------------------------------------------------

def _detect_build_tools(
    results: list[dict],
    soup: BeautifulSoup,
    html_lower: str,
    script_srcs: list[str],
    inline_js_lower: str,
) -> None:
    # Vite: injects /@vite/ paths, vite.svg placeholder, or modulepreload links
    if (
        any('/@vite/' in u for u in script_srcs)
        or re.search(r'/@vite/', html_lower)
        or re.search(r'/vite\.svg', html_lower)
        or soup.find('link', rel=lambda r: r and 'modulepreload' in r)
        or re.search(r'__vite__', html_lower)
        or re.search(r'vite/client', html_lower)
    ):
        _add(results, 'Vite', 'Build Tool', confidence='high')

    # webpack: often leaves __webpack_require__ in inline chunks
    if re.search(r'__webpack_require__', inline_js_lower) or re.search(r'webpackChunk', inline_js_lower):
        _add(results, 'webpack', 'Build Tool', confidence='high')

    # Parcel
    if re.search(r'parcelRequire', inline_js_lower):
        _add(results, 'Parcel', 'Build Tool', confidence='high')


# ---------------------------------------------------------------------------
# JS framework detection
# ---------------------------------------------------------------------------

def _detect_js_frameworks(
    results: list[dict],
    soup: BeautifulSoup,
    html_lower: str,
    script_srcs: list[str],
    inline_js_lower: str = '',
) -> None:
    # Next.js (check before React — it implies React)
    if (
        re.search(r'__NEXT_DATA__', html_lower)
        or any('/_next/static/' in u for u in script_srcs)
    ):
        _add(results, 'Next.js', 'JS Framework', confidence='high')
        _add(results, 'React', 'JS Framework', confidence='high')
        return

    # Nuxt (check before Vue — it implies Vue)
    if (
        re.search(r'__NUXT__', html_lower)
        or any('/_nuxt/' in u for u in script_srcs)
    ):
        _add(results, 'Nuxt', 'JS Framework', confidence='high')
        _add(results, 'Vue', 'JS Framework', confidence='high')
        return

    # React — HTML attributes (older React), inline JS fingerprints (React 18+),
    # or URL-based (CDN / non-hashed builds)
    if (
        soup.find(attrs={'data-reactroot': True})
        or soup.find(attrs={'data-reactid': True})
        or re.search(r'__react_', html_lower)
        or re.search(r'_reactRootContainer', html_lower)
        or re.search(r'__reactFiber', html_lower)
        or re.search(r'__reactProps', html_lower)
    ):
        _add(results, 'React', 'JS Framework', confidence='high')
    elif (
        re.search(r'react\.createElement', inline_js_lower)
        or re.search(r'react\.createelement', inline_js_lower)
        or re.search(r'"react"', inline_js_lower)
        or re.search(r"'react'", inline_js_lower)
    ):
        _add(results, 'React', 'JS Framework', confidence='medium')
    else:
        matched, version = _any_url_matches(
            script_srcs,
            [r'react(?:\.development|\.production\.min)?\.js',
             r'react@([\d.]+)',
             r'/react/([\d.]+)/react']
        )
        if matched:
            _add(results, 'React', 'JS Framework', version=version, confidence='high')

    # Vue
    if soup.find(lambda tag: any(a.startswith('data-v-') for a in tag.attrs)):
        _add(results, 'Vue', 'JS Framework', confidence='high')
    elif (
        re.search(r'__vue_app__', html_lower)
        or re.search(r'__vue__', html_lower)
        or re.search(r'createapp\(', inline_js_lower)
    ):
        _add(results, 'Vue', 'JS Framework', confidence='high')
    elif re.search(r'"vue"', inline_js_lower) or re.search(r"'vue'", inline_js_lower):
        _add(results, 'Vue', 'JS Framework', confidence='medium')
    else:
        matched, version = _any_url_matches(
            script_srcs,
            [r'vue(?:\.min)?\.js',
             r'vue@([\d.]+)',
             r'vue\.runtime(?:\.min)?\.js']
        )
        if matched:
            _add(results, 'Vue', 'JS Framework', version=version, confidence='high')

    # Angular
    ng_version_tag = soup.find(attrs={'ng-version': True})
    if ng_version_tag:
        version = str(ng_version_tag.get('ng-version', '')) or None
        _add(results, 'Angular', 'JS Framework', version=version, confidence='high')
    elif soup.find(attrs={'ng-app': True}) or re.search(r'ng-app=', html_lower):
        _add(results, 'Angular', 'JS Framework', confidence='high')
    elif re.search(r'platformbrowserdynamic', inline_js_lower) or re.search(r'@angular', inline_js_lower):
        _add(results, 'Angular', 'JS Framework', confidence='medium')
    else:
        matched, version = _any_url_matches(
            script_srcs,
            [r'angular(?:\.min)?\.js',
             r'@angular/core@([\d.]+)',
             r'angular@([\d.]+)']
        )
        if matched:
            _add(results, 'Angular', 'JS Framework', version=version, confidence='high')

    # Svelte
    if (
        re.search(r'__svelte', html_lower)
        or re.search(r'svelte-', html_lower)
        or re.search(r'"svelte"', inline_js_lower)
    ):
        _add(results, 'Svelte', 'JS Framework', confidence='high')
    else:
        matched, version = _any_url_matches(script_srcs, [r'svelte@([\d.]+)', r'svelte\.js'])
        if matched:
            _add(results, 'Svelte', 'JS Framework', version=version, confidence='high')

    # Ember
    if (
        re.search(r'Ember\.VERSION', html_lower)
        or soup.find(attrs={'data-ember-extension': True})
        or re.search(r'"ember"', inline_js_lower)
    ):
        _add(results, 'Ember', 'JS Framework', confidence='high')
    else:
        matched, version = _any_url_matches(script_srcs, [r'ember(?:\.min)?\.js', r'ember@([\d.]+)'])
        if matched:
            _add(results, 'Ember', 'JS Framework', version=version, confidence='high')

    # Backbone
    matched, version = _any_url_matches(script_srcs, [r'backbone(?:\.min)?\.js', r'backbone@([\d.]+)'])
    if matched:
        _add(results, 'Backbone.js', 'JS Framework', version=version, confidence='high')
    elif re.search(r'Backbone\.VERSION', html_lower) or re.search(r'"backbone"', inline_js_lower):
        _add(results, 'Backbone.js', 'JS Framework', confidence='high')

    # SvelteKit
    if (
        re.search(r'__sveltekit_', html_lower)
        or any('/_app/immutable/' in u for u in script_srcs)
        or re.search(r'sveltekit', html_lower)
    ):
        _add(results, 'SvelteKit', 'JS Framework', confidence='high')
        _add(results, 'Svelte', 'JS Framework', confidence='high')

    # Astro
    if (
        soup.find('astro-island')
        or re.search(r'astro-island', html_lower)
        or any('/_astro/' in u for u in script_srcs)
        or re.search(r'data-astro-', html_lower)
    ):
        _add(results, 'Astro', 'JS Framework', confidence='high')

    # Remix
    if (
        re.search(r'__remix(?:Context|Manifest|RouteModules)', html_lower)
        or re.search(r'window\.__remixContext', html_lower)
    ):
        _add(results, 'Remix', 'JS Framework', confidence='high')
        _add(results, 'React', 'JS Framework', confidence='high')

    # Gatsby
    if (
        re.search(r'___gatsby', html_lower)
        or re.search(r'gatsby-image', html_lower)
        or re.search(r'gatsby-chunk-mapper', html_lower)
        or any('/gatsby-chunk-' in u or 'gatsby' in u for u in script_srcs)
    ):
        _add(results, 'Gatsby', 'JS Framework', confidence='high')
        _add(results, 'React', 'JS Framework', confidence='high')

    # Solid.js
    if (
        re.search(r'solid-js', html_lower)
        or any('solid-js' in u for u in script_srcs)
        or re.search(r'"solid-js"', inline_js_lower)
    ):
        _add(results, 'Solid.js', 'JS Framework', confidence='high')


# ---------------------------------------------------------------------------
# JS library detection
# ---------------------------------------------------------------------------

def _detect_js_libraries(
    results: list[dict],
    soup: BeautifulSoup,
    html_lower: str,
    script_srcs: list[str],
    inline_js_lower: str = '',
) -> None:
    # jQuery — version often in filename
    matched, version = _any_url_matches(
        script_srcs,
        [r'jquery[.-]([\d.]+)(?:\.min)?\.js',
         r'jquery@([\d.]+)',
         r'/jquery/([\d.]+)/jquery',
         r'jquery(?:\.min)?\.js']
    )
    if matched:
        _add(results, 'jQuery', 'JS Library', version=version, confidence='high')
    elif (
        re.search(r'window\.jQuery|window\.\$\s*=|jQuery\.fn\.jquery', html_lower)
        or re.search(r'"jquery"', inline_js_lower)
        or re.search(r"'jquery'", inline_js_lower)
    ):
        _add(results, 'jQuery', 'JS Library', confidence='medium')

    # Lodash
    matched, version = _any_url_matches(
        script_srcs,
        [r'lodash(?:\.min)?\.js', r'lodash@([\d.]+)', r'/lodash/([\d.]+)/lodash']
    )
    if matched:
        _add(results, 'Lodash', 'JS Library', version=version, confidence='high')

    # Axios
    matched, version = _any_url_matches(
        script_srcs,
        [r'axios(?:\.min)?\.js', r'axios@([\d.]+)', r'/axios/([\d.]+)/axios']
    )
    if matched:
        _add(results, 'Axios', 'JS Library', version=version, confidence='high')

    # moment.js
    matched, version = _any_url_matches(
        script_srcs,
        [r'moment(?:\.min)?\.js', r'moment@([\d.]+)', r'/moment/([\d.]+)/moment']
    )
    if matched:
        _add(results, 'Moment.js', 'JS Library', version=version, confidence='high')

    # GSAP
    matched, version = _any_url_matches(
        script_srcs, [r'gsap(?:\.min)?\.js', r'gsap@([\d.]+)', r'TweenMax(?:\.min)?\.js']
    )
    if matched:
        _add(results, 'GSAP', 'JS Library', version=version, confidence='high')

    # Three.js
    matched, version = _any_url_matches(
        script_srcs, [r'three(?:\.min)?\.js', r'three@([\d.]+)', r'/three\.js/']
    )
    if matched:
        _add(results, 'Three.js', 'JS Library', version=version, confidence='high')

    # Alpine.js
    matched, version = _any_url_matches(
        script_srcs, [r'alpine(?:\.min)?\.js', r'alpinejs@([\d.]+)']
    )
    if matched:
        _add(results, 'Alpine.js', 'JS Library', version=version, confidence='high')
    elif soup.find(attrs={'x-data': True}) or soup.find(attrs={'x-bind': True}):
        _add(results, 'Alpine.js', 'JS Library', confidence='high')

    # htmx
    matched, version = _any_url_matches(
        script_srcs, [r'htmx(?:\.min)?\.js', r'htmx@([\d.]+)']
    )
    if matched:
        _add(results, 'htmx', 'JS Library', version=version, confidence='high')
    elif soup.find(attrs={'hx-get': True}) or soup.find(attrs={'hx-post': True}):
        _add(results, 'htmx', 'JS Library', confidence='high')

    # Socket.io
    matched, version = _any_url_matches(
        script_srcs, [r'socket\.io(?:\.min)?\.js', r'socket\.io@([\d.]+)']
    )
    if matched:
        _add(results, 'Socket.io', 'JS Library', version=version, confidence='high')
    elif any('socket.io' in u for u in script_srcs) or re.search(r'io\.connect\(|io\.socket', html_lower):
        _add(results, 'Socket.io', 'JS Library', confidence='medium')

    # Chart.js
    matched, version = _any_url_matches(
        script_srcs, [r'chart(?:\.min)?\.js', r'chart@([\d.]+)', r'chart\.js/([\d.]+)']
    )
    if matched:
        _add(results, 'Chart.js', 'JS Library', version=version, confidence='high')

    # D3.js
    matched, version = _any_url_matches(
        script_srcs, [r'd3(?:\.min)?\.js', r'd3@([\d.]+)', r'd3\.v([\d]+)(?:\.min)?\.js']
    )
    if matched:
        _add(results, 'D3.js', 'JS Library', version=version, confidence='high')

    # Swiper
    matched, version = _any_url_matches(
        script_srcs, [r'swiper(?:\.min)?\.js', r'swiper@([\d.]+)']
    )
    if matched:
        _add(results, 'Swiper', 'JS Library', version=version, confidence='high')
    elif soup.find(class_=re.compile(r'^swiper', re.I)):
        _add(results, 'Swiper', 'JS Library', confidence='medium')

    # Pusher
    matched, version = _any_url_matches(
        script_srcs, [r'pusher(?:\.min)?\.js', r'pusher@([\d.]+)', r'js\.pusher\.com/([\d.]+)/']
    )
    if matched:
        _add(results, 'Pusher', 'JS Library', version=version, confidence='high')


# ---------------------------------------------------------------------------
# CSS framework detection
# ---------------------------------------------------------------------------

def _detect_css_frameworks(
    results: list[dict],
    soup: BeautifulSoup,
    html_lower: str,
    stylesheet_hrefs: list[str],
    script_srcs: list[str],
    inline_css: str = '',
) -> None:
    all_hrefs = stylesheet_hrefs + script_srcs
    inline_css_lower = inline_css.lower()

    # Bootstrap
    matched, version = _any_url_matches(
        all_hrefs,
        [r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)',
         r'bootstrap@([\d.]+)',
         r'/bootstrap/([\d.]+)/css/bootstrap',
         r'bootstrap(?:\.min)?\.css']
    )
    if matched:
        _add(results, 'Bootstrap', 'CSS Framework', version=version, confidence='high')

    # Tailwind CSS — only match on actual asset usage, not page body text
    # Tailwind v3+ injects /* ! tailwindcss vX.X.X */ comment in compiled CSS output
    tailwind_version = None
    m = re.search(r'tailwindcss\s+v([\d.]+)', inline_css_lower)
    if m:
        tailwind_version = m.group(1)
    if (
        any('tailwind' in u for u in all_hrefs)
        or re.search(r'cdn\.tailwindcss\.com', html_lower)
        or re.search(r'tailwindcss\s+v[\d.]+', inline_css_lower)
        or re.search(r'@layer\s+base', inline_css_lower)
        or re.search(r'@layer\s+utilities', inline_css_lower)
    ):
        _add(results, 'Tailwind CSS', 'CSS Framework', version=tailwind_version, confidence='high')

    # Foundation
    matched, _ = _any_url_matches(
        stylesheet_hrefs, [r'foundation(?:\.min)?\.css', r'foundation@[\d.]+']
    )
    if matched:
        _add(results, 'Foundation', 'CSS Framework', confidence='high')

    # Materialize
    matched, version = _any_url_matches(
        all_hrefs, [r'materialize(?:\.min)?\.(?:css|js)', r'materialize@([\d.]+)']
    )
    if matched:
        _add(results, 'Materialize', 'CSS Framework', version=version, confidence='high')

    # Bulma
    matched, version = _any_url_matches(
        stylesheet_hrefs, [r'bulma(?:\.min)?\.css', r'bulma@([\d.]+)']
    )
    if matched:
        _add(results, 'Bulma', 'CSS Framework', version=version, confidence='high')

    # Font Awesome
    if (
        any('font-awesome' in u or 'fontawesome' in u for u in all_hrefs)
        or re.search(r'<i\s[^>]*class="fa[sb]?\s', html_lower)
        or re.search(r'font-awesome', html_lower)
    ):
        matched, version = _any_url_matches(
            all_hrefs, [r'font-awesome@([\d.]+)', r'fontawesome@([\d.]+)',
                        r'font-awesome/([\d.]+)/', r'fontawesome/([\d.]+)/']
        )
        _add(results, 'Font Awesome', 'CSS Framework', version=version, confidence='high')

    # UIkit
    matched, version = _any_url_matches(
        all_hrefs, [r'uikit(?:\.min)?\.(?:css|js)', r'uikit@([\d.]+)']
    )
    if matched:
        _add(results, 'UIkit', 'CSS Framework', version=version, confidence='high')


# ---------------------------------------------------------------------------
# Analytics & tracking
# ---------------------------------------------------------------------------

def _detect_analytics(
    results: list[dict],
    html_lower: str,
    script_srcs: list[str],
) -> None:
    # Google Analytics / Tag Manager
    ga_src = any('google-analytics.com' in u or 'googletagmanager.com' in u for u in script_srcs)
    ga_inline = re.search(r'google-analytics\.com|googletagmanager\.com', html_lower)
    if ga_src or ga_inline:
        if re.search(r'googletagmanager\.com/gtm', html_lower) or any('gtm.js' in u for u in script_srcs):
            _add(results, 'Google Tag Manager', 'Analytics', confidence='high')
        else:
            _add(results, 'Google Analytics', 'Analytics', confidence='high')

    # Facebook Pixel
    if (
        any('connect.facebook.net' in u for u in script_srcs)
        or re.search(r'fbq\(', html_lower)
        or re.search(r'facebook-pixel', html_lower)
    ):
        _add(results, 'Facebook Pixel', 'Analytics', confidence='high')

    # Hotjar
    if any('hotjar.com' in u for u in script_srcs) or re.search(r'hotjar\.com', html_lower):
        _add(results, 'Hotjar', 'Analytics', confidence='high')

    # Segment
    if any('segment.com' in u for u in script_srcs) or re.search(r'analytics\.load\(', html_lower):
        _add(results, 'Segment', 'Analytics', confidence='high')

    # Intercom
    if any('intercom.io' in u for u in script_srcs) or re.search(r'intercomSettings', html_lower):
        _add(results, 'Intercom', 'Analytics', confidence='high')

    # Drift
    if any('drift.com' in u or 'driftt.com' in u for u in script_srcs):
        _add(results, 'Drift', 'Analytics', confidence='high')

    # Mixpanel
    if any('mixpanel.com' in u for u in script_srcs) or re.search(r'mixpanel\.init\(', html_lower):
        _add(results, 'Mixpanel', 'Analytics', confidence='high')

    # Heap
    if any('heap.io' in u for u in script_srcs) or re.search(r'heap\.load\(', html_lower):
        _add(results, 'Heap', 'Analytics', confidence='medium')

    # Cloudflare Web Analytics
    if any('cloudflareinsights.com' in u for u in script_srcs):
        _add(results, 'Cloudflare Web Analytics', 'Analytics', confidence='high')

    # Plausible
    if any('plausible.io' in u for u in script_srcs):
        _add(results, 'Plausible', 'Analytics', confidence='high')

    # Matomo / Piwik
    if (
        re.search(r'matomo\.js|piwik\.js', html_lower)
        or any('matomo.js' in u or 'piwik.js' in u for u in script_srcs)
    ):
        _add(results, 'Matomo', 'Analytics', confidence='high')

    # Microsoft Clarity
    if any('clarity.ms' in u for u in script_srcs) or re.search(r'clarity\.js|microsoft\.clarity', html_lower):
        _add(results, 'Microsoft Clarity', 'Analytics', confidence='high')

    # TikTok Pixel
    if (
        any('analytics.tiktok.com' in u for u in script_srcs)
        or re.search(r'ttq\.load\(|tiktok\s*pixel', html_lower)
    ):
        _add(results, 'TikTok Pixel', 'Analytics', confidence='high')

    # LinkedIn Insight Tag
    if any('snap.licdn.com' in u for u in script_srcs) or re.search(r'linkedin\.insight', html_lower):
        _add(results, 'LinkedIn Insight', 'Analytics', confidence='high')

    # Amplitude
    if any('amplitude.com' in u for u in script_srcs) or re.search(r'amplitude\.getInstance\(', html_lower):
        _add(results, 'Amplitude', 'Analytics', confidence='high')


# ---------------------------------------------------------------------------
# Backend / runtime detection
# ---------------------------------------------------------------------------

def _detect_backend(
    results: list[dict],
    headers: dict,
    cookies: dict,
    powered_by: str,
) -> None:
    # X-Powered-By header
    if 'php' in powered_by:
        m = re.search(r'php/([\d.]+)', powered_by)
        _add(results, 'PHP', 'Backend', version=m.group(1) if m else None, confidence='high')
    if 'express' in powered_by:
        _add(results, 'Express', 'Backend', confidence='high')
    if 'asp.net' in powered_by:
        _add(results, 'ASP.NET', 'Backend', confidence='high')
    if 'next.js' in powered_by:
        if not any(r['name'] == 'Next.js' for r in results):
            _add(results, 'Next.js', 'JS Framework', confidence='high')

    # Cookie-based inference
    if 'phpsessid' in cookies:
        _add(results, 'PHP', 'Backend', confidence='medium')
    if 'laravel_session' in cookies or 'xsrf-token' in cookies:
        _add(results, 'Laravel', 'Backend', confidence='high')
    if 'csrftoken' in cookies and 'sessionid' in cookies:
        _add(results, 'Django', 'Backend', confidence='high')
    if '_rails_session' in cookies:
        _add(results, 'Ruby on Rails', 'Backend', confidence='high')
    if 'asp.net_sessionid' in cookies:
        _add(results, 'ASP.NET', 'Backend', confidence='high')
    if 'jsessionid' in cookies:
        _add(results, 'Java', 'Backend', confidence='medium')

    # Django REST Framework adds this header
    if headers.get('Allow') and 'application/json' in headers.get('Content-Type', ''):
        pass  # too generic to infer

    # Node.js — implied by Express or Koa X-Powered-By, or explicit header
    if 'node.js' in powered_by or 'nodejs' in powered_by:
        _add(results, 'Node.js', 'Backend', confidence='high')

    # Flask / Werkzeug
    if 'werkzeug' in str(headers.get('Server', '')).lower():
        _add(results, 'Flask', 'Backend', confidence='high')
        _add(results, 'Python', 'Backend', confidence='high')

    # FastAPI / Starlette (uvicorn server)
    if 'uvicorn' in str(headers.get('Server', '')).lower():
        _add(results, 'FastAPI', 'Backend', confidence='medium')
        _add(results, 'Python', 'Backend', confidence='high')

    # Symfony
    if any(k.startswith('sf_') or k == 'symfony' for k in cookies):
        _add(results, 'Symfony', 'Backend', confidence='high')

    # Spring Boot — Spring Security session or X-Application-Context header
    if (
        headers.get('X-Application-Context')
        or (cookies.get('jsessionid') and 'spring' in str(headers).lower())
    ):
        _add(results, 'Spring Boot', 'Backend', confidence='medium')

    # Vercel
    if headers.get('x-vercel-id') or headers.get('x-vercel-cache'):
        _add(results, 'Vercel', 'Hosting', confidence='high')

    # Netlify
    if headers.get('x-nf-request-id') or headers.get('netlify-cdn-cache-control'):
        _add(results, 'Netlify', 'Hosting', confidence='high')

    # GitHub Pages — Server: GitHub.com or X-GitHub-Request-Id
    if (
        'github.com' in str(headers.get('Server', '')).lower()
        or headers.get('X-GitHub-Request-Id')
    ):
        _add(results, 'GitHub Pages', 'Hosting', confidence='high')

    # AWS
    if 'awselb' in str(headers.get('Server', '')).lower():
        _add(results, 'AWS Elastic Load Balancer', 'Hosting', confidence='high')

    # Firebase Hosting
    if (
        headers.get('x-firebase-appcheck')
        or 'firebase' in str(headers.get('Server', '')).lower()
    ):
        _add(results, 'Firebase', 'Hosting', confidence='high')

    # Render
    if headers.get('rndr-id') or headers.get('x-render-origin-server'):
        _add(results, 'Render', 'Hosting', confidence='high')


# ---------------------------------------------------------------------------
# Web server detection
# ---------------------------------------------------------------------------

def _detect_server(
    results: list[dict],
    server_header: str,
    headers: dict,
) -> None:
    if not server_header:
        return

    if 'nginx' in server_header:
        m = re.search(r'nginx/([\d.]+)', server_header)
        _add(results, 'nginx', 'Web Server', version=m.group(1) if m else None, confidence='high')
    elif 'apache' in server_header:
        m = re.search(r'apache/([\d.]+)', server_header)
        _add(results, 'Apache', 'Web Server', version=m.group(1) if m else None, confidence='high')
    elif 'microsoft-iis' in server_header:
        m = re.search(r'iis/([\d.]+)', server_header)
        _add(results, 'IIS', 'Web Server', version=m.group(1) if m else None, confidence='high')
    elif 'cloudflare' in server_header:
        _add(results, 'Cloudflare', 'CDN', confidence='high')
    elif 'openresty' in server_header:
        _add(results, 'OpenResty', 'Web Server', confidence='high')
    elif 'litespeed' in server_header:
        _add(results, 'LiteSpeed', 'Web Server', confidence='high')
    elif 'gunicorn' in server_header:
        _add(results, 'Gunicorn', 'Web Server', confidence='high')
    elif 'caddy' in server_header:
        _add(results, 'Caddy', 'Web Server', confidence='high')


# ---------------------------------------------------------------------------
# CDN / delivery network detection
# ---------------------------------------------------------------------------

def _detect_cdn(
    results: list[dict],
    headers: dict,
    resource_urls: list[str],
) -> None:
    # Cloudflare (header signals)
    if headers.get('CF-RAY') or headers.get('cf-cache-status'):
        _add(results, 'Cloudflare', 'CDN', confidence='high')

    # AWS CloudFront
    if 'cloudfront' in headers.get('X-Cache', '').lower() or headers.get('X-Amz-Cf-Id'):
        _add(results, 'AWS CloudFront', 'CDN', confidence='high')

    # Fastly — X-Fastly-Request-ID is the most reliable signal;
    # X-Served-By shows cache node names (e.g. cache-lcy-egml...) not the word "fastly"
    if (
        headers.get('X-Fastly-Request-ID')
        or headers.get('Fastly-Debug-Digest')
        or 'fastly' in str(headers.get('X-Served-By', '')).lower()
        or 'fastly' in str(headers.get('Via', '')).lower()
    ):
        _add(results, 'Fastly', 'CDN', confidence='high')

    # Akamai
    if headers.get('X-Check-Cacheable') or headers.get('X-Akamai-Transformed'):
        _add(results, 'Akamai', 'CDN', confidence='high')

    # jsDelivr
    if any('cdn.jsdelivr.net' in u for u in resource_urls):
        _add(results, 'jsDelivr', 'CDN', confidence='high')

    # cdnjs
    if any('cdnjs.cloudflare.com' in u for u in resource_urls):
        _add(results, 'cdnjs', 'CDN', confidence='high')

    # unpkg
    if any('unpkg.com' in u for u in resource_urls):
        _add(results, 'unpkg', 'CDN', confidence='high')

    # Google Hosted Libraries
    if any('ajax.googleapis.com' in u or 'fonts.googleapis.com' in u for u in resource_urls):
        _add(results, 'Google Hosted Libraries', 'CDN', confidence='high')


# ---------------------------------------------------------------------------
# Security / bot-protection tool detection
# ---------------------------------------------------------------------------

def _detect_security(
    results: list[dict],
    html_lower: str,
    script_srcs: list[str],
) -> None:
    # Cloudflare Turnstile
    if (
        any('challenges.cloudflare.com' in u for u in script_srcs)
        or re.search(r'cf-turnstile|turnstile\.render', html_lower)
    ):
        _add(results, 'Cloudflare Turnstile', 'Security', confidence='high')

    # Google reCAPTCHA
    if (
        any('google.com/recaptcha' in u or 'recaptcha.net' in u for u in script_srcs)
        or re.search(r'grecaptcha|data-sitekey', html_lower)
    ):
        _add(results, 'reCAPTCHA', 'Security', confidence='high')

    # hCaptcha
    if (
        any('hcaptcha.com' in u for u in script_srcs)
        or re.search(r'hcaptcha\.render|h-captcha', html_lower)
    ):
        _add(results, 'hCaptcha', 'Security', confidence='high')

    # Cloudflare Bot Management (inline challenge injection)
    if re.search(r'__CF\$cv\$params|cf-challenge', html_lower):
        _add(results, 'Cloudflare Bot Management', 'Security', confidence='high')


# ---------------------------------------------------------------------------
# Payment processor detection
# ---------------------------------------------------------------------------

def _detect_payment(
    results: list[dict],
    html_lower: str,
    script_srcs: list[str],
) -> None:
    # Stripe
    if (
        any('js.stripe.com' in u for u in script_srcs)
        or re.search(r'stripe\.elements\(|stripe\.confirmCard', html_lower)
    ):
        _add(results, 'Stripe', 'Payment', confidence='high')

    # PayPal
    if (
        any('paypal.com/sdk' in u or 'paypalobjects.com' in u for u in script_srcs)
        or re.search(r'paypal\.Buttons\(|paypal\.checkout', html_lower)
    ):
        _add(results, 'PayPal', 'Payment', confidence='high')

    # Square
    if any('squareup.com' in u or 'square.com/payments' in u for u in script_srcs):
        _add(results, 'Square', 'Payment', confidence='high')

    # Klarna
    if any('klarna.com' in u for u in script_srcs) or re.search(r'klarna\.load\(', html_lower):
        _add(results, 'Klarna', 'Payment', confidence='high')
