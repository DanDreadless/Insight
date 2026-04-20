"""
Domain-level threat intelligence module.
All detection is content/heuristic-based — no external threat intel APIs.
"""
import ipaddress
import math
import re
import unicodedata
from urllib.parse import urlparse

import tldextract

# ---------------------------------------------------------------------------
# Allowlist of well-known safe domains (SLD only)
# ---------------------------------------------------------------------------
_SAFE_DOMAINS = frozenset([
    'google', 'microsoft', 'amazon', 'facebook', 'twitter', 'github',
    'cloudflare', 'apple', 'netflix', 'youtube', 'instagram', 'linkedin',
    'yahoo', 'bing', 'wikipedia', 'reddit', 'stackoverflow', 'mozilla',
    'adobe', 'dropbox', 'paypal', 'ebay', 'zoom', 'slack', 'discord',
    'twitch', 'tiktok', 'snapchat', 'pinterest', 'tumblr', 'wordpress',
    'shopify', 'stripe', 'heroku', 'netlify', 'vercel', 'digitalocean',
    'linode', 'vultr', 'fastly', 'akamai', 'amazonaws', 'azure', 'gcp',
])

# ---------------------------------------------------------------------------
# High-risk TLDs
# ---------------------------------------------------------------------------
_HIGH_RISK_TLDS = frozenset([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'download',
    'loan', 'win', 'zip', 'mov', 'party', 'date', 'review', 'stream',
    'gdn', 'bid', 'trade', 'work', 'racing', 'cricket', 'science',
    'accountant', 'faith', 'men', 'webcam', 'country', 'cyou',
])

# ---------------------------------------------------------------------------
# Brand keywords for impersonation checks
# ---------------------------------------------------------------------------
_BRAND_NAMES = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
    'twitter', 'instagram', 'netflix', 'bank', 'chase', 'wellsfargo',
    'barclays', 'hsbc', 'lloyds', 'natwest', 'halifax', 'santander',
    'citibank', 'steam', 'ebay', 'linkedin', 'dropbox', 'icloud',
    'yahoo', 'outlook', 'coinbase', 'binance', 'blockchain',
    'metamask', 'bitmart', 'myetherwallet', 'kucoin', 'blockfi',
    'ledger', 'trezor', 'trustwallet', 'opensea', 'uniswap',
    'roblox', 'discord', 'twitch', 'spotify',
]

# Mapping: brand name → authoritative SLD
_BRAND_REAL_DOMAINS: dict[str, list[str]] = {
    'paypal': ['paypal'],
    'google': ['google', 'googleapis', 'gstatic', 'googleusercontent'],
    'apple': ['apple', 'icloud', 'mzstatic'],
    'microsoft': ['microsoft', 'live', 'hotmail', 'msn', 'azure', 'windows', 'office'],
    'amazon': ['amazon', 'amazonaws', 'amazon-adsystem'],
    'facebook': ['facebook', 'fb', 'fbcdn'],
    'twitter': ['twitter', 'twimg', 't'],
    'instagram': ['instagram'],
    'netflix': ['netflix', 'nflxso'],
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
    'outlook': ['outlook', 'live'],
    'metamask': ['metamask'],
    'bitmart': ['bitmart'],
    'myetherwallet': ['myetherwallet'],
    'kucoin': ['kucoin'],
    'blockfi': ['blockfi'],
    'ledger': ['ledger'],
    'trezor': ['trezor'],
    'trustwallet': ['trustwallet'],
    'opensea': ['opensea'],
    'uniswap': ['uniswap'],
    'roblox': ['roblox'],
    'discord': ['discord', 'discordapp'],
    'twitch': ['twitch', 'twitchapps'],
    'spotify': ['spotify'],
}

# ---------------------------------------------------------------------------
# Confusable Unicode characters (Cyrillic lookalikes)
# ---------------------------------------------------------------------------
_CONFUSABLE_CHARS = {
    '\u0430': 'a',   # Cyrillic а
    '\u043e': 'o',   # Cyrillic о
    '\u0435': 'e',   # Cyrillic е
    '\u0440': 'p',   # Cyrillic р
    '\u0441': 'c',   # Cyrillic с
    '\u0445': 'x',   # Cyrillic х
    '\u0456': 'i',   # Cyrillic і
    '\u0458': 'j',   # Cyrillic ј
    '\u0455': 's',   # Cyrillic ѕ
    '\u04cf': 'l',   # Cyrillic ӏ
}

# ---------------------------------------------------------------------------
# DGA heuristic helpers
# ---------------------------------------------------------------------------
_VOWELS = frozenset('aeiou')
_ENGLISH_SUBWORDS = frozenset([
    'the', 'and', 'ing', 'tion', 'ion', 'ent', 'for', 'ment', 'com', 'net',
    'org', 'info', 'site', 'web', 'app', 'data', 'api', 'auth', 'login',
    'mail', 'news', 'shop', 'store', 'pay', 'bank', 'account', 'secure',
    'update', 'verify', 'service', 'support', 'help', 'online', 'cloud',
])


# ---------------------------------------------------------------------------
# Free cloud-hosting platforms frequently abused for phishing kits
# ---------------------------------------------------------------------------
# Maps registrable domain → platform description.
# Only fires when the subdomain looks machine-generated (≥10 chars, not a
# human-chosen vanity name like "myblog.pages.dev").
_ABUSE_HOSTING_PLATFORMS: dict[str, str] = {
    'r2.dev':          'Cloudflare R2 object storage',
    'pages.dev':       'Cloudflare Pages',
    'web.app':         'Firebase Hosting',
    'firebaseapp.com': 'Firebase Hosting',
    'zapier.app':      'Zapier no-code automation',
    'glitch.me':       'Glitch live coding platform',
    'onrender.com':    'Render cloud platform',
    'repl.co':         'Replit online IDE',
}


# ---------------------------------------------------------------------------
# Levenshtein edit distance (for typosquat detection)
# ---------------------------------------------------------------------------
def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two short strings."""
    if abs(len(a) - len(b)) > 2:
        return 999  # quick reject — too different in length
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            curr = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + (0 if a[i - 1] == b[j - 1] else 1))
            prev = curr
    return dp[n]


def _dga_score(domain: str) -> float:
    """
    Heuristic DGA probability score 0.0-1.0.
    Higher = more likely algorithmically generated.
    """
    if not domain or domain.lower() in _SAFE_DOMAINS:
        return 0.0

    d = domain.lower()

    # Digit-heavy domains (e.g. "2398g9848394") are a strong DGA signal —
    # no legitimate registered domain is composed almost entirely of digits.
    digit_ratio_early = sum(1 for c in d if c.isdigit()) / max(len(d), 1)
    if digit_ratio_early >= 0.7 and len(d) >= 8:
        return 0.85

    # Length scoring
    length = len(d)
    if length < 5:
        return 0.0  # Too short to judge
    length_score = min(1.0, max(0.0, (length - 5) / 15))  # peaks at 20 chars

    # Consonant density
    vowel_count = sum(1 for c in d if c in _VOWELS)
    consonant_count = sum(1 for c in d if c.isalpha() and c not in _VOWELS)
    total_alpha = vowel_count + consonant_count
    if total_alpha == 0:
        consonant_ratio = 1.0
    else:
        consonant_ratio = consonant_count / total_alpha
    # Real words have ~60% consonants; DGA domains often 80%+
    consonant_score = max(0.0, (consonant_ratio - 0.6) / 0.4)

    # English subword presence (real domains usually contain recognisable fragments)
    has_subword = any(w in d for w in _ENGLISH_SUBWORDS)
    subword_penalty = 0.0 if has_subword else 0.3

    # Entropy
    entropy = _domain_entropy(d)
    # Real domains: 2.0-3.5 bits/char; DGA: 3.5-5.0
    entropy_score = max(0.0, (entropy - 3.0) / 2.0)

    # Numeric density
    digit_ratio = sum(1 for c in d if c.isdigit()) / max(len(d), 1)
    digit_score = min(1.0, digit_ratio * 3)

    score = (
        0.3 * consonant_score +
        0.25 * entropy_score +
        0.2 * length_score +
        0.15 * subword_penalty +
        0.1 * digit_score
    )
    return min(1.0, score)


def _domain_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((f / total) * math.log2(f / total) for f in freq.values())


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyse_domain(url: str, whois_data: dict | None = None) -> list[dict]:
    """
    Perform domain-level threat analysis on a URL.
    Returns list of finding dicts.
    """
    findings: list[dict] = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    ext = tldextract.extract(url)
    sld = ext.domain.lower()          # second-level domain
    tld = ext.suffix.lower()           # TLD (may be multi-part, e.g. co.uk)
    subdomain = ext.subdomain.lower()  # subdomain part

    if not sld:
        return findings

    # Bare IP addresses have no SLD/TLD in the domain sense — skip all
    # domain-heuristic checks (DGA, typosquat, brand, TLD risk) since they
    # would produce nonsensical results (e.g. digits scoring as high-consonant DGA).
    try:
        ipaddress.ip_address(hostname)
        return findings
    except ValueError:
        pass

    # ------------------------------------------------------------------
    # 1. High-risk TLD
    # ------------------------------------------------------------------
    tld_parts = tld.split('.')
    last_tld = tld_parts[-1] if tld_parts else ''
    if last_tld in _HIGH_RISK_TLDS:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'Domain',
            'title': f'High-risk TLD: .{last_tld}',
            'description': (
                f'The .{last_tld} TLD has disproportionately high rates of malicious registration. '
                'These TLDs are typically free or extremely cheap, lowering the barrier for threat '
                'actors who register large numbers of domains for phishing campaigns, malware C2, '
                'and spam infrastructure — then abandon them. '
                'This finding alone is not conclusive; it is most significant when combined with '
                'brand impersonation, external form actions, or malicious JavaScript signals.'
            ),
            'evidence': f'Domain: {sld}.{tld} | TLD: .{last_tld}',
        })

    # ------------------------------------------------------------------
    # 2. DGA probability
    # ------------------------------------------------------------------
    dga_score = _dga_score(sld)
    if dga_score > 0.6:
        d = sld.lower()
        vowel_count = sum(1 for c in d if c in _VOWELS)
        consonant_count = sum(1 for c in d if c.isalpha() and c not in _VOWELS)
        total_alpha = vowel_count + consonant_count
        consonant_ratio = consonant_count / total_alpha if total_alpha else 1.0
        has_subword = any(w in d for w in _ENGLISH_SUBWORDS)
        entropy = _domain_entropy(sld)
        evidence = (
            f'[Domain breakdown]\n'
            f'  Full hostname : {hostname}\n'
            f'  Registered SLD: {sld}.{tld}\n'
            f'\n[DGA score signals]\n'
            f'  Overall score    : {dga_score:.2f} / 1.00\n'
            f'  Length           : {len(sld)} chars\n'
            f'  Shannon entropy  : {entropy:.2f} bits/char  (real domains ~2.0–3.5; DGA ~3.5–5.0)\n'
            f'  Consonant ratio  : {consonant_ratio:.0%}  (real words ~60%; DGA often 80%+)\n'
            f'  English subwords : {"present" if has_subword else "none detected"}'
        )
        if dga_score > 0.8:
            findings.append({
                'severity': 'HIGH',
                'category': 'Domain',
                'title': f'Domain appears algorithmically generated (DGA score={dga_score:.2f})',
                'description': (
                    f'The second-level domain "{sld}" scores {dga_score:.2f}/1.0 on the DGA heuristic. '
                    'High consonant density, entropy, and lack of recognisable English subwords suggest '
                    'this domain was generated by a domain generation algorithm used by malware C2 infrastructure.'
                ),
                'evidence': evidence,
            })
        else:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Domain',
                'title': f'Domain may be algorithmically generated (DGA score={dga_score:.2f})',
                'description': (
                    f'The second-level domain "{sld}" scores {dga_score:.2f}/1.0 on the DGA heuristic. '
                    'Characteristics suggest possible algorithmic generation.'
                ),
                'evidence': evidence,
            })

    # ------------------------------------------------------------------
    # 3. Subdomain brand impersonation
    # ------------------------------------------------------------------
    if subdomain:
        subdomain_parts = subdomain.split('.')
        for brand in _BRAND_NAMES:
            if any(brand in part for part in subdomain_parts):
                legitimate_slds = _BRAND_REAL_DOMAINS.get(brand, [brand])
                if sld not in legitimate_slds:
                    legitimate_slds_str = ', '.join(f'{d}.{tld}' for d in legitimate_slds)
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'Domain',
                        'title': f'Brand impersonation via subdomain: "{brand}"',
                        'description': (
                            f'The hostname uses "{brand}" in the subdomain position '
                            f'on a non-brand registrable domain ("{sld}.{tld}"). '
                            'This is a well-established phishing technique: the brand name in the '
                            'leftmost part of the URL is what users scan when checking if a link '
                            'is legitimate. Attackers deliberately exploit this scanning pattern '
                            f'— a visitor glancing at "{hostname}" may perceive it as an official '
                            f'{brand} URL without reading the full domain. '
                            f'The legitimate {brand} service uses: {legitimate_slds_str}'
                        ),
                        'evidence': (
                            f'[Hostname decomposition]\n'
                            f'  Full hostname   : {hostname}\n'
                            f'  Subdomain       : {subdomain}  ← contains "{brand}"\n'
                            f'  Registered SLD  : {sld}.{tld}  ← NOT a legitimate {brand} domain\n'
                            f'  Legitimate domains for {brand}: {legitimate_slds_str}'
                        ),
                    })
                    break

    # ------------------------------------------------------------------
    # 4. Homograph / IDN detection
    # ------------------------------------------------------------------
    try:
        hostname_bytes = hostname.encode('utf-8')
    except Exception:
        hostname_bytes = b''

    confusable_found: list[str] = []
    for char in hostname:
        if char in _CONFUSABLE_CHARS:
            latin_equiv = _CONFUSABLE_CHARS[char]
            codepoint = f'U+{ord(char):04X}'
            name = unicodedata.name(char, 'UNKNOWN')
            confusable_found.append(f'{char!r} ({codepoint} {name}, looks like "{latin_equiv}")')

    # Also check for any non-ASCII in what looks like a Latin domain
    try:
        hostname.encode('ascii')
    except UnicodeEncodeError:
        if not confusable_found:
            confusable_found.append('non-ASCII characters detected in hostname')

    if confusable_found:
        findings.append({
            'severity': 'HIGH',
            'category': 'Domain',
            'title': 'Homograph / IDN domain attack detected',
            'description': (
                'The hostname contains Unicode characters that are visually identical or similar to '
                'ASCII characters. This is used to impersonate trusted domains in phishing attacks.'
            ),
            'evidence': (
                f'[Hostname as displayed]\n  {hostname}\n\n'
                f'[Confusable characters detected]\n'
                + '\n'.join(f'  {c}' for c in confusable_found)
            ),
        })

    # ------------------------------------------------------------------
    # 5. Brand keyword in registered domain (not subdomain)
    # Require the brand to be a standalone hyphen-delimited component of the
    # SLD (or the full SLD) to avoid compound-word false positives like
    # "snowbank" triggering the "bank" keyword.
    # ------------------------------------------------------------------
    sld_components = sld.split('-')
    for brand in _BRAND_NAMES:
        brand_present = brand == sld or brand in sld_components
        if brand_present and sld not in _SAFE_DOMAINS:
            legitimate_slds = _BRAND_REAL_DOMAINS.get(brand, [brand])
            if sld not in legitimate_slds:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Domain',
                    'title': f'Brand keyword "{brand}" in registered domain (not the real {brand})',
                    'description': (
                        f'The registered domain "{sld}.{tld}" contains "{brand}" but is not the '
                        f'legitimate {brand} service. Attackers register domains like '
                        f'"paypal-secure.com" or "microsoft-support.net" to pass cursory URL '
                        'inspection — victims see the brand name and assume it is legitimate. '
                        'This is distinct from subdomain impersonation: here the attacker owns '
                        'the registrable domain itself, making the impersonation more convincing '
                        'and more expensive (requiring domain registration rather than a free subdomain).'
                    ),
                    'evidence': f'Domain: {sld}.{tld} | Brand keyword: "{brand}" | This is not an official {brand} domain',
                })
                break  # One finding per domain is sufficient

    # ------------------------------------------------------------------
    # 6. Excessive subdomain depth
    # ------------------------------------------------------------------
    if subdomain:
        depth = len(subdomain.split('.'))
        if depth > 4:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Domain',
                'title': f'Excessive subdomain depth ({depth} levels)',
                'description': (
                    f'The hostname has {depth} subdomain levels. Unusually deep subdomains '
                    'are sometimes used to obscure the true registrable domain '
                    '(e.g., login.secure.update.microsoft.com.evil.xyz).'
                ),
                'evidence': f'Full hostname: {hostname}',
            })

    # ------------------------------------------------------------------
    # 7. Number substitution (l33t speak)
    # ------------------------------------------------------------------
    leet_pattern = re.compile(r'(?:g00gle|paypa1|micr0s0ft|f4cebook|4pple|app1e|tw1tter)', re.IGNORECASE)
    leet_match = leet_pattern.search(sld)
    if leet_match:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'Domain',
            'title': 'Digit substitution impersonating a brand',
            'description': (
                f'Domain "{sld}.{tld}" uses digit substitution (l33t-speak) to impersonate a '
                f'legitimate brand: "{leet_match.group(0)}" detected.'
            ),
            'evidence': f'Domain: {sld}.{tld} | Pattern: {leet_match.group(0)}',
        })

    # ------------------------------------------------------------------
    # 8. Typosquat detection — SLD within edit-distance 1 of a brand name
    # ------------------------------------------------------------------
    # Brands < 6 chars excluded to avoid false positives on short common words.
    # Only fires if no other brand finding was already emitted for this domain.
    already_has_brand_finding = any(
        'brand' in f.get('title', '').lower() or 'impersonat' in f.get('title', '').lower()
        for f in findings
    )
    if not already_has_brand_finding and sld not in _SAFE_DOMAINS:
        for brand in _BRAND_NAMES:
            if len(brand) < 6:
                continue
            legitimate_slds = _BRAND_REAL_DOMAINS.get(brand, [brand])
            if sld in legitimate_slds or sld == brand:
                continue
            if _levenshtein(sld, brand) == 1:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Domain',
                    'title': f'Typosquat of brand "{brand}" detected in registered domain',
                    'description': (
                        f'The registered domain "{sld}.{tld}" is a single edit away from the '
                        f'brand name "{brand}" (edit distance 1). Typosquatting is a common '
                        'phishing technique where attackers register near-identical domains.'
                    ),
                    'evidence': f'Registered domain: {sld}.{tld} | Near-match brand: {brand} | Edit distance: 1',
                })
                break  # One typosquat finding per domain is sufficient

    # Check subdomain tokens (split by . and -) for typosquats of brand names
    if subdomain and not already_has_brand_finding:
        tokens: set[str] = set()
        for part in subdomain.split('.'):
            tokens.add(part)
            for word in part.split('-'):
                if len(word) >= 5:
                    tokens.add(word)
        for token in tokens:
            matched_typosquat = False
            for brand in _BRAND_NAMES:
                if len(brand) < 6:
                    continue
                if brand in token:  # exact substring — already handled by check 3
                    continue
                legitimate_slds = _BRAND_REAL_DOMAINS.get(brand, [brand])
                if sld in legitimate_slds:
                    continue
                if _levenshtein(token, brand) == 1:
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'Domain',
                        'title': f'Typosquat of brand "{brand}" in subdomain',
                        'description': (
                            f'Subdomain token "{token}" is a single edit away from the brand '
                            f'name "{brand}" (edit distance 1) on non-brand domain "{sld}.{tld}". '
                            'Attackers use near-identical brand names in subdomains to deceive users.'
                        ),
                        'evidence': (
                            f'[Hostname decomposition]\n'
                            f'  Full hostname  : {hostname}\n'
                            f'  Subdomain token: {token}  ← 1 edit away from "{brand}"\n'
                            f'  Registered SLD : {sld}.{tld}  ← NOT a legitimate {brand} domain'
                        ),
                    })
                    matched_typosquat = True
                    break
            if matched_typosquat:
                break  # One typosquat finding per subdomain is sufficient

    # ------------------------------------------------------------------
    # 9. Free cloud hosting platform used as phishing staging
    # ------------------------------------------------------------------
    registrable = f'{sld}.{tld}'
    platform = _ABUSE_HOSTING_PLATFORMS.get(registrable)
    if platform and subdomain and len(subdomain.replace('-', '').replace('.', '')) >= 10:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'Domain',
            'title': f'Page hosted on abuse-prone free platform: {platform}',
            'description': (
                f'The page is hosted on {platform} ({registrable}), a free platform '
                'increasingly used to host phishing kits and credential harvesting pages. '
                'Hosting on managed platforms makes takedown harder and URL reputation checks less effective.'
            ),
            'evidence': f'Host: {hostname} | Platform: {platform} ({registrable})',
        })

    # ------------------------------------------------------------------
    # 10. Newly registered domain — WHOIS creation_date
    # Skip safe/well-known domains: WHOIS would return decades-old dates
    # for those, but the check is meaningless for e.g. google.com subdomains.
    # ------------------------------------------------------------------
    if whois_data and sld not in _SAFE_DOMAINS:
        creation_date_str = whois_data.get('creation_date')
        if creation_date_str:
            try:
                from datetime import date as _date
                creation = _date.fromisoformat(creation_date_str[:10])
                age_days = (_date.today() - creation).days
                if age_days <= 30:
                    findings.append({
                        'severity': 'MEDIUM',
                        'category': 'Domain',
                        'title': f'Newly registered domain ({age_days} day{"s" if age_days != 1 else ""} old)',
                        'description': (
                            f'The domain {sld}.{tld} was registered {age_days} day{"s" if age_days != 1 else ""} ago '
                            f'(registration date: {creation_date_str[:10]}). '
                            'Attackers routinely register fresh domains specifically for phishing campaigns, '
                            'ClickFix payload delivery, and malware C2 infrastructure — deploying them '
                            'immediately before reputation databases have any record of them. '
                            'Domains under 30 days old are heavily over-represented in active threat feeds. '
                            'This signal is most significant when combined with a high-risk TLD, external '
                            'form submission, or obfuscated JavaScript.'
                        ),
                        'evidence': (
                            f'Domain     : {sld}.{tld}\n'
                            f'Registered : {creation_date_str[:10]}\n'
                            f'Age        : {age_days} day{"s" if age_days != 1 else ""}'
                        ),
                    })
                elif age_days <= 90:
                    findings.append({
                        'severity': 'INFO',
                        'category': 'Domain',
                        'title': f'Recently registered domain ({age_days} days old)',
                        'description': (
                            f'The domain {sld}.{tld} was registered {age_days} days ago '
                            f'(registration date: {creation_date_str[:10]}). '
                            'Domains under 90 days old have elevated representation in threat intelligence '
                            'feeds, though many are legitimate new sites. Treat as a context signal when '
                            'evaluating other findings rather than a standalone indicator.'
                        ),
                        'evidence': (
                            f'Domain     : {sld}.{tld}\n'
                            f'Registered : {creation_date_str[:10]}\n'
                            f'Age        : {age_days} days'
                        ),
                    })
            except (ValueError, TypeError):
                pass  # Malformed or redacted WHOIS date — skip silently

    # ------------------------------------------------------------------
    # 11. Dot-to-hyphen encoded domain in subdomain
    # ------------------------------------------------------------------
    # Pattern: subdomain ends with a hyphen-separated TLD token such as
    # "-com", "-net", "-org" — a domain name with dots replaced by hyphens.
    #
    # Example: "support-netcoin-com.zapier.app" encodes "support.netcoin.com".
    #
    # This is a textbook phishing-as-a-service technique: attackers use free
    # subdomain hosting (Zapier, GitHub Pages, Vercel, Netlify, etc.) to
    # create lookalike URLs.  Users scanning the URL quickly may read the
    # leftmost subdomain token as the authoritative domain name.
    #
    # The TLD token at the end is the structural tell — legitimate vanity
    # subdomains almost never end with "-com", "-net", etc.
    # ------------------------------------------------------------------
    # Only include well-established ccTLDs and gTLDs that are unambiguous as
    # domain suffixes.  Short generic words like 'io', 'co', 'app', 'dev' are
    # deliberately excluded: they appear legitimately as descriptive subdomain
    # components (e.g. 'react-todo-app.netlify.app', 'my-project-io.vercel.app')
    # and would generate excessive false positives.
    _ENCODED_TLDS = {
        'com', 'net', 'org',
        'uk', 'us', 'de', 'fr', 'au', 'ca', 'eu',
        'ru', 'cn', 'jp', 'br', 'in', 'nl', 'pl', 'it', 'es',
    }
    if subdomain:
        # The subdomain may itself have dots (e.g. "api.support-netcoin-com")
        # — check the leftmost label which is the attacker-chosen part.
        leftmost = subdomain.split('.')[0].lower()
        parts = leftmost.split('-')
        if len(parts) >= 2 and parts[-1] in _ENCODED_TLDS:
            core = '-'.join(parts[:-1])  # everything before the TLD token
            if len(core) >= 4:           # ignore single-char stems like "x-com"
                encoded_tld = parts[-1]
                decoded_domain = '.'.join(parts)  # reconstruct the impersonated domain
                on_abuse_platform = registrable in _ABUSE_HOSTING_PLATFORMS
                severity = 'HIGH' if on_abuse_platform else 'MEDIUM'
                platform_note = (
                    f' This page is hosted on {_ABUSE_HOSTING_PLATFORMS[registrable]} '
                    f'({registrable}), a free platform where attackers create pages at no cost '
                    'and with no identity verification.'
                    if on_abuse_platform else ''
                )
                findings.append({
                    'severity': severity,
                    'category': 'Domain',
                    'title': f'Subdomain encodes a domain via dot-to-hyphen substitution: {decoded_domain}',
                    'description': (
                        f'The subdomain "{leftmost}" is a domain name with dots replaced by hyphens — '
                        f'it encodes "{decoded_domain}". '
                        'Attackers use free subdomain hosting to create lookalike URLs where the '
                        'impersonated brand appears in the leftmost subdomain position, exploiting '
                        'the user habit of scanning only the start of a URL for legitimacy. '
                        f'The subdomain ending in "-{encoded_tld}" is the structural tell: '
                        'legitimate vanity subdomains do not embed a TLD token.'
                        + platform_note
                    ),
                    'evidence': (
                        f'Full hostname     : {hostname}\n'
                        f'Subdomain         : {leftmost}  ← dot-to-hyphen encoded domain\n'
                        f'Decoded as        : {decoded_domain}\n'
                        f'Registered domain : {registrable}'
                    ),
                })

    return findings
