"""
JavaScript threat analysis module.
Detects obfuscation, exfiltration, skimmers, miners, and other malicious patterns.
"""
import base64
import math
import re
import logging
from typing import Optional

from scanner.modules.known_good_domains import is_analytics, is_known_good

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _sev_key(f: dict) -> int:
    return _SEV_ORDER.get(f.get('severity', 'INFO'), 4)


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ---------------------------------------------------------------------------
# String literal extractor
# ---------------------------------------------------------------------------
_STRING_LITERAL_RE = re.compile(
    r'(?:"(?:[^"\\]|\\.)*"' r"|'(?:[^'\\]|\\.)*')",
    re.DOTALL,
)


def _extract_string_literals(js: str) -> list[str]:
    return [m.group(0)[1:-1] for m in _STRING_LITERAL_RE.finditer(js)]


# ---------------------------------------------------------------------------
# Evidence helper
# ---------------------------------------------------------------------------

def _snippet(js: str, m: re.Match, pad: int = 500, maxlen: int = 3000) -> str:
    """
    Return the fullest meaningful context around a regex match.

    For beautified JS (has newlines near the match): returns the complete
    containing line — i.e. the whole statement.  This gives the full
    malicious command/string rather than an arbitrary window.

    For minified JS (no newlines): falls back to a wide padded window.

    Capped at maxlen with ellipsis markers so the evidence block stays readable.
    """
    # Check if JS is beautified in the region around the match
    nearby = js[max(0, m.start() - 300):min(len(js), m.end() + 300)]
    if '\n' in nearby:
        line_start = js.rfind('\n', 0, m.start()) + 1
        line_end = js.find('\n', m.end())
        if line_end == -1:
            line_end = len(js)
        line = js[line_start:line_end].strip()
        if 0 < len(line) <= maxlen:
            return line
        if len(line) > maxlen:
            return line[:maxlen] + '...'

    # Minified JS or very long single line — use wide padded window
    start = max(0, m.start() - pad)
    end = min(len(js), m.end() + pad)
    raw = js[start:end].strip()
    prefix = '...' if start > 0 else ''
    suffix = '...' if end < len(js) else ''
    raw = prefix + raw + suffix
    if len(raw) > maxlen:
        raw = raw[:maxlen] + '...'
    return raw


# ---------------------------------------------------------------------------
# Base64 decode helper
# ---------------------------------------------------------------------------

def _try_b64_decode(s: str) -> Optional[str]:
    """
    Attempt to decode s as standard or URL-safe base64.

    Returns the decoded UTF-8 text if at least 70% of the decoded bytes are
    printable ASCII (space–tilde, plus tab/LF/CR).  Returns None if the result
    is binary/non-printable, the string is too short, or decoding fails.

    Normalises URL-safe characters (- → +, _ → /) and pads as needed before
    attempting decode.  Output is capped at 2000 chars.
    """
    s = s.strip(' "\'`\t\n\r')
    if len(s) < 16:
        return None

    # Normalise URL-safe base64 to standard, then fix padding
    normalised = s.replace('-', '+').replace('_', '/')
    padded = normalised + '=' * (-len(normalised) % 4)

    try:
        raw = base64.b64decode(padded, validate=True)
    except Exception:
        return None

    if not raw:
        return None

    # Require ≥70% printable bytes to reject binary/encrypted payloads
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    if printable / len(raw) < 0.70:
        return None

    try:
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return None

    if len(text) > 2000:
        return text[:2000] + '\n... [truncated]'
    return text


# Regex to find base64 candidates inside arbitrary text.
# Requires ≥16 chars (encodes ≥12 bytes) to suppress short false positives.
_B64_INLINE_RE = re.compile(r'[A-Za-z0-9+/\-_]{16,}={0,2}')


def _decode_b64_in_text(text: str) -> Optional[str]:
    """
    Scan text for base64 candidates and return the first that decodes to
    readable content, or None if nothing decodes successfully.
    Used to augment evidence blocks with decoded payloads.
    """
    seen: set[str] = set()
    for m in _B64_INLINE_RE.finditer(text):
        candidate = m.group(0)
        if candidate in seen:
            continue
        seen.add(candidate)
        result = _try_b64_decode(candidate)
        if result:
            return result
    return None


# ---------------------------------------------------------------------------
# Beautifier (optional — degrades gracefully)
# ---------------------------------------------------------------------------

# Large minified files (lottie, three.js, bundled apps) can take 20-30 s
# through jsbeautifier's regex engine, consuming the entire Celery task
# budget before a single threat check runs.  Files above this threshold are
# analysed as-is — the 19+ regex checks work on raw minified JS too.
_BEAUTIFY_MAX_BYTES = 256 * 1024  # 256 KB


def _beautify(js: str) -> str:
    if len(js) > _BEAUTIFY_MAX_BYTES:
        return js  # Skip beautification for large files — analyse raw
    try:
        import jsbeautifier  # type: ignore
        opts = jsbeautifier.default_options()
        opts.unescape_strings = True
        opts.eval_code = False
        return jsbeautifier.beautify(js, opts)
    except Exception:
        return js


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_eval_obfuscation(js: str) -> list[dict]:
    findings: list[dict] = []

    patterns = [
        (r'eval\s*\(\s*atob\s*\(', 'eval(atob(...)) — base64-encoded payload executed via eval'),
        (r'eval\s*\(\s*unescape\s*\(', 'eval(unescape(...)) — URL-encoded payload executed via eval'),
        (r'eval\s*\(\s*decodeURIComponent\s*\(', 'eval(decodeURIComponent(...)) — encoded payload executed via eval'),
        (r'new\s+Function\s*\([^)]*\)\s*\(\)', 'new Function(...)() — dynamic function construction used to execute code'),
        (r'eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(',
         'Nested decode + eval chain — multiple layers of encoding before execution'),
    ]

    for pattern, desc in patterns:
        m = re.search(pattern, js, re.IGNORECASE)
        if m:
            # Exclude jQuery/framework globalEval: new Function("return " + expr)()
            # This legitimate pattern appears in minified jQuery and similar libraries.
            if 'Function' in pattern and re.search(
                r'new\s+Function\s*\(\s*["\']return\s', js[max(0, m.start()-5):m.end()+5], re.IGNORECASE
            ):
                continue
            evidence = _snippet(js, m)
            # If the pattern involves atob(), try to extract and decode the
            # base64 argument so the analyst can read the decoded payload.
            if 'atob' in pattern:
                atob_arg_m = re.search(
                    r'atob\s*\(\s*["\']([A-Za-z0-9+/=\-_]{16,})["\']',
                    js, re.IGNORECASE,
                )
                if atob_arg_m:
                    decoded = _try_b64_decode(atob_arg_m.group(1))
                    if decoded:
                        evidence += f'\n\n[Decoded atob() payload]\n{decoded}'
            findings.append({
                'severity': 'CRITICAL',
                'category': 'JavaScript',
                'title': 'Eval-based obfuscation detected',
                'description': desc,
                'evidence': evidence,
            })

    return findings


def _check_array_rotation_obfuscation(js: str) -> list[dict]:
    findings: list[dict] = []

    hex_var_pattern = re.compile(r'var\s+_0x[0-9a-fA-F]+\s*=\s*\[', re.IGNORECASE)
    matches = hex_var_pattern.findall(js)
    if not matches:
        return findings

    # Count elements in the array (rough estimate via comma count in surrounding block)
    # Find the array block after the match
    for m in hex_var_pattern.finditer(js):
        start = m.start()
        bracket_start = js.find('[', start)
        if bracket_start == -1:
            continue

        depth = 0
        end = bracket_start
        for i in range(bracket_start, min(bracket_start + 50000, len(js))):
            if js[i] == '[':
                depth += 1
            elif js[i] == ']':
                depth -= 1
                if depth == 0:
                    end = i
                    break

        array_content = js[bracket_start:end + 1]
        element_count = array_content.count(',') + 1

        has_eval_or_atob = bool(re.search(r'\b(?:eval|atob)\b', array_content, re.IGNORECASE))

        if element_count > 10:
            severity = 'CRITICAL' if has_eval_or_atob else 'HIGH'
            findings.append({
                'severity': severity,
                'category': 'JavaScript',
                'title': 'Obfuscator.io / hex-array string obfuscation',
                'description': (
                    f'Variable with hex name contains an array of {element_count} obfuscated strings. '
                    'This is a signature of tools like obfuscator.io used to hide malicious intent.'
                    + (' Contains eval/atob — likely executable payload.' if has_eval_or_atob else '')
                ),
                'evidence': array_content,
            })
            break  # one finding per file is sufficient

    return findings


def _check_fromcharcode(js: str) -> list[dict]:
    findings: list[dict] = []
    pattern = re.compile(r'String\.fromCharCode\s*\(([^)]+)\)', re.IGNORECASE)
    for match in pattern.finditer(js):
        args = match.group(1)
        count = len(args.split(','))
        if count >= 5:
            findings.append({
                'severity': 'HIGH',
                'category': 'JavaScript',
                'title': 'String.fromCharCode character-code string construction',
                'description': (
                    f'String assembled from {count} character codes via String.fromCharCode(). '
                    'Attackers use this to hide URLs, shell commands, and payloads from static analysis.'
                ),
                'evidence': match.group(0),
            })
            if len(findings) >= 3:
                break

    return findings


def _check_hex_string_obfuscation(js: str, source_url: str = '') -> list[dict]:
    """
    Detect systematic \\x hex-escape obfuscation in JavaScript.

    Occasional \\x escapes are normal (special chars, unicode).  Systematic
    encoding of entire string literals — especially property names accessed via
    bracket notation — is a strong obfuscation indicator used in phishing kits,
    skimmers, and credential harvesters to evade static analysis.

    Evidence block contains the full original encoded script and the fully
    decoded script (every \\xNN replaced with its character) so an analyst
    can read both and make their own judgement.
    """
    # Akamai Bot Manager scripts are served from the merchant's domain under the
    # well-known /akam/ path.  They are intentionally heavily hex-obfuscated by
    # Akamai to protect their bot-detection logic.  This is vendor obfuscation,
    # not malicious obfuscation.
    if source_url and re.search(r'/akam/', source_url, re.IGNORECASE):
        return []

    hex_seq = re.compile(r'\\x[0-9a-fA-F]{2}')
    total_sequences = len(hex_seq.findall(js))

    # Noise threshold: ignore files with only a handful of \x sequences
    if total_sequences < 15:
        return []

    # Produce a fully decoded version — replace every \xNN escape with its char
    def _replace_hex(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    decoded_full = re.sub(r'\\x([0-9a-fA-F]{2})', _replace_hex, js)

    # Flag if decoded script exposes DOM/browser API operations
    _DOM_KEYWORDS = {
        'appendChild', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'createElement', 'document', 'script', 'eval', 'fetch',
        'XMLHttpRequest', 'cookie', 'localStorage', 'sessionStorage',
        'location', 'href', 'src', 'head', 'body',
    }
    has_dom = any(k in decoded_full for k in _DOM_KEYWORDS)

    severity = 'HIGH' if has_dom else 'MEDIUM'

    # Cap each section at 10 KB to keep DB rows reasonable
    _MAX = 10_000
    original_block = js if len(js) <= _MAX else js[:_MAX] + '\n... [truncated]'
    decoded_block  = decoded_full if len(decoded_full) <= _MAX else decoded_full[:_MAX] + '\n... [truncated]'

    dom_note = (
        ' Decoded script exposes DOM manipulation and browser API calls — '
        'the obfuscated code actively modifies the page structure.'
        if has_dom else ''
    )

    evidence = (
        f'Total \\x hex sequences: {total_sequences}\n\n'
        f'[Original — encoded]:\n{original_block}\n\n'
        f'[Decoded — all \\x sequences resolved]:\n{decoded_block}'
    )

    return [{
        'severity': severity,
        'category': 'JavaScript',
        'title': f'Hex-encoded string obfuscation ({total_sequences} \\x sequences)',
        'description': (
            f'The script contains {total_sequences} \\x hex-escape sequences systematically '
            'replacing string literals and property names. This technique hides method calls, '
            'URLs, and behaviour from static analysis tools and WAFs.'
            + dom_note +
            ' Commonly used in phishing kits, credit card skimmers, and credential harvesters.'
        ),
        'evidence': evidence,
    }]


_JS_KEYWORDS = frozenset([
    'function', 'return', 'var ', 'let ', 'const ', 'if(', 'if (', 'else',
    'for(', 'for (', 'while(', 'while (', 'switch(', 'switch (', 'case ',
    'break', 'continue', 'new ', 'this.', 'prototype', 'typeof', 'instanceof',
    'undefined', 'null', 'true', 'false', '=>', '.call(', '.apply(',
    'addEventListener', 'document.', 'window.',
    '.setAttribute(', '.getAttribute(', '.appendChild(', '.removeChild(',
    '.replace(', '.test(', '.match(', '.indexOf(', '.length',
    'font-family', 'font-style', 'src: url(', '@font-face',
    # Minified code operators — common in any minified JS, rare in encoded payloads
    '&&', '||', '===', '!==', '+=', '-=', '++', '--', '!0', '!1',
    # Webpack/modern JS bundle patterns — always code, never encoded payloads
    'Object.defineProperty', 'Promise.all(', '.then(', '.bind(',
])


def _has_js_keywords(s: str, threshold: int = 2) -> bool:
    """Return True if the string contains >= threshold distinct JS keywords/patterns.
    Used to detect minified code masquerading as encoded payloads."""
    count = sum(1 for kw in _JS_KEYWORDS if kw in s)
    return count >= threshold


def _check_high_entropy_strings(js: str, source_url: str = '') -> list[dict]:
    findings: list[dict] = []
    # Analytics/CDN scripts (e.g. GTM, GA) embed origin-trial tokens, signing
    # keys, and other legitimately high-entropy config strings.  Flag entropy
    # from known-good sources as noise, not threats.
    if source_url and (is_analytics(source_url) or is_known_good(source_url)):
        return findings
    seen: set[str] = set()

    for literal in _extract_string_literals(js):
        if len(literal) < 64:
            continue
        if literal in seen:
            continue
        seen.add(literal)

        # Skip URL strings — query parameters and hex tracking tokens raise
        # entropy naturally, but URLs are never encoded payloads.  Also handle
        # backslash-escaped slashes (https:\/\/) as they appear in raw JS strings.
        if re.match(r'https?:(?://|\\/\\/)', literal, re.IGNORECASE):
            continue

        # Skip CSS-like strings — property:value pairs produce naturally high
        # entropy from the mix of colons, semicolons, hashes, and keywords.
        if len(re.findall(r'[a-z-]+\s*:', literal, re.IGNORECASE)) >= 3:
            continue

        # Skip SRI integrity hashes — sha256-/sha384-/sha512- prefixed base64
        # strings are legitimately high-entropy but are not payloads.
        if re.match(r'sha(?:256|384|512)-[A-Za-z0-9+/=]+$', literal, re.IGNORECASE):
            continue

        # Skip data URI strings — data:image/png;base64,... and similar are
        # embedded images (icons, sprites, email widget branding).  They are
        # legitimately high-entropy base64 but are never encoded attack payloads.
        if re.match(r'data:[a-z]+/[a-z+\-]+;base64,', literal, re.IGNORECASE):
            continue

        # Skip SVG path data — the `d` attribute of <path> elements contains
        # numeric coordinates and path commands (M, L, C, Z, etc.) that are
        # legitimately high entropy but are not encoded payloads.
        if re.match(r'[MmLlHhVvCcSsQqTtAaZz][0-9\s.,\-MmLlHhVvCcSsQqTtAaZz]{20,}$', literal):
            continue
        # Also skip inline SVG markup strings
        if literal.lstrip().startswith('<svg') or literal.lstrip().startswith('<path'):
            continue

        # Skip minified JS code embedded in strings — high entropy is expected
        # in minified code but it is not an encoded payload.  If the string
        # contains several distinct JS keywords/patterns it is almost certainly
        # inlined or concatenated source code, not a base64 blob.
        if _has_js_keywords(literal):
            continue

        # Skip the standard base64 alphabet itself — it appears verbatim in
        # many libraries (crypto polyfills, encoding utilities) and has
        # maximum entropy by construction, but is not an encoded payload.
        # Matches both the 64-char form (no padding) and the 65-char form
        # with trailing '=' that Akamai and similar libraries include.
        if re.match(r'^[A-Za-z0-9+/=]{64,65}$', literal) and len(set(literal)) >= 64:
            continue

        # Skip human-readable strings (credits, comments, changelogs).
        # Real encoded payloads never contain spaces; if >5% of the string is
        # spaces the string is almost certainly natural language, not a payload.
        if literal.count(' ') / len(literal) > 0.05:
            continue

        # Skip strings that are predominantly non-ASCII Unicode — these are
        # natural-language strings in non-Latin scripts (Thai, Chinese, Japanese,
        # Korean, Arabic, Devanagari, etc.) which have artificially high entropy
        # because of their multi-byte UTF-8 representation, but are never encoded
        # payloads. Encoded payloads (base64, hex) are always pure ASCII.
        if sum(1 for c in literal if ord(c) > 0x7F) / len(literal) > 0.3:
            continue

        # Skip regex pattern strings — minified JS frequently stores compiled
        # regexes as string literals (e.g. for new RegExp(str)).  Regex
        # metachar sequences (\s, \d, \w, character classes [^...], anchors)
        # are high-entropy by nature but are not encoded payloads.
        if re.search(r'\\[sdwbSWDnrtv]|\[\^|/\^|(?:\.\*|\.\+)\$', literal):
            continue

        # Skip valid JSON structures — legitimate API configurations (e.g.
        # Google Privacy Sandbox HPKE public keys) are structured JSON and have
        # naturally high entropy, but are not encoded payloads.
        # Unescape JS string escapes (\") before parsing so JSON.loads works on
        # literals extracted from inside JS double-quoted strings.
        stripped_lit = literal.strip()
        if (
            (stripped_lit.startswith('{') and stripped_lit.endswith('}'))
            or (stripped_lit.startswith('[') and stripped_lit.endswith(']'))
        ):
            try:
                import json as _json
                _json.loads(stripped_lit.replace('\\"', '"').replace("\\'", "'"))
                continue  # Valid JSON — skip entropy check
            except (ValueError, TypeError):
                pass

        entropy = shannon_entropy(literal)

        # Attempt base64 decode — the literal itself may be a raw base64 payload
        decoded = _try_b64_decode(literal)
        evidence = literal
        if decoded:
            evidence += f'\n\n[Decoded]\n{decoded}'

        if entropy > 5.5:
            findings.append({
                'severity': 'HIGH',
                'category': 'JavaScript',
                'title': 'High-entropy string (likely base64/encoded payload)',
                'description': (
                    f'String literal of length {len(literal)} has entropy {entropy:.2f} bits/char '
                    '(>5.5). This strongly suggests a base64-encoded or otherwise obfuscated payload.'
                ),
                'evidence': evidence,
            })
        elif entropy > 4.8:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'JavaScript',
                'title': 'Possibly encoded string (elevated entropy)',
                'description': (
                    f'String literal of length {len(literal)} has entropy {entropy:.2f} bits/char '
                    '(>4.8). May be encoded data worth investigating.'
                ),
                'evidence': evidence,
            })

        if len(findings) >= 5:
            break

    return findings


def _check_split_join_evasion(js: str) -> list[dict]:
    findings: list[dict] = []
    # Pattern: ['...','...','...'].join('') or similar
    pattern = re.compile(
        r'\[(?:\s*["\'][^"\']{1,30}["\'],?\s*){3,}\]\s*\.\s*join\s*\(\s*["\']["\']?\s*\)',
        re.IGNORECASE,
    )
    matches = pattern.findall(js)
    if matches:
        # Reconstruct the joined string to check if it's trivially short or a
        # common HTTP method — ["G","E","T"].join("") = "GET" is a known minifier
        # pattern in legitimate libraries (lottie, dotlottie, etc.), not evasion.
        _HTTP_METHODS = frozenset(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
        for match in matches:
            parts = re.findall(r"['\"]([^'\"]*)['\"]", match)
            joined = ''.join(parts)
            if len(joined) < 8 or joined.upper() in _HTTP_METHODS:
                continue
            findings.append({
                'severity': 'MEDIUM',
                'category': 'JavaScript',
                'title': 'Split-join string construction (URL/keyword evasion)',
                'description': (
                    'Array of short strings joined together to evade static detection. '
                    'Commonly used to hide malicious URLs or function names from scanners.'
                ),
                'evidence': match,
            })
            break
    return findings


def _check_cookie_exfiltration(js: str) -> list[dict]:
    findings: list[dict] = []
    cookie_m = re.search(r'document\.cookie', js, re.IGNORECASE)
    if not cookie_m:
        return findings

    exfil_m = re.search(
        r'(?:fetch\s*\(|new\s+XMLHttpRequest|navigator\.sendBeacon\s*\()',
        js, re.IGNORECASE
    )
    if not exfil_m:
        return findings

    # Require the cookie value to actually be used near the exfiltration call.
    # A privacy banner reading document.cookie for consent state and making an
    # unrelated geolocation fetch is NOT exfiltration.  We check for a variable
    # or expression that bridges the two: the cookie value (or a var holding it)
    # should appear within 800 chars of the exfiltration call.
    bridge_re = re.compile(
        r'document\.cookie|\.cookie\b',
        re.IGNORECASE,
    )
    exfil_region_start = max(0, exfil_m.start() - 800)
    exfil_region_end = min(len(js), exfil_m.end() + 200)
    nearby_region = js[exfil_region_start:exfil_region_end]
    if not bridge_re.search(nearby_region):
        return findings

    # Only fire if there is an external (absolute URL) network call nearby.
    # A fetch with a relative URL (starting with '/') is same-origin — the
    # data never leaves the site.  LiteSpeed Cache's guest.vary.php is the
    # canonical example: it reads _lscache_vary from document.cookie, then
    # posts to /wp-content/plugins/litespeed-cache/guest.vary.php.
    external_call_re = re.compile(
        r'(?:'
        r'(?:fetch|sendBeacon)\s*\(\s*["\'\`]https?://'
        r'|\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']https?://'
        r')',
        re.IGNORECASE,
    )
    if not external_call_re.search(nearby_region):
        return findings

    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'Cookie exfiltration — document.cookie sent via network call',
        'description': (
            'document.cookie is accessed close to a network call '
            '(fetch/XHR/sendBeacon). This is the primary pattern for session cookie theft.'
        ),
        'evidence': (
            f'[Cookie access]\n{_snippet(js, cookie_m)}\n\n'
            f'[Network exfiltration call]\n{_snippet(js, exfil_m)}'
        ),
    })
    return findings


def _check_form_hijacking(js: str) -> list[dict]:
    findings: list[dict] = []
    submit_m = re.search(
        r'addEventListener\s*\(\s*["\']submit["\']', js, re.IGNORECASE
    )
    if not submit_m:
        return findings

    prevent_m = re.search(r'preventDefault\s*\(\s*\)', js, re.IGNORECASE)
    # Require an explicit hardcoded external URL in the network call.
    # Legitimate AJAX form plugins (CF7, Gravity Forms, WPForms) compute their
    # endpoint dynamically from window.location — they never hardcode an exfil URL.
    # Real credential harvesters always hardcode their destination: fetch('https://evil.com/...')
    exfil_m = re.search(
        r'(?:'
        r'fetch\s*\(\s*["\'\`]https?://'           # fetch('https://...')
        r'|\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']https?://'  # xhr.open('POST','https://...')
        r'|sendBeacon\s*\(\s*["\'\`]https?://'     # sendBeacon('https://...')
        r')',
        js, re.IGNORECASE
    )

    if exfil_m:
        evidence_parts = [f'[Form submit interceptor]\n{_snippet(js, submit_m)}']
        if prevent_m:
            evidence_parts.append(f'[Default submission blocked (data silently stolen)]\n{_snippet(js, prevent_m)}')
        evidence_parts.append(f'[Data exfiltration call]\n{_snippet(js, exfil_m)}')
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'Form hijacking / phishing data exfiltration',
            'description': (
                'Form submit event listener combined with outbound network call detected. '
                + ('preventDefault() also present — form submission silently intercepted and data stolen.' if prevent_m else
                   'Form data likely being silently forwarded to attacker-controlled endpoint.')
            ),
            'evidence': '\n\n'.join(evidence_parts),
        })
    return findings


def _check_keylogger(js: str) -> list[dict]:
    findings: list[dict] = []
    key_m = re.search(
        r'addEventListener\s*\(\s*["\']key(?:down|up|press)["\']',
        js, re.IGNORECASE
    )
    if not key_m:
        return findings

    # Require that the handler actually captures key values — audio unlock
    # listeners, modal close handlers, and other legitimate keydown uses do NOT
    # read the key value.  Real keyloggers must read event.key / event.keyCode /
    # event.which to know what was typed.
    # Check within 600 chars of the listener for key capture.
    capture_re = re.compile(
        r'(?:event|e|evt|ev)\s*\.\s*(?:key\b|keyCode\b|which\b|charCode\b|code\b)',
        re.IGNORECASE,
    )
    listener_region = js[key_m.start():min(len(js), key_m.start() + 600)]
    capture_m = capture_re.search(listener_region)
    if not capture_m:
        return findings

    # Exclude accessibility focus-trap patterns — GDPR cookie consent banners
    # (Complianz, CookieYes, Borlabs, etc.) use keydown listeners to trap Tab
    # focus within the consent dialog for keyboard accessibility (WCAG 2.1).
    # These handlers check `e.key === "Tab"` or `"Escape"` and do NOT collect
    # arbitrary keystrokes.  Real keyloggers must capture all keys, not just
    # specific named navigation keys.
    # Strategy: if the only key comparisons visible in the capture region are
    # against specific named keys AND the key value is never stored/concatenated,
    # this is an accessibility handler, not a keylogger.
    nav_key_compare_re = re.compile(
        r'(?:'
        r'"(?:Tab|Escape|Esc|Enter|ArrowUp|ArrowDown|ArrowLeft|ArrowRight|'
        r'Home|End|PageUp|PageDown|Backspace|Delete|Space|Shift|Control|Alt|Meta|F\d{1,2})"'
        r'|'
        r"'(?:Tab|Escape|Esc|Enter|ArrowUp|ArrowDown|ArrowLeft|ArrowRight|"
        r"Home|End|PageUp|PageDown|Backspace|Delete|Space|Shift|Control|Alt|Meta|F\d{1,2})'"
        r')',
        re.IGNORECASE,
    )
    key_collect_re = re.compile(
        r'(?:event|e|evt|ev)\s*\.\s*key\s*(?:[+\-]|\.|push|concat|join|\+=|=(?!=))',
        re.IGNORECASE,
    )
    if nav_key_compare_re.search(listener_region) and not key_collect_re.search(listener_region):
        return findings

    # The exfiltration call must be close to where keystrokes are captured —
    # not just anywhere in the same file.  A cookie-consent banner that reads
    # event.key (to close on Escape) and also makes an unrelated geolocation
    # fetch is NOT a keylogger.  Require the exfil to be within 3000 chars of
    # the capture point.
    capture_abs_pos = key_m.start() + capture_m.start()
    exfil_m = re.search(
        r'(?:fetch\s*\(|XMLHttpRequest|sendBeacon\s*\()',
        js[max(0, capture_abs_pos - 200):min(len(js), capture_abs_pos + 3000)],
        re.IGNORECASE,
    )
    if exfil_m:
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'Keylogger pattern detected',
            'description': (
                'Keyboard event listener (keydown/keyup/keypress) reads key values and makes an '
                'outbound network call. This is the signature pattern for a JavaScript keylogger '
                'stealing typed input.'
            ),
            'evidence': (
                f'[Key event listener with key capture]\n{_snippet(js, key_m)}\n\n'
                f'[Exfiltration call]\n{_snippet(js, exfil_m)}'
            ),
        })
    return findings


def _check_payment_skimmer(js: str) -> list[dict]:
    """
    Detect Magecart-style payment card skimmers with high precision.

    A real skimmer MUST do two things:
      1. Query the DOM directly for card input elements to read their values.
         Legitimate payment SDKs (Stripe, PayPal) operate inside sandboxed
         iframes and never need to do this on the merchant page.
      2. Exfiltrate the harvested data to a network endpoint.

    Keyword presence alone (e.g. 'cardnumber' in a string) is not sufficient —
    Stripe.js and every checkout component contain these words legitimately.
    DOM access is the non-negotiable discriminator.

    Corroborating signals (data encoding, form interception, polling) raise
    confidence from HIGH to CRITICAL.
    """
    findings: list[dict] = []

    # --- Signal 1: Direct DOM query targeting card-related input fields ------
    # Matches querySelector/getElementById/getElementsByName with a card-related
    # selector string.  This is the primary discriminating signal.
    dom_query_re = re.compile(
        r'(?:querySelector(?:All)?|getElementById|getElementsByName|getElementsByClassName)'
        r'\s*\(\s*["\'][^"\']*'
        r'(?:card[-_\s]?(?:number|num|holder|name|no\b)|'
        r'cvv|cv2|cvc|ccv|'
        r'security[-_\s]?code|'
        r'expir(?:y|ation|[-_]?date|[-_]?year|[-_]?month)?|'
        r'pan\b|cc[-_]?(?:number|num\b)|'
        r'credit[-_\s]?card|payment[-_\s]?(?:card|number))'
        r'[^"\']*["\']',
        re.IGNORECASE,
    )

    # --- Signal 2: Exfiltration call -----------------------------------------
    exfil_re = re.compile(
        r'(?:fetch\s*\(|(?:new\s+)?XMLHttpRequest|navigator\.sendBeacon\s*\(|'
        r'new\s+Image\s*\(\s*\))',
        re.IGNORECASE,
    )

    # Separate pattern to extract exfil URL for whitelist check
    exfil_url_re = re.compile(
        r'(?:fetch|sendBeacon)\s*\(\s*["\']([^"\']{8,})["\']',
        re.IGNORECASE,
    )

    # --- Signal 3: Pre-exfiltration data encoding ----------------------------
    # Skimmers commonly encode stolen data to avoid content inspection.
    encoding_re = re.compile(
        r'(?:btoa\s*\(|window\.btoa\s*\(|'
        r'encodeURIComponent\s*\([^)]*(?:card|cvv|cvc|pan|expir)|'
        r'\bxor\b[^;]{0,60}(?:card|cvv|pan)|'
        r'\.toString\s*\(\s*16\s*\))',
        re.IGNORECASE,
    )

    # --- Signal 4: Form submit interception ----------------------------------
    submit_re = re.compile(
        r'addEventListener\s*\(\s*["\']submit["\']',
        re.IGNORECASE,
    )

    # --- Signal 5: Polling / DOM observation ---------------------------------
    polling_re = re.compile(
        r'(?:setInterval\s*\(|MutationObserver\s*\(|new\s+MutationObserver)',
        re.IGNORECASE,
    )

    dom_match = dom_query_re.search(js)
    exfil_match = exfil_re.search(js)
    encoding_match = encoding_re.search(js)
    submit_match = submit_re.search(js)
    polling_match = polling_re.search(js)

    # DOM card-field access and an exfiltration call are both required.
    if not dom_match or not exfil_match:
        return findings

    # If every extractable exfiltration URL is relative (same-origin) or a known
    # payment processor/analytics endpoint, this is not a skimmer.  Real Magecart
    # skimmers always exfiltrate to an attacker-controlled external domain — they
    # never send card data back to the merchant's own API.
    from scanner.modules.known_good_domains import is_payment_processor, is_analytics
    all_exfil_urls = exfil_url_re.findall(js)
    if all_exfil_urls:
        external_exfil = [u for u in all_exfil_urls if '://' in u]
        if not external_exfil:
            return findings  # all fetch/beacon targets are relative (same-origin)
        if all(is_payment_processor(u) or is_analytics(u) for u in external_exfil):
            return findings

    # Score corroborating signals — each raises confidence.
    corroborating = sum([
        bool(encoding_match),
        bool(submit_match),
        bool(polling_match),
    ])

    # CRITICAL requires DOM access + exfil + at least one corroborating signal.
    # HIGH fires on DOM access + exfil alone (possible skimmer, lower confidence).
    severity = 'CRITICAL' if corroborating >= 1 else 'HIGH'

    # Build structured evidence from actual matched code
    evidence_lines = [f'[DOM query — card field targeted]\n{dom_match.group(0)}']
    evidence_lines.append(f'[Exfiltration call]\n{exfil_match.group(0)}')
    if encoding_match:
        evidence_lines.append(f'[Data encoding before exfiltration]\n{encoding_match.group(0)}')
    if submit_match:
        evidence_lines.append(f'[Form submit interception]\n{submit_match.group(0)}')
    if polling_match:
        evidence_lines.append(f'[Polling / DOM observation]\n{polling_match.group(0)}')

    signal_desc = ['direct DOM access to card input fields', 'outbound data exfiltration']
    if encoding_match:
        signal_desc.append('pre-exfiltration encoding')
    if submit_match:
        signal_desc.append('form submit interception')
    if polling_match:
        signal_desc.append('polling/mutation observation')

    findings.append({
        'severity': severity,
        'category': 'JavaScript',
        'title': 'Payment card skimmer (Magecart-style) detected',
        'description': (
            f'Skimmer signals confirmed: {", ".join(signal_desc)}. '
            'Direct DOM access to card input fields combined with outbound exfiltration '
            'is the operational fingerprint of Magecart-family card skimmers. '
            'Legitimate payment SDKs operate inside sandboxed iframes and never '
            'query card fields from the merchant page.'
        ),
        'evidence': '\n\n'.join(evidence_lines),
    })

    return findings


def _check_crypto_miner(js: str) -> list[dict]:
    findings: list[dict] = []
    miner_strings = [
        'stratum+tcp', 'mining.submit', 'CoinHive', 'coinhive',
        'CryptoLoot', 'cryptoloot', 'JSEcoin', 'jsecoin',
        'minero', 'cryptonight', 'hashrate', 'JobThread',
    ]
    found: list[str] = []
    for s in miner_strings:
        if s.lower() in js.lower():
            found.append(s)

    # WebWorker + wasm pattern
    has_wasm_worker = bool(re.search(
        r'new\s+Worker\s*\([^)]*\.wasm', js, re.IGNORECASE
    ))

    if found or has_wasm_worker:
        evidence_parts = found
        if has_wasm_worker:
            evidence_parts.append('WebWorker+WASM loading')
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'Cryptocurrency mining script detected',
            'description': (
                'Known crypto mining indicators found in script. '
                'This script likely hijacks visitor CPU for mining without consent.'
            ),
            'evidence': ', '.join(evidence_parts),
        })
    return findings


# Scripts from these specific hosts create hidden iframes for legitimate purposes
# (CAPTCHA sandboxing, third-party cookie checks) and must not trigger the
# hidden-iframe injection finding.  Listed by full hostname rather than
# registrable domain to avoid over-suppressing (e.g. cloudflare.com is
# intentionally excluded from known_good_domains due to CDN abuse, but the
# Turnstile CAPTCHA subdomain is a narrow, well-defined service).
_IFRAME_ALLOWLISTED_HOSTS: frozenset[str] = frozenset({
    'challenges.cloudflare.com',  # Cloudflare Turnstile CAPTCHA
    'cdn.prod.website-files.com', # Webflow platform CDN (cookie-check iframe)
})


def _check_hidden_iframe_injection(js: str, source_url: str = '') -> list[dict]:
    findings: list[dict] = []
    # Analytics/tag-management scripts (e.g. GTM) and specific trusted service
    # hosts (CAPTCHA, platform CDN) routinely create display:none iframes for
    # sandboxed execution — not a threat when the source is known-good.
    if source_url:
        from urllib.parse import urlparse as _urlparse
        _src_host = _urlparse(source_url).hostname or ''
        if _src_host in _IFRAME_ALLOWLISTED_HOSTS or is_analytics(source_url):
            return findings
    # Cloudflare Bot Management injects an inline script that creates a 1×1
    # hidden iframe to load its challenge script from /cdn-cgi/.  The signature
    # is window.__CF$cv$params.  This is WAF infrastructure, not an attack.
    if '__CF$cv$params' in js:
        return findings
    # Tealium Tag Management System (utag) creates 1×1 hidden iframes as
    # standard tracking-pixel infrastructure.  The utag.ut.merge signature
    # is highly specific — it only appears in Tealium's tag container code.
    if 'utag.ut.merge' in js:
        return findings
    # BuyGoods affiliate conversion pixel — a hidden iframe loading
    # buygoods.com/affiliates/go/conversion is standard affiliate tracking,
    # not clickjacking or drive-by malware.
    if 'buygoods.com/affiliates/go/conversion' in js:
        return findings
    # OneTrust Cookie Compliance SDK creates hidden iframes for cross-domain
    # consent synchronisation.  The otSDKStub / OptanonWrapper signatures are
    # unique to OneTrust's consent management platform.
    if source_url and 'otSDKStub' in source_url:
        return findings
    if 'OptanonWrapper' in js or 'OneTrust.initializeCookiePolicyHtml' in js:
        return findings
    iframe_m = re.search(
        r'createElement\s*\(\s*["\']iframe["\']',
        js, re.IGNORECASE
    )
    if not iframe_m:
        return findings

    # Only look for hidden styling within 800 chars of the iframe creation.
    # Searching the entire script catches unrelated elements (e.g. viewport
    # measurement divs with width:0) that have nothing to do with the iframe.
    iframe_window = js[max(0, iframe_m.start() - 200): min(len(js), iframe_m.end() + 800)]
    hidden_m = re.search(
        r'(?:display\s*(?:=|:)\s*["\']?none|'
        r'visibility\s*(?:=|:)\s*["\']?hidden|'
        r'width\s*(?:=|:)\s*["\']?0|'
        r'height\s*(?:=|:)\s*["\']?0)',
        iframe_window, re.IGNORECASE
    )
    if hidden_m:
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'Hidden iframe injection via JavaScript',
            'description': (
                'Script dynamically creates an iframe element and sets it to be invisible '
                '(display:none, width:0, height:0, or visibility:hidden). '
                'Used for clickjacking, credential harvesting, or drive-by downloads.'
            ),
            'evidence': (
                f'[Iframe created dynamically]\n{_snippet(js, iframe_m)}\n\n'
                f'[Hidden styling applied]\n{_snippet(iframe_window, hidden_m)}'
            ),
        })
    return findings


def _check_forced_download(js: str) -> list[dict]:
    findings: list[dict] = []
    has_create_a = bool(re.search(
        r'createElement\s*\(\s*["\']a["\']', js, re.IGNORECASE
    ))
    if not has_create_a:
        return findings

    has_download_click = bool(re.search(
        r'\.download\s*=', js, re.IGNORECASE
    )) and bool(re.search(r'\.click\s*\(\s*\)', js, re.IGNORECASE))

    if not has_download_click:
        return findings

    exe_pattern = re.compile(
        r'\.(?:exe|msi|js|vbs|ps1|bat|cmd|dmg|pkg|scr|pif|com|hta)\b',
        re.IGNORECASE,
    )
    exe_match = exe_pattern.search(js)

    # Executable extension → HIGH (drive-by malware delivery).
    # No extension identified → MEDIUM (could be a legitimate "download this PDF"
    # button in a popup or export feature — severity reflects reduced confidence).
    severity = 'HIGH' if exe_match else 'MEDIUM'
    findings.append({
        'severity': severity,
        'category': 'JavaScript',
        'title': 'Forced file download via JavaScript',
        'description': (
            'Script creates an anchor element, sets a .download attribute, and calls .click() to '
            'silently trigger a file download.' +
            (f' Target file has executable extension: {exe_match.group(0)}' if exe_match else '')
        ),
        'evidence': 'createElement("a") + .download = + .click() detected' +
                    (f' — extension: {exe_match.group(0)}' if exe_match else ''),
    })
    return findings


def _check_auto_redirect(js: str) -> list[dict]:
    findings: list[dict] = []

    # window.location assignment in setTimeout with delay < 3000.
    # Require an actual assignment (window.location = or window.location.href =)
    # not just any window.location reference — reading window.location.search
    # to construct a URL is not a redirect.
    pattern = re.compile(
        r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{[^}]*window\.location(?:\.href)?\s*=[^=][^}]*\}\s*,\s*(\d+)',
        re.IGNORECASE | re.DOTALL,
    )
    for m in pattern.finditer(js):
        delay = int(m.group(1))
        if delay < 3000:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'JavaScript',
                'title': f'Auto-redirect via setTimeout (delay={delay}ms)',
                'description': (
                    f'Script redirects the user via window.location after only {delay}ms. '
                    'Very short auto-redirects are used to funnel victims to phishing pages.'
                ),
                'evidence': m.group(0),
            })

    # window.location.replace to external
    replace_pattern = re.compile(
        r'window\.location\.replace\s*\(\s*["\']https?://([^"\']+)',
        re.IGNORECASE,
    )
    for m in replace_pattern.finditer(js):
        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': 'window.location.replace redirect to external URL',
            'description': (
                'Script uses window.location.replace() to redirect to an external URL. '
                'This removes the current page from browser history, preventing the back button.'
            ),
            'evidence': m.group(0),
        })

    return findings


def _check_js_location_redirect(js: str, source_url: str = '') -> list[dict]:
    """
    Detects unconditional window.location / window.location.href assignments
    to a literal external URL — a classic open-redirect staging pattern where
    a neutral host (cloud storage, CDN, GitHub Pages) serves a minimal page
    whose only purpose is to forward victims to attack infrastructure.

    Covers:
      window.location.href = 'https://evil.com/...'
      window.location      = "https://evil.com/..."
      window.location.href = 'https://evil.com/' + <dynamic suffix>
    """
    findings: list[dict] = []

    pattern = re.compile(
        r'window\.location(?:\.href)?\s*=\s*["\'](\s*https?://([^"\'/?#\s]+)[^"\']*)',
        re.IGNORECASE,
    )
    for m in pattern.finditer(js):
        target_url = m.group(1).strip()
        target_domain = m.group(2).lower()

        # Skip same-domain redirects
        if source_url:
            source_m = re.match(r'https?://([^/?#]+)', source_url)
            if source_m and source_m.group(1).lower() == target_domain:
                continue

        # Skip known-good destinations (Google, Microsoft, CDNs, etc.)
        if is_known_good(target_domain):
            continue

        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': f'JavaScript redirect to external domain: {target_domain}',
            'description': (
                f'Script unconditionally redirects the visitor to an external domain ({target_domain}) '
                'via a window.location assignment. This is a common staging technique: a neutral '
                'hosting platform (cloud storage, CDN, GitHub Pages) serves a minimal wrapper page '
                'whose only job is to forward victims to the actual attack infrastructure. '
                f'Run a new scan on {target_domain} to analyse the destination.'
            ),
            'evidence': m.group(0).strip(),
        })

    return findings


def _check_anchor_redirect(js: str, source_url: str = '') -> list[dict]:
    """
    Detect TDS (traffic distribution system) redirect via anchor .href + .click().

    Covers two patterns:
      1. Literal URL:  element.href = "https://evil.com/?u=" + window.location; element.click()
      2. Variable URL: var u = "https://evil.com/..."; element.href = u; element.click()

    Both bypass _check_js_location_redirect (which looks for window.location = assignments)
    and are used by TDS infrastructure to funnel victims from neutral hosting to attack
    landing pages, often with visitor URL telemetry appended to the redirect destination.

    Required signal sequence (within 800 + 600 char windows):
      external URL string  →  .href = assignment  →  .click() or synthetic click
    Download anchors (.download =) are excluded — those are HTML smuggling.
    """
    findings: list[dict] = []

    # Anchor on any external URL string literal in the code
    url_pattern = re.compile(
        r'["\'](\s*https?://([^"\'?#\s]{3,})[^"\']*)["\']',
        re.IGNORECASE,
    )
    seen_domains: set[str] = set()

    for url_m in url_pattern.finditer(js):
        target_domain = url_m.group(2).split('/')[0].lower()

        if target_domain in seen_domains:
            continue

        # Skip same-domain references and known-good destinations
        if source_url:
            source_host = re.match(r'https?://([^/?#]+)', source_url)
            if source_host and source_host.group(1).lower() == target_domain:
                continue
        if is_known_good(target_domain):
            continue

        # Look for .href = within 800 chars after the URL literal
        window_800 = js[url_m.start(): min(len(js), url_m.start() + 800)]
        href_m = re.search(r'(?:\w+|\))\s*\.\s*href\s*=', window_800, re.IGNORECASE)
        if not href_m:
            continue

        # Look for .click() or synthetic MouseEvent within 600 chars after .href =
        href_abs = url_m.start() + href_m.start()
        click_window = js[href_abs: min(len(js), href_abs + 600)]
        click_m = re.search(
            r'(?:\.click\s*\(\s*\)|initEvent\s*\(\s*["\']click["\'])',
            click_window, re.IGNORECASE,
        )
        if not click_m:
            continue

        # Exclude download anchors — HTML smuggling, handled by _check_html_smuggling
        if re.search(r'\.download\s*=', click_window, re.IGNORECASE):
            continue

        seen_domains.add(target_domain)

        # Elevated severity when visitor URL data is exfiltrated to the TDS
        exfil_m = re.search(
            r'window\.location|document\.URL|document\.referrer',
            window_800, re.IGNORECASE,
        )
        severity = 'HIGH' if exfil_m else 'MEDIUM'
        exfil_note = (
            ' Visitor URL is concatenated into the redirect destination — the TDS is '
            'collecting entry-point telemetry from every victim it forwards.'
            if exfil_m else ''
        )

        findings.append({
            'severity': severity,
            'category': 'JavaScript',
            'title': f'TDS redirect via anchor .click() to: {target_domain}',
            'description': (
                f'Script constructs an external URL, assigns it to an anchor element\'s '
                f'href, and calls .click() to force navigation to {target_domain}. '
                'This is a traffic distribution system (TDS) redirect pattern used by '
                'malware campaigns and phishing infrastructure to funnel victims from '
                'neutral hosting (cloud storage, CDN, newly registered domains) to the '
                'actual attack landing page.' + exfil_note
            ),
            'evidence': _snippet(js, url_m),
        })

    return findings


def _check_right_click_disable(js: str) -> list[dict]:
    findings: list[dict] = []
    # Two separate bounded patterns — avoids the DOTALL backtracking of the original
    ctx_m = re.search(r'addEventListener\s*\(\s*["\']contextmenu["\']', js, re.IGNORECASE)
    prev_m = re.search(r'preventDefault\s*\(\s*\)', js, re.IGNORECASE) if ctx_m else None
    if ctx_m and prev_m:
        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': 'Right-click context menu disabled',
            'description': (
                'Script prevents the contextmenu event to disable right-click inspection. '
                'Sites disabling right-click typically hide malicious content from casual inspection.'
            ),
            'evidence': (
                f'[Context menu event listener]\n{_snippet(js, ctx_m)}\n\n'
                f'[Event default action blocked]\n{_snippet(js, prev_m)}'
            ),
        })
    return findings


def _check_devtools_detection(js: str) -> list[dict]:
    findings: list[dict] = []

    patterns = [
        (r'outerWidth\s*-\s*innerWidth|outerHeight\s*-\s*innerHeight',
         'outerWidth/outerHeight vs innerWidth/innerHeight devtools detection'),
        # Must match actual detection globals/patterns — NOT XState's .devTools.send()
        # or React DevTools bridge internals.  Use word-boundary anchors and require
        # the token to stand alone or be accessed as a top-level check.
        (r'window\.__REACT_DEVTOOLS_GLOBAL_HOOK__|window\.devtools\b|window\._devtools\b'
         r'|firebug\.version\b|typeof\s+firebug\b',
         'DevTools global object detection'),
        (r'console\s*\.\s*(?:log|warn|error)\s*\(\s*(?:/%[sc]/|new\s+RegExp)',
         'Console-based devtools timing detection'),
    ]

    for pattern, desc in patterns:
        m = re.search(pattern, js, re.IGNORECASE)
        if m:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'JavaScript',
                'title': 'Developer tools detection attempt',
                'description': (
                    f'Script attempts to detect open developer tools ({desc}). '
                    'Malicious pages use this to alter behaviour when being analysed.'
                ),
                'evidence': f'[Detection technique: {desc}]\n{_snippet(js, m)}',
            })
            break

    return findings


def _check_sendbeacon_external(js: str, source_url: str) -> list[dict]:
    findings: list[dict] = []
    pattern = re.compile(
        r'navigator\.sendBeacon\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern.finditer(js):
        beacon_url = m.group(1)
        # Check if it's external (different host)
        if beacon_url.startswith('http') and source_url:
            from urllib.parse import urlparse
            src_host = urlparse(source_url).hostname or ''
            dst_host = urlparse(beacon_url).hostname or ''
            if src_host and dst_host and src_host != dst_host:
                if is_analytics(beacon_url):
                    # Known analytics/tag management endpoint — suppress finding
                    continue
                findings.append({
                    'severity': 'HIGH',
                    'category': 'JavaScript',
                    'title': 'navigator.sendBeacon to external domain',
                    'description': (
                        f'Script sends beacon data to external host "{dst_host}" '
                        f'(page origin: "{src_host}"). Often used for covert data exfiltration.'
                    ),
                    'evidence': m.group(0),
                })
    return findings


def _check_clipboard_hijacking(js: str) -> list[dict]:
    findings: list[dict] = []
    m = re.search(r'navigator\.clipboard\.writeText\s*\(', js, re.IGNORECASE)
    if not m:
        return findings

    # --- Check 1: Is the clipboard payload itself a shell command? -----------
    # ClickFix writes PowerShell/cmd payloads inside click handlers on fake
    # CAPTCHA buttons.  A click handler alone does NOT make a clipboard write
    # legitimate — we must inspect what is actually being written.
    # Check both: string literal argument AND any high-risk strings in the 2KB
    # surrounding the call (covers the variable-assignment pattern).
    _SHELL_CMD_RE = re.compile(
        r'powershell|mshta\.exe|mshta\b|cmd\.exe|rundll32|regsvr32|'
        r'wscript\.exe|cscript\.exe|wscript\b|cscript\b|'
        r'invoke-expression|\biex\b|invoke-restmethod|\birm\b|'
        # LoLBAS staging tools used in ClickFix DNS-staging chains (Microsoft, Jan 2026)
        r'nslookup\b|certutil\b|msiexec\b|'
        r'base64\s+-d|\|\s*bash|\|\s*sh\b|'
        r'curl\b.{0,40}https?://|wget\b.{0,40}https?://',
        re.IGNORECASE,
    )

    # Try literal string argument first (most reliable)
    write_arg_m = re.search(
        r'navigator\.clipboard\.writeText\s*\(\s*["\']([^"\']{10,})["\']',
        js, re.IGNORECASE,
    )
    # Also scan 2KB around the call for shell-command strings — covers variable pattern
    call_region = js[max(0, m.start() - 500):min(len(js), m.end() + 1500)]

    shell_in_arg = bool(write_arg_m and _SHELL_CMD_RE.search(write_arg_m.group(1)))
    shell_in_region = bool(_SHELL_CMD_RE.search(call_region))

    if shell_in_arg or shell_in_region:
        payload_evidence = (
            f'[Clipboard payload — literal argument]\n{write_arg_m.group(1)[:500]}'
            if write_arg_m else
            f'[Shell command indicator near writeText() call]\n{_snippet(js, m)}'
        )
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'ClickFix clipboard payload — shell command written to clipboard',
            'description': (
                'navigator.clipboard.writeText() is called with a value containing shell command '
                'indicators (PowerShell, cmd.exe, mshta, etc.). This is the ClickFix technique: '
                'a malicious command is placed in the clipboard while the user is socially '
                'engineered into pasting and executing it via a fake CAPTCHA or verification prompt. '
                'The click-handler context is irrelevant — the content itself is malicious.'
            ),
            'evidence': payload_evidence,
        })
        return findings  # CRITICAL already emitted — skip INFO/MEDIUM below

    # --- Check 2: ConsentFix — OAuth authorization URL written to clipboard --
    # ConsentFix (Push Security, Oct 2025) is a ClickFix variant that places an
    # OAuth authorization URL in the clipboard.  The victim pastes it into their
    # browser address bar, granting the attacker an OAuth token for a cloud app.
    # The payload contains no shell commands — only the OAuth URL — so the shell
    # check above misses it.  We detect it via the URL structure.
    _OAUTH_URL_RE = re.compile(
        r'(?:'
        r'client_id\s*=.{0,300}redirect_uri\s*=\s*https?://'
        r'|response_type\s*=\s*(?:code|token).{0,300}client_id\s*='
        r'|/oauth2?/(?:authorize|auth)[?&]'
        r')',
        re.IGNORECASE | re.DOTALL,
    )
    oauth_in_arg = bool(write_arg_m and _OAUTH_URL_RE.search(write_arg_m.group(1)))
    oauth_in_region = bool(_OAUTH_URL_RE.search(call_region))
    if oauth_in_arg or oauth_in_region:
        payload_evidence = (
            f'[OAuth clipboard payload — literal argument]\n{write_arg_m.group(1)[:500]}'
            if write_arg_m else
            f'[OAuth URL indicator near writeText() call]\n{_snippet(js, m)}'
        )
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'ConsentFix — OAuth authorization URL written to clipboard',
            'description': (
                'navigator.clipboard.writeText() is called with a value containing OAuth '
                'authorization URL parameters (client_id=, redirect_uri=, response_type=). '
                'This is the ConsentFix technique (Push Security, 2025): an evolution of '
                'ClickFix where the victim pastes an OAuth URL into their browser address bar, '
                'granting the attacker OAuth tokens for cloud applications (Microsoft 365, '
                'Google Workspace, etc.) without entering credentials. No endpoint execution '
                'is required — the attack happens entirely in the browser.'
            ),
            'evidence': payload_evidence,
        })
        return findings

    # --- Check 3: Is the write user-triggered (heuristic)? ------------------
    # Legitimate "copy to clipboard" buttons are inside click/event handlers.
    # Malicious clipboard hijackers fire on page load or in setInterval — not
    # in direct response to a user gesture.
    context_start = max(0, m.start() - 1000)
    context_end = min(len(js), m.end() + 200)
    surrounding_before = js[context_start:m.start()]
    surrounding_after = js[m.end():context_end]

    click_handler_re = re.compile(
        r'(?:addEventListener\s*\(\s*["\']click["\']'
        r'|onclick\s*='
        r'|on(?:click|mousedown|touchstart|pointerdown)\s*[=({]'
        r'|\.click\s*\()',
        re.IGNORECASE,
    )

    # Copy-intent names: function/variable names that indicate a copy button
    copy_intent_re = re.compile(
        r'(?:copy|copied|clipboard)',
        re.IGNORECASE,
    )

    is_user_triggered = (
        bool(click_handler_re.search(surrounding_before))
        or bool(copy_intent_re.search(surrounding_before))
        or bool(copy_intent_re.search(surrounding_after))
    )

    if is_user_triggered:
        # Likely a legitimate "copy" button — flag as INFO only
        findings.append({
            'severity': 'INFO',
            'category': 'JavaScript',
            'title': 'Clipboard write in click handler (copy button)',
            'description': (
                'Script writes to the clipboard inside a click handler. '
                'This is the standard implementation of a "copy to clipboard" button and is not malicious.'
            ),
            'evidence': f'[Clipboard write call]\n{_snippet(js, m)}',
        })
    else:
        # No recognisable user-gesture handler in the vicinity — could be
        # autonomous clipboard write (crypto address swap) or a copy button
        # whose click handler is defined elsewhere in the call chain.
        # Static analysis cannot distinguish these with certainty, so MEDIUM.
        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': 'Clipboard write outside recognisable click handler',
            'description': (
                'Script calls navigator.clipboard.writeText() with no recognisable click/event '
                'handler in the immediate vicinity. If this is not a user-triggered copy feature, '
                'it may silently replace clipboard content (e.g., crypto wallet addresses).'
            ),
            'evidence': f'[Clipboard write call]\n{_snippet(js, m)}',
        })
    return findings


def _check_execcommand_clipboard(js: str) -> list[dict]:
    """
    Detect legacy ClickFix clipboard writes using document.execCommand('copy').

    Older ClickFix pages (pre-2025) use the deprecated execCommand API instead of
    navigator.clipboard.writeText().  The pattern: a shell command string is
    assigned to a DOM element (textarea/input) which is then selected and copied.
    The payload string is near the execCommand call, not in its arguments.

    This is completely blind to _check_clipboard_hijacking() which only checks
    navigator.clipboard.writeText().
    """
    findings: list[dict] = []
    m = re.search(r"document\s*\.\s*execCommand\s*\(\s*['\"]copy['\"]\s*\)", js, re.IGNORECASE)
    if not m:
        return findings

    # Reuse the same shell-indicator regex as _check_clipboard_hijacking
    _SHELL_CMD_RE = re.compile(
        r'powershell|mshta\.exe|mshta\b|cmd\.exe|rundll32|regsvr32|'
        r'wscript\.exe|cscript\.exe|wscript\b|cscript\b|'
        r'invoke-expression|\biex\b|invoke-restmethod|\birm\b|'
        r'nslookup\b|certutil\b|msiexec\b|'
        r'base64\s+-d|\|\s*bash|\|\s*sh\b|'
        r'curl\b.{0,40}https?://|wget\b.{0,40}https?://',
        re.IGNORECASE,
    )

    # Scan the entire script for a shell payload — ClickFix pages vary widely in
    # how close the command string is to the execCommand call.  On compact pages
    # the assignment is a few lines above; on pages with more scaffolding (event
    # listener setup, DOM manipulation) the command variable can be defined
    # hundreds or thousands of chars away.  Searching the whole script is safe:
    # the co-occurrence of execCommand('copy') and a shell command in the same
    # script blob is already a very strong signal.
    shell_m = _SHELL_CMD_RE.search(js)
    if shell_m:
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'ClickFix clipboard payload — shell command written via execCommand',
            'description': (
                'document.execCommand("copy") is called with a shell command string '
                'visible in the surrounding context. This is the legacy ClickFix technique: '
                'a malicious command is written to a hidden DOM element, selected, then '
                'copied to the clipboard using the deprecated execCommand API, before the '
                'user is socially engineered into pasting and executing it. '
                'Functionally identical to the navigator.clipboard.writeText() variant.'
            ),
            'evidence': (
                f'[Shell indicator near execCommand("copy")]\n{shell_m.group(0)}\n\n'
                f'[Context]\n{_snippet(js, m)}'
            ),
        })
    else:
        # execCommand('copy') with no obvious shell payload — could be a legitimate
        # "copy to clipboard" button using the old API.  Flag MEDIUM (same reasoning
        # as the writeText() fallback: cannot confirm benign without user-gesture context).
        findings.append({
            'severity': 'MEDIUM',
            'category': 'JavaScript',
            'title': 'Clipboard write via legacy execCommand("copy")',
            'description': (
                'Script uses the deprecated document.execCommand("copy") to write to the '
                'clipboard. No shell command payload detected in the immediate context. '
                'May be a legacy "copy to clipboard" button or an obfuscated ClickFix payload '
                'where the command string is dynamically assembled.'
            ),
            'evidence': f'[execCommand copy call]\n{_snippet(js, m)}',
        })
    return findings


def _check_document_write_external_script(js: str) -> list[dict]:
    findings: list[dict] = []
    pattern = re.compile(
        r'document\.write\s*\([^)]*<script\s+src\s*=\s*["\']https?://',
        re.IGNORECASE | re.DOTALL,
    )
    matches = pattern.findall(js)
    if matches:
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'document.write() injects external script',
            'description': (
                'Script uses document.write() to inject an external script tag. '
                'This bypasses CSP and SRI protections and can introduce attacker-controlled code.'
            ),
            'evidence': matches[0],
        })
    return findings


def _extract_injected_script_src(window: str) -> str | None:
    """
    Extract the URL being assigned to a dynamically created script element.

    Handles three common patterns found in the 1500-char window after the
    createElement('script') call:

    1. String literal:   elem.src = 'https://...'   → return the URL as-is
    2. atob() call:      elem.src = atob('base64')   → decode and return the URL
    3. Variable ref:     elem.src = varName          → return the variable name
                         with the assignment value if it can be found nearby

    Returns None if no src assignment is detectable.
    """
    # Pattern 1: string literal  .src = "url"  or  ['src'] = "url"
    literal_m = re.search(
        r"""(?:\.src\s*=\s*|['"]\s*src\s*['"]\s*\]\s*=\s*)(['"])(https?://[^'"]{4,})\1""",
        window,
        re.IGNORECASE,
    )
    if literal_m:
        return literal_m.group(2).strip()

    # Pattern 2: atob()-encoded src  .src = atob('base64...')
    atob_m = re.search(
        r"""(?:\.src\s*=\s*|['"]\s*src\s*['"]\s*\]\s*=\s*)atob\s*\(\s*(['"])([\w+/=]{16,})\1\s*\)""",
        window,
        re.IGNORECASE,
    )
    if atob_m:
        import base64 as _b64
        try:
            decoded = _b64.b64decode(atob_m.group(2) + '==').decode('utf-8', errors='replace').strip()
            return f'{decoded}  [decoded from atob]'
        except Exception:
            return f'atob("{atob_m.group(2)}")  [decode failed]'

    # Pattern 3: variable reference  .src = varName
    var_m = re.search(
        r"""(?:\.src\s*=\s*|['"]\s*src\s*['"]\s*\]\s*=\s*)([$_a-zA-Z][$_a-zA-Z0-9]*)""",
        window,
        re.IGNORECASE,
    )
    if var_m:
        var_name = var_m.group(1)
        # Try to resolve the variable in the surrounding window by finding its
        # most recent string assignment: varName = 'value' or varName = "value"
        resolve_m = re.search(
            r"""\b""" + re.escape(var_name) + r"""\s*=\s*(['"])(https?://[^'"]{4,})\1""",
            window,
            re.IGNORECASE,
        )
        if resolve_m:
            return resolve_m.group(2).strip()
        return f'<variable: {var_name}>'

    return None


def _check_dom_script_injection(js: str, source_url: str = '') -> list[dict]:
    """
    Detect dynamic script injection via createElement('script') + src + appendChild.

    Functionally equivalent to document.write(<script src=...>) but evades naive
    detection and CSP report-only modes.  The createElement/src/appendChild triad
    is the standard DOM-based script loader used by ad injectors, Magecart skimmers,
    and JavaScript droppers to pull in a second-stage payload at runtime.

    Handles both dot-notation (elem.src = url) and bracket-notation
    (elem['src'] = url) so it catches hex-decoded obfuscated loaders too.

    Evidence block includes the extracted src URL (decoded if atob-wrapped) so
    analysts can identify the injected script without reading through the code.
    """
    # Analytics and tag-management scripts (GTM, GA, etc.) use this exact
    # pattern to load their tags at runtime — it is their intended mechanism,
    # not an attack.  Suppress when the script originates from a known-good
    # or analytics domain so we don't fire on GTM loading its own tag library.
    if source_url and (is_analytics(source_url) or is_known_good(source_url)):
        return []

    # Visual Website Optimizer (VWO) — its standard loader defines an internal
    # addScript() helper that uses the createElement/src/appendChild triad.
    # This is A/B testing infrastructure, not script injection.
    if '_vwo_code' in js or 'visualwebsiteoptimizer.com' in js:
        return []

    # WordPress emoji detection loader — tests emoji rendering support via
    # OffscreenCanvas/Canvas, then conditionally injects the emoji polyfill.
    # Fingerprinted by the `everythingExceptFlag` supports-object key, which is
    # unique to wp-emoji-release.min.js and does not appear in ad injectors or
    # Magecart skimmers.
    if 'everythingExceptFlag' in js:
        return []

    # Complianz GDPR consent management plugin — cmplz_run_script() is the
    # plugin's consent-gate loader: it holds third-party scripts and injects
    # them only after the visitor gives consent.  This is the plugin's core
    # function, not script injection by an attacker.
    if 'cmplz_run_script' in js or 'cmplz_banner' in js:
        return []

    # Match createElement('script') in both dot-notation and bracket-notation:
    #   dot:     document.createElement('script')   → createElement(
    #   bracket: document['createElement']('script') → createElement']('script')
    create_re = re.compile(
        r"createElement\s*(?:['\"]?\s*\])?\s*\(\s*['\"]script['\"]\s*\)",
        re.IGNORECASE,
    )

    # Determine whether the whole script is a webpack bundle at file level.
    # Webpack bundles always contain the __webpack_require__ runtime — any
    # createElement('script') inside is almost certainly a chunk loader.
    # Exception: we still fire when we can extract an explicit external URL
    # that is NOT a same-origin chunk path, because an attacker could inject
    # a malicious loader into a webpack-bundled page and hardcode the C2 URL.
    is_webpack_file = '__webpack_require__' in js or 'webpackChunk' in js

    findings = []
    for m in create_re.finditer(js):
        # Look for appendChild within 1500 chars after the createElement call
        forward_window = js[m.start(): min(len(js), m.start() + 1500)]

        has_append = bool(re.search(r'appendChild\b', forward_window, re.IGNORECASE))
        if not has_append:
            continue

        # src assignment in either notation
        has_src = bool(re.search(
            r"""(?:['"]\s*src\s*['"]\s*\]\s*=|\.src\s*=)""",
            forward_window,
            re.IGNORECASE,
        ))
        if not has_src:
            continue

        injected_src = _extract_injected_script_src(forward_window)

        # Variable URL — the forward window didn't contain the assignment.
        # Try the backward window (1000 chars before the createElement call):
        # video player libraries (YouTube/Vimeo API loaders) typically assign
        # the URL before the createElement call, not after.
        if injected_src and injected_src.startswith('<variable'):
            backward_window = js[max(0, m.start() - 1000): m.start()]
            injected_src_back = _extract_injected_script_src(backward_window + forward_window)
            if injected_src_back and not injected_src_back.startswith('<variable'):
                injected_src = injected_src_back

        # Webpack file: only fire if we have an explicit external https:// URL
        # that is not a known-good domain.  Variable URLs inside webpack bundles
        # are chunk loaders — always benign.
        if is_webpack_file:
            if not injected_src or injected_src.startswith('<variable'):
                continue  # webpack chunk loader with dynamic URL
            # Fall through to the known-good check below for explicit URLs

        # If the injected script src resolves to a known-good domain, suppress
        if injected_src and not injected_src.startswith('<variable'):
            if is_known_good(injected_src):
                continue

        evidence_parts = [f'[Injection code]\n{_snippet(js, m)}']
        if injected_src:
            evidence_parts.append(f'[Injected script URL]\n{injected_src}')

        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'Dynamic script injection — createElement + src + appendChild',
            'description': (
                'Script creates a <script> element, assigns an external src, and appends it '
                'to the document. This DOM-based loader is equivalent to document.write(<script src=...>) '
                'but harder to block with CSP and invisible to naive static analysis. '
                'Commonly used in ad injectors, Magecart skimmers, and JavaScript droppers to '
                'pull a second-stage payload into the page at runtime.'
            ),
            'evidence': '\n\n'.join(evidence_parts),
        })
        break  # one finding per script

    return findings


def _check_shell_dropper(js: str) -> list[dict]:
    """
    Detect shell command dropper strings embedded in JavaScript.

    Legitimate JavaScript has no reason to contain shell commands. The presence
    of bash/PowerShell dropper patterns — especially `base64 -d | bash` or
    `irm ... | iex` — is unambiguous evidence of a staged malware delivery
    mechanism, regardless of whether the JS decodes and executes them directly.

    SEC-04: All patterns are simple, bounded, and non-backtracking.  The original
    implementation used `[^|]{0,30}\\|` and `[^\\s"'|]{8,}` inside multi-
    alternation groups which caused catastrophic backtracking on crafted input.
    Replaced with independent signal checks — each is O(n); no cross-quantifier
    backtracking.  Two co-present signals (e.g. `base64 -d` AND `| bash`) are
    sufficient to identify a dropper without needing a single spanning regex.
    """
    findings: list[dict] = []

    # --- Independent signal checks (all O(n), no DOTALL, no nested quantifiers) ---

    # Unix dropper signals
    has_base64_decode = bool(re.search(r'base64\s+(?:-d|--decode)', js, re.IGNORECASE))
    has_pipe_shell = bool(re.search(r'\|\s*(?:ba?sh|zsh|ash)\b', js, re.IGNORECASE))
    is_unix_dropper = has_base64_decode and has_pipe_shell

    # PowerShell dropper signals
    has_ps_fetcher = bool(re.search(
        r'\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b', js, re.IGNORECASE
    ))
    has_iex = bool(re.search(r'\|\s*(?:iex|Invoke-Expression)\b', js, re.IGNORECASE))
    is_ps_dropper = has_ps_fetcher and has_iex

    # PowerShell download-and-execute: Invoke-WebRequest -OutFile <path> + Start-Process/Invoke-Item
    # This pattern writes an exe to disk then runs it — no pipe-to-iex required.
    has_outfile = bool(re.search(r'-OutFile\b', js, re.IGNORECASE))
    has_ps_execute = bool(re.search(r'\b(?:Start-Process|Invoke-Item)\b', js, re.IGNORECASE))
    is_ps_download_exec = has_ps_fetcher and has_outfile and has_ps_execute

    # curl/wget to a bare IP — bounded `[^\s"'<>{};]{0,40}` avoids backtracking
    curl_ip_m = re.search(
        r'(?:curl|wget)\b[^\s"\'<>{};]{0,40}https?://(\d{1,3}(?:\.\d{1,3}){3})/',
        js, re.IGNORECASE,
    )

    # bash -c shell execution string — simple literal anchor, no quantifier nesting
    bash_c_m = re.search(r'["\'/](?:bin/)?(?:bash|sh)\s+-c\s+["\']', js, re.IGNORECASE)

    # Locate the actual match objects for evidence snippets
    b64_m = re.search(r'base64\s+(?:-d|--decode)', js, re.IGNORECASE)
    pipe_shell_m = re.search(r'\|\s*(?:ba?sh|zsh|ash)\b', js, re.IGNORECASE)
    ps_fetch_m = re.search(r'\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b', js, re.IGNORECASE)
    iex_m = re.search(r'\|\s*(?:iex|Invoke-Expression)\b', js, re.IGNORECASE)
    outfile_m = re.search(r'-OutFile\b', js, re.IGNORECASE)
    ps_exec_m = re.search(r'\b(?:Start-Process|Invoke-Item)\b', js, re.IGNORECASE)

    # --- Emit findings ---

    if is_unix_dropper:
        ip_note = (
            f' Payload fetched from bare IP {curl_ip_m.group(1)} — '
            'characteristic of malicious C2 infrastructure.'
            if curl_ip_m else ''
        )
        evidence_parts = []
        if b64_m:
            evidence_parts.append(f'[Base64 decode signal]\n{_snippet(js, b64_m)}')
        if pipe_shell_m:
            evidence_parts.append(f'[Pipe-to-shell signal]\n{_snippet(js, pipe_shell_m)}')
        if curl_ip_m:
            evidence_parts.append(f'[C2 bare-IP fetch]\n{_snippet(js, curl_ip_m)}')
        # Extract and decode the base64 payload from `echo <b64> | base64 -d`
        echo_b64_m = re.search(r"echo\s+['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|", js, re.IGNORECASE)
        if echo_b64_m:
            decoded = _try_b64_decode(echo_b64_m.group(1))
            if decoded:
                evidence_parts.append(f'[Decoded shell payload]\n{decoded}')
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'Unix shell dropper embedded in JavaScript',
            'description': (
                'A `base64 -d | bash` shell dropper command is stored as a string in this script. '
                'This is a staged malware delivery pattern: the base64 payload decodes to a shell '
                'command that downloads and executes a remote binary, bypassing static AV signatures.'
                + ip_note
            ),
            'evidence': '\n\n'.join(evidence_parts) if evidence_parts else 'base64 decode + pipe-to-shell signals detected',
        })

    if is_ps_dropper:
        evidence_parts = []
        if ps_fetch_m:
            evidence_parts.append(f'[PowerShell remote fetch]\n{_snippet(js, ps_fetch_m)}')
        if iex_m:
            evidence_parts.append(f'[Invoke-Expression execution]\n{_snippet(js, iex_m)}')
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'PowerShell dropper embedded in JavaScript',
            'description': (
                'An `irm/Invoke-RestMethod ... | iex` PowerShell dropper command is stored as a '
                'string in this script. This is a fileless malware delivery technique: the remote '
                'script is fetched and immediately executed in memory, leaving no file on disk.'
            ),
            'evidence': '\n\n'.join(evidence_parts) if evidence_parts else 'Invoke-RestMethod/irm + Invoke-Expression/iex signals detected',
        })

    if is_ps_download_exec:
        evidence_parts = []
        if ps_fetch_m:
            evidence_parts.append(f'[PowerShell download command]\n{_snippet(js, ps_fetch_m)}')
        if outfile_m:
            evidence_parts.append(f'[-OutFile write-to-disk]\n{_snippet(js, outfile_m)}')
        if ps_exec_m:
            evidence_parts.append(f'[Execution command]\n{_snippet(js, ps_exec_m)}')
        findings.append({
            'severity': 'CRITICAL',
            'category': 'JavaScript',
            'title': 'PowerShell download-and-execute dropper in JavaScript',
            'description': (
                'A PowerShell command sequence is embedded in this script that downloads a file '
                'using `Invoke-WebRequest -OutFile` and immediately executes it with `Start-Process` '
                'or `Invoke-Item`. This is a disk-based malware delivery technique: the payload is '
                'written to a temporary path (commonly `$env:TEMP`) and launched as a process, '
                'bypassing in-memory execution restrictions. Commonly used in ClickFix campaigns '
                'to deliver info-stealers (Lumma, Vidar) and RATs.'
            ),
            'evidence': '\n\n'.join(evidence_parts) if evidence_parts else 'Invoke-WebRequest -OutFile + Start-Process signals detected',
        })

    # Only fire bash -c as a standalone finding if the full dropper wasn't already flagged
    if bash_c_m and not is_unix_dropper:
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'Shell command execution string in JavaScript',
            'description': (
                'A string containing a shell command (`bash -c` / `/bin/bash -c`) is present in '
                'this script. JavaScript has no legitimate reason to embed shell execution strings; '
                'this is consistent with a dropper, command injection payload, or exploitation kit.'
            ),
            'evidence': f'[Shell execution string]\n{_snippet(js, bash_c_m)}',
        })

    # Bare-IP curl/wget without the full dropper pattern still warrants HIGH
    if curl_ip_m and not is_unix_dropper:
        ip = curl_ip_m.group(1)
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': f'Outbound fetch to bare IP address ({ip}) in JavaScript',
            'description': (
                f'Script contains a curl/wget call to a bare IP address ({ip}) rather than a '
                'domain name. Malicious actors use raw IP addresses for C2 infrastructure to '
                'avoid domain takedowns and reputation blacklists.'
            ),
            'evidence': f'[C2 fetch command]\n{_snippet(js, curl_ip_m)}',
        })

    return findings


# ---------------------------------------------------------------------------
# Living off Trusted Sites (LoTS) exfiltration targets
# ---------------------------------------------------------------------------

_LOTS_TARGETS: list[tuple[str, str]] = [
    ('api.telegram.org', 'Telegram Bot API'),
    ('discord.com/api/webhooks', 'Discord Webhook'),
    ('discordapp.com/api/webhooks', 'Discord Webhook'),
    ('hooks.slack.com', 'Slack Incoming Webhook'),
    ('script.google.com/macros', 'Google Apps Script'),
    ('docs.google.com/forms', 'Google Forms'),
    ('webhook.site', 'Webhook.site'),
    ('pipedream.net', 'Pipedream Webhook'),
    ('requestbin.com', 'RequestBin'),
    ('pastebin.com/api', 'Pastebin API'),
]


def _check_html_smuggling(js: str) -> list[dict]:
    """
    Detect HTML smuggling: a payload assembled client-side using the Blob API and
    auto-downloaded, bypassing email gateways and network DLP controls entirely.
    The file never traverses the network as a recognisable binary.
    Actively used by Qakbot/BazarLoader successors and initial access brokers.

    Requires all three signals AND proximity: Blob construction + createObjectURL +
    a download trigger — all within 2500 chars of each other.

    The download trigger must be .download= (the HTML5 attribute that forces a save
    dialog), msSaveBlob, or msSaveOrOpenBlob.  Bare .click() is intentionally excluded:
    it appears in countless legitimate patterns (UI interactions, webpack chunk loading,
    Next.js code splitting) and its presence alone across a whole file does not
    indicate payload delivery.  Real HTML smuggling always sets .download on the anchor.
    """
    findings: list[dict] = []

    # Step 1: find Blob construction
    blob_m = re.search(r'new\s+Blob\s*\(\s*\[', js, re.IGNORECASE)
    if not blob_m:
        return findings

    # Step 2: find createObjectURL within 2500 chars of the Blob construction
    # (search in both directions to handle varied code ordering)
    _PROXIMITY = 2500
    blob_pos = blob_m.start()
    search_start = max(0, blob_pos - _PROXIMITY)
    search_end = min(len(js), blob_pos + _PROXIMITY)
    window = js[search_start:search_end]

    obj_url_m = re.search(r'URL\.createObjectURL\s*\(', window, re.IGNORECASE)
    if not obj_url_m:
        return findings
    # Adjust match position to be absolute
    obj_url_abs = search_start + obj_url_m.start()

    # Step 3: find a download trigger within 2500 chars of the createObjectURL call
    trigger_start = max(0, obj_url_abs - _PROXIMITY)
    trigger_end = min(len(js), obj_url_abs + _PROXIMITY)
    trigger_window = js[trigger_start:trigger_end]

    trigger_m = re.search(
        r'(?:\.download\s*=|msSaveOrOpenBlob|msSaveBlob)',
        trigger_window, re.IGNORECASE,
    )
    if not trigger_m:
        return findings

    evidence_parts = [
        f'[Blob construction]\n{_snippet(js, blob_m)}',
        f'[Object URL creation]\n{_snippet(js, obj_url_m)}',
        f'[Auto-download trigger]\n{_snippet(js, trigger_m)}',
    ]
    # Attempt to decode any base64 payload inside the Blob
    atob_m = re.search(r'atob\s*\(\s*["\']([A-Za-z0-9+/=\-_]{16,})["\']', js, re.IGNORECASE)
    if atob_m:
        decoded = _try_b64_decode(atob_m.group(1))
        if decoded:
            evidence_parts.append(f'[Decoded Blob payload]\n{decoded}')

    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'HTML smuggling — Blob-assembled payload download',
        'description': (
            'Script constructs a file payload in-browser using the Blob API, creates an object URL, '
            'and triggers an automatic download. This is HTML smuggling: the file never traverses the '
            'network as a recognisable binary, bypassing email gateways and network DLP controls. '
            'Actively used by Qakbot/BazarLoader successors and initial access brokers.'
        ),
        'evidence': '\n\n'.join(evidence_parts),
    })
    return findings


def _check_wallet_drainer(js: str) -> list[dict]:
    """
    Detect Web3 wallet drainer scripts.
    Requires Ethereum provider access plus either a transaction/signing call or an
    exfiltration endpoint — the combination distinguishes drainers from read-only dApps.
    Active drainer families: Inferno Drainer successors, Angel Drainer, Pink Drainer.
    """
    findings: list[dict] = []
    eth_m = re.search(
        r'window\.ethereum\b|ethereum\.request\s*\(|eth_requestAccounts|web3\.eth\b',
        js, re.IGNORECASE,
    )
    if not eth_m:
        return findings

    tx_m = re.search(
        r'eth_sendTransaction|eth_signTypedData|personal_sign|'
        r'eth_sendRawTransaction|wallet_addEthereumChain|eth_sign\b',
        js, re.IGNORECASE,
    )
    exfil_m = re.search(
        r'(?:fetch|sendBeacon)\s*\(\s*["\']https?://',
        js, re.IGNORECASE,
    )
    if not tx_m and not exfil_m:
        return findings

    evidence_parts = [f'[Ethereum provider access]\n{_snippet(js, eth_m)}']
    if tx_m:
        evidence_parts.append(f'[Transaction / signing call]\n{_snippet(js, tx_m)}')
    if exfil_m:
        evidence_parts.append(f'[Exfiltration endpoint]\n{_snippet(js, exfil_m)}')

    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'Web3 wallet drainer script detected',
        'description': (
            'Script accesses the Ethereum provider (window.ethereum) and initiates transaction signing '
            'or approval requests. This is the operational pattern of Web3 wallet drainers that trick '
            'users into signing malicious transactions, transferring NFTs or tokens to attacker wallets. '
            'Active drainer families include successors to Inferno Drainer and Angel Drainer.'
        ),
        'evidence': '\n\n'.join(evidence_parts),
    })
    return findings


def _check_service_worker_abuse(js: str) -> list[dict]:
    """
    Detect suspicious service worker registrations.
    Legitimate SWs are always same-origin static files (e.g. /sw.js).
    External URLs, blob: URIs, or data: URIs indicate malicious intent:
    the SW persists after the tab closes and intercepts all future requests.
    """
    findings: list[dict] = []
    sw_m = re.search(r'navigator\.serviceWorker\.register\s*\(', js, re.IGNORECASE)
    if not sw_m:
        return findings

    url_m = re.search(
        r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
        js, re.IGNORECASE,
    )
    sw_url = url_m.group(1) if url_m else ''
    is_external = sw_url.startswith('http')
    is_blob = sw_url.startswith('blob:')
    is_data = sw_url.startswith('data:')

    if not (is_external or is_blob or is_data):
        return findings

    if is_blob or is_data:
        severity = 'CRITICAL'
        url_desc = (
            'a blob: URL (payload constructed in memory — no static URL to block or inspect)'
            if is_blob else
            'a data: URI (service worker code embedded inline)'
        )
    else:
        severity = 'HIGH'
        url_desc = f'an external domain ("{sw_url}")'

    findings.append({
        'severity': severity,
        'category': 'JavaScript',
        'title': 'Suspicious service worker registration',
        'description': (
            f'Script registers a service worker from {url_desc}. '
            'Service workers persist after the tab is closed and intercept all future requests '
            'to the affected origin, enabling persistent credential theft, offline phishing pages, '
            'and request manipulation. Legitimate service workers are always same-origin static files.'
        ),
        'evidence': _snippet(js, sw_m),
    })
    return findings


def _check_lots_exfiltration(js: str) -> list[dict]:
    """
    Detect Living off Trusted Sites (LoTS) exfiltration.
    Matches fetch()/sendBeacon() calls where the URL argument contains a known
    platform endpoint abused for data exfiltration. Anchoring to the call (not just
    a link or comment) avoids false positives from legitimate embeds or mentions.
    """
    findings: list[dict] = []
    for domain, service in _LOTS_TARGETS:
        pattern = re.compile(
            r'(?:fetch|sendBeacon)\s*\(\s*["\'][^"\']*'
            + re.escape(domain)
            + r'[^"\']*["\']',
            re.IGNORECASE,
        )
        m = pattern.search(js)
        if m:
            findings.append({
                'severity': 'HIGH',
                'category': 'JavaScript',
                'title': f'Data exfiltration via legitimate service ({service})',
                'description': (
                    f'Script calls fetch() or sendBeacon() targeting a {service} endpoint ({domain}). '
                    'Attackers route stolen credentials, cookies, and keystrokes through legitimate '
                    'platforms to evade domain-reputation blocklists — Living off Trusted Sites (LoTS). '
                    'This technique is heavily used in current phishing kits and payment skimmers.'
                ),
                'evidence': _snippet(js, m),
            })
    return findings


def _check_fetch_eval(js: str) -> list[dict]:
    """
    Detect fetch() + eval() / new Function() chained via async bridge.

    Remote-code-execution pattern common in compromised WordPress sites: an
    injected snippet fetches a malicious payload URL asynchronously and then
    eval()s the response body, keeping the actual malware off the page source.

    Requires:
      1. fetch() call in the script.
      2. eval() or new Function() within 1500 chars downstream.
      3. An async bridge (await / .then()) between them — this distinguishes a
         fetch-then-eval chain from a file that happens to contain both calls in
         completely unrelated contexts.

    False-positive rate: near zero.  Legitimate code never fetches a URL and
    evaluates its text body as executable JavaScript.
    """
    findings: list[dict] = []

    fetch_m = re.search(r'\bfetch\s*\(', js, re.IGNORECASE)
    if not fetch_m:
        return findings

    # Search for eval/new Function within 1500 chars of the fetch call
    window_start = fetch_m.start()
    window_end = min(len(js), window_start + 1500)
    eval_m_rel = re.search(
        r'\beval\s*\(|new\s+Function\s*\(',
        js[window_start:window_end],
        re.IGNORECASE,
    )
    if not eval_m_rel:
        return findings

    eval_abs_start = window_start + eval_m_rel.start()

    # Require an async bridge (await / .then) between fetch and eval
    between = js[fetch_m.end():eval_abs_start]
    if not re.search(r'\.then\s*\(|\bawait\b', between, re.IGNORECASE):
        return findings

    eval_snippet = js[eval_abs_start:eval_abs_start + 200].strip()

    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'Remote code execution — fetch() result evaluated via eval()',
        'description': (
            'Script fetches a remote resource and evaluates the response with eval() '
            'or new Function(). This is a remote-code-execution pattern prevalent in '
            'compromised WordPress sites: an injected snippet fetches a malicious payload '
            'asynchronously and executes it, keeping the actual malware off the page source '
            'and bypassing file-based detection.'
        ),
        'evidence': (
            f'[Remote fetch]\n{_snippet(js, fetch_m)}\n\n'
            f'[Dynamic execution]\n{eval_snippet}'
        ),
    })
    return findings


def _check_decrypt_exec(js: str) -> list[dict]:
    """
    Detect decrypt-then-execute pattern: WebCrypto API + eval()/new Function().

    Sophisticated malware stores payloads in encrypted form and decrypts them at
    runtime using the browser-native WebCrypto API (crypto.subtle).  The decrypted
    plaintext is then passed to eval() or new Function() for execution.  The payload
    is never present in plaintext in the source or in network traffic, defeating
    most static analysis and network DLP controls.

    False-positive rate: near zero.  There is no legitimate reason to decrypt data
    and then immediately evaluate it as executable JavaScript.
    """
    findings: list[dict] = []
    decrypt_m = re.search(
        r'crypto\.subtle\.(?:decrypt|importKey|deriveKey|deriveBits)\s*\(',
        js, re.IGNORECASE,
    )
    if not decrypt_m:
        return findings

    eval_m = re.search(r'\beval\s*\(|new\s+Function\s*\(', js, re.IGNORECASE)
    if not eval_m:
        return findings

    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'Decrypt-then-execute pattern (WebCrypto + eval)',
        'description': (
            'Script uses the WebCrypto API (crypto.subtle) alongside eval() or new Function(). '
            'This decrypt-then-execute pattern is used by sophisticated malware to store payloads '
            'in encrypted form, decrypting and executing them at runtime to evade static analysis '
            'and AV scanning. The payload is never present in plaintext in the source or network traffic.'
        ),
        'evidence': (
            f'[WebCrypto operation]\n{_snippet(js, decrypt_m)}\n\n'
            f'[Dynamic execution]\n{_snippet(js, eval_m)}'
        ),
    })
    return findings


def _check_xor_string_array_obfuscation(js: str) -> list[dict]:
    """
    Detects polymorphic XOR byte-encoded string array obfuscation.

    The pattern: a JS array of 8+ hex-encoded strings (each entry consists of
    pairs of hex digits representing XOR'd ASCII bytes) combined with a decode
    function that uses parseInt(s.substr(j,2),16)^KEY.  This encodes all API
    endpoints, method names, and redirect URLs to defeat static analysis.

    Used by TDS/cloaking malware — biometrie-sante-carte.com campaign (Apr 2026).
    The obfuscation key and variable names are randomised per request (polymorphic),
    so checking for a fixed variable name like _0x is insufficient.
    """
    findings: list[dict] = []

    # Require the XOR decode idiom: parseInt(expr, 16) ^ variable
    # Use lazy .{1,80}? to handle nested-call args like s.substr(j,2)
    if not re.search(r'parseInt\s*\(.{1,80}?,\s*16\)\s*\^\s*\w+', js, re.IGNORECASE | re.DOTALL):
        return findings

    # Look for an array containing 8+ hex-only even-length strings (byte pairs)
    array_re = re.compile(r"var\s+\w+\s*=\s*\[([^\]]{50,})\]", re.DOTALL)
    hex_str_re = re.compile(r"'([0-9a-fA-F]{4,})'")
    for m in array_re.finditer(js):
        candidates = hex_str_re.findall(m.group(1))
        valid = [s for s in candidates if len(s) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', s)]
        if len(valid) >= 8:
            findings.append({
                'severity': 'HIGH',
                'category': 'JavaScript',
                'title': f'Polymorphic XOR string-array obfuscation ({len(valid)} encoded strings)',
                'description': (
                    f'Script contains an array of {len(valid)} XOR byte-encoded strings paired with a '
                    'decode function using parseInt(s.substr(j,2),16)^KEY.  This technique encodes all '
                    'API endpoints, JS method names, and redirect URLs to hide them from static analysis. '
                    'It is characteristic of Traffic Direction Systems (TDS) and cloaking malware that '
                    'fingerprint visitors and redirect real users to phishing or malware infrastructure '
                    'while showing clean content to automated crawlers and scanners.  The obfuscation '
                    'key and variable names are randomised per request (polymorphic).'
                ),
                'evidence': m.group(0)[:600],
            })
            break
    return findings


def _check_tds_fingerprint_redirect(js: str) -> list[dict]:
    """
    Detects Traffic Direction System (TDS) / server-response-based cloaking.

    Visitor fingerprint data (navigator.userAgent, navigator.language) is
    collected and POSTed to a remote server via fetch().  Based on the JSON
    response, the server decides whether to redirect the visitor to attack
    infrastructure (phishing, malware) or return them to a clean page.  This
    makes the redirect destination invisible to static analysis — it only
    appears at runtime for real user sessions.

    All five structural tokens (navigator fingerprint, fetch, JSON, .then chain,
    window redirect) must be present in the same script to fire.
    False-positive rate: near zero — this combination does not appear in
    legitimate single-page applications.
    """
    findings: list[dict] = []

    has_fetch = bool(re.search(r'\bfetch\s*\(', js))
    has_then = bool(re.search(r'\.then\s*\(', js))
    has_json = bool(re.search(r'\bJSON\s*[\.\[]', js))
    # Covers both dot-notation and bracket-notation (obfuscated) window redirects
    has_window_assign = bool(re.search(
        r'window(?:\.location|\s*\[[^\]]+\])(?:\.href|\.replace|\s*\[[^\]]+\])?\s*=(?!=)',
        js, re.IGNORECASE,
    ))
    # Require navigator fingerprint data to appear WITHIN the fetch() call body,
    # not just anywhere in the file.  A large bundle may independently contain
    # navigator.userAgent (for responsive design) and an unrelated fetch() call;
    # a real TDS script must collect the fingerprint and POST it together.
    has_fingerprint_in_fetch = bool(re.search(
        r'\bfetch\s*\([^;]{0,600}navigator\s*\.\s*(?:userAgent|language|platform)',
        js, re.IGNORECASE | re.DOTALL,
    ))

    if has_fingerprint_in_fetch and has_fetch and has_then and has_json and has_window_assign:
        fetch_m = re.search(r'\bfetch\s*\([^;]{0,300}', js, re.DOTALL)
        evidence = fetch_m.group(0)[:400].strip() if fetch_m else '(fetch call obfuscated)'
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'Traffic Direction System (TDS): server-response-based cloaking redirect',
            'description': (
                'Script collects browser fingerprint data (navigator.userAgent / navigator.language) '
                'and POSTs it to a remote server via fetch(), then assigns window.location based on '
                'the server\'s JSON response.  This is the signature of a Traffic Direction System '
                '(TDS) / cloaking attack: the server distinguishes real users from bots and redirects '
                'victims to phishing or malware pages while returning a clean page to automated '
                'scanners.  The redirect destination is controlled entirely by the server and is '
                'never present in the page source, defeating static analysis.'
            ),
            'evidence': evidence,
        })
    return findings


def _check_dynamic_import_external(js: str) -> list[dict]:
    """
    Detect dynamic import() calls loading from external absolute URLs.

    Legitimate dynamic imports use relative paths (./chunk-abc.js, ../lib/x.js)
    or known CDN hostnames.  Importing from an arbitrary https:// URL is a code
    injection technique: the attacker hosts a malicious ES module at a remote URL
    and the injected script loads it without touching the page source.

    False-positive rate: low.  Known-good CDN URLs are suppressed.
    """
    findings: list[dict] = []
    for m in re.finditer(r'\bimport\s*\(\s*["\']https?://', js, re.IGNORECASE):
        # Extract the full URL string
        url_m = re.match(r'\bimport\s*\(\s*["\']([^"\']+)["\']', js[m.start():], re.IGNORECASE)
        import_url = url_m.group(1) if url_m else ''
        if import_url and is_known_good(import_url):
            continue
        findings.append({
            'severity': 'HIGH',
            'category': 'JavaScript',
            'title': 'Dynamic import() from external URL',
            'description': (
                'Script uses a dynamic import() call targeting an external absolute URL. '
                'Legitimate dynamic imports reference relative paths or known CDN assets. '
                'Loading ES modules from arbitrary external URLs is a code injection technique '
                'used to deliver malicious payloads without embedding them in the page source.'
            ),
            'evidence': _snippet(js, m),
        })
        break  # one finding per script

    return findings


# ---------------------------------------------------------------------------
# REC-01 — JSFuck / JSFireTruck obfuscation
# ---------------------------------------------------------------------------

def _check_jsfuck_obfuscation(js: str) -> list[dict]:
    """
    Detect JSFuck / JSFireTruck obfuscation — JavaScript encoded using only []()+!.

    JSFuck (2009) and its derivative JSFireTruck encode arbitrary JavaScript using
    six characters via type coercion.  All existing obfuscation checks (hex, entropy,
    fromCharCode, _0x) are completely blind to this encoding.

    Signal: 300+ consecutive characters drawn exclusively from [ ] ( ) + !
    This density is impossible in legitimate code.  Over 269,000 websites were
    compromised with JSFireTruck in a single month (Unit 42 / Palo Alto, Apr 2025).
    """
    findings: list[dict] = []
    m = re.search(r'[\[\]()+!]{300,}', js)
    if not m:
        return findings
    matched = m.group(0)
    snippet_val = matched[:200] + ('...' if len(matched) > 200 else '')
    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'JSFuck/JSFireTruck obfuscation detected',
        'description': (
            'A block of JavaScript encoded using only the six characters []()+! was found. '
            'This technique (JSFuck / JSFireTruck) uses JavaScript type coercion to represent '
            'arbitrary code — all standard obfuscation checks (hex escapes, entropy, fromCharCode, '
            '_0x) are blind to it. Over 269,000 websites were compromised with JSFireTruck in a '
            'single month in 2025 (Unit 42). The encoded segment must be decoded to determine '
            'its purpose — the obfuscation itself is the threat indicator.'
        ),
        'evidence': f'[JSFuck/JSFireTruck encoded segment — {len(matched)} chars]\n{snippet_val}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-02 — JJEncode obfuscation
# ---------------------------------------------------------------------------

def _check_jjencode_obfuscation(js: str) -> list[dict]:
    """
    Detect JJEncode obfuscation — JavaScript encoded using an 18-character ASCII set.

    JJEncode produces a distinctive initialisation: $=~[] followed by a structured
    object with property names like ___, $$$$, etc.  Companion technique to JSFuck.
    """
    findings: list[dict] = []
    m = re.search(r'\$\s*=\s*~\[\]|\$\$\s*=\s*!\[\]', js)
    if not m:
        return findings
    # Require ≥200 chars in the surrounding context to exclude incidental
    # bitwise NOT expressions like `$=~0` in compact utility code.
    vicinity = js[max(0, m.start() - 20): min(len(js), m.end() + 500)]
    if len(vicinity.strip()) < 200:
        return findings
    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'JJEncode obfuscation detected',
        'description': (
            'A JJEncode initialisation pattern ($=~[] or $$=![]) was found. '
            'JJEncode encodes arbitrary JavaScript using an 18-character ASCII set, '
            'making the code unreadable and bypassing signature-based detection. '
            'JJEncode is used in malvertising and web compromise campaigns to hide '
            'redirect chains and payload droppers. The encoded segment must be decoded '
            'to determine its purpose.'
        ),
        'evidence': f'[JJEncode initialisation]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-03 — NDSW / NDSX WordPress injection (Balada Injector family)
# ---------------------------------------------------------------------------

def _check_ndsw_injection(js: str) -> list[dict]:
    """
    Detect Balada Injector / NDSW/NDSX WordPress malware.

    The NDSW/NDSX campaign is one of the most prolific WordPress compromise
    vectors — 43,106 detections in H1 2024 alone (Sucuri SiteCheck).  The malware
    checks a global sentinel variable before executing, using a PHP proxy to
    dynamically serve the injection.  It redirects search-engine visitors to
    attacker sites while hiding the redirect from logged-in admins.

    The sentinel variable names (ndsw, ndsx, ndsy, ndsz) are unique to this
    campaign — false positives are essentially impossible.
    """
    findings: list[dict] = []
    m = re.search(
        r'if\s*\(\s*nds[wxyz]\s*===\s*undefined\s*\)',
        js, re.IGNORECASE,
    )
    if not m:
        return findings
    findings.append({
        'severity': 'CRITICAL',
        'category': 'JavaScript',
        'title': 'NDSW/NDSX WordPress malware injection (Balada Injector family)',
        'description': (
            'The NDSW/NDSX malware sentinel variable check was found — a campaign-unique '
            'identifier with no legitimate use. This is one of the most active WordPress '
            'compromise vectors: 43,000+ detections in H1 2024 (Sucuri). The malware '
            'checks if a global variable (ndsw, ndsx, ndsy, ndsz) is undefined, then '
            'executes its payload via a PHP proxy that dynamically serves the injection. '
            'Visitors arriving from search engines are redirected to attacker-controlled '
            'sites; logged-in admins see clean content. The site is compromised — the '
            'full WordPress installation and all plugins require immediate auditing.'
        ),
        'evidence': f'[NDSW sentinel check]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-05 — Checkout-page skimmer activation gate
# ---------------------------------------------------------------------------

def _check_skimmer_activation_gate(js: str) -> list[dict]:
    """
    Detect Magecart checkout-page activation gates.

    Modern skimmers restrict execution to checkout pages to evade scanners that
    only analyse the homepage.  The activation gate itself is present in the
    static source — revealing the skimmer's existence even when the scanner
    does not visit the checkout page.

    Requires: URL-check pattern (location.href.includes('checkout')) in proximity
    to either a card-field DOM selector or an outbound exfiltration call.
    """
    findings: list[dict] = []

    gate_re = re.compile(
        r'(?:location\.href|location\.pathname|document\.URL|window\.location\b)'
        r'\s*\.(?:includes|indexOf|match|search)\s*\(\s*["\']'
        r'(?:checkout|payment|billing|order|purchase|cart)["\']',
        re.IGNORECASE,
    )
    m = gate_re.search(js)
    if not m:
        return findings

    _PROXIMITY = 3000
    region = js[max(0, m.start() - _PROXIMITY): min(len(js), m.end() + _PROXIMITY)]

    card_field_re = re.compile(
        r'(?:querySelector(?:All)?|getElementById|getElementsByName|name\s*[=:]\s*["\'])'
        r'[^;]{0,80}'
        r'(?:card[-_]?(?:number|num|holder|no\b)|cvv|cvc|cv2|ccv|expir|pan\b|cc[-_]?num)',
        re.IGNORECASE,
    )
    exfil_re = re.compile(
        r'(?:fetch\s*\(|sendBeacon\s*\(|new\s+XMLHttpRequest|new\s+Image\s*\(\s*\))',
        re.IGNORECASE,
    )

    if not (card_field_re.search(region) or exfil_re.search(region)):
        return findings

    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'Checkout-page skimmer activation gate',
        'description': (
            'A script checks the current URL for a payment/checkout context before executing, '
            'in proximity to card-field selectors or outbound network calls. '
            'This is the activation gate pattern used by modern Magecart skimmers to restrict '
            'execution to checkout pages — evading scanners that only analyse the homepage. '
            'The skimmer code is present in the source even though its payload fires only '
            'on the checkout page. The merchant site requires immediate investigation.'
        ),
        'evidence': f'[Activation gate]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-06 — MutationObserver-based payment skimmer
# ---------------------------------------------------------------------------

def _check_mutation_observer_skimmer(js: str) -> list[dict]:
    """
    Detect MutationObserver-based payment skimmers.

    Modern Magecart skimmers register a MutationObserver to defer card capture
    until payment elements appear in the DOM.  The existing _check_payment_skimmer
    requires an explicit querySelector card-field call; this check catches the
    variant where the observer iterates e.addedNodes / e.target without an
    explicit querySelector, making it invisible to the primary skimmer check.

    Fires when MutationObserver + card-field keywords + exfiltration appear in
    proximity — regardless of whether querySelector is present.
    """
    findings: list[dict] = []

    mo_re = re.compile(r'new\s+MutationObserver\s*\(', re.IGNORECASE)
    m = mo_re.search(js)
    if not m:
        return findings

    _PROXIMITY = 3000
    region = js[max(0, m.start() - _PROXIMITY): min(len(js), m.end() + _PROXIMITY)]

    card_re = re.compile(
        r'card[-_\s]?(?:number|num|holder|name|no\b)|'
        r'cvv|cvc|cv2|ccv|security[-_\s]?code|expir|pan\b|cc[-_]?num|'
        r'credit[-_\s]?card',
        re.IGNORECASE,
    )
    exfil_re = re.compile(
        r'(?:fetch\s*\(|sendBeacon\s*\(|new\s+XMLHttpRequest|new\s+Image\s*\(\s*\)|\.send\s*\()',
        re.IGNORECASE,
    )

    if not (card_re.search(region) and exfil_re.search(region)):
        return findings

    # Avoid double-reporting if _check_payment_skimmer already fires — it also
    # checks for MutationObserver as a corroborating signal.
    # This check covers the non-querySelector variant; if querySelector IS present
    # the primary skimmer check will produce a CRITICAL, so only emit HIGH here
    # if no explicit card DOM query is in the region.
    dom_query_re = re.compile(
        r'querySelector(?:All)?\s*\(\s*["\'][^"\']*'
        r'(?:card|cvv|cvc|expir|pan\b|cc[-_]?num)',
        re.IGNORECASE,
    )
    if dom_query_re.search(region):
        return findings  # _check_payment_skimmer will cover this more precisely

    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'MutationObserver-based payment skimmer',
        'description': (
            'A MutationObserver registration was found in proximity to payment card keywords '
            'and an outbound exfiltration call. Modern Magecart skimmers defer card capture '
            'until payment elements appear in the DOM via MutationObserver, avoiding detection '
            'by scanners that only analyse page-load behaviour. This pattern was documented '
            'by Malwarebytes Labs and SecurityMetrics as a primary evasion technique in 2025.'
        ),
        'evidence': f'[MutationObserver registration]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-07 — Blob-URI iframe injection (GhostFrame phishing technique)
# ---------------------------------------------------------------------------

def _check_blob_iframe_injection(js: str) -> list[dict]:
    """
    Detect blob-URI iframe injection (GhostFrame phishing, PhishFort 2025-2026).

    GhostFrame constructs a Blob from HTML content containing a phishing form,
    creates an object URL, and assigns it to an iframe's src.  This bypasses CSP
    frame-src directives (blob: is treated as same-origin) and defeats static HTML
    form analysis (the form is inside the blob, not in page source).

    Distinct from _check_html_smuggling which requires a .download trigger —
    this uses iframe.src instead of a forced file download.
    """
    findings: list[dict] = []

    blob_m = re.search(r'new\s+Blob\s*\(\s*\[', js, re.IGNORECASE)
    if not blob_m:
        return findings

    _PROXIMITY = 2500
    blob_pos = blob_m.start()
    search_window = js[max(0, blob_pos - _PROXIMITY): min(len(js), blob_pos + _PROXIMITY)]

    obj_url_m = re.search(r'URL\.createObjectURL\s*\(', search_window, re.IGNORECASE)
    if not obj_url_m:
        return findings

    obj_url_abs = max(0, blob_pos - _PROXIMITY) + obj_url_m.start()
    trigger_window = js[max(0, obj_url_abs - _PROXIMITY): min(len(js), obj_url_abs + _PROXIMITY)]

    # iframe src assignment — various notations
    iframe_m = re.search(
        r'(?:iframe|frame)\b[^;]{0,100}\.src\s*='
        r'|(?:iframe|frame)\b[^;]{0,100}\.setAttribute\s*\(\s*["\']src["\']'
        r'|\.src\s*=\s*(?:blobUrl|objectUrl|blobURL|objectURL)',
        trigger_window, re.IGNORECASE,
    )
    if not iframe_m:
        return findings

    # Skip if this is already caught as HTML smuggling (.download is present)
    if re.search(r'\.download\s*=', trigger_window, re.IGNORECASE):
        return findings

    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'Blob-URI iframe injection — GhostFrame phishing technique',
        'description': (
            'Script constructs a Blob from HTML, creates an object URL, and assigns it to an '
            'iframe src. The GhostFrame technique (PhishFort, 2025) uses this to deliver a '
            'phishing form inside a blob:-URI iframe, bypassing CSP frame-src directives '
            'because blob: URLs are treated as same-origin. The phishing form is invisible to '
            'static HTML analysis. Combined with a brand-matching domain or login form, '
            'this is a strong phishing indicator.'
        ),
        'evidence': (
            f'[Blob construction]\n{_snippet(js, blob_m)}\n\n'
            f'[Object URL creation]\n{_snippet(js, obj_url_m)}'
        ),
    })
    return findings


# ---------------------------------------------------------------------------
# REC-13 — Smart-contract-backed skimmer (JScrambler, 2025)
# ---------------------------------------------------------------------------

def _check_web3_skimmer_storage(js: str) -> list[dict]:
    """
    Detect Magecart skimmers that store the exfiltration endpoint in a blockchain
    smart contract (JScrambler research, 2025).

    The skimmer uses web3.js / ethers.js to read a URL from a Binance Smart Chain
    contract via eth_call, then exfiltrates stolen card data to that URL.  The C2
    URL is takedown-resistant — it cannot be removed once deployed to the chain.

    Distinct from _check_wallet_drainer (which requires eth_sendTransaction /
    signature requests) — this is a READ operation to retrieve C2 infrastructure.
    """
    findings: list[dict] = []

    web3_re = re.compile(
        r'ethers\.Contract|new\s+Web3\s*\(|web3\.eth\.|'
        r'\beth_call\b|\.methods\b[^;]{0,40}\.\s*call\s*\(',
        re.IGNORECASE,
    )
    m = web3_re.search(js)
    if not m:
        return findings

    # Skip — wallet drainer check already covers transaction-signing variants
    if re.search(r'eth_sendTransaction|eth_signTypedData|personal_sign', js, re.IGNORECASE):
        return findings

    _PROXIMITY = 4000
    region = js[max(0, m.start() - _PROXIMITY): min(len(js), m.end() + _PROXIMITY)]

    card_re = re.compile(
        r'card[-_\s]?(?:number|num|holder)|cvv\b|cvc\b|expir|pan\b|cc[-_]?num|'
        r'querySelector[^;]{0,80}(?:card|cvv|expir)',
        re.IGNORECASE,
    )
    if not card_re.search(region):
        return findings

    findings.append({
        'severity': 'HIGH',
        'category': 'JavaScript',
        'title': 'Smart-contract-backed skimmer infrastructure',
        'description': (
            'Web3 contract access (ethers.js, web3.js, or eth_call) was found in proximity '
            'to payment card field keywords. A Magecart campaign documented by JScrambler (2025) '
            'stores its exfiltration URL inside a Binance Smart Chain contract — making the '
            'C2 infrastructure takedown-resistant once deployed. This pattern indicates a '
            'sophisticated persistent skimmer. Checkout-page analysis and server-side audit required.'
        ),
        'evidence': f'[Smart contract access near payment context]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# REC-14 — WebAssembly-based code obfuscation (Wobfuscator, NDSS 2026)
# ---------------------------------------------------------------------------

def _check_wasm_obfuscation(js: str) -> list[dict]:
    """
    Detect WebAssembly instantiation near sensitive browser operations.

    Wobfuscator (NDSS 2026) and similar tools transpile JavaScript logic into
    WebAssembly to evade static analysis.  Legitimate WASM uses (game engines,
    image processing, crypto libraries) do not appear near card-field selectors,
    eval(), cookie writes, or clipboard operations.

    Fires MEDIUM when WASM instantiation appears in proximity to suspicious
    browser APIs — a combination that has no legitimate explanation.
    """
    findings: list[dict] = []

    wasm_re = re.compile(
        r'WebAssembly\.(?:instantiate|compile|instantiateStreaming)\s*\(',
        re.IGNORECASE,
    )
    m = wasm_re.search(js)
    if not m:
        return findings

    _PROXIMITY = 3000
    region = js[max(0, m.start() - _PROXIMITY): min(len(js), m.end() + _PROXIMITY)]

    suspicious_re = re.compile(
        r'eval\s*\(|card[-_\s]?(?:number|num|holder)|cvv\b|cvc\b|'
        r'document\.cookie|sendBeacon|navigator\.clipboard',
        re.IGNORECASE,
    )
    if not suspicious_re.search(region):
        return findings

    findings.append({
        'severity': 'MEDIUM',
        'category': 'JavaScript',
        'title': 'WebAssembly instantiation near sensitive operations',
        'description': (
            'WebAssembly.instantiate() or compile() was found in proximity to payment card '
            'fields, eval(), cookie access, or clipboard operations. Wobfuscator (NDSS 2026) '
            'and similar tools transpile malicious JavaScript logic into WASM to evade static '
            'analysis — the binary contains the actual payload and cannot be read without '
            'decompilation. This combination warrants manual analysis of the WASM binary.'
        ),
        'evidence': f'[WebAssembly instantiation]\n{_snippet(js, m)}',
    })
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyse_js(js_content: str, source_url: str = '', beautify: bool = True) -> list[dict]:
    """
    Analyse JavaScript content for malicious patterns.

    Returns a list of finding dicts, sorted CRITICAL → INFO.
    Each dict has: severity, category, title, description, evidence.

    beautify: if False, skip jsbeautifier entirely. All 30 checks work on raw
    minified JS — beautification only improves evidence readability. Set False
    for external scripts in batch scanning to avoid jsbeautifier's CPU-bound
    regex hanging the GIL and blocking the phase timeout.
    """
    if not js_content or not js_content.strip():
        return []

    findings: list[dict] = []

    # Build analysis versions: original, beautified, hex-decoded, beautified hex-decoded.
    # Running all checks against the decoded version ensures obfuscated bracket-notation
    # code (e.g. document['createElement']('script')) is caught by the same rules that
    # cover plaintext dot-notation code.
    _HEX_RE = re.compile(r'\\x([0-9a-fA-F]{2})')

    def _decode_hex(s: str) -> str:
        def _r(m: re.Match) -> str:
            try:
                return chr(int(m.group(1), 16))
            except Exception:
                return m.group(0)
        return _HEX_RE.sub(_r, s)

    beautified = _beautify(js_content) if beautify else js_content
    hex_decoded = _decode_hex(js_content)

    versions: list[str] = [js_content]
    if beautified != js_content:
        versions.append(beautified)
    if hex_decoded != js_content:
        versions.append(hex_decoded)
        if beautify:
            beautified_hex = _beautify(hex_decoded)
            if beautified_hex != hex_decoded:
                versions.append(beautified_hex)

    seen_titles: set[str] = set()

    def add_findings(new_findings: list[dict]) -> None:
        for f in new_findings:
            title = f.get('title', '')
            if title not in seen_titles:
                seen_titles.add(title)
                findings.append(f)

    for js in versions:
        add_findings(_check_eval_obfuscation(js))
        add_findings(_check_array_rotation_obfuscation(js))
        add_findings(_check_fromcharcode(js))
        add_findings(_check_hex_string_obfuscation(js, source_url))
        add_findings(_check_high_entropy_strings(js, source_url))
        add_findings(_check_split_join_evasion(js))
        add_findings(_check_cookie_exfiltration(js))
        add_findings(_check_form_hijacking(js))
        add_findings(_check_keylogger(js))
        add_findings(_check_payment_skimmer(js))
        add_findings(_check_crypto_miner(js))
        add_findings(_check_hidden_iframe_injection(js, source_url))
        add_findings(_check_forced_download(js))
        add_findings(_check_auto_redirect(js))
        add_findings(_check_js_location_redirect(js, source_url))
        add_findings(_check_anchor_redirect(js, source_url))
        add_findings(_check_right_click_disable(js))
        add_findings(_check_devtools_detection(js))
        add_findings(_check_sendbeacon_external(js, source_url))
        add_findings(_check_clipboard_hijacking(js))
        add_findings(_check_execcommand_clipboard(js))
        add_findings(_check_document_write_external_script(js))
        add_findings(_check_dom_script_injection(js, source_url))
        add_findings(_check_shell_dropper(js))
        add_findings(_check_html_smuggling(js))
        add_findings(_check_wallet_drainer(js))
        add_findings(_check_service_worker_abuse(js))
        add_findings(_check_lots_exfiltration(js))
        add_findings(_check_fetch_eval(js))
        add_findings(_check_decrypt_exec(js))
        add_findings(_check_dynamic_import_external(js))
        add_findings(_check_xor_string_array_obfuscation(js))
        add_findings(_check_tds_fingerprint_redirect(js))
        # P0 / P1 new checks (2026-04 detection review)
        add_findings(_check_jsfuck_obfuscation(js))
        add_findings(_check_jjencode_obfuscation(js))
        add_findings(_check_ndsw_injection(js))
        add_findings(_check_skimmer_activation_gate(js))
        add_findings(_check_mutation_observer_skimmer(js))
        add_findings(_check_blob_iframe_injection(js))
        add_findings(_check_web3_skimmer_storage(js))
        add_findings(_check_wasm_obfuscation(js))

    # Sort by severity
    findings.sort(key=_sev_key)
    return findings
