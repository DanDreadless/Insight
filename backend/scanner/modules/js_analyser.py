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


def _check_hex_string_obfuscation(js: str) -> list[dict]:
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

        # Skip SRI integrity hashes — sha256-/sha384-/sha512- prefixed base64
        # strings are legitimately high-entropy but are not payloads.
        if re.match(r'sha(?:256|384|512)-[A-Za-z0-9+/=]+$', literal, re.IGNORECASE):
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
        if re.match(r'^[A-Za-z0-9+/]{64}$', literal) and len(set(literal)) == 64:
            continue

        # Skip human-readable strings (credits, comments, changelogs).
        # Real encoded payloads never contain spaces; if >5% of the string is
        # spaces the string is almost certainly natural language, not a payload.
        if literal.count(' ') / len(literal) > 0.05:
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

    # If the exfiltration target URL is a known payment processor this is
    # almost certainly a legitimate SDK call (e.g. Stripe Elements posting to
    # api.stripe.com), not a skimmer.
    url_match = exfil_url_re.search(js)
    if url_match:
        from scanner.modules.known_good_domains import is_payment_processor, is_analytics
        exfil_url = url_match.group(1)
        if is_payment_processor(exfil_url) or is_analytics(exfil_url):
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
    iframe_m = re.search(
        r'createElement\s*\(\s*["\']iframe["\']',
        js, re.IGNORECASE
    )
    if not iframe_m:
        return findings

    hidden_m = re.search(
        r'(?:display\s*(?:=|:)\s*["\']?none|'
        r'visibility\s*(?:=|:)\s*["\']?hidden|'
        r'width\s*(?:=|:)\s*["\']?0|'
        r'height\s*(?:=|:)\s*["\']?0)',
        js, re.IGNORECASE
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
                f'[Hidden styling applied]\n{_snippet(js, hidden_m)}'
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

    findings.append({
        'severity': 'HIGH',
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

    # window.location assignment in setTimeout with delay < 3000
    pattern = re.compile(
        r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{[^}]*window\.location[^}]*\}\s*,\s*(\d+)',
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
        r'wscript|cscript|invoke-expression|\biex\b|invoke-restmethod|\birm\b|'
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

    # --- Check 2: Is the write user-triggered (heuristic)? ------------------
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

    # Match createElement('script') in both dot-notation and bracket-notation:
    #   dot:     document.createElement('script')   → createElement(
    #   bracket: document['createElement']('script') → createElement']('script')
    create_re = re.compile(
        r"createElement\s*(?:['\"]?\s*\])?\s*\(\s*['\"]script['\"]\s*\)",
        re.IGNORECASE,
    )
    m = create_re.search(js)
    if not m:
        return []

    # Look for appendChild within 1500 chars after the createElement call
    window = js[m.start(): min(len(js), m.start() + 1500)]

    has_append = bool(re.search(r'appendChild\b', window, re.IGNORECASE))
    if not has_append:
        return []

    # src assignment in either notation:
    #   dot:     elem.src = url
    #   bracket: elem['src'] = url  or  elem["src"] = url
    has_src = bool(re.search(
        r"""(?:['"]\s*src\s*['"]\s*\]\s*=|\.src\s*=)""",
        window,
        re.IGNORECASE,
    ))
    if not has_src:
        return []

    # Try to extract the actual URL being injected — include in evidence so
    # the analyst doesn't need to read through the code to find it.
    injected_src = _extract_injected_script_src(window)

    evidence_parts = [f'[Injection code]\n{_snippet(js, m)}']
    if injected_src:
        evidence_parts.append(f'[Injected script URL]\n{injected_src}')

    return [{
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
    }]


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
    Requires all three signals: Blob construction + createObjectURL + download trigger.
    """
    findings: list[dict] = []
    blob_m = re.search(r'new\s+Blob\s*\(\s*\[', js, re.IGNORECASE)
    if not blob_m:
        return findings
    obj_url_m = re.search(r'URL\.createObjectURL\s*\(', js, re.IGNORECASE)
    if not obj_url_m:
        return findings
    trigger_m = re.search(
        r'(?:\.download\s*=|\.click\s*\(\s*\)|msSaveOrOpenBlob|msSaveBlob)',
        js, re.IGNORECASE,
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
# Main entry point
# ---------------------------------------------------------------------------

def analyse_js(js_content: str, source_url: str = '') -> list[dict]:
    """
    Analyse JavaScript content for malicious patterns.

    Returns a list of finding dicts, sorted CRITICAL → INFO.
    Each dict has: severity, category, title, description, evidence.
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

    beautified = _beautify(js_content)
    hex_decoded = _decode_hex(js_content)

    versions: list[str] = [js_content]
    if beautified != js_content:
        versions.append(beautified)
    if hex_decoded != js_content:
        versions.append(hex_decoded)
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
        add_findings(_check_hex_string_obfuscation(js))
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
        add_findings(_check_right_click_disable(js))
        add_findings(_check_devtools_detection(js))
        add_findings(_check_sendbeacon_external(js, source_url))
        add_findings(_check_clipboard_hijacking(js))
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

    # Sort by severity
    findings.sort(key=_sev_key)
    return findings
