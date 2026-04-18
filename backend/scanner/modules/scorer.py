"""
Scoring and verdict derivation module.
Combines individual findings into an overall verdict and detects context collapse.
"""

SEVERITY_ORDER: dict[str, int] = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4,
}


def derive_verdict(findings: list[dict]) -> str:
    """
    Derive an overall verdict from the findings list.

    MALICIOUS  – any CRITICAL finding present
    SUSPICIOUS – any HIGH finding, or >= 2 MEDIUM findings
    CLEAN      – only LOW/INFO findings
    UNKNOWN    – no findings at all
    """
    if not findings:
        return 'UNKNOWN'

    severities = {f.get('severity', 'INFO') for f in findings}

    if 'CRITICAL' in severities:
        return 'MALICIOUS'

    if 'HIGH' in severities:
        return 'SUSPICIOUS'

    medium_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    if medium_count >= 2:
        return 'SUSPICIOUS'

    return 'CLEAN'


def sort_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by severity order, then by category alphabetically."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get('severity', 'INFO'), 4),
            f.get('category', ''),
            f.get('title', ''),
        ),
    )


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Collapse findings that share the same (category, title, resource_url) into one,
    appending an occurrence count to the evidence when duplicates exist.
    Order of first occurrence is preserved.
    """
    seen: dict[tuple, dict] = {}
    counts: dict[tuple, int] = {}

    for f in findings:
        key = (f.get('category', ''), f.get('title', ''), f.get('resource_url', ''))
        if key in seen:
            counts[key] += 1
        else:
            seen[key] = f
            counts[key] = 1

    result = []
    for key, finding in seen.items():
        if counts[key] > 1:
            f = dict(finding)
            evidence = f.get('evidence', '')
            f['evidence'] = evidence + f'\n[{counts[key]} identical findings — shown once]'
            result.append(f)
        else:
            result.append(finding)

    return result


def context_collapse_check(all_findings: list[dict]) -> list[dict]:
    """
    Detect context collapse: multiple independent moderate signals that together indicate malice.

    Adds synthetic HIGH/CRITICAL findings when combinations are detected.
    Returns the updated findings list (original + any synthetic findings).
    """
    findings = list(all_findings)
    categories = {f.get('category', '') for f in findings}
    titles = {f.get('title', '') for f in findings}
    severities = {f.get('severity', 'INFO') for f in findings}

    def _has_category(cat: str) -> bool:
        return any(f.get('category', '') == cat for f in findings)

    def _has_title_fragment(fragment: str) -> bool:
        return any(fragment.lower() in f.get('title', '').lower() for f in findings)

    def _has_severity(sev: str) -> bool:
        return any(f.get('severity') == sev for f in findings)

    def _count_severity(sev: str) -> int:
        return sum(1 for f in findings if f.get('severity') == sev)

    synthetic: list[dict] = []

    # Context 1: High-risk TLD + external form action (phishing infrastructure)
    # Missing security headers are INFO-level individually but in this combination
    # they provide additional signal that the site was stood up quickly by a threat
    # actor rather than by a developer who'd add standard security hardening.
    has_highrisk_tld = _has_title_fragment('high-risk tld')
    has_external_form = _has_title_fragment('form submits') and _has_title_fragment('external')
    missing_headers_count = sum(1 for f in findings if 'Missing' in f.get('title', '') and f.get('category') == 'Headers')
    if has_highrisk_tld and has_external_form:
        if not any(f.get('title') == 'Context collapse: phishing infrastructure' for f in findings):
            header_note = (
                f' Combined with {missing_headers_count} absent security header(s) '
                '(typical of hastily deployed phishing pages), this pattern is consistent '
                'with commodity phishing kit infrastructure.'
                if missing_headers_count >= 1 else
                ' This combination is a core phishing infrastructure pattern.'
            )
            synthetic.append({
                'severity': 'HIGH',
                'category': 'Threat',
                'title': 'Context collapse: phishing infrastructure',
                'description': (
                    'Two converging signals indicate phishing infrastructure: a high-risk TLD '
                    '(disproportionately abused for phishing) combined with a form that submits '
                    'credentials to an external domain (the attacker\'s collection server). '
                    + header_note + ' '
                    'Legitimate websites on high-risk TLDs rarely submit login forms to a different domain.'
                ),
                'evidence': (
                    f'High-risk TLD + external form action'
                    + (f' + {missing_headers_count} missing security header(s)' if missing_headers_count >= 1 else '')
                ),
            })

    # Context 2: DGA domain + hidden iframe + obfuscated JS
    has_dga = _has_title_fragment('algorithmically generated')
    has_hidden_iframe = _has_title_fragment('hidden iframe')
    has_obfuscated_js = _has_title_fragment('obfuscat') or _has_title_fragment('eval') or _has_title_fragment('hex-array')
    if has_dga and has_hidden_iframe and has_obfuscated_js:
        if not any(f.get('title') == 'Context collapse: drive-by malware delivery' for f in findings):
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: drive-by malware delivery',
                'description': (
                    'Critical combination: DGA-pattern domain + hidden iframe + obfuscated JavaScript. '
                    'This triad is a signature pattern for drive-by malware delivery pages. '
                    'The site very likely serves malware to visitors.'
                ),
                'evidence': 'DGA domain + hidden iframe + JS obfuscation',
            })

    # Context 3: Brand impersonation + new cert + phishing form
    has_brand_impersonation = _has_title_fragment('brand impersonation') or _has_title_fragment('brand keyword')
    has_new_cert = _has_title_fragment('recently') and _has_category('SSL')
    has_phishing_form = (_has_title_fragment('form submits') and _has_title_fragment('external')) or _has_title_fragment('phishing')
    if has_brand_impersonation and has_phishing_form:
        if not any(f.get('title') == 'Context collapse: active phishing campaign' for f in findings):
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: active phishing campaign',
                'description': (
                    'Brand impersonation combined with phishing form detected. '
                    + ('Fresh SSL certificate further confirms a newly deployed phishing page.' if has_new_cert else '')
                    + ' This combination is the operational signature of an active phishing campaign.'
                ),
                'evidence': 'Brand impersonation + phishing form' + (' + new SSL cert' if has_new_cert else ''),
            })

    # Context 4: Keylogger/skimmer + devtools detection (targeted attack)
    has_keylogger = _has_title_fragment('keylogger')
    has_skimmer = _has_title_fragment('skimmer')
    has_devtools = _has_title_fragment('developer tools')
    if (has_keylogger or has_skimmer) and has_devtools:
        if not any(f.get('title') == 'Context collapse: sophisticated targeted malware' for f in findings):
            # Collect actual evidence from the triggering findings
            trigger_parts: list[str] = []
            for f in findings:
                title = f.get('title', '').lower()
                if 'keylogger' in title or 'skimmer' in title or 'developer tools' in title:
                    label = f.get('title', '')
                    ev = f.get('evidence', '').strip()
                    if ev:
                        trigger_parts.append(f'[{label}]\n{ev}')
                    else:
                        trigger_parts.append(f'[{label}]')
            evidence_block = '\n\n'.join(trigger_parts) if trigger_parts else (
                ('Keylogger' if has_keylogger else 'Skimmer') + ' + DevTools evasion detected'
            )
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: sophisticated targeted malware',
                'description': (
                    'A data exfiltration payload (keylogger/skimmer) combined with developer tools '
                    'evasion indicates sophisticated, targeted malware. The operator is actively '
                    'trying to avoid analysis while stealing sensitive data.'
                ),
                'evidence': evidence_block,
            })

    # Context 5: ClickFix — fake CAPTCHA UI + autonomous clipboard write
    # The HTML analyser emits a HIGH for the fake CAPTCHA page;
    # the JS analyser emits MEDIUM for clipboard write outside a click handler.
    # Together they are a confirmed ClickFix delivery chain → CRITICAL.
    has_fake_captcha = _has_title_fragment('fake captcha') or _has_title_fragment('clickfix')
    has_clipboard_write = _has_title_fragment('clipboard write outside')
    if has_fake_captcha and has_clipboard_write:
        if not any(f.get('title') == 'Context collapse: ClickFix malware delivery' for f in findings):
            trigger_parts: list[str] = []
            for f in findings:
                title = f.get('title', '').lower()
                if 'fake captcha' in title or 'clickfix' in title or 'clipboard write outside' in title:
                    label = f.get('title', '')
                    ev = f.get('evidence', '').strip()
                    trigger_parts.append(f'[{label}]\n{ev}' if ev else f'[{label}]')
            evidence_block = '\n\n'.join(trigger_parts) if trigger_parts else (
                'Fake CAPTCHA/verification UI + autonomous clipboard write detected'
            )
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: ClickFix malware delivery',
                'description': (
                    'Fake CAPTCHA/verification UI combined with an autonomous clipboard write. '
                    'This is the ClickFix technique: a malicious command is silently written to '
                    'the clipboard while the user is socially engineered into pasting and running it, '
                    'bypassing all browser security controls. One of the most active initial-access '
                    'delivery techniques in 2024–2025.'
                ),
                'evidence': evidence_block,
            })

    # Context 6: Injected external script + clipboard write or ClickFix content
    # Covers the compromised-legitimate-site pattern (e.g. WordPress compromise):
    # - An unknown external script is injected into the page (Fix 1 in html_analyser)
    # - That script delivers a ClickFix payload (clipboard write / fake CAPTCHA)
    # Either combination confirms the site is actively delivering malware to visitors.
    has_injected_script = _has_title_fragment('external script injection from unknown domain')
    has_clickfix_payload = (
        _has_title_fragment('clickfix clipboard payload')
        or _has_title_fragment('fake captcha')
        or _has_title_fragment('clipboard write outside')
    )
    if has_injected_script and has_clickfix_payload:
        if not any(f.get('title') == 'Context collapse: compromised site delivering ClickFix malware' for f in findings):
            trigger_parts: list[str] = []
            for f in findings:
                title = f.get('title', '').lower()
                if any(kw in title for kw in ('external script injection', 'clickfix', 'fake captcha', 'clipboard write outside')):
                    label = f.get('title', '')
                    ev = f.get('evidence', '').strip()
                    trigger_parts.append(f'[{label}]\n{ev}' if ev else f'[{label}]')
            evidence_block = '\n\n'.join(trigger_parts) if trigger_parts else (
                'Injected unknown external script + ClickFix/clipboard payload detected'
            )
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: compromised site delivering ClickFix malware',
                'description': (
                    'A script injected from an unknown external domain is delivering a ClickFix '
                    'payload on this page. This is the signature of a compromised legitimate website '
                    '(commonly WordPress) where an attacker has injected a malicious script tag that '
                    'dynamically displays a fake CAPTCHA and writes a shell command to the clipboard. '
                    'Visitors are socially engineered into pasting and executing the command. '
                    'The legitimate site owner is almost certainly unaware of the compromise.'
                ),
                'evidence': evidence_block,
            })

    # Context 7: Newly registered domain + high-risk TLD → purpose-built attack infrastructure
    # Even without any content-based findings, this combination is a strong operational
    # indicator: the vast majority of fresh high-risk-TLD registrations are throwaway
    # attack domains that never accumulate enough reputation for blocklists to catch them.
    has_new_domain = _has_title_fragment('newly registered domain')
    if has_new_domain and has_highrisk_tld:
        if not any(f.get('title') == 'Context collapse: newly registered high-risk domain' for f in findings):
            synthetic.append({
                'severity': 'HIGH',
                'category': 'Threat',
                'title': 'Context collapse: newly registered high-risk domain',
                'description': (
                    'A domain registered within the last 30 days on a high-risk TLD was detected. '
                    'This combination — fresh registration on a cheap, abuse-prone TLD — is a strong '
                    'operational indicator of purpose-built attack infrastructure. Threat actors '
                    'register large batches of such domains for phishing, ClickFix delivery, malware '
                    'C2, and spam campaigns, discarding them before they appear in reputation feeds. '
                    'The absence of content-based findings does not rule out a threat: scanners '
                    'may encounter a staging page, parked domain, or redirect chain before the '
                    'payload is activated.'
                ),
                'evidence': 'Newly registered domain (<30 days) + high-risk TLD combination',
            })

    # Context 8: Renderer-confirmed overlay + runtime network intercept
    # CSS_OVERLAY_INJECTED fires when the Carapace browser renderer detects a fullscreen
    # overlay — not inferred from source but confirmed at render time.  INTERCEPTED_REQUEST
    # fires when JS attempted real network calls during that same render session.
    # The combination is browser-grade evidence of an active ClickFix/SocGholish delivery
    # chain: the overlay is live and the JS is calling out to a payload server.
    has_css_overlay = _has_title_fragment('fullscreen css overlay')
    has_intercepted_request = _has_title_fragment('runtime network request')
    if has_css_overlay and has_intercepted_request:
        if not any(f.get('title') == 'Context collapse: renderer-confirmed active overlay attack' for f in findings):
            trigger_parts: list[str] = []
            for f in findings:
                title = f.get('title', '').lower()
                if 'css overlay' in title or 'runtime network request' in title:
                    label = f.get('title', '')
                    ev = f.get('evidence', '').strip()
                    trigger_parts.append(f'[{label}]\n{ev}' if ev else f'[{label}]')
            evidence_block = '\n\n'.join(trigger_parts) if trigger_parts else (
                'Renderer-confirmed fullscreen overlay + runtime network request intercepted'
            )
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: renderer-confirmed active overlay attack',
                'description': (
                    'The Carapace browser renderer confirmed two signals in a single render session: '
                    'a fullscreen CSS overlay (the structural signature of ClickFix and SocGholish) '
                    'and JavaScript runtime network requests that were intercepted and blocked. '
                    'This is browser-grade evidence of an active attack delivery chain — the overlay '
                    'is live and the page script was actively calling out to an external payload '
                    'or C2 server. Unlike static analysis, this detection cannot be a false positive '
                    'from legitimate code: both signals were observed during real JavaScript execution '
                    'in an isolated Chromium environment.'
                ),
                'evidence': evidence_block,
            })

    # Context 9: TDS cloaking redirect + polymorphic obfuscation
    # A Traffic Direction System that hides its API endpoint and redirect URLs
    # behind per-request XOR obfuscation is purpose-built attack infrastructure.
    # No legitimate website uses both patterns together.  The obfuscation exists
    # solely to prevent static scanners from seeing the destination URL, confirming
    # the operator knows the destination is malicious.
    has_tds = _has_title_fragment('traffic direction system')
    has_xor_obfuscation = _has_title_fragment('polymorphic xor')
    if has_tds and has_xor_obfuscation:
        if not any(f.get('title') == 'Context collapse: TDS cloaking with polymorphic obfuscation' for f in findings):
            trigger_parts: list[str] = []
            for f in findings:
                title = f.get('title', '').lower()
                if 'traffic direction system' in title or 'polymorphic xor' in title:
                    label = f.get('title', '')
                    ev = f.get('evidence', '').strip()
                    trigger_parts.append(f'[{label}]\n{ev}' if ev else f'[{label}]')
            evidence_block = '\n\n'.join(trigger_parts) if trigger_parts else (
                'TDS cloaking redirect + polymorphic XOR obfuscation detected'
            )
            synthetic.append({
                'severity': 'CRITICAL',
                'category': 'Threat',
                'title': 'Context collapse: TDS cloaking with polymorphic obfuscation',
                'description': (
                    'A Traffic Direction System (TDS) combined with polymorphic XOR string-array '
                    'obfuscation confirms purpose-built malicious delivery infrastructure. '
                    'The TDS fingerprints every visitor and redirects real users to attack '
                    'infrastructure (phishing, malware) while showing a clean page to scanners. '
                    'The polymorphic obfuscation — where the XOR key and all variable names are '
                    'randomised per request — exists specifically to hide the destination URL from '
                    'static analysis. No legitimate website uses both patterns together. '
                    'The redirect destination is server-controlled and never present in the page source.'
                ),
                'evidence': evidence_block,
            })

    findings.extend(synthetic)
    return findings
