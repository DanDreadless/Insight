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

    # Context 1: High-risk TLD + missing all security headers + external form action
    has_highrisk_tld = _has_title_fragment('high-risk tld')
    has_external_form = _has_title_fragment('form submits to external')
    missing_headers_count = sum(1 for f in findings if 'Missing' in f.get('title', '') and f.get('category') == 'Headers')
    if has_highrisk_tld and has_external_form and missing_headers_count >= 2:
        if not any(f.get('title') == 'Context collapse: phishing infrastructure' for f in findings):
            synthetic.append({
                'severity': 'HIGH',
                'category': 'Threat',
                'title': 'Context collapse: phishing infrastructure',
                'description': (
                    'Multiple independent signals converge: high-risk TLD, external form action, '
                    f'and {missing_headers_count} missing security headers. '
                    'Individually moderate findings — together they strongly indicate phishing infrastructure.'
                ),
                'evidence': 'High-risk TLD + external form action + missing security headers',
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
    has_phishing_form = _has_title_fragment('form submits to external') or _has_title_fragment('phishing')
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

    findings.extend(synthetic)
    return findings
