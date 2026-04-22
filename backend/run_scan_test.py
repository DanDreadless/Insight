"""
Standalone scan test — runs all analyser modules directly against a URL.
No Django/Celery/Redis required.

Usage:
    python run_scan_test.py [URL]                # single URL test
    python run_scan_test.py --feedback           # run all cases from feedback/cases.json
    python run_scan_test.py --feedback --id 3    # run a single feedback case by ID

If URL is omitted in single mode, TARGET_URL below is used.
"""
import argparse
import json
import os
import re
import sys
import time
import warnings
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from concurrent.futures import ThreadPoolExecutor, as_completed

# Force line-buffered stdout so output appears immediately in background runs
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None

# Ensure stdout/stderr use UTF-8, line-buffered so output appears immediately
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

# Add backend to path so scanner modules resolve
sys.path.insert(0, os.path.dirname(__file__))

# Minimal Django settings stub so validators/models don't crash on import
os.environ.setdefault('DJANGO_SETTINGS_MODULE', '')

# Prevent tldextract from making a network call to refresh the public suffix list.
# Patch the module-level extractor to use no remote URLs — falls back to bundled list.
import tldextract as _tle
_tle._extractor = _tle.TLDExtract(suffix_list_urls=[])

# Import analysers directly
from scanner.modules import (
    header_analyser,
    domain_intelligence,
    html_analyser,
    js_analyser,
    ssl_analyser,
    scorer,
)
from scanner.modules.resource_collector import collect_resources
from scanner.modules.known_good_domains import is_known_good, is_site_builder_cdn, PLATFORM_INLINE_SKIP_BYTES

TARGET_URL = 'https://www.cloudretouch.com'

CASES_PATH = os.path.join(os.path.dirname(__file__), 'feedback', 'cases.json')

# ---------------------------------------------------------------------------
# Carapace renderer integration (optional)
# ---------------------------------------------------------------------------

def _discover_carapace_url() -> str | None:
    """
    Return a reachable Carapace base URL, or None if unavailable.

    Resolution order:
    1. CARAPACE_URL env var (explicit override)
    2. Docker inspect on the known container name → use bridge IP directly
       (works on Linux — the Pi runs Docker natively, bridge IPs are routable)
    """
    env_url = os.environ.get('CARAPACE_URL', '').rstrip('/')
    if env_url:
        return env_url

    import subprocess
    try:
        result = subprocess.run(
            [
                'docker', 'inspect',
                '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}',
                'insight_vault1337-carapace-1',
            ],
            capture_output=True, text=True, timeout=5,
        )
        ip = result.stdout.strip().split()[0] if result.stdout.strip() else None
        if ip:
            return f'http://{ip}:8080'
    except Exception:
        pass

    return None


# --- Tuning knobs ---
JS_WORKERS              = 8             # parallel script fetches
JS_FETCH_TIMEOUT        = (5, 6)        # (connect, read) seconds per script
JS_PHASE_TIMEOUT        = 60            # hard wall-clock cap for entire JS fetch phase (seconds)
JS_MAX_SCRIPTS          = 50            # max external scripts to analyse
JS_MAX_BYTES            = 512 * 1024    # 512 KB per script — matches production scanner which allows 1 MB;
                                        # attackers inject payloads mid-file (not just prepend/append)
JS_DOWNLOAD_HARD_TIMEOUT = 12           # increase to match larger download cap
JS_SKIP_ABOVE_BYTES     = 600 * 1024   # skip scripts >600KB

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-GB,en;q=0.5',
}

SEV_COLOURS = {
    'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
    'MEDIUM': '\033[33m',   'LOW': '\033[94m', 'INFO': '\033[90m',
}
VERDICT_COLOURS = {
    'MALICIOUS': '\033[91m', 'SUSPICIOUS': '\033[93m',
    'CLEAN': '\033[92m',     'UNKNOWN': '\033[90m',
}
RESET = '\033[0m'
GREEN = '\033[92m'
RED   = '\033[91m'
BOLD  = '\033[1m'


def fetch_page(url, max_bytes=5 * 1024 * 1024):
    r = requests.get(url, headers=HEADERS, timeout=(5, 15),
                     verify=False, allow_redirects=True, stream=True)
    content = b''
    for chunk in r.iter_content(8192):
        content += chunk
        if len(content) >= max_bytes:
            break
    return {
        'url': r.url,
        'status_code': r.status_code,
        'headers': dict(r.headers),
        'text': content.decode('utf-8', errors='replace'),
    }


def fetch_and_analyse_script(url):
    """
    Fetch a single external script and run JS analysis — all in the worker thread
    so both I/O and jsbeautifier CPU work are fully parallelised.
    Returns (url, findings, size_kb).

    Uses a hard wall-clock download deadline to prevent slow-streaming servers
    from holding a thread for minutes. requests timeout=(connect, read) is
    per-chunk, not total — a trickle server can stall indefinitely without this.
    """
    deadline = time.monotonic() + JS_DOWNLOAD_HARD_TIMEOUT
    r = requests.get(url, headers=HEADERS, timeout=JS_FETCH_TIMEOUT,
                     verify=False, allow_redirects=True, stream=True)
    content = b''
    for chunk in r.iter_content(8192):
        content += chunk
        if len(content) >= JS_MAX_BYTES:
            break
        if time.monotonic() > deadline:
            raise TimeoutError(f'download exceeded {JS_DOWNLOAD_HARD_TIMEOUT}s wall-clock limit')

    js_text = content.decode('utf-8', errors='replace')
    size_kb = len(js_text) // 1024

    # Analyse first 10KB + last 10KB only.
    # Injected malware is a compact blob prepended/appended to the legitimate
    # file in most campaigns. Keeping the sample small is critical: jsbeautifier
    # is CPU-bound and Python's GIL serialises it across all worker threads.
    # Exception: when critical-payload indicators (clipboard write, execCommand,
    # eval(atob)) are detected in the middle of the file, a 3KB window around
    # each match is appended to ensure parity with the production scanner, which
    # passes the full file to js_analyser.analyse_js() with no sampling.
    EDGE = 10 * 1024
    if len(js_text) > EDGE * 2:
        js_sample = js_text[:EDGE] + '\n' + js_text[-EDGE:]
        _CRITICAL_INDICATOR_RE = re.compile(
            r'navigator\.clipboard\.writeText'
            r'|document\.execCommand\s*\(\s*["\']copy["\']'
            r'|eval\s*\(\s*(?:atob|unescape)\s*\(',
            re.IGNORECASE,
        )
        MID_WIN = 3 * 1024
        for m in _CRITICAL_INDICATOR_RE.finditer(js_text):
            if EDGE <= m.start() <= len(js_text) - EDGE:
                win_start = max(0, m.start() - MID_WIN // 2)
                win_end = min(len(js_text), m.start() + MID_WIN)
                js_sample += '\n' + js_text[win_start:win_end]
    else:
        js_sample = js_text

    # Skip beautification for external scripts — jsbeautifier is CPU-bound and
    # Python's re module holds the GIL, so a single problematic webpack chunk
    # can block the 60s phase timeout from ever firing. Detection is unaffected:
    # all 30 checks work on raw minified JS. Inline scripts retain beautification.
    findings = js_analyser.analyse_js(js_sample, url, beautify=False)
    for f in findings:
        f['resource_url'] = url
    return url, findings, size_kb


def print_finding(f, target_url):
    sev = f.get('severity', '?')
    colour = SEV_COLOURS.get(sev, '')
    print(f"\n{'='*70}")
    print(f"{colour}[{sev}]{RESET} [{f.get('category')}] {f.get('title')}")
    print(f"  {f.get('description', '')}")
    evidence = f.get('evidence', '')
    if evidence:
        print(f"\n  --- EVIDENCE ---")
        for line in evidence.splitlines():
            print(f"  {line}")
    resource = f.get('resource_url', '')
    if resource and resource != target_url:
        print(f"\n  Source: {resource}")


def run_scan(target_url, verbose=True):
    """
    Run the full scan pipeline against target_url.
    Returns (verdict, findings).
    """
    if verbose:
        print(f"Scanning: {target_url}\n")

    # --- Fetch main page ---
    if verbose:
        print("[1/6] Fetching page...")
    resp = fetch_page(target_url)
    final_url = resp['url']
    html_content = resp['text']
    response_headers = resp['headers']
    status_code = resp['status_code']
    if verbose:
        print(f"      Status: {status_code} | Final URL: {final_url}")

    all_findings = []

    # --- Cross-domain redirect check ---
    # If the submitted URL redirected to a completely different registered domain,
    # add a HIGH finding.  Phishing kits commonly redirect automated scanners to
    # major consumer sites (Google, Bing, etc.) while serving malicious content
    # to real visitors — a technique known as "cloaking".  When the redirect
    # target is one of these well-known consumer destinations, skip HTML/JS
    # analysis to avoid firing false positives on the target site's own code.
    _CLOAKING_REDIRECT_TARGETS: frozenset[str] = frozenset({
        'google.com', 'bing.com', 'yahoo.com', 'baidu.com', 'duckduckgo.com',
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'amazon.com', 'microsoft.com', 'apple.com', 'wikipedia.org',
    })
    _orig_host = urlparse(target_url).hostname or ''
    _orig_is_ip = bool(__import__('re').match(r'^\d{1,3}(?:\.\d{1,3}){3}$', _orig_host))
    if _orig_is_ip:
        all_findings.append({
            'severity': 'MEDIUM',
            'category': 'Domain',
            'title': 'Submitted URL uses a bare IP address',
            'description': (
                f'The submitted URL targets a server by its raw IP address ({_orig_host}) '
                'rather than a registered domain name. Bare IP hosting is uncommon for legitimate '
                'sites — it is frequently used by malware distribution infrastructure, phishing '
                'kits, and C2 servers to avoid registering a traceable domain. Combined with an '
                'obfuscated or hashed path, this is a strong indicator of malicious hosting.'
            ),
            'evidence': f'Submitted URL: {target_url}\nHost: {_orig_host}',
            'resource_url': target_url,
        })
    _orig_domain = _tle.extract(target_url).top_domain_under_public_suffix.lower()
    _final_domain = _tle.extract(final_url).top_domain_under_public_suffix.lower()
    _skip_content_analysis = False
    _cross_domain = (
        (_orig_domain and _final_domain and _orig_domain != _final_domain)
        or (_orig_is_ip and _final_domain)
    )
    if _cross_domain:
        _redirect_to_cloaking_target = _final_domain in _CLOAKING_REDIRECT_TARGETS
        all_findings.append({
            'severity': 'HIGH',
            'category': 'Redirect',
            'title': 'Suspicious HTTP redirect to unrelated domain',
            'description': (
                'The submitted URL redirected to a completely different registered domain. '
                'Redirecting scanners and bots to an innocent page (e.g. Google) while '
                'serving malicious content to real visitors is a well-known cloaking technique '
                'used by phishing kits and malware distribution sites to evade automated detection.'
                + (' The redirect destination is a major consumer site, which strongly '
                   'suggests active scanner evasion rather than a legitimate redirect.'
                   if _redirect_to_cloaking_target else '')
            ),
            'evidence': f'Submitted: {target_url}\nRedirected to: {final_url}',
            'resource_url': target_url,
        })
        if _redirect_to_cloaking_target:
            _skip_content_analysis = True

    # --- Headers ---
    if verbose:
        print("[2/6] Analysing headers...")
    hf = header_analyser.analyse_headers(response_headers, final_url, status_code)
    for f in hf:
        f.setdefault('resource_url', final_url)
    all_findings.extend(hf)
    if verbose:
        print(f"      {len(hf)} finding(s)")

    # --- SSL ---
    if verbose:
        print("[3/6] Analysing SSL...")
    hostname = urlparse(final_url).hostname or ''
    if hostname and urlparse(final_url).scheme == 'https':
        try:
            sf = ssl_analyser.analyse_ssl(hostname, 443)
            for f in sf:
                f.setdefault('resource_url', final_url)
            all_findings.extend(sf)
            if verbose:
                print(f"      {len(sf)} finding(s)")
        except Exception as e:
            if verbose:
                print(f"      SSL error: {e}")

    # --- Domain ---
    if verbose:
        print("[4/6] Analysing domain...")
    df = domain_intelligence.analyse_domain(final_url)
    for f in df:
        f.setdefault('resource_url', final_url)
    all_findings.extend(df)
    if verbose:
        print(f"      {len(df)} finding(s)")

    # --- HTML ---
    if verbose:
        print("[5/6] Analysing HTML...")
    if _skip_content_analysis:
        resources = {'scripts': [], 'iframes': [], 'forms': [], 'meta_refresh': []}
        if verbose:
            print("      Skipped — redirect target is a known-good domain (cloaking)")
    else:
        resources = collect_resources(html_content, final_url)
        htmlf = html_analyser.analyse_html(html_content, final_url, resources)
        for f in htmlf:
            f.setdefault('resource_url', final_url)
        all_findings.extend(htmlf)
        if verbose:
            print(f"      {len(htmlf)} finding(s)")

    # --- JavaScript ---
    if verbose:
        print("[6/6] Analysing JavaScript...")
    scripts = resources.get('scripts', [])

    inline_scripts = [s for s in scripts if s.get('inline') and s.get('content', '').strip()]
    external_scripts = [s for s in scripts if not s.get('inline') and s.get('url')]

    skipped = [s for s in external_scripts if is_known_good(s['url'])]
    external_scripts = [s for s in external_scripts if not is_known_good(s['url'])]
    external_scripts = external_scripts[:JS_MAX_SCRIPTS]

    # Platform-page detection: if every external script was skipped as known-good
    # AND at least one came from a site-builder CDN, this is a platform-hosted page
    # (e.g. Wix). Inline scripts on these pages are platform initialisation blobs
    # (Thunderbolt renderer, i18n data, React boot) — not user-authored content.
    # Skip inline scripts above PLATFORM_INLINE_SKIP_BYTES; small ones (<4 KB)
    # are still checked since they could be user-injected code.
    _is_platform_page = (
        (len(external_scripts) == 0
         and any(is_site_builder_cdn(s['url']) for s in skipped))
        or is_known_good(final_url)
    )
    platform_inline_skipped = 0
    if _is_platform_page:
        filtered = []
        for s in inline_scripts:
            if len(s.get('content', '')) > PLATFORM_INLINE_SKIP_BYTES:
                platform_inline_skipped += 1
            else:
                filtered.append(s)
        inline_scripts = filtered

    if verbose:
        print(f"      {len(inline_scripts)} inline | {len(external_scripts)} external to fetch "
              f"| {len(skipped)} known-good skipped"
              + (f" | {platform_inline_skipped} platform blobs skipped" if platform_inline_skipped else ""))

    js_findings = []
    js_count = 0

    for script in inline_scripts:
        jf = js_analyser.analyse_js(script['content'], final_url)
        for f in jf:
            f.setdefault('resource_url', final_url)
        js_findings.extend(jf)
        js_count += 1

    if external_scripts:
        from concurrent.futures import TimeoutError as FuturesTimeout
        phase_deadline = time.monotonic() + JS_PHASE_TIMEOUT
        futures = {}
        pool = ThreadPoolExecutor(max_workers=JS_WORKERS)
        try:
            for script in external_scripts:
                fut = pool.submit(fetch_and_analyse_script, script['url'])
                futures[fut] = script['url']

            try:
                for fut in as_completed(futures, timeout=JS_PHASE_TIMEOUT):
                    if time.monotonic() > phase_deadline:
                        if verbose:
                            print(f"      JS phase timeout ({JS_PHASE_TIMEOUT}s) — stopping early")
                        break
                    script_url = futures[fut]
                    try:
                        _, jf, size_kb = fut.result()
                        js_findings.extend(jf)
                        if verbose:
                            size_note = f" [{size_kb}KB]" if size_kb > 50 else ""
                            finding_note = f" — {len(jf)} finding(s)" if jf else ""
                            print(f"      OK   {script_url}{size_note}{finding_note}")
                        js_count += 1
                    except Exception as e:
                        if verbose:
                            print(f"      ERR  {script_url} — {e}")
            except FuturesTimeout:
                if verbose:
                    pending = sum(1 for f in futures if not f.done())
                    print(f"      JS phase timeout ({JS_PHASE_TIMEOUT}s) — {pending} script(s) abandoned")
        finally:
            pool.shutdown(wait=False)

    all_findings.extend(js_findings)
    if verbose:
        print(f"      Analysed {js_count} script(s) | "
              f"{len([f for f in js_findings if f.get('category') == 'JavaScript'])} JS finding(s)")

    # --- Direct script routing ---
    # If the URL is a .js file (or served with a JS content-type) and no scripts
    # were found via <script> tags, route the raw body through the JS analyser.
    # Mirrors the _is_direct_script path in tasks.py (step 4f).
    from pathlib import PurePosixPath
    _suffix = PurePosixPath(urlparse(final_url).path).suffix.lower()
    _ct = response_headers.get('Content-Type', response_headers.get('content-type', '')).lower().split(';')[0].strip()
    _JS_EXTS = {'.js', '.mjs', '.jsx', '.ts', '.tsx', '.jse'}
    _JS_CTS = {'text/javascript', 'application/javascript', 'application/x-javascript', 'text/jscript'}
    if (_suffix in _JS_EXTS or _ct in _JS_CTS) and html_content.strip() and js_count == 0:
        if verbose:
            print(f"\n      Direct script file detected — analysing raw body via JS analyser...")
        direct_jf = js_analyser.analyse_js(html_content, final_url)
        for f in direct_jf:
            f.setdefault('resource_url', final_url)
        all_findings.extend(direct_jf)
        if verbose:
            print(f"      {len(direct_jf)} finding(s) from direct script analysis")

    # --- Carapace renderer (optional) ---
    # Discovers the running container automatically via docker inspect.
    # Falls back silently if Carapace is not running or unreachable.
    _carapace_url = _discover_carapace_url()
    if _carapace_url and not is_known_good(final_url):
        if verbose:
            print("\n[Renderer] Carapace visual analysis...")
        try:
            from scanner.modules.carapace_client import flags_to_findings as _c_flags
            _cr = requests.post(
                f'{_carapace_url}/render',
                json={'url': final_url, 'format': 'png', 'width': 1280, 'no_assets': False},
                headers={'Content-Type': 'application/json'},
                timeout=30,
            )
            _cr.raise_for_status()
            _cd = _cr.json()
            _ct = _cd.get('threat_report', {})
            _renderer_findings = _c_flags(_ct.get('flags', []), final_url, _ct.get('risk_score', 0))
            all_findings.extend(_renderer_findings)
            if verbose:
                print(f"      risk={_ct.get('risk_score', 0)} | "
                      f"{len(_renderer_findings)} renderer finding(s)")
        except Exception as _ce:
            if verbose:
                print(f"      Carapace unavailable: {_ce}")

    # --- Deduplicate, collapse, sort ---
    all_findings = scorer.deduplicate_findings(all_findings)
    all_findings = scorer.context_collapse_check(all_findings)
    all_findings = scorer.sort_findings(all_findings)

    verdict = scorer.derive_verdict(all_findings)
    return verdict, all_findings


def run_single(target_url):
    """Interactive single-URL scan with full output."""
    verdict, all_findings = run_scan(target_url, verbose=True)

    vc = VERDICT_COLOURS.get(verdict, '')
    print(f"\n{'='*70}")
    print(f"VERDICT: {vc}{verdict}{RESET}  |  {len(all_findings)} finding(s)")
    print(f"{'='*70}")

    for f in all_findings:
        print_finding(f, target_url)

    print(f"\n{'='*70}")
    print(f"Scan complete. {len(all_findings)} total finding(s). Verdict: {verdict}")


def run_feedback_mode(target_id=None, cases_path=None):
    """
    Run the scanner against all feedback cases that have expected_verdict set.
    Compares actual result to expected and reports PASS/FAIL.
    """
    cases_path = cases_path or CASES_PATH
    if not os.path.exists(cases_path):
        print(f"{RED}No cases.json found at {cases_path}{RESET}")
        print("Run: python manage.py export_feedback")
        sys.exit(1)

    with open(cases_path, encoding='utf-8') as f:
        cases = json.load(f)

    if target_id is not None:
        cases = [c for c in cases if c['id'] == target_id]
        if not cases:
            print(f"{RED}No case with id={target_id} found in {cases_path}{RESET}")
            sys.exit(1)

    # Only test cases with expected_verdict set — others need developer annotation
    testable = [c for c in cases if c.get('expected_verdict')]
    pending_review = [c for c in cases if not c.get('expected_verdict')]

    print(f"{BOLD}Feedback Test Mode{RESET}")
    print(f"{'─'*70}")
    print(f"Cases loaded: {len(cases)} total | {len(testable)} testable | {len(pending_review)} awaiting review")
    if pending_review:
        print(f"\n{VERDICT_COLOURS['SUSPICIOUS']}Cases needing expected_verdict annotation:{RESET}")
        for c in pending_review:
            note = f' — "{c["note"]}"' if c.get('note') else ''
            print(f"  ID {c['id']:>4}  [{c['reason']:<16}]  {c['actual_verdict']:<10}  {c['url']}{note}")
        print(f"\nEdit {cases_path} to set expected_verdict for each case before testing.")
    print(f"{'─'*70}\n")

    if not testable:
        print("No testable cases. Set expected_verdict in cases.json to proceed.")
        return

    passed = []
    failed = []

    for i, case in enumerate(testable, 1):
        url = case['url']
        expected = case['expected_verdict']
        reason = case['reason']
        note = case.get('note', '')

        print(f"[{i}/{len(testable)}] {url}")
        print(f"       Reason: {reason}" + (f' | Note: "{note}"' if note else ''))
        print(f"       Expected: {expected}")

        try:
            actual_verdict, findings = run_scan(url, verbose=False)
        except Exception as e:
            print(f"       {RED}ERROR: scan failed — {e}{RESET}\n")
            failed.append({'case': case, 'actual': 'ERROR', 'error': str(e)})
            continue

        if actual_verdict == expected:
            print(f"       Got: {actual_verdict} → {GREEN}PASS{RESET}\n")
            passed.append({'case': case, 'actual': actual_verdict})
        else:
            print(f"       Got: {actual_verdict} → {RED}FAIL{RESET}")
            # Show which findings are driving the wrong verdict
            high_sev = [f for f in findings if f.get('severity') in ('CRITICAL', 'HIGH')]
            if high_sev:
                print(f"       High-severity findings ({len(high_sev)}):")
                for f in high_sev[:5]:
                    print(f"         [{f['severity']}] {f.get('title')}")
            print()
            failed.append({'case': case, 'actual': actual_verdict})

    # Summary
    print(f"{'─'*70}")
    total = len(passed) + len(failed)
    print(f"{BOLD}Results: {GREEN}{len(passed)} pass{RESET}{BOLD}, {RED}{len(failed)} fail{RESET}{BOLD} / {total} tested{RESET}")

    if passed:
        ids = [str(r['case']['id']) for r in passed]
        print(f"\nTo resolve passing cases:")
        print(f"  python manage.py resolve_feedback {' '.join(ids)}")

    if failed:
        print(f"\n{RED}Failed cases need detection engine fixes before resolving.{RESET}")
        for r in failed:
            c = r['case']
            print(f"  ID {c['id']:>4}  expected={c['expected_verdict']}  got={r['actual']}  {c['url']}")


def main():
    parser = argparse.ArgumentParser(description='Insight scan test tool')
    parser.add_argument('url', nargs='?', help='URL to scan (single mode)')
    parser.add_argument('--feedback', action='store_true', help='Run against feedback/cases.json')
    parser.add_argument('--id', type=int, dest='case_id', help='Test a single feedback case by ID')
    parser.add_argument('--cases-file', dest='cases_file', default=None,
                        help='Path to cases.json (default: feedback/cases.json)')
    args = parser.parse_args()

    if args.feedback or args.case_id is not None:
        run_feedback_mode(target_id=args.case_id, cases_path=args.cases_file)
    else:
        target_url = args.url or TARGET_URL
        run_single(target_url)


if __name__ == '__main__':
    main()
