"""
Standalone scan test — runs all analyser modules directly against a URL.
No Django/Celery/Redis required.

Usage:
    python run_scan_test.py [URL]

If URL is omitted, TARGET_URL below is used.
"""
import sys
import os
import time
import requests
from urllib.parse import urlparse
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
from scanner.modules.known_good_domains import is_known_good

TARGET_URL = 'https://www.cloudretouch.com'

# --- Tuning knobs ---
JS_WORKERS         = 8              # parallel script fetches
JS_FETCH_TIMEOUT   = (5, 6)         # (connect, read) seconds per script
JS_PHASE_TIMEOUT   = 60             # hard wall-clock cap for entire JS fetch phase (seconds)
JS_MAX_SCRIPTS     = 50             # max external scripts to analyse
JS_MAX_BYTES            = 50 * 1024   # 50 KB per script (download cap — we only analyse 20KB anyway)
JS_DOWNLOAD_HARD_TIMEOUT = 8          # total wall-clock seconds for any single download
JS_SKIP_ABOVE_BYTES = 150 * 1024    # skip scripts >150KB — large bundles are almost never
                                    # the injection vector and cause jsbeautifier to hang

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-GB,en;q=0.5',
}


def fetch_page(url, max_bytes=5 * 1024 * 1024):
    r = requests.get(url, headers=HEADERS, timeout=(5, 15),
                     verify=True, allow_redirects=True, stream=True)
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
                     verify=True, allow_redirects=True, stream=True)
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
    # Injected malware is a compact blob always prepended/appended to the
    # legitimate file — 10KB from each end is more than enough to catch it.
    # Keeping the sample small is critical: jsbeautifier is CPU-bound and
    # Python's GIL serialises it across all worker threads, so large samples
    # cause the entire JS phase to stall.
    EDGE = 10 * 1024
    if len(js_text) > EDGE * 2:
        js_sample = js_text[:EDGE] + '\n' + js_text[-EDGE:]
    else:
        js_sample = js_text

    findings = js_analyser.analyse_js(js_sample, url)
    for f in findings:
        f['resource_url'] = url
    return url, findings, size_kb


def print_finding(f, target_url):
    sev = f.get('severity', '?')
    sev_colours = {
        'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
        'MEDIUM': '\033[33m',   'LOW': '\033[94m', 'INFO': '\033[90m',
    }
    reset = '\033[0m'
    colour = sev_colours.get(sev, '')
    print(f"\n{'='*70}")
    print(f"{colour}[{sev}]{reset} [{f.get('category')}] {f.get('title')}")
    print(f"  {f.get('description', '')}")
    evidence = f.get('evidence', '')
    if evidence:
        print(f"\n  --- EVIDENCE ---")
        for line in evidence.splitlines():
            print(f"  {line}")
    resource = f.get('resource_url', '')
    if resource and resource != target_url:
        print(f"\n  Source: {resource}")


def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    print(f"Scanning: {target_url}\n")

    # --- Fetch main page ---
    print("[1/6] Fetching page...")
    resp = fetch_page(target_url)
    final_url = resp['url']
    html_content = resp['text']
    response_headers = resp['headers']
    status_code = resp['status_code']
    print(f"      Status: {status_code} | Final URL: {final_url}")

    all_findings = []

    # --- Headers ---
    print("[2/6] Analysing headers...")
    hf = header_analyser.analyse_headers(response_headers, final_url, status_code)
    for f in hf:
        f.setdefault('resource_url', final_url)
    all_findings.extend(hf)
    print(f"      {len(hf)} finding(s)")

    # --- SSL ---
    print("[3/6] Analysing SSL...")
    hostname = urlparse(final_url).hostname or ''
    if hostname and urlparse(final_url).scheme == 'https':
        try:
            sf = ssl_analyser.analyse_ssl(hostname, 443)
            for f in sf:
                f.setdefault('resource_url', final_url)
            all_findings.extend(sf)
            print(f"      {len(sf)} finding(s)")
        except Exception as e:
            print(f"      SSL error: {e}")

    # --- Domain ---
    print("[4/6] Analysing domain...")
    df = domain_intelligence.analyse_domain(final_url)
    for f in df:
        f.setdefault('resource_url', final_url)
    all_findings.extend(df)
    print(f"      {len(df)} finding(s)")

    # --- HTML ---
    print("[5/6] Analysing HTML...")
    resources = collect_resources(html_content, final_url)
    htmlf = html_analyser.analyse_html(html_content, final_url, resources)
    for f in htmlf:
        f.setdefault('resource_url', final_url)
    all_findings.extend(htmlf)
    print(f"      {len(htmlf)} finding(s)")

    # --- JavaScript ---
    print("[6/6] Analysing JavaScript...")
    scripts = resources.get('scripts', [])

    # Split inline (instant) vs external (needs network fetch)
    inline_scripts = [s for s in scripts if s.get('inline') and s.get('content', '').strip()]
    external_scripts = [s for s in scripts if not s.get('inline') and s.get('url')]

    # Filter out known-good CDN/analytics domains — no threat signal there
    def _should_skip(url):
        return is_known_good(url)

    skipped = [s for s in external_scripts if _should_skip(s['url'])]
    external_scripts = [s for s in external_scripts if not _should_skip(s['url'])]
    external_scripts = external_scripts[:JS_MAX_SCRIPTS]

    print(f"      {len(inline_scripts)} inline | {len(external_scripts)} external to fetch "
          f"| {len(skipped)} known-good skipped")

    js_findings = []
    js_count = 0

    # Inline scripts — no I/O, analyse immediately
    for script in inline_scripts:
        jf = js_analyser.analyse_js(script['content'], final_url)
        for f in jf:
            f.setdefault('resource_url', final_url)
        js_findings.extend(jf)
        js_count += 1

    # External scripts — parallel fetch + analyse
    if external_scripts:
        from concurrent.futures import TimeoutError as FuturesTimeout
        phase_deadline = time.monotonic() + JS_PHASE_TIMEOUT
        futures = {}
        # Do NOT use 'with' here — the context manager calls shutdown(wait=True)
        # on exit which blocks until ALL threads finish, including hung ones.
        # We call shutdown(wait=False) ourselves after the timeout so the main
        # thread can continue and print results immediately.
        pool = ThreadPoolExecutor(max_workers=JS_WORKERS)
        try:
            for script in external_scripts:
                fut = pool.submit(fetch_and_analyse_script, script['url'])
                futures[fut] = script['url']

            try:
                for fut in as_completed(futures, timeout=JS_PHASE_TIMEOUT):
                    if time.monotonic() > phase_deadline:
                        print(f"      JS phase timeout ({JS_PHASE_TIMEOUT}s) — stopping early")
                        break
                    script_url = futures[fut]
                    try:
                        _, jf, size_kb = fut.result()
                        js_findings.extend(jf)
                        size_note = f" [{size_kb}KB]" if size_kb > 50 else ""
                        finding_note = f" — {len(jf)} finding(s)" if jf else ""
                        print(f"      OK   {script_url}{size_note}{finding_note}")
                        js_count += 1
                    except Exception as e:
                        print(f"      ERR  {script_url} — {e}")
            except FuturesTimeout:
                pending = sum(1 for f in futures if not f.done())
                print(f"      JS phase timeout ({JS_PHASE_TIMEOUT}s) — {pending} script(s) abandoned")
        finally:
            pool.shutdown(wait=False)  # Release main thread immediately; daemon threads clean up

    all_findings.extend(js_findings)
    print(f"      Analysed {js_count} script(s) | "
          f"{len([f for f in js_findings if f.get('category') == 'JavaScript'])} JS finding(s)")

    # --- Deduplicate, collapse, sort ---
    all_findings = scorer.deduplicate_findings(all_findings)
    all_findings = scorer.context_collapse_check(all_findings)
    all_findings = scorer.sort_findings(all_findings)

    # --- Verdict ---
    verdict = scorer.derive_verdict(all_findings)
    verdict_colours = {
        'MALICIOUS': '\033[91m', 'SUSPICIOUS': '\033[93m',
        'CLEAN': '\033[92m',     'UNKNOWN': '\033[90m',
    }
    vc = verdict_colours.get(verdict, '')
    reset = '\033[0m'
    print(f"\n{'='*70}")
    print(f"VERDICT: {vc}{verdict}{reset}  |  {len(all_findings)} finding(s)")
    print(f"{'='*70}")

    for f in all_findings:
        print_finding(f, target_url)

    print(f"\n{'='*70}")
    print(f"Scan complete. {len(all_findings)} total finding(s). Verdict: {verdict}")


if __name__ == '__main__':
    main()
