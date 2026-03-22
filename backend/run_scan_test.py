"""
Standalone scan test — runs all analyser modules directly against a URL.
No Django/Celery/Redis required.
"""
import sys
import os
import ssl
import json
import requests
from urllib.parse import urlparse

# Ensure stdout/stderr use UTF-8 on Windows (avoids CP1252 UnicodeEncodeError
# when decoded evidence contains non-ASCII bytes).
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Add backend to path so scanner modules resolve
sys.path.insert(0, os.path.dirname(__file__))

# Minimal Django settings stub so validators/models don't crash on import
os.environ.setdefault('DJANGO_SETTINGS_MODULE', '')

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

TARGET_URL = 'https://www.snowbank.nl'

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-GB,en;q=0.5',
}


def fetch(url, max_bytes=5 * 1024 * 1024):
    r = requests.get(url, headers=HEADERS, timeout=(5, 15),
                     verify=True, allow_redirects=True, stream=True)
    content = b''
    for chunk in r.iter_content(8192):
        content += chunk
        if len(content) >= max_bytes:
            break
    text = content.decode('utf-8', errors='replace')
    return {
        'url': r.url,
        'status_code': r.status_code,
        'headers': dict(r.headers),
        'text': text,
    }


def print_finding(f, idx):
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
    if resource and resource != TARGET_URL:
        print(f"\n  Source: {resource}")


def main():
    print(f"Scanning: {TARGET_URL}\n")

    # --- Fetch main page ---
    print("[1/6] Fetching page...")
    resp = fetch(TARGET_URL)
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
    print(f"      Found {len(scripts)} script(s)")
    js_count = 0
    for script in scripts[:50]:
        if script.get('inline'):
            content = script.get('content', '').strip()
            if content:
                jf = js_analyser.analyse_js(content, final_url)
                for f in jf:
                    f.setdefault('resource_url', final_url)
                all_findings.extend(jf)
                js_count += 1
        else:
            script_url = script.get('url', '')
            if not script_url:
                continue
            try:
                sr = fetch(script_url, max_bytes=1024 * 1024)
                jf = js_analyser.analyse_js(sr['text'], script_url)
                for f in jf:
                    f['resource_url'] = script_url
                all_findings.extend(jf)
                print(f"      Analysed: {script_url}")
                js_count += 1
            except Exception as e:
                print(f"      Failed: {script_url} — {e}")

    print(f"      Analysed {js_count} script(s), {len([f for f in all_findings if f.get('category') == 'JavaScript'])} JS finding(s)")

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

    for i, f in enumerate(all_findings):
        print_finding(f, i)

    print(f"\n{'='*70}")
    print(f"Scan complete. {len(all_findings)} total finding(s). Verdict: {verdict}")


if __name__ == '__main__':
    main()
