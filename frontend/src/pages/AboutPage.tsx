import { Link } from 'react-router-dom'

const DETECTION_METHODS = [
  {
    title: 'JavaScript Analysis',
    items: [
      'Eval-based obfuscation (eval/atob/unescape chains)',
      'Obfuscator.io hex-array string rotation',
      'String.fromCharCode character construction',
      'High-entropy string detection (Shannon entropy > 4.8 bits/char)',
      'Cookie exfiltration and session theft patterns',
      'Form hijacking and credential harvesting',
      'Keyloggers (keyboard event + outbound network call)',
      'Payment skimmers (Magecart / direct DOM access to card fields)',
      'Cryptocurrency miners (CoinHive, stratum+tcp, WebWorker + WASM)',
      'Unix shell dropper (base64 -d | bash embedded in JS)',
      'PowerShell dropper (irm | iex embedded in JS)',
      'HTML smuggling (Blob + createObjectURL + auto-download)',
      'Web3 wallet drainer (window.ethereum + signing calls)',
      'Malicious service worker (blob:/data: URI or external domain)',
      'Living off Trusted Sites exfiltration (Telegram, Discord, Slack, Google Apps Script)',
      'navigator.sendBeacon() to external domain',
      'document.write() loading external script',
      'Hidden iframe injection and forced downloads',
      'Clipboard hijacking and autonomous clipboard writes',
      'Auto-redirects, devtools evasion, right-click disabling',
      'Split-join URL evasion',
      'bash -c / curl / wget to bare IP address (C2 indicator)',
    ],
  },
  {
    title: 'HTML Structure',
    items: [
      'Phishing forms (cross-domain action URLs)',
      'Hidden iframes (display:none, width:0, off-screen positioning)',
      'Base tag hijacking for URL manipulation',
      'Meta refresh rapid redirects',
      'Right-click and text selection blocking',
      'Suspicious executable download links (.exe, .msi, .ps1, etc.)',
      'Sensitive information in HTML comments',
      'External scripts without Subresource Integrity (SRI)',
      'Clickjacking overlay elements (high z-index full-viewport layers)',
      'Password forms transmitted over HTTP',
      'Password field missing autocomplete attribute',
      'Noscript block containing external URL redirect',
      'Inline script dominates page content (script-delivery vehicle)',
      'Fake browser update page (SocGholish / ClearFake signature)',
      'Fake CAPTCHA / ClickFix (Win+R paste-and-run social engineering)',
      'IPFS-hosted resources (takedown-resistant phishing infrastructure)',
    ],
  },
  {
    title: 'Domain Intelligence',
    items: [
      'High-risk TLD detection (.tk, .xyz, .click, .zip, .mov, etc.)',
      'DGA probability scoring (Shannon entropy + consonant density)',
      'Brand impersonation in subdomains (paypal.evil.com pattern)',
      'Homograph / IDN Unicode character spoofing (Cyrillic lookalikes)',
      'Brand keywords in registered domain (typosquatting)',
      'Excessive subdomain depth',
      'Number substitution / l33t-speak impersonation (g00gle, paypa1)',
    ],
  },
  {
    title: 'Security Headers',
    items: [
      'HTTP (non-HTTPS) plaintext transmission',
      'Missing Content-Security-Policy header',
      "CSP quality issues (unsafe-inline, unsafe-eval directives)",
      'Missing or weak X-Frame-Options (clickjacking)',
      'Missing Strict-Transport-Security (HSTS) or low max-age',
      'Missing X-Content-Type-Options nosniff',
      'Missing Referrer-Policy and Permissions-Policy',
      'Server version and X-Powered-By technology disclosure',
      'Deprecated end-of-life server software (Apache 2.2, PHP 5.x, IIS 6)',
      'Insecure cookie flags (missing HttpOnly, Secure, SameSite)',
      'CORS wildcard + credentials misconfiguration',
    ],
  },
  {
    title: 'SSL / TLS Analysis',
    items: [
      'Certificate expiry and validity period',
      'Self-signed certificate detection',
      'Hostname / SAN mismatch',
      "Let's Encrypt certificate on brand-impersonating domain",
      'Deprecated TLS version acceptance (TLS 1.0, TLS 1.1)',
      'Freshly issued certificate (< 7 days old — phishing indicator)',
    ],
  },
  {
    title: 'Technology Stack Detection',
    items: [
      'CMS detection (WordPress, Drupal, Joomla, Shopify, etc.)',
      'JavaScript framework identification (React, Vue, Angular, Next.js, etc.)',
      'CSS framework detection (Bootstrap, Tailwind, Bulma, etc.)',
      'Analytics and tag managers (GA4, GTM, Hotjar, Mixpanel, etc.)',
      'Backend runtime and web server detection (PHP, Python, Node.js, etc.)',
      'CDN provider identification (Cloudflare, Fastly, Akamai, etc.)',
      'Payment and third-party SDK detection (Stripe, PayPal, etc.)',
    ],
  },
  {
    title: 'File Downloads',
    items: [
      'Direct file download detection (URL responds with binary content)',
      'SHA-256 hash computed and reported for downloaded files',
      'Content-Type / file extension mismatch detection (obfuscation indicator)',
      'File integrity guidance — VirusTotal hash check, sandbox detonation',
      'Header, SSL, and domain analysis still runs on download URLs',
    ],
  },
]

export default function AboutPage() {
  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-white mb-3">
          About <span style={{ color: '#bd363a' }}>Insight</span>
        </h1>
        <p className="text-white/60 text-lg leading-relaxed max-w-2xl">
          A passive web threat scanner that analyses public URLs for malicious content,
          JavaScript-based attacks, and security vulnerabilities — without any active exploitation.
        </p>
      </div>

      {/* How it works */}
      <section
        className="rounded-xl p-6 mb-8"
        style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.07)' }}
      >
        <h2 className="text-lg font-bold text-white mb-4">How It Works</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm text-white/65 leading-relaxed">
          <div>
            <p className="font-semibold text-white/85 mb-2">1. Passive Fetch</p>
            <p>
              The scanner fetches the target URL using a standard HTTP GET request, exactly as a
              browser would. No JavaScript is executed, no forms are submitted, and no exploits
              are attempted. robots.txt is checked and noted, but does not block the scan.
            </p>
          </div>
          <div>
            <p className="font-semibold text-white/85 mb-2">2. Content Analysis</p>
            <p>
              The HTML, embedded scripts, HTTP headers, SSL certificate, and domain name are
              analysed using pattern-matching, entropy analysis, and heuristic scoring entirely
              within the scanner. No external threat intel APIs are used — detection catches
              zero-day campaigns that reputation databases have not yet indexed.
            </p>
          </div>
          <div>
            <p className="font-semibold text-white/85 mb-2">3. Verdict</p>
            <p>
              Findings are aggregated and scored. Context collapse detection identifies when
              multiple moderate signals converge into high-confidence indicators of malice
              (e.g. DGA domain + hidden iframe + obfuscated JS = drive-by delivery). Identical
              scans within the same session are deduplicated from cache.
            </p>
          </div>
        </div>
      </section>

      {/* What it does NOT do */}
      <section
        className="rounded-xl p-6 mb-8"
        style={{ backgroundColor: 'rgba(22,163,74,0.08)', border: '1px solid rgba(22,163,74,0.2)' }}
      >
        <h2 className="text-lg font-bold text-white mb-3">Privacy &amp; Limitations</h2>
        <ul className="text-sm text-white/65 space-y-2">
          <li>No credentials are stored or logged — only the submitted URL and scan findings.</li>
          <li>No active exploitation, port scanning, or vulnerability probing is performed.</li>
          <li>JavaScript is not executed — dynamic content rendered client-side is not analysed.</li>
          <li>Detection is content-based only. Novel or highly targeted malware may evade static analysis.</li>
          <li>Rate limited to 5 scans per hour per IP address to prevent abuse.</li>
          <li>Only public HTTP/HTTPS URLs can be scanned — private networks and loopback addresses are blocked.</li>
          <li>robots.txt Disallow rules are noted as an informational finding but do not stop the scan.</li>
        </ul>
      </section>

      {/* Detection methods */}
      <section className="mb-8">
        <h2 className="text-lg font-bold text-white mb-4">Detection Methods</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {DETECTION_METHODS.map((method) => (
            <div
              key={method.title}
              className="rounded-xl p-5"
              style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.07)' }}
            >
              <h3 className="font-semibold text-white mb-3">{method.title}</h3>
              <ul className="text-xs text-white/55 space-y-1.5">
                {method.items.map((item) => (
                  <li key={item} className="flex items-start gap-1.5">
                    <span style={{ color: '#bd363a', flexShrink: 0 }}>•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <div className="text-center py-8">
        <p className="text-white/50 text-sm mb-4">
          Part of the{' '}
          <a
            href="https://vault1337.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline"
            style={{ color: '#bd363a' }}
          >
            vault1337.com
          </a>{' '}
          security toolset.
        </p>
        <Link
          to="/"
          className="inline-block text-sm px-6 py-3 rounded-lg font-semibold text-white"
          style={{ backgroundColor: '#bd363a' }}
          onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#a52e32' }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#bd363a' }}
        >
          Start Scanning
        </Link>
      </div>
    </div>
  )
}
