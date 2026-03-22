# Insight — Web Threat Scanner

---

[![License](https://img.shields.io/badge/AGPL-3.0--Clause-blue.svg)](https://github.com/DanDreadless/insight_vault1337/blob/main/LICENSE)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Finsight.vault1337.com%2F&label=insight.vault1337.com&link=https%3A%2F%2Finsight.vault1337.com%2F)](https://insight.vault1337.com/)
[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/DanDreadless?link=https%3A%2F%2Fx.com%2FDanDreadless)](https://x.com/DanDreadless)

---

Insight is an open-source passive web threat scanner. Submit any URL and it fetches all public resources — HTML, scripts, headers, certificates — and analyses them entirely on content alone, with no reliance on reputation databases or external threat intelligence APIs. The result is a prioritised findings report covering JavaScript threats, phishing indicators, domain intelligence, security misconfigurations, and the full detected technology stack.

Because detection is content-based, Insight catches zero-day campaigns, freshly registered phishing domains, and newly injected skimmers that reputation feeds haven't yet indexed.

A companion tool to [vault1337.com](https://vault1337.com). Shares the same design system and mirrors the stack.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 / Django 5.2 / Django REST Framework |
| Task Queue | Celery + Redis |
| Frontend | React 19 / TypeScript / Vite / Tailwind CSS 4 |
| Database | PostgreSQL (production) / SQLite (development) |
| Cache / Broker | Redis |

---

## What It Detects

### JavaScript threats (30 checks)
- Remote code execution: `fetch()` + `eval()` async chains — the compromised WordPress staging pattern
- Eval-based obfuscation: `eval(atob(...))`, `eval(unescape(...))`, nested decode chains
- Decrypt-then-execute: WebCrypto API (`crypto.subtle`) used to decrypt and run a payload at runtime
- Payment card skimmers (Magecart-style): DOM queries targeting card/CVV fields + exfiltration
- Keyloggers: keyboard event listeners reading key values with outbound network calls
- Cookie and session exfiltration
- Form hijacking and credential harvesting
- Web3 wallet drainers (Inferno/Angel Drainer pattern)
- HTML smuggling via the Blob API
- Malicious and external service worker registrations
- Crypto miners (CoinHive, CryptoLoot, WebWorker + WASM)
- Shell droppers embedded in JS: Unix (`base64 -d | bash`) and PowerShell (`irm | iex`)
- Dynamic `import()` loading ES modules from external unknown URLs
- Living off Trusted Sites (LoTS): exfiltration routed through Telegram, Discord, Slack, Google Apps Script, and similar platforms to bypass domain-reputation blocklists
- Obfuscation fingerprints: obfuscator.io `_0x` arrays, `String.fromCharCode` chains, high Shannon entropy strings
- Anti-analysis: DevTools detection, right-click disable, auto-redirects

### HTML and structural checks (18 checks)
- Phishing forms with cross-domain `action` targets
- Hidden iframes, base tag hijacking, meta-refresh redirects
- Fake browser update pages (SocGholish / ClearFake signature)
- Fake CAPTCHA / ClickFix social engineering (Win+R execution instructions)
- Clickjacking overlay elements
- IPFS-hosted resources (takedown-resistant phishing and drainer hosting)
- External script preload/prefetch hints — a common WordPress malware injection staging pattern
- Executable download links, inline script anomalies, sensitive HTML comments
- Security misconfigurations: missing SRI, password fields without autocomplete, login forms over HTTP

### Domain intelligence (10 checks)
- Subdomain and SLD typosquatting via Levenshtein edit distance against a brand watchlist
- Exact brand impersonation in subdomain tokens
- IDN / homograph attacks (Cyrillic and mixed-script lookalikes)
- DGA probability scoring (consonant ratio, entropy, English subword absence)
- High-risk TLDs (`.xyz`, `.top`, `.click`, `.loan`, `.zip`, `.cyou`, and 20+ more)
- Digit substitution (`g00gle`, `faceb00k`)
- Abuse-prone free hosting platforms (Cloudflare R2, Pages.dev, Firebase) with random subdomains

### HTTP headers (12 checks)
Missing CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; server/version disclosure; deprecated software versions; insecure cookie flags; CORS wildcard with credentials.

### TLS / SSL (6 checks)
Certificate expiry, self-signed certificates, hostname mismatch, Let's Encrypt on brand-impersonating domains, deprecated TLS versions, newly issued certificates on suspicious domains.

### Verdict
| Verdict | Condition |
|---|---|
| MALICIOUS | Any CRITICAL finding |
| SUSPICIOUS | Any HIGH finding, or 2+ MEDIUM findings |
| CLEAN | LOW and INFO findings only |
| UNKNOWN | No findings |

Context collapse rules fire additional synthetic findings when signal combinations indicate coordinated attack infrastructure (e.g. DGA domain + hidden iframe + obfuscated JS → CRITICAL "drive-by malware delivery").

### Technology stack detection
Identifies CMS, JS frameworks, build tools, libraries, CSS frameworks, backend runtime, web server, CDN, hosting platform, analytics, security tools, and payment providers — displayed as colour-coded badges with logos on the results page.

---

## Running Locally

### Requirements

- Python 3.11+
- Node.js 18+
- Redis 7+ (running locally or via Docker)

### 1. Start Redis

```bash
# Docker (any OS)
docker run -d -p 6379:6379 redis:7-alpine
```

### 2. Backend

```bash
git clone https://github.com/DanDreadless/insight_vault1337.git
cd insight_vault1337/backend

pip install -r requirements.txt

cp ../.env.sample ../.env
# Edit ../.env — set a SECRET_KEY value at minimum

python manage.py migrate
python manage.py runserver
```

### 3. Celery worker (separate terminal — required for scans to run)

```bash
cd backend
celery -A insight worker -l info
```

### 4. Frontend (separate terminal)

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies all `/api/` requests to Django on `:8000`.

### Environment variables

Copy `.env.sample` to `.env` in the repo root. The only required change for local development is setting a `SECRET_KEY`.

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *(insecure sample)* | Change before running |
| `DEBUG` | `True` | Set `False` in production |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `DATABASE_URL` | `sqlite:///db.sqlite3` | Use PostgreSQL in production |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | |
| `RATE_LIMIT_SCANS_PER_HOUR` | `5` | Per IP |
| `MAX_SCAN_RESOURCES` | `50` | External scripts analysed per scan |
| `SCAN_TIMEOUT_SECONDS` | `60` | Hard Celery task limit |

### Full stack via Docker

If you prefer not to install Python and Node locally:

```bash
cp .env.sample .env   # edit SECRET_KEY
docker-compose up --build
```

Stops all services and removes volumes:

```bash
docker-compose down -v
```

---

## API

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scan/` | Submit a URL for scanning |
| GET | `/api/scan/{id}/` | Poll results |
| GET | `/api/scan/{id}/stream/` | Server-Sent Events progress stream |
| GET | `/api/health/` | Health check |
| GET | `/api/schema/swagger-ui/` | Interactive API docs |

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. This ensures that:

- You are free to use, modify, and share this software under the terms of the AGPL-3.0.
- If you deploy this software as a hosted service, you must make the source code — including any modifications — available to your users under the same licence.

The full licence text is in the [LICENSE](LICENSE) file.

## Commercial Use

Insight is open-source, but organisations that need to deploy it privately without the AGPL's copyleft requirements can obtain a commercial licence.

**Benefits of a commercial licence:**
1. Deploy in proprietary environments without open-sourcing modifications.
2. Support continued development of the project.

**To enquire:** contact via LinkedIn — [www.linkedin.com/in/dan-pickering](https://www.linkedin.com/in/dan-pickering)

## Supporting the Project

If Insight is useful to you, consider supporting it through sponsorship or donations. Your contributions help keep it free and actively maintained.

Thank you for using Insight.

---
