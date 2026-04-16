"""
Known-good domain whitelist.

Used to suppress or downgrade findings for well-known, legitimate third-party
services that appear on the vast majority of normal websites.

Design rules:
  - Entries are *registrable domains* (SLD + TLD, no subdomain) so a single
    entry covers all subdomains.  e.g. 'googleapis.com' covers
    ajax.googleapis.com, fonts.googleapis.com, etc.
  - Whitelisting suppresses false positives; it never overrides a CRITICAL
    finding that has additional corroborating signals.
  - Organised by category so reviewers can audit each group independently.

DELIBERATELY EXCLUDED — generic infrastructure that is routinely abused:
  - cloudflare.com     — WAF/CDN used by phishing pages and malware campaigns
  - cloudfront.net     — AWS CDN trivially used to host malicious payloads
  - azureedge.net      — Azure CDN, same issue
  - fastly.net         — Generic CDN, same issue
  - akamai.com         — Generic CDN, same issue
  - akamaihd.net       — Akamai media CDN, same issue
  - unpkg.com          — npm CDN; a malicious package publish reaches all sites
  - wp.com             — WordPress hosting; commonly hacked / phishing lures
  - wpengine.com       — WordPress hosting
  - squarespace.com    — Website builder hosting used for phishing clones
  - shopify.com        — E-commerce platform used for scam storefronts
  - wix.com            — Website builder hosting used for phishing pages
  - imperva.com        — WAF vendor CDN still abused by protected malicious sites
  - incapsula.com      — Legacy Imperva, same issue
  - akamai.com         — Listed under CDN exclusion above

These domains provide zero signal about the legitimacy of the content they
serve — a site being behind Cloudflare or hosted on Shopify tells you nothing.
"""

import tldextract

# ---------------------------------------------------------------------------
# Category sets — purpose-specific services only
# ---------------------------------------------------------------------------

# Tag management & web analytics
# These domains have a narrow, well-defined purpose (analytics beacons,
# tag firing) and are not meaningfully abused in the specific checks applied.
ANALYTICS_DOMAINS: frozenset[str] = frozenset({
    'googletagmanager.com',   # Google Tag Manager
    'google-analytics.com',   # Google Analytics (UA + GA4)
    'googletagservices.com',  # Google tag services
    'doubleclick.net',        # Google Ads / Analytics infrastructure
    'clarity.ms',             # Microsoft Clarity
    'hotjar.com',             # Hotjar heatmaps / session recording
    'mixpanel.com',           # Mixpanel product analytics
    'segment.com',            # Segment CDP
    'segment.io',             # Segment CDN
    'amplitude.com',          # Amplitude analytics
    'heap.io',                # Heap analytics
    'fullstory.com',          # FullStory session replay
    'logrocket.com',          # LogRocket session replay
    'matomo.org',             # Matomo (open-source analytics)
    'piwik.pro',              # Piwik PRO analytics
    'kissmetrics.com',        # Kissmetrics
    'woopra.com',             # Woopra analytics
    'mouseflow.com',          # Mouseflow heatmaps
    'crazyegg.com',           # Crazy Egg heatmaps
    'luckyorange.com',        # Lucky Orange analytics
})

# Purpose-specific CDNs and font services.
# Generic infrastructure CDNs (Cloudflare, CloudFront, Fastly, Akamai, unpkg)
# are intentionally excluded — see module docstring.
CDN_DOMAINS: frozenset[str] = frozenset({
    'jsdelivr.net',           # jsDelivr — open-source package CDN
    'googleapis.com',         # Google APIs (ajax.googleapis.com, fonts, etc.)
    'gstatic.com',            # Google static assets (fonts.gstatic.com)
    'bootstrapcdn.com',       # Bootstrap CDN (maxcdn / stackpath)
    'jquery.com',             # jQuery Foundation CDN (code.jquery.com)
    'fontawesome.com',        # Font Awesome icon library
    'typekit.com',            # Adobe Fonts (formerly Typekit)
    'typekit.net',            # Adobe Fonts CDN
})

# Payment processors — cross-domain form submissions to these are expected.
PAYMENT_DOMAINS: frozenset[str] = frozenset({
    'paypal.com',             # PayPal checkout
    'paypalobjects.com',      # PayPal static assets / buttons
    'stripe.com',             # Stripe checkout
    'stripecdn.com',          # Stripe CDN
    'stripe.network',         # Stripe infrastructure
    'braintreegateway.com',   # Braintree (PayPal)
    'squareup.com',           # Square payments
    'square.com',             # Square
    'checkout.com',           # Checkout.com
    'adyen.com',              # Adyen
    'worldpay.com',           # Worldpay (FIS)
    'cybersource.com',        # CyberSource (Visa)
    'authorize.net',          # Authorize.Net
    'sagepay.com',            # Sage Pay
    'opayo.com',              # Opayo (formerly Sage Pay)
    'klarna.com',             # Klarna BNPL
    'afterpay.com',           # Afterpay BNPL
    'clearpay.co.uk',         # Clearpay (Afterpay UK)
    'gocardless.com',         # GoCardless direct debit
    'mollie.com',             # Mollie payments
})

# Social media platforms — pixels and embed scripts from these are ubiquitous
# on legitimate sites and are not meaningfully exploited via the checks applied.
SOCIAL_DOMAINS: frozenset[str] = frozenset({
    'facebook.com',           # Facebook pixel, SDK
    'facebook.net',           # Facebook CDN (connect.facebook.net)
    'fbcdn.net',              # Facebook static assets
    'twitter.com',            # Twitter/X widgets
    'twimg.com',              # Twitter/X static assets
    'x.com',                  # Twitter/X (new domain)
    'linkedin.com',           # LinkedIn insight tag
    'licdn.com',              # LinkedIn static assets
    'instagram.com',          # Instagram embeds
    'youtube.com',            # YouTube embeds
    'ytimg.com',              # YouTube static assets
    'youtube-nocookie.com',   # YouTube privacy-enhanced embeds
    'vimeo.com',              # Vimeo embeds
    'vimeocdn.com',           # Vimeo CDN
    'tiktok.com',             # TikTok pixel
    'pinterest.com',          # Pinterest tag
    'snapchat.com',           # Snap pixel
    'reddit.com',             # Reddit pixel
})

# Application error monitoring & observability
MONITORING_DOMAINS: frozenset[str] = frozenset({
    'sentry.io',              # Sentry error tracking
    'bugsnag.com',            # Bugsnag error monitoring
    'rollbar.com',            # Rollbar error monitoring
    'raygun.io',              # Raygun APM
    'newrelic.com',           # New Relic APM
    'nr-data.net',            # New Relic data ingest
    'datadoghq.com',          # Datadog RUM
    'dynatrace.com',          # Dynatrace RUM
    'appdynamics.com',        # AppDynamics RUM
    'honeybadger.io',         # Honeybadger errors
    'airbrake.io',            # Airbrake errors
})

# Cookie consent / privacy compliance platforms
CONSENT_DOMAINS: frozenset[str] = frozenset({
    'cookielaw.org',          # OneTrust
    'onetrust.com',           # OneTrust
    'cookiebot.com',          # Cookiebot / Usercentrics
    'iubenda.com',            # iubenda consent solution
    'trustarc.com',           # TrustArc (formerly TRUSTe)
    'cookiepro.com',          # CookiePro
    'usercentrics.eu',        # Usercentrics CMP
    'usercentrics.com',       # Usercentrics CMP
    'didomi.io',              # Didomi CMP
    'quantcast.com',          # Quantcast Choice CMP
    'osano.com',              # Osano CMP
})

# Live chat & customer support widgets
SUPPORT_DOMAINS: frozenset[str] = frozenset({
    'intercom.io',            # Intercom chat
    'intercomcdn.com',        # Intercom CDN
    'tawk.to',                # Tawk.to live chat
    'livechatinc.com',        # LiveChat
    'livechat.com',           # LiveChat
    'zendesk.com',            # Zendesk chat / support
    'zdassets.com',           # Zendesk static assets
    'freshworks.com',         # Freshchat / Freshdesk
    'freshdesk.com',          # Freshdesk
    'crisp.chat',             # Crisp chat
    'drift.com',              # Drift chat
    'hubspot.com',            # HubSpot chat (also marketing)
    'gorgias.io',             # Gorgias e-commerce support
    'tidio.com',              # Tidio chat
    'olark.com',              # Olark chat
    'chatra.io',              # Chatra chat
})

# Marketing automation & CRM
MARKETING_DOMAINS: frozenset[str] = frozenset({
    'hs-scripts.com',         # HubSpot tracking script CDN
    'hsforms.com',            # HubSpot forms
    'hscollectedforms.net',   # HubSpot form data
    'marketo.net',            # Marketo (Adobe)
    'mktoresp.com',           # Marketo response tracking
    'pardot.com',             # Pardot / Marketing Cloud (Salesforce)
    'salesforce.com',         # Salesforce
    'mailchimp.com',          # Mailchimp
    'list-manage.com',        # Mailchimp subscription forms
    'klaviyo.com',            # Klaviyo email/SMS
    'braze.com',              # Braze customer engagement
    'iterable.com',           # Iterable marketing
    'activecampaign.com',     # ActiveCampaign
    'drip.com',               # Drip email marketing
    'convertkit.com',         # ConvertKit
    'omnisend.com',           # Omnisend e-commerce marketing
    'sendgrid.net',           # SendGrid (Twilio)
    'constantcontact.com',    # Constant Contact
    'campaignmonitor.com',    # Campaign Monitor
    'dotdigital.com',         # Dotdigital
})

# CAPTCHA & purpose-built bot protection scripts.
# Generic WAF/CDN providers (Cloudflare, Imperva, Akamai) are excluded —
# being protected by a WAF does not make a site's content legitimate.
CAPTCHA_DOMAINS: frozenset[str] = frozenset({
    'recaptcha.net',          # Google reCAPTCHA (privacy-friendly domain)
    'hcaptcha.com',           # hCaptcha
    'perimeterx.com',         # PerimeterX bot protection script
    'datadome.co',            # DataDome bot management script
    'kasada.io',              # Kasada bot protection script
    'arkoselabs.com',         # Arkose Labs FunCaptcha
    'funcaptcha.com',         # FunCaptcha (Arkose)
})

# No-code / automation / app-builder platforms.
# These platforms serve their own framework code (Next.js chunks, SDK files)
# from platform-owned CDN subdomains.  Marking the CDN domain as known-good
# suppresses false positives from framework code (webpack bundles, etc.)
# that legitimately use patterns like createElement/script/appendChild.
# Note: this does NOT skip analysis of inline scripts on pages hosted at
# these platforms — only external scripts loaded from the platform CDN.
NOCODE_DOMAINS: frozenset[str] = frozenset({
    'zapier.com',             # Zapier automation platform CDN (interfaces.zapier.com)
    'typeform.com',           # Typeform form builder
    'webflow.com',            # Webflow site builder
    'webflowcdn.com',         # Webflow CDN
})

# ---------------------------------------------------------------------------
# Combined lookup set
# ---------------------------------------------------------------------------

ALL_KNOWN_GOOD: frozenset[str] = (
    ANALYTICS_DOMAINS
    | CDN_DOMAINS
    | PAYMENT_DOMAINS
    | SOCIAL_DOMAINS
    | MONITORING_DOMAINS
    | CONSENT_DOMAINS
    | SUPPORT_DOMAINS
    | MARKETING_DOMAINS
    | CAPTCHA_DOMAINS
    | NOCODE_DOMAINS
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _registrable(url_or_host: str) -> str:
    """Return the registrable domain (SLD.TLD) from a URL or hostname."""
    ext = tldextract.extract(url_or_host)
    return f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain


def is_known_good(url_or_host: str) -> bool:
    """Return True if the URL/hostname belongs to any known-good domain."""
    return _registrable(url_or_host) in ALL_KNOWN_GOOD


def is_analytics(url_or_host: str) -> bool:
    """Return True if the domain is a known analytics or tag management service."""
    return _registrable(url_or_host) in ANALYTICS_DOMAINS


def is_cdn(url_or_host: str) -> bool:
    """Return True if the domain is a known purpose-specific CDN."""
    return _registrable(url_or_host) in CDN_DOMAINS


def is_payment_processor(url_or_host: str) -> bool:
    """Return True if the domain is a known payment processor."""
    return _registrable(url_or_host) in PAYMENT_DOMAINS
