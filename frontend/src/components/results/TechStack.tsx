interface Technology {
  name: string
  category: string
  version?: string
  confidence: 'high' | 'medium'
}

interface TechStackProps {
  technologies: Technology[]
}

const CATEGORY_ORDER = [
  'CMS',
  'JS Framework',
  'JS Library',
  'CSS Framework',
  'Build Tool',
  'Backend',
  'Web Server',
  'CDN',
  'Hosting',
  'Analytics',
  'Security',
  'Payment',
]

const CATEGORY_COLOURS: Record<string, { bg: string; text: string; border: string }> = {
  'CMS':          { bg: 'rgba(139,92,246,0.15)', text: '#c4b5fd', border: 'rgba(139,92,246,0.4)' },
  'JS Framework': { bg: 'rgba(59,130,246,0.15)', text: '#93c5fd', border: 'rgba(59,130,246,0.4)' },
  'JS Library':   { bg: 'rgba(14,165,233,0.15)', text: '#7dd3fc', border: 'rgba(14,165,233,0.4)' },
  'CSS Framework':{ bg: 'rgba(20,184,166,0.15)', text: '#5eead4', border: 'rgba(20,184,166,0.4)' },
  'Build Tool':   { bg: 'rgba(168,85,247,0.12)', text: '#d8b4fe', border: 'rgba(168,85,247,0.35)' },
  'Backend':      { bg: 'rgba(234,179,8,0.12)',  text: '#fde047', border: 'rgba(234,179,8,0.35)' },
  'Web Server':   { bg: 'rgba(107,114,128,0.15)',text: '#9ca3af', border: 'rgba(107,114,128,0.4)' },
  'CDN':          { bg: 'rgba(249,115,22,0.12)', text: '#fdba74', border: 'rgba(249,115,22,0.35)' },
  'Hosting':      { bg: 'rgba(239,68,68,0.12)',  text: '#fca5a5', border: 'rgba(239,68,68,0.35)' },
  'Analytics':    { bg: 'rgba(34,197,94,0.12)',  text: '#86efac', border: 'rgba(34,197,94,0.35)' },
  'Security':     { bg: 'rgba(6,182,212,0.12)',  text: '#67e8f9', border: 'rgba(6,182,212,0.35)' },
  'Payment':      { bg: 'rgba(251,191,36,0.12)', text: '#fcd34d', border: 'rgba(251,191,36,0.35)' },
}

const DEFAULT_COLOUR = { bg: 'rgba(255,255,255,0.07)', text: 'rgba(255,255,255,0.6)', border: 'rgba(255,255,255,0.2)' }

// Maps technology name → Simple Icons slug (https://simpleicons.org)
// Icons are fetched from cdn.simpleicons.org at render time.
const TECH_ICON: Record<string, string> = {
  // CMS
  'WordPress':                 'wordpress',
  'Drupal':                    'drupal',
  'Joomla':                    'joomla',
  'Ghost':                     'ghost',
  'Shopify':                   'shopify',
  'Wix':                       'wix',
  'Squarespace':               'squarespace',
  'Webflow':                   'webflow',
  'HubSpot CMS':               'hubspot',
  // JS Framework
  'React':                     'react',
  'Next.js':                   'nextdotjs',
  'Vue':                       'vuedotjs',
  'Nuxt':                      'nuxtdotjs',
  'Angular':                   'angular',
  'Svelte':                    'svelte',
  'SvelteKit':                 'svelte',
  'Ember':                     'emberdotjs',
  'Backbone.js':               'backbone',
  'Astro':                     'astro',
  'Remix':                     'remix',
  'Gatsby':                    'gatsby',
  'Solid.js':                  'solid',
  // Build Tool
  'Vite':                      'vite',
  'webpack':                   'webpack',
  // JS Library
  'jQuery':                    'jquery',
  'Lodash':                    'lodash',
  'Axios':                     'axios',
  'GSAP':                      'greensock',
  'Three.js':                  'threedotjs',
  'Alpine.js':                 'alpinedotjs',
  'htmx':                      'htmx',
  'Socket.io':                 'socketdotio',
  'Chart.js':                  'chartdotjs',
  'D3.js':                     'd3dotjs',
  'Swiper':                    'swiper',
  'Pusher':                    'pusher',
  // CSS Framework
  'Bootstrap':                 'bootstrap',
  'Tailwind CSS':              'tailwindcss',
  'Bulma':                     'bulma',
  'Font Awesome':              'fontawesome',
  'UIkit':                     'uikit',
  // Backend
  'PHP':                       'php',
  'Python':                    'python',
  'Express':                   'express',
  'ASP.NET':                   'dotnet',
  'Laravel':                   'laravel',
  'Django':                    'django',
  'Ruby on Rails':             'rubyonrails',
  'Java':                      'openjdk',
  'Node.js':                   'nodedotjs',
  'Flask':                     'flask',
  'FastAPI':                   'fastapi',
  'Symfony':                   'symfony',
  'Spring Boot':               'springboot',
  // Web Server
  'nginx':                     'nginx',
  'Apache':                    'apache',
  'Caddy':                     'caddy',
  'Gunicorn':                  'gunicorn',
  // CDN
  'Cloudflare':                'cloudflare',
  'AWS CloudFront':            'amazonaws',
  'Fastly':                    'fastly',
  'Akamai':                    'akamai',
  'jsDelivr':                  'jsdelivr',
  // Hosting
  'Vercel':                    'vercel',
  'Netlify':                   'netlify',
  'GitHub Pages':              'github',
  'Firebase':                  'firebase',
  'Render':                    'render',
  // Analytics
  'Google Analytics':          'googleanalytics',
  'Google Tag Manager':        'googletagmanager',
  'Facebook Pixel':            'meta',
  'Hotjar':                    'hotjar',
  'Intercom':                  'intercom',
  'Mixpanel':                  'mixpanel',
  'Cloudflare Web Analytics':  'cloudflare',
  'Plausible':                 'plausibleanalytics',
  'Matomo':                    'matomo',
  'TikTok Pixel':              'tiktok',
  'LinkedIn Insight':          'linkedin',
  // Security
  'Cloudflare Turnstile':      'cloudflare',
  'Cloudflare Bot Management': 'cloudflare',
  'reCAPTCHA':                 'google',
  // Payment
  'Stripe':                    'stripe',
  'PayPal':                    'paypal',
  'Square':                    'square',
  'Klarna':                    'klarna',
}

function TechIcon({ name }: { name: string }) {
  const slug = TECH_ICON[name]
  if (!slug) return null
  return (
    <img
      src={`https://cdn.simpleicons.org/${slug}/ffffff`}
      alt=""
      width={12}
      height={12}
      style={{ opacity: 0.75, flexShrink: 0 }}
      loading="lazy"
    />
  )
}

function TechBadge({ tech }: { tech: Technology }) {
  const colour = CATEGORY_COLOURS[tech.category] ?? DEFAULT_COLOUR
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border"
      style={{ backgroundColor: colour.bg, color: colour.text, borderColor: colour.border }}
      title={tech.confidence === 'medium' ? 'Detected with medium confidence' : undefined}
    >
      <TechIcon name={tech.name} />
      {tech.name}
      {tech.version && (
        <span style={{ opacity: 0.65 }}>v{tech.version}</span>
      )}
      {tech.confidence === 'medium' && (
        <span style={{ opacity: 0.5, fontSize: '0.65rem' }}>~</span>
      )}
    </span>
  )
}

export default function TechStack({ technologies }: TechStackProps) {
  if (!technologies || technologies.length === 0) {
    return (
      <div
        className="rounded-lg border p-4 flex flex-col"
        style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.1)' }}
      >
        <h3 className="text-sm font-semibold text-white/70 uppercase tracking-wider mb-3">
          Technology Stack
        </h3>
        <p className="text-sm text-white/30 text-center my-auto py-4">
          No technologies detected.
        </p>
      </div>
    )
  }

  // Group by category, preserving CATEGORY_ORDER
  const grouped: Record<string, Technology[]> = {}
  for (const tech of technologies) {
    if (!grouped[tech.category]) grouped[tech.category] = []
    grouped[tech.category].push(tech)
  }

  const orderedCategories = [
    ...CATEGORY_ORDER.filter((c) => grouped[c]),
    ...Object.keys(grouped).filter((c) => !CATEGORY_ORDER.includes(c)),
  ]

  return (
    <div
      className="rounded-lg border p-4"
      style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.1)' }}
    >
      <h3 className="text-sm font-semibold text-white/70 uppercase tracking-wider mb-3">
        Technology Stack
      </h3>

      <div className="flex flex-col gap-3">
        {orderedCategories.map((category) => (
          <div key={category} className="flex flex-wrap items-start gap-2">
            <span
              className="text-xs text-white/30 w-24 shrink-0 pt-0.5"
              style={{ minWidth: '6rem' }}
            >
              {category}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {grouped[category].map((tech) => (
                <TechBadge key={tech.name} tech={tech} />
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="text-xs text-white/20 mt-3">
        ~ medium confidence &nbsp;·&nbsp; version shown where detected
      </p>
    </div>
  )
}
