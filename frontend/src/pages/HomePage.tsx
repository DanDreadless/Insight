import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { submitScan } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'

const FEATURE_CARDS = [
  {
    title: 'JavaScript Analysis',
    desc: 'Detects obfuscation, eval chains, skimmers, keyloggers, crypto miners, and exfiltration patterns in page scripts.',
  },
  {
    title: 'HTML Structure',
    desc: 'Identifies phishing forms, hidden iframes, clickjacking overlays, suspicious downloads, and insecure configurations.',
  },
  {
    title: 'Domain Intelligence',
    desc: 'Scores DGA probability, detects brand impersonation, homograph attacks, high-risk TLDs, and typosquatting.',
  },
  {
    title: 'Security Headers',
    desc: 'Audits CSP, HSTS, X-Frame-Options, cookie flags, CORS misconfigurations, and server version disclosure.',
  },
  {
    title: 'SSL / TLS',
    desc: 'Checks certificate validity, expiry, hostname match, deprecated TLS versions, and LE cert on phishing domains.',
  },
  {
    title: 'Threat Scoring',
    desc: 'Combines signals using context collapse detection to identify converging moderate indicators of malice.',
  },
]

export default function HomePage() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  function normaliseUrl(input: string): string {
    const trimmed = input.trim()
    // If no scheme is present, default to https://.
    // Most modern sites are HTTPS-only; plain HTTP often drops the connection
    // at the TCP level rather than redirecting.  Users who explicitly need HTTP
    // can type http:// themselves.
    if (trimmed && !trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return 'https://' + trimmed
    }
    return trimmed
  }

  function validateUrl(input: string): string | null {
    const normalised = normaliseUrl(input)
    if (!normalised) return 'Please enter a URL.'
    try {
      const parsed = new URL(normalised)
      if (!parsed.hostname) return 'URL must include a valid hostname.'
    } catch {
      return 'Please enter a valid URL.'
    }
    if (normalised.length > 2048) return 'URL must not exceed 2048 characters.'
    return null
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    const validationError = validateUrl(url)
    if (validationError) {
      setError(validationError)
      return
    }

    setLoading(true)
    try {
      const result = await submitScan(normaliseUrl(url))
      navigate(`/scan/${result.id}`)
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { status?: number; data?: { error?: string; detail?: string; url?: string[] } } }
        if (axiosErr.response?.status === 429) {
          const detail = axiosErr.response?.data?.detail
          setError(detail ? `Rate limit reached. ${detail}` : 'Rate limit reached. Please try again later.')
        } else if (axiosErr.response?.data?.error) {
          setError(axiosErr.response.data.error)
        } else if (axiosErr.response?.data?.url) {
          setError(axiosErr.response.data.url[0] ?? 'Invalid URL.')
        } else {
          setError('Failed to submit scan. Please try again.')
        }
      } else {
        setError('Failed to connect to the scanner backend.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      {/* Hero */}
      <div className="text-center mb-12 pt-8">
        <h1 className="text-4xl sm:text-5xl font-bold text-white mb-3 leading-tight">
          Threats hide in plain sight.
        </h1>
        <p className="text-4xl sm:text-5xl font-bold mb-4 text-white leading-tight">
          <span style={{ color: '#bd363a' }}>Insight</span> finds them.
        </p>
        <p className="text-white/60 text-lg max-w-2xl mx-auto mb-8 leading-relaxed">
          Reads what's actually on the page.<br />
          JavaScript behaviour, domain signals, security headers, and SSL.<br />
          No user interaction required.
        </p>

        {/* URL input form */}
        <div className="max-w-2xl mx-auto">
          <div
            className="rounded-xl p-6"
            style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.08)' }}
          >
            <label htmlFor="url-input" className="block text-sm font-medium text-white/70 mb-3 text-left">
              Enter a URL or domain to scan
            </label>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value)
                  setError(null)
                }}
                placeholder="example.com or https://example.com"
                className="flex-1 rounded-lg px-4 py-3 text-sm text-white placeholder-white/30 outline-none focus:ring-2 transition-all"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.07)',
                  border: error ? '1px solid #ef4444' : '1px solid rgba(255,255,255,0.12)',
                  '--tw-ring-color': '#bd363a',
                } as React.CSSProperties}
                maxLength={2048}
                autoComplete="off"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading}
                className="flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold text-white text-sm transition-all disabled:opacity-60 disabled:cursor-not-allowed"
                style={{
                  backgroundColor: '#bd363a',
                  minWidth: '100px',
                }}
                onMouseEnter={(e) => { if (!loading) e.currentTarget.style.backgroundColor = '#a52e32' }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#bd363a' }}
              >
                {loading ? <LoadingSpinner size="sm" /> : 'Scan'}
              </button>
            </form>

            {error && (
              <p className="mt-3 text-sm text-left" style={{ color: '#fca5a5' }}>
                {error}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Feature cards */}
      <div className="max-w-5xl mx-auto">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURE_CARDS.map((card) => (
            <div
              key={card.title}
              className="rounded-lg p-5"
              style={{
                backgroundColor: '#2a3238',
                border: '1px solid rgba(255,255,255,0.06)',
              }}
            >
              <h3 className="font-semibold text-white mb-2">{card.title}</h3>
              <p className="text-sm text-white/55 leading-relaxed">{card.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
