import { useState } from 'react'
import { getScanSource } from '../../api/api'

interface Props {
  scanId: string
  mainUrl: string
  scriptUrls: string[]
}

type SourceCache = Record<string, string>
type ErrorSet = Record<string, boolean>

function shortLabel(url: string): string {
  try {
    const { hostname, pathname } = new URL(url)
    const file = pathname.split('/').filter(Boolean).pop() || '/'
    return `${hostname}/…/${file}`
  } catch {
    return url
  }
}

export default function SourceViewer({ scanId, mainUrl, scriptUrls }: Props) {
  const [open, setOpen] = useState(false)
  const [activeUrl, setActiveUrl] = useState<string>(mainUrl)
  const [cache, setCache] = useState<SourceCache>({})
  const [fetching, setFetching] = useState<SourceCache>({})
  const [errors, setErrors] = useState<ErrorSet>({})

  const source = cache[activeUrl] ?? null
  const isLoading = !cache[activeUrl] && !errors[activeUrl]
  const isError = !!errors[activeUrl]

  async function loadSource(url: string) {
    if (cache[url] !== undefined || fetching[url]) return
    setFetching((prev) => ({ ...prev, [url]: 'loading' }))
    try {
      const text = await getScanSource(scanId, url)
      setCache((prev) => ({ ...prev, [url]: text }))
    } catch {
      setErrors((prev) => ({ ...prev, [url]: true }))
    } finally {
      setFetching((prev) => { const next = { ...prev }; delete next[url]; return next })
    }
  }

  function handleToggle() {
    const next = !open
    setOpen(next)
    if (next) {
      // Pre-fetch all URLs in parallel so tab switches are instant
      ;[mainUrl, ...scriptUrls].forEach((url) => loadSource(url))
    }
  }

  function handleCopy() {
    if (source) navigator.clipboard.writeText(source)
  }

  const allUrls = [mainUrl, ...scriptUrls]

  return (
    <div
      className="rounded-lg mb-4"
      style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3">
        <span className="text-sm font-semibold text-white/70">Source Code</span>
        <button
          type="button"
          onClick={handleToggle}
          className="text-xs px-3 py-1 rounded font-medium transition-colors"
          style={{
            backgroundColor: open ? 'rgba(255,255,255,0.08)' : '#bd363a',
            color: '#fff',
          }}
        >
          {open ? 'Hide' : 'View Source'}
        </button>
      </div>

      {open && (
        <div className="border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          {/* URL selector tabs */}
          {allUrls.length > 1 && (
            <div
              className="flex flex-wrap gap-1 px-3 py-2 border-b overflow-x-auto"
              style={{ borderColor: 'rgba(255,255,255,0.06)' }}
            >
              {allUrls.map((u) => (
                <button
                  type="button"
                  key={u}
                  onClick={() => setActiveUrl(u)}
                  title={u}
                  className="text-xs px-2 py-1 rounded whitespace-nowrap transition-colors"
                  style={{
                    backgroundColor: activeUrl === u
                      ? 'rgba(189,54,58,0.25)'
                      : 'rgba(255,255,255,0.05)',
                    color: activeUrl === u ? '#fca5a5' : 'rgba(255,255,255,0.45)',
                    border: activeUrl === u
                      ? '1px solid rgba(189,54,58,0.5)'
                      : '1px solid rgba(255,255,255,0.08)',
                  }}
                >
                  {u === mainUrl ? 'Page source' : shortLabel(u)}
                </button>
              ))}
            </div>
          )}

          {/* Toolbar */}
          <div
            className="flex items-center justify-between px-3 py-2 border-b"
            style={{ borderColor: 'rgba(255,255,255,0.06)' }}
          >
            <span className="text-xs font-mono truncate max-w-xs" style={{ color: 'rgba(255,255,255,0.3)' }}>
              {activeUrl}
            </span>
            {source && (
              <button
                type="button"
                onClick={handleCopy}
                className="text-xs px-2 py-0.5 rounded ml-2 shrink-0"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.45)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}
              >
                Copy
              </button>
            )}
          </div>

          {/* Content area */}
          <div className="p-3">
            {isError && (
              <p className="text-xs text-center py-6" style={{ color: '#fca5a5' }}>
                Could not retrieve source for this URL.
              </p>
            )}
            {isLoading && !isError && (
              <p className="text-xs text-center py-6" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Fetching source…
              </p>
            )}
            {source !== null && (
              <pre
                className="text-xs leading-relaxed overflow-auto rounded p-3"
                style={{
                  backgroundColor: '#1a1f24',
                  color: '#b0ffb0',
                  fontFamily: 'monospace',
                  maxHeight: '600px',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {source}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
