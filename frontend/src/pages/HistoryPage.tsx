import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { getHistory } from '../api/api'
import type { ScanSummary, HistoryResponse } from '../api/api'

const VERDICT_STYLES: Record<string, { bg: string; border: string; text: string }> = {
  MALICIOUS:  { bg: 'rgba(127,29,29,0.4)',   border: '#ef4444', text: '#fca5a5' },
  SUSPICIOUS: { bg: 'rgba(120,53,15,0.4)',   border: '#f97316', text: '#fdba74' },
  CLEAN:      { bg: 'rgba(20,83,45,0.4)',    border: '#22c55e', text: '#86efac' },
  UNKNOWN:    { bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.12)', text: 'rgba(255,255,255,0.4)' },
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const s = VERDICT_STYLES[verdict] ?? VERDICT_STYLES.UNKNOWN
  return (
    <span
      className="text-xs font-bold px-2 py-0.5 rounded shrink-0"
      style={{ backgroundColor: s.bg, border: `1px solid ${s.border}`, color: s.text }}
    >
      {verdict}
    </span>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export default function HistoryPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('q') ?? '')
  const [data, setData] = useState<HistoryResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const page = parseInt(searchParams.get('page') ?? '1', 10) || 1

  useEffect(() => {
    setLoading(true)
    setError(false)
    getHistory(searchParams.get('q') ?? '', page)
      .then((res) => { setData(res); setLoading(false) })
      .catch(() => { setError(true); setLoading(false) })
  }, [searchParams])

  function handleQueryChange(value: string) {
    setQuery(value)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      const next = new URLSearchParams()
      if (value.trim()) next.set('q', value.trim())
      setSearchParams(next)
    }, 350)
  }

  function goToPage(p: number) {
    const next = new URLSearchParams(searchParams)
    if (p <= 1) next.delete('page')
    else next.set('page', String(p))
    setSearchParams(next)
  }

  return (
    <div className="max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-1">Scan History</h1>
        <p className="text-sm" style={{ color: 'rgba(255,255,255,0.4)' }}>
          All completed scans — search by domain or URL fragment.
        </p>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          value={query}
          onChange={(e) => handleQueryChange(e.target.value)}
          placeholder="Search by domain or URL…"
          className="w-full rounded px-3 py-2 text-sm text-white placeholder-white/30 outline-none transition-colors"
          style={{
            backgroundColor: '#2a3238',
            border: '1px solid rgba(255,255,255,0.15)',
          }}
          onFocus={(e) => { e.currentTarget.style.borderColor = '#bd363a' }}
          onBlur={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)' }}
        />
      </div>

      {/* Results */}
      {error && (
        <p className="text-sm text-center py-12" style={{ color: '#fca5a5' }}>
          Failed to load history.
        </p>
      )}

      {loading && !error && (
        <p className="text-sm text-center py-12" style={{ color: 'rgba(255,255,255,0.3)' }}>
          Loading…
        </p>
      )}

      {!loading && !error && data && (
        <>
          {/* Count */}
          <p className="text-xs mb-3" style={{ color: 'rgba(255,255,255,0.3)' }}>
            {data.count === 0
              ? 'No scans found.'
              : `${data.count} scan${data.count !== 1 ? 's' : ''}${query ? ` matching "${query}"` : ''}`}
          </p>

          {/* Table */}
          {data.results.length > 0 && (
            <div
              className="rounded-lg overflow-hidden mb-4"
              style={{ border: '1px solid rgba(255,255,255,0.06)' }}
            >
              {data.results.map((scan: ScanSummary, idx: number) => (
                <Link
                  key={scan.id}
                  to={`/scan/${scan.id}`}
                  className="flex items-center gap-3 px-4 py-3 transition-colors group"
                  style={{
                    backgroundColor: idx % 2 === 0 ? '#2a3238' : 'rgba(255,255,255,0.02)',
                    borderTop: idx > 0 ? '1px solid rgba(255,255,255,0.05)' : undefined,
                    textDecoration: 'none',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(189,54,58,0.08)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = idx % 2 === 0 ? '#2a3238' : 'rgba(255,255,255,0.02)' }}
                >
                  <VerdictBadge verdict={scan.verdict} />

                  <span
                    className="flex-1 text-sm font-mono truncate"
                    style={{ color: 'rgba(255,255,255,0.85)' }}
                  >
                    {scan.url}
                  </span>

                  <span
                    className="text-xs shrink-0 hidden sm:block"
                    style={{ color: 'rgba(255,255,255,0.3)' }}
                  >
                    {scan.findings_count} finding{scan.findings_count !== 1 ? 's' : ''}
                  </span>

                  <span
                    className="text-xs shrink-0 hidden md:block text-right"
                    style={{ color: 'rgba(255,255,255,0.3)', minWidth: '12rem' }}
                  >
                    {scan.last_scanned_at && scan.last_scanned_at !== scan.completed_at ? (
                      <>
                        <span title="First scanned">First: {formatDate(scan.created_at)}</span>
                        <br />
                        <span title="Last scanned">Last: {formatDate(scan.last_scanned_at)}</span>
                      </>
                    ) : (
                      formatDate(scan.completed_at ?? scan.created_at)
                    )}
                  </span>
                </Link>
              ))}
            </div>
          )}

          {/* Pagination */}
          {data.total_pages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-4">
              <button
                onClick={() => goToPage(page - 1)}
                disabled={page <= 1}
                className="text-xs px-3 py-1.5 rounded disabled:opacity-30"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.6)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}
              >
                Previous
              </button>
              <span className="text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>
                Page {data.page} of {data.total_pages}
              </span>
              <button
                onClick={() => goToPage(page + 1)}
                disabled={page >= data.total_pages}
                className="text-xs px-3 py-1.5 rounded disabled:opacity-30"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.6)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
