import { useEffect, useRef, useState } from 'react'
import type { ScanJob } from '../../types'
import LoadingSpinner from '../LoadingSpinner'

interface ScanProgressProps {
  scanId: string
  onComplete: (scan: ScanJob) => void
}

interface ProgressData {
  step: number
  total_steps: number
  label: string
  current_url: string
  findings_count: number
}

const MAX_RETRIES = 3
const RETRY_DELAY_MS = 2000

function truncateUrl(url: string, max = 60): string {
  if (!url || url.length <= max) return url
  try {
    const { hostname, pathname } = new URL(url)
    const short = `${hostname}${pathname}`
    return short.length <= max ? short : short.slice(0, max - 1) + '…'
  } catch {
    return url.slice(0, max - 1) + '…'
  }
}

export default function ScanProgress({ scanId, onComplete }: ScanProgressProps) {
  const [progress, setProgress] = useState<ProgressData | null>(null)
  const [statusText, setStatusText] = useState('PENDING')
  const [error, setError] = useState<string | null>(null)
  const [errorMetadata, setErrorMetadata] = useState<Record<string, unknown> | null>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const retryCountRef = useRef(0)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const namedErrorRef = useRef(false)

  useEffect(() => {
    connect()
    return cleanup
  }, [scanId])

  function connect() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const es = new EventSource(`/api/scan/${scanId}/stream/`)
    eventSourceRef.current = es

    es.addEventListener('status_update', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as {
          status: string
          step?: number
          total_steps?: number
          label?: string
          current_url?: string
          findings_count?: number
        }
        setStatusText(data.status)
        if (data.step !== undefined && data.step > 0) {
          setProgress({
            step: data.step,
            total_steps: data.total_steps ?? 6,
            label: data.label ?? '',
            current_url: data.current_url ?? '',
            findings_count: data.findings_count ?? 0,
          })
        }
      } catch {
        // ignore parse errors
      }
    })

    es.addEventListener('complete', (e: MessageEvent) => {
      try {
        const scan = JSON.parse(e.data) as ScanJob
        cleanup()
        onComplete(scan)
      } catch {
        namedErrorRef.current = true
        setError('Failed to parse scan results.')
        cleanup()
      }
    })

    es.addEventListener('error', (e: MessageEvent) => {
      namedErrorRef.current = true
      try {
        const data = JSON.parse(e.data) as { error?: string; error_message?: string; scan_metadata?: Record<string, unknown> }
        setError(data.error_message || data.error || 'Scan failed.')
        setErrorMetadata(data.scan_metadata ?? null)
      } catch {
        setError('Scan failed.')
      }
      cleanup()
    })

    es.onerror = () => {
      if (namedErrorRef.current) return

      es.close()
      eventSourceRef.current = null

      if (retryCountRef.current < MAX_RETRIES) {
        retryCountRef.current += 1
        retryTimerRef.current = setTimeout(connect, RETRY_DELAY_MS)
      } else {
        setError('Connection to scan stream lost. The scan may still be running — please refresh.')
        cleanup()
      }
    }
  }

  function cleanup() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
  }

  if (error) {
    const httpMatch = error.match(/^(HTTP (\d{3}):\s*)(.*)$/)
    const errorHeaders = errorMetadata?.error_response_headers as Record<string, string> | undefined
    const headerEntries = errorHeaders ? Object.entries(errorHeaders) : []
    return (
      <div
        className="rounded-lg border p-6"
        style={{ backgroundColor: 'rgba(127,29,29,0.3)', borderColor: '#ef4444' }}
      >
        <p className="text-red-300 font-semibold mb-3 text-center">Scan Error</p>
        {httpMatch ? (
          <>
            <div className="text-center mb-2">
              <span
                className="inline-block font-mono font-bold text-sm px-3 py-1 rounded"
                style={{ backgroundColor: 'rgba(239,68,68,0.25)', color: '#fca5a5' }}
              >
                HTTP {httpMatch[2]}
              </span>
            </div>
            <p className="text-red-400/80 text-sm text-center">{httpMatch[3]}</p>
          </>
        ) : (
          <p className="text-red-400/80 text-sm text-center">{error}</p>
        )}
        {headerEntries.length > 0 && (
          <details className="mt-4">
            <summary
              className="text-xs font-medium cursor-pointer select-none list-none flex items-center gap-2"
              style={{ color: 'rgba(252,165,165,0.6)', WebkitAppearance: 'none' }}
            >
              <span>Response Headers</span>
              <span
                className="px-1.5 py-0.5 rounded text-xs"
                style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}
              >
                {headerEntries.length}
              </span>
              <span style={{ color: 'rgba(252,165,165,0.4)' }}>&#9660;</span>
            </summary>
            <div
              className="mt-3 rounded p-3 text-xs font-mono overflow-x-auto"
              style={{ backgroundColor: '#1a1f24', color: '#b0ffb0' }}
            >
              {headerEntries.map(([name, value]) => (
                <div key={name} className="flex gap-2 leading-relaxed">
                  <span style={{ color: 'rgba(176,255,176,0.5)', flexShrink: 0 }}>{name}:</span>
                  <span className="break-all">{value}</span>
                </div>
              ))}
            </div>
          </details>
        )}
      </div>
    )
  }

  const pct = progress ? Math.round((progress.step / progress.total_steps) * 100) : 0
  const label = progress?.label || (statusText === 'RUNNING' ? 'Starting scan…' : 'Waiting in queue…')
  const currentUrl = progress?.current_url ?? ''
  const findingsCount = progress?.findings_count ?? 0

  return (
    <div
      className="rounded-lg border p-8 flex flex-col items-center gap-5"
      style={{ backgroundColor: 'rgba(255,255,255,0.03)', borderColor: 'rgba(255,255,255,0.1)' }}
    >
      <LoadingSpinner size="lg" />

      {/* Step label */}
      <p className="text-white/90 font-medium text-center">{label}</p>

      {/* Progress bar */}
      <div className="w-full max-w-sm">
        <div
          className="w-full rounded-full overflow-hidden"
          style={{ height: '6px', backgroundColor: 'rgba(255,255,255,0.08)' }}
        >
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${pct}%`,
              backgroundColor: '#bd363a',
            }}
          />
        </div>
        <div className="flex justify-between mt-1.5">
          <span className="text-xs" style={{ color: 'rgba(255,255,255,0.3)' }}>
            {progress ? `Step ${progress.step} of ${progress.total_steps}` : 'Initialising…'}
          </span>
          {findingsCount > 0 && (
            <span
              className="text-xs font-medium px-2 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(189,54,58,0.2)', color: '#fca5a5' }}
            >
              {findingsCount} finding{findingsCount !== 1 ? 's' : ''} so far
            </span>
          )}
        </div>
      </div>

      {/* Current URL being scanned */}
      {currentUrl && (
        <p
          className="text-xs font-mono text-center max-w-sm truncate"
          style={{ color: 'rgba(255,255,255,0.35)' }}
          title={currentUrl}
        >
          {truncateUrl(currentUrl)}
        </p>
      )}

      <p className="text-white/30 text-xs text-center max-w-sm">
        Passively analysing the target URL for threats. This typically takes 15–60 seconds.
      </p>
    </div>
  )
}
