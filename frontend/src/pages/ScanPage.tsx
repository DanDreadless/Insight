import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan, getScanUrlHistory, submitFeedback } from '../api/api'
import type { HistoryResponse, ScanSummary } from '../api/api'
import type { ScanJob } from '../types'
import ScanProgress from '../components/results/ScanProgress'
import VerdictBanner from '../components/results/VerdictBanner'
import FindingCard from '../components/results/FindingCard'
import ResourceList from '../components/results/ResourceList'
import TechStack from '../components/results/TechStack'
import DomainInfo from '../components/results/DomainInfo'
import NetworkTrace from '../components/results/NetworkTrace'
import SourceViewer from '../components/results/SourceViewer'
import ScreenshotViewer from '../components/results/ScreenshotViewer'
import LoadingSpinner from '../components/LoadingSpinner'

const VERDICT_STYLES: Record<string, { bg: string; border: string; text: string }> = {
  MALICIOUS:  { bg: 'rgba(127,29,29,0.4)',    border: '#ef4444', text: '#fca5a5' },
  SUSPICIOUS: { bg: 'rgba(120,53,15,0.4)',    border: '#f97316', text: '#fdba74' },
  CLEAN:      { bg: 'rgba(20,83,45,0.4)',     border: '#22c55e', text: '#86efac' },
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

function PreviousScans({ scanId }: { scanId: string }) {
  const [data, setData] = useState<HistoryResponse | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getScanUrlHistory(scanId, page)
      .then((res) => { setData(res); setLoading(false) })
      .catch(() => setLoading(false))
  }, [scanId, page])

  if (!loading && (!data || data.count === 0)) return null

  return (
    <section className="mt-8">
      <h2
        className="text-sm font-semibold mb-3 flex items-center gap-2"
        style={{ color: 'rgba(255,255,255,0.5)' }}
      >
        Previous scans of this URL
        {data && data.count > 0 && (
          <span
            className="text-xs px-2 py-0.5 rounded"
            style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}
          >
            {data.count}
          </span>
        )}
      </h2>

      {loading && (
        <p className="text-xs" style={{ color: 'rgba(255,255,255,0.25)' }}>Loading…</p>
      )}

      {!loading && data && data.results.length > 0 && (
        <>
          <div
            className="rounded-lg overflow-hidden mb-3"
            style={{ border: '1px solid rgba(255,255,255,0.06)' }}
          >
            {data.results.map((scan: ScanSummary, idx: number) => (
              <Link
                key={scan.id}
                to={`/scan/${scan.id}`}
                className="flex items-center gap-3 px-4 py-2.5 transition-colors"
                style={{
                  backgroundColor: idx % 2 === 0 ? '#2a3238' : 'rgba(255,255,255,0.02)',
                  borderTop: idx > 0 ? '1px solid rgba(255,255,255,0.05)' : undefined,
                  textDecoration: 'none',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(189,54,58,0.08)' }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = idx % 2 === 0 ? '#2a3238' : 'rgba(255,255,255,0.02)' }}
              >
                <VerdictBadge verdict={scan.verdict} />
                <span className="flex-1 text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>
                  {scan.findings_count} finding{scan.findings_count !== 1 ? 's' : ''}
                </span>
                <span className="text-xs shrink-0" style={{ color: 'rgba(255,255,255,0.3)' }}>
                  {scan.completed_at
                    ? new Date(scan.completed_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
                    : new Date(scan.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
                </span>
              </Link>
            ))}
          </div>

          {data.total_pages > 1 && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => p - 1)}
                disabled={page <= 1}
                className="text-xs px-3 py-1 rounded disabled:opacity-30"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.5)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}
              >
                Previous
              </button>
              <span className="text-xs" style={{ color: 'rgba(255,255,255,0.3)' }}>
                {data.page} / {data.total_pages}
              </span>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= data.total_pages}
                className="text-xs px-3 py-1 rounded disabled:opacity-30"
                style={{
                  backgroundColor: 'rgba(255,255,255,0.06)',
                  color: 'rgba(255,255,255,0.5)',
                  border: '1px solid rgba(255,255,255,0.08)',
                }}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

const FEEDBACK_REASONS = [
  { value: 'false_positive', label: 'False Positive — result flagged something that is not a threat' },
  { value: 'missed_threat', label: 'Missed Threat — result missed something that is clearly malicious' },
  { value: 'wrong_severity', label: 'Wrong Severity — finding is real but rated at the wrong level' },
  { value: 'other', label: 'Other' },
]

function FeedbackModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit() {
    if (!reason) { setError('Please select a reason.'); return }
    setSubmitting(true)
    setError('')
    try {
      await submitFeedback(scanId, reason, note)
      setDone(true)
    } catch {
      setError('Submission failed. Please try again.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        className="w-full max-w-md rounded-lg p-6"
        style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.12)' }}
      >
        {done ? (
          <div className="text-center py-4">
            <p className="text-green-400 font-semibold mb-2">Feedback submitted</p>
            <p className="text-white/50 text-sm mb-4">
              Thanks — this scan has been queued for detection engineering review.
            </p>
            <button
              onClick={onClose}
              className="text-sm px-4 py-2 rounded text-white"
              style={{ backgroundColor: '#bd363a' }}
            >
              Close
            </button>
          </div>
        ) : (
          <>
            <h3 className="text-white font-semibold mb-1">Report Incorrect Results</h3>
            <p className="text-white/40 text-xs mb-4">
              This scan will be queued for detection engineering review. Your feedback
              helps reduce false positives and improve detection accuracy.
            </p>

            <label className="block text-white/60 text-xs mb-1">Reason</label>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full rounded px-3 py-2 text-sm mb-3"
              style={{
                backgroundColor: '#353E43',
                border: '1px solid rgba(255,255,255,0.15)',
                color: reason ? '#fff' : 'rgba(255,255,255,0.35)',
              }}
            >
              <option value="" disabled>Select a reason…</option>
              {FEEDBACK_REASONS.map((r) => (
                <option key={r.value} value={r.value} style={{ color: '#fff' }}>{r.label}</option>
              ))}
            </select>

            <label className="block text-white/60 text-xs mb-1">Additional notes <span className="text-white/25">(optional)</span></label>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={1000}
              rows={3}
              placeholder="e.g. This is a known CDN. The flagged script is jQuery served from cdnjs."
              className="w-full rounded px-3 py-2 text-sm resize-none mb-3"
              style={{
                backgroundColor: '#353E43',
                border: '1px solid rgba(255,255,255,0.15)',
                color: '#fff',
              }}
            />

            {error && <p className="text-red-400 text-xs mb-3">{error}</p>}

            <div className="flex gap-2 justify-end">
              <button
                onClick={onClose}
                className="text-sm px-4 py-2 rounded"
                style={{ color: 'rgba(255,255,255,0.4)', border: '1px solid rgba(255,255,255,0.1)' }}
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="text-sm px-4 py-2 rounded font-medium text-white disabled:opacity-50"
                style={{ backgroundColor: '#bd363a' }}
              >
                {submitting ? 'Submitting…' : 'Submit Feedback'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default function ScanPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<ScanJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [feedbackOpen, setFeedbackOpen] = useState(false)

  useEffect(() => {
    if (!id) return
    getScan(id)
      .then((data) => {
        setScan(data)
        setLoading(false)
      })
      .catch((err: unknown) => {
        if (err && typeof err === 'object' && 'response' in err) {
          const axiosErr = err as { response?: { status?: number } }
          if (axiosErr.response?.status === 404) {
            setNotFound(true)
          }
        }
        setLoading(false)
      })
  }, [id])

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  if (!id || !UUID_RE.test(id)) {
    return <div className="text-white/60 text-center py-20">Invalid scan ID.</div>
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center py-20">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (notFound) {
    return (
      <div className="text-center py-20">
        <p className="text-white/60 text-lg mb-4">Scan not found.</p>
        <Link
          to="/"
          className="text-sm px-4 py-2 rounded font-medium text-white"
          style={{ backgroundColor: '#bd363a' }}
        >
          Scan another URL
        </Link>
      </div>
    )
  }

  // If pending/running, show progress component
  if (!scan || scan.status === 'PENDING' || scan.status === 'RUNNING') {
    return (
      <div className="max-w-3xl mx-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Scanning in progress</h1>
          {scan?.url && (
            <p className="text-sm text-white/50 break-all font-mono">{scan.url}</p>
          )}
        </div>
        <ScanProgress
          scanId={id}
          onComplete={(completedScan) => setScan(completedScan)}
        />
      </div>
    )
  }

  // Failed
  if (scan.status === 'FAILED') {
    const httpMatch = scan.error_message?.match(/^(HTTP (\d{3}):\s*)(.*)$/)
    const errorHeaders = scan.scan_metadata?.error_response_headers as Record<string, string> | undefined
    const headerEntries = errorHeaders ? Object.entries(errorHeaders) : []
    return (
      <div className="max-w-3xl mx-auto">
        <div
          className="rounded-lg border p-6 mb-6"
          style={{ backgroundColor: 'rgba(127,29,29,0.3)', borderColor: '#ef4444' }}
        >
          <h2 className="text-red-300 font-bold text-lg mb-2">Scan Failed</h2>
          <p className="text-red-400/80 text-sm mb-1 break-all font-mono">{scan.url}</p>
          {scan.error_message && (
            <div className="mt-3">
              {httpMatch ? (
                <>
                  <span
                    className="inline-block font-mono font-bold text-sm px-3 py-1 rounded mb-2"
                    style={{ backgroundColor: 'rgba(239,68,68,0.25)', color: '#fca5a5' }}
                  >
                    HTTP {httpMatch[2]}
                  </span>
                  <p className="text-red-400/70 text-sm">{httpMatch[3]}</p>
                </>
              ) : (
                <p className="text-red-400/70 text-sm">{scan.error_message}</p>
              )}
            </div>
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
        <Link
          to="/"
          className="inline-block text-sm px-4 py-2 rounded font-medium text-white"
          style={{ backgroundColor: '#bd363a' }}
        >
          Try another URL
        </Link>
      </div>
    )
  }

  // Complete
  const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
  const findings = [...(scan.findings ?? [])].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4)
  )
  const criticalAndHigh = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
  const mediumAndLow = findings.filter((f) => f.severity === 'MEDIUM' || f.severity === 'LOW')
  const infoFindings = findings.filter((f) => f.severity === 'INFO')
  const scanTime = scan.completed_at
    ? new Date(scan.completed_at).toLocaleString()
    : undefined

  return (
    <div className="max-w-7xl mx-auto">
      {/* Beta disclaimer */}
      <div
        className="rounded-lg px-4 py-3 mb-4 flex items-start gap-3 text-sm"
        style={{ backgroundColor: 'rgba(189,54,58,0.12)', border: '1px solid rgba(189,54,58,0.35)' }}
      >
        <span style={{ color: '#bd363a' }} className="font-bold shrink-0 mt-px">BETA</span>
        <p style={{ color: 'rgba(255,255,255,0.55)' }}>
          Insight is in early beta. Results are heuristic-based and may contain false positives or miss emerging threats.
          All findings should be verified by a qualified analyst before taking action.
        </p>
      </div>

      {/* Verdict banner */}
      <VerdictBanner verdict={scan.verdict} url={scan.url} scanTime={scanTime} />

      {/* Screenshot */}
      {!!scan.scan_metadata?.screenshot_b64 && (
        <ScreenshotViewer
          screenshotB64={scan.scan_metadata.screenshot_b64 as string}
        />
      )}

      {/* No findings at all */}
      {findings.length === 0 && (
        <div
          className="rounded-lg p-6 text-center mb-4"
          style={{ backgroundColor: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <p className="text-white/50">No findings detected for this URL.</p>
        </div>
      )}

      {/* Critical & High threats */}
      {criticalAndHigh.length > 0 && (
        <section className="mb-6">
          <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
            <span style={{ color: '#ef4444' }}>Threats Detected</span>
            <span
              className="text-sm font-normal px-2 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}
            >
              {criticalAndHigh.length}
            </span>
          </h2>
          {criticalAndHigh.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </section>
      )}

      {/* Medium & Low indicators */}
      {mediumAndLow.length > 0 && (
        <section className="mb-6">
          <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
            <span style={{ color: '#eab308' }}>Suspicious Indicators</span>
            <span
              className="text-sm font-normal px-2 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(234,179,8,0.15)', color: '#fde047' }}
            >
              {mediumAndLow.length}
            </span>
          </h2>
          {mediumAndLow.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </section>
      )}

      {/* Informational — collapsed by default */}
      {infoFindings.length > 0 && (
        <section className="mb-6">
          <details>
            <summary
              className="text-sm text-white/50 cursor-pointer select-none list-none mb-3 flex items-center gap-2"
              style={{ WebkitAppearance: 'none' }}
            >
              <span>Informational</span>
              <span
                className="text-xs px-2 py-0.5 rounded"
                style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.4)' }}
              >
                {infoFindings.length}
              </span>
              <span className="text-white/30 text-xs">&#9660;</span>
            </summary>
            {infoFindings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </details>
        </section>
      )}

      {/* Domain info + Technology stack + Scanned Resources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <DomainInfo whois={(scan.scan_metadata?.whois_data as never) ?? null} />
        <TechStack technologies={(scan.scan_metadata?.detected_technologies as never) ?? []} />
        <ResourceList metadata={scan.scan_metadata ?? {}} />
      </div>

      {/* Network trace — domains/IPs for all hops in the redirect chain */}
      {Array.isArray(scan.scan_metadata?.network_trace) && (
        <NetworkTrace trace={scan.scan_metadata.network_trace as { url: string; host: string; ip: string }[]} />
      )}

      {/* Source viewer */}
      <SourceViewer
        scanId={id}
        mainUrl={(scan.scan_metadata?.final_url as string | undefined) ?? scan.url}
        scriptUrls={(scan.scan_metadata?.scripts_urls as string[] | undefined) ?? []}
      />

      {/* Previous scans of this URL */}
      <PreviousScans scanId={id} />

      {/* Footer actions */}
      <div className="mt-8 flex flex-col items-center gap-3">
        <Link
          to="/"
          className="inline-block text-sm px-6 py-3 rounded-lg font-semibold text-white transition-all"
          style={{ backgroundColor: '#bd363a' }}
          onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#a52e32' }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#bd363a' }}
        >
          Scan another URL
        </Link>
        <button
          onClick={() => setFeedbackOpen(true)}
          className="text-xs transition-colors"
          style={{ color: 'rgba(255,255,255,0.25)' }}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'rgba(255,255,255,0.5)' }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'rgba(255,255,255,0.25)' }}
        >
          Results seem incorrect? Report for review
        </button>
      </div>

      {feedbackOpen && id && (
        <FeedbackModal scanId={id} onClose={() => setFeedbackOpen(false)} />
      )}
    </div>
  )
}
