import type { Finding, SeverityLevel } from '../../types'

interface FindingCardProps {
  finding: Finding
}

const severityConfig: Record<
  SeverityLevel,
  { bg: string; border: string; textColor: string; badgeBg: string }
> = {
  CRITICAL: {
    bg: 'rgba(127,29,29,0.4)',
    border: '#ef4444',
    textColor: '#fca5a5',
    badgeBg: 'rgba(239,68,68,0.2)',
  },
  HIGH: {
    bg: 'rgba(120,53,15,0.4)',
    border: '#f97316',
    textColor: '#fdba74',
    badgeBg: 'rgba(249,115,22,0.2)',
  },
  MEDIUM: {
    bg: 'rgba(113,63,18,0.4)',
    border: '#eab308',
    textColor: '#fde047',
    badgeBg: 'rgba(234,179,8,0.2)',
  },
  LOW: {
    bg: 'rgba(23,37,84,0.3)',
    border: '#3b82f6',
    textColor: '#93c5fd',
    badgeBg: 'rgba(59,130,246,0.2)',
  },
  INFO: {
    bg: 'rgba(255,255,255,0.05)',
    border: 'rgba(255,255,255,0.1)',
    textColor: 'rgba(255,255,255,0.4)',
    badgeBg: 'rgba(255,255,255,0.08)',
  },
}

export default function FindingCard({ finding }: FindingCardProps) {
  const cfg = severityConfig[finding.severity]

  return (
    <details
      className="rounded-lg border mb-3 overflow-hidden"
      style={{ backgroundColor: cfg.bg, borderColor: cfg.border }}
    >
      <summary
        className="flex items-center gap-3 p-4 cursor-pointer select-none list-none"
        style={{ WebkitAppearance: 'none' }}
      >
        {/* Severity badge */}
        <span
          className="flex-shrink-0 text-xs font-bold px-2 py-0.5 rounded"
          style={{ backgroundColor: cfg.badgeBg, color: cfg.textColor }}
        >
          {finding.severity}
        </span>

        {/* Category */}
        <span
          className="flex-shrink-0 text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.5)' }}
        >
          {finding.category}
        </span>

        {/* Title */}
        <span className="text-sm font-medium text-white/90 flex-1 min-w-0">
          {finding.title}
        </span>

        {/* Expand indicator */}
        <span className="flex-shrink-0 text-white/30 text-xs">&#9660;</span>
      </summary>

      {/* Expanded content */}
      <div className="px-4 pb-4 pt-2 border-t" style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
        <p className="text-sm text-white/80 mb-3 leading-relaxed">{finding.description}</p>

        {finding.evidence && (
          <div className="mb-3">
            <p className="text-xs text-white/40 mb-1 uppercase tracking-wider">Evidence</p>
            <pre className="output-pre">{finding.evidence}</pre>
          </div>
        )}

        {finding.resource_url && (
          <div className="mb-2">
            <p className="text-xs text-white/40 mb-1 uppercase tracking-wider">Source</p>
            <p className="text-xs font-mono text-white/60 break-all">{finding.resource_url}</p>
          </div>
        )}

      </div>
    </details>
  )
}
