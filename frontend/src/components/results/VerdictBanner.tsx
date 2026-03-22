import type { VerdictType } from '../../types'

interface VerdictBannerProps {
  verdict: VerdictType
  url: string
  scanTime?: string
}

const verdictConfig: Record<
  VerdictType,
  { bg: string; border: string; textColor: string; icon: string; label: string }
> = {
  MALICIOUS: {
    bg: 'rgba(127,29,29,0.4)',
    border: '#ef4444',
    textColor: '#fca5a5',
    icon: '✕',
    label: 'MALICIOUS',
  },
  SUSPICIOUS: {
    bg: 'rgba(120,53,15,0.4)',
    border: '#f97316',
    textColor: '#fdba74',
    icon: '⚠',
    label: 'SUSPICIOUS',
  },
  CLEAN: {
    bg: 'rgba(20,83,45,0.3)',
    border: '#16a34a',
    textColor: '#86efac',
    icon: '✓',
    label: 'CLEAN',
  },
  UNKNOWN: {
    bg: 'rgba(255,255,255,0.05)',
    border: 'rgba(255,255,255,0.2)',
    textColor: 'rgba(255,255,255,0.5)',
    icon: '?',
    label: 'UNKNOWN',
  },
}

export default function VerdictBanner({ verdict, url, scanTime }: VerdictBannerProps) {
  const cfg = verdictConfig[verdict]
  const truncatedUrl = url.length > 80 ? url.slice(0, 80) + '...' : url

  return (
    <div
      className="rounded-lg border p-6 mb-6"
      style={{ backgroundColor: cfg.bg, borderColor: cfg.border }}
    >
      <div className="flex items-center gap-4">
        <div
          className="flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center text-2xl font-bold border-2"
          style={{ borderColor: cfg.border, color: cfg.textColor }}
        >
          {cfg.icon}
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <span
              className="text-2xl font-bold tracking-wider"
              style={{ color: cfg.textColor }}
            >
              {cfg.label}
            </span>
          </div>
          <p className="text-sm" style={{ color: 'rgba(255,255,255,0.6)' }}>
            Scanned:{' '}
            <span className="font-mono text-xs break-all" style={{ color: 'rgba(255,255,255,0.8)' }}>
              {truncatedUrl}
            </span>
          </p>
          {scanTime && (
            <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>
              Completed: {scanTime}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
