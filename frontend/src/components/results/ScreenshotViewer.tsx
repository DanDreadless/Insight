import { useState } from 'react'

interface Props {
  screenshotB64: string
}

export default function ScreenshotViewer({ screenshotB64 }: Props) {
  const [open, setOpen] = useState(false)

  if (!screenshotB64) return null

  return (
    <div
      className="rounded-lg mb-4"
      style={{ backgroundColor: '#2a3238', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3">
        <span className="text-sm font-semibold text-white/70">Visual Screenshot</span>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="text-xs px-3 py-1 rounded font-medium transition-colors"
          style={{
            backgroundColor: open ? 'rgba(255,255,255,0.08)' : '#bd363a',
            color: '#fff',
          }}
        >
          {open ? 'Hide' : 'View Screenshot'}
        </button>
      </div>

      {open && (
        <div className="border-t px-4 pb-4 pt-3" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          <p className="text-xs mb-3" style={{ color: 'rgba(255,255,255,0.35)' }}>
            Rendered via Carapace — Chromium headless, JavaScript disabled, network access blocked.
          </p>
          <img
            src={`data:image/png;base64,${screenshotB64}`}
            alt="Site screenshot"
            className="w-full rounded"
            style={{ border: '1px solid rgba(255,255,255,0.08)', display: 'block' }}
          />
        </div>
      )}
    </div>
  )
}
