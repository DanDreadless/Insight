import { useState } from 'react'

interface ResourceListProps {
  metadata: Record<string, unknown>
}

interface FormEntry {
  action: string
  method: string
  input_count: number
}

// --- Collapsible section ---

function ScanSection({
  label,
  count,
  sublabel,
  children,
}: {
  label: string
  count: number
  sublabel?: string
  children?: React.ReactNode
}) {
  const [open, setOpen] = useState(false)
  const hasContent = !!children && count > 0

  return (
    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }} className="last:border-0">
      <button
        onClick={() => hasContent && setOpen(o => !o)}
        className="w-full flex items-center justify-between py-2.5 text-left"
        style={{ cursor: hasContent ? 'pointer' : 'default' }}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm text-white/60">{label}</span>
          {sublabel && (
            <span className="text-xs text-white/30">{sublabel}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-white">{count}</span>
          {hasContent && (
            <span className="text-xs" style={{ color: 'rgba(255,255,255,0.3)' }}>
              {open ? '▴' : '▾'}
            </span>
          )}
        </div>
      </button>

      {hasContent && open && (
        <div className="pb-3">
          {children}
        </div>
      )}
    </div>
  )
}

// --- Plain text list (no links) ---

function TextList({ items, emptyText }: { items: string[]; emptyText?: string }) {
  if (items.length === 0 && emptyText) {
    return <p className="text-xs text-white/30 pl-2">{emptyText}</p>
  }
  return (
    <div
      className="rounded p-2 flex flex-col gap-1 overflow-y-auto"
      style={{ backgroundColor: 'rgba(0,0,0,0.2)', maxHeight: '14rem' }}
    >
      {items.map((item, i) => (
        <span key={i} className="text-xs font-mono break-all" style={{ color: 'rgba(255,255,255,0.5)' }}>
          {item}
        </span>
      ))}
    </div>
  )
}

// --- Main component ---

export default function ResourceList({ metadata }: ResourceListProps) {
  const scriptsCount = (metadata.scripts_count as number | undefined) ?? 0
  const scriptsAnalysed = (metadata.scripts_analysed as number | undefined) ?? 0
  const scriptsUrls = (metadata.scripts_urls as string[] | undefined) ?? []
  const stylesheetsCount = (metadata.stylesheets_count as number | undefined) ?? 0
  const stylesheetsUrls = (metadata.stylesheets_urls as string[] | undefined) ?? []
  const iframesCount = (metadata.iframes_count as number | undefined) ?? 0
  const iframesUrls = (metadata.iframes_urls as string[] | undefined) ?? []
  const formsCount = (metadata.forms_count as number | undefined) ?? 0
  const formsList = (metadata.forms_list as FormEntry[] | undefined) ?? []
  const linksCount = (metadata.links_count as number | undefined) ?? 0
  const links = (metadata.links as string[] | undefined) ?? []
  const externalDomains = (metadata.external_domains as string[] | undefined) ?? []
  const finalUrl = metadata.final_url as string | undefined
  const statusCode = metadata.status_code as number | undefined
  const redirectChain = (metadata.redirect_chain as string[] | undefined) ?? []

  const linksCapNote = links.length < linksCount ? ` (showing first ${links.length})` : ''

  return (
    <div className="rounded-lg border" style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
      <div className="px-4 pt-3 pb-1" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <span className="text-sm font-semibold text-white/70 uppercase tracking-wider">
          Scanned Resources
        </span>
      </div>

      <div className="px-4 pt-2 pb-4">

        {/* Connection info */}
        <div className="flex flex-wrap gap-4 mb-3 pb-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          {finalUrl && (
            <div>
              <p className="text-xs text-white/40 uppercase tracking-wider mb-0.5">Final URL</p>
              <p className="text-xs font-mono text-white/60 break-all">{finalUrl}</p>
            </div>
          )}
          {statusCode !== undefined && (
            <div>
              <p className="text-xs text-white/40 uppercase tracking-wider mb-0.5">HTTP Status</p>
              <span
                className="text-xs font-mono px-2 py-0.5 rounded"
                style={{
                  backgroundColor: statusCode < 400 ? 'rgba(22,163,74,0.2)' : 'rgba(239,68,68,0.2)',
                  color: statusCode < 400 ? '#86efac' : '#fca5a5',
                }}
              >
                {statusCode}
              </span>
            </div>
          )}
        </div>

        {/* Redirect chain */}
        {redirectChain.length > 0 && (
          <div className="mb-3 pb-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="text-xs text-white/40 uppercase tracking-wider mb-1">
              Redirect Chain ({redirectChain.length})
            </p>
            <div className="flex flex-col gap-1">
              {redirectChain.map((r, i) => (
                <span key={i} className="text-xs font-mono text-white/50 break-all">
                  {i + 1}. {r}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Per-resource sections */}
        <ScanSection
          label="Scripts"
          count={scriptsCount}
          sublabel={scriptsAnalysed > 0 ? `${scriptsAnalysed} analysed` : undefined}
        >
          <TextList items={scriptsUrls} emptyText="No external scripts recorded." />
        </ScanSection>

        <ScanSection label="Stylesheets" count={stylesheetsCount}>
          <TextList items={stylesheetsUrls} emptyText="No external stylesheets recorded." />
        </ScanSection>

        <ScanSection label="iFrames" count={iframesCount}>
          <TextList items={iframesUrls} emptyText="No iFrame sources recorded." />
        </ScanSection>

        <ScanSection label="Forms" count={formsCount}>
          <div
            className="rounded p-2 flex flex-col gap-1.5 overflow-y-auto"
            style={{ backgroundColor: 'rgba(0,0,0,0.2)', maxHeight: '14rem' }}
          >
            {formsList.map((f, i) => (
              <span key={i} className="text-xs font-mono break-all" style={{ color: 'rgba(255,255,255,0.5)' }}>
                {f.method} — {f.action || '(same page)'} — {f.input_count} input{f.input_count !== 1 ? 's' : ''}
              </span>
            ))}
          </div>
        </ScanSection>

        <ScanSection label={`Links${linksCapNote}`} count={linksCount}>
          <TextList items={links} />
        </ScanSection>

        {/* External domains */}
        {externalDomains.length > 0 && (
          <div className="pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <p className="text-xs text-white/40 uppercase tracking-wider mb-2">
              External Domains ({externalDomains.length})
            </p>
            <div className="flex flex-wrap gap-2">
              {externalDomains.map((domain) => (
                <span
                  key={domain}
                  className="text-xs font-mono px-2 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.6)' }}
                >
                  {domain}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
