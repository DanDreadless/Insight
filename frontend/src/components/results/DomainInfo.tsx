interface WhoisData {
  domain_name?: string
  registrar?: string
  creation_date?: string
  expiry_date?: string
  updated_date?: string
  registrant_country?: string
  name_servers?: string[]
  status?: string[]
}

interface DomainInfoProps {
  whois: WhoisData | null
}

function Row({ label, value }: { label: string; value: string | string[] | undefined }) {
  if (!value || (Array.isArray(value) && value.length === 0)) return null
  return (
    <div className="flex gap-3 py-1.5 border-b" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
      <span className="text-xs text-white/35 w-28 shrink-0 pt-0.5">{label}</span>
      <span className="text-xs text-white/75 break-all">
        {Array.isArray(value) ? value.join(', ') : value}
      </span>
    </div>
  )
}

export default function DomainInfo({ whois }: DomainInfoProps) {
  const hasContent = whois && (
    whois.registrar ||
    whois.creation_date ||
    whois.expiry_date ||
    whois.registrant_country ||
    (whois.name_servers && whois.name_servers.length > 0)
  )

  if (!hasContent) {
    return (
      <div
        className="rounded-lg border p-4 flex flex-col"
        style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.1)' }}
      >
        <h3 className="text-sm font-semibold text-white/70 uppercase tracking-wider mb-3">
          Domain Registration
        </h3>
        <p className="text-sm text-white/30 text-center my-auto py-4">
          WHOIS data unavailable for this domain.
        </p>
      </div>
    )
  }

  // Warn if cert is fresh (< 30 days since creation)
  let domainAge: string | null = null
  if (whois.creation_date) {
    const created = new Date(whois.creation_date)
    const now = new Date()
    const days = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24))
    if (days < 30) {
      domainAge = `${days} day${days === 1 ? '' : 's'} old`
    } else if (days < 365) {
      const months = Math.floor(days / 30)
      domainAge = `${months} month${months === 1 ? '' : 's'} old`
    } else {
      const years = Math.floor(days / 365)
      domainAge = `${years} year${years === 1 ? '' : 's'} old`
    }
  }

  const isFreshDomain = whois.creation_date
    ? (new Date().getTime() - new Date(whois.creation_date).getTime()) / (1000 * 60 * 60 * 24) < 30
    : false

  return (
    <div
      className="rounded-lg border p-4"
      style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.1)' }}
    >
      <h3 className="text-sm font-semibold text-white/70 uppercase tracking-wider mb-3">
        Domain Registration
      </h3>

      {isFreshDomain && (
        <div
          className="rounded px-3 py-2 mb-3 text-xs"
          style={{ backgroundColor: 'rgba(234,179,8,0.1)', border: '1px solid rgba(234,179,8,0.3)', color: '#fde047' }}
        >
          Newly registered domain — {domainAge}. Recently created domains are commonly used for phishing campaigns.
        </div>
      )}

      <div className="flex flex-col">
        <Row label="Registrar" value={whois.registrar} />
        <Row label="Country" value={whois.registrant_country} />
        <Row
          label="Created"
          value={whois.creation_date ? `${whois.creation_date}${domainAge && !isFreshDomain ? ` (${domainAge})` : ''}` : undefined}
        />
        <Row label="Expires" value={whois.expiry_date} />
        <Row label="Updated" value={whois.updated_date} />
        <Row label="Nameservers" value={whois.name_servers} />
      </div>
    </div>
  )
}
