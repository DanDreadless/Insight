interface TraceEntry {
  url: string
  host: string
  ip: string
}

interface NetworkTraceProps {
  trace: TraceEntry[]
}

export default function NetworkTrace({ trace }: NetworkTraceProps) {
  if (!trace || trace.length === 0) return null

  return (
    <div
      className="rounded-lg border mb-4"
      style={{ borderColor: 'rgba(255,255,255,0.1)', backgroundColor: 'rgba(255,255,255,0.02)' }}
    >
      <div
        className="px-4 py-3 flex items-center gap-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <span className="text-sm font-semibold text-white/70 uppercase tracking-wider">
          Network Trace
        </span>
        <span
          className="text-xs px-2 py-0.5 rounded"
          style={{ backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}
        >
          {trace.length} hop{trace.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="px-4 py-3 overflow-x-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr>
              <th
                className="text-left pb-2 pr-3 font-normal w-6"
                style={{ color: 'rgba(255,255,255,0.3)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                #
              </th>
              <th
                className="text-left pb-2 pr-6 font-normal"
                style={{ color: 'rgba(255,255,255,0.3)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                URL
              </th>
              <th
                className="text-left pb-2 pr-4 font-normal whitespace-nowrap"
                style={{ color: 'rgba(255,255,255,0.3)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                Host
              </th>
              <th
                className="text-left pb-2 font-normal whitespace-nowrap"
                style={{ color: 'rgba(255,255,255,0.3)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                IP
              </th>
            </tr>
          </thead>
          <tbody>
            {trace.map((entry, i) => {
              const isFinal = i === trace.length - 1
              const isRedirect = !isFinal && trace.length > 1
              return (
                <tr
                  key={i}
                  style={{ borderBottom: i < trace.length - 1 ? '1px solid rgba(255,255,255,0.04)' : undefined }}
                >
                  <td className="py-2 pr-3" style={{ color: 'rgba(255,255,255,0.2)' }}>
                    {i + 1}
                  </td>
                  <td className="py-2 pr-6 font-mono break-all" style={{ color: 'rgba(255,255,255,0.5)' }}>
                    <span>{entry.url}</span>
                    {isFinal && trace.length > 1 && (
                      <span
                        className="ml-2 inline-block px-1.5 py-0.5 rounded text-xs align-middle"
                        style={{ backgroundColor: 'rgba(22,163,74,0.15)', color: '#86efac' }}
                      >
                        landing
                      </span>
                    )}
                    {isRedirect && (
                      <span
                        className="ml-2 inline-block text-xs align-middle"
                        style={{ color: 'rgba(255,255,255,0.2)' }}
                      >
                        ↓
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-4 font-mono whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.6)' }}>
                    {entry.host || '—'}
                  </td>
                  <td className="py-2 font-mono whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.4)' }}>
                    {entry.ip && entry.ip !== entry.host
                      ? entry.ip
                      : entry.ip === entry.host && entry.ip
                        ? <span style={{ color: 'rgba(255,255,255,0.25)' }}>{entry.ip}</span>
                        : <span style={{ color: 'rgba(255,255,255,0.15)' }}>—</span>
                    }
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
