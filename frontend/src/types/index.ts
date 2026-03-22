export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type VerdictType = 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN'
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED'

export interface Finding {
  id: string
  severity: SeverityLevel
  category: string
  title: string
  description: string
  evidence: string
  resource_url: string
}

export interface ScanJob {
  id: string
  url: string
  status: ScanStatus
  verdict: VerdictType
  created_at: string
  completed_at: string | null
  findings: Finding[]
  scan_metadata: Record<string, unknown>
  error_message?: string
}

export interface ScanSubmitResponse {
  id: string
  status: ScanStatus
}
