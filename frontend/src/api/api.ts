import axios from 'axios'
import type { ScanJob, ScanSubmitResponse } from '../types'

const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
})

export async function submitScan(url: string): Promise<ScanSubmitResponse> {
  const response = await apiClient.post<ScanSubmitResponse>('/scan/', { url })
  return response.data
}

export async function getScan(id: string): Promise<ScanJob> {
  const response = await apiClient.get<ScanJob>(`/scan/${id}/`)
  return response.data
}

export interface ScanSummary {
  id: string
  url: string
  status: string
  verdict: string
  created_at: string
  completed_at: string | null
  last_scanned_at: string | null
  findings_count: number
}

export interface HistoryResponse {
  count: number
  page: number
  total_pages: number
  results: ScanSummary[]
}

export async function getHistory(q?: string, page?: number): Promise<HistoryResponse> {
  const params: Record<string, string | number> = {}
  if (q) params.q = q
  if (page && page > 1) params.page = page
  const response = await apiClient.get<HistoryResponse>('/history/', { params })
  return response.data
}

export async function getScanSource(scanId: string, url?: string): Promise<string> {
  const params = url ? { url } : {}
  const response = await apiClient.get<string>(`/scan/${scanId}/source/`, {
    params,
    responseType: 'text',
    timeout: 30000,
  })
  return response.data
}
