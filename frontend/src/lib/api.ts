// API client for the control-plane evidence endpoints.
// The admin bearer token is held in memory only (never persisted) and sent as
// Authorization: Bearer <token>. All endpoints are read-only.

import type {
  Receipt, Session, Summary, TrendBucket, VerifyResult, SearchParams,
} from './types'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

let token = ''
export function setToken(t: string) { token = t.trim() }
export function hasToken() { return token.length > 0 }

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (res.status === 401) throw new ApiError(401, 'Unauthorized — check the admin token')
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`)
  return res.json() as Promise<T>
}

function qs(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '' && v !== null) sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

export const api = {
  session: () => get<Session>('/api/session'),
  summary: () => get<Summary>('/api/summary'),
  trends: (buckets: number, spanHours: number) =>
    get<{ series: TrendBucket[] }>(`/api/trends${qs({ buckets, span_hours: spanHours })}`),
  search: (p: SearchParams) =>
    get<{ count: number; receipts: Receipt[] }>(`/api/search${qs({ ...p })}`),
  receipt: (seq: number, plane?: string) =>
    get<Receipt>(`/api/receipts/${seq}${qs({ plane })}`),
  verify: (seq: number, plane?: string) =>
    get<VerifyResult>(`/api/verify/${seq}${qs({ plane })}`),
}
