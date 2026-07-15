// Shared types mirroring the control-plane read-only API.

export interface Finding {
  scanner: string
  rule_id: string
  severity: string
  owasp?: string
  mitre?: string
}

export type Verdict = 'allow' | 'warn' | 'strip' | 'ask' | 'block'

export interface Receipt {
  v: number
  seq: number
  ts: string
  actor: string
  action: string
  target: string
  verdict: Verdict
  findings?: Finding[]
  block_reason?: string
  redaction?: Record<string, number>
  policy_hash?: string
  session?: string
  latency_ms?: number
  prev_hash: string
  record_hash: string
  sig: string
  // Presentation-only tag added by the evidence pool: which plane's ledger
  // this receipt came from ("data" = gateway, "control" = control plane).
  plane?: string
}

export interface ChainStatus {
  verified: boolean
  length?: number
  // Why it is unverified: "invalid" = the signatures were checked and failed
  // (tampering). "unavailable" = we could not check (no readable pubkey/ledger).
  // Only the first is an alarm; conflating them would cry wolf on a config typo.
  reason?: 'unavailable' | 'invalid' | null
  error: string | null
}

export interface KillswitchStatus {
  engaged: boolean
  source?: string | null
  reason?: string | null
  ts?: string | null
}

export interface Summary {
  mode: string
  env: string
  config_hash: string
  chain: ChainStatus
  chains?: Record<string, ChainStatus>
  killswitch?: KillswitchStatus
  events: number
  planes?: Record<string, number>
  verdicts: Record<string, number>
  actions: Record<string, number>
  block_reasons: Record<string, number>
  actors: Record<string, number>
  orgs: Record<string, number>
}

export interface Session {
  authenticated: boolean
  role: 'admin' | 'operator' | 'viewer'
  capabilities: string[]
  org: string | null
  orgs: string[]
  planes?: string[]
  mode: string
  env: string
}

export interface TrendBucket {
  bucket_start: string
  total: number
  allow: number
  block: number
  strip: number
  warn: number
  ask: number
}

export interface VerifyResult {
  seq: number
  plane?: string
  verified: boolean
  error: string | null
  record_hash?: string
  prev_hash?: string
  sig?: string
}

export interface SearchParams {
  q?: string
  since?: string
  until?: string
  actor?: string
  action?: string
  verdict?: string
  org?: string
  limit?: number
}
