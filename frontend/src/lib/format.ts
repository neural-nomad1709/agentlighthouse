import type { Receipt, Verdict } from './types'

export function shortTime(ts: string): string {
  // ts is ISO UTC with trailing Z; show HH:MM:SS
  const t = ts.replace('T', ' ').replace('Z', '')
  return t.slice(11, 19) || t
}

export function relTime(ts: string, nowMs: number): string {
  const then = Date.parse(ts)
  if (Number.isNaN(then)) return ''
  const s = Math.max(0, Math.round((nowMs - then) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

export const VERDICTS: Verdict[] = ['allow', 'strip', 'warn', 'ask', 'block']

// One id per receipt across BOTH evidence planes — seq alone collides.
export function rid(r: Pick<Receipt, 'seq' | 'plane'>): string {
  return `${r.plane ?? 'local'}:${r.seq}`
}

export function verdictClass(v: string): string {
  return VERDICTS.includes(v as Verdict) ? v : 'warn'
}

// Verdict series colors — categorical slots validated for both surfaces
// (scripts/validate_palette.js); the CSS vars swap with the theme.
export const VERDICT_COLOR: Record<string, string> = {
  allow: 'var(--v-allow)',
  strip: 'var(--v-strip)',
  warn: 'var(--v-warn)',
  ask: 'var(--v-ask)',
  block: 'var(--v-block)',
}

export function sevClass(sev: string): string {
  return `sev-${sev}`
}

export function iso(d: Date): string {
  return d.toISOString().replace(/\.\d+Z$/, '.000Z')
}

export function fmtLatency(ms: number | undefined): string {
  if (ms === undefined) return ''
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

export function fmtInt(n: number): string { return n.toLocaleString('en-US') }

export function percentile(sorted: number[], p: number): number | null {
  if (sorted.length === 0) return null
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
  return sorted[Math.max(0, idx)]
}

export function isAlert(r: Receipt): boolean {
  return r.verdict === 'block' || r.verdict === 'ask'
}
