import { useMemo, useState } from 'react'
import type { Receipt, Summary, TrendBucket } from '../lib/types'
import { fmtInt, fmtLatency, percentile } from '../lib/format'
import { chainClass } from './TopBar'
import { Trends } from './Trends'

// The analytical board: posture at the top (Z-pattern — the numbers an
// operator scans first sit top-left), then time series, then breakdowns.
// Rates come exactly from the bucketed trends API; latency percentiles are
// computed from the receipts in the current window (the fetch is capped, so
// the panel names its sample honestly).
export function PerfBoard({ summary, trends, receipts, onBrush }: {
  summary: Summary | null
  trends: TrendBucket[]
  receipts: Receipt[]
  onBrush: (since: string, until: string) => void
}) {
  const lat = useMemo(() => {
    const xs = receipts.map((r) => r.latency_ms).filter((v): v is number => v !== undefined)
    xs.sort((a, b) => a - b)
    return { n: xs.length, p50: percentile(xs, 50), p95: percentile(xs, 95) }
  }, [receipts])

  if (!summary) return <div className="muted" style={{ padding: 24 }}>Loading…</div>

  const blocks = summary.verdicts.block ?? 0
  const asks = summary.verdicts.ask ?? 0
  const strips = summary.verdicts.strip ?? 0
  const total = summary.events || 1
  const blockRate = (blocks / total) * 100

  return (
    <div className="perf-grid" data-testid="perf-board">
      <div className="tiles">
        <Tile k="Events (ledger)" v={fmtInt(summary.events)}
          sub={planesLine(summary.planes)} />
        <Tile k="Blocked" v={fmtInt(blocks)} cls="bad" sub={`${blockRate.toFixed(1)}% of events`} />
        <Tile k="Held for approval" v={fmtInt(asks)} cls={asks > 0 ? 'warn' : ''} />
        <Tile k="Redactions" v={fmtInt(strips)} />
        <Tile k="Latency p50 / p95" v={lat.p50 === null ? 'n/a' : fmtLatency(lat.p50)}
          sub={lat.p95 === null ? 'no timed receipts in window'
            : `p95 ${fmtLatency(lat.p95)} · ${lat.n} timed receipts`} data-testid="latency-tile" />
        <Tile k="Actors" v={fmtInt(Object.keys(summary.actors).length)}
          sub={`${Object.keys(summary.orgs).length} orgs`} />
      </div>

      <Trends series={trends} onBrush={onBrush} />

      <div className="two-up">
        <RateChart series={trends} />
        <LatencyChart receipts={receipts} />
      </div>

      <div className="three-up">
        <TopList title="Top block reasons" data={summary.block_reasons}
          color="var(--v-block)" />
        <TopList title="Most active agents" data={summary.actors} />
        <TopList title="Actions" data={summary.actions} />
      </div>

      <Posture s={summary} />
    </div>
  )
}

function planesLine(planes?: Record<string, number>): string | undefined {
  if (!planes) return undefined
  return Object.entries(planes).map(([p, n]) => `${p} ${fmtInt(n)}`).join(' · ')
}

function Tile({ k, v, cls, sub, ...rest }: {
  k: string; v: string | number; cls?: string; sub?: string; 'data-testid'?: string
}) {
  return (
    <div className="tile" data-testid={rest['data-testid']}>
      <div className="k">{k}</div>
      <div className={`v ${cls ?? ''}`}>{v}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  )
}

// Block + held rate per bucket, one axis (percent), 2px line, end dot.
function RateChart({ series }: { series: TrendBucket[] }) {
  const W = 320, H = 170, padL = 34, padB = 18, padT = 10, padR = 10
  const iw = W - padL - padR, ih = H - padT - padB
  const n = series.length
  const [hover, setHover] = useState<number | null>(null)

  const rate = (b: TrendBucket) => (b.total > 0 ? ((b.block + b.ask) / b.total) * 100 : null)
  const pts = series.map((b, i) => ({ i, r: rate(b) }))
  const max = Math.max(10, ...pts.map((p) => p.r ?? 0))
  const x = (i: number) => padL + (n > 1 ? (i / (n - 1)) * iw : iw / 2)
  const y = (r: number) => padT + ih - (r / max) * ih
  const path = pts.filter((p) => p.r !== null)
    .map((p, j) => `${j === 0 ? 'M' : 'L'}${x(p.i).toFixed(1)},${y(p.r!).toFixed(1)}`).join(' ')
  const last = [...pts].reverse().find((p) => p.r !== null)
  const hovered = hover !== null ? series[hover] : null
  const hr = hovered ? rate(hovered) : null

  return (
    <div className="card chart" data-testid="rate-chart">
      <h3>Blocked or held, % of traffic</h3>
      <div className="chart-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="block rate over time"
          onMouseMove={(e) => {
            const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect()
            const px = ((e.clientX - rect.left) / rect.width) * W - padL
            if (n > 1) setHover(Math.max(0, Math.min(n - 1, Math.round((px / iw) * (n - 1)))))
          }}
          onMouseLeave={() => setHover(null)}>
          {[0, 0.5, 1].map((f) => {
            const t = max * f
            return (
              <g key={f}>
                <line className="grid" x1={padL} y1={y(t)} x2={W - padR} y2={y(t)} />
                <text x={padL - 5} y={y(t) + 3} textAnchor="end" fontSize="9"
                  fill="var(--fg-mut)">{Math.round(t)}%</text>
              </g>
            )
          })}
          {hover !== null && (
            <line x1={x(hover)} y1={padT} x2={x(hover)} y2={padT + ih}
              stroke="var(--fg-mut)" strokeWidth="1" opacity="0.5" />
          )}
          <path d={path} fill="none" stroke="var(--v-block)" strokeWidth="2"
            strokeLinejoin="round" strokeLinecap="round" />
          {last && last.r !== null && (
            <circle cx={x(last.i)} cy={y(last.r)} r="4" fill="var(--v-block)"
              stroke="var(--bg-2)" strokeWidth="2" />
          )}
          <line className="axis" x1={padL} y1={padT + ih} x2={W - padR} y2={padT + ih} />
        </svg>
        {hovered && hr !== null && (
          <div className="tip" style={{ left: `${(x(hover!) / W) * 100}%` }}>
            <div className="t-when">{hovered.bucket_start.replace('T', ' ').replace('Z', ' UTC')}</div>
            <div className="t-row"><span>blocked/held</span><b>{hr.toFixed(1)}%</b></div>
            <div className="t-row"><span>events</span><b>{fmtInt(hovered.total)}</b></div>
          </div>
        )}
      </div>
    </div>
  )
}

// Gateway decision latency per time slice, p50 and p95 — computed from the
// receipts in the window that carry latency_ms (fetch/llm_call). Sampled: the
// receipt fetch is capped, and the subtitle says so.
function LatencyChart({ receipts }: { receipts: Receipt[] }) {
  const W = 320, H = 170, padL = 40, padB = 18, padT = 10, padR = 10
  const iw = W - padL - padR, ih = H - padT - padB
  const BUCKETS = 12
  const [hover, setHover] = useState<number | null>(null)

  const timed = useMemo(() =>
    receipts.filter((r) => r.latency_ms !== undefined)
      .map((r) => ({ t: Date.parse(r.ts), ms: r.latency_ms! }))
      .filter((p) => !Number.isNaN(p.t))
      .sort((a, b) => a.t - b.t), [receipts])

  if (timed.length === 0) {
    return (
      <div className="card chart" data-testid="latency-chart">
        <h3>Decision latency, p50 and p95</h3>
        <div className="muted empty-chart">No timed receipts in this window yet —
          gateway fetch and LLM calls carry latency.</div>
      </div>
    )
  }

  const t0 = timed[0].t, t1 = timed[timed.length - 1].t
  const span = Math.max(1, t1 - t0)
  const buckets: number[][] = Array.from({ length: BUCKETS }, () => [])
  for (const p of timed) {
    const i = Math.min(BUCKETS - 1, Math.floor(((p.t - t0) / span) * BUCKETS))
    buckets[i].push(p.ms)
  }
  const series = buckets.map((xs) => {
    xs.sort((a, b) => a - b)
    return { p50: percentile(xs, 50), p95: percentile(xs, 95), n: xs.length }
  })
  const max = Math.max(10, ...series.map((s) => s.p95 ?? 0))
  const x = (i: number) => padL + ((i + 0.5) / BUCKETS) * iw
  const y = (ms: number) => padT + ih - (ms / max) * ih
  const line = (key: 'p50' | 'p95') => series
    .map((s, i) => ({ i, v: s[key] }))
    .filter((p) => p.v !== null)
    .map((p, j) => `${j === 0 ? 'M' : 'L'}${x(p.i).toFixed(1)},${y(p.v!).toFixed(1)}`)
    .join(' ')
  const hovered = hover !== null ? series[hover] : null

  return (
    <div className="card chart" data-testid="latency-chart">
      <h3>Decision latency, p50 and p95</h3>
      <div className="chart-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="latency percentiles over time"
          onMouseMove={(e) => {
            const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect()
            const px = ((e.clientX - rect.left) / rect.width) * W - padL
            setHover(Math.max(0, Math.min(BUCKETS - 1, Math.floor((px / iw) * BUCKETS))))
          }}
          onMouseLeave={() => setHover(null)}>
          {[0, 0.5, 1].map((f) => {
            const t = max * f
            return (
              <g key={f}>
                <line className="grid" x1={padL} y1={y(t)} x2={W - padR} y2={y(t)} />
                <text x={padL - 5} y={y(t) + 3} textAnchor="end" fontSize="9"
                  fill="var(--fg-mut)">{fmtLatency(Math.round(t))}</text>
              </g>
            )
          })}
          {hover !== null && (
            <line x1={x(hover)} y1={padT} x2={x(hover)} y2={padT + ih}
              stroke="var(--fg-mut)" strokeWidth="1" opacity="0.5" />
          )}
          <path d={line('p95')} fill="none" stroke="var(--v-ask)" strokeWidth="2"
            strokeLinejoin="round" strokeLinecap="round" />
          <path d={line('p50')} fill="none" stroke="var(--v-allow)" strokeWidth="2"
            strokeLinejoin="round" strokeLinecap="round" />
          <line className="axis" x1={padL} y1={padT + ih} x2={W - padR} y2={padT + ih} />
        </svg>
        {hovered && (hovered.p50 !== null || hovered.p95 !== null) && (
          <div className="tip" style={{ left: `${(x(hover!) / W) * 100}%` }}>
            {hovered.p95 !== null && <div className="t-row">
              <i style={{ background: 'var(--v-ask)' }} /><span>p95</span><b>{fmtLatency(hovered.p95)}</b></div>}
            {hovered.p50 !== null && <div className="t-row">
              <i style={{ background: 'var(--v-allow)' }} /><span>p50</span><b>{fmtLatency(hovered.p50)}</b></div>}
            <div className="t-row"><span>samples</span><b>{hovered.n}</b></div>
          </div>
        )}
      </div>
      <div className="legend">
        <span><i style={{ background: 'var(--v-allow)' }} />p50</span>
        <span><i style={{ background: 'var(--v-ask)' }} />p95</span>
        <span className="muted">from the {fmtInt(timed.length)} timed receipts in view</span>
      </div>
    </div>
  )
}

// Single-series horizontal bars: one hue for all bars (identity lives in the
// row label, not a color ramp).
function TopList({ title, data, color }: {
  title: string; data: Record<string, number>; color?: string
}) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const max = Math.max(1, ...entries.map(([, n]) => n))
  return (
    <div className="card">
      <h3>{title}</h3>
      {entries.length === 0 && <div className="muted" style={{ fontSize: 11 }}>no data</div>}
      {entries.map(([k, n]) => (
        <div className="bar" key={k}>
          <span className="lbl" title={k}>{k}</span>
          <span className="track">
            <span className="fill" style={{
              width: `${(n / max) * 100}%`,
              background: color ?? 'var(--v-allow)',
            }} />
          </span>
          <span className="n">{fmtInt(n)}</span>
        </div>
      ))}
    </div>
  )
}

function Posture({ s }: { s: Summary }) {
  const chains = s.chains ?? { local: s.chain }
  const ks = s.killswitch
  return (
    <div className="card" data-testid="posture">
      <h3>Posture</h3>
      <div className="tiles" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(150px,1fr))' }}>
        {Object.entries(chains).map(([plane, c]) => (
          <div className="tile" key={plane}>
            <div className="k">{plane} evidence chain</div>
            <div className={`v ${chainClass(c)}`} style={{ fontSize: 18 }}>
              {c.verified ? 'verified'
                : c.reason === 'unavailable' ? 'unverified' : 'BROKEN'}
            </div>
            <div className="sub">{c.error ?? `${fmtInt(c.length ?? 0)} receipts, signed + hash-chained`}</div>
          </div>
        ))}
        {ks && (
          <div className="tile">
            <div className="k">Kill switch</div>
            <div className={`v ${ks.engaged ? 'bad' : 'ok'}`} style={{ fontSize: 18 }}>
              {ks.engaged ? 'ENGAGED' : 'armed'}
            </div>
            <div className="sub">{ks.engaged
              ? `${ks.source ?? 'unknown source'}${ks.reason ? ` · ${ks.reason}` : ''}`
              : 'deny-all one action away'}</div>
          </div>
        )}
        <div className="tile">
          <div className="k">Mode</div>
          <div className="v" style={{ fontSize: 18, textTransform: 'capitalize' }}>{s.mode}</div>
          <div className="sub">{s.env} · config {s.config_hash.slice(7, 19)}</div>
        </div>
      </div>
    </div>
  )
}
