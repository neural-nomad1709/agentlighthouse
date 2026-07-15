import { useRef, useState } from 'react'
import type { TrendBucket } from '../lib/types'
import { fmtInt, shortTime, VERDICT_COLOR, VERDICTS } from '../lib/format'

// Stacked-bar volume chart over time buckets, verdict-colored. Click-drag
// selects a bucket range and calls onBrush(sinceISO, untilISO) — drag over a
// spike to pin the whole console to that window. Hover shows the bucket's
// full verdict breakdown; the marks follow the shared specs (thin bars,
// 2px surface gaps between stacked segments, rounded top cap, solid hairline
// grid, one axis).
export function Trends({ series, onBrush }: {
  series: TrendBucket[]
  onBrush: (since: string, until: string) => void
}) {
  const W = 640, H = 210, padL = 40, padB = 24, padT = 10, padR = 8
  const iw = W - padL - padR, ih = H - padT - padB
  const n = series.length
  const max = Math.max(1, ...series.map((b) => b.total))
  const bw = n > 0 ? iw / n : iw
  const barW = Math.min(24, Math.max(3, bw * 0.62))

  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null)
  const [hover, setHover] = useState<number | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  const idxAt = (clientX: number): number => {
    const rect = svgRef.current!.getBoundingClientRect()
    const x = ((clientX - rect.left) / rect.width) * W - padL
    return Math.max(0, Math.min(n - 1, Math.floor(x / bw)))
  }

  const yTicks = [0, 0.5, 1].map((f) => Math.round(max * f))
  const hovered = hover !== null ? series[hover] : null

  return (
    <div className="card chart">
      <h3>Volume and verdicts over time</h3>
      <div className="chart-wrap">
        <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} role="img" aria-label="verdict volume over time"
          data-testid="trends-svg"
          onMouseDown={(e) => setDrag({ a: idxAt(e.clientX), b: idxAt(e.clientX) })}
          onMouseMove={(e) => {
            if (n > 0) setHover(idxAt(e.clientX))
            if (drag) setDrag((d) => d && { ...d, b: idxAt(e.clientX) })
          }}
          onMouseUp={() => {
            if (drag && n > 0) {
              const lo = Math.min(drag.a, drag.b), hi = Math.max(drag.a, drag.b)
              const since = series[lo].bucket_start
              const until = hi + 1 < n ? series[hi + 1].bucket_start
                : new Date().toISOString()
              onBrush(since, until)
            }
            setDrag(null)
          }}
          onMouseLeave={() => { setDrag(null); setHover(null) }}
          style={{ cursor: 'crosshair' }}>
          {yTicks.map((t, i) => {
            const y = padT + ih - (t / max) * ih
            return (
              <g key={i}>
                <line className="grid" x1={padL} y1={y} x2={W - padR} y2={y} />
                <text x={padL - 6} y={y + 3} textAnchor="end" fontSize="9"
                  fill="var(--fg-mut)" style={{ fontVariantNumeric: 'tabular-nums' }}>{fmtInt(t)}</text>
              </g>
            )
          })}
          {drag && (() => {
            const lo = Math.min(drag.a, drag.b), hi = Math.max(drag.a, drag.b)
            return <rect x={padL + lo * bw} y={padT} width={(hi - lo + 1) * bw} height={ih}
              fill="var(--accent)" opacity="0.14" />
          })()}
          {hover !== null && !drag && (
            <rect x={padL + hover * bw} y={padT} width={bw} height={ih}
              fill="var(--fg-mut)" opacity="0.08" />
          )}
          {series.map((b, i) => {
            const x = padL + i * bw + (bw - barW) / 2
            // 2px surface gap between touching segments; the TOP segment gets
            // the 4px rounded data-end, interior/base segments stay square.
            const segs = VERDICTS
              .map((v) => ({ v, val: (b[v as keyof TrendBucket] as number) || 0 }))
              .filter((s) => s.val > 0)
            let acc = 0
            return (
              <g key={b.bucket_start}>
                {segs.map((s, si) => {
                  const h = (s.val / max) * ih
                  const yTop = padT + ih - acc - h
                  acc += h
                  const isTop = si === segs.length - 1
                  const gap = si > 0 ? 1 : 0 // 2px total between fills (1px each side)
                  const hh = Math.max(1, h - gap - (isTop ? 0 : 1))
                  return isTop ? (
                    <path key={s.v} fill={VERDICT_COLOR[s.v]}
                      d={roundedTop(x, yTop + gap, barW, hh, Math.min(4, barW / 2, hh))} />
                  ) : (
                    <rect key={s.v} x={x} y={yTop + gap} width={barW} height={hh}
                      fill={VERDICT_COLOR[s.v]} />
                  )
                })}
              </g>
            )
          })}
          <line className="axis" x1={padL} y1={padT + ih} x2={W - padR} y2={padT + ih} />
          {n > 0 && (
            <>
              <text x={padL} y={H - 8} fontSize="9" fill="var(--fg-mut)">
                {shortTime(series[0].bucket_start)}</text>
              <text x={W - padR} y={H - 8} fontSize="9" fill="var(--fg-mut)" textAnchor="end">
                {shortTime(series[n - 1].bucket_start)}</text>
            </>
          )}
        </svg>
        {hovered && (
          <div className="tip" style={{ left: `${((padL + (hover! + 0.5) * bw) / W) * 100}%` }}>
            <div className="t-when">{hovered.bucket_start.replace('T', ' ').replace('Z', ' UTC')}</div>
            <div className="t-row total"><span>total</span><b>{fmtInt(hovered.total)}</b></div>
            {VERDICTS.map((v) => {
              const val = (hovered[v as keyof TrendBucket] as number) || 0
              return val > 0 && (
                <div className="t-row" key={v}>
                  <i style={{ background: VERDICT_COLOR[v] }} /><span>{v}</span><b>{fmtInt(val)}</b>
                </div>
              )
            })}
          </div>
        )}
      </div>
      <div className="legend">
        {VERDICTS.map((v) => (
          <span key={v}><i style={{ background: VERDICT_COLOR[v] }} />{v}</span>
        ))}
      </div>
      <div className="brush-hint">Drag across the chart to pin every board to that window.</div>
    </div>
  )
}

// Bar path with rounded TOP corners only (data-end), square at the baseline.
function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.max(0, Math.min(r, h))
  return `M${x},${y + h} L${x},${y + rr} Q${x},${y} ${x + rr},${y} L${x + w - rr},${y} ` +
    `Q${x + w},${y} ${x + w},${y + rr} L${x + w},${y + h} Z`
}
