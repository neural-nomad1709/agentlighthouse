import type { Receipt } from '../lib/types'
import { fmtLatency, rid, shortTime, verdictClass } from '../lib/format'

// Left column: dense, auto-updating trace of EVERY mediated command — run or
// blocked. High-impact fields only; click an item to open the full receipt.
// New items animate in. Ids are (plane, seq) — two ledgers feed this stream.
export function LiveStream({ receipts, selectedId, onSelect, freshIds }: {
  receipts: Receipt[]
  selectedId: string | null
  onSelect: (r: Receipt) => void
  freshIds: Set<string>
}) {
  return (
    <div className="stream" data-testid="stream">
      {receipts.length === 0 && (
        <div className="muted" style={{ padding: 24, textAlign: 'center' }}>
          No receipts match the current filters.
        </div>
      )}
      {receipts.map((r) => {
        const id = rid(r)
        return (
          <div
            key={id}
            data-testid="event"
            className={`event ${selectedId === id ? 'selected' : ''} ${freshIds.has(id) ? 'enter' : ''}`}
            onClick={() => onSelect(r)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && onSelect(r)}
          >
            <span className={`pill ${verdictClass(r.verdict)}`}>{r.verdict}</span>
            <span className="meta">
              <span className="line1">
                {r.plane && <span className={`plane ${r.plane}`}>{r.plane}</span>}
                <span className="seq">#{r.seq}</span>
                <span className="actor" title={r.actor}>{r.actor}</span>
              </span>
              <span className="line2" title={`${r.action} · ${r.target}`}>
                {r.action} · {r.block_reason ?? r.target}
              </span>
            </span>
            <span className="tail">
              <span className="time">{shortTime(r.ts)}</span>
              {r.latency_ms !== undefined && (
                <span className="lat">{fmtLatency(r.latency_ms)}</span>
              )}
            </span>
          </div>
        )
      })}
    </div>
  )
}
