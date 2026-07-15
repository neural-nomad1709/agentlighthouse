import type { Receipt } from '../lib/types'
import { fmtLatency, isAlert, rid, sevClass, shortTime, verdictClass } from '../lib/format'

// Center column of the Trace board: every BLOCK and ASK in the current window
// as a full-context alert card. An operator must never have to hunt for the
// who/where of an alert — agent id, session, plane, seq, rule, and the signed
// hash are all on the card; click opens the receipt for verification.
export function AlertCenter({ receipts, selectedId, onSelect }: {
  receipts: Receipt[]
  selectedId: string | null
  onSelect: (r: Receipt) => void
}) {
  const alerts = receipts.filter(isAlert)
  return (
    <div data-testid="alert-center">
      <div className="col-title">
        Alerts — blocked &amp; held commands
        <span className="count">{alerts.length}</span>
      </div>
      {alerts.length === 0 && (
        <div className="card empty-note">
          No blocked or held commands in this window. Allowed traffic keeps
          flowing in the live trace on the left.
        </div>
      )}
      {alerts.map((r) => {
        const id = rid(r)
        return (
          <div key={id} data-testid="alert-card"
            className={`alert-card v-${verdictClass(r.verdict)} ${selectedId === id ? 'selected' : ''}`}
            onClick={() => onSelect(r)} role="button" tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && onSelect(r)}>
            <div className="head">
              <span className={`pill ${verdictClass(r.verdict)}`}>{r.verdict}</span>
              <span className="reason">{r.block_reason ?? 'held for approval'}</span>
              <span className="when" title={r.ts}>{shortTime(r.ts)}</span>
            </div>
            <div className="grid">
              <span className="k">agent</span>
              <span className="v mono" title={r.actor}>{r.actor}</span>
              {r.session && (<>
                <span className="k">session</span>
                <span className="v mono" title={r.session}>{r.session}</span>
              </>)}
              <span className="k">command</span>
              <span className="v"><b>{r.action}</b> → <span className="mono">{r.target}</span></span>
              <span className="k">receipt</span>
              <span className="v mono">
                {r.plane && <span className={`plane ${r.plane}`}>{r.plane}</span>}
                {' '}#{r.seq} · {r.record_hash.slice(0, 26)}…
                {r.latency_ms !== undefined && ` · ${fmtLatency(r.latency_ms)}`}
              </span>
            </div>
            {(r.findings?.length ?? 0) > 0 && (
              <div className="rules">
                {r.findings!.map((f, i) => (
                  <span className="rule" key={i}>
                    <span className={sevClass(f.severity)}>{f.severity}</span>
                    <span className="mono">{f.scanner}/{f.rule_id}</span>
                    {f.owasp && <span className="t">{f.owasp}</span>}
                    {f.mitre && <span className="t">{f.mitre}</span>}
                  </span>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
