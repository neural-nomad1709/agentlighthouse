import { useEffect, useState } from 'react'
import type { Receipt, VerifyResult } from '../lib/types'
import { api } from '../lib/api'
import { fmtLatency, rid, sevClass, verdictClass } from '../lib/format'
import { Check, Cross } from './Icons'

// Right column: full receipt inspection + an in-place signature verify that
// runs the same standalone verifier third parties use — against the KEY OF THE
// PLANE the receipt came from. Everything an audit needs is on this panel:
// identity, session, command, rule hits, and the hash-chain pointers.
export function DetailDrawer({ receipt, capabilities, onClose }: {
  receipt: Receipt | null
  capabilities: string[]
  onClose: () => void
}) {
  const [verify, setVerify] = useState<VerifyResult | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => { setVerify(null) }, [receipt && rid(receipt)])

  if (!receipt) {
    return (
      <div className="detail">
        <div className="col-title">Receipt detail</div>
        <div className="empty">Select a trace entry or an alert to inspect the
          signed receipt, its findings, and verify its signature.</div>
      </div>
    )
  }

  const runVerify = async () => {
    setBusy(true)
    try { setVerify(await api.verify(receipt.seq, receipt.plane)) }
    catch { setVerify({ seq: receipt.seq, verified: false, error: 'verify request failed' }) }
    finally { setBusy(false) }
  }

  return (
    <div className="detail" data-testid="detail">
      <div className="col-title">
        <span>
          {receipt.plane && <span className={`plane ${receipt.plane}`}>{receipt.plane}</span>}
          {' '}Receipt #{receipt.seq}
        </span>
        <button className="icon-btn" onClick={onClose} aria-label="close detail"
          style={{ padding: '2px 8px' }}>×</button>
      </div>

      <div className="kv">
        <span className="k">verdict</span>
        <span className="v"><span className={`pill ${verdictClass(receipt.verdict)}`}>{receipt.verdict}</span></span>
        <span className="k">agent</span><span className="v" data-testid="detail-actor">{receipt.actor}</span>
        {receipt.session && (<><span className="k">session</span>
          <span className="v" data-testid="detail-session">{receipt.session}</span></>)}
        <span className="k">action</span><span className="v">{receipt.action}</span>
        <span className="k">target</span><span className="v">{receipt.target}</span>
        <span className="k">time</span><span className="v">{receipt.ts}</span>
        {receipt.latency_ms !== undefined && (<><span className="k">latency</span>
          <span className="v">{fmtLatency(receipt.latency_ms)}</span></>)}
        {receipt.block_reason && (<><span className="k">reason</span>
          <span className="v" style={{ color: 'var(--v-block)' }}>{receipt.block_reason}</span></>)}
        {receipt.redaction && (<><span className="k">redaction</span>
          <span className="v">{Object.entries(receipt.redaction)
            .map(([c, n]) => `${c} ×${n}`).join(', ')} (counts only — plaintext never enters a receipt)</span></>)}
      </div>

      {(receipt.findings?.length ?? 0) > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div className="col-title" style={{ marginBottom: 8 }}>Findings</div>
          {receipt.findings!.map((f, i) => (
            <div className="finding-row" key={i}>
              <div className="top">
                <span className="rid">{f.scanner} / {f.rule_id}</span>
                <span className={sevClass(f.severity)} style={{ fontSize: 11, fontWeight: 700 }}>{f.severity}</span>
              </div>
              <div className="tags">
                {f.owasp && <span className="t">{f.owasp}</span>}
                {f.mitre && <span className="t">{f.mitre}</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="col-title" style={{ marginBottom: 8 }}>Signed receipt</div>
      <JsonTree data={stripPlane(receipt)} />

      {capabilities.includes('verify') && (
        <>
          <button className="btn primary" style={{ marginTop: 12, width: '100%', justifyContent: 'center' }}
            onClick={runVerify} disabled={busy} data-testid="verify-btn">
            {busy ? <span className="spin" /> : 'Verify signature'}
          </button>
          {verify && (
            <div className={`verify-box ${verify.verified ? 'pass' : 'fail'}`} data-testid="verify-result">
              <span style={{ color: verify.verified ? 'var(--ok)' : 'var(--v-block)' }}>
                {verify.verified ? <Check /> : <Cross />}
              </span>
              <div className="txt">
                <div className="t1">{verify.verified ? 'Signature verified' : 'Verification FAILED'}</div>
                <div className="t2">{verify.verified
                  ? `Ed25519 signature + record hash check out against the ${receipt.plane ?? 'local'} plane key (standalone verifier).`
                  : verify.error}</div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// The plane tag is presentation-only (added by the evidence pool) — show the
// receipt as it is signed on disk.
function stripPlane(r: Receipt): Record<string, unknown> {
  const { plane: _plane, ...rest } = r
  return rest
}

function JsonTree({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="jsontree">
      {Object.entries(data).filter(([, v]) => v !== undefined).map(([k, v]) => (
        <div key={k}><span className="key">{k}</span>: <span className="str">{JSON.stringify(v)}</span></div>
      ))}
    </div>
  )
}
