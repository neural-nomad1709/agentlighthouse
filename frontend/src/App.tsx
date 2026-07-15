import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, setToken } from './lib/api'
import type { Receipt, Session, Summary, TrendBucket } from './lib/types'
import { rid } from './lib/format'
import { Header, Toolbar, type Filters } from './components/TopBar'
import { LiveStream } from './components/LiveStream'
import { AlertCenter } from './components/AlertCenter'
import { DetailDrawer } from './components/DetailDrawer'
import { PerfBoard } from './components/PerfBoard'
import { Logo } from './components/Icons'

const DEFAULT_FILTERS: Filters = {
  q: '', verdict: '', action: '', org: '', plane: '', spanHours: 24,
}
const POLL_MS = 3000

export type Board = 'trace' | 'performance'

export function App() {
  const [authed, setAuthed] = useState(false)
  const [session, setSession] = useState<Session | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [receipts, setReceipts] = useState<Receipt[]>([])
  const [trends, setTrends] = useState<TrendBucket[]>([])
  const [selected, setSelected] = useState<Receipt | null>(null)
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS)
  const [board, setBoard] = useState<Board>('trace')
  // Live tracking is the point of an operational board — on by default.
  const [live, setLive] = useState(true)
  const [connected, setConnected] = useState(true)
  const [theme, setTheme] = useState<'dark' | 'light'>('dark')
  const seen = useRef<Set<string>>(new Set())
  const [fresh, setFresh] = useState<Set<string>>(new Set())

  useEffect(() => { document.documentElement.setAttribute('data-theme', theme) }, [theme])

  const loadData = useCallback(async () => {
    try {
      const [sum, tr, sr] = await Promise.all([
        api.summary(),
        api.trends(Math.min(48, Math.max(12, filters.spanHours)), filters.spanHours),
        api.search({
          q: filters.q || undefined,
          verdict: filters.verdict || undefined,
          action: filters.action || undefined,
          org: filters.org || undefined,
          since: filters.since, until: filters.until, limit: 300,
        }),
      ])
      setSummary(sum)
      setTrends(tr.series)
      // The plane filter is client-side: the merged feed is already tagged.
      const incoming = filters.plane
        ? sr.receipts.filter((r) => (r.plane ?? 'local') === filters.plane)
        : sr.receipts
      // Mark newly-arrived receipts for the enter animation (plane-aware id).
      const newOnes = new Set<string>()
      const firstLoad = seen.current.size === 0
      for (const r of incoming) if (!seen.current.has(rid(r))) newOnes.add(rid(r))
      incoming.forEach((r) => seen.current.add(rid(r)))
      setFresh(firstLoad ? new Set() : newOnes)
      setReceipts(incoming)
      setConnected(true)
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) { logout(); return }
      setConnected(false)
    }
  }, [filters])

  // Debounced reload on filter changes.
  useEffect(() => {
    if (!authed) return
    const h = setTimeout(loadData, filters.q ? 250 : 0)
    return () => clearTimeout(h)
  }, [authed, loadData, filters.q])

  // Live polling.
  useEffect(() => {
    if (!authed || !live) return
    const id = setInterval(loadData, POLL_MS)
    return () => clearInterval(id)
  }, [authed, live, loadData])

  const connect = async (s: Session) => {
    setSession(s)
    setAuthed(true)
  }

  const logout = () => {
    setToken('')
    setAuthed(false); setSession(null); setSummary(null); setReceipts([])
    setSelected(null); seen.current = new Set()
  }

  if (!authed) return <Gate onConnected={connect} />

  return (
    <div className="app">
      <Header session={session} summary={summary} connected={connected} live={live}
        board={board} onBoard={setBoard}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onLogout={logout} />
      <Toolbar filters={filters} setFilters={setFilters} summary={summary} session={session}
        live={live} setLive={setLive} onRefresh={loadData} />

      {board === 'trace' ? (
        <div className="main trace">
          <div className="col left">
            <div className="col-title">Live trace <span className="count">{receipts.length}</span></div>
            <LiveStream receipts={receipts} selectedId={selected ? rid(selected) : null}
              onSelect={setSelected} freshIds={fresh} />
          </div>

          <div className="col center">
            <AlertCenter receipts={receipts} selectedId={selected ? rid(selected) : null}
              onSelect={setSelected} />
          </div>

          <div className={`col right ${selected ? 'open' : ''}`}>
            <DetailDrawer receipt={selected} capabilities={session?.capabilities ?? []}
              onClose={() => setSelected(null)} />
          </div>
        </div>
      ) : (
        <div className="main perf">
          <PerfBoard summary={summary} trends={trends} receipts={receipts}
            onBrush={(since, until) => setFilters((f) => ({ ...f, since, until }))} />
        </div>
      )}
    </div>
  )
}

function Gate({ onConnected }: { onConnected: (s: Session) => void }) {
  const [value, setValue] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    if (!value.trim()) return
    setBusy(true); setErr('')
    setToken(value)
    try {
      const s = await api.session()
      onConnected(s)
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 401
        ? 'Invalid admin token.' : 'Could not reach the control plane.')
      setToken('')
    } finally { setBusy(false) }
  }

  return (
    <div className="gate">
      <div className="panel">
        <Logo size={40} />
        <h2>AgentLighthouse</h2>
        <p>Operations console for the evidence ledger. Sign in with your admin API
          token to watch live traffic and inspect signed receipts. Read-only; the
          token stays in this tab.</p>
        <label htmlFor="tok">Admin API token</label>
        <input id="tok" type="password" value={value} data-testid="token-input"
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="AL_ADMIN_API_TOKEN" autoFocus />
        {err && <div className="err" data-testid="gate-error">{err}</div>}
        <button className="btn primary" onClick={submit} disabled={busy} data-testid="connect-btn">
          {busy ? <span className="spin" /> : 'Connect'}
        </button>
      </div>
    </div>
  )
}
