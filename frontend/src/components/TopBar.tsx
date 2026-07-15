import type { Board } from '../App'
import type { ChainStatus, Session, Summary } from '../lib/types'
import { Logo, Search, Theme } from './Icons'

export interface Filters {
  q: string
  verdict: string
  action: string
  org: string
  plane: string
  spanHours: number
  since?: string
  until?: string
}

const SPANS: { label: string; hours: number }[] = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
  { label: '30d', hours: 720 },
]

export function Header({ session, summary, connected, live, board, onBoard, onToggleTheme, onLogout }: {
  session: Session | null
  summary: Summary | null
  connected: boolean
  live: boolean
  board: Board
  onBoard: (b: Board) => void
  onToggleTheme: () => void
  onLogout: () => void
}) {
  const chains = summary?.chains ?? (summary ? { local: summary.chain } : {})
  const ks = summary?.killswitch
  return (
    <div className="header">
      <div className="brand">
        <Logo />
        <h1>AgentLighthouse</h1>
        <span className="tag">Operations console</span>
      </div>

      <nav className="boards" role="tablist" aria-label="boards">
        <button role="tab" aria-selected={board === 'trace'} data-testid="tab-trace"
          className={board === 'trace' ? 'active' : ''} onClick={() => onBoard('trace')}>
          Trace
        </button>
        <button role="tab" aria-selected={board === 'performance'} data-testid="tab-performance"
          className={board === 'performance' ? 'active' : ''} onClick={() => onBoard('performance')}>
          Performance
        </button>
      </nav>

      <div className="spacer" />
      {summary && (
        <span className="chip" title="operating mode / environment">
          {summary.mode} · {summary.env}
        </span>
      )}
      {ks && (
        <span className={`chip ${ks.engaged ? 'bad' : ''}`} title="kill switch"
          data-testid="killswitch-chip">
          <span className="dot" />
          {ks.engaged ? 'KILL SWITCH ENGAGED' : 'kill switch armed'}
        </span>
      )}
      {Object.entries(chains).map(([plane, c]) => (
        <span key={plane} className={`chip ${chainClass(c)}`}
          title={c.error ?? `${plane} evidence chain (${c.length ?? 0} receipts)`}
          data-testid="chain-chip">
          <span className="dot" />
          {chainLabel(plane, c)}
        </span>
      ))}
      {session && (
        <span className="chip" title="your RBAC role" data-testid="role-chip">{session.role}</span>
      )}
      <span className={`beacon ${connected ? (live ? 'live' : 'paused') : 'off'}`}
        title={connected ? (live ? 'live — polling every 3s' : 'live tracking paused') : 'connection lost'}
        data-testid="live-beacon">
        <span className="beam" />
        {connected ? (live ? 'live' : 'paused') : 'offline'}
      </span>
      <button className="icon-btn" onClick={onToggleTheme} aria-label="toggle theme"><Theme /></button>
      <button className="btn ghost" onClick={onLogout}>Sign out</button>
    </div>
  )
}

// BROKEN is reserved for a chain that was checked and failed — that is
// tampering. A chain we could not check reads "unverified", so the alarm keeps
// its meaning.
export function chainClass(c: ChainStatus): string {
  if (c.verified) return 'ok'
  return c.reason === 'unavailable' ? 'warn' : 'bad'
}

export function chainLabel(plane: string, c: ChainStatus): string {
  if (c.verified) return `${plane} chain ok`
  return c.reason === 'unavailable'
    ? `${plane} chain unverified` : `${plane} chain BROKEN`
}

export function Toolbar({ filters, setFilters, summary, session, live, setLive, onRefresh }: {
  filters: Filters
  setFilters: (f: Filters) => void
  summary: Summary | null
  session: Session | null
  live: boolean
  setLive: (b: boolean) => void
  onRefresh: () => void
}) {
  const set = (patch: Partial<Filters>) => setFilters({ ...filters, ...patch })
  const orgs = summary ? Object.keys(summary.orgs) : []
  const actions = summary ? Object.keys(summary.actions) : []
  const planes = session?.planes ?? []
  const brushed = filters.since || filters.until

  return (
    <div className="toolbar">
      <div className="search">
        <Search />
        <input
          data-testid="search-input"
          placeholder="Search actor, target, or block reason…"
          value={filters.q}
          onChange={(e) => set({ q: e.target.value })}
        />
      </div>

      <div className="seg" role="group" aria-label="time range">
        {SPANS.map((s) => (
          <button key={s.hours}
            className={filters.spanHours === s.hours && !brushed ? 'active' : ''}
            onClick={() => set({ spanHours: s.hours, since: undefined, until: undefined })}>
            {s.label}
          </button>
        ))}
      </div>

      <select className="filter" value={filters.verdict}
        onChange={(e) => set({ verdict: e.target.value })} aria-label="verdict filter"
        data-testid="verdict-filter">
        <option value="">any verdict</option>
        {['allow', 'block', 'strip', 'warn', 'ask'].map((v) => <option key={v} value={v}>{v}</option>)}
      </select>

      <select className="filter" value={filters.action}
        onChange={(e) => set({ action: e.target.value })} aria-label="action filter">
        <option value="">any action</option>
        {actions.map((a) => <option key={a} value={a}>{a}</option>)}
      </select>

      {planes.length > 1 && (
        <select className="filter" value={filters.plane}
          onChange={(e) => set({ plane: e.target.value })} aria-label="plane filter"
          data-testid="plane-filter">
          <option value="">both planes</option>
          {planes.map((p) => <option key={p} value={p}>{p} plane</option>)}
        </select>
      )}

      {orgs.length > 1 && (
        <select className="filter" value={filters.org}
          onChange={(e) => set({ org: e.target.value })} aria-label="org filter"
          data-testid="org-filter">
          <option value="">all orgs</option>
          {orgs.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      )}

      {brushed && (
        <button className="btn" onClick={() => set({ since: undefined, until: undefined })}>
          clear window
        </button>
      )}
      <div className="spacer" style={{ flex: 1 }} />
      <label className="toggle" title="poll the evidence API every 3 seconds">
        <input type="checkbox" checked={live} data-testid="live-toggle"
          onChange={(e) => setLive(e.target.checked)} />
        live
      </label>
      <button className="btn" onClick={onRefresh} data-testid="refresh-btn">Refresh</button>
    </div>
  )
}
