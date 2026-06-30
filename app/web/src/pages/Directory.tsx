import { Link } from 'react-router-dom'
import { useDirectory, useOverview } from '../hooks'
import { fmtNum, fmtPct, timeAgo, type AgentRow, type DirectoryMode } from '../api'
import { ErrorBox, Loading, PorBadge, TypeBadge, VerifiedBadge } from '../components'

export default function Directory() {
  const overview = useOverview()
  const dir = useDirectory()

  const o = overview.data
  const d = dir.data
  const passRate =
    o && o.receipts.count ? Math.round((o.receipts.validated / o.receipts.count) * 100) : null

  return (
    <>
      <section className="hero">
        <h1>
          Verified <span className="accent">Proof-of-Reserves</span> agents
        </h1>
        <p>
          Trading agents that have proven they control a wallet and hold a balance above a
          threshold — without revealing the balance or the address. Each proof is a Risc0 receipt
          verified on zkVerify and recorded on the Horizen Labs Agent Marketplace.
        </p>
      </section>

      <div className="statbar">
        <div className="stat">
          <div className="num">{d ? fmtNum(d.porCount) : '—'}</div>
          <div className="label">Proof-of-Reserves agents</div>
        </div>
        <div className="stat">
          <div className="num">{o ? fmtNum(o.agents.withReceipts) : '—'}</div>
          <div className="label">Verified agents (all proof types)</div>
        </div>
        <div className="stat">
          <div className="num">{o ? fmtNum(o.receipts.count) : '—'}</div>
          <div className="label">Quality receipts on-chain</div>
        </div>
        <div className="stat">
          <div className="num">{fmtPct(passRate)}</div>
          <div className="label">Lifetime pass rate</div>
        </div>
      </div>

      {d?.mode === 'fallback-all' && <FallbackNotice porTypeLive={o?.porTypeLive} />}

      {(overview.isError || dir.isError) && (
        <ErrorBox error={dir.error || overview.error} />
      )}

      {dir.isLoading ? (
        <Loading label="Reading the marketplace…" />
      ) : d && d.agents.length ? (
        <>
          <div className="section-head">
            <h2>{d.mode === 'fallback-all' ? 'All verified agents' : 'Proof-of-Reserves agents'}</h2>
            <span className="count">{d.agents.length} shown</span>
          </div>
          <div className="grid">
            {d.agents.map((a) => (
              <AgentCard key={a.agentId} agent={a} mode={d.mode} />
            ))}
          </div>
        </>
      ) : (
        !dir.isError && (
          <div className="center-state">
            No verified agents yet. Once a Proof-of-Reserves agent records a validation, it shows up
            here.
          </div>
        )
      )}
    </>
  )
}

function AgentCard({ agent, mode }: { agent: AgentRow; mode: DirectoryMode }) {
  const isPor = mode !== 'fallback-all'
  return (
    <Link to={`/agent/${agent.agentId}`} className="agent-card">
      <div className="top">
        <div>
          <div className="name">{agent.name || 'Unnamed agent'}</div>
          <div className="id">{agent.agentId}</div>
        </div>
        {isPor ? <PorBadge /> : <VerifiedBadge />}
      </div>

      <div className="chips">
        <TypeBadge type={agent.type} />
        {(agent.proofTypes || []).map((t) => (
          <span key={t} className="chip">
            {t}
          </span>
        ))}
      </div>

      <div className="metrics">
        <div className="metric">
          <div className="v">{fmtNum(agent.receipts)}</div>
          <div className="k">Receipts</div>
        </div>
        <div className="metric">
          <div className="v">{fmtPct(agent.passRatePct)}</div>
          <div className="k">Pass rate</div>
        </div>
        <div className="metric">
          <div className="v">{fmtPct(agent.slaPct)}</div>
          <div className="k">7d SLA</div>
        </div>
      </div>

      <div className="foot">Last activity {timeAgo(agent.lastActivity)}</div>
    </Link>
  )
}

function FallbackNotice({ porTypeLive }: { porTypeLive?: boolean }) {
  return (
    <div className="notice">
      <span className="dot">●</span>
      <div>
        <b>Preview mode — showing all verified agents.</b>{' '}
        {porTypeLive
          ? 'No agent has recorded a Proof-of-Reserves validation yet.'
          : 'Proof-of-Reserves isn’t a registered proof type on the marketplace yet.'}{' '}
        Once PoR agents record validations, this directory automatically filters to them. (Set{' '}
        <span className="mono">POR_AGENT_IDS</span> or <span className="mono">POR_PROOF_TYPES</span>{' '}
        on the read-proxy to pin the filter.)
      </div>
    </div>
  )
}
