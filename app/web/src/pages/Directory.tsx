import { Link } from 'react-router-dom'
import { useDirectory, useOverview, usePipeline } from '../hooks'
import { fmtNum, fmtTime, timeAgo, type AgentRow, type DirectoryMode } from '../api'
import { ErrorBox, Loading, NetworkBadge, PipelineTimeline, PorBadge, TypeBadge, VerifiedBadge } from '../components'

export default function Directory() {
  const overview = useOverview()
  const dir = useDirectory()
  const pipeline = usePipeline()

  const o = overview.data
  const d = dir.data
  const p = pipeline.data
  const challengeCount = d ? d.agents.reduce((n, a) => n + (a.challengeCount ?? 0), 0) : null
  // The single most recently recorded challenge across all listed agents.
  const lastPassed = d?.agents
    .filter((a) => a.lastChallenge)
    .map((a) => ({ agent: a, c: a.lastChallenge! }))
    .sort((x, y) => (y.c.recordedAt ?? '').localeCompare(x.c.recordedAt ?? ''))[0]

  return (
    <>
      <section className="hero">
        <div className="hero-top">
          <NetworkBadge network={d?.network} />
        </div>
        <h1>
          Verified <span className="accent">Proof-of-Reserves</span> agents
        </h1>
        <p>
          Trading agents that have proven they control a wallet and hold a balance above a
          threshold — without revealing the balance or the address. Each proof is a Risc0 receipt
          verified on zkVerify and recorded on the Horizen Labs Agent Marketplace.
        </p>
      </section>

      {p?.enabled && p.jobs.length > 0 && (
        <section className="pipeline-section">
          <div className="section-head">
            <h2>Verification pipeline</h2>
            <span className="count">live · this node</span>
          </div>
          <p className="section-sub">
            Each proof travels Kurier → zkVerify → attestation relay → on-chain{' '}
            <span className="mono">recordValidation</span> on Base Sepolia before it counts as a
            receipt below.
          </p>
          <PipelineTimeline
            jobs={p.jobs}
            explorer={p.explorer || d?.explorer}
            baseExplorer={p.baseExplorer || d?.baseExplorer}
          />
        </section>
      )}

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
          <div className="num">{challengeCount != null ? fmtNum(challengeCount) : '—'}</div>
          <div className="label">Challenges passed</div>
        </div>
      </div>

      {lastPassed && (
        <Link to={`/agent/${lastPassed.agent.agentId}`} className="last-challenge">
          <div className="lc-head">
            <span className="lc-label">Last passed challenge</span>
            <span className="lc-when">{timeAgo(lastPassed.c.recordedAt)}</span>
          </div>
          <div className="lc-body">
            <span className="lc-agent">{lastPassed.agent.name || lastPassed.agent.agentId}</span>{' '}
            proved <span className="lc-strong">≥ {lastPassed.c.threshold ?? '—'}</span>
            {lastPassed.c.chain && (
              <>
                {' '}on <span className="chip">{lastPassed.c.chain}</span>
              </>
            )}
          </div>
          {lastPassed.c.first && lastPassed.c.last && (
            <div className="lc-meta">
              {lastPassed.c.proofCount} blocks · covered {fmtTime(lastPassed.c.first)} →{' '}
              {fmtTime(lastPassed.c.last)}
            </div>
          )}
        </Link>
      )}

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
          <div className="v">{fmtNum(agent.challengeCount ?? 0)}</div>
          <div className="k">Challenges</div>
        </div>
      </div>

      {agent.lastChallenge && (
        <div className="card-last">
          Last: ≥ {agent.lastChallenge.threshold ?? '—'}
          {agent.lastChallenge.chain ? ` on ${agent.lastChallenge.chain}` : ''} ·{' '}
          {agent.lastChallenge.proofCount} blocks
        </div>
      )}

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
        <span className="mono">POR_PROOF_TYPES</span> on the read-proxy to match the proof type
        you register PoR under.)
      </div>
    </div>
  )
}
