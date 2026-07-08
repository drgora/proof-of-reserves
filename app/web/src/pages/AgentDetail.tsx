import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAgent } from '../hooks'
import { fmtNum, fmtTime, shortHash, type Receipt } from '../api'
import { agentIdDecimal, baseAddressUrl, baseTxUrl, marketplaceAgentUrl } from '../chain'
import { ErrorBox, Loading, NetworkBadge, PorBadge, TypeBadge, VerifiedBadge } from '../components'

export default function AgentDetail() {
  const { agentId } = useParams()
  const q = useAgent(agentId)
  const d = q.data

  if (q.isLoading) return <Loading label="Loading agent…" />
  if (q.isError) return <ErrorBox error={q.error} />
  if (!d) return null

  const a = d.agent
  const r = d.receipts

  return (
    <>
      <Link to="/" className="back">
        ← All agents
      </Link>

      <div className="detail-head">
        <h1>{a.name || 'Unnamed agent'}</h1>
        {d.isPor ? <PorBadge /> : a.zkVerified ? <VerifiedBadge /> : null}
        <TypeBadge type={a.type} />
        <NetworkBadge network={d.network} />
        {!a.active && <span className="badge type">inactive</span>}
      </div>
      <div className="detail-sub">
        <span className="detail-id mono">Agent #{agentIdDecimal(a.agentId)}</span>
        <a
          className="marketplace-link"
          href={marketplaceAgentUrl(d.marketplace, a.agentId)}
          target="_blank"
          rel="noreferrer"
        >
          View on marketplace ↗
        </a>
      </div>
      {a.description && <p className="detail-desc">{a.description}</p>}

      <div className="bigmetrics">
        <div className="bigmetric">
          <div className="v">{fmtNum(r.count)}</div>
          <div className="k">Quality receipts ({fmtNum(r.validated)} passed · {fmtNum(r.failed)} failed)</div>
        </div>
      </div>

      <div className="panels">
        <div className="panel">
          <h3>Identity</h3>
          <KV k="Agent ID" v={<span className="mono">{agentIdDecimal(a.agentId)}</span>} />
          <KV
            k="Owner"
            v={
              /^0x[0-9a-fA-F]{40}$/.test(a.owner) ? (
                <a
                  className="mono"
                  href={baseAddressUrl(d.baseExplorer, a.owner)}
                  target="_blank"
                  rel="noreferrer"
                >
                  {shortHash(a.owner, 10, 8)} ↗
                </a>
              ) : (
                <span className="mono">{shortHash(a.owner, 10, 8)}</span>
              )
            }
          />
          {a.type && <KV k="Type" v={a.type} />}
          {a.pricing && <KV k="Pricing" v={a.pricing} />}
          <KV k="Active" v={a.active ? 'Yes' : 'No'} />
          {a.website && (
            <KV
              k="Website"
              v={
                <a href={a.website} target="_blank" rel="noreferrer">
                  {a.website}
                </a>
              }
            />
          )}
          {!!a.skills?.length && <KV k="Skills" v={chips(a.skills)} />}
          {!!a.domains?.length && <KV k="Domains" v={chips(a.domains)} />}
        </div>

        <div className="panel">
          <h3>What its receipts prove</h3>
          <p style={{ margin: '0 0 12px', color: 'var(--muted)', fontSize: 14, lineHeight: 1.55 }}>
            {d.whatThisProves?.summary || 'No published description for this proof type.'}
          </p>
          {!!d.whatThisProves?.proofTypes?.length && (
            <div className="chips">
              {d.whatThisProves.proofTypes.map((t) => (
                <span key={t} className="chip">
                  {t}
                </span>
              ))}
            </div>
          )}
          <div style={{ marginTop: 16 }}>
            <KV
              k="Reputation"
              v={
                d.reputation && d.reputation.reviewCount > 0
                  ? `${d.reputation.avgScore}/100 · ${d.reputation.reviewCount} reviews`
                  : 'No on-chain reviews yet'
              }
            />
          </div>
        </div>

        <div className="panel full">
          <h3>Quality receipts {r.returned < r.count ? `(latest ${r.returned} of ${r.count})` : `(${r.count})`}</h3>
          <ChallengeList items={r.items} baseExplorer={d.baseExplorer} />
        </div>
      </div>
    </>
  )
}

type Challenge = {
  key: string
  nonce: string | null
  chain: string | null
  threshold: string | null
  proofType: string | null
  first: string | null
  last: string | null
  items: Receipt[]
}

// Group proofs that answer the same challenge (shared challenge_nonce in the journal).
// Proofs without decoded public inputs fall back to a group of their own.
function groupByChallenge(items: Receipt[]): Challenge[] {
  const groups = new Map<string, Receipt[]>()
  for (const it of items) {
    const key = it.publicInputs?.challengeNonce || `solo:${it.id}`
    const arr = groups.get(key)
    if (arr) arr.push(it)
    else groups.set(key, [it])
  }
  const challenges = [...groups.entries()].map(([key, its]) => {
    const times = its
      .map((x) => x.publicInputs?.blockTimestamp)
      .filter((t): t is string => !!t)
      .sort()
    const pi = its[0].publicInputs
    return {
      key,
      nonce: pi?.challengeNonce ?? null,
      chain: pi?.chain ?? null,
      threshold: pi?.threshold ?? null,
      proofType: its[0].proofType ?? null,
      first: times[0] ?? null,
      last: times[times.length - 1] ?? null,
      // proofs newest reference block first
      items: its
        .slice()
        .sort((a, b) => (b.publicInputs?.blockNumber ?? 0) - (a.publicInputs?.blockNumber ?? 0)),
    }
  })
  // newest challenge first (by latest reference block covered)
  challenges.sort((a, b) => (b.last ?? '').localeCompare(a.last ?? ''))
  return challenges
}

function ChallengeList({ items, baseExplorer }: { items: Receipt[]; baseExplorer?: string }) {
  if (!items?.length) return <div style={{ color: 'var(--muted)' }}>No receipts.</div>
  return (
    <div className="challenges">
      {groupByChallenge(items).map((c) => (
        <ChallengeCard key={c.key} c={c} baseExplorer={baseExplorer} />
      ))}
    </div>
  )
}

function ChallengeCard({ c, baseExplorer }: { c: Challenge; baseExplorer?: string }) {
  const dur = c.first && c.last ? formatDuration(c.first, c.last) : null
  return (
    <div className="challenge">
      <div className="challenge-head">
        <span className="challenge-title">
          {c.nonce ? (
            <>
              Challenge <span className="mono">{shortHash(c.nonce)}</span>
            </>
          ) : (
            'Proof'
          )}
        </span>
        {c.proofType && <span className="chip">{c.proofType}</span>}
        {c.chain && <span className="chip">{c.chain}</span>}
        {c.threshold && <span className="challenge-badge">Proved ≥ {c.threshold}</span>}
        <span className="challenge-meta">
          {c.items.length} proof{c.items.length > 1 ? 's' : ''}
        </span>
      </div>
      {c.first && c.last && (
        <div className="challenge-window">
          <span className="cw-label">Reserves held across</span>
          <span className="cw-dur">{dur}</span>
          <span className="cw-span">
            {fmtTime(c.first)} <span className="cw-arrow">→</span> {fmtTime(c.last)}
          </span>
        </div>
      )}
      <div className="table-wrap">
        <table className="receipts">
          <thead>
            <tr>
              <th>Status</th>
              <th>Reference block</th>
              <th>Block time</th>
              <th>Recorded</th>
              <th>On-chain validation</th>
            </tr>
          </thead>
          <tbody>
            {c.items.map((it) => (
              <tr key={it.id}>
                <td>
                  <span className={`status ${it.status}`}>{it.status}</span>
                </td>
                <td className="mono">
                  {it.publicInputs ? (
                    it.publicInputs.blockUrl ? (
                      <a href={it.publicInputs.blockUrl} target="_blank" rel="noreferrer">
                        {it.publicInputs.blockNumber} ↗
                      </a>
                    ) : (
                      it.publicInputs.blockNumber
                    )
                  ) : (
                    '—'
                  )}
                </td>
                <td>{it.publicInputs?.blockTimestamp ? fmtTime(it.publicInputs.blockTimestamp) : '—'}</td>
                <td>{fmtTime(it.timestamp)}</td>
                <td className="mono">
                  {it.validationTxHash ? (
                    <a href={baseTxUrl(baseExplorer, it.validationTxHash)} target="_blank" rel="noreferrer">
                      {shortHash(it.validationTxHash)} ↗
                    </a>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Human-readable span between the earliest and latest reference block a challenge covered —
// the window over which reserves were continuously proven (e.g. "3d 4h", "18h", "42m").
function formatDuration(a: string, b: string): string {
  const ms = Math.abs(new Date(b).getTime() - new Date(a).getTime())
  if (!isFinite(ms) || ms <= 0) return 'a moment'
  const mins = Math.round(ms / 60000)
  const days = Math.floor(mins / 1440)
  const hrs = Math.floor((mins % 1440) / 60)
  const rem = mins % 60
  if (days >= 1) return hrs ? `${days}d ${hrs}h` : `${days}d`
  if (hrs >= 1) return rem ? `${hrs}h ${rem}m` : `${hrs}h`
  return `${mins}m`
}

function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  )
}

function chips(items: string[]) {
  return (
    <span className="chips" style={{ justifyContent: 'flex-end', marginTop: 0 }}>
      {items.map((s) => (
        <span key={s} className="chip">
          {s}
        </span>
      ))}
    </span>
  )
}
