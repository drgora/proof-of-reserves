import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAgent } from '../hooks'
import { fmtNum, fmtPct, fmtTime, shortHash, txUrl, type Receipt } from '../api'
import { baseAddressUrl, baseTxUrl, marketplaceAgentUrl } from '../chain'
import { ErrorBox, Loading, NetworkBadge, PorBadge, SlaMeter, TypeBadge, VerifiedBadge } from '../components'

export default function AgentDetail() {
  const { agentId } = useParams()
  const q = useAgent(agentId)
  const d = q.data

  if (q.isLoading) return <Loading label="Loading agent…" />
  if (q.isError) return <ErrorBox error={q.error} />
  if (!d) return null

  const a = d.agent
  const r = d.receipts
  const slaPct = d.stats?.slaPct ?? null

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
        <span className="detail-id mono">{a.agentId}</span>
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
        <div className="bigmetric">
          <div className={'v' + (r.passRatePct === 100 ? ' good' : '')}>{fmtPct(r.passRatePct)}</div>
          <div className="k">Lifetime pass rate</div>
        </div>
        <div className="bigmetric">
          <div className={'v' + (slaPct === 100 ? ' good' : '')}>{fmtPct(slaPct)}</div>
          <div className="k">Last-7-day uptime SLA</div>
          {slaPct != null && <SlaMeter pct={slaPct} />}
        </div>
      </div>

      <div className="panels">
        <div className="panel">
          <h3>Identity</h3>
          <KV k="Agent ID" v={<span className="mono">{a.agentId}</span>} />
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
          <ReceiptsTable items={r.items} explorer={d.explorer} baseExplorer={d.baseExplorer} />
        </div>
      </div>
    </>
  )
}

function ReceiptsTable({
  items,
  explorer,
  baseExplorer,
}: {
  items: Receipt[]
  explorer: string
  baseExplorer?: string
}) {
  if (!items?.length) return <div style={{ color: 'var(--muted)' }}>No receipts.</div>
  return (
    <div className="table-wrap">
      <table className="receipts">
        <thead>
          <tr>
            <th>Status</th>
            <th>Score</th>
            <th>Proof type</th>
            <th>When</th>
            <th>zkVerify tx</th>
            <th>On-chain validation</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.id}>
              <td>
                <span className={`status ${it.status}`}>{it.status}</span>
              </td>
              <td>{fmtPct(it.scorePct)}</td>
              <td>
                <span className="chip">{it.proofType}</span>
              </td>
              <td>{fmtTime(it.timestamp)}</td>
              <td className="mono">
                {it.zkVerify?.txHash ? (
                  <a href={txUrl(explorer, it.zkVerify.txHash)} target="_blank" rel="noreferrer">
                    {shortHash(it.zkVerify.txHash)} ↗
                  </a>
                ) : (
                  '—'
                )}
              </td>
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
  )
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
