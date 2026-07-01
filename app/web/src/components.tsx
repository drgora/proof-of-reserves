import type { ReactNode } from 'react'
import { NETWORK, baseTxUrl } from './chain'
import { shortHash, timeAgo, txUrl, type PipelineJob, type PipelineStage } from './api'

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="center-state">
      <div className="spinner" />
      {label}
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div className="error-box">
      <b>Couldn’t reach the registry.</b>
      <div style={{ marginTop: 6, opacity: 0.85 }}>{msg}</div>
      <div style={{ marginTop: 8, fontSize: 13, opacity: 0.7 }}>
        Is the read-proxy running? Start it with <span className="mono">npm run server</span> (it
        listens on :8090, which Vite proxies under <span className="mono">/api</span>).
      </div>
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="center-state">{children}</div>
}

export function VerifiedBadge() {
  return <span className="badge verified dot">zkVerified</span>
}

export function PorBadge() {
  return <span className="badge por dot">Proof-of-Reserves</span>
}

export function TypeBadge({ type }: { type?: string | null }) {
  if (!type) return null
  return <span className="badge type">{type}</span>
}

export function NetworkBadge({ network = NETWORK }: { network?: string }) {
  return (
    <span className="badge net" title="Recorded on-chain on this network">
      {network}
    </span>
  )
}

// ---- Live submission pipeline ------------------------------------------------
// Stage order, matching the skill's recommended status timeline. FAILED is
// terminal and rendered specially (no fixed position in the ladder).
const PIPELINE_STEPS: { stage: PipelineStage; label: string }[] = [
  { stage: 'SUBMITTED', label: 'Submitted to Kurier' },
  { stage: 'FINALIZED', label: 'Verified on zkVerify' },
  { stage: 'AGGREGATED', label: 'Aggregated' },
  { stage: 'RELAYING', label: 'Relaying to Base' },
  { stage: 'RECORDING', label: 'Recording on-chain' },
  { stage: 'VERIFIED', label: 'Validation recorded' },
]
const stepIndex = (s: PipelineStage) => PIPELINE_STEPS.findIndex((x) => x.stage === s)

/** A per-job stepper: SUBMITTED → … → VERIFIED, with explorer links per stage. */
export function PipelineTimeline({
  jobs,
  explorer,
  baseExplorer,
}: {
  jobs: PipelineJob[]
  explorer?: string
  baseExplorer?: string
}) {
  if (!jobs?.length) return null
  return (
    <div className="pipeline">
      {jobs.map((j) => (
        <PipelineCard key={j.jobId} job={j} explorer={explorer} baseExplorer={baseExplorer} />
      ))}
    </div>
  )
}

function PipelineCard({
  job,
  explorer,
  baseExplorer,
}: {
  job: PipelineJob
  explorer?: string
  baseExplorer?: string
}) {
  const failed = job.stage === 'FAILED'
  const cur = stepIndex(job.stage)
  const done = !failed && job.stage === 'VERIFIED'

  const detail = (stage: PipelineStage): ReactNode => {
    switch (stage) {
      case 'SUBMITTED':
        return job.zkVerifyJobId ? <span className="mono">{job.zkVerifyJobId}</span> : null
      case 'FINALIZED':
        return job.zkVerifyExtrinsicHash && explorer ? (
          <a href={txUrl(explorer, job.zkVerifyExtrinsicHash)} target="_blank" rel="noreferrer">
            {shortHash(job.zkVerifyExtrinsicHash)} ↗
          </a>
        ) : null
      case 'AGGREGATED':
        return job.aggregationId != null ? <span className="mono">#{job.aggregationId}</span> : null
      case 'VERIFIED':
        return job.validationTxHash ? (
          <a href={baseTxUrl(baseExplorer, job.validationTxHash)} target="_blank" rel="noreferrer">
            {shortHash(job.validationTxHash)} ↗
          </a>
        ) : null
      default:
        return null
    }
  }

  return (
    <div className={'pipe-card' + (done ? ' done' : '') + (failed ? ' failed' : '')}>
      <div className="pipe-head">
        <div className="pipe-title">{job.agentName || job.agentId}</div>
        <div className="pipe-meta">
          <span className={'pipe-stage ' + (failed ? 'failed' : done ? 'done' : 'active')}>
            {failed ? 'Failed' : done ? 'Recorded' : 'In progress'}
          </span>
          <span className="pipe-when">{timeAgo(job.updatedAt || job.submittedAt)}</span>
        </div>
      </div>
      <ol className="stepper">
        {PIPELINE_STEPS.map((step, i) => {
          const state = failed
            ? 'pending'
            : done || i < cur
              ? 'done'
              : i === cur
                ? 'active'
                : 'pending'
          const d = detail(step.stage)
          return (
            <li key={step.stage} className={'step ' + state}>
              <span className="dot" />
              <span className="step-label">{step.label}</span>
              {d && <span className="step-detail">{d}</span>}
            </li>
          )
        })}
      </ol>
      {failed && job.error && <div className="pipe-error">{job.error}</div>}
    </div>
  )
}

export function SlaMeter({ pct }: { pct: number | null | undefined }) {
  const v = typeof pct === 'number' ? Math.max(0, Math.min(100, pct)) : 0
  return (
    <div className="meter" aria-label={`SLA ${v}%`}>
      <span style={{ width: `${v}%` }} />
    </div>
  )
}
