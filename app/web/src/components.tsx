import type { ReactNode } from 'react'

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

export function SlaMeter({ pct }: { pct: number | null | undefined }) {
  const v = typeof pct === 'number' ? Math.max(0, Math.min(100, pct)) : 0
  return (
    <div className="meter" aria-label={`SLA ${v}%`}>
      <span style={{ width: `${v}%` }} />
    </div>
  )
}
