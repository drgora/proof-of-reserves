// REST client for the local read-proxy (server.mjs), which wraps the HL Agent
// Registry MCP API. All endpoints are GET + JSON.

export type AgentRow = {
  agentId: string
  name: string
  type: string | null
  receipts: number
  passRatePct: number | null
  slaPct: number | null
  slaWindow?: { bpsSum: number; total: number }
  lastActivity: string | null
  proofTypes?: string[]
}

export type DirectoryMode = 'allowlist' | 'por' | 'fallback-all'

export type Directory = {
  mode: DirectoryMode
  agents: AgentRow[]
  totalVerified: number
  porCount: number
  explorer: string
}

export type ProofType = {
  proofType: string
  name: string
  description: string | null
  keyCount: number
}

export type Overview = {
  network: string
  agents: { totalRegistered: number; withReceipts: number }
  receipts: { count: number; validated: number; failed: number }
  proofTypes: { count: number; types: ProofType[] }
  topAgentsByReceipts: AgentRow[]
  porProofTypes: string[]
  porTypeLive: boolean
  explorer: string
}

export type Receipt = {
  id: string
  status: 'validated' | 'failed' | string
  scorePct: number | null
  proofType: string
  timestamp: string
  zkVerify?: {
    txHash: string
    blockHash: string
    curve?: string
    constraintCount?: number
  }
}

export type AgentDetail = {
  agentId: string
  network: string
  agent: {
    agentId: string
    name: string
    description: string
    skills: string[]
    domains: string[]
    pricing: string | null
    zkVerified: boolean
    proofType: string | null
    website: string | null
    owner: string
    active: boolean
    // get_agent doesn't return an agent `type` (only the verified-list rows do),
    // so it's optional here; the TypeBadge just hides when absent.
    type?: string | null
  }
  whatThisProves: {
    proofType: string | null
    proofTypes: string[]
    summary: string | null
    claims: unknown[]
  }
  receipts: {
    count: number
    validated: number
    failed: number
    passRatePct: number | null
    returned: number
    items: Receipt[]
  }
  reputation?: { reviewCount: number; avgScore: number; feedback: unknown[] }
  stats?: { slaPct: number | null; slaLast7d?: { bpsSum: number; total: number } } | null
  isPor: boolean
  explorer: string
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url)
  if (!r.ok) {
    const e = await r.json().catch(() => ({}))
    throw new Error((e as any).error || `HTTP ${r.status}`)
  }
  return r.json() as Promise<T>
}

export const api = {
  overview: () => get<Overview>('/api/overview'),
  agents: () => get<Directory>('/api/agents'),
  agent: (id: string) => get<AgentDetail>(`/api/agents/${encodeURIComponent(id)}`),
}

// ---------------- formatting helpers ----------------

export const shortHash = (h?: string | null, head = 8, tail = 6) =>
  !h ? '—' : h.length <= head + tail + 2 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`

export const fmtNum = (n?: number | null) =>
  n == null ? '—' : n.toLocaleString('en-US')

export const fmtPct = (n?: number | null) => (n == null ? '—' : `${n}%`)

export function fmtTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  })
}

export function timeAgo(iso?: string | null): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (isNaN(then)) return '—'
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

/** zkVerify explorer link for an extrinsic tx hash. */
export const txUrl = (explorer: string, txHash: string) =>
  `${explorer.replace(/\/$/, '')}/extrinsic/${txHash}`
