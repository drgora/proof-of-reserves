// Thin read-only proxy in front of the HL Agent Registry MCP server.
//
// The browser can't call the registry MCP endpoint directly (it's CORS-blocked
// and speaks JSON-RPC / MCP, not plain REST), so this little server:
//   - speaks MCP `tools/call` to the registry over HTTP,
//   - unwraps the `--- structured ---` JSON block each tool returns,
//   - filters the verified-agent set down to *proof-of-reserves* agents,
//   - exposes clean REST under /api that the Vite dev proxy already forwards.
//
// Zero dependencies: Node 22 `http` + global `fetch`.
//
// Env:
//   PORT                (default 8090)        — must match vite.config.ts API_PROXY target
//   REGISTRY_MCP_URL     default https://agent-registry.horizenlabs.io/api/mcp
//   POR_PROOF_TYPES      comma list, default "proof-of-reserves,reserves,por,risc0"
//                        — a verified agent counts as PoR if any of its receipts/
//                          proof-types match one of these (case-insensitive). Any
//                          agent with ≥1 matching receipt is listed.
//   POR_SHOW_ALL         "1" (default) — when no PoR agent is found, fall back to
//                        listing all verified agents (so the UI isn't blank before
//                        PoR is registered). Set "0" to strictly show only PoR.
//   CACHE_TTL_MS         default 60000
//   ZKVERIFY_EXPLORER    default https://zkverify-testnet.subscan.io  (per-tx link base)
//   BASESCAN_URL         default https://sepolia.basescan.org  (Base Sepolia explorer:
//                        recordValidation tx + contract/owner address links)
//   MARKETPLACE_URL      default https://agent-registry.horizenlabs.io  (canonical
//                        per-agent marketplace page base)
//   PIPELINE_URL         (unset) — if set, /api/pipeline proxies this submitter
//                        status source (e.g. the mock's /mock/pipeline, or a real
//                        submitter's status API). Unset → pipeline disabled.

import http from 'node:http'

const PORT = Number(process.env.PORT || 8090)
const REGISTRY_MCP_URL =
  process.env.REGISTRY_MCP_URL || 'https://agent-registry.horizenlabs.io/api/mcp'
const POR_PROOF_TYPES = (process.env.POR_PROOF_TYPES || 'proof-of-reserves,reserves,por,risc0')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
const POR_SHOW_ALL = (process.env.POR_SHOW_ALL ?? '1') !== '0'
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 60_000)
// The verified-agent scan is ~N get_agent calls, so cache it for much longer
// than the cheap single-shot endpoints.
const DIRECTORY_TTL_MS = Number(process.env.DIRECTORY_TTL_MS || 300_000)
const ZKVERIFY_EXPLORER = process.env.ZKVERIFY_EXPLORER || 'https://zkverify-testnet.subscan.io'
const BASESCAN_URL = process.env.BASESCAN_URL || 'https://sepolia.basescan.org'
const MARKETPLACE_URL = process.env.MARKETPLACE_URL || 'https://agent-registry.horizenlabs.io'
const NETWORK = process.env.POR_NETWORK || 'Base Sepolia'
const PIPELINE_URL = process.env.PIPELINE_URL || ''

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------------------------------------------------------------------------
// MCP plumbing
// ---------------------------------------------------------------------------

let rpcId = 1

const isRateLimit = (s) => /rate.?limit|too many requests/i.test(s || '')

/**
 * Call an MCP tool and return its parsed `--- structured ---` JSON payload.
 * The registry caps us at 240 req/min; a cold directory scan can brush that,
 * so retry with exponential backoff on HTTP 429 / 5xx and rate-limit tool errors.
 */
async function mcpTool(name, args = {}) {
  const MAX_ATTEMPTS = 6
  let lastErr
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (attempt > 0) await sleep(Math.min(8000, 600 * 2 ** (attempt - 1)) + attempt * 120)
    let res
    try {
      res = await fetch(REGISTRY_MCP_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: rpcId++,
          method: 'tools/call',
          params: { name, arguments: args },
        }),
      })
    } catch (e) {
      lastErr = new Error(`MCP ${name} fetch failed: ${e.message}`)
      continue
    }
    if (res.status === 429 || res.status >= 500) {
      lastErr = new Error(`MCP ${name} HTTP ${res.status}`)
      continue
    }
    if (!res.ok) throw new Error(`MCP ${name} HTTP ${res.status}`)
    const json = await res.json()
    if (json.error) {
      if (isRateLimit(json.error.message)) {
        lastErr = new Error(`MCP ${name} rate limited`)
        continue
      }
      throw new Error(`MCP ${name} error: ${json.error.message || JSON.stringify(json.error)}`)
    }
    const result = json.result
    if (result?.isError) {
      const t = result.content?.map((c) => c.text).join('\n') || 'tool error'
      if (isRateLimit(t)) {
        lastErr = new Error(`MCP ${name} rate limited`)
        continue
      }
      throw new Error(`MCP ${name} tool error: ${t}`)
    }
    const text = result?.content?.find((c) => c.type === 'text')?.text || ''
    return { structured: parseStructured(text), text }
  }
  throw lastErr || new Error(`MCP ${name} failed`)
}

/** Each tool returns human text followed by `--- structured ---\n{json}`. */
function parseStructured(text) {
  const marker = '--- structured ---'
  const i = text.indexOf(marker)
  const blob = i >= 0 ? text.slice(i + marker.length) : text
  try {
    return JSON.parse(blob.trim())
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Tiny TTL cache with in-flight de-duplication
// ---------------------------------------------------------------------------

const cache = new Map() // key -> { at, value }
const inflight = new Map() // key -> Promise

async function cached(key, ttl, fn) {
  const hit = cache.get(key)
  const now = Date.now()
  if (hit && now - hit.at < ttl) return hit.value
  if (inflight.has(key)) return inflight.get(key)
  const p = (async () => {
    try {
      const value = await fn()
      cache.set(key, { at: Date.now(), value })
      return value
    } finally {
      inflight.delete(key)
    }
  })()
  inflight.set(key, p)
  return p
}

/** Run async tasks with bounded concurrency (keeps us under the MCP rate limit). */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length)
  let next = 0
  async function worker() {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i], i)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

// ---------------------------------------------------------------------------
// Domain logic
// ---------------------------------------------------------------------------

const norm = (s) => String(s || '').trim().toLowerCase()

/** Does an agent detail object look like a proof-of-reserves agent? */
function isPorAgent(detail) {
  if (!detail) return false
  const types = new Set()
  const w = detail.whatThisProves
  if (w?.proofType) types.add(norm(w.proofType))
  for (const t of w?.proofTypes || []) types.add(norm(t))
  if (detail.agent?.proofType) types.add(norm(detail.agent.proofType))
  for (const r of detail.receipts?.items || []) if (r.proofType) types.add(norm(r.proofType))
  return POR_PROOF_TYPES.some((t) => types.has(t))
}

/** Fetch every verified agent (paged), structured. */
async function fetchAllVerified() {
  const out = []
  let offset = 0
  for (let page = 0; page < 20; page++) {
    const { structured } = await mcpTool('list_verified_agents', { limit: 100, offset })
    const agents = structured?.agents || []
    out.push(...agents)
    const total = structured?.matched ?? structured?.totalVerified ?? out.length
    offset += agents.length
    if (agents.length === 0 || out.length >= total) break
  }
  return out
}

async function getAgentDetail(agentId) {
  return cached(`agent:${agentId}`, CACHE_TTL_MS, async () => {
    const { structured } = await mcpTool('get_agent', { agentId })
    return structured
  })
}

/** Registry overview, enriched with whether a PoR proof type is live. Cached. */
async function getOverview() {
  return cached('overview', CACHE_TTL_MS, async () => {
    const { structured } = await mcpTool('get_registry_overview')
    const proofTypes = structured?.proofTypes?.types || []
    const porTypeLive = proofTypes.some((t) => POR_PROOF_TYPES.includes(norm(t.proofType)))
    return {
      ...structured,
      porProofTypes: POR_PROOF_TYPES,
      porTypeLive,
      explorer: ZKVERIFY_EXPLORER,
      baseExplorer: BASESCAN_URL,
      marketplace: MARKETPLACE_URL,
    }
  })
}

/**
 * The verified PoR directory: every agent with ≥1 PoR-typed receipt.
 * Returns { mode, agents, totalVerified, porCount }.
 *   mode = 'por' | 'fallback-all'
 */
async function getDirectory() {
  return cached('directory', DIRECTORY_TTL_MS, async () => {
    const verified = await fetchAllVerified()

    // 1) If no PoR proof type is registered on the marketplace yet, no agent can
    //    possibly hold a PoR receipt — so skip the expensive per-agent scan
    //    (one get_agent per verified agent) entirely and fall back immediately.
    let porTypeLive = false
    try {
      porTypeLive = (await getOverview()).porTypeLive
    } catch {
      /* if overview is unavailable, treat PoR as not-live and fall back */
    }
    if (!porTypeLive) {
      return POR_SHOW_ALL
        ? { mode: 'fallback-all', agents: verified, totalVerified: verified.length, porCount: 0 }
        : { mode: 'por', agents: [], totalVerified: verified.length, porCount: 0 }
    }

    // 2) PoR type is live — enrich each verified agent and keep those whose
    //    receipts use a PoR proof type (i.e. submitted ≥1 PoR proof).
    const details = await mapLimit(verified, 4, (a) => getAgentDetail(a.agentId).catch(() => null))
    const por = []
    verified.forEach((row, i) => {
      if (isPorAgent(details[i])) por.push({ ...row, proofTypes: porTypesOf(details[i]) })
    })

    if (por.length === 0 && POR_SHOW_ALL) {
      return { mode: 'fallback-all', agents: verified, totalVerified: verified.length, porCount: 0 }
    }
    return { mode: 'por', agents: por, totalVerified: verified.length, porCount: por.length }
  })
}

function porTypesOf(detail) {
  const w = detail?.whatThisProves
  return [...new Set([...(w?.proofTypes || []), ...(detail?.receipts?.items || []).map((r) => r.proofType)])].filter(Boolean)
}

/**
 * Live submission pipeline. Pipeline state (Kurier → zkVerify → attestation relay
 * → on-chain recordValidation) is owned by the *submitter*, not the read-only
 * registry — so it comes from a separate PIPELINE_URL status source (the mock's
 * /mock/pipeline locally; a real submitter's status API in prod). Unset → disabled.
 */
async function getPipeline() {
  if (!PIPELINE_URL) return { enabled: false, jobs: [] }
  return cached('pipeline', 2000, async () => {
    try {
      const res = await fetch(PIPELINE_URL, { headers: { accept: 'application/json' } })
      if (!res.ok) return { enabled: true, jobs: [], error: `pipeline HTTP ${res.status}` }
      const data = await res.json()
      const jobs = Array.isArray(data) ? data : data.jobs || []
      return { enabled: true, jobs, explorer: ZKVERIFY_EXPLORER, baseExplorer: BASESCAN_URL }
    } catch (e) {
      return { enabled: true, jobs: [], error: e.message }
    }
  })
}

function detailToRow(detail) {
  const a = detail.agent || {}
  const r = detail.receipts || {}
  return {
    agentId: a.agentId,
    name: a.name,
    type: a.type || null,
    receipts: r.count ?? 0,
    passRatePct: r.passRatePct ?? null,
    slaPct: null,
    lastActivity: r.items?.[0]?.timestamp ?? null,
    proofTypes: porTypesOf(detail),
  }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

function send(res, status, body) {
  const data = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(data)
}

const routes = [
  {
    method: 'GET',
    pattern: /^\/api\/health$/,
    handler: async () => ({
      ok: true,
      registry: REGISTRY_MCP_URL,
      network: NETWORK,
      baseExplorer: BASESCAN_URL,
      marketplace: MARKETPLACE_URL,
      pipeline: PIPELINE_URL ? PIPELINE_URL : false,
      porProofTypes: POR_PROOF_TYPES,
      showAllFallback: POR_SHOW_ALL,
    }),
  },
  {
    method: 'GET',
    pattern: /^\/api\/overview$/,
    handler: () => getOverview(),
  },
  {
    method: 'GET',
    pattern: /^\/api\/proof-types$/,
    handler: () => cached('proof-types', CACHE_TTL_MS, async () => (await mcpTool('list_proof_types')).structured),
  },
  {
    method: 'GET',
    pattern: /^\/api\/agents$/,
    handler: async () => {
      const dir = await getDirectory()
      return {
        ...dir,
        network: NETWORK,
        explorer: ZKVERIFY_EXPLORER,
        baseExplorer: BASESCAN_URL,
        marketplace: MARKETPLACE_URL,
      }
    },
  },
  {
    method: 'GET',
    pattern: /^\/api\/pipeline$/,
    handler: () => getPipeline(),
  },
  {
    method: 'GET',
    pattern: /^\/api\/agents\/([^/]+)$/,
    handler: async (m) => {
      const detail = await getAgentDetail(decodeURIComponent(m[1]))
      if (!detail) throw Object.assign(new Error('agent not found'), { status: 404 })
      let stats = null
      try {
        const id = detail.agent?.agentId
        stats = await cached(`stats:${id}`, CACHE_TTL_MS, async () =>
          (await mcpTool('get_validation_stats', { agentId: id })).structured,
        )
      } catch {
        /* stats are best-effort */
      }
      return {
        ...detail,
        stats,
        isPor: isPorAgent(detail),
        network: NETWORK,
        explorer: ZKVERIFY_EXPLORER,
        baseExplorer: BASESCAN_URL,
        marketplace: MARKETPLACE_URL,
      }
    },
  },
]

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const route = routes.find((r) => r.method === req.method && r.pattern.test(url.pathname))
  if (!route) return send(res, 404, { error: 'not found' })
  try {
    const m = url.pathname.match(route.pattern)
    const body = await route.handler(m, url)
    send(res, 200, body)
  } catch (err) {
    const status = err?.status || 502
    console.error(`[api] ${url.pathname} -> ${status}: ${err?.message}`)
    send(res, status, { error: err?.message || 'upstream error' })
  }
})

server.listen(PORT, () => {
  console.log(`[por-registry] read-proxy on :${PORT} -> ${REGISTRY_MCP_URL}`)
  console.log(`[por-registry] PoR proof types: ${POR_PROOF_TYPES.join(', ')}`)
  console.log(`[por-registry] fallback-to-all-verified: ${POR_SHOW_ALL}`)
})
