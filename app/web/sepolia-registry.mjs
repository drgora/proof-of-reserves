// Base Sepolia read adapter — a drop-in replacement for server.mjs when your
// agent lives on the *testnet* marketplace.
//
// Why this exists: the public registry MCP at agent-registry.horizenlabs.io is
// Base *mainnet*-only (no network selector), so it can't see agents registered
// on the Base Sepolia contracts. This shim serves the same clean `/api` surface
// the verifier (POR_REGISTRY_URL -> /api/agents/:id -> /agent/owner) and the
// Vite dev proxy already consume, but sources identity/ownership straight from
// Base Sepolia on-chain reads (IdentityRegistry.ownerOf). No MCP, zero deps.
//
// Faithful to real testnet state for the part that matters for auth (owner).
// Receipts are stubbed to 0 for now (accurate until a PoR validation is recorded
// on-chain); decoding ValidationRegistry is a later extension — see NOTE below.
//
// Env:
//   PORT                  default 8090   — same as server.mjs so it's a drop-in
//   BASE_SEPOLIA_RPC_URL  default https://sepolia.base.org
//   IDENTITY_REGISTRY     default 0x8004A818BFB912233c491871b3d84c89A494BD9e (ERC-721 AgentCards)
//   POR_AGENT_IDS         comma list of agent ids (hex 0x16ec or decimal 5868) shown in the directory
//   POR_PROOF_TYPES       parity with server.mjs (default proof-of-reserves,reserves,por,risc0)
//   POR_NETWORK           display label (default "Base Sepolia")
//   ZKVERIFY_EXPLORER / BASESCAN_URL / MARKETPLACE_URL — same defaults as server.mjs

import http from 'node:http'

const PORT = Number(process.env.PORT || 8090)
const RPC_URL = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org'
const IDENTITY_REGISTRY =
  process.env.IDENTITY_REGISTRY || '0x8004A818BFB912233c491871b3d84c89A494BD9e'
const POR_AGENT_IDS = (process.env.POR_AGENT_IDS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
const POR_PROOF_TYPES = (process.env.POR_PROOF_TYPES || 'proof-of-reserves,reserves,por,risc0')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
const NETWORK = process.env.POR_NETWORK || 'Base Sepolia'
const ZKVERIFY_EXPLORER = process.env.ZKVERIFY_EXPLORER || 'https://zkverify-testnet.subscan.io'
const BASESCAN_URL = process.env.BASESCAN_URL || 'https://sepolia.basescan.org'
const MARKETPLACE_URL = process.env.MARKETPLACE_URL || 'https://agent-registry.horizenlabs.io'

// --- chain reads -----------------------------------------------------------

let rpcId = 1
async function ethCall(to, data) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: rpcId++,
      method: 'eth_call',
      params: [{ to, data }, 'latest'],
    }),
  })
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`)
  const j = await res.json()
  if (j.error) throw Object.assign(new Error(j.error.message || 'eth_call reverted'), { revert: true })
  return j.result || '0x'
}

/** Accept "0x16ec" (hex) or "5868" (decimal) -> 32-byte zero-padded tokenId hex. */
function toTokenId(agentId) {
  const n = BigInt(agentId) // BigInt parses both 0x-hex and decimal
  return n.toString(16).padStart(64, '0')
}
/** Canonical agent id the marketplace uses: lowercase 0x-hex of the token id. */
function toHexId(agentId) {
  return '0x' + BigInt(agentId).toString(16)
}

const SEL_OWNER_OF = '6352211e' // ownerOf(uint256)
const SEL_TOKEN_URI = 'c87b56dd' // tokenURI(uint256)

async function ownerOf(agentId) {
  const r = await ethCall(IDENTITY_REGISTRY, '0x' + SEL_OWNER_OF + toTokenId(agentId))
  if (!r || r === '0x' || /^0x0{64}$/.test(r)) return null
  return '0x' + r.slice(-40)
}

/** Best-effort display name via ERC-721 tokenURI -> AgentCard JSON .name. */
async function tokenName(agentId) {
  try {
    const r = await ethCall(IDENTITY_REGISTRY, '0x' + SEL_TOKEN_URI + toTokenId(agentId))
    const uri = decodeAbiString(r)
    if (!uri) return null
    let json = null
    if (uri.startsWith('data:')) {
      const comma = uri.indexOf(',')
      const payload = uri.slice(comma + 1)
      const raw = uri.slice(0, comma).includes('base64')
        ? Buffer.from(payload, 'base64').toString('utf8')
        : decodeURIComponent(payload)
      json = JSON.parse(raw)
    } else if (/^https?:\/\//.test(uri)) {
      const res = await fetch(uri, { signal: AbortSignal.timeout(4000) })
      if (res.ok) json = await res.json()
    }
    return json?.name || null
  } catch {
    return null
  }
}

/** Decode a single dynamic `string` ABI return (offset|length|data). */
function decodeAbiString(hex) {
  if (!hex || hex.length < 130) return null
  const body = hex.slice(2)
  const len = parseInt(body.slice(64, 128), 16)
  if (!len) return null
  const bytes = Buffer.from(body.slice(128, 128 + len * 2), 'hex')
  return bytes.toString('utf8')
}

// --- structured shapes (mirror server.mjs / the MCP get_agent output) -------

async function getAgentDetail(agentId) {
  const owner = await ownerOf(agentId) // throws {revert} if token doesn't exist
  if (!owner) return null
  const hexId = toHexId(agentId)
  const name = (await tokenName(agentId)) || `Agent #${hexId}`
  return {
    agentId: hexId,
    network: NETWORK,
    agent: {
      agentId: hexId,
      name,
      description: 'No description available',
      owner,
      active: true,
      zkVerified: false,
      proofType: null,
    },
    whatThisProves: { proofType: null, proofTypes: [], summary: '', claims: [] },
    // NOTE: receipts are on ValidationRegistry (0x75a7f712…71BC); decoding them
    // is a later extension. 0 is accurate until a PoR validation is recorded.
    receipts: { count: 0, validated: 0, failed: 0, passRatePct: null, returned: 0, items: [] },
    reputation: { reviewCount: 0, avgScore: null, feedback: [] },
  }
}

function detailToRow(detail) {
  const a = detail.agent || {}
  return {
    agentId: a.agentId,
    name: a.name,
    type: null,
    receipts: detail.receipts?.count ?? 0,
    passRatePct: detail.receipts?.passRatePct ?? null,
    slaPct: null,
    lastActivity: null,
    proofTypes: [],
  }
}

// --- HTTP (routes mirror server.mjs so this is a drop-in) -------------------

function send(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(body))
}

const routes = [
  {
    pattern: /^\/api\/health$/,
    handler: async () => ({
      ok: true,
      registry: `onchain:${RPC_URL}`,
      identityRegistry: IDENTITY_REGISTRY,
      network: NETWORK,
      baseExplorer: BASESCAN_URL,
      marketplace: MARKETPLACE_URL,
      porProofTypes: POR_PROOF_TYPES,
      porAgentIds: POR_AGENT_IDS,
    }),
  },
  {
    pattern: /^\/api\/overview$/,
    // Shape must match the `Overview` type in api.ts — the Directory reads
    // o.agents.withReceipts and o.receipts.{count,validated} WITHOUT optional
    // chaining, so these objects must exist. This adapter is not a full-registry
    // indexer (that's what the MCP was), so the registry-wide tiles are 0: we
    // only know the allowlisted agents, and receipts aren't decoded yet.
    handler: async () => ({
      network: NETWORK,
      source: 'base-sepolia-onchain',
      agents: { totalRegistered: 0, withReceipts: 0 },
      receipts: { count: 0, validated: 0, failed: 0 },
      proofTypes: { count: 0, types: [] },
      porProofTypes: POR_PROOF_TYPES,
      porTypeLive: false, // gateway proof-type list isn't read on-chain here; use allowlist mode
      explorer: ZKVERIFY_EXPLORER,
      baseExplorer: BASESCAN_URL,
      marketplace: MARKETPLACE_URL,
    }),
  },
  {
    pattern: /^\/api\/agents$/,
    handler: async () => {
      const details = await Promise.all(
        POR_AGENT_IDS.map((id) => getAgentDetail(id).catch(() => null)),
      )
      const agents = details.filter(Boolean).map(detailToRow)
      return {
        mode: 'allowlist',
        agents,
        totalVerified: agents.length,
        porCount: agents.length,
        network: NETWORK,
        explorer: ZKVERIFY_EXPLORER,
        baseExplorer: BASESCAN_URL,
        marketplace: MARKETPLACE_URL,
      }
    },
  },
  {
    pattern: /^\/api\/agents\/([^/]+)$/,
    handler: async (m) => {
      let detail
      try {
        detail = await getAgentDetail(decodeURIComponent(m[1]))
      } catch (e) {
        if (e.revert) detail = null
        else throw e
      }
      if (!detail) throw Object.assign(new Error('agent not found'), { status: 404 })
      return {
        ...detail,
        stats: null,
        isPor: true,
        network: NETWORK,
        explorer: ZKVERIFY_EXPLORER,
        baseExplorer: BASESCAN_URL,
        marketplace: MARKETPLACE_URL,
      }
    },
  },
]

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`)
    if (req.method !== 'GET') return send(res, 404, { error: 'not found' })
    const route = routes.find((r) => r.pattern.test(url.pathname))
    if (!route) return send(res, 404, { error: 'not found' })
    try {
      const body = await route.handler(url.pathname.match(route.pattern), url)
      send(res, 200, body)
    } catch (err) {
      const status = err?.status || 502
      console.error(`[sepolia-api] ${url.pathname} -> ${status}: ${err?.message}`)
      send(res, status, { error: err?.message || 'upstream error' })
    }
  })
  .listen(PORT, () => {
    console.log(`[sepolia-registry] read-proxy on :${PORT} -> ${IDENTITY_REGISTRY} @ ${RPC_URL}`)
    console.log(`[sepolia-registry] network: ${NETWORK}`)
    if (POR_AGENT_IDS.length) console.log(`[sepolia-registry] directory allowlist: ${POR_AGENT_IDS.join(', ')}`)
  })
