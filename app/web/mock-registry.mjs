// Interactive mock of the HL Agent Registry — for local E2E testing of the whole
// loop: proof creation (por-risc0 `host`) → submission (`por_verify` → Kurier) →
// UI (read-proxy → this mock). One stateful server plays TWO roles:
//
//   1. Registry read MCP  — the slice server.mjs calls (list_verified_agents,
//      get_agent, get_registry_overview, get_validation_stats, list_proof_types),
//      served from MUTABLE state at POST /api/mcp.
//   2. Kurier stand-in    — the exact endpoints por_verify hits
//      (POST /submit-proof/:key, GET /job-status/:key/:jobId), so the REAL
//      por_verify binary submits its REAL receipt here with no code changes.
//
// The bridge: when a submitted receipt reaches "Aggregated", the mock AUTO-RECORDS
// a validation on the prover's agent — which then shows up in the directory UI.
// This collapses the marketplace's on-chain steps (attestation relay +
// ValidationGateway.recordValidation), which need Base Sepolia + viem and so
// can't run locally. Everything else is faithful.
//
// ── E2E (four terminals) ────────────────────────────────────────────────────
//   npm run mock                                   # this — MCP :8091 + Kurier :8091
//   npm run server:mock                            # read-proxy :8090
//   npm run dev                                    # Vite :5173  → open it
//   # then, from por-risc0/, submit a REAL proof to the mock Kurier:
//   KURIER_API_KEY=mock KURIER_API_URL=http://127.0.0.1:8091 \
//     POR_ALLOW_DEBUG=1 POR_REQUIRED_THRESHOLD=1 ./target/release/por_verify
//   # → a validation lands on the "self" prover agent; refresh the UI to see it.
//
// Zero dependencies: Node 22 `http` + `crypto`.
//
// Env:
//   MOCK_PORT           default 8091
//   MOCK_POR_LIVE       "1" (default) — advertise `risc0` as a live proof type so
//                       the proxy runs the real por-mode scan; "0" → preview mode.
//   MOCK_SELF_AGENT_ID  default 0xF00DBABE… — the agent Kurier submissions attribute
//   MOCK_SELF_AGENT_NAME  to. Starts UNVERIFIED (0 receipts, hidden) and appears in
//                       the directory once its first proof is recorded.
//   MOCK_KURIER_POLLS   default 0 — intermediate job-status polls before "Aggregated"
//                       (0 = terminal on the first poll; raise to watch the lifecycle).

import http from 'node:http'
import crypto from 'node:crypto'

const PORT = Number(process.env.MOCK_PORT || 8091)
const POR_LIVE = (process.env.MOCK_POR_LIVE ?? '1') !== '0'
const NETWORK = 'base-sepolia'
const SELF_ID = (process.env.MOCK_SELF_AGENT_ID || '0xf00dbabe0000000000000000000000000000f00d').toLowerCase()
const SELF_NAME = process.env.MOCK_SELF_AGENT_NAME || 'Local Reserve Prover (this node)'
const KURIER_POLLS = Math.max(0, Number(process.env.MOCK_KURIER_POLLS || 0))

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex')

/** Deterministic-looking 32-byte hex hash from a seed (not crypto — just fixtures). */
function fakeHash(seed) {
  let s = ''
  for (let i = 0; i < 64; i++) s += ((seed.charCodeAt(i % seed.length) * 31 + i * 7) % 16).toString(16)
  return '0x' + s
}

const hoursAgo = (h) => new Date(Date.now() - h * 3_600_000).toISOString()

/** A run of quality receipts; the first `failed` (most recent) are marked failed. */
function makeReceipts(agentId, proofType, { count, failed, curve, constraintCount, hoursStep = 9 }) {
  const items = []
  for (let i = 0; i < count; i++) {
    const isFail = i < failed
    items.push({
      id: `${agentId}-r${count - i}`,
      status: isFail ? 'failed' : 'validated',
      scorePct: isFail ? 60 + ((i * 7) % 30) : 100,
      proofType,
      timestamp: hoursAgo(i * hoursStep + 2),
      zkVerify: {
        txHash: fakeHash(`${agentId}:tx:${i}`),
        blockHash: fakeHash(`${agentId}:blk:${i}`),
        curve,
        constraintCount,
      },
    })
  }
  return items
}

/** Decode the ETH block_hash from a risc0 journal (publicSignals): the leading
 *  [u8;32] is serialized as 32 little-endian u32 words, so the low byte of each
 *  word (first byte of each 4-byte word) is the block-hash byte. Best-effort. */
function decodeBlockHash(publicSignalsHex) {
  try {
    const h = String(publicSignalsHex || '').replace(/^0x/, '')
    if (h.length < 32 * 8) return null
    let out = ''
    for (let i = 0; i < 32; i++) out += h.substr(i * 8, 2)
    return /^[0-9a-fA-F]{64}$/.test(out) ? '0x' + out : null
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Seed dataset — starting state (POST /mock/reset restores this)
// ---------------------------------------------------------------------------

const SEED_AGENTS = [
  {
    agentId: '0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d',
    name: 'Aegis Reserve Prover',
    type: 'trading',
    owner: '0xA11CE0000000000000000000000000000000AEGD',
    description:
      'Autonomous market-making agent that proves it controls a funded L1 wallet holding ≥ threshold ETH — balance and address never revealed. Risc0 receipt verified on zkVerify.',
    skills: ['market-making', 'proof-of-reserves', 'risk-management'],
    domains: ['defi', 'trading'],
    pricing: '0.25% of notional',
    website: 'https://aegis.example',
    active: true,
    proofType: 'risc0',
    porTypes: ['risc0', 'proof-of-reserves'],
    summary:
      'Each receipt proves: an EIP-1186 account proof verifies under the block header state root, balance ≥ threshold, and in-circuit secp256k1 ownership of the address — with balance and address kept private.',
    reputation: { reviewCount: 12, avgScore: 96, feedback: [] },
    stats: { slaPct: 100, slaLast7d: { bpsSum: 336, total: 336 } },
    receipts: { count: 47, failed: 0, curve: 'risc0-succinct', constraintCount: 1_048_576 },
  },
  {
    agentId: '0x9f8e7d6c5b4a3928176554433221100ffeeddccb',
    name: 'Helios Vault Agent',
    type: 'custody',
    owner: '0xB0B0000000000000000000000000000000HELIOS',
    description:
      'Custody agent proving continuous solvency of a treasury wallet above a required reserve threshold, on a fixed cadence.',
    skills: ['custody', 'proof-of-reserves', 'treasury'],
    domains: ['custody', 'defi'],
    pricing: 'flat 500 USDC / mo',
    website: 'https://helios.example',
    active: true,
    proofType: 'risc0',
    porTypes: ['risc0', 'proof-of-reserves'],
    summary:
      'Proves reserves ≥ threshold at each checkpoint against a TLSNotary-attested block header, without disclosing the treasury balance or address.',
    reputation: { reviewCount: 5, avgScore: 92, feedback: [] },
    stats: { slaPct: 98, slaLast7d: { bpsSum: 329, total: 336 } },
    receipts: { count: 21, failed: 1, curve: 'risc0-succinct', constraintCount: 1_048_576 },
  },
  {
    agentId: '0x5555444433332222111100009999888877776666',
    name: 'Groth Quant Bot',
    type: 'trading',
    owner: '0xC0FFEE000000000000000000000000000000QUANT',
    description:
      'Statistical-arbitrage agent publishing Groth16 proofs of correct strategy execution. Not a proof-of-reserves agent.',
    skills: ['arbitrage', 'strategy-execution'],
    domains: ['trading'],
    pricing: '0.1% of notional',
    website: null,
    active: true,
    proofType: 'groth16',
    porTypes: ['groth16'],
    summary: 'Proves the published trade set is a correct execution of the committed strategy.',
    reputation: { reviewCount: 3, avgScore: 88, feedback: [] },
    stats: { slaPct: 95, slaLast7d: { bpsSum: 319, total: 336 } },
    receipts: { count: 31, failed: 2, curve: 'bn254', constraintCount: 262_144 },
  },
  {
    agentId: '0xdeadbeef00112233445566778899aabbccddeeff',
    name: 'EZKL Vision Oracle',
    type: 'oracle',
    owner: '0xD00D000000000000000000000000000000VISION',
    description:
      'zkML oracle proving correct ONNX model inference over signed image inputs. Not a proof-of-reserves agent.',
    skills: ['zkml', 'inference', 'oracle'],
    domains: ['ai', 'oracle'],
    pricing: '2 USDC / inference',
    website: 'https://vision.example',
    active: false,
    proofType: 'ezkl',
    porTypes: ['ezkl'],
    summary: 'Proves the returned classification is the committed model run on the committed input.',
    reputation: { reviewCount: 0, avgScore: 0, feedback: [] },
    stats: { slaPct: 74, slaLast7d: { bpsSum: 249, total: 336 } },
    receipts: { count: 8, failed: 3, curve: 'kzg-bn254', constraintCount: 524_288 },
  },
]

// The prover's own agent — attribution target for Kurier submissions. Starts with
// NO receipts, so it's registered-but-unverified (hidden from the directory) until
// its first real proof is recorded, which is exactly the E2E moment to watch for.
const SELF_SPEC = {
  agentId: SELF_ID,
  name: SELF_NAME,
  type: 'trading',
  owner: '0x0000000000000000000000000000000000000000',
  description:
    'Your local proof-of-reserves prover. Registered but not yet verified — submit a proof via por_verify (pointed at this mock) and it appears here with a receipt.',
  skills: ['proof-of-reserves', 'self-custody'],
  domains: ['defi'],
  pricing: null,
  website: null,
  active: true,
  proofType: 'risc0',
  porTypes: ['risc0', 'proof-of-reserves'],
  summary:
    'Proves control of a funded wallet holding ≥ threshold ETH under a TLSNotary-attested block header — balance and address kept private.',
  reputation: { reviewCount: 0, avgScore: 0, feedback: [] },
  stats: { slaPct: 100, slaLast7d: { bpsSum: 0, total: 0 } },
  receipts: { count: 0, failed: 0, curve: 'risc0-succinct', constraintCount: 1_048_576 },
}

const UNVERIFIED_COUNT = 3 // registered-but-not-verified padding for totalRegistered

// ---------------------------------------------------------------------------
// Mutable state
// ---------------------------------------------------------------------------

let state

function buildAgent(spec) {
  const a = { ...spec, receiptItems: makeReceipts(spec.agentId, spec.proofType, spec.receipts) }
  recompute(a)
  return a
}

/** Recompute derived receipt stats after any mutation. */
function recompute(a) {
  const items = a.receiptItems
  a._validated = items.filter((r) => r.status === 'validated').length
  a._failed = items.length - a._validated
  a._passRatePct = items.length ? Math.round((a._validated / items.length) * 100) : null
  a._lastActivity = items[0]?.timestamp ?? null
}

function seedState() {
  const agents = new Map()
  for (const spec of SEED_AGENTS) agents.set(spec.agentId.toLowerCase(), buildAgent(spec))
  agents.set(SELF_ID, buildAgent(SELF_SPEC)) // starts with 0 receipts → unverified
  state = { agents, jobs: new Map(), targetId: SELF_ID, jobSeq: 0 }
}
seedState()

const getAgent = (id) => state.agents.get(String(id || '').toLowerCase())
const allAgents = () => [...state.agents.values()]
/** An agent is discoverable/"verified" once it has recorded ≥1 validation. */
const verifiedAgents = () => allAgents().filter((a) => a.receiptItems.length > 0)

/**
 * Record a validation receipt on an agent (creating a bare agent if needed).
 * Returns the new receipt. This is the mock's stand-in for the marketplace's
 * on-chain ValidationGateway.recordValidation.
 */
function recordValidation(agentId, { fingerprint, proofType = 'risc0', ethBlockHash = null }) {
  const id = String(agentId || state.targetId).toLowerCase()
  let a = state.agents.get(id)
  if (!a) {
    a = buildAgent({ ...SELF_SPEC, agentId: id, name: `Agent ${id.slice(0, 10)}…`, receipts: { count: 0, failed: 0, curve: 'risc0-succinct', constraintCount: 1_048_576 } })
    state.agents.set(id, a)
  }
  const fp = fingerprint || sha256(`${id}:${a.receiptItems.length}:${Date.now()}`)
  const txHash = '0x' + fp.slice(0, 64)
  const blockHash = '0x' + sha256(fp + ':zkv-block').slice(0, 64)
  const receipt = {
    id: `val-${fp.slice(0, 12)}`,
    status: 'validated',
    scorePct: 100,
    proofType,
    timestamp: new Date().toISOString(),
    zkVerify: { txHash, blockHash, curve: 'risc0-succinct', constraintCount: 1 << 20 },
    ethBlockHash, // extra: the ETH block the reserves were proven against (UI ignores unknown fields)
  }
  a.receiptItems.unshift(receipt)
  if (!a.porTypes?.includes(proofType)) a.porTypes = [...new Set([...(a.porTypes || []), proofType])]
  recompute(a)
  console.log(`[mock] recorded ${proofType} validation on ${id} (now ${a.receiptItems.length} receipts)` +
    (ethBlockHash ? ` — reserves proven at ETH block ${ethBlockHash.slice(0, 12)}…` : ''))
  return { receipt, txHash, blockHash }
}

// ---------------------------------------------------------------------------
// Structured payloads (shapes match what server.mjs / the UI read)
// ---------------------------------------------------------------------------

const REGISTERED_RETURN = 12 // how many receipts get_agent returns (latest N)

const listRow = (a) => ({
  agentId: a.agentId,
  name: a.name,
  type: a.type,
  receipts: a.receiptItems.length,
  passRatePct: a._passRatePct,
  slaPct: a.stats.slaPct,
  lastActivity: a._lastActivity,
  proofTypes: a.porTypes,
})

function agentDetail(a) {
  const items = a.receiptItems.slice(0, REGISTERED_RETURN)
  return {
    agentId: a.agentId,
    network: NETWORK,
    agent: {
      agentId: a.agentId,
      name: a.name,
      description: a.description,
      skills: a.skills,
      domains: a.domains,
      pricing: a.pricing,
      zkVerified: a.receiptItems.length > 0,
      proofType: a.proofType,
      website: a.website,
      owner: a.owner,
      active: a.active,
    },
    whatThisProves: { proofType: a.proofType, proofTypes: a.porTypes, summary: a.summary, claims: [] },
    receipts: {
      count: a.receiptItems.length,
      validated: a._validated,
      failed: a._failed,
      passRatePct: a._passRatePct,
      returned: items.length,
      items,
    },
    reputation: a.reputation,
  }
}

const PROOF_TYPE_CATALOG = [
  { proofType: 'risc0', name: 'RISC Zero zkVM', description: 'zkVM STARK receipts (Risc0 v3.0).', keyCount: 4 },
  { proofType: 'groth16', name: 'Groth16', description: 'Groth16 SNARK over BN254.', keyCount: 6 },
  { proofType: 'ezkl', name: 'EZKL', description: 'zkML proofs for ONNX model inference.', keyCount: 2 },
]

function registryOverview() {
  const verified = verifiedAgents()
  const receiptCount = verified.reduce((n, a) => n + a.receiptItems.length, 0)
  const validated = verified.reduce((n, a) => n + a._validated, 0)
  const failed = receiptCount - validated
  const types = POR_LIVE ? PROOF_TYPE_CATALOG : PROOF_TYPE_CATALOG.filter((t) => t.proofType !== 'risc0')
  const top = [...verified]
    .sort((a, b) => b.receiptItems.length - a.receiptItems.length)
    .slice(0, 5)
    .map(listRow)
  return {
    network: NETWORK,
    agents: { totalRegistered: allAgents().length + UNVERIFIED_COUNT, withReceipts: verified.length },
    receipts: { count: receiptCount, validated, failed },
    proofTypes: { count: types.length, types },
    topAgentsByReceipts: top,
  }
}

// ---------------------------------------------------------------------------
// MCP tool dispatch (read side)
// ---------------------------------------------------------------------------

function callTool(name, args = {}) {
  switch (name) {
    case 'list_verified_agents': {
      const limit = Number(args.limit ?? 100)
      const offset = Number(args.offset ?? 0)
      const all = verifiedAgents().map(listRow)
      const page = all.slice(offset, offset + limit)
      return {
        human: `${all.length} verified agents (showing ${page.length} from offset ${offset}).`,
        structured: { agents: page, matched: all.length, totalVerified: all.length, limit, offset },
      }
    }
    case 'get_agent': {
      const a = getAgent(args.agentId)
      // Missing agent → success with a null structured payload; server.mjs's
      // `if (!detail) throw …404` branch expects this falsy structured.
      if (!a) return { human: `Agent ${args.agentId} not found.`, structured: null }
      return { human: `Agent ${a.name} (${a.agentId}).`, structured: agentDetail(a) }
    }
    case 'get_registry_overview':
      return { human: 'Registry overview.', structured: registryOverview() }
    case 'get_validation_stats': {
      const a = getAgent(args.agentId)
      if (!a) return { human: `Agent ${args.agentId} not found.`, structured: null }
      return {
        human: `Validation stats for ${a.name}.`,
        structured: { agentId: a.agentId, slaPct: a.stats.slaPct, slaLast7d: a.stats.slaLast7d },
      }
    }
    case 'list_proof_types': {
      const types = registryOverview().proofTypes.types
      return { human: `${types.length} proof types.`, structured: { count: types.length, types } }
    }
    default:
      throw Object.assign(new Error(`unknown tool: ${name}`), { unknownTool: true })
  }
}

const TOOLS = [
  { name: 'list_verified_agents', description: 'List verified agents (paged).' },
  { name: 'get_agent', description: 'Full agent profile by agentId.' },
  { name: 'get_registry_overview', description: 'Registry totals + proof types.' },
  { name: 'get_validation_stats', description: 'SLA / validation stats for an agent.' },
  { name: 'list_proof_types', description: 'Proof types accepted by the gateway.' },
]

function toolResult({ human, structured }) {
  const text = `${human}\n\n--- structured ---\n${JSON.stringify(structured, null, 2)}`
  return { content: [{ type: 'text', text }] }
}
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result })
const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } })

function handleRpc(msg) {
  const { id, method, params } = msg || {}
  switch (method) {
    case 'initialize':
      return rpcResult(id, {
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'mock-hl-agent-registry', version: '0.2.0' },
        capabilities: { tools: {} },
      })
    case 'tools/list':
      return rpcResult(id, { tools: TOOLS })
    case 'tools/call': {
      const { name, arguments: args } = params || {}
      try {
        return rpcResult(id, toolResult(callTool(name, args)))
      } catch (e) {
        if (e.unknownTool) return rpcError(id, -32601, e.message)
        return rpcError(id, -32603, e.message || 'internal error')
      }
    }
    default:
      return rpcError(id, -32601, `method not found: ${method}`)
  }
}

// ---------------------------------------------------------------------------
// Kurier stand-in (write side) — matches por_verify's exact paths + fields
// ---------------------------------------------------------------------------

/** POST /submit-proof/:key — accept a receipt, open a job. */
function kurierSubmit(body) {
  if (body?.proofType !== 'risc0' || !body?.proofData?.proof) {
    // No jobId in the response → por_verify treats it as a rejection (exit 3).
    return { status: 400, body: { error: 'invalid submission: expected proofType "risc0" with proofData.proof' } }
  }
  const fingerprint = sha256(body.proofData.publicSignals || body.proofData.proof)
  const ethBlockHash = decodeBlockHash(body.proofData.publicSignals)
  const jobId = `job-${(++state.jobSeq).toString().padStart(4, '0')}-${fingerprint.slice(0, 10)}`
  state.jobs.set(jobId, { jobId, agentId: state.targetId, fingerprint, ethBlockHash, polls: 0, recorded: false })
  console.log(`[mock][kurier] submit accepted → ${jobId} (target agent ${state.targetId.slice(0, 12)}…)`)
  return { status: 200, body: { jobId, optimisticVerify: 'Verified' } }
}

/** GET /job-status/:key/:jobId — advance the job; auto-record on "Aggregated". */
function kurierStatus(jobId) {
  const job = state.jobs.get(jobId)
  if (!job) return { status: 200, body: { status: 'Failed', error: `unknown job ${jobId}` } }
  job.polls++
  if (job.polls <= KURIER_POLLS) {
    return { status: 200, body: { status: 'AggregationPending', jobId } }
  }
  if (!job.recorded) {
    const { txHash, blockHash } = recordValidation(job.agentId, {
      fingerprint: job.fingerprint,
      proofType: 'risc0',
      ethBlockHash: job.ethBlockHash,
    })
    job.recorded = true
    job.txHash = txHash
    job.blockHash = blockHash
    job.aggregationId = (state.jobSeq * 1000 + 22435) >>> 0
  }
  return {
    status: 200,
    body: {
      status: 'Aggregated',
      jobId,
      txHash: job.txHash,
      blockHash: job.blockHash,
      aggregationId: job.aggregationId,
      aggregationDetails: { leaf: job.txHash, merkleProof: [], numberOfLeaves: 1, leafIndex: 0 },
    },
  }
}

// ---------------------------------------------------------------------------
// Control API (interactive) — inspect / reset / register / inject
// ---------------------------------------------------------------------------

const stateSnapshot = () => ({
  targetId: state.targetId,
  porLive: POR_LIVE,
  agents: allAgents().map((a) => ({
    agentId: a.agentId,
    name: a.name,
    proofType: a.proofType,
    receipts: a.receiptItems.length,
    verified: a.receiptItems.length > 0,
    isTarget: a.agentId.toLowerCase() === state.targetId.toLowerCase(),
  })),
  jobs: [...state.jobs.values()].map((j) => ({
    jobId: j.jobId, agentId: j.agentId, polls: j.polls, recorded: j.recorded, ethBlockHash: j.ethBlockHash,
  })),
})

/** Upsert an agent from a partial body; merges onto the seed defaults. */
function upsertAgent(body = {}) {
  const id = String(body.agentId || `0x${sha256(body.name || 'agent').slice(0, 40)}`).toLowerCase()
  const existing = state.agents.get(id)
  const merged = {
    ...SELF_SPEC,
    ...existing,
    ...body,
    agentId: id,
    porTypes: body.porTypes || existing?.porTypes || [body.proofType || 'risc0'],
    proofType: body.proofType || existing?.proofType || 'risc0',
    receipts: existing ? undefined : { count: 0, failed: 0, curve: 'risc0-succinct', constraintCount: 1_048_576 },
  }
  const a = existing
    ? Object.assign(existing, merged, { receiptItems: existing.receiptItems })
    : buildAgent(merged)
  recompute(a)
  state.agents.set(id, a)
  if (body.makeTarget) state.targetId = id
  return listRow(a)
}

// ---------------------------------------------------------------------------
// HTTP router
// ---------------------------------------------------------------------------

const readBody = (req) =>
  new Promise((resolve) => {
    let s = ''
    req.on('data', (c) => {
      s += c
      if (s.length > 2_000_000) req.destroy()
    })
    req.on('end', () => {
      try {
        resolve(s ? JSON.parse(s) : {})
      } catch {
        resolve(null)
      }
    })
  })

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(body))
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const p = url.pathname
  const seg = p.split('/').filter(Boolean)

  // --- health ---
  if (req.method === 'GET' && p === '/health') {
    return json(res, 200, { ok: true, agents: allAgents().length, verified: verifiedAgents().length, porLive: POR_LIVE, target: state.targetId })
  }

  // --- registry read MCP ---
  if (req.method === 'POST' && p === '/api/mcp') {
    const msg = await readBody(req)
    if (msg === null) return json(res, 400, rpcError(null, -32700, 'parse error'))
    return json(res, 200, handleRpc(msg))
  }

  // --- Kurier stand-in (por_verify): POST /submit-proof/:key ---
  if (req.method === 'POST' && seg[0] === 'submit-proof') {
    const body = await readBody(req)
    if (body === null) return json(res, 400, { error: 'parse error' })
    const r = kurierSubmit(body)
    return json(res, r.status, r.body)
  }
  // --- Kurier stand-in: GET /job-status/:key/:jobId ---
  if (req.method === 'GET' && seg[0] === 'job-status' && seg.length >= 3) {
    const r = kurierStatus(seg.slice(2).join('/'))
    return json(res, r.status, r.body)
  }

  // --- control API ---
  if (req.method === 'GET' && p === '/mock/state') return json(res, 200, stateSnapshot())
  if (req.method === 'POST' && p === '/mock/reset') {
    seedState()
    return json(res, 200, { ok: true, ...stateSnapshot() })
  }
  if (req.method === 'POST' && p === '/mock/target') {
    const body = (await readBody(req)) || {}
    if (body.agentId) state.targetId = String(body.agentId).toLowerCase()
    return json(res, 200, { targetId: state.targetId })
  }
  if (req.method === 'POST' && p === '/mock/agent') {
    const body = await readBody(req)
    if (body === null) return json(res, 400, { error: 'parse error' })
    return json(res, 200, { ok: true, agent: upsertAgent(body) })
  }
  // Manually record a validation without running the prover (pure-UI iteration).
  if (req.method === 'POST' && p === '/mock/record') {
    const body = (await readBody(req)) || {}
    const { receipt } = recordValidation(body.agentId || state.targetId, {
      fingerprint: body.fingerprint,
      proofType: body.proofType || 'risc0',
      ethBlockHash: body.ethBlockHash || null,
    })
    return json(res, 200, { ok: true, receipt })
  }

  return json(res, 404, { error: `not found: ${req.method} ${p}` })
})

server.listen(PORT, () => {
  const base = `http://127.0.0.1:${PORT}`
  console.log(`[mock-registry] up on :${PORT} (registry MCP + Kurier + control), risc0 live: ${POR_LIVE}`)
  console.log(`[mock-registry]   registry MCP : POST ${base}/api/mcp   (point server.mjs here)`)
  console.log(`[mock-registry]   kurier       : POST ${base}/submit-proof/:key  ·  GET ${base}/job-status/:key/:jobId`)
  console.log(`[mock-registry]   control      : GET ${base}/mock/state  ·  POST ${base}/mock/{reset,target,agent,record}`)
  console.log(`[mock-registry]   self agent   : ${SELF_ID} ("${SELF_NAME}") — unverified until its first proof lands`)
  console.log('[mock-registry] E2E submit (from por-risc0/):')
  console.log(`[mock-registry]   KURIER_API_KEY=mock KURIER_API_URL=${base} POR_ALLOW_DEBUG=1 POR_REQUIRED_THRESHOLD=1 ./target/release/por_verify`)
})
