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
// Faithful to real testnet state: owner comes from IdentityRegistry.ownerOf, and
// receipts are read from on-chain ValidationGateway logs (eth_getLogs, chunked) — so
// they survive submitter/adapter restarts. The submitter /pipeline is used only for the
// live in-progress timeline panel (PIPELINE_URL), not as the receipt source.
//
// The directory is discovered, not configured: the log scan reads EVERY
// ValidationRecorded event on the gateway (agentId is an indexed topic) and lists
// every agent that recorded at least one PoR-typed proof — no agent allowlist.
//
// Env:
//   PORT                  default 8090   — same as server.mjs so it's a drop-in
//   BASE_SEPOLIA_RPC_URL  default https://sepolia.base.org
//   IDENTITY_REGISTRY     default 0x8004A818BFB912233c491871b3d84c89A494BD9e (ERC-721 AgentCards)
//   POR_PROOF_TYPES       parity with server.mjs (default proof-of-reserves,reserves,por,risc0)
//                         — an agent is listed if any recorded validation's proofType matches
//   POR_NETWORK           display label (default "Base Sepolia")
//   ZKVERIFY_EXPLORER / BASESCAN_URL / MARKETPLACE_URL — same defaults as server.mjs
//   VALIDATION_GATEWAY    default 0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920 (V2 proxy; emits ValidationRecorded)
//   VALIDATION_EVENT_TOPIC default ValidationRecorded topic0 (agentId+validationId indexed)
//   RECEIPTS_LOOKBACK_BLOCKS default 50000 — initial on-chain log-scan depth from head (~28h on Base)
//   RECEIPTS_FROM_BLOCK   optional absolute start block for deep history (overrides lookback)
//   RECEIPTS_REFRESH_MS   default 20000 — min interval between incremental re-scans
//   PIPELINE_URL          submitter /pipeline; drives the LIVE timeline panel only (not receipts)

import http from 'node:http'

const PORT = Number(process.env.PORT || 8090)
const RPC_URL = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org'
const IDENTITY_REGISTRY =
  process.env.IDENTITY_REGISTRY || '0x8004A818BFB912233c491871b3d84c89A494BD9e'
const POR_PROOF_TYPES = (process.env.POR_PROOF_TYPES || 'proof-of-reserves,reserves,por,risc0')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
const NETWORK = process.env.POR_NETWORK || 'Base Sepolia'
const ZKVERIFY_EXPLORER = process.env.ZKVERIFY_EXPLORER || 'https://zkverify-testnet.subscan.io'
const BASESCAN_URL = process.env.BASESCAN_URL || 'https://sepolia.basescan.org'
const MARKETPLACE_URL = process.env.MARKETPLACE_URL || 'https://agent-registry.horizenlabs.io'
// Submitter status source (submitter.mjs /pipeline). It reports what it actually
// recorded on Base (real recordValidation tx hashes) — the receipt source until a
// pure on-chain ValidationRegistry log scan is wired (needs the event ABI).
const PIPELINE_URL = process.env.PIPELINE_URL || ''
const PROOF_TYPE = process.env.POR_PROOF_TYPE || 'proof-of-reserves'

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

// --- live in-progress timeline (submitter /pipeline) -----------------------
// Optional: the submitter reports jobs still moving through Kurier→aggregate→relay→record.
// This drives the UI's live timeline panel only; RECEIPTS come from on-chain logs (below),
// so a dead/absent submitter no longer zeroes the portal.
let pipelineCache = { at: 0, jobs: [] }
async function pipelineJobs() {
  if (!PIPELINE_URL) return []
  if (Date.now() - pipelineCache.at < 2000) return pipelineCache.jobs
  try {
    const res = await fetch(PIPELINE_URL, { signal: AbortSignal.timeout(4000) })
    const data = await res.json()
    pipelineCache = { at: Date.now(), jobs: Array.isArray(data) ? data : data.jobs || [] }
  } catch {
    pipelineCache = { at: Date.now(), jobs: pipelineCache.jobs } // keep last good on error
  }
  return pipelineCache.jobs
}

// Forward a "clear failed jobs" request to the submitter (which owns the pipeline state). The
// submitter's clear endpoint sits next to /pipeline; invalidate our cache so the next poll is fresh.
async function clearFailedPipeline() {
  if (!PIPELINE_URL) return { enabled: false, cleared: 0 }
  const url = PIPELINE_URL.replace(/\/[^/]*$/, '') + '/pipeline/clear-failed'
  const res = await fetch(url, { method: 'POST', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(5000) })
  if (!res.ok) throw Object.assign(new Error(`clear-failed HTTP ${res.status}`), { status: 502 })
  pipelineCache = { at: 0, jobs: [] } // force a re-fetch on the next /api/pipeline
  return res.json()
}

// --- receipts from on-chain ValidationGateway logs -------------------------
// Each ValidationGateway.recordValidation emits ValidationRecorded(agentId indexed,
// validationId indexed, string proofType, uint256 attestationId, bytes32 leaf,
// bytes32 fingerprint, bytes32 zkVerifyBlockHash). We eth_getLogs that event and turn
// each into a receipt, keyed by agentId. This is durable on-chain truth: it survives
// submitter/adapter restarts (unlike the old ephemeral in-memory /pipeline read).
// sepolia.base.org caps eth_getLogs at 2000 blocks/query, so the scan is chunked; an
// incremental cursor keeps refreshes cheap (only new blocks). Deep history (validations
// older than the initial lookback) needs RECEIPTS_FROM_BLOCK.
const VALIDATION_GATEWAY = (
  process.env.VALIDATION_GATEWAY || '0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920'
).toLowerCase()
const VALIDATION_TOPIC =
  process.env.VALIDATION_EVENT_TOPIC ||
  '0x816e123c9567e2dac73985f152bfbc51fc9b323357a989b8a3851a2194f791c8'
const GETLOGS_MAX_RANGE = 2000n // sepolia.base.org hard cap
const RECEIPTS_LOOKBACK = BigInt(process.env.RECEIPTS_LOOKBACK_BLOCKS || 50000) // initial scan depth
const RECEIPTS_FROM_BLOCK = process.env.RECEIPTS_FROM_BLOCK
  ? BigInt(process.env.RECEIPTS_FROM_BLOCK)
  : null
const RECEIPTS_REFRESH_MS = Number(process.env.RECEIPTS_REFRESH_MS || 20000)

async function rpc(method, params) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params }),
  })
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`)
  const j = await res.json()
  if (j.error) throw new Error(j.error.message || `${method} failed`)
  return j.result
}

const blockTsCache = new Map() // blockNumber(int) -> ISO string
async function blockTimestamp(blockNumber) {
  if (blockTsCache.has(blockNumber)) return blockTsCache.get(blockNumber)
  try {
    const b = await rpc('eth_getBlockByNumber', ['0x' + blockNumber.toString(16), false])
    const iso = b?.timestamp ? new Date(parseInt(b.timestamp, 16) * 1000).toISOString() : null
    blockTsCache.set(blockNumber, iso)
    return iso
  } catch {
    return null
  }
}

// Decode the event's first (dynamic `string`) param — proofType.
function decodeEventProofType(data) {
  try {
    const body = data.slice(2)
    const off = Number(BigInt('0x' + body.slice(0, 64))) * 2
    const len = Number(BigInt('0x' + body.slice(off, off + 64)))
    if (!len) return null
    return Buffer.from(body.slice(off + 64, off + 64 + len * 2), 'hex').toString('utf8')
  } catch {
    return null
  }
}

// --- public inputs (the guest journal, decoded from the recordValidation calldata) ---
// The journal is committed by the risc0 guest and passed to recordValidation as `pubsBytes`.
// We fetch the validation tx, pull `pubsBytes` out of the calldata, and decode the risc0-serde
// journal so the UI can show what each proof actually attests: threshold, chain, reference block.
// Journal layout (risc0 word-expands byte arrays to 1 word/byte; scalars stay native LE words):
//   block_hash[32]·threshold u128·chain_id u32·debug bool·challenge_nonce[32]·agent_id[32]·
//   block_number u64·agent_token_id u64·identity[u64;4]  = 114 words / 456 bytes.
const CHAINS = {
  1: { name: 'Ethereum', symbol: 'ETH', explorer: 'https://etherscan.io', rpc: 'https://eth.drpc.org' },
  10: { name: 'Optimism', symbol: 'ETH', explorer: 'https://optimistic.etherscan.io', rpc: 'https://optimism.drpc.org' },
  56: { name: 'BNB Chain', symbol: 'BNB', explorer: 'https://bscscan.com', rpc: 'https://bsc.drpc.org' },
  137: { name: 'Polygon', symbol: 'POL', explorer: 'https://polygonscan.com', rpc: 'https://polygon.drpc.org' },
  8453: { name: 'Base', symbol: 'ETH', explorer: 'https://basescan.org', rpc: 'https://base.drpc.org' },
  11155111: { name: 'Sepolia', symbol: 'ETH', explorer: 'https://sepolia.etherscan.io', rpc: 'https://sepolia.drpc.org' },
  11155420: { name: 'OP Sepolia', symbol: 'ETH', explorer: 'https://sepolia-optimism.etherscan.io', rpc: 'https://optimism-sepolia.drpc.org' },
  84532: { name: 'Base Sepolia', symbol: 'ETH', explorer: 'https://sepolia.basescan.org', rpc: 'https://base-sepolia.drpc.org' },
}
// Timestamp of a block on the PROVEN chain (not Base) — for the challenge coverage window.
// Override a chain's endpoint with POR_CHAIN_RPC_<id>. Cached (block times are immutable).
const chainTsCache = new Map() // `${chainId}:${block}` -> ISO|null
async function chainBlockTimestamp(chainId, blockNumber) {
  const key = `${chainId}:${blockNumber}`
  if (chainTsCache.has(key)) return chainTsCache.get(key)
  const url = process.env[`POR_CHAIN_RPC_${chainId}`] || CHAINS[chainId]?.rpc
  if (!url) {
    chainTsCache.set(key, null)
    return null
  }
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getBlockByNumber',
        params: ['0x' + blockNumber.toString(16), false],
      }),
      signal: AbortSignal.timeout(5000),
    })
    const j = await res.json()
    const iso = j.result?.timestamp
      ? new Date(parseInt(j.result.timestamp, 16) * 1000).toISOString()
      : null
    chainTsCache.set(key, iso)
    return iso
  } catch {
    chainTsCache.set(key, null)
    return null
  }
}
function formatWei(wei) {
  const v = BigInt(wei)
  const whole = v / 10n ** 18n
  const frac = (v % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}
// Pull the `bytes pubsBytes` argument (tuple head index 10) out of recordValidation calldata.
function extractPubsBytes(input) {
  const body = input.slice(2 + 8) // strip 0x + 4-byte selector
  const tupleOff = Number(BigInt('0x' + body.slice(0, 64)))
  const tuple = body.slice(tupleOff * 2)
  const off = Number(BigInt('0x' + tuple.slice(10 * 64, 10 * 64 + 64)))
  const at = off * 2
  const len = Number(BigInt('0x' + tuple.slice(at, at + 64)))
  return '0x' + tuple.slice(at + 64, at + 64 + len * 2)
}
function decodeJournal(pubsHex) {
  const b = Buffer.from(pubsHex.slice(2), 'hex')
  const word = (i) => b.readUInt32LE(i * 4)
  const u64 = (w) => BigInt(word(w)) | (BigInt(word(w + 1)) << 32n)
  let w = 0
  w += 32 // block_hash [u8;32]
  let threshold = 0n
  for (let k = 0; k < 4; k++) threshold |= BigInt(word(w + k)) << BigInt(32 * k) // u128
  w += 4
  const chain_id = word(w); w += 1
  const debug = word(w); w += 1
  const bytes32 = (at) => {
    let s = '0x'
    for (let k = 0; k < 32; k++) s += (word(at + k) & 0xff).toString(16).padStart(2, '0')
    return s
  }
  const challenge_nonce = bytes32(w); w += 32
  w += 32 // agent_id
  const block_number = u64(w); w += 2
  return { threshold: threshold.toString(), chain_id, debug, challenge_nonce, block_number: Number(block_number) }
}
async function resolvePublicInputs(item) {
  try {
    const tx = await rpc('eth_getTransactionByHash', [item.validationTxHash])
    if (!tx?.input) return
    const j = decodeJournal(extractPubsBytes(tx.input))
    const c = CHAINS[j.chain_id] || { name: `chain ${j.chain_id}`, symbol: '', explorer: null }
    item.publicInputs = {
      threshold: `${formatWei(j.threshold)}${c.symbol ? ` ${c.symbol}` : ''}`,
      thresholdWei: j.threshold,
      chainId: j.chain_id,
      chain: c.name,
      blockNumber: j.block_number,
      blockUrl: c.explorer ? `${c.explorer}/block/${j.block_number}` : null,
      blockTimestamp: await chainBlockTimestamp(j.chain_id, j.block_number),
      challengeNonce: j.challenge_nonce,
      ownershipProven: !j.debug,
    }
  } catch {
    /* leave publicInputs undefined; UI shows — */
  }
}

// agentHex -> Map(validationId -> receipt); cursor makes refreshes incremental.
// Every key is an agent discovered from the logs, so it has ≥1 PoR receipt by construction.
const store = { cursor: null, byAgent: new Map(), lastScan: 0, inflight: null }
/** Agents that have recorded ≥1 PoR proof (the whole directory). Requires a scan first. */
const discoveredAgentIds = () => [...store.byAgent.keys()]

async function scanOnce() {
  const head = BigInt(await rpc('eth_blockNumber', []))
  const from =
    store.cursor != null
      ? store.cursor + 1n
      : RECEIPTS_FROM_BLOCK ?? (head > RECEIPTS_LOOKBACK ? head - RECEIPTS_LOOKBACK : 0n)
  for (let start = from; start <= head; start += GETLOGS_MAX_RANGE) {
    const end = start + GETLOGS_MAX_RANGE - 1n > head ? head : start + GETLOGS_MAX_RANGE - 1n
    // Scan EVERY ValidationRecorded log (no agentId topic filter) so we discover every
    // agent that recorded a validation, then keep those whose proofType is PoR. This is
    // "list any agent that submitted ≥1 PoR proof" straight from on-chain truth.
    const logs = await rpc('eth_getLogs', [
      {
        address: VALIDATION_GATEWAY,
        topics: [VALIDATION_TOPIC],
        fromBlock: '0x' + start.toString(16),
        toBlock: '0x' + end.toString(16),
      },
    ])
    for (const l of logs) {
      const proofType = decodeEventProofType(l.data)
      // Keep PoR-typed proofs (unknown proofType falls back to PROOF_TYPE, a PoR type).
      if (proofType && !POR_PROOF_TYPES.includes(proofType.toLowerCase())) continue
      const agentHex = '0x' + BigInt(l.topics[1]).toString(16)
      const validationId = Number(BigInt(l.topics[2]))
      let m = store.byAgent.get(agentHex)
      if (!m) {
        m = new Map()
        store.byAgent.set(agentHex, m)
      }
      if (m.has(validationId)) continue
      m.set(validationId, {
        id: `val-${validationId}`,
        status: 'validated', // recordValidation only emits on success
        scorePct: null,
        proofType: proofType || PROOF_TYPE,
        timestamp: null, // resolved lazily from the block
        blockNumber: parseInt(l.blockNumber, 16),
        validationTxHash: l.transactionHash,
        validationId,
      })
    }
    store.cursor = end
  }
}

async function ensureScan() {
  if (store.cursor != null && Date.now() - store.lastScan < RECEIPTS_REFRESH_MS) return
  if (store.inflight) return store.inflight
  store.inflight = scanOnce()
    .catch((e) => console.error('[adapter] validation scan failed:', e.message))
    .finally(() => {
      store.lastScan = Date.now()
      store.inflight = null
    })
  return store.inflight
}

function agentReceiptCount(agentId) {
  const m = store.byAgent.get(toHexId(agentId).toLowerCase())
  return m ? m.size : 0
}

async function receiptsFor(hexId) {
  await ensureScan()
  const m = store.byAgent.get(hexId.toLowerCase())
  const items = m ? [...m.values()].sort((a, b) => b.blockNumber - a.blockNumber) : []
  await Promise.all([
    ...items
      .filter((it) => it.timestamp == null)
      .map(async (it) => {
        it.timestamp = await blockTimestamp(it.blockNumber)
      }),
    ...items.filter((it) => !it.publicInputs).map(resolvePublicInputs),
  ])
  return {
    count: items.length,
    validated: items.length,
    failed: 0,
    passRatePct: items.length ? 100 : null,
    returned: items.length,
    items,
  }
}

// --- structured shapes (mirror server.mjs / the MCP get_agent output) -------

async function getAgentDetail(agentId) {
  const owner = await ownerOf(agentId) // throws {revert} if token doesn't exist
  if (!owner) return null
  const hexId = toHexId(agentId)
  const name = (await tokenName(agentId)) || `Agent #${hexId}`
  const receipts = await receiptsFor(hexId)
  const hasReceipts = receipts.count > 0
  return {
    agentId: hexId,
    network: NETWORK,
    agent: {
      agentId: hexId,
      name,
      description: 'No description available',
      owner,
      active: true,
      zkVerified: hasReceipts,
      proofType: hasReceipts ? PROOF_TYPE : null,
    },
    whatThisProves: {
      proofType: hasReceipts ? PROOF_TYPE : null,
      proofTypes: hasReceipts ? [PROOF_TYPE] : [],
      summary: '',
      claims: [],
    },
    receipts,
    reputation: { reviewCount: 0, avgScore: null, feedback: [] },
  }
}

// Group an agent's receipts into challenges (shared challenge_nonce) and summarize each —
// used for the directory's "last passed challenge" overview + challenge counts.
function summarizeChallenges(items) {
  const g = new Map()
  for (const it of items) {
    const key = it.publicInputs?.challengeNonce || `solo:${it.id}`
    const arr = g.get(key)
    if (arr) arr.push(it)
    else g.set(key, [it])
  }
  const challenges = [...g.entries()].map(([, its]) => {
    const times = its.map((x) => x.publicInputs?.blockTimestamp).filter(Boolean).sort()
    const recs = its.map((x) => x.timestamp).filter(Boolean).sort()
    const pi = its[0].publicInputs || {}
    return {
      nonce: pi.challengeNonce ?? null,
      chain: pi.chain ?? null,
      threshold: pi.threshold ?? null,
      proofCount: its.length,
      first: times[0] ?? null, // earliest reference block covered
      last: times[times.length - 1] ?? null, // latest reference block covered
      recordedAt: recs[recs.length - 1] ?? null, // when it landed on-chain (recency key)
    }
  })
  challenges.sort((a, b) => (b.recordedAt ?? '').localeCompare(a.recordedAt ?? '')) // newest first
  return challenges
}

function detailToRow(detail) {
  const a = detail.agent || {}
  const items = detail.receipts?.items || []
  const challenges = summarizeChallenges(items)
  return {
    agentId: a.agentId,
    name: a.name,
    type: null,
    receipts: detail.receipts?.count ?? 0,
    challengeCount: challenges.length,
    lastChallenge: challenges[0] ?? null,
    lastActivity: items[0]?.timestamp ?? null,
    proofTypes: detail.whatThisProves?.proofTypes || [],
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
    }),
  },
  {
    pattern: /^\/api\/overview$/,
    // Shape must match the `Overview` type in api.ts — the Directory reads
    // o.agents.withReceipts and o.receipts.{count,validated} WITHOUT optional
    // chaining, so these objects must exist. This adapter isn't a full-registry
    // indexer (that's what the MCP was), so the tiles cover the agents discovered
    // from on-chain ValidationGateway logs (every agent with ≥1 PoR receipt).
    handler: async () => {
      await ensureScan()
      const ids = discoveredAgentIds()
      let count = 0
      for (const id of ids) count += agentReceiptCount(id)
      return {
        network: NETWORK,
        source: 'base-sepolia-onchain',
        // Every discovered agent has ≥1 receipt by construction, so withReceipts == count of agents.
        agents: { totalRegistered: ids.length, withReceipts: ids.length },
        receipts: { count, validated: count, failed: 0 },
        proofTypes: { count: count ? 1 : 0, types: count ? [PROOF_TYPE] : [] },
        porProofTypes: POR_PROOF_TYPES,
        porTypeLive: count > 0,
        explorer: ZKVERIFY_EXPLORER,
        baseExplorer: BASESCAN_URL,
        marketplace: MARKETPLACE_URL,
      }
    },
  },
  {
    // Proxy the submitter's live pipeline so the UI's timeline panel lights up.
    pattern: /^\/api\/pipeline$/,
    handler: async () => {
      if (!PIPELINE_URL) return { enabled: false, jobs: [] }
      return { enabled: true, jobs: await pipelineJobs(), explorer: ZKVERIFY_EXPLORER, baseExplorer: BASESCAN_URL }
    },
  },
  {
    pattern: /^\/api\/agents$/,
    handler: async () => {
      await ensureScan()
      const details = await Promise.all(
        discoveredAgentIds().map((id) => getAgentDetail(id).catch(() => null)),
      )
      const agents = details.filter(Boolean).map(detailToRow)
      return {
        mode: 'por',
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
    if (req.method === 'POST' && url.pathname === '/api/pipeline/clear-failed') {
      try {
        return send(res, 200, await clearFailedPipeline())
      } catch (e) {
        return send(res, e?.status || 502, { error: e?.message || 'clear failed' })
      }
    }
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
    console.log(`[sepolia-registry] PoR proof types: ${POR_PROOF_TYPES.join(', ')}`)
    // Warm the on-chain receipt scan so the first page load is instant.
    ensureScan()
      .then(() => {
        let count = 0
        for (const m of store.byAgent.values()) count += m.size
        console.log(
          `[sepolia-registry] on-chain receipts scanned: ${count} across ${store.byAgent.size} agent(s) (cursor @ ${store.cursor})`,
        )
      })
      .catch(() => {})
  })
