// Marketplace submitter — the missing "→ Base → UI" half of the PoR pipeline.
//
// The core loop (prover → verifier → Kurier/zkVerify) proves the reserves and
// verifies on zkVerify. This service takes those same verified bundles and drives
// the *marketplace* recording that the verifier does NOT do:
//
//   Kurier(chainId 84532) → Aggregated → [leaf preflight] → attestation relay
//   → ValidationGatewayV2.recordValidation() on Base Sepolia
//
// It persists a live pipeline status the UI already knows how to render (point the
// read-proxy's PIPELINE_URL here), and exposes the recorded validations so the
// directory can show them as receipts.
//
// Uses viem (already an app/web dependency) to sign the Base Sepolia tx.
//
// Env:
//   PRIVATE_KEY           0x… wallet with Base Sepolia ETH (gas + protocol fee).
//                         recordValidation is permissionless, so this need NOT own the agent.
//   BASE_SEPOLIA_RPC_URL  default https://sepolia.base.org
//   KURIER_API_KEY        required to submit
//   KURIER_API_URL        default https://api-testnet.kurier.xyz
//   KURIER_SUBMIT_PATH    default /api/v1/submit-proof   (real Kurier scheme; matches verify.rs)
//   KURIER_STATUS_PATH    default /api/v1/job-status
//   POR_PROOF_TYPE        default proof-of-reserves   (the gateway proofType label you registered)
//   POR_CTX_HASH          default keccak256("risc0")  (must equal the ctxHash you registered)
//   POR_VERSION_HASH      optional; if set, skip the search and use this bytes32
//   AGENT_CARD_TOKEN_ID   optional decimal; else read from pubsBytes at AGENT_ID_OFFSET (cross-checked)
//   AGENT_ID_OFFSET       default 416    AGENT_ID_LENGTH default 8   (measured journal layout)
//   DOMAIN_ID             default 2 (Base Sepolia attestation domain)
//   GATEWAY               default 0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920 (V2 proxy)
//   ATTESTATION           default 0x0807C544D38aE7729f8798388d89Be6502A1e8A8
//   SUBMITTER_PORT        default 8092
//   PIPELINE_DONE_TTL_MS  default 120000; how long a completed (VERIFIED) job stays in the live
//                         pipeline panel before it's auto-evicted (FAILED jobs are left to the
//                         explicit "Clear failed" action)
//   POR_RESPONSE          optional path to a prover response.json to auto-submit on startup

import http from 'node:http'
import { readFile } from 'node:fs/promises'
import {
  createPublicClient, createWalletClient, http as viemHttp,
  keccak256, sha256, concat, toBytes, slice, hexToBigInt, isHex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { baseSepolia } from 'viem/chains'

const RPC_URL = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org'
const KURIER_API_URL = process.env.KURIER_API_URL || 'https://api-testnet.kurier.xyz'
const KURIER_API_KEY = process.env.KURIER_API_KEY || ''
const KURIER_SUBMIT_PATH = process.env.KURIER_SUBMIT_PATH || '/api/v1/submit-proof'
const KURIER_STATUS_PATH = process.env.KURIER_STATUS_PATH || '/api/v1/job-status'
const PROOF_TYPE = process.env.POR_PROOF_TYPE || 'proof-of-reserves'
const CTX_HASH = process.env.POR_CTX_HASH || keccak256(toBytes('risc0'))
const FORCED_VERSION_HASH = process.env.POR_VERSION_HASH || null
const AGENT_ID_OFFSET = Number(process.env.AGENT_ID_OFFSET || 416)
const AGENT_ID_LENGTH = Number(process.env.AGENT_ID_LENGTH || 8)
// Journal byte offset of the identity field (keccak256(agent_secret), committed as [u64;4]).
// The gateway reads it little-endian; the registered commitment is that value as bytes32 =
// the 32 journal bytes reversed. Measured layout; see por-hl-marketplace-gateway-v2 memory.
const IDENTITY_BINDING_OFFSET = Number(process.env.IDENTITY_BINDING_OFFSET || 424)
const ZERO32 = '0x' + '0'.repeat(64)
const DOMAIN_ID = BigInt(process.env.DOMAIN_ID || 2)
const GATEWAY = (process.env.GATEWAY || '0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920')
const ATTESTATION = (process.env.ATTESTATION || '0x0807C544D38aE7729f8798388d89Be6502A1e8A8')
const PORT = Number(process.env.SUBMITTER_PORT || 8092)
// How long a completed (VERIFIED) job lingers in the live pipeline before it's evicted. The
// live panel is for in-flight work; once a job is recorded its receipt shows up in the directory
// below, so keeping the card forever just clutters the UI (and grows this map unbounded). The
// grace window is long enough that the user sees the ✓ "Recorded" state + the validation tx link.
const DONE_TTL_MS = Number(process.env.PIPELINE_DONE_TTL_MS || 120_000)

// risc0 versionHash candidates. zkVerify's statement uses VERSION_HASH = sha256("risc0:v<M>.<N>")
// — SHA-256 (not keccak), colon format (not underscores). The Risc0Version enum is V2_1/V2_2/V2_3/V3_0,
// so V<M>_<N> maps to "risc0:v<M>.<N>"; our proofOptions.version is V3_0 -> "risc0:v3.0". The others are
// kept as fallbacks and the exact string is confirmed at runtime by matching Kurier's leaf.
const VERSION_HASH_CANDIDATES = [
  ['risc0:v3.0', sha256(toBytes('risc0:v3.0'))],
  ['risc0:v3.0.0', sha256(toBytes('risc0:v3.0.0'))],
  ['risc0:v2.3', sha256(toBytes('risc0:v2.3'))],
  ['risc0:v2.2', sha256(toBytes('risc0:v2.2'))],
  ['risc0:v2.1', sha256(toBytes('risc0:v2.1'))],
  ['sha256("")', sha256('0x')],
]

const gatewayAbi = [
  {
    type: 'function', name: 'recordValidation', stateMutability: 'payable',
    inputs: [{
      name: 'p', type: 'tuple', components: [
        { name: 'agentId', type: 'uint256' },
        { name: 'proofType', type: 'string' },
        { name: 'zkVerifyTxHash', type: 'bytes32' },
        { name: 'zkVerifyBlockHash', type: 'bytes32' },
        { name: 'domainId', type: 'uint256' },
        { name: 'attestationId', type: 'uint256' },
        { name: 'leaf', type: 'bytes32' },
        { name: 'merklePath', type: 'bytes32[]' },
        { name: 'leafCount', type: 'uint256' },
        { name: 'index', type: 'uint256' },
        { name: 'pubsBytes', type: 'bytes' },
        { name: 'vkHash', type: 'bytes32' },
        { name: 'versionHash', type: 'bytes32' },
      ],
    }],
    outputs: [{ name: 'validationId', type: 'uint256' }],
  },
  { type: 'function', name: 'protocolFee', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  {
    type: 'function', name: 'agentCommitments', stateMutability: 'view',
    inputs: [{ name: 'agentId', type: 'uint256' }, { name: 'proofType', type: 'string' }],
    outputs: [{ type: 'bytes32' }],
  },
  {
    type: 'function', name: 'registerAgentCommitment', stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentId', type: 'uint256' },
      { name: 'proofType', type: 'string' },
      { name: 'commitment', type: 'bytes32' },
      { name: 'asRegistrar', type: 'bool' },
    ],
    outputs: [],
  },
]
const attestationAbi = [{
  type: 'function', name: 'proofsAggregations', stateMutability: 'view',
  inputs: [{ name: '_domainId', type: 'uint256' }, { name: '_aggregationId', type: 'uint256' }],
  outputs: [{ type: 'bytes32' }],
}]

const account = PRIVATE_KEY_ACCOUNT()
function PRIVATE_KEY_ACCOUNT() {
  const pk = process.env.PRIVATE_KEY
  if (!pk) return null
  return privateKeyToAccount(pk.startsWith('0x') ? pk : `0x${pk}`)
}
const publicClient = createPublicClient({ chain: baseSepolia, transport: viemHttp(RPC_URL) })
const walletClient = account
  ? createWalletClient({ account, chain: baseSepolia, transport: viemHttp(RPC_URL) })
  : null

// Registrar key for auto-registering per-agent identity commitments (asRegistrar=true requires
// msg.sender == proofTypeRegistrar[proofType]). Defaults to the recording wallet (PRIVATE_KEY),
// which IS the registrar in our deployment; override with POR_REGISTRAR_KEY if they differ.
const registrarAccount = process.env.POR_REGISTRAR_KEY
  ? privateKeyToAccount(process.env.POR_REGISTRAR_KEY.startsWith('0x') ? process.env.POR_REGISTRAR_KEY : `0x${process.env.POR_REGISTRAR_KEY}`)
  : account
const registrarClient = registrarAccount
  ? createWalletClient({ account: registrarAccount, chain: baseSepolia, transport: viemHttp(RPC_URL) })
  : null

// The identity commitment this proof presents, read from its own journal: bytes32(_extractField(
// pubs, IDENTITY_BINDING_OFFSET, 32, LE)) == the 32 journal bytes reversed. Registering exactly
// this makes recordValidation's commitment check pass for the same proof.
function extractIdentityCommitment(pubsBytes) {
  const start = 2 + IDENTITY_BINDING_OFFSET * 2
  const le = pubsBytes.slice(start, start + 64)
  if (le.length < 64) return null
  return '0x' + le.match(/../g).reverse().join('')
}

// Register the agent's identity commitment if it isn't set yet (set-once, first-claim-wins).
// Derived from the proof's journal, so it always matches. No-op when: already registered (the
// agent keeps its original commitment — a mismatch there means the proof used a different secret
// and recordValidation will surface it), agentId is 0, or the identity is the zero-secret hash.
async function ensureCommitment(agentId, pubsBytes) {
  if (agentId === 0n) return
  const commitment = extractIdentityCommitment(pubsBytes)
  if (!commitment || commitment === ZERO32) {
    console.warn(`[submitter] agent ${agentId}: journal identity is unset (zero-secret) — not auto-registering`)
    return
  }
  const existing = await publicClient.readContract({
    address: GATEWAY, abi: gatewayAbi, functionName: 'agentCommitments', args: [agentId, PROOF_TYPE],
  })
  if (existing && existing !== ZERO32) return // set-once; leave the original in place
  if (!registrarClient) {
    console.warn(`[submitter] agent ${agentId}: no registrar key (PRIVATE_KEY / POR_REGISTRAR_KEY) — cannot auto-register commitment`)
    return
  }
  await withTxLock(async () => {
    const { request } = await publicClient.simulateContract({
      account: registrarAccount, address: GATEWAY, abi: gatewayAbi,
      functionName: 'registerAgentCommitment', args: [agentId, PROOF_TYPE, commitment, true],
    })
    const tx = await registrarClient.writeContract(request)
    await publicClient.waitForTransactionReceipt({ hash: tx })
    console.log(`[submitter] registered identity commitment ${commitment} for agent ${agentId} (tx ${tx})`)
  })
}

// --- pipeline state (in-memory; the UI polls a snapshot) --------------------
const jobs = new Map() // jobId -> PipelineJob
let seq = 0
const nowIso = () => new Date().toISOString()
function upsert(jobId, patch) {
  const prev = jobs.get(jobId) || {}
  const next = { ...prev, ...patch, updatedAt: nowIso() }
  // Stamp the moment a job reaches its terminal success stage, so pruning is measured from
  // completion rather than from any later touch (there shouldn't be one, but be defensive).
  if (patch.stage === 'VERIFIED' && !prev.doneAt) next.doneAt = Date.now()
  jobs.set(jobId, next)
  return next
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Evict completed (VERIFIED) jobs once they've lingered past the grace window. FAILED jobs are
// left to the explicit "Clear failed" action (a human may want to read the error); only the
// happy-path "Recorded" cards auto-expire so the live panel doesn't grow forever.
function pruneDone(now = Date.now()) {
  let pruned = 0
  for (const [id, j] of jobs) {
    if (j.stage === 'VERIFIED' && j.doneAt && now - j.doneAt > DONE_TTL_MS) {
      jobs.delete(id)
      pruned++
    }
  }
  if (pruned) console.log(`[submitter] pruned ${pruned} completed job(s) from the pipeline`)
  return pruned
}

// Serialize on-chain sends across concurrently-running bundles. All bundles share ONE wallet,
// so simultaneous writeContract calls grab the same nonce and all but one fail with
// "replacement transaction underpriced". withTxLock chains the simulate→write→wait section so
// each tx mines (nonce advances on the node) before the next bundle sends.
let txChain = Promise.resolve()
function withTxLock(fn) {
  const result = txChain.then(fn, fn) // run regardless of the previous send's outcome
  txChain = result.then(() => {}, () => {}) // keep the chain alive past failures
  return result
}

// --- Kurier -----------------------------------------------------------------
async function kurierSubmit(bundle) {
  const body = {
    proofType: bundle.proofType,            // "risc0"
    vkRegistered: false,
    chainId: 84532,                          // Base Sepolia — REQUIRED for attestation relay
    proofOptions: bundle.proofOptions,       // { version: "V3_0" }
    proofData: bundle.proofData,             // { proof, vk, publicSignals }
  }
  const res = await fetch(`${KURIER_API_URL}${KURIER_SUBMIT_PATH}/${KURIER_API_KEY}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  if (!json.jobId) throw new Error(`Kurier rejected submission: HTTP ${res.status} ${JSON.stringify(json)}`)
  return json.jobId
}
async function kurierStatus(jobId) {
  const res = await fetch(`${KURIER_API_URL}${KURIER_STATUS_PATH}/${KURIER_API_KEY}/${jobId}`)
  return res.json()
}

// --- leaf reconstruction (the gas-free "Leaf mismatch" guard) ---------------
// leaf = keccak256(ctxHash ‖ vkHash ‖ versionHash ‖ keccak256(pubsBytes))
function reconstructLeaf(vkHash, versionHash, pubsBytes) {
  return keccak256(concat([CTX_HASH, vkHash, versionHash, keccak256(pubsBytes)]))
}
/** Find the versionHash whose reconstructed leaf matches Kurier's. Returns {versionHash, label} or null. */
function resolveVersionHash(vkHash, pubsBytes, kurierLeaf) {
  const target = kurierLeaf.toLowerCase()
  const list = FORCED_VERSION_HASH ? [['forced', FORCED_VERSION_HASH]] : VERSION_HASH_CANDIDATES
  for (const [label, vh] of list) {
    if (reconstructLeaf(vkHash, vh, pubsBytes).toLowerCase() === target) return { versionHash: vh, label }
  }
  return null
}

function extractAgentId(pubsBytes) {
  // u64 little-endian at AGENT_ID_OFFSET
  const start = 2 + AGENT_ID_OFFSET * 2
  const hex = pubsBytes.slice(start, start + AGENT_ID_LENGTH * 2)
  let v = 0n
  for (let i = 0; i < AGENT_ID_LENGTH; i++) v |= BigInt(parseInt(hex.slice(i * 2, i * 2 + 2), 16)) << BigInt(8 * i)
  return v
}

// --- one bundle end-to-end --------------------------------------------------
async function runPipeline(bundle, meta = {}) {
  const jobId = `sub-${++seq}`
  const pubsBytes = bundle.proofData.publicSignals
  const vkHash = bundle.proofData.vk
  const agentId = process.env.AGENT_CARD_TOKEN_ID ? BigInt(process.env.AGENT_CARD_TOKEN_ID) : extractAgentId(pubsBytes)
  if (process.env.AGENT_CARD_TOKEN_ID && extractAgentId(pubsBytes) !== agentId) {
    console.warn(`[submitter] WARNING: AGENT_CARD_TOKEN_ID=${agentId} != agentId in journal ${extractAgentId(pubsBytes)} — recordValidation will revert "Agent ID mismatch"`)
  }
  upsert(jobId, {
    jobId, agentId: '0x' + agentId.toString(16), agentName: meta.agentName,
    stage: 'SUBMITTED', submittedAt: nowIso(), ethBlockHash: meta.ethBlockHash ?? null, error: null,
  })
  try {
    if (!KURIER_API_KEY) throw new Error('KURIER_API_KEY not set')
    if (!walletClient) throw new Error('PRIVATE_KEY not set (need a Base Sepolia wallet to record)')

    // 1. submit to Kurier (chainId 84532)
    const kJobId = await kurierSubmit(bundle)
    upsert(jobId, { zkVerifyJobId: kJobId })

    // 2. poll to Aggregated
    let agg = null
    for (let i = 0; i < 180; i++) {
      await sleep(5000)
      const s = await kurierStatus(kJobId)
      const st = s.status || '?'
      if (s.txHash) upsert(jobId, { stage: 'FINALIZED', zkVerifyExtrinsicHash: s.txHash, zkVerifyBlockHash: s.blockHash })
      if (st === 'Failed' || st === 'Error' || st === 'Invalid') throw new Error(`Kurier verification failed: ${JSON.stringify(s)}`)
      if (st === 'Aggregated' || st === 'AggregationPublished') { agg = s; break }
    }
    if (!agg) throw new Error('timed out waiting for Kurier Aggregated')
    const aggregationId = agg.aggregationId
    const details = agg.aggregationDetails || {}
    upsert(jobId, { stage: 'AGGREGATED', aggregationId, zkVerifyExtrinsicHash: agg.txHash, zkVerifyBlockHash: agg.blockHash })

    // 3. leaf preflight — resolve versionHash by matching Kurier's leaf (no gas)
    const kurierLeaf = details.leaf
    if (!kurierLeaf) throw new Error(`Kurier response has no aggregationDetails.leaf: ${JSON.stringify(details)}`)
    const resolved = resolveVersionHash(vkHash, pubsBytes, kurierLeaf)
    if (!resolved) {
      throw new Error(
        `Leaf preflight FAILED — no versionHash candidate reproduces Kurier's leaf.\n` +
        `  kurierLeaf=${kurierLeaf}\n  ctxHash=${CTX_HASH}\n  vkHash=${vkHash}\n` +
        `  keccak256(pubsBytes)=${keccak256(pubsBytes)}\n` +
        `  tried=${(FORCED_VERSION_HASH ? ['forced'] : VERSION_HASH_CANDIDATES.map((c) => c[0])).join(', ')}\n` +
        `  → recordValidation would revert "Leaf mismatch". Check ctxHash / pubsBytes / version.`,
      )
    }
    console.log(`[submitter] ${jobId}: versionHash resolved via "${resolved.label}" = ${resolved.versionHash}`)

    // 4. wait for attestation relay to Base
    upsert(jobId, { stage: 'RELAYING' })
    let relayed = false
    for (let i = 0; i < 60; i++) {
      const root = await publicClient.readContract({
        address: ATTESTATION, abi: attestationAbi, functionName: 'proofsAggregations',
        args: [DOMAIN_ID, BigInt(aggregationId)],
      })
      if (root && root !== '0x' + '0'.repeat(64)) { relayed = true; break }
      await sleep(10_000)
    }
    if (!relayed) throw new Error('attestation relay to Base Sepolia timed out (retry later)')

    // 4.5 ensure the agent's identity commitment is registered (set-once) so recordValidation's
    // mandatory identity-binding check passes. Derived from this proof's own journal.
    await ensureCommitment(agentId, pubsBytes)

    // 5. recordValidation (exact protocol fee)
    upsert(jobId, { stage: 'RECORDING' })
    const fee = await publicClient.readContract({ address: GATEWAY, abi: gatewayAbi, functionName: 'protocolFee' })
    const p = {
      agentId,
      proofType: PROOF_TYPE,
      zkVerifyTxHash: agg.txHash,
      zkVerifyBlockHash: agg.blockHash,
      domainId: DOMAIN_ID,
      attestationId: BigInt(aggregationId),
      leaf: kurierLeaf,
      merklePath: details.merkleProof,
      leafCount: BigInt(details.numberOfLeaves),
      index: BigInt(details.leafIndex),
      pubsBytes,
      vkHash,
      versionHash: resolved.versionHash,
    }
    // simulate first: validates on-chain (surfaces reverts) AND returns validationId — no gas.
    // The send is serialized (withTxLock) so parallel bundles don't collide on the wallet nonce.
    const { txHash, validationId } = await withTxLock(async () => {
      const { request, result: vId } = await publicClient.simulateContract({
        account, address: GATEWAY, abi: gatewayAbi, functionName: 'recordValidation', args: [p], value: fee,
      })
      const tx = await walletClient.writeContract(request)
      const receipt = await publicClient.waitForTransactionReceipt({ hash: tx })
      if (receipt.status !== 'success') throw new Error(`recordValidation reverted (tx ${tx})`)
      return { txHash: tx, validationId: vId }
    })
    upsert(jobId, {
      stage: 'VERIFIED', validationTxHash: txHash,
      validationId: validationId != null ? Number(validationId) : undefined,
    })
    console.log(`[submitter] ${jobId}: recorded validation ${validationId} on agent 0x${agentId.toString(16)} (tx ${txHash})`)
  } catch (e) {
    upsert(jobId, { stage: 'FAILED', error: e.message })
    console.error(`[submitter] ${jobId} FAILED: ${e.message}`)
  }
  return jobId
}

async function submitResponse(response) {
  const bundles = response.bundles || (response.proofData ? [response] : [])
  if (!bundles.length) throw new Error('no bundles in response')
  return bundles.map((b, i) => runPipeline(b, { bundleIndex: i })) // fire-and-track; don't await
}

// --- HTTP -------------------------------------------------------------------
function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}
async function readBody(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  try {
    if (req.method === 'GET' && url.pathname === '/pipeline') {
      pruneDone() // drop long-completed cards so the live panel doesn't stick forever
      return send(res, 200, { enabled: true, jobs: [...jobs.values()].sort((a, b) => (a.jobId < b.jobId ? 1 : -1)) })
    }
    if (req.method === 'GET' && url.pathname === '/health') {
      return send(res, 200, { ok: true, wallet: account?.address ?? null, gateway: GATEWAY, proofType: PROOF_TYPE, kurier: KURIER_API_URL })
    }
    if (req.method === 'POST' && url.pathname === '/submit') {
      const body = await readBody(req)
      const response = body.responsePath ? JSON.parse(await readFile(body.responsePath, 'utf8')) : body
      const ids = await submitResponse(response)
      return send(res, 202, { accepted: ids })
    }
    // Evict terminal FAILED jobs from the live pipeline. They never leave on their own (a retry
    // creates a fresh job), so without this they accumulate in the "live" panel indefinitely.
    if (req.method === 'POST' && url.pathname === '/pipeline/clear-failed') {
      let cleared = 0
      for (const [id, j] of jobs) if (j.stage === 'FAILED') { jobs.delete(id); cleared++ }
      console.log(`[submitter] cleared ${cleared} failed job(s) from the pipeline`)
      return send(res, 200, { cleared })
    }
    return send(res, 404, { error: 'not found' })
  } catch (e) {
    return send(res, 500, { error: e.message })
  }
}).listen(PORT, async () => {
  console.log(`[submitter] on :${PORT} — wallet ${account?.address ?? '(none — set PRIVATE_KEY)'} → gateway ${GATEWAY}`)
  console.log(`[submitter] proofType="${PROOF_TYPE}" ctxHash=${CTX_HASH} kurier=${KURIER_API_URL}${KURIER_SUBMIT_PATH}`)
  if (process.env.POR_RESPONSE) {
    try {
      const r = JSON.parse(await readFile(process.env.POR_RESPONSE, 'utf8'))
      const ids = await submitResponse(r)
      console.log(`[submitter] auto-submitting ${process.env.POR_RESPONSE}: ${ids.length} bundle(s)`)
    } catch (e) { console.error(`[submitter] POR_RESPONSE load failed: ${e.message}`) }
  }
})

// Sweep completed jobs even when nobody is polling /pipeline, so the map stays bounded on a
// long-lived process. unref() so this timer never keeps the process alive on its own.
setInterval(() => pruneDone(), Math.max(15_000, Math.floor(DONE_TTL_MS / 2))).unref()
