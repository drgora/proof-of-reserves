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
//   KURIER_SUBMIT_PATH    default /submit-proof   (repo/verify.rs scheme; skill uses /api/v1/submit-proof)
//   KURIER_STATUS_PATH    default /job-status
//   POR_PROOF_TYPE        default proof-of-reserves   (the gateway proofType label you registered)
//   POR_CTX_HASH          default keccak256("risc0")  (must equal the ctxHash you registered)
//   POR_VERSION_HASH      optional; if set, skip the search and use this bytes32
//   AGENT_CARD_TOKEN_ID   optional decimal; else read from pubsBytes at AGENT_ID_OFFSET (cross-checked)
//   AGENT_ID_OFFSET       default 416    AGENT_ID_LENGTH default 8   (measured journal layout)
//   DOMAIN_ID             default 2 (Base Sepolia attestation domain)
//   GATEWAY               default 0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920 (V2 proxy)
//   ATTESTATION           default 0x0807C544D38aE7729f8798388d89Be6502A1e8A8
//   SUBMITTER_PORT        default 8092
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
const KURIER_SUBMIT_PATH = process.env.KURIER_SUBMIT_PATH || '/submit-proof'
const KURIER_STATUS_PATH = process.env.KURIER_STATUS_PATH || '/job-status'
const PROOF_TYPE = process.env.POR_PROOF_TYPE || 'proof-of-reserves'
const CTX_HASH = process.env.POR_CTX_HASH || keccak256(toBytes('risc0'))
const FORCED_VERSION_HASH = process.env.POR_VERSION_HASH || null
const AGENT_ID_OFFSET = Number(process.env.AGENT_ID_OFFSET || 416)
const AGENT_ID_LENGTH = Number(process.env.AGENT_ID_LENGTH || 8)
const DOMAIN_ID = BigInt(process.env.DOMAIN_ID || 2)
const GATEWAY = (process.env.GATEWAY || '0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920')
const ATTESTATION = (process.env.ATTESTATION || '0x0807C544D38aE7729f8798388d89Be6502A1e8A8')
const PORT = Number(process.env.SUBMITTER_PORT || 8092)

// risc0 versionHash candidates. zkVerify's statement uses VERSION_HASH = keccak256("risc0_"+version);
// the exact version string for V3_0 is confirmed at runtime by matching Kurier's leaf.
const VERSION_HASH_CANDIDATES = [
  ['risc0_V3_0', keccak256(toBytes('risc0_V3_0'))],
  ['risc0_v3.0', keccak256(toBytes('risc0_v3.0'))],
  ['risc0_3.0.0', keccak256(toBytes('risc0_3.0.0'))],
  ['risc0_3.0', keccak256(toBytes('risc0_3.0'))],
  ['risc0_v3.0.0', keccak256(toBytes('risc0_v3.0.0'))],
  ['risc0_V3.0', keccak256(toBytes('risc0_V3.0'))],
  ['V3_0', keccak256(toBytes('V3_0'))],
  ['3.0.0', keccak256(toBytes('3.0.0'))],
  ['sha256("")', sha256('0x')],
  ['zero', '0x' + '0'.repeat(64)],
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

// --- pipeline state (in-memory; the UI polls a snapshot) --------------------
const jobs = new Map() // jobId -> PipelineJob
let seq = 0
const nowIso = () => new Date().toISOString()
function upsert(jobId, patch) {
  const prev = jobs.get(jobId) || {}
  jobs.set(jobId, { ...prev, ...patch, updatedAt: nowIso() })
  return jobs.get(jobId)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

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
    const { request, result: validationId } = await publicClient.simulateContract({
      account, address: GATEWAY, abi: gatewayAbi, functionName: 'recordValidation', args: [p], value: fee,
    })
    const txHash = await walletClient.writeContract(request)
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })
    if (receipt.status !== 'success') throw new Error(`recordValidation reverted (tx ${txHash})`)
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
