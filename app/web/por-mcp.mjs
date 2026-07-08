// por-mcp — a Model Context Protocol server that lets an AI agent drive the whole
// Proof-of-Reserves flow with tools: register on the marketplace, request a challenge, run the
// prover, submit the response, and poll the verdict. It runs LOCALLY alongside the agent (like
// the prover, it holds the agent's key only in-process — nothing sensitive is sent to the
// service). Transports: stdio (default — how `claude mcp add` / Claude Desktop connect) and an
// optional plain HTTP JSON-RPC endpoint (`--http [port]`) for remote/curl use.
//
// Zero MCP SDK: speaks JSON-RPC 2.0 directly (newline-delimited over stdio, request/response
// over HTTP). viem (already an app/web dependency) is used for registration + on-chain reads.
//
// Config (env):
//   VERIFIER_URL          default https://verifier-production-d672.up.railway.app
//   NOTARY_ADDR           default hayabusa.proxy.rlwy.net:39286 (passed to the prover)
//   BASE_SEPOLIA_RPC_URL  default https://sepolia.base.org (registration + ownerOf reads)
//   IDENTITY_REGISTRY     default 0x8004A818BFB912233c491871b3d84c89A494BD9e
//   PROVER_BIN            default "prover" (the prover binary/Docker entrypoint on PATH)
//   MCP_HTTP_PORT         default 8765 when --http is passed with no port
//
// Run:
//   node por-mcp.mjs                 # stdio (for an MCP client)
//   node por-mcp.mjs --http 8765     # HTTP JSON-RPC on :8765 (POST /mcp)
//
// IMPORTANT (stdio): only JSON-RPC frames may go to stdout. All diagnostics go to stderr.

import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createPublicClient, http as viemHttp } from 'viem'
import { baseSepolia } from 'viem/chains'
import { registerAgent } from './register-agent.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const VERIFIER_URL = (process.env.VERIFIER_URL || 'https://verifier-production-d672.up.railway.app').replace(/\/$/, '')
const NOTARY_ADDR = process.env.NOTARY_ADDR || 'hayabusa.proxy.rlwy.net:39286'
const BASE_RPC = process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org'
const IDENTITY_REGISTRY = process.env.IDENTITY_REGISTRY || '0x8004A818BFB912233c491871b3d84c89A494BD9e'
const PROVER_BIN = process.env.PROVER_BIN || 'prover'
const PROTOCOL_VERSION = '2025-06-18'
const SERVER_INFO = { name: 'proof-of-reserves', version: '1.0.0' }

const log = (...a) => console.error('[por-mcp]', ...a)

// --- verifier REST helpers --------------------------------------------------
async function verifierGet(path) {
  const r = await fetch(`${VERIFIER_URL}${path}`, { headers: { accept: 'application/json' } })
  const j = await r.json().catch(() => null)
  if (!r.ok) throw new Error(j?.error || `verifier ${path} -> HTTP ${r.status}`)
  return j
}
async function verifierPost(path, body) {
  const r = await fetch(`${VERIFIER_URL}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
  const j = await r.json().catch(() => null)
  if (!r.ok && !(j && j.verdict)) throw new Error(j?.error || `verifier ${path} -> HTTP ${r.status}`)
  return j
}

// --- on-chain reads (registration status) -----------------------------------
const idAbi = [
  { type: 'function', name: 'ownerOf', stateMutability: 'view', inputs: [{ name: 'tokenId', type: 'uint256' }], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'tokenURI', stateMutability: 'view', inputs: [{ name: 'tokenId', type: 'uint256' }], outputs: [{ type: 'string' }] },
]
const publicClient = () => createPublicClient({ chain: baseSepolia, transport: viemHttp(BASE_RPC) })
const toTokenId = (agentId) => BigInt(agentId) // parses 0x-hex and decimal

async function checkRegistration(agentId) {
  const client = publicClient()
  const tokenId = toTokenId(agentId)
  let owner = null
  try {
    owner = await client.readContract({ address: IDENTITY_REGISTRY, abi: idAbi, functionName: 'ownerOf', args: [tokenId] })
  } catch {
    return { agentId, registered: false, owner: null, name: null }
  }
  let name = null
  try {
    const uri = await client.readContract({ address: IDENTITY_REGISTRY, abi: idAbi, functionName: 'tokenURI', args: [tokenId] })
    if (uri?.startsWith('data:')) {
      const payload = uri.slice(uri.indexOf(',') + 1)
      const raw = uri.slice(0, uri.indexOf(',')).includes('base64') ? Buffer.from(payload, 'base64').toString('utf8') : decodeURIComponent(payload)
      name = JSON.parse(raw)?.name ?? null
    }
  } catch { /* name is best-effort */ }
  return { agentId, registered: !!owner, owner, name, marketplaceUrl: `https://agent-registry.horizenlabs.io/agent/0x${tokenId.toString(16)}` }
}

// --- prove jobs (the prover is a long-running child; keep tool calls fast) ---
// prove_reserves spawns the prover in connected mode and returns a jobId immediately; the agent
// polls get_prove_status. Proving is CPU-heavy (~15-30 min for the 3-block challenge), far longer
// than an MCP client will hold a single tool call open — hence the background-job model.
const jobs = new Map() // jobId -> { state, verdict, reason, log, exitCode, startedAt }
const clip = (s, n = 6000) => (s.length > n ? s.slice(-n) : s)

function startProveJob({ agentId, threshold, chainId, privateKey, ownerKey, notaryAddr, verifierUrl }) {
  const jobId = randomBytes(6).toString('hex')
  const args = ['--verifier', verifierUrl || VERIFIER_URL, '--agent-id', String(agentId), '--threshold', String(threshold)]
  if (chainId != null) args.push('--chain-id', String(chainId))
  const env = { ...process.env, POR_PRIVATE_KEY: privateKey }
  if (ownerKey) env.POR_OWNER_KEY = ownerKey
  const na = notaryAddr ?? NOTARY_ADDR
  if (na && na !== 'none') env.NOTARY_ADDR = na
  else delete env.NOTARY_ADDR

  const job = { state: 'proving', verdict: null, reason: null, log: '', exitCode: null, startedAt: Date.now() }
  jobs.set(jobId, job)
  log(`prove job ${jobId}: ${PROVER_BIN} ${args.join(' ')}`)

  let child
  try {
    child = spawn(PROVER_BIN, args, { env })
  } catch (e) {
    job.state = 'error'
    job.reason = `could not launch prover "${PROVER_BIN}": ${e.message}`
    return jobId
  }
  child.stdout.on('data', (d) => { job.log = clip(job.log + d.toString()) })
  child.stderr.on('data', (d) => { job.log = clip(job.log + d.toString()) })
  child.on('error', (e) => { job.state = 'error'; job.reason = e.message })
  child.on('close', (code) => {
    job.exitCode = code
    // Connected mode prints the verdict; exit 0 == verified. Fall back to scanning the log.
    if (/verdict:\s*verified/i.test(job.log) || code === 0) { job.state = 'verified'; job.verdict = 'verified' }
    else {
      job.state = 'rejected'; job.verdict = 'rejected'
      const m = job.log.match(/reason[:\s]+(.+)/i) || job.log.match(/verdict:\s*rejected\s*[—-]?\s*(.+)/i)
      job.reason = (m && m[1].trim()) || `prover exited ${code}`
    }
    log(`prove job ${jobId}: ${job.state}${job.reason ? ' — ' + job.reason : ''}`)
  })
  return jobId
}

// --- tool registry ----------------------------------------------------------
const S = (props, required = []) => ({ type: 'object', properties: props, required, additionalProperties: false })
const str = (description) => ({ type: 'string', description })
const num = (description) => ({ type: ['integer', 'string'], description })

const TOOLS = [
  {
    name: 'list_supported_chains',
    description: 'List the chains you can prove reserves on. Returns each chain\'s selector (pass as chainId), the resolved chain id committed in the proof, name, and whether the service is in testnet mode.',
    inputSchema: S({}),
    handler: async () => verifierGet('/v1/chains'),
  },
  {
    name: 'get_service_info',
    description: 'Get the verifier\'s service info: version, mode (mainnet/testnet), the RISC Zero image_id it accepts (your prover must match), whether a TLSNotary notary is required, endpoints, and links to the guide/OpenAPI.',
    inputSchema: S({}),
    handler: async () => verifierGet('/v1/info'),
  },
  {
    name: 'register_agent',
    description: 'Register a new agent on the Horizen Labs marketplace (Base Sepolia) so the verifier will authenticate it. Sends IdentityRegistry.register() from ownerPrivateKey (the key stays in this local process); msg.sender becomes the owner — use this SAME key to authorize challenges. The wallet needs Base Sepolia ETH for gas. Omit ownerPrivateKey to get a dry-run (calldata only, nothing sent).',
    inputSchema: S({
      ownerPrivateKey: str('0x 32-byte private key of the wallet that will own the agent AND authorize challenges. Stays local. Omit for a dry-run.'),
      name: str('Agent display name.'),
      description: str('What the agent does (optional).'),
      endpoint: str('Public service endpoint URL (optional).'),
      skills: { type: 'array', items: { type: 'string' }, description: 'Skill tags (optional).' },
      domains: { type: 'array', items: { type: 'string' }, description: 'Domain tags (optional).' },
    }, ['name']),
    handler: async (a) => registerAgent({
      privateKey: a.ownerPrivateKey, name: a.name, description: a.description,
      endpoint: a.endpoint, skills: a.skills, domains: a.domains, dryRun: !a.ownerPrivateKey,
    }),
  },
  {
    name: 'check_registration',
    description: 'Check whether an agent id is registered on the marketplace (Base Sepolia) and return its on-chain owner and name. The owner is the address the verifier requires your challenge signature to recover to.',
    inputSchema: S({ agentId: str('Marketplace agent id, hex (0x16ec) or decimal (5868).') }, ['agentId']),
    handler: async (a) => checkRegistration(a.agentId),
  },
  {
    name: 'request_challenge',
    description: 'Ask the verifier for a challenge. Returns the challenge (nonce + 3 unpredictable finalized block numbers + resolved chain id + expiry). Save the challenge_id; the challenge expires in ~1 hour.',
    inputSchema: S({
      agentId: str('Registered marketplace agent id.'),
      threshold: num('Minimum combined reserves in wei (decimal string). e.g. "50000000000000000" = 0.05 ETH.'),
      chainId: num('Chain selector (default 1 = Ethereum/Sepolia). See list_supported_chains.'),
    }, ['agentId', 'threshold']),
    handler: async (a) => {
      const body = { agent_id: String(a.agentId), threshold: String(a.threshold) }
      if (a.chainId != null) body.chain_id = a.chainId
      return verifierPost('/v1/challenges', body)
    },
  },
  {
    name: 'get_challenge_status',
    description: 'Get a challenge\'s current state, verdict/reason, and (once verified, if settle is enabled) the zkVerify/marketplace settle progress.',
    inputSchema: S({ challengeId: str('The challenge_id from request_challenge.') }, ['challengeId']),
    handler: async (a) => verifierGet(`/v1/challenges/${encodeURIComponent(a.challengeId)}`),
  },
  {
    name: 'submit_proof',
    description: 'Submit a prover-produced response (por-response-v1) to a challenge and return the verdict. Provide either `response` (the parsed JSON object) or `responsePath` (a path to response.json). Only needed if you produced the proof yourself; prove_reserves submits automatically.',
    inputSchema: S({
      challengeId: str('The challenge_id being answered.'),
      response: { type: 'object', description: 'The response JSON object (por-response-v1).' },
      responsePath: str('Path to a response.json file to read and submit.'),
    }, ['challengeId']),
    handler: async (a) => {
      let response = a.response
      if (!response && a.responsePath) response = JSON.parse(readFileSync(a.responsePath, 'utf8'))
      if (!response) throw new Error('provide `response` (object) or `responsePath` (file path)')
      return verifierPost(`/v1/challenges/${encodeURIComponent(a.challengeId)}/response`, response)
    },
  },
  {
    name: 'prove_reserves',
    description: 'Run the full flow end-to-end: request a challenge, prove all 3 blocks locally with the `prover` binary, and submit — using connected mode. Returns a jobId immediately (proving takes ~15-30 min); poll get_prove_status. Requires the `prover` binary on PATH (or PROVER_BIN). privateKey is the reserve wallet key (comma-separate for multiple wallets); ownerKey defaults to privateKey. Keys stay in this local process.',
    inputSchema: S({
      agentId: str('Registered marketplace agent id.'),
      threshold: num('Minimum combined reserves in wei (decimal string).'),
      privateKey: str('Reserve wallet private key (0x hex); comma-separated list for multiple wallets. Stays local.'),
      chainId: num('Chain selector (default 1).'),
      ownerKey: str('Agent owner key that signs the challenge (defaults to privateKey\'s first key).'),
      notaryAddr: str('Override the TLSNotary notary host:port ("none" to disable — dev only).'),
    }, ['agentId', 'threshold', 'privateKey']),
    handler: async (a) => {
      const jobId = startProveJob({
        agentId: a.agentId, threshold: a.threshold, chainId: a.chainId,
        privateKey: a.privateKey, ownerKey: a.ownerKey, notaryAddr: a.notaryAddr,
      })
      return { jobId, state: jobs.get(jobId).state, message: 'Proving started in the background. Poll get_prove_status with this jobId (expect ~15-30 min).' }
    },
  },
  {
    name: 'get_prove_status',
    description: 'Poll a prove_reserves job. Returns state (proving | verified | rejected | error), the verdict/reason once done, and a tail of the prover log.',
    inputSchema: S({ jobId: str('The jobId from prove_reserves.') }, ['jobId']),
    handler: async (a) => {
      const j = jobs.get(a.jobId)
      if (!j) throw new Error(`unknown jobId ${a.jobId}`)
      return { jobId: a.jobId, state: j.state, verdict: j.verdict, reason: j.reason, exitCode: j.exitCode, elapsedSec: Math.round((Date.now() - j.startedAt) / 1000), log: clip(j.log, 2000) }
    },
  },
]
const TOOL_MAP = new Map(TOOLS.map((t) => [t.name, t]))

// --- resources --------------------------------------------------------------
const RESOURCES = [
  { uri: 'guide://proof-of-reserves', name: 'Agent guide', description: 'The external-agent guide (AGENT_GUIDE.md): register, prove, submit.', mimeType: 'text/markdown' },
  { uri: 'openapi://verifier', name: 'Verifier OpenAPI', description: 'OpenAPI 3.1 spec for the verifier HTTP API.', mimeType: 'application/json' },
]
async function readResource(uri) {
  if (uri === 'guide://proof-of-reserves') {
    const local = join(HERE, '..', '..', 'AGENT_GUIDE.md')
    const text = existsSync(local)
      ? readFileSync(local, 'utf8')
      : await fetch(`${VERIFIER_URL.replace(/verifier[^.]*/, 'ui')}/AGENT_GUIDE.md`).then((r) => r.text()).catch(() => '# Agent guide unavailable')
    return { uri, mimeType: 'text/markdown', text }
  }
  if (uri === 'openapi://verifier') {
    const text = await fetch(`${VERIFIER_URL}/v1/openapi.json`).then((r) => r.text())
    return { uri, mimeType: 'application/json', text }
  }
  throw new Error(`unknown resource ${uri}`)
}

// --- JSON-RPC dispatch ------------------------------------------------------
async function handleRpc(msg) {
  const { id, method, params } = msg
  const isNotification = id === undefined || id === null
  const reply = (result) => ({ jsonrpc: '2.0', id, result })
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } })
  try {
    switch (method) {
      case 'initialize':
        return reply({
          protocolVersion: params?.protocolVersion || PROTOCOL_VERSION,
          capabilities: { tools: {}, resources: {} },
          serverInfo: SERVER_INFO,
          instructions: 'Prove reserves privately. Typical flow: register_agent → request_challenge → prove_reserves → get_prove_status. Or drive the steps manually. Keys stay local.',
        })
      case 'notifications/initialized':
      case 'notifications/cancelled':
        return null // notifications get no response
      case 'ping':
        return reply({})
      case 'tools/list':
        return reply({ tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) })
      case 'tools/call': {
        const tool = TOOL_MAP.get(params?.name)
        if (!tool) return fail(-32602, `unknown tool: ${params?.name}`)
        try {
          const out = await tool.handler(params.arguments || {})
          return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out, isError: false })
        } catch (e) {
          return reply({ content: [{ type: 'text', text: `Error: ${e.shortMessage || e.message || String(e)}` }], isError: true })
        }
      }
      case 'resources/list':
        return reply({ resources: RESOURCES })
      case 'resources/read': {
        try {
          return reply({ contents: [await readResource(params?.uri)] })
        } catch (e) {
          return fail(-32602, e.message)
        }
      }
      case 'prompts/list':
        return reply({ prompts: [] })
      default:
        if (isNotification) return null
        return fail(-32601, `method not found: ${method}`)
    }
  } catch (e) {
    if (isNotification) return null
    return fail(-32603, e.message || String(e))
  }
}

// --- stdio transport (newline-delimited JSON) -------------------------------
function runStdio() {
  let buf = ''
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (chunk) => {
    buf += chunk
    let nl
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim()
      buf = buf.slice(nl + 1)
      if (!line) continue
      let msg
      try {
        msg = JSON.parse(line)
      } catch {
        log('bad JSON line ignored')
        continue
      }
      handleRpc(msg).then((res) => {
        if (res) process.stdout.write(JSON.stringify(res) + '\n')
      })
    }
  })
  process.stdin.on('end', () => process.exit(0))
  log(`stdio transport ready — verifier ${VERIFIER_URL}, prover "${PROVER_BIN}"`)
}

// --- HTTP transport (single request/response JSON-RPC) ----------------------
function runHttp(port) {
  const server = createServer(async (req, res) => {
    const cors = {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'content-type',
    }
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end() }
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
      res.writeHead(200, { ...cors, 'content-type': 'application/json' })
      return res.end(JSON.stringify({ ok: true, server: SERVER_INFO, transport: 'http-jsonrpc', endpoint: '/mcp', verifier: VERIFIER_URL, tools: TOOLS.map((t) => t.name) }))
    }
    if (req.method !== 'POST') { res.writeHead(405, cors); return res.end() }
    const chunks = []
    for await (const c of req) chunks.push(c)
    let body
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
    } catch {
      res.writeHead(400, { ...cors, 'content-type': 'application/json' })
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }))
    }
    const out = Array.isArray(body)
      ? (await Promise.all(body.map(handleRpc))).filter(Boolean)
      : await handleRpc(body)
    res.writeHead(200, { ...cors, 'content-type': 'application/json' })
    res.end(JSON.stringify(out ?? {}))
  })
  server.listen(port, () => log(`HTTP JSON-RPC transport on http://127.0.0.1:${port}/mcp — verifier ${VERIFIER_URL}`))
}

// --- entry ------------------------------------------------------------------
const argv = process.argv.slice(2)
const httpIdx = argv.indexOf('--http')
if (httpIdx >= 0) {
  const p = Number(argv[httpIdx + 1]) || Number(process.env.MCP_HTTP_PORT) || 8765
  runHttp(p)
} else {
  runStdio()
}
