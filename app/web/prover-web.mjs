// prover-web — the human, browser-wallet Proof-of-Reserves flow.
//
// Serves the built frontend + a small orchestration API, and drives the local `prover`
// binary in its two-phase browser-wallet mode so the wallet's private key never leaves the
// browser. One self-contained container: `docker run -p 8080:8080 …` → open localhost:8080.
//
// Flow (see /api/prove/* below):
//   1. browser connects wallet, POSTs {agentId, threshold, chainId, address}
//   2. we check address == the agent's registered owner, ask the verifier for a challenge,
//      run `prover --prepare` (fetch state, no key) → return the 32-byte messages to sign
//   3. browser personal_signs each message, POSTs the signatures
//   4. we run `prover --finalize` (attest + prove, minutes), submit to the verifier, and
//      surface the verdict via /api/prove/status polling
//
// Anything under /api that we don't own is proxied to the registry adapter (so the agent
// directory keeps working); everything else serves the static SPA.
//
// Env: PORT (8080), VERIFIER_URL (deployed verifier), NOTARY_ADDR (deployed notary),
//   REGISTRY_URL (adapter/UI base for owner lookup + /api proxy), PROVER_BIN (`prover`),
//   PUBLIC_DIR (built frontend), WORK_DIR (job scratch), plus any POR_* the prover reads
//   (POR_RPC_URL_<id>, POR_SEGMENT_PO2, POR_AGENT_TOKEN_ID/SECRET, RISC0_DEV_MODE) which we
//   pass straight through to the prover subprocess.
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync, readFileSync, existsSync, createReadStream, statSync, readdirSync } from 'node:fs'
import { join, extname, normalize } from 'node:path'
import { tmpdir } from 'node:os'

const PORT = Number(process.env.PORT || 8080)
const VERIFIER_URL = (process.env.VERIFIER_URL || 'https://verifier-production-d672.up.railway.app').replace(/\/$/, '')
const REGISTRY_URL = (process.env.REGISTRY_URL || 'https://ui-production-3e28.up.railway.app').replace(/\/$/, '')
const NOTARY_ADDR = process.env.NOTARY_ADDR || 'hayabusa.proxy.rlwy.net:39286'
const PROVER_BIN = process.env.PROVER_BIN || 'prover'
const PUBLIC_DIR = process.env.PUBLIC_DIR || join(process.cwd(), 'dist')
const WORK_DIR = process.env.WORK_DIR || join(tmpdir(), 'por-jobs')
mkdirSync(WORK_DIR, { recursive: true })

// One heavy prove at a time (proving is CPU/RAM-bound; concurrent proves OOM a laptop).
let proving = false
const jobs = new Map() // jobId -> { state, phase, verdict, reason, log, challengeId, dir, ... }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json' }

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body)
  res.writeHead(status, { 'content-type': typeof body === 'object' && !Buffer.isBuffer(body) ? 'application/json' : (headers['content-type'] || 'text/plain'), ...headers })
  res.end(data)
}

async function readBody(req, cap = 8 * 1024 * 1024) {
  const chunks = []
  let n = 0
  for await (const c of req) {
    n += c.length
    if (n > cap) throw new Error('body too large')
    chunks.push(c)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function appendLog(job, s) {
  job.log = (job.log + s).slice(-8000)
}

// --- durable jobs -----------------------------------------------------------
// Each job's state is mirrored to dir/job.json so a job survives a server restart
// (Railway redeploy, crash) and — combined with the client remembering its jobId — so a
// human who closes the browser mid-flow can reconnect and resume. `dir` is recomputed on
// load (never trusted from disk), so a moved WORK_DIR still resolves.
function persistable(job) {
  return {
    id: job.id, state: job.state, phase: job.phase, verdict: job.verdict, reason: job.reason,
    challengeId: job.challengeId, agentId: job.agentId, address: job.address,
    chainId: job.chainId, threshold: job.threshold,
    toSign: job.toSign || null, blocks: job.blocks || null, log: job.log || '', challenge: job.challenge,
  }
}

function saveJob(job) {
  try {
    writeFileSync(join(job.dir, 'job.json'), JSON.stringify(persistable(job)))
  } catch (e) {
    console.error(`saveJob ${job.id} failed: ${e.message}`)
  }
}

// Reload jobs from WORK_DIR on startup and resume any that were mid-prove. A job caught in
// `preparing` with no prepare.json can't be resumed (witnesses were never written); one caught
// in `proving` still has prepare.json + sigs.json on disk, so finalize can be re-run (or, if the
// receipt was already produced, just re-submitted). We serialize resumes through the prove slot.
function rehydrate() {
  let dirs
  try {
    dirs = readdirSync(WORK_DIR, { withFileTypes: true })
  } catch {
    return
  }
  for (const d of dirs) {
    if (!d.isDirectory()) continue
    const f = join(WORK_DIR, d.name, 'job.json')
    if (!existsSync(f)) continue
    let saved
    try {
      saved = JSON.parse(readFileSync(f, 'utf8'))
    } catch {
      continue
    }
    saved.dir = join(WORK_DIR, d.name) // recompute; never trust the stored path
    if (saved.state === 'preparing') {
      if (existsSync(join(saved.dir, 'prepare.json')) && saved.toSign) saved.state = 'awaiting-signatures'
      else {
        saved.state = 'error'
        saved.reason = 'preparation was interrupted by a restart; start a new proof'
      }
    }
    jobs.set(saved.id, saved)
  }
  const resumable = [...jobs.values()].filter((j) => j.state === 'proving')
  if (resumable.length) {
    console.log(`resuming ${resumable.length} interrupted proof(s)`)
    ;(async () => {
      for (const job of resumable) {
        while (proving) await sleep(1000)
        proving = true
        appendLog(job, `\n[resumed after a server restart]\n`)
        await runFinalizeAndSubmit(job) // clears `proving` in its finally
      }
    })()
  }
}

// Run the prover with a set of args, streaming stdout/stderr into the job log. The prover
// attests via the notary iff NOTARY_ADDR is set in its env — production requires it, so we
// pass it through; NOTARY_ADDR="none"/"" disables attestation (dev/no-notary runs).
function runProver(job, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    appendLog(job, `\n$ ${PROVER_BIN} ${args.join(' ')}\n`)
    const childEnv = { ...process.env, ...extraEnv }
    if (NOTARY_ADDR && NOTARY_ADDR !== 'none') childEnv.NOTARY_ADDR = NOTARY_ADDR
    else delete childEnv.NOTARY_ADDR
    const child = spawn(PROVER_BIN, args, { cwd: job.dir, env: childEnv })
    child.stdout.on('data', (d) => appendLog(job, d.toString()))
    child.stderr.on('data', (d) => appendLog(job, d.toString()))
    child.on('error', reject)
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`prover exited ${code}`))))
  })
}

// GET the agent's registered owner from the adapter (require-registration policy).
async function lookupOwner(agentId) {
  const r = await fetch(`${REGISTRY_URL}/api/agents/${encodeURIComponent(agentId)}`)
  if (!r.ok) return null
  const j = await r.json().catch(() => null)
  return j?.agent?.owner || j?.owner || null
}

// --- POST /api/prove/start ---------------------------------------------------
async function proveStart(req, res) {
  const body = JSON.parse(await readBody(req))
  const agentId = String(body.agentId || '').trim()
  const address = String(body.address || '').trim()
  const threshold = String(body.threshold || '').trim() // wei, decimal string
  const chainId = Number(body.chainId || 1)
  if (!agentId || !/^0x[0-9a-fA-F]{40}$/.test(address) || !/^\d+$/.test(threshold)) {
    return send(res, 400, { error: 'need agentId, a 0x address, and a decimal wei threshold' })
  }

  // Require registration: the connected wallet must be the agent's registered owner.
  const owner = await lookupOwner(agentId)
  if (!owner) return send(res, 404, { error: `agent "${agentId}" is not registered on the marketplace` })
  if (owner.toLowerCase() !== address.toLowerCase()) {
    return send(res, 403, { error: `connected wallet ${address} is not the registered owner (${owner}) of agent ${agentId}` })
  }

  // Ask the verifier for a challenge.
  const chReq = await fetch(`${VERIFIER_URL}/v1/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ agent_id: agentId, threshold, chain_id: chainId }),
  })
  const challenge = await chReq.json().catch(() => null)
  if (!chReq.ok || !challenge?.challenge_id) {
    // Surface the verifier's actual reason (e.g. "agent not found in registry",
    // "unsupported chain_id") instead of a generic message.
    const why = challenge?.error || (typeof challenge === 'string' ? challenge : JSON.stringify(challenge))
    return send(res, 502, { error: `verifier didn't issue a challenge: ${why}`, detail: challenge })
  }

  const jobId = randomBytes(8).toString('hex')
  const dir = join(WORK_DIR, jobId)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'challenge.json'), JSON.stringify(challenge))
  const job = { id: jobId, state: 'preparing', phase: 'Fetching on-chain state', verdict: null, reason: null, log: '', challengeId: challenge.challenge_id, dir, agentId, address, chainId: challenge.chain_id, threshold, challenge, toSign: null, blocks: null }
  jobs.set(jobId, job)
  saveJob(job)

  // Prepare: fetch the account proof + header for each block, emit the to-sign messages.
  try {
    await runProver(job, ['--prepare', '--challenge', 'challenge.json', '--address', address, '--out', 'prepare.json'])
  } catch (e) {
    job.state = 'error'
    job.reason = /balance .* < threshold/.test(job.log) ? 'wallet balance is below the threshold at one of the challenged blocks' : `prepare failed: ${e.message}`
    saveJob(job)
    return send(res, 200, { jobId, error: job.reason, log: job.log })
  }
  const prepared = JSON.parse(readFileSync(join(dir, 'prepare.json'), 'utf8'))
  // Stash the to-sign messages + block list on the job so /status can serve them: a browser
  // that reconnects while awaiting signatures needs them to re-prompt the wallet.
  job.toSign = {
    blockHashes: prepared.to_sign.block_hashes, // personal_sign each (raw 32 bytes)
    challengePrehash: prepared.to_sign.challenge_prehash,
  }
  job.blocks = prepared.blocks.map((b) => ({ number: b.block_number, hash: b.block_hash }))
  job.state = 'awaiting-signatures'
  job.phase = 'Waiting for wallet signatures'
  saveJob(job)
  return send(res, 200, {
    jobId,
    challengeId: challenge.challenge_id,
    chainId: challenge.chain_id,
    threshold,
    toSign: job.toSign,
    blocks: job.blocks,
  })
}

// --- POST /api/prove/finalize ------------------------------------------------
async function proveFinalize(req, res) {
  const body = JSON.parse(await readBody(req))
  const jobId = String(body.jobId || '')
  const job = jobs.get(jobId)
  if (!job) return send(res, 404, { error: 'unknown job' })
  if (job.state !== 'awaiting-signatures') return send(res, 409, { error: `job is ${job.state}` })
  const blockSigs = body.blockSigs
  const ownerSig = body.ownerSig
  if (!Array.isArray(blockSigs) || !ownerSig) return send(res, 400, { error: 'need blockSigs[] and ownerSig' })
  if (proving) return send(res, 429, { error: 'the prover is busy with another proof; try again shortly' })

  writeFileSync(join(job.dir, 'sigs.json'), JSON.stringify({ block_sigs: blockSigs, owner_sig: ownerSig }))
  job.state = 'proving'
  job.phase = 'Attesting + proving (this takes a few minutes)'
  proving = true
  saveJob(job)
  send(res, 202, { jobId, state: job.state })
  runFinalizeAndSubmit(job) // background; clears `proving` in its finally
}

// Finalize (attest + prove) → submit to the verifier → record the verdict. Shared by the
// live finalize request and the startup resume of an interrupted `proving` job, so it must be
// idempotent: if response.json already exists (finalize ran in a previous life) we skip the
// multi-minute prove and re-submit; if the verifier says "already answered", we fetch the
// authoritative verdict instead of trusting that reply. Assumes the caller holds the prove slot.
async function runFinalizeAndSubmit(job) {
  try {
    if (!existsSync(join(job.dir, 'response.json'))) {
      job.phase = 'Attesting + proving (this takes a few minutes)'
      saveJob(job)
      await runProver(job, ['--finalize', '--prepared', 'prepare.json', '--sigs', 'sigs.json', '--out', 'response.json'])
    }
    job.phase = 'Submitting to the verifier'
    saveJob(job)
    const response = readFileSync(join(job.dir, 'response.json'), 'utf8')
    const sub = await fetch(`${VERIFIER_URL}/v1/challenges/${job.challengeId}/response`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: response,
    })
    let verdict = await sub.json().catch(() => null)
    if (verdict?.reason && /already answered/i.test(String(verdict.reason))) {
      const st = await fetch(`${VERIFIER_URL}/v1/challenges/${job.challengeId}`).then((r) => r.json()).catch(() => null)
      if (st?.verdict) verdict = { verdict: st.verdict, reason: st.reason }
    }
    job.verdict = verdict?.verdict || 'unknown'
    job.reason = verdict?.reason || null
    job.state = job.verdict === 'verified' ? 'verified' : 'rejected'
    job.phase = job.verdict === 'verified' ? 'Verified' : 'Rejected'
    appendLog(job, `\nverdict: ${job.verdict}${job.reason ? ' — ' + job.reason : ''}\n`)
  } catch (e) {
    job.state = 'error'
    job.reason = e.message
    appendLog(job, `\nerror: ${e.message}\n`)
  } finally {
    proving = false
    saveJob(job)
  }
}

// --- GET /api/prove/status/:id -----------------------------------------------
// Full enough to rebuild the UI from scratch: a reconnecting browser rehydrates from this
// alone (toSign/blocks let it re-prompt the wallet when the job is awaiting signatures).
function proveStatus(res, jobId) {
  const job = jobs.get(jobId)
  if (!job) return send(res, 404, { error: 'unknown job' })
  send(res, 200, {
    jobId,
    state: job.state,
    phase: job.phase,
    verdict: job.verdict,
    reason: job.reason,
    challengeId: job.challengeId,
    chainId: job.chainId,
    threshold: job.threshold,
    agentId: job.agentId,
    address: job.address,
    toSign: job.toSign || null,
    blocks: job.blocks || null,
    log: (job.log || '').slice(-4000),
  })
}

// Proxy any other /api/* (GET) to the registry adapter so the directory keeps working.
async function proxyRegistry(req, res, path) {
  try {
    const r = await fetch(`${REGISTRY_URL}${path}`, { headers: { accept: 'application/json' } })
    const buf = Buffer.from(await r.arrayBuffer())
    send(res, r.status, buf, { 'content-type': r.headers.get('content-type') || 'application/json' })
  } catch (e) {
    send(res, 502, { error: 'registry proxy failed', detail: e.message })
  }
}

function serveStatic(res, urlPath) {
  let rel = decodeURIComponent(urlPath.split('?')[0])
  if (rel === '/' || rel === '') rel = '/index.html'
  let file = normalize(join(PUBLIC_DIR, rel))
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, 'forbidden')
  if (!existsSync(file) || !statSync(file).isFile()) file = join(PUBLIC_DIR, 'index.html') // SPA fallback
  if (!existsSync(file)) return send(res, 404, 'not found (frontend not built)')
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' })
  createReadStream(file).pipe(res)
}

const server = createServer(async (req, res) => {
  try {
    const url = req.url || '/'
    const path = url.split('?')[0]
    if (path === '/api/health') return send(res, 200, { ok: true, verifier: VERIFIER_URL, notary: NOTARY_ADDR })
    if (req.method === 'POST' && path === '/api/prove/start') return await proveStart(req, res)
    if (req.method === 'POST' && path === '/api/prove/finalize') return await proveFinalize(req, res)
    if (req.method === 'GET' && path.startsWith('/api/prove/status/')) return proveStatus(res, path.slice('/api/prove/status/'.length))
    if (path.startsWith('/api/')) return await proxyRegistry(req, res, url)
    return serveStatic(res, url)
  } catch (e) {
    send(res, 500, { error: e.message })
  }
})

rehydrate() // reload persisted jobs + resume any interrupted proof

server.listen(PORT, () => {
  console.log(`prover-web on http://0.0.0.0:${PORT}`)
  console.log(`  verifier ${VERIFIER_URL}`)
  console.log(`  notary   ${NOTARY_ADDR}`)
  console.log(`  registry ${REGISTRY_URL}  (owner lookup + /api proxy)`)
  console.log(`  prover   ${PROVER_BIN}   static ${PUBLIC_DIR}`)
})
