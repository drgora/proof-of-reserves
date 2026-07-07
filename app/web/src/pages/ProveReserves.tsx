import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi'
import { parseEther } from 'viem'
import { marketplaceAgentUrl } from '../chain'

// The chain SELECTORS the deployed (testnet) verifier accepts. It resolves each to its
// paired testnet, so you prove a testnet native balance — fund from a faucet.
const CHAINS = [
  { id: 1, label: 'Sepolia', coin: 'ETH' },
  { id: 10, label: 'Optimism Sepolia', coin: 'ETH' },
  { id: 8453, label: 'Base Sepolia', coin: 'ETH' },
]

type ToSign = {
  blockHashes: `0x${string}`[]
  challengePrehash: `0x${string}`
  // Text message signed to derive the agent's per-agent marketplace identity secret. Optional
  // so a job prepared before this shipped still resumes (the proof just won't be recordable).
  identityMessage?: string
}
type StartResp = {
  jobId?: string
  challengeId?: string
  chainId?: number
  toSign?: ToSign
  blocks?: { number: number; hash: string }[]
  error?: string
}
type State = 'preparing' | 'awaiting-signatures' | 'proving' | 'verified' | 'rejected' | 'error'
type Status = {
  state: State
  phase: string
  verdict: string | null
  reason: string | null
  log: string
  challengeId?: string
  chainId?: number
  toSign?: ToSign | null
  blocks?: { number: number; hash: string }[] | null
}

// A challenge is minutes-to-an-hour of work; we remember just enough in localStorage to
// reconnect a browser that was closed or refreshed mid-flow. The backend keeps the heavy
// state (and keeps proving) — this only holds the pointer + the human-facing form values.
const STORAGE_KEY = 'por.activeJob.v1'
type Active = { jobId: string; agentId: string; chainId: number; amount: string; address?: string }
function saveActive(a: Active) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(a))
  } catch {}
}
function loadActive(): Active | null {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null')
  } catch {
    return null
  }
}
function clearActive() {
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {}
}

const short = (a?: string) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const TERMINAL: State[] = ['verified', 'rejected', 'error']

export default function ProveReserves() {
  const { address, isConnected } = useAccount()
  const { connect, connectors, isPending: connecting } = useConnect()
  const { disconnect } = useDisconnect()
  const { signMessageAsync } = useSignMessage()

  const [agentId, setAgentId] = useState('')
  const [chainId, setChainId] = useState(1)
  const [amount, setAmount] = useState('0.05')

  const [phase, setPhase] = useState<string>('') // human-facing step label
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [start, setStart] = useState<StartResp | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [signCount, setSignCount] = useState(0)
  // True when we reconnected to a job that's waiting for wallet signatures: signing needs a
  // fresh user gesture (and a connected wallet), so we can't auto-resume it — we prompt.
  const [resuming, setResuming] = useState(false)

  const chain = CHAINS.find((c) => c.id === chainId) || CHAINS[0]
  const thresholdWei = useMemo(() => {
    try {
      return parseEther(amount as `${number}`).toString()
    } catch {
      return null
    }
  }, [amount])

  const done = !!status && TERMINAL.includes(status.state)
  const running = (busy || (!!status && !done)) && !resuming
  const canProve = isConnected && agentId.trim() && thresholdWei && !busy && !resuming

  // Poll status until the job reaches a resume/terminal point. Returns the last status.
  async function pollUntil(jobId: string): Promise<Status> {
    for (;;) {
      await sleep(2500)
      const st: Status = await fetch(`/api/prove/status/${jobId}`).then((r) => r.json())
      setStatus(st)
      setPhase(st.phase)
      // awaiting-signatures is a resume point (we can only reach it when reconnecting to a
      // job that hadn't been signed yet); terminal states end the poll.
      if (TERMINAL.includes(st.state) || st.state === 'awaiting-signatures') return st
    }
  }

  // Sign the messages the verifier chose (one per block + the challenge), hand them back so
  // the backend proves + submits, then poll for the verdict. Shared by the fresh run and the
  // resume-from-awaiting-signatures path.
  async function signFinalizePoll(jobId: string, toSign: ToSign) {
    const msgs = toSign.blockHashes
    const hasIdentity = !!toSign.identityMessage
    const total = msgs.length + 1 + (hasIdentity ? 1 : 0) // blocks + challenge + (identity)
    const sigs: `0x${string}`[] = []
    for (let i = 0; i < msgs.length; i++) {
      setPhase(`Sign ${i + 1} of ${total} in your wallet — block ownership`)
      sigs.push(await signMessageAsync({ message: { raw: msgs[i] } }))
      setSignCount(i + 1)
    }
    setPhase(`Sign ${msgs.length + 1} of ${total} in your wallet — the challenge`)
    const ownerSig = await signMessageAsync({ message: { raw: toSign.challengePrehash } })
    setSignCount(msgs.length + 1)

    // Identity binding: derives the agent's per-agent marketplace secret in the wallet — the
    // private key never leaves the browser. Signed as readable text, so the wallet shows intent.
    let identitySig: `0x${string}` | undefined
    if (toSign.identityMessage) {
      setPhase(`Sign ${total} of ${total} in your wallet — agent identity`)
      identitySig = await signMessageAsync({ message: toSign.identityMessage })
      setSignCount(total)
    }

    setPhase('Attesting + proving — this takes a few minutes…')
    const fin = await fetch('/api/prove/finalize', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jobId, blockSigs: sigs, ownerSig, identitySig }),
    }).then((r) => r.json())
    if (fin.error) throw new Error(fin.error)

    const st = await pollUntil(jobId)
    if (st.state === 'awaiting-signatures') setResuming(true) // shouldn't happen post-finalize
  }

  // On mount: if we have a saved in-progress job, reconnect to it and resume the right UI.
  // The per-invocation `cancelled` flag makes this safe under React StrictMode's double-mount.
  useEffect(() => {
    const active = loadActive()
    if (!active?.jobId) return
    let cancelled = false
    ;(async () => {
      const st: Status | null = await fetch(`/api/prove/status/${active.jobId}`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null)
      if (cancelled) return
      if (!st || (st as any).error || !st.state) {
        clearActive() // the server no longer knows this job
        return
      }
      // Restore the form so result/labels read correctly.
      setAgentId(active.agentId || '')
      setChainId(active.chainId || 1)
      setAmount(active.amount || '0.05')
      setStart({ jobId: active.jobId, challengeId: st.challengeId, chainId: st.chainId, toSign: st.toSign || undefined, blocks: st.blocks || undefined })
      setStatus(st)
      setPhase(st.phase || '')

      if (TERMINAL.includes(st.state)) return // already finished — just show the result
      if (st.state === 'awaiting-signatures') {
        setResuming(true) // needs a user gesture to re-sign; show the resume card
        return
      }
      // preparing / proving: the backend is still working — reattach the poll.
      setBusy(true)
      try {
        const last = await pollUntil(active.jobId)
        if (!cancelled && last.state === 'awaiting-signatures') setResuming(true)
      } catch (e: any) {
        if (!cancelled) setError(e?.shortMessage || e?.message || String(e))
      } finally {
        if (!cancelled) setBusy(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  function reset() {
    clearActive()
    setStart(null)
    setStatus(null)
    setError(null)
    setResuming(false)
    setSignCount(0)
    setPhase('')
  }

  async function run() {
    reset()
    if (!thresholdWei) return setError('Enter a valid amount, e.g. 0.05')
    setBusy(true)
    try {
      // 1. Ask the backend to issue a challenge + fetch state (owner check happens here).
      setPhase('Requesting challenge & reading on-chain state…')
      const s: StartResp = await fetch('/api/prove/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ agentId: agentId.trim(), threshold: thresholdWei, chainId, address }),
      }).then((r) => r.json())
      if (!s.jobId || s.error) throw new Error(s.error || 'could not start')
      setStart(s)
      // Remember the job the moment it exists, so a close/refresh before the verdict resumes.
      saveActive({ jobId: s.jobId, agentId: agentId.trim(), chainId, amount, address })

      // 2. Sign, 3. finalize, 4. poll — the wallet's key never leaves the browser.
      await signFinalizePoll(s.jobId, s.toSign!)
    } catch (e: any) {
      setError(e?.shortMessage || e?.message || String(e))
    } finally {
      setBusy(false)
    }
  }

  // Continue a reconnected job that was left waiting for signatures.
  async function resumeSigning() {
    if (!start?.jobId || !start.toSign) return
    setError(null)
    setResuming(false)
    setSignCount(0)
    setBusy(true)
    try {
      await signFinalizePoll(start.jobId, start.toSign)
    } catch (e: any) {
      setError(e?.shortMessage || e?.message || String(e))
      setResuming(true) // let them try again
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="prove">
      <div className="prove-hero">
        <span className="eyebrow">Prove your reserves</span>
        <h1>
          Prove you hold the funds — <span className="grad">reveal nothing else</span>
        </h1>
        <p className="prove-lede">
          Prove your wallet holds at least a threshold of a chain's native coin at three
          unpredictable, finalized blocks — without disclosing the balance or the address.
          You sign in your browser; the private key never leaves your wallet.
        </p>
      </div>

      <div className="prove-grid">
        {/* left: the form */}
        <div className="panel prove-form">
          <div className="prove-wallet">
            {isConnected ? (
              <>
                <span className="badge ok">Wallet connected</span>
                <span className="mono">{short(address)}</span>
                <button className="btn ghost small" onClick={() => disconnect()} disabled={busy || resuming}>
                  Disconnect
                </button>
              </>
            ) : (
              <button
                className="btn"
                onClick={() => connect({ connector: connectors[0] })}
                disabled={connecting || !connectors[0]}
              >
                {connecting ? 'Connecting…' : 'Connect wallet'}
              </button>
            )}
          </div>

          <label className="field">
            <span>Agent ID</span>
            <input
              className="input"
              placeholder="your marketplace agent id, e.g. 0x16ec"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              disabled={busy || resuming}
            />
            <small>
              The connected wallet must be this agent's registered owner. Not registered?{' '}
              <a href="https://agent-registry.horizenlabs.io" target="_blank" rel="noreferrer">
                Agent Marketplace ↗
              </a>
            </small>
          </label>

          <div className="field-row">
            <label className="field">
              <span>Chain</span>
              <select className="input" value={chainId} onChange={(e) => setChainId(Number(e.target.value))} disabled={busy || resuming}>
                {CHAINS.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Threshold ({chain.coin})</span>
              <input
                className="input"
                inputMode="decimal"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                disabled={busy || resuming}
              />
              <small>{thresholdWei ? `${thresholdWei} wei` : 'invalid amount'}</small>
            </label>
          </div>

          <button className="btn primary block" onClick={run} disabled={!canProve}>
            {busy ? 'Proving…' : 'Prove reserves'}
          </button>
          {!isConnected && <small className="hint">Connect a wallet to begin.</small>}
        </div>

        {/* right: progress / result */}
        <div className="panel prove-status">
          {!resuming && !running && !status && !error && (
            <div className="prove-idle">
              <h3>How it works</h3>
              <ol className="prove-steps">
                <li>The verifier picks 3 recent, unpredictable blocks.</li>
                <li>You sign one message per block, the challenge, and a one-time agent identity (no gas).</li>
                <li>A zkVM proof is generated and checked — balance &amp; address stay private.</li>
              </ol>
              <p className="fine">Proving runs after you sign and takes a few minutes.</p>
              <p className="fine">
                Safe to close this tab: proving continues on the server and this page reconnects to
                your challenge when you return.
              </p>
            </div>
          )}

          {resuming && (
            <div className="prove-running">
              <span className="badge">↻ Resumed challenge</span>
              <div className="phase">
                We reconnected to a proof waiting for your wallet signatures. Sign to finish — no gas.
              </div>
              {start?.blocks && (
                <div className="blocks">
                  <span className="blocks-label">Challenged blocks ({chain.label})</span>
                  {start.blocks.map((b) => (
                    <span key={b.number} className="mono block-pill">
                      #{b.number}
                    </span>
                  ))}
                </div>
              )}
              <div className="result-actions">
                {isConnected ? (
                  <button className="btn primary" onClick={resumeSigning}>
                    Continue signing
                  </button>
                ) : (
                  <button className="btn" onClick={() => connect({ connector: connectors[0] })} disabled={connecting || !connectors[0]}>
                    {connecting ? 'Connecting…' : 'Reconnect wallet to continue'}
                  </button>
                )}
                <button className="btn ghost" onClick={reset}>
                  Start over
                </button>
              </div>
            </div>
          )}

          {running && !done && (
            <div className="prove-running">
              <div className="spinner" />
              <div className="phase">{phase}</div>
              {start?.toSign && (
                <div className="sign-dots">
                  {Array.from({ length: start.toSign.blockHashes.length + 1 + (start.toSign.identityMessage ? 1 : 0) }).map((_, i) => (
                    <span key={i} className={`dot ${i < signCount ? 'done' : ''}`} />
                  ))}
                </div>
              )}
              {start?.blocks && (
                <div className="blocks">
                  <span className="blocks-label">Challenged blocks ({chain.label})</span>
                  {start.blocks.map((b) => (
                    <span key={b.number} className="mono block-pill">
                      #{b.number}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {done && status!.state === 'verified' && (
            <div className="prove-result ok">
              <span className="badge ok big">✓ Verified</span>
              <p>
                Your reserves of ≥ {amount} {chain.coin} on {chain.label} are proven for challenge{' '}
                <span className="mono">{short(start?.challengeId)}</span>.
              </p>
              <div className="result-actions">
                <a className="btn" href={marketplaceAgentUrl(undefined, agentId.trim())} target="_blank" rel="noreferrer">
                  View agent on marketplace ↗
                </a>
                <Link className="btn ghost" to={`/agent/${agentId.trim()}`}>
                  Open in directory
                </Link>
                <button className="btn ghost" onClick={reset}>
                  Start over
                </button>
              </div>
            </div>
          )}

          {done && status!.state !== 'verified' && (
            <div className="prove-result bad">
              <span className="badge bad big">✕ {status!.state === 'rejected' ? 'Rejected' : 'Error'}</span>
              <p>{status!.reason || 'The proof was not accepted.'}</p>
              <div className="result-actions">
                <button className="btn ghost" onClick={reset}>
                  Start over
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="error-box" style={{ marginTop: 12 }}>
              {error}
            </div>
          )}

          {(running || status) && (
            <details className="prove-log">
              <summary>Prover log</summary>
              <pre>{status?.log || '…'}</pre>
            </details>
          )}
        </div>
      </div>
    </div>
  )
}
