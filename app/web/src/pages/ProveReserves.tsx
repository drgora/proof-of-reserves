import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi'
import { parseEther, recoverMessageAddress } from 'viem'
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
  // Two wallet roles: `address` = the reserves wallet F whose funds we prove (signs the block
  // ownership messages); `owner` = the agent's registered owner O that must authorize the
  // challenge (signs owner_sig + identity). F and O may — and ideally should — be different.
  address?: string
  owner?: string
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
  address?: string
  owner?: string | null
  toSign?: ToSign | null
  blocks?: { number: number; hash: string }[] | null
}

// A challenge is minutes-to-an-hour of work; we remember just enough in localStorage to
// reconnect a browser that was closed or refreshed mid-flow. The backend keeps the heavy
// state (and keeps proving) — this only holds the pointer + the human-facing form values.
const STORAGE_KEY = 'por.activeJob.v1'
type Active = { jobId: string; agentId: string; chainId: number; amount: string; reserves?: string; owner?: string }
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

const short = (a?: string | null) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')
const eq = (a?: string | null, b?: string | null) => !!a && !!b && a.toLowerCase() === b.toLowerCase()
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const TERMINAL: State[] = ['verified', 'rejected', 'error']

type SwitchTo = { to: string; role: 'reserves' | 'owner' } | null

export default function ProveReserves() {
  const { address, isConnected } = useAccount()
  const { connect, connectors, isPending: connecting } = useConnect()
  const { disconnect } = useDisconnect()
  const { signMessageAsync } = useSignMessage()

  const [agentId, setAgentId] = useState('')
  const [chainId, setChainId] = useState(1)
  const [amount, setAmount] = useState('0.05')
  // Advanced, optional: a custom 32-byte identity secret. Blank = derive from the wallet.
  // Not persisted anywhere (it's key material) — re-enter it if you resume a challenge.
  const [customSecret, setCustomSecret] = useState('')

  const [phase, setPhase] = useState<string>('') // human-facing step label
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [start, setStart] = useState<StartResp | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [signCount, setSignCount] = useState(0)
  // When set, we're paused waiting for the user to switch their wallet to a specific account
  // (the two-account flow: reserves wallet F signs block ownership; owner O authorizes).
  const [needSwitch, setNeedSwitch] = useState<SwitchTo>(null)
  // True when we reconnected to a job that's waiting for wallet signatures: signing needs a
  // fresh user gesture (and a connected wallet), so we can't auto-resume it — we prompt.
  const [resuming, setResuming] = useState(false)

  // The live wallet account, mirrored into a ref so async signing loops can poll it across
  // account switches without being closed over a stale value.
  const addrRef = useRef<string | undefined>(address)
  useEffect(() => {
    addrRef.current = address
  }, [address])
  // Set by the Cancel button to break out of an account-switch wait.
  const abortRef = useRef(false)

  const chain = CHAINS.find((c) => c.id === chainId) || CHAINS[0]
  const thresholdWei = useMemo(() => {
    try {
      return parseEther(amount as `${number}`).toString()
    } catch {
      return null
    }
  }, [amount])

  const secretTrimmed = customSecret.trim()
  const secretValid = !secretTrimmed || /^0x[0-9a-fA-F]{64}$/.test(secretTrimmed)
  const done = !!status && TERMINAL.includes(status.state)
  const running = (busy || (!!status && !done)) && !resuming
  const canProve = isConnected && agentId.trim() && thresholdWei && secretValid && !busy && !resuming
  // Warn (softly) when the reserves wallet being proven (F) is also the agent owner (O) — allowed,
  // but the recommended flow proves a wallet distinct from the public owner identity. Compare the
  // job's F/O (not the live `address`, which becomes O during the authorize step even when F ≠ O).
  const provingOwnWallet = eq(start?.address, start?.owner)

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

  // Block until the wallet's active account equals `target`, prompting the user to switch. The
  // injected connector updates useAccount() on `accountsChanged`, so the ref-poll resolves once
  // the user selects the right account in their wallet. Cancel (abortRef) throws to bail out.
  async function ensureAccount(target: string, role: 'reserves' | 'owner') {
    if (eq(addrRef.current, target)) return
    setNeedSwitch({ to: target, role })
    while (!eq(addrRef.current, target)) {
      if (abortRef.current) {
        setNeedSwitch(null)
        throw new Error('cancelled — switch to the requested account and try again')
      }
      await sleep(400)
    }
    setNeedSwitch(null)
  }

  // Sign the messages the verifier chose, then hand them to the backend to prove + submit, then
  // poll for the verdict. TWO accounts: the reserves wallet F signs each block's ownership
  // message; the owner O signs the challenge (+ identity). Shared by the fresh run and the
  // resume-from-awaiting-signatures path.
  async function signFinalizePoll(jobId: string, toSign: ToSign, reserves: string, owner: string) {
    abortRef.current = false
    const msgs = toSign.blockHashes
    const agentSecret = customSecret.trim() // advanced override; blank = derive from the wallet
    // A custom secret replaces the wallet-derived one, so the identity signature isn't needed.
    const signIdentity = !!toSign.identityMessage && !agentSecret
    const total = msgs.length + 1 + (signIdentity ? 1 : 0) // blocks + challenge + (identity)

    // Phase A — the reserves wallet F proves it controls the funds at each challenged block.
    await ensureAccount(reserves, 'reserves')
    const sigs: `0x${string}`[] = []
    for (let i = 0; i < msgs.length; i++) {
      // A switch back to F (e.g. the user wandered off O) is possible between signatures.
      await ensureAccount(reserves, 'reserves')
      setPhase(`Sign ${i + 1} of ${total} with your reserves wallet — block ownership`)
      sigs.push(await signMessageAsync({ message: { raw: msgs[i] } }))
      setSignCount(i + 1)
    }

    // Phase B — the agent owner O authorizes the challenge so the verifier can authenticate the
    // agent. If F ≠ O the user switches accounts here; if F == O this resolves immediately.
    await ensureAccount(owner, 'owner')
    setPhase(`Sign ${msgs.length + 1} of ${total} with your owner wallet — the challenge`)
    const ownerSig = await signMessageAsync({ message: { raw: toSign.challengePrehash } })
    setSignCount(msgs.length + 1)

    // Identity binding: derives the agent's per-agent marketplace secret in the wallet — the
    // private key never leaves the browser. Signed as readable text by the OWNER, so the derived
    // secret stays tied to the agent identity (stable across proofs → matches the on-chain commitment).
    let identitySig: `0x${string}` | undefined
    if (signIdentity) {
      await ensureAccount(owner, 'owner')
      setPhase(`Sign ${total} of ${total} with your owner wallet — agent identity`)
      identitySig = await signMessageAsync({ message: toSign.identityMessage! })
      setSignCount(total)
    }

    // Fail fast: the owner signature MUST recover to O, else the verifier rejects after minutes
    // of proving. Guards against a wallet that signed with an unexpected account.
    const recovered = await recoverMessageAddress({ message: { raw: toSign.challengePrehash }, signature: ownerSig })
    if (!eq(recovered, owner)) {
      throw new Error(
        `the challenge was authorized by ${short(recovered)}, not the agent owner ${short(owner)} — switch to the owner account and retry`,
      )
    }

    setPhase('Attesting + proving — this takes a few minutes…')
    const fin = await fetch('/api/prove/finalize', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jobId, blockSigs: sigs, ownerSig, identitySig, agentSecret: agentSecret || undefined }),
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
      setStart({
        jobId: active.jobId,
        challengeId: st.challengeId,
        chainId: st.chainId,
        address: st.address || active.reserves, // reserves wallet F
        owner: st.owner || active.owner, // agent owner O
        toSign: st.toSign || undefined,
        blocks: st.blocks || undefined,
      })
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
    abortRef.current = true
    clearActive()
    setStart(null)
    setStatus(null)
    setError(null)
    setResuming(false)
    setNeedSwitch(null)
    setSignCount(0)
    setPhase('')
  }

  function cancelFlow() {
    abortRef.current = true // breaks the account-switch wait; the catch surfaces it
    setNeedSwitch(null)
  }

  async function run() {
    reset()
    if (!thresholdWei) return setError('Enter a valid amount, e.g. 0.05')
    if (!address) return setError('Connect your reserves wallet first')
    const reserves = address // F = the currently-connected account = the reserves wallet
    setBusy(true)
    try {
      // 1. Ask the backend to issue a challenge + fetch state (looks up the agent's owner O).
      setPhase('Requesting challenge & reading on-chain state…')
      const s: StartResp = await fetch('/api/prove/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ agentId: agentId.trim(), threshold: thresholdWei, chainId, address: reserves }),
      }).then((r) => r.json())
      if (!s.jobId || s.error) throw new Error(s.error || 'could not start')
      if (!s.owner) throw new Error('the verifier did not return the agent owner; cannot authorize')
      setStart({ ...s, address: reserves })
      // Remember the job the moment it exists, so a close/refresh before the verdict resumes.
      saveActive({ jobId: s.jobId, agentId: agentId.trim(), chainId, amount, reserves, owner: s.owner })

      // 2. Sign (F then O), 3. finalize, 4. poll — both wallets' keys stay in the browser.
      await signFinalizePoll(s.jobId, s.toSign!, reserves, s.owner)
    } catch (e: any) {
      setError(e?.shortMessage || e?.message || String(e))
    } finally {
      setBusy(false)
    }
  }

  // Continue a reconnected job that was left waiting for signatures.
  async function resumeSigning() {
    if (!start?.jobId || !start.toSign) return
    if (!start.address || !start.owner) {
      setError('this challenge predates the reserves/owner split — please start over')
      return
    }
    setError(null)
    setResuming(false)
    setSignCount(0)
    setBusy(true)
    try {
      await signFinalizePoll(start.jobId, start.toSign, start.address, start.owner)
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
                <span className="badge ok">Reserves wallet</span>
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
                {connecting ? 'Connecting…' : 'Connect reserves wallet'}
              </button>
            )}
          </div>

          <div className="notice prove-privacy">
            <span className="dot">●</span>
            <div>
              <b>Prove a wallet that isn't your agent's owner.</b> Connect the treasury whose balance
              you want to prove — ideally a <em>different</em> account from your agent's registered
              owner. You'll switch to the owner account to authorize the challenge in a later step
              (an account switch, no gas). Keeping them separate leaves your funded wallet unlinkable
              from your public agent identity.
            </div>
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
              The agent must be registered; you'll authorize with its owner account. Not registered?{' '}
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

          <details className="advanced">
            <summary>Advanced: custom identity secret</summary>
            <label className="field">
              <span>Identity secret (optional)</span>
              <input
                className="input mono"
                placeholder="0x… 32-byte hex — leave blank to derive from your wallet"
                value={customSecret}
                onChange={(e) => setCustomSecret(e.target.value)}
                disabled={busy || resuming}
                spellCheck={false}
                autoComplete="off"
              />
              {secretValid ? (
                <small>
                  Leave blank and your secret is derived from a one-time owner-wallet signature. Set
                  this only if your agent's marketplace commitment was registered under a specific
                  secret. Sent to this prover; never stored or persisted.
                </small>
              ) : (
                <small className="err">Must be 0x followed by 64 hex characters (32 bytes).</small>
              )}
            </label>
          </details>

          <button className="btn primary block" onClick={run} disabled={!canProve}>
            {busy ? 'Proving…' : 'Prove reserves'}
          </button>
          {!isConnected && <small className="hint">Connect your reserves wallet to begin.</small>}
        </div>

        {/* right: progress / result */}
        <div className="panel prove-status">
          {!resuming && !running && !status && !error && (
            <div className="prove-idle">
              <h3>How it works</h3>
              <ol className="prove-steps">
                <li>The verifier picks 3 recent, unpredictable blocks.</li>
                <li>
                  Your <b>reserves wallet</b> signs one message per block to prove it controls the
                  funds (no gas).
                </li>
                <li>
                  You switch to the <b>agent owner</b> account and sign the challenge + a one-time
                  identity to authorize (no gas).
                </li>
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
              {start?.address && (
                <p className="fine">
                  Reserves wallet <span className="mono">{short(start.address)}</span>
                  {start.owner && !eq(start.address, start.owner) && (
                    <>
                      {' '}· owner <span className="mono">{short(start.owner)}</span>
                    </>
                  )}
                </p>
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
              {needSwitch ? (
                <div className="switch-card">
                  <span className="badge">↻ Switch wallet account</span>
                  <div className="phase">
                    Switch to your {needSwitch.role === 'owner' ? 'agent owner' : 'reserves'} account
                  </div>
                  <div className="switch-target mono">{needSwitch.to}</div>
                  <p className="fine">
                    {needSwitch.role === 'owner'
                      ? 'This authorizes the challenge as the agent’s registered owner — no gas.'
                      : 'This is the wallet whose reserves you’re proving — no gas.'}
                  </p>
                  <p className="fine">
                    Connected now: <span className="mono">{short(address) || 'none'}</span>
                  </p>
                  <button className="btn ghost small" onClick={cancelFlow}>
                    Cancel
                  </button>
                </div>
              ) : (
                <>
                  <div className="spinner" />
                  <div className="phase">{phase}</div>
                </>
              )}
              {start?.toSign && !needSwitch && (
                <div className="sign-dots">
                  {Array.from({ length: start.toSign.blockHashes.length + 1 + (start.toSign.identityMessage && !customSecret.trim() ? 1 : 0) }).map((_, i) => (
                    <span key={i} className={`dot ${i < signCount ? 'done' : ''}`} />
                  ))}
                </div>
              )}
              {provingOwnWallet && !needSwitch && (
                <p className="fine warn">
                  You're proving your agent's owner wallet. Consider a separate treasury for better privacy.
                </p>
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
