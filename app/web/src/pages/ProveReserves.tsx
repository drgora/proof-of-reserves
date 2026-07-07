import { useMemo, useState } from 'react'
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

type ToSign = { blockHashes: `0x${string}`[]; challengePrehash: `0x${string}` }
type StartResp = {
  jobId?: string
  challengeId?: string
  chainId?: number
  toSign?: ToSign
  blocks?: { number: number; hash: string }[]
  error?: string
}
type Status = {
  state: 'preparing' | 'awaiting-signatures' | 'proving' | 'verified' | 'rejected' | 'error'
  phase: string
  verdict: string | null
  reason: string | null
  log: string
}

const short = (a?: string) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')

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

  const chain = CHAINS.find((c) => c.id === chainId)!
  const thresholdWei = useMemo(() => {
    try {
      return parseEther(amount as `${number}`).toString()
    } catch {
      return null
    }
  }, [amount])

  const done = status && ['verified', 'rejected', 'error'].includes(status.state)
  const canProve = isConnected && agentId.trim() && thresholdWei && !busy

  async function run() {
    setError(null)
    setStatus(null)
    setStart(null)
    setSignCount(0)
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

      // 2. Sign the messages the verifier chose (one per block + the challenge). Signing
      //    only — no gas, no network switch. Up to 4 wallet prompts.
      const sigs: `0x${string}`[] = []
      const msgs = s.toSign!.blockHashes
      for (let i = 0; i < msgs.length; i++) {
        setPhase(`Sign ${i + 1} of ${msgs.length + 1} in your wallet — block ownership`)
        sigs.push(await signMessageAsync({ message: { raw: msgs[i] } }))
        setSignCount(i + 1)
      }
      setPhase(`Sign ${msgs.length + 1} of ${msgs.length + 1} in your wallet — the challenge`)
      const ownerSig = await signMessageAsync({ message: { raw: s.toSign!.challengePrehash } })
      setSignCount(msgs.length + 1)

      // 3. Hand the signatures back; the backend proves (minutes) and submits.
      setPhase('Attesting + proving — this takes a few minutes…')
      const fin = await fetch('/api/prove/finalize', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jobId: s.jobId, blockSigs: sigs, ownerSig }),
      }).then((r) => r.json())
      if (fin.error) throw new Error(fin.error)

      // 4. Poll for the verdict.
      for (;;) {
        await new Promise((r) => setTimeout(r, 2500))
        const st: Status = await fetch(`/api/prove/status/${s.jobId}`).then((r) => r.json())
        setStatus(st)
        setPhase(st.phase)
        if (['verified', 'rejected', 'error'].includes(st.state)) break
      }
    } catch (e: any) {
      setError(e?.shortMessage || e?.message || String(e))
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
                <button className="btn ghost small" onClick={() => disconnect()} disabled={busy}>
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
              disabled={busy}
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
              <select className="input" value={chainId} onChange={(e) => setChainId(Number(e.target.value))} disabled={busy}>
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
                disabled={busy}
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
          {!busy && !status && !error && (
            <div className="prove-idle">
              <h3>How it works</h3>
              <ol className="prove-steps">
                <li>The verifier picks 3 recent, unpredictable blocks.</li>
                <li>You sign one message per block + the challenge (no gas).</li>
                <li>A zkVM proof is generated and checked — balance &amp; address stay private.</li>
              </ol>
              <p className="fine">Proving runs after you sign and takes a few minutes.</p>
            </div>
          )}

          {(busy || status) && !done && (
            <div className="prove-running">
              <div className="spinner" />
              <div className="phase">{phase}</div>
              {start?.toSign && (
                <div className="sign-dots">
                  {Array.from({ length: start.toSign.blockHashes.length + 1 }).map((_, i) => (
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
              </div>
            </div>
          )}

          {done && status!.state !== 'verified' && (
            <div className="prove-result bad">
              <span className="badge bad big">✕ {status!.state === 'rejected' ? 'Rejected' : 'Error'}</span>
              <p>{status!.reason || 'The proof was not accepted.'}</p>
            </div>
          )}

          {error && (
            <div className="error-box" style={{ marginTop: 12 }}>
              {error}
            </div>
          )}

          {(busy || status) && (
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
