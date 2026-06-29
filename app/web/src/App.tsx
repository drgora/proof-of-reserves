import { useEffect, useState } from 'react'
import type { CSSProperties } from 'react'
import {
  useAccount,
  useConnect,
  useDisconnect,
  useSignMessage,
  useChainId,
} from 'wagmi'
import { SiweMessage } from 'siwe'

type VerifyResponse = {
  verified: boolean
  serverName: string | null
  time: string | null
  thresholdProven: number | null
  notaryKey: string | null
  wallet: string | null
  ownerVerified: boolean | null
  error: string | null
}

type ProveResponse = {
  wallet: string
  requestedThreshold: number
  verification: VerifyResponse
}

// The Rust service serializes with snake_case; normalize to the camelCase used above.
function norm(v: any): VerifyResponse {
  return {
    verified: !!v.verified,
    serverName: v.server_name ?? null,
    time: v.time ?? null,
    thresholdProven: v.threshold_proven ?? null,
    notaryKey: v.notary_key ?? null,
    wallet: v.wallet ?? null,
    ownerVerified: v.owner_verified ?? null,
    error: v.error ?? null,
  }
}

export default function App() {
  const { address, isConnected } = useAccount()
  const { connect, connectors } = useConnect()
  const { disconnect } = useDisconnect()
  const { signMessageAsync } = useSignMessage()
  const chainId = useChainId()

  const [threshold, setThreshold] = useState('1000000')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ProveResponse | null>(null)
  const [adminMode, setAdminMode] = useState(false)
  const [adminAddr, setAdminAddr] = useState('')

  // Discover whether the server enabled local admin mode.
  useEffect(() => {
    fetch('/api/config')
      .then((r) => r.json())
      .then((c) => setAdminMode(!!c.admin_mode))
      .catch(() => {})
  }, [])

  const thr = () => Math.floor(Number(threshold))

  function showVerdict(data: any, fallbackThr: number) {
    if (data?.error) throw new Error(data.error)
    const verification = norm(data.verification)
    if (!verification.verified) throw new Error(verification.error || 'proof not verified')
    setResult({
      wallet: data.wallet,
      requestedThreshold: data.requested_threshold ?? fallbackThr,
      verification,
    })
  }

  async function prove() {
    if (!address) return
    const t = thr()
    if (!Number.isFinite(t) || t < 0) return setStatus('Enter a whole-number USD threshold.')
    setBusy(true)
    setResult(null)
    setStatus('Requesting challenge…')
    try {
      const { nonce } = await (await fetch('/api/nonce')).json()
      const message = new SiweMessage({
        domain: window.location.host,
        address,
        statement: 'Prove ownership of this wallet for a proof-of-reserves attestation.',
        uri: window.location.origin,
        version: '1',
        chainId: chainId || 1,
        nonce,
      }).prepareMessage()

      setStatus('Awaiting wallet signature…')
      const signature = await signMessageAsync({ message })

      setStatus('Proving in zero-knowledge (MPC-TLS to Zerion + Noir ≥ T)… ~10s')
      const resp = await fetch('/api/prove', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message, signature, threshold: t }),
      })
      showVerdict(await resp.json(), t)
      setStatus('')
    } catch (e: any) {
      setStatus('Error: ' + (e?.message ?? String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function adminProve() {
    const t = thr()
    if (!/^0x[0-9a-fA-F]{40}$/.test(adminAddr.trim())) return setStatus('Enter a valid 0x… address.')
    if (!Number.isFinite(t) || t < 0) return setStatus('Enter a whole-number USD threshold.')
    setBusy(true)
    setResult(null)
    setStatus('Proving (admin — no ownership check)… ~10s')
    try {
      const resp = await fetch('/api/admin/prove', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address: adminAddr.trim(), threshold: t }),
      })
      showVerdict(await resp.json(), t)
      setStatus('')
    } catch (e: any) {
      setStatus('Error: ' + (e?.message ?? String(e)))
    } finally {
      setBusy(false)
    }
  }

  const usd = (n: number | null) =>
    n == null ? '—' : n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 })

  const v = result?.verification

  return (
    <div style={S.page}>
      <div style={S.card}>
        <h1 style={S.h1}>Proof of Reserves</h1>
        <p style={S.sub}>
          Prove a wallet you control holds at least a threshold on Zerion —{' '}
          <strong>in zero-knowledge</strong>. The exact balance is never revealed: a separate notary
          attests the TLS session, and a Noir proof shows <code>balance ≥ T</code> against that
          attestation. An independent verifier checks it offline.
        </p>

        {!isConnected ? (
          <button style={S.btn} onClick={() => connect({ connector: connectors[0] })}>
            Connect Wallet
          </button>
        ) : (
          <>
            <div style={S.row}>
              <span style={S.mono}>{address}</span>
              <button style={S.linkBtn} onClick={() => disconnect()}>
                disconnect
              </button>
            </div>

            <label style={S.label}>Threshold (USD, whole number)</label>
            <input
              style={S.input}
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              inputMode="numeric"
            />

            <button
              style={{ ...S.btn, opacity: busy ? 0.6 : 1, cursor: busy ? 'default' : 'pointer' }}
              disabled={busy}
              onClick={prove}
            >
              {busy ? 'Working…' : `Prove ≥ ${usd(thr() || 0)}`}
            </button>
          </>
        )}

        {adminMode && (
          <div style={S.admin}>
            <div style={S.adminTag}>🛠 admin (local) — prove any address, no wallet / no signature</div>
            <input
              style={S.input}
              placeholder="0x… address to test"
              value={adminAddr}
              onChange={(e) => setAdminAddr(e.target.value)}
            />
            <input
              style={S.input}
              placeholder="threshold (USD)"
              inputMode="numeric"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
            />
            <button
              style={{ ...S.btn, ...S.adminBtn, opacity: busy ? 0.6 : 1, cursor: busy ? 'default' : 'pointer' }}
              disabled={busy}
              onClick={adminProve}
            >
              {busy ? 'Working…' : `Prove ≥ ${usd(thr() || 0)} (admin)`}
            </button>
          </div>
        )}

        {status && <div style={S.status}>{status}</div>}

        {result && v && (
          <div style={S.result}>
            <div style={{ ...S.verdict, color: '#3fb950' }}>
              ✓ Proven: balance ≥ {usd(v.thresholdProven)}
            </div>
            <div style={S.hidden}>🔒 the exact balance was never revealed</div>
            <Field k="Wallet" val={result.wallet} mono />
            <Field
              k="Ownership (SIWE)"
              val={v.ownerVerified == null ? 'n/a (admin)' : v.ownerVerified ? 'verified ✓' : 'NOT verified ✗'}
            />
            <Field k="Threshold proven" val={usd(v.thresholdProven)} />
            <Field k="Server" val={v.serverName ?? '—'} />
            <Field k="Session time" val={v.time ?? '—'} />
            <Field k="Notary key" val={v.notaryKey ?? '—'} mono />
          </div>
        )}
      </div>
    </div>
  )
}

function Field({ k, val, mono }: { k: string; val: string; mono?: boolean }) {
  return (
    <div style={S.field}>
      <span style={S.fk}>{k}</span>
      <span style={{ ...S.fv, fontFamily: mono ? 'ui-monospace, monospace' : 'inherit' }}>{val}</span>
    </div>
  )
}

const S: Record<string, CSSProperties> = {
  page: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: '#0b0d12',
    color: '#e6e8eb',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    padding: 24,
  },
  card: {
    width: '100%',
    maxWidth: 560,
    background: '#151821',
    border: '1px solid #232838',
    borderRadius: 16,
    padding: 28,
    boxShadow: '0 10px 40px rgba(0,0,0,0.4)',
  },
  h1: { margin: '0 0 8px', fontSize: 24 },
  sub: { margin: '0 0 20px', fontSize: 13, lineHeight: 1.6, color: '#9aa3b2' },
  btn: {
    width: '100%',
    padding: '12px 16px',
    fontSize: 15,
    fontWeight: 600,
    color: '#0b0d12',
    background: '#6ea8fe',
    border: 'none',
    borderRadius: 10,
    cursor: 'pointer',
  },
  linkBtn: {
    background: 'none',
    border: 'none',
    color: '#6ea8fe',
    cursor: 'pointer',
    fontSize: 13,
    padding: 0,
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    marginBottom: 16,
  },
  mono: {
    fontFamily: 'ui-monospace, monospace',
    fontSize: 13,
    color: '#c7cdd8',
    wordBreak: 'break-all',
  },
  label: { display: 'block', fontSize: 12, color: '#9aa3b2', margin: '8px 0 6px' },
  input: {
    width: '100%',
    boxSizing: 'border-box',
    padding: '10px 12px',
    fontSize: 15,
    background: '#0f121a',
    color: '#e6e8eb',
    border: '1px solid #2a3043',
    borderRadius: 10,
    marginBottom: 10,
  },
  status: { marginTop: 16, fontSize: 13, color: '#9aa3b2', lineHeight: 1.5 },
  result: { marginTop: 20, paddingTop: 18, borderTop: '1px solid #232838' },
  verdict: { fontSize: 18, fontWeight: 700, marginBottom: 4 },
  hidden: { fontSize: 12, color: '#9aa3b2', marginBottom: 12 },
  field: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 16,
    padding: '6px 0',
    fontSize: 13,
    borderBottom: '1px solid #1b2030',
  },
  fk: { color: '#9aa3b2', whiteSpace: 'nowrap' },
  fv: { textAlign: 'right', wordBreak: 'break-all', color: '#e6e8eb' },
  admin: { marginTop: 18, paddingTop: 16, borderTop: '1px dashed #3a3340' },
  adminTag: { fontSize: 12, color: '#d6a44c', marginBottom: 8 },
  adminBtn: { background: '#caa15a' },
}
