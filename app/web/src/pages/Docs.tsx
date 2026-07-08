import { useEffect, useMemo, useState } from 'react'
import { renderMarkdown } from '../markdown'

// The external-agent guide, served from the SPA (build-synced from the repo's AGENT_GUIDE.md),
// plus the machine-readable entry points an agent needs: the OpenAPI spec and the MCP server.
// The verifier base is discovered from the backend's /api/health (prover-web returns `verifier`);
// falls back to the deployed verifier so the directory-only deployments still render sane links.
const DEFAULT_VERIFIER = 'https://verifier-production-d672.up.railway.app'

export default function Docs() {
  const [md, setMd] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [verifier, setVerifier] = useState<string>(DEFAULT_VERIFIER)

  useEffect(() => {
    fetch('/AGENT_GUIDE.md')
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setMd)
      .catch((e) => setErr(e.message))
    fetch('/api/health')
      .then((r) => (r.ok ? r.json() : null))
      .then((h) => h?.verifier && setVerifier(String(h.verifier).replace(/\/$/, '')))
      .catch(() => {})
  }, [])

  const html = useMemo(() => (md ? renderMarkdown(md) : ''), [md])
  const mcpSnippet = `claude mcp add proof-of-reserves -- node app/web/por-mcp.mjs`

  return (
    <div className="docs">
      <div className="prove-hero">
        <span className="eyebrow">For agents & developers</span>
        <h1>
          Integrate <span className="grad">Proof-of-Reserves</span>
        </h1>
        <p className="prove-lede">
          Everything an agent needs to register, request a challenge, prove, and submit — over a
          plain HTTP API, or driven by an AI agent through MCP tools. Your keys stay on your machine.
        </p>
      </div>

      <div className="docs-cards">
        <div className="panel docs-card">
          <h3>REST API</h3>
          <p>Machine-readable OpenAPI 3.1. Point any client generator at it.</p>
          <div className="docs-links">
            <a className="btn small" href="/openapi.json" target="_blank" rel="noreferrer">
              openapi.json ↗
            </a>
            <a className="btn ghost small" href={`${verifier}/v1/openapi.json`} target="_blank" rel="noreferrer">
              Live spec ↗
            </a>
          </div>
          <p className="fine">
            Base URL <span className="mono">{verifier}</span>. Discover the service at{' '}
            <a className="mono" href={`${verifier}/v1/info`} target="_blank" rel="noreferrer">
              /v1/info
            </a>{' '}
            (chains, image_id, notary).
          </p>
        </div>

        <div className="panel docs-card">
          <h3>MCP server</h3>
          <p>
            Let an AI agent drive the whole flow with tools: <span className="mono">register_agent</span>,{' '}
            <span className="mono">request_challenge</span>, <span className="mono">prove_reserves</span>,{' '}
            <span className="mono">submit_proof</span>.
          </p>
          <pre className="docs-snippet">{mcpSnippet}</pre>
          <p className="fine">
            Runs locally (keys never leave your machine). Also exposes a plain HTTP JSON-RPC endpoint
            with <span className="mono">--http</span>. See <span className="mono">app/web/por-mcp.mjs</span>.
          </p>
        </div>

        <div className="panel docs-card">
          <h3>Register</h3>
          <p>
            One-time, self-custody: <span className="mono">IdentityRegistry.register()</span> from your
            own wallet on Base Sepolia. That wallet becomes the owner the verifier authenticates.
          </p>
          <div className="docs-links">
            <a className="btn ghost small" href={`${verifier}/v1/register`} target="_blank" rel="noreferrer">
              Registration info ↗
            </a>
          </div>
          <p className="fine">
            Via the <span className="mono">register_agent</span> MCP tool,{' '}
            <span className="mono">node app/web/register-agent.mjs</span>, or a browser wallet.
          </p>
        </div>
      </div>

      <div className="panel md-doc">
        {err && <div className="error-box">Couldn’t load the guide: {err}</div>}
        {!md && !err && <div className="center-state"><div className="spinner" />Loading guide…</div>}
        {md && <div dangerouslySetInnerHTML={{ __html: html }} />}
      </div>
    </div>
  )
}
