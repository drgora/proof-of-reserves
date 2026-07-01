import { Link, Outlet } from 'react-router-dom'
import { CONTRACTS, DEFAULT_MARKETPLACE, NETWORK, baseAddressUrl } from './chain'

export default function App() {
  return (
    <>
      <header className="site-header">
        <div className="container">
          <Link to="/" className="brand">
            <img src="/brand/zkverify-logo-white.svg" alt="zkVerify" />
            <span className="divider" />
            <span className="product">
              Proof-of-Reserves <span className="dim">· Verified Agents</span>
            </span>
          </Link>
          <span className="header-spacer" />
          <a
            className="header-link"
            href="https://agent-registry.horizenlabs.io"
            target="_blank"
            rel="noreferrer"
          >
            Agent Marketplace ↗
          </a>
        </div>
      </header>

      <main className="container">
        <Outlet />
      </main>

      <footer className="site-footer">
        <div className="container footer-cols">
          <div className="footer-line">
            <span>Data: Horizen Labs Agent Marketplace (ERC-8004 · {NETWORK})</span>
            <span>·</span>
            <span>Quality proven on zkVerify</span>
            <span>·</span>
            <a href={DEFAULT_MARKETPLACE} target="_blank" rel="noreferrer">
              Agent Marketplace ↗
            </a>
          </div>
          <div className="footer-contracts">
            <span className="footer-heading">{NETWORK} contracts</span>
            {CONTRACTS.map((c) => (
              <a
                key={c.address}
                className="contract"
                href={baseAddressUrl(undefined, c.address)}
                target="_blank"
                rel="noreferrer"
                title={c.purpose}
              >
                {c.name} <span className="mono">{c.address.slice(0, 6)}…{c.address.slice(-4)}</span> ↗
              </a>
            ))}
          </div>
        </div>
      </footer>
    </>
  )
}
