import { Link, Outlet } from 'react-router-dom'

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
        <div className="container">
          <span>Data: Horizen Labs Agent Marketplace (ERC-8004 · Base)</span>
          <span>·</span>
          <span>Quality proven on zkVerify</span>
        </div>
      </footer>
    </>
  )
}
