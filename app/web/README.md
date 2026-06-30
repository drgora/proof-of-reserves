# Verified-agent directory (web UI)

A read-only directory of **verified Proof-of-Reserves agents** on the Horizen Labs
Agent Marketplace. Lists each agent's identity + on-chain quality receipts and a
per-agent detail page — quality proven on zkVerify, balances/addresses never shown.

## Architecture

```
browser (React/Vite, :5173)
   │  GET /api/...                     (same-origin; Vite proxies /api → :8090)
   ▼
server.mjs  (Node read-proxy, :8090)   ← this repo, zero deps
   │  MCP tools/call (JSON-RPC over HTTP)
   ▼
agent-registry.horizenlabs.io/api/mcp  ← marketplace's own read API over the
                                          ERC-8004 IdentityRegistry + ValidationRegistry
```

The browser can't call the registry MCP endpoint directly (CORS-blocked, and it
speaks MCP not REST), so `server.mjs` wraps the MCP tools (`list_verified_agents`,
`get_agent`, `get_registry_overview`, `get_validation_stats`) and exposes clean
REST under `/api`. It caches results and backs off on the registry's 240 req/min
rate limit.

## Run

```bash
npm install
npm run server   # terminal 1 — read-proxy on :8090
npm run dev      # terminal 2 — Vite on :5173 (proxies /api → :8090)
# open http://localhost:5173
```

`npm run build` produces a static bundle in `dist/`; serve it behind any host that
proxies `/api` to a running `server.mjs`.

## Configuring the Proof-of-Reserves filter

The directory shows only agents that have proven **Proof-of-Reserves**. Until a PoR
proof type + PoR agents exist on the marketplace it runs in **preview mode**
(shows all verified agents, with a banner). Configure the read-proxy via env:

| Env | Default | Meaning |
|-----|---------|---------|
| `PORT` | `8090` | Port the read-proxy listens on (must match the Vite proxy target). |
| `REGISTRY_MCP_URL` | `https://agent-registry.horizenlabs.io/api/mcp` | Registry MCP endpoint. |
| `POR_AGENT_IDS` | _(unset)_ | Comma list of agent ids — **the production path**: directory = exactly these agents, no scan. Set this once you've registered your PoR agents. |
| `POR_PROOF_TYPES` | `proof-of-reserves,reserves,por,risc0` | An agent counts as PoR if any receipt uses one of these proof types (case-insensitive). Set this to the exact `proofType` string you register PoR under. |
| `POR_SHOW_ALL` | `1` | When no PoR agent is found, fall back to listing all verified agents. Set `0` to strictly show only PoR (empty until PoR exists). |
| `ZKVERIFY_EXPLORER` | `https://zkverify-testnet.subscan.io` | Base URL for per-receipt `…/extrinsic/{txHash}` links. |
| `CACHE_TTL_MS` / `DIRECTORY_TTL_MS` | `60000` / `300000` | Cache TTLs for cheap endpoints / the verified-agent scan. |

Once you register PoR on the marketplace, the simplest wiring is:

```bash
POR_AGENT_IDS=0xabc123,0xdef456 npm run server
```

If `POR_PROOF_TYPES` doesn't yet match a live marketplace proof type, the proxy
skips the (expensive) per-agent scan entirely and serves preview mode.

## API (read-proxy)

| Endpoint | Returns |
|----------|---------|
| `GET /api/health` | proxy config (registry url, PoR filter settings). |
| `GET /api/overview` | registry totals + `porTypeLive`. |
| `GET /api/proof-types` | proof types accepted by the validation gateway. |
| `GET /api/agents` | `{ mode, agents[], totalVerified, porCount }` — `mode` is `allowlist`/`por`/`fallback-all`. |
| `GET /api/agents/:agentId` | full agent profile: identity, what-it-proves, receipts (with zkVerify tx/block), SLA, reputation. |
