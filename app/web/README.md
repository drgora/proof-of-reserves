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

## Local testing with a mock registry

The live registry is rate-limited, CORS-blocked, and (until PoR is registered)
has no Proof-of-Reserves agents — so it can't exercise the `por`-mode filter or a
real end-to-end submission. `mock-registry.mjs` is a zero-dep, **stateful**
stand-in that plays **two roles** in one process:

1. **Registry read MCP** — the `tools/call` slice the proxy uses, served from
   mutable state (seeded with two PoR agents + two non-PoR agents).
2. **Kurier stand-in** — the exact endpoints `por_verify` hits
   (`POST /api/v1/submit-proof/:key`, `GET /api/v1/job-status/:key/:jobId`), so the **real
   `por_verify` binary submits its real receipt here with no code changes**.

The bridge: when a submitted receipt reaches `Aggregated`, the mock **auto-records
a validation** on the prover's agent, which then appears in the UI. (This collapses
the marketplace's on-chain steps — attestation relay + `ValidationGateway.record‑
Validation` — which need Base Sepolia + viem and can't run locally.)

### Full E2E: proof → submission → UI

```bash
# terminal 1 — mock (registry MCP + Kurier + control), all on :8091
npm run mock
# terminal 2 — read-proxy on :8090, pointed at the mock (short cache TTLs so new
#              validations show up on refresh within a few seconds)
npm run server:mock
# terminal 3 — Vite on :5173
npm run dev
# open http://localhost:5173  → `por` mode, 2 PoR agents; the "Local Reserve
#   Prover (this node)" agent is registered but NOT yet shown (0 receipts).

# terminal 4 — submit a REAL receipt from por-risc0/ (uses the existing proof.json)
cd ../../por-risc0
KURIER_API_KEY=mock KURIER_API_URL=http://127.0.0.1:8091 \
  POR_ALLOW_DEBUG=1 POR_REQUIRED_THRESHOLD=1 ./target/release/por_verify
#   → por_verify verifies locally, submits to the mock Kurier, polls to
#     "Aggregated". Refresh the UI: the self-agent now appears with its receipt,
#     whose zkVerify txHash matches por_verify's output and whose ethBlockHash is
#     the actual block the reserves were proven against.
```

To make a *fresh* proof first, run the prover (`host`) per the top-level README,
then submit as above. `npm run server:mock` is `npm run server` with
`REGISTRY_MCP_URL`, `PIPELINE_URL=…/mock/pipeline`, `POR_PROOF_TYPES=proof-of-reserves,risc0`,
and short cache TTLs prepended.

While a proof is in flight, the Directory shows a **Verification pipeline** panel
that polls `/api/pipeline` every ~3 s and animates each submission through
`SUBMITTED → FINALIZED → AGGREGATED → RELAYING → RECORDING → VERIFIED` — the on-chain
recording steps the `hl-registry-integration` skill documents (`POST /mock/record`
seeds an already-`VERIFIED` entry if you just want to see the panel). The panel is
hidden entirely in production unless `PIPELINE_URL` is wired to a submitter's status
API, keeping the directory read-only by default.

> Requires a `por_verify` built from this branch — it now streams the (~0.5 MB)
> receipt to `curl` over stdin instead of an inline argv (which overflowed
> `ARG_MAX`). Rebuild with `cargo build --release --bin por_verify` in `por-risc0/`.

### Control API (interactive)

| Endpoint | Does |
|----------|------|
| `GET /mock/state` | dump agents (receipts, verified, target) + open Kurier jobs. |
| `POST /mock/reset` | restore the seed fixtures (clears recorded validations). |
| `POST /mock/target` `{agentId}` | set which agent Kurier submissions attribute to. |
| `POST /mock/agent` `{agentId?,name,proofType,…,makeTarget?}` | register/upsert an agent. |
| `POST /mock/record` `{agentId?,proofType?,ethBlockHash?}` | inject a validation **without** running the prover (fast UI iteration); also seeds a matching, already-`VERIFIED` entry in the pipeline. |
| `GET /mock/pipeline` | live submission-pipeline snapshot (what `PIPELINE_URL` points the proxy at). |

### Read-side modes you can also exercise

| Want | Do |
|------|----|
| `por` mode | default — overview advertises `risc0`, proxy runs the scan, keeps every agent with a PoR receipt. |
| `fallback-all` / preview banner | start the mock with `MOCK_POR_LIVE=0 npm run mock`. |
| 404 path | `GET /api/agents/0xnope` → 404. |

Mock env: `MOCK_PORT` (default `8091`), `MOCK_POR_LIVE` (default `1`),
`MOCK_SELF_AGENT_ID` / `MOCK_SELF_AGENT_NAME` (the submission-target agent),
`MOCK_KURIER_POLLS` (default `0`; intermediate `AggregationPending` polls before
`Aggregated` — raise to watch the lifecycle). Edit the `SEED_AGENTS` array in
`mock-registry.mjs` to change the fixture set.

## Configuring the Proof-of-Reserves filter

The directory lists **every agent that has submitted at least one Proof-of-Reserves
proof** — discovered from the registry/on-chain validation records, not from a
configured allowlist. Until a PoR proof type + PoR agents exist on the marketplace it
runs in **preview mode** (shows all verified agents, with a banner). Configure the
read-proxy via env:

| Env | Default | Meaning |
|-----|---------|---------|
| `PORT` | `8090` | Port the read-proxy listens on (must match the Vite proxy target). |
| `REGISTRY_MCP_URL` | `https://agent-registry.horizenlabs.io/api/mcp` | Registry MCP endpoint. |
| `POR_PROOF_TYPES` | `proof-of-reserves,reserves,por,risc0` | An agent is listed if any receipt uses one of these proof types (case-insensitive). Set this to the exact `proofType` string(s) you register PoR under. |
| `POR_SHOW_ALL` | `1` | When no PoR agent is found, fall back to listing all verified agents. Set `0` to strictly show only PoR (empty until PoR exists). |
| `ZKVERIFY_EXPLORER` | `https://zkverify-testnet.subscan.io` | Base URL for per-receipt `…/extrinsic/{txHash}` (zkVerify) links. |
| `BASESCAN_URL` | `https://sepolia.basescan.org` | Base Sepolia explorer — on-chain `recordValidation` tx + contract/owner address links. |
| `MARKETPLACE_URL` | `https://agent-registry.horizenlabs.io` | Marketplace base for the canonical per-agent page (`…/agent/{tokenIdHex}`). |
| `POR_NETWORK` | `Base Sepolia` | Display label for the network the marketplace runs on (shown in the UI network badge/footer). |
| `PIPELINE_URL` | _(unset)_ | If set, `/api/pipeline` proxies this submitter status source so the UI can show a live submission timeline. Unset → pipeline disabled. Locally point it at the mock's `/mock/pipeline`. |
| `CACHE_TTL_MS` / `DIRECTORY_TTL_MS` | `60000` / `300000` | Cache TTLs for cheap endpoints / the verified-agent scan. |

Once you register PoR on the marketplace, no per-agent configuration is needed — set
`POR_PROOF_TYPES` to the `proofType` string(s) you register PoR under and every agent
that has submitted such a proof is listed automatically:

```bash
POR_PROOF_TYPES=proof-of-reserves,risc0 npm run server
```

If `POR_PROOF_TYPES` doesn't yet match a live marketplace proof type, the proxy
skips the (expensive) per-agent scan entirely and serves preview mode.

## API (read-proxy)

| Endpoint | Returns |
|----------|---------|
| `GET /api/health` | proxy config (registry url, PoR filter settings). |
| `GET /api/overview` | registry totals + `porTypeLive`. |
| `GET /api/proof-types` | proof types accepted by the validation gateway. |
| `GET /api/agents` | `{ mode, agents[], totalVerified, porCount, network, marketplace, baseExplorer }` — `mode` is `por`/`fallback-all`. |
| `GET /api/agents/:agentId` | full agent profile: identity, what-it-proves, receipts (with zkVerify extrinsic + on-chain `recordValidation` tx), SLA, reputation, network + explorer/marketplace bases. |
| `GET /api/pipeline` | `{ enabled, jobs[] }` — live submission timeline (SUBMITTED→FINALIZED→AGGREGATED→RELAYING→RECORDING→VERIFIED). `enabled:false` unless `PIPELINE_URL` is set. |
