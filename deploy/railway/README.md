# Railway deployment

Deploys the Proof-of-Reserves stack as **5 Railway services** in one project, all
from this repo:

| Service     | Process                          | Config file       | Root dir      | Exposure                     |
|-------------|----------------------------------|-------------------|---------------|------------------------------|
| `adapter`   | `node sepolia-registry.mjs`      | `adapter.json`    | `app/web`     | private (internal only)      |
| `submitter` | `node submitter.mjs`             | `submitter.json`  | `app/web`     | private (internal only)      |
| `notary`    | `notary` (Rust, raw TCP)         | `notary.json`     | `deploy/railway` | **public TCP proxy**      |
| `verifier`  | `verifier` (Rust, HTTP)          | `verifier.json`   | `deploy/railway` | **public HTTPS domain**   |
| `ui`        | `vite` dev server                | `ui.json`         | `app/web`     | **public HTTPS domain**      |

The **prover is not deployed** — it runs on the agent's own machine (heavy Risc0
proving) and connects *in* to the public `verifier` (HTTP) and `notary` (raw TCP).

```
              external agent (prover)
                 │                 │
      HTTP (challenge/response)   raw TCP (MPC-TLS attest)
                 ▼                 ▼
          ┌────────────┐     ┌──────────┐
          │  verifier  │     │  notary  │   ← Railway TCP Proxy + Volume(/data)
          └─────┬──────┘     └──────────┘
     owner lookup│ └─ forward verified bundles ┐
                 ▼                              ▼
          ┌────────────┐   PIPELINE_URL   ┌────────────┐
   /api ← │  adapter   │ ───────────────▶ │ submitter  │ → Kurier + Base Sepolia
          └────────────┘                  └────────────┘   (recordValidation)
                 ▲
       vite proxies /api (server-side, private)
                 │
          ┌────────────┐
   users →│     ui     │
          └────────────┘
```

Services talk to each other over Railway's **private network** at
`<service-name>.railway.internal`. Name the services exactly `adapter`,
`submitter`, `notary`, `verifier`, `ui` so the hostnames below resolve. Private
networking is IPv6 — the Node services bind `::` by default (fine) and the Rust
services are told to bind `[::]` in their start commands.

The two private services (`adapter`, `submitter`) pin a fixed `PORT` (8090 / 8092)
so (a) peers can address them at `<svc>.railway.internal:<port>` and (b) Railway's
healthcheck and port-detection target the same port the app listens on. If a
healthcheck ever blocks a deploy, remove `healthcheckPath` from that service's
config — it's optional.

---

## One-time: build & push the Rust runtime image (notary + verifier)

The notary/verifier are prebuilt binaries baked into a GHCR image — Railway just
pulls it, so there's no 30-min Risc0+tlsn compile on Railway and the verifier's
guest `image_id` stays byte-identical to the prover's.

```bash
docker login ghcr.io                       # GitHub PAT with write:packages
deploy/railway/build-and-push.sh           # builds guest reproducibly, pushes image
```

- Push to a path you control and update the `FROM` line in `Dockerfile.risc0`
  (default `ghcr.io/horizenlabs/por-risc0-runtime:latest`), or set
  `RISC0_RUNTIME_IMAGE` for the script.
- Make the GHCR package **public**, or add **private-registry credentials** in
  Railway, so Railway can pull it.
- **Re-run this and redeploy `notary`+`verifier` whenever the guest changes** — a
  verifier built from a different guest will reject every real proof (image_id
  mismatch). See the note in `build-and-push.sh`.

The binaries are staged to `deploy/railway/bin/` (git-ignored) and never committed.

---

## Create the services

For each service, in the Railway dashboard (or `railway.json` config-as-code path):

1. **New Service → GitHub Repo** → this repo.
2. **Settings → Root Directory** → the value from the table above.
3. **Settings → Config-as-code** → path to the config file, e.g.
   `deploy/railway/verifier.json` (paths are relative to the repo root).
4. Set the **Variables** for that service (below).
5. Networking (below): public domain / TCP proxy / private-only.

> `dockerfilePath` in each config is relative to that service's **Root Directory**
> (`Dockerfile` resolves to `app/web/Dockerfile` or `deploy/railway/Dockerfile.risc0`).

---

## Networking

- **`ui`** — add a **public domain** (Settings → Networking → Generate Domain).
  Railway routes it to the vite server on `$PORT`.
- **`verifier`** — add a **public domain**. This is the URL agents pass as
  `--verifier https://<verifier-domain>`.
- **`notary`** — add a **TCP Proxy** (Settings → Networking → TCP Proxy). Railway
  gives you `<host>.proxy.rlwy.net:<port>`. Agents pass this as
  `NOTARY_ADDR=<host>.proxy.rlwy.net:<port>`. (The notary speaks raw TLSNotary
  MPC-TLS, not HTTP, so it needs a TCP proxy — a normal HTTP domain won't work.)
- **`adapter`**, **`submitter`** — **no public networking**; reached only over the
  private network by `verifier`/`ui`/`adapter`.

---

## Volume (notary)

The notary persists its secp256k1 signing key to `notary-signing-key.bin` in its
working directory (`/data`). Attach a **Volume** to the `notary` service mounted at
`/data` so the key survives restarts/redeploys. Without it, the notary mints a new
identity on every boot.

- First boot generates a fresh key on the volume. To reuse an existing notary key,
  upload your `notary-signing-key.bin` into the volume once (e.g. via a temporary
  shell), then restart.

---

## Variables

Secrets (🔒) go in Railway variables, never in the repo. `$PORT` is injected by
Railway for the public services; the private services pin their port so peers can
address them.

### `adapter`
```
PORT=8090
POR_AGENT_IDS=0x16ec                       # your marketplace agent id(s), comma-separated
PIPELINE_URL=http://submitter.railway.internal:8092/pipeline
# optional overrides (defaults target Base Sepolia):
# BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
# IDENTITY_REGISTRY=0x8004A818BFB912233c491871b3d84c89A494BD9e
# VALIDATION_GATEWAY=0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920
# RECEIPTS_FROM_BLOCK=<block>              # narrow the on-chain receipt scan
```

### `submitter`
```
PORT=8092                                  # aligns Railway's healthcheck/port-detect
SUBMITTER_PORT=8092                        # the port the app actually reads
PRIVATE_KEY=0x...            🔒            # Base Sepolia wallet (gas + protocol fee)
KURIER_API_KEY=...           🔒            # testnet Kurier key
# optional (defaults shown in submitter.mjs):
# BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
# KURIER_API_URL=https://api-testnet.kurier.xyz
# DOMAIN_ID=2
```
> Mirror whatever you set in your local `.env` / `por-tmux.sh` for the submitter —
> those are the same keys used by the recordValidation pipeline today.

### `notary`
```
# NOTARY_ADDR is set from $PORT by the start command — nothing to add.
# (Attach the /data volume; see above.)
```

### `verifier`  (production mode — no dev/allow flags)
```
POR_REGISTRY_URL=http://adapter.railway.internal:8090
POR_SUBMITTER_URL=http://submitter.railway.internal:8092
# optional:
# POR_WINDOW_DAYS=3
# POR_TESTNET=1                            # set ONLY if proving testnet chains
# POR_RPC_URL_1=https://<archive-endpoint> # per-chain head-pin endpoint (id = chain id)
```
> Do **not** set `KURIER_API_KEY` here — the verifier forwards verified bundles to
> the submitter, which owns Kurier settlement. Do **not** set `POR_ALLOW_DEBUG`,
> `POR_ALLOW_NO_PRESENTATION`, or `POR_ALLOW_UNVERIFIED_OWNER` — those disable
> production checks.

### `ui`
```
API_PROXY=http://adapter.railway.internal:8090
```

---

## Running the prover against the deployment

From the agent machine (unchanged flow, just remote endpoints):

```bash
POR_PRIVATE_KEY=<32B-hex> POR_OWNER_KEY=<32B-hex> \
NOTARY_ADDR=<host>.proxy.rlwy.net:<port> \
  por-risc0/target/release/prover \
    --verifier https://<verifier-domain> \
    --agent-id <agent-id> --threshold <wei> [--chain-id <id>]
```

The prover must build its guest with `RISC0_USE_DOCKER=1` so its `image_id` matches
the deployed verifier's.

---

## Notes / caveats

- **`ui` runs the vite dev server** (matches `docker-compose.yml`). It works behind
  Railway's HTTPS edge; HMR websockets may not connect but the app loads fine. For a
  hardened UI, switch to a static build + a server that also proxies `/api` (needs
  `preview.proxy` in `vite.config.ts`).
- **Runtime base is `debian:trixie-slim`** to match the glibc the binaries are built
  against. If a Rust service fails at startup on a missing `.so`, add it to the apt
  list in `Dockerfile.runtime` and re-push.
- **RPC egress**: `adapter`/`submitter` hit Base Sepolia; `verifier` head-pins each
  proven chain via its default (drpc) RPCs. For reliability on mainnet windows, set
  `POR_RPC_URL_<id>` to archive endpoints on the verifier.
